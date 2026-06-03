// Look up URLs in SURBL

const dns = require('node:dns/promises')
const net = require('node:net')

const { parseFrom, parseReplyTo } = require('@haraka/email-address')
const tlds = require('haraka-tld')
const net_utils = require('haraka-net-utils')
const utils = require('haraka-utils')

// A blocked/dropped DNSBL query hangs on the c-ares default for ~25s; a bounded
// resolver rejects it in a few seconds so a slow zone can't stall the whole
// transaction (the hook timeout is the overall budget, this caps each lookup).
const resolver = new dns.Resolver({ tries: 2, timeout: 1500 })
exports.resolver = resolver

// Regexps to extract URIs from the message.
const numeric_ip =
  /\w{3,16}:\/{1,3}(?:[^\s/@]{1,64}@)?(\d+|0[xX][0-9A-Fa-f]+)\.(\d+|0[xX][0-9A-Fa-f]+)\.(\d+|0[xX][0-9A-Fa-f]+)\.(\d+|0[xX][0-9A-Fa-f]+)/gi
let schemeless =
  /(?:%(?:25)?(?:2F|3D|40))?((?:www\.)?[a-zA-Z0-9][a-zA-Z0-9\-.]{0,250}\.(?:aero|arpa|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|[a-zA-Z]{2}))(?!\w)/gi
let schemed =
  /(\w{3,16}:\/{1,3}(?:[^\s/@]{1,64}@)?([a-zA-Z0-9][a-zA-Z0-9\-.]{0,250}\.(?:aero|arpa|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|[a-zA-Z]{2})))(?!\w)/gi
const isTruthy = (val) => /^(?:1|true|yes|enabled|on)$/i.test(val)

exports.register = function () {
  // haraka-tld loads async, rebuild again once the load resolves.
  this.buildExtractRegexps()
  if (typeof tlds.ready?.then === 'function') {
    tlds.ready.then(() => this.buildExtractRegexps())
  }

  this.load_uribl_ini()
  this.load_uribl_exludes()

  if (this.zones.length === 0) {
    this.logerror('aborting: no zones configured')
  } else {
    this.register_hook('lookup_rdns', 'lookup_remote_ip')
    this.register_hook('helo', 'lookup_ehlo')
    this.register_hook('ehlo', 'lookup_ehlo')
    this.register_hook('mail', 'lookup_mailfrom')
    this.register_hook('data', 'enable_body_parsing')
    this.register_hook('data_post', 'lookup_header_zones')
  }
}

// Widen the body URL extractors to every known TLD. Without this they only
// match the ~25 hardcoded TLDs plus any 2-letter ccTLD, missing modern gTLDs.
exports.buildExtractRegexps = function () {
  if (!tlds.top_level_tlds?.size) return
  this.logdebug('Building new regexps from TLD file')
  const alt = [...tlds.top_level_tlds].join('|')
  schemeless = new RegExp(
    `(?:%(?:25)?(?:2F|3D|40))?((?:www\\.)?[a-zA-Z0-9][a-zA-Z0-9\\-.]{0,250}\\.(?:${alt}))(?!\\w)`,
    'gi',
  )
  schemed = new RegExp(
    `(\\w{3,16}:\\/{1,3}(?:[^\\s/@]{1,64}@)?([a-zA-Z0-9][a-zA-Z0-9\\-.]{0,250}\\.(?:${alt})))(?!\\w)`,
    'gi',
  )
}

exports.load_uribl_ini = function () {
  this.cfg = this.config.get('uribl.ini', () => {
    this.load_uribl_ini()
  })

  this.zones = Object.keys(this.cfg).filter((a) => a !== 'main')

  // defaults
  if (!this.cfg.main.max_uris_per_list) {
    this.cfg.main.max_uris_per_list = 20
  }
}

exports.load_uribl_exludes = function () {
  const newExcludes = new Set()
  const rawDomains = this.config.get('uribl.excludes', 'list', () => {
    this.load_uribl_exludes()
  })
  for (const d of rawDomains) {
    newExcludes.add(d.toLowerCase())
  }
  this.excludes = newExcludes
}

exports.isExcluded = function (host) {
  const parts = host.split('.')
  for (let i = parts.length - 1; i >= 0; i--) {
    // host.example.com (i=1,0): example.com -> host.example.com
    if (this.excludes.has(parts.slice(i).join('.'))) return true
  }
  return false
}

exports.isValidTLD = function (host) {
  if (net.isIPv4(host) || net.isIPv6(host)) return false
  // Lists load asynchronously; until they are ready, don't filter by TLD.
  if (!tlds.top_level_tlds.size) return true
  const tld = host.split('.').slice(-1)[0].toLowerCase()
  return tlds.top_level_tlds.has(tld)
}

exports.inAddrArpaToIP = (host) => {
  const strippedHost = host.replace(/^\d+(?:\.\d+)?\//, '')
  const arpa = strippedHost.split(/\./).reverse()
  if (arpa.shift() !== 'arpa') return host
  const ip_format = arpa.shift()
  if (ip_format === 'in-addr') {
    if (arpa.length < 4) return host // Only full IP addresses
    host = arpa.join('.')
  } else if (ip_format === 'ip6') {
    if (arpa.length < 32) return host // Only full IP addresses
    host = arpa.join('.')
  }
  return host
}

exports.getIPv4Lookup = function (host, zone, results) {
  if (isTruthy(this.cfg[zone].no_ip_lookups)) {
    results.add(this, {
      skip: `IP (${host}) disabled for ${zone}`,
    })
    return
  }

  if (net_utils.is_private_ip(host)) {
    results.add(this, { skip: 'private IP' })
    return
  }

  return host.split(/\./).reverse().join('.')
}

exports.getIPv6Lookup = function (host, zone, results) {
  if (
    isTruthy(this.cfg[zone].not_ipv6_compatible) ||
    isTruthy(this.cfg[zone].no_ip_lookups)
  ) {
    results.add(this, {
      skip: `IP (${host}) disabled for ${zone}`,
    })
    return
  }

  if (net_utils.is_private_ip(host)) {
    results.add(this, { skip: 'private IP' })
    return
  }

  return net_utils.ipv6_reverse(host)
}

// Resolves to { code, msg } when a host is listed (the caller should DENY),
// or undefined when nothing matched.
exports.do_lookups = async function (connection, hosts, type) {
  const results = connection?.transaction?.results || connection?.results
  if (!results) return

  if (typeof hosts === 'string') hosts = [hosts]

  if (!hosts || !hosts.length) {
    connection.logdebug(this, `(${type}) no items found for lookup`)
    results.add(this, { skip: type })
    return
  }

  connection.logdebug(this, `(${type}) found ${hosts.length} items for lookup`)

  const queries_to_run = this.collectQueries(connection, hosts, type, results)

  if (!queries_to_run.length) {
    results.add(this, { skip: `${type} (no queries)` })
    return
  }

  return this.runQueries(connection, queries_to_run, type, results)
}

// Turn the candidate hosts into a flat [lookup, zone] worklist, recording a
// skip result for every host/zone pair that is filtered out along the way.
exports.collectQueries = function (connection, hosts, type, results) {
  utils.shuffle(hosts)

  const queries = {}
  for (let host of hosts) {
    host = host.toLowerCase()
    connection.logdebug(this, `(${type}) checking: ${host}`)

    if (!this.isValidTLD(host)) continue

    if (this.isExcluded(host)) {
      results.add(this, { skip: `excluded domain:${host}` })
      continue
    }

    for (const zone of this.zones) {
      if (zone === 'main') continue
      if (!this.cfg[zone] || !isTruthy(this.cfg[zone][type])) {
        results.add(this, { skip: `${type} disabled for ${zone}` })
        continue
      }

      const lookup = this.buildLookup(host, zone, results)
      if (!lookup) continue

      if (!queries[zone]) queries[zone] = {}
      if (
        Object.keys(queries[zone]).length >= this.cfg.main.max_uris_per_list
      ) {
        connection.logwarn(
          this,
          `discarding lookup ${lookup} for zone ${zone} maximum query limit reached`,
        )
        results.add(this, { skip: `max query limit for ${zone}` })
        continue
      }
      queries[zone][lookup] = 1
    }
  }

  const queries_to_run = []
  for (const zone of Object.keys(queries)) {
    for (const lookup of Object.keys(queries[zone])) {
      queries_to_run.push([lookup, zone])
    }
  }
  return queries_to_run
}

// Derive the name to look up for one host in one zone, or undefined when the
// host should be skipped for that zone (private/disabled IP, etc).
exports.buildLookup = function (host, zone, results) {
  host = this.inAddrArpaToIP(host)

  let lookup
  if (net.isIPv4(host)) {
    lookup = this.getIPv4Lookup(host, zone, results)
  } else if (net.isIPv6(host)) {
    lookup = this.getIPv6Lookup(host, zone, results)
  } else if (isTruthy(this.cfg[zone].strip_to_domain)) {
    lookup = tlds.split_hostname(host, 3)[1]
  } else {
    lookup = host
  }

  if (!lookup) return
  if (this.cfg[zone].dqs_key) lookup = `${lookup}.${this.cfg[zone].dqs_key}`
  return lookup
}

// Decide what a zone's A record means: 'listed' rejects, 'validate-fail' and
// 'bitmask-miss' ignore the answer.
exports.classifyResult = function (zoneCfg = {}, addrs) {
  if (zoneCfg.validate && !new RegExp(zoneCfg.validate).test(addrs[0])) {
    return 'validate-fail'
  }

  // A bitmask zone returns a single result; we only support a bitmask of up
  // to 128 in a single octet.
  if (zoneCfg.bitmask) {
    const last_octet = Number(addrs[0].split('.')[3])
    return (last_octet & Number(zoneCfg.bitmask)) > 0
      ? 'listed'
      : 'bitmask-miss'
  }

  return 'listed'
}

exports.formatRejectMessage = function (zone, uri) {
  const custom_msg = this.cfg[zone]?.custom_msg
  if (custom_msg) {
    return custom_msg.replace(/\{uri\}/g, uri).replace(/\{zone\}/g, zone)
  }
  return `${uri} blacklisted in ${zone}`
}

// Resolve one zone lookup. Returns { uri, zone } when the host is listed, and
// throws otherwise (DNS miss, failed validation, unmatched bitmask) so
// Promise.any() yields the first hit and discards the rest.
exports.checkQuery = async function (connection, uri, zone) {
  let lookup = `${uri}.${zone}`
  if (lookup[lookup.length - 1] !== '.') lookup = `${lookup}.`

  let addrs
  try {
    addrs = await resolver.resolve4(lookup)
  } catch (err) {
    connection.logdebug(this, `${lookup} => (${err})`)
    throw err
  }
  connection.logdebug(this, `${lookup} => (${addrs.join(', ')})`)

  const verdict = this.classifyResult(this.cfg[zone], addrs)
  if (verdict === 'validate-fail') {
    connection.logwarn(
      this,
      `ignoring result (${addrs[0]}) for: ${lookup} as it did not match validation rule`,
    )
    throw new Error(verdict)
  }
  if (verdict === 'bitmask-miss') {
    connection.logdebug(
      this,
      `ignoring result (${addrs[0]}) for: ${lookup} as the bitmask did not match`,
    )
    throw new Error(verdict)
  }

  connection.loginfo(this, `found ${uri} in zone ${zone} (${addrs.join(',')})`)
  return { uri, zone }
}

exports.runQueries = async function (
  connection,
  queries_to_run,
  type,
  results,
) {
  utils.shuffle(queries_to_run)

  try {
    const { uri, zone } = await Promise.any(
      queries_to_run.map(([uri, zone]) =>
        this.checkQuery(connection, uri, zone),
      ),
    )
    results.add(this, { fail: [type, uri, zone].join('/') })
    return { code: DENY, msg: this.formatRejectMessage(zone, uri) }
  } catch {
    // AggregateError: nothing was listed
    results.add(this, { pass: type })
  }
}

// Race a lookup against the configured timeout. The lookup resolves to a DENY
// payload or undefined; on timeout (or an unexpected error) we resolve
// undefined so the caller continues — a URIBL fails open rather than block mail.
function withTimeout(plugin, connection, type, work) {
  const ms = Math.max(0, (Number(plugin.cfg.main?.timeout) || 30) - 2) * 1000

  let timer
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => {
      connection.logdebug(plugin, 'timeout')
      connection.results.add(plugin, { err: `${type} timeout` })
      resolve()
    }, ms)
  })

  const lookup = Promise.resolve()
    .then(work)
    .catch((err) => {
      connection.results.add(plugin, { err })
    })

  return Promise.race([lookup, timeout]).finally(() => clearTimeout(timer))
}

exports.lookup_remote_ip = async function (next, connection) {
  const result = await withTimeout(this, connection, 'rdns', async () => {
    let rdns
    try {
      rdns = await resolver.reverse(connection.remote.ip)
    } catch (err) {
      // ENOTFOUND covers both NXDOMAIN and a name with no PTR record
      if (err.code !== dns.NOTFOUND) connection.results.add(this, { err })
      return
    }
    this.logdebug(
      `lookup_remote_ip, ${connection.remote.ip} resolves to ${rdns}`,
    )
    return this.do_lookups(connection, rdns, 'rdns')
  })
  next(result?.code, result?.msg)
}

exports.lookup_ehlo = async function (next, connection, helo) {
  const literal = net_utils
    .get_ipany_re('^\\[(?:IPv6:)?', '\\]$', '')
    .exec(helo)
  const host = literal ? literal[1] : helo
  const result = await withTimeout(this, connection, 'helo', () =>
    this.do_lookups(connection, host, 'helo'),
  )
  next(result?.code, result?.msg)
}

exports.lookup_mailfrom = async function (next, connection, params) {
  const result = await withTimeout(this, connection, 'envfrom', () =>
    this.do_lookups(connection, params[0].host, 'envfrom'),
  )
  next(result?.code, result?.msg)
}

exports.enable_body_parsing = (next, connection) => {
  if (connection?.transaction) connection.transaction.parse_body = true
  next()
}

exports.lookup_header_zones = async function (next, connection) {
  const trans = connection.transaction

  const header_hosts = (parse, value) => {
    if (!value) return []
    try {
      return parse(value)
        .map((addr) => addr.host)
        .filter(Boolean)
    } catch {
      return []
    }
  }

  const tasks = []
  const from = header_hosts(parseFrom, trans.header.get_decoded('from'))
  if (from.length) tasks.push([from, 'from'])
  const reply = header_hosts(parseReplyTo, trans.header.get_decoded('reply-to'))
  if (reply.length) tasks.push([reply, 'replyto'])
  const msgid = /@([^@>\s]+)>/.exec(trans.header.get('message-id'))
  if (msgid) tasks.push([[msgid[1]], 'msgid'])
  const urls = {}
  extract_urls(urls, trans.body, connection, this)
  tasks.push([Object.keys(urls), 'body'])

  const result = await withTimeout(this, connection, 'data', async () => {
    for (const [hosts, type] of tasks) {
      const hit = await this.do_lookups(connection, hosts, type)
      if (hit) return hit
    }
  })
  next(result?.code, result?.msg)
}

function extract_urls(urls, body, connection, self) {
  // extract from body.bodytext
  let match
  if (!body || !body.bodytext) {
    return
  }

  let uri
  // extract numeric URIs
  while ((match = numeric_ip.exec(body.bodytext))) {
    try {
      // Don't reverse the IPs here; we do it in the lookup
      uri = new URL(match[0])
      if (uri.hostname) urls[uri.hostname] = uri
    } catch (error) {
      connection.logerror(self, `parse error: ${match[0]} ${error.message}`)
    }
  }

  // match plain hostname.tld
  while ((match = schemeless.exec(body.bodytext))) {
    try {
      uri = new URL(`http://${match[1]}`)
      if (uri.hostname) urls[uri.hostname] = uri
    } catch (error) {
      connection.logerror(self, `parse error: ${match[1]} ${error.message}`)
    }
  }

  // match scheme:// URI
  while ((match = schemed.exec(body.bodytext))) {
    try {
      uri = new URL(match[1])
      if (uri.hostname) urls[uri.hostname] = uri
    } catch (error) {
      connection.logerror(self, `parse error: ${match[1]} ${error.message}`)
    }
  }

  // TODO: URIHASH
  // TODO: MAILHASH

  for (let i = 0, l = body.children.length; i < l; i++) {
    extract_urls(urls, body.children[i], connection, self)
  }
}
