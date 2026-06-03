// Look up URLs in SURBL

const url = require('node:url')
const dns = require('node:dns')
const net = require('node:net')

const tlds = require('haraka-tld')
const net_utils = require('haraka-net-utils')
const utils = require('haraka-utils')

// Default regexps to extract the URIs from the message
const numeric_ip =
  /\w{3,16}:\/+(\S+@)?(\d+|0[xX][0-9A-Fa-f]+)\.(\d+|0[xX][0-9A-Fa-f]+)\.(\d+|0[xX][0-9A-Fa-f]+)\.(\d+|0[xX][0-9A-Fa-f]+)/gi
let schemeless =
  /(?:%(?:25)?(?:2F|3D|40))?((?:www\.)?[a-zA-Z0-9][a-zA-Z0-9\-.]{0,250}\.(?:aero|arpa|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|[a-zA-Z]{2}))(?!\w)/gi
let schemed =
  /(\w{3,16}:\/+(?:\S+@)?([a-zA-Z0-9][a-zA-Z0-9\-.]+\.(?:aero|arpa|asia|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|xxx|[a-zA-Z]{2})))(?!\w)/gi
const isTruthy = (val) => /^(?:1|true|yes|enabled|on)$/i.test(val)

exports.register = function () {
  // Override regexps if top_level_tlds file is present
  if (tlds.top_level_tlds && Object.keys(tlds.top_level_tlds).length) {
    this.logdebug('Building new regexps from TLD file')
    const re_schemeless = `(?:%(?:25)?(?:2F|3D|40))?((?:www\\.)?[a-zA-Z0-9][a-zA-Z0-9\\-.]{0,250}\\.(?:${Object.keys(tlds.top_level_tlds).join('|')}))(?!\\w)`
    schemeless = new RegExp(re_schemeless, 'gi')
    const re_schemed = `(\\w{3,16}:\\/+(?:\\S+@)?([a-zA-Z0-9][a-zA-Z0-9\\-.]+\\.(?:${Object.keys(tlds.top_level_tlds).join('|')})))(?!\\w)`
    schemed = new RegExp(re_schemed, 'gi')
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
  const tld = host.split('.').slice(-1)[0]
  return !net.isIPv4(host) && !net.isIPv6(host) && !tlds.top_level_tlds[tld]
}

exports.inAddrArpaToIP = (host) => {
  const strippedHost = host.replace(/^\d+(?:.\d+)?\//, '')
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

exports.do_lookups = function (connection, next, hosts, type) {
  const results = connection?.transaction?.results || connection?.results
  if (!results) return next()

  if (typeof hosts === 'string') hosts = [hosts]

  if (!hosts || !hosts.length) {
    connection.logdebug(this, `(${type}) no items found for lookup`)
    results.add(this, { skip: type })
    return next()
  }

  connection.logdebug(this, `(${type}) found ${hosts.length} items for lookup`)

  const queries_to_run = this.collectQueries(connection, hosts, type, results)

  if (!queries_to_run.length) {
    results.add(this, { skip: `${type} (no queries)` })
    return next()
  }

  this.runQueries(connection, next, queries_to_run, type, results)
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

exports.runQueries = function (
  connection,
  next,
  queries_to_run,
  type,
  results,
) {
  const plugin = this
  utils.shuffle(queries_to_run)

  let pending_queries = 0
  let called_next = false
  function nextOnce(code, msg) {
    if (called_next) return
    called_next = true
    next(code, msg)
  }

  const conclude_if_no_pending = () => {
    if (pending_queries !== 0) return
    results.add(plugin, { pass: type })
    nextOnce()
  }

  for (const [uri, zone] of queries_to_run) {
    let lookup = `${uri}.${zone}`
    if (lookup[lookup.length - 1] !== '.') lookup = `${lookup}.`

    pending_queries++
    dns.resolve4(lookup, (err, addrs) => {
      pending_queries--
      connection.logdebug(
        plugin,
        `${lookup} => (${err ? err : addrs.join(', ')})`,
      )

      if (err) return conclude_if_no_pending()

      switch (plugin.classifyResult(plugin.cfg[zone], addrs)) {
        case 'listed':
          if (!called_next) {
            connection.loginfo(
              plugin,
              `found ${uri} in zone ${zone} (${addrs.join(',')})`,
            )
            results.add(plugin, { fail: [type, uri, zone].join('/') })
            nextOnce(DENY, plugin.formatRejectMessage(zone, uri))
          }
          break
        case 'validate-fail':
          connection.logwarn(
            plugin,
            `ignoring result (${addrs[0]}) for: ${lookup} as it did not match validation rule`,
          )
          break
        case 'bitmask-miss':
          connection.logdebug(
            plugin,
            `ignoring result (${addrs[0]}) for: ${lookup} as the bitmask did not match`,
          )
          break
      }

      conclude_if_no_pending()
    })
  }

  conclude_if_no_pending()
}

function getTimedNext(plugin, connection, next, type) {
  let timer
  let calledNext = false

  function timedNextOnce(code, msg) {
    clearTimeout(timer)
    if (calledNext) return
    calledNext = true
    next(code, msg)
  }

  timer = setTimeout(
    () => {
      connection.logdebug(plugin, 'timeout')
      connection.results.add(plugin, { err: `${type} timeout` })
      timedNextOnce()
    },
    ((plugin.cfg.main?.timeout || 30) - 2) * 1000,
  )

  return timedNextOnce
}

exports.lookup_remote_ip = function (next, connection) {
  const timedNext = getTimedNext(this, connection, next, 'rdns')

  dns.reverse(connection.remote.ip, (err, rdns) => {
    if (err) {
      switch (err.code) {
        case dns.NXDOMAIN:
        case dns.NOTFOUND:
          break
        default:
          connection.results.add(this, { err })
      }
      return timedNext()
    }
    this.logdebug(
      `lookup_remote_ip, ${connection.remote.ip} resolves to ${rdns}`,
    )
    this.do_lookups(connection, timedNext, rdns, 'rdns')
  })
}

exports.lookup_ehlo = function (next, connection, helo) {
  const timedNext = getTimedNext(this, connection, next, 'helo')

  // Handle IP literals
  let literal
  if (
    (literal = net_utils.get_ipany_re('^\\[(?:IPv6:)?', '\\]$', '').exec(helo))
  ) {
    this.do_lookups(connection, timedNext, literal[1], 'helo')
  } else {
    this.do_lookups(connection, timedNext, helo, 'helo')
  }
}

exports.lookup_mailfrom = function (next, connection, params) {
  const timedNext = getTimedNext(this, connection, next, 'envfrom')
  this.do_lookups(connection, timedNext, params[0].host, 'envfrom')
}

exports.enable_body_parsing = (next, connection) => {
  if (connection?.transaction) {
    connection.transaction.parse_body = true
  }
  next()
}

exports.lookup_header_zones = function (next, connection) {
  const email_re = /<?[^@]+@([^> ]+)>?/
  const plugin = this
  const trans = connection.transaction
  const timedNext = getTimedNext(this, connection, next, 'data')

  function do_from_header(cb) {
    const fmatch = email_re.exec(trans.header.get_decoded('from'))
    if (fmatch) {
      return plugin.do_lookups(connection, cb, fmatch[1], 'from')
    }
    cb()
  }

  function do_replyto_header(cb) {
    const rmatch = email_re.exec(trans.header.get('reply-to'))
    if (rmatch) {
      return plugin.do_lookups(connection, cb, rmatch[1], 'replyto')
    }
    cb()
  }

  function do_msgid_header(cb) {
    const mmatch = /@([^>]+)>/.exec(trans.header.get('message-id'))
    if (mmatch) {
      return plugin.do_lookups(connection, cb, mmatch[1], 'msgid')
    }
    cb()
  }

  function do_body(cb) {
    const urls = {}
    extract_urls(urls, trans.body, connection, plugin)
    plugin.do_lookups(connection, cb, Object.keys(urls), 'body')
  }

  const chain = [do_from_header, do_replyto_header, do_msgid_header, do_body]
  function chain_caller(code, msg) {
    if (code) return timedNext(code, msg)

    if (!chain.length) return timedNext()

    const next_in_chain = chain.shift()
    next_in_chain(chain_caller)
  }
  chain_caller()
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
      uri = url.parse(match[0])
      // Don't reverse the IPs here; we do it in the lookup
      urls[uri.hostname] = uri
    } catch (error) {
      connection.logerror(self, `parse error: ${match[0]} ${error.message}`)
    }
  }

  // match plain hostname.tld
  while ((match = schemeless.exec(body.bodytext))) {
    try {
      uri = url.parse(`http://${match[1]}`)
      urls[uri.hostname] = uri
    } catch (error) {
      connection.logerror(self, `parse error: ${match[1]} ${error.message}`)
    }
  }

  // match scheme:// URI
  while ((match = schemed.exec(body.bodytext))) {
    try {
      uri = url.parse(match[1])
      urls[uri.hostname] = uri
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
