'use strict'

// assert: https://nodejs.org/api/assert.html
const assert = require('node:assert')
const dns = require('node:dns')
const { before, after, beforeEach, describe, it } = require('node:test')

const net_utils = require('haraka-net-utils')
const tlds = require('haraka-tld')
const {
  makeConnection,
  makePlugin,
  callHook,
  callConnect,
  getResult,
} = require('haraka-test-fixtures')

let plugin, connection

beforeEach(() => {
  plugin = makePlugin('uribl', { configDir: __dirname })
})

describe('uribl', () => {
  it('loads', () => {
    assert.ok(plugin)
  })

  it('load_uribl_ini', () => {
    plugin.load_uribl_ini()
    assert.equal(plugin.cfg.main.max_uris_per_list, 20)
  })

  it('load_uribl_exludes', () => {
    plugin.load_uribl_exludes()
    assert.deepEqual(plugin.excludes, new Set(['test.com']))
  })
})

describe('register', () => {
  it('buildExtractRegexps is a no-op until the TLD set loads', () => {
    const saved = tlds.top_level_tlds
    tlds.top_level_tlds = new Set()
    try {
      assert.doesNotThrow(() => plugin.buildExtractRegexps())
    } finally {
      tlds.top_level_tlds = saved
    }
  })

  it('buildExtractRegexps rebuilds from the TLD set', () => {
    const saved = tlds.top_level_tlds
    tlds.top_level_tlds = new Set(['com', 'net', 'example'])
    try {
      assert.doesNotThrow(() => plugin.buildExtractRegexps())
    } finally {
      tlds.top_level_tlds = saved
    }
  })

  it('aborts and registers no hooks when no zones are configured', () => {
    const p = makePlugin('uribl', { configDir: __dirname, register: false })
    p.load_uribl_ini = function () {
      this.cfg = { main: {} }
      this.zones = []
    }
    p.load_uribl_exludes = function () {
      this.excludes = new Set()
    }
    let logged
    p.logerror = (msg) => {
      logged = msg
    }
    p.register()
    assert.match(logged, /no zones/)
    assert.deepEqual(p.hooks, {})
  })
})

describe('isExcluded', () => {
  const positiveTests = ['test.com', 'example.test.com']
  const negativeTests = ['example.com', 'test.example.com']

  for (const domain of positiveTests) {
    it(`isExcluded: ${domain}`, () => {
      assert.equal(plugin.isExcluded(domain), true)
    })
  }

  for (const domain of negativeTests) {
    it(`isExcluded: ${domain}`, () => {
      assert.equal(plugin.isExcluded(domain), false)
    })
  }
})

describe('inAddrArpaToIP', () => {
  const testCases = [
    { '165.160/27.51.128.66.in-addr.arpa': '66.128.51.27' },
    { '61.133.210.138.in-addr.arpa': '138.210.133.61' },
    {
      '2.0.0.0.0.0.0.0.0.0.0.0.a.0.0.0.5.9.1.0.b.0.0.0.0.7.4.0.1.0.0.2.ip6.arpa':
        '2.0.0.1.0.4.7.0.0.0.0.b.0.1.9.5.0.0.0.a.0.0.0.0.0.0.0.0.0.0.0.2',
    },
  ]

  for (const testCase of testCases) {
    for (const [ip, host] of Object.entries(testCase)) {
      it(`inAddrArpaToIP: ${ip}`, () => {
        assert.equal(plugin.inAddrArpaToIP(ip), host)
      })
    }
  }

  it('returns non-arpa hosts unchanged', () => {
    assert.equal(plugin.inAddrArpaToIP('example.com'), 'example.com')
  })

  it('leaves partial in-addr.arpa names alone', () => {
    assert.equal(plugin.inAddrArpaToIP('1.2.in-addr.arpa'), '1.2.in-addr.arpa')
  })

  it('only strips a real numeric CIDR prefix (escaped dot)', () => {
    assert.equal(
      plugin.inAddrArpaToIP('1a2/3.4.5.6.in-addr.arpa'),
      '6.5.4.1a2/3',
    )
  })

  it('runs in linear time on long numeric input', () => {
    const evil = `${'9'.repeat(50000)}a`
    const start = process.hrtime.bigint()
    plugin.inAddrArpaToIP(evil)
    const ms = Number(process.hrtime.bigint() - start) / 1e6
    assert.ok(ms < 100, `inAddrArpaToIP took ${ms}ms`)
  })
})

describe('getIPv4Lookup', () => {
  beforeEach(() => {
    connection = makeConnection()
  })

  it('reverses a public address', () => {
    assert.equal(
      plugin.getIPv4Lookup('1.2.3.4', 'multi.uribl.com', connection.results),
      '4.3.2.1',
    )
  })

  it('skips when no_ip_lookups is set', () => {
    assert.equal(
      plugin.getIPv4Lookup('1.2.3.4', 'dbl.spamhaus.org', connection.results),
      undefined,
    )
    assert.ok(
      getResult(connection, plugin).skip.some((s) => /disabled/.test(s)),
    )
  })

  it('skips private addresses', () => {
    assert.equal(
      plugin.getIPv4Lookup(
        '192.168.1.1',
        'multi.uribl.com',
        connection.results,
      ),
      undefined,
    )
    assert.ok(getResult(connection, plugin).skip.includes('private IP'))
  })
})

describe('getIPv6Lookup', () => {
  beforeEach(() => {
    connection = makeConnection()
  })

  it('reverses a public address', () => {
    assert.equal(
      plugin.getIPv6Lookup(
        '2001:db8::1',
        'multi.uribl.com',
        connection.results,
      ),
      net_utils.ipv6_reverse('2001:db8::1'),
    )
  })

  it('skips when the zone is not ipv6 compatible', () => {
    plugin.cfg['multi.uribl.com'].not_ipv6_compatible = '1'
    try {
      assert.equal(
        plugin.getIPv6Lookup(
          '2001:db8::1',
          'multi.uribl.com',
          connection.results,
        ),
        undefined,
      )
    } finally {
      delete plugin.cfg['multi.uribl.com'].not_ipv6_compatible
    }
  })

  it('skips when no_ip_lookups is set', () => {
    assert.equal(
      plugin.getIPv6Lookup(
        '2001:db8::1',
        'dbl.spamhaus.org',
        connection.results,
      ),
      undefined,
    )
  })

  it('skips private addresses', () => {
    assert.equal(
      plugin.getIPv6Lookup('::1', 'multi.uribl.com', connection.results),
      undefined,
    )
    assert.ok(getResult(connection, plugin).skip.includes('private IP'))
  })
})

describe('isValidTLD', () => {
  before(async () => {
    await tlds.ready
  })

  it('accepts a recognized TLD', () => {
    assert.equal(plugin.isValidTLD('example.com'), true)
  })

  it('accepts a modern gTLD', () => {
    assert.equal(plugin.isValidTLD('example.xyz'), true)
  })

  it('rejects an unrecognized TLD', () => {
    assert.equal(plugin.isValidTLD('host.invalidtld'), false)
  })

  it('rejects an IPv4 address', () => {
    assert.equal(plugin.isValidTLD('1.2.3.4'), false)
  })

  it('rejects an IPv6 address', () => {
    assert.equal(plugin.isValidTLD('2001:db8::1'), false)
  })

  it('falls open while the TLD set is still loading', () => {
    const saved = tlds.top_level_tlds
    tlds.top_level_tlds = new Set()
    try {
      assert.equal(plugin.isValidTLD('host.invalidtld'), true)
    } finally {
      tlds.top_level_tlds = saved
    }
  })
})

describe('classifyResult', () => {
  it('lists when there is no validation or bitmask', () => {
    assert.equal(plugin.classifyResult({}, ['127.0.0.2']), 'listed')
  })

  it('defaults a missing zone config to listed', () => {
    assert.equal(plugin.classifyResult(undefined, ['127.0.0.2']), 'listed')
  })

  it('lists when validation passes', () => {
    assert.equal(
      plugin.classifyResult({ validate: '^127' }, ['127.0.0.2']),
      'listed',
    )
  })

  it('ignores when validation fails', () => {
    assert.equal(
      plugin.classifyResult({ validate: '^127' }, ['10.0.0.1']),
      'validate-fail',
    )
  })

  it('validation failure wins over a matching bitmask', () => {
    assert.equal(
      plugin.classifyResult({ validate: '^127', bitmask: '2' }, ['10.0.0.2']),
      'validate-fail',
    )
  })

  it('lists when the bitmask matches', () => {
    assert.equal(
      plugin.classifyResult({ bitmask: '2' }, ['127.0.0.2']),
      'listed',
    )
  })

  it('ignores when the bitmask does not match', () => {
    assert.equal(
      plugin.classifyResult({ bitmask: '2' }, ['127.0.0.1']),
      'bitmask-miss',
    )
  })
})

describe('formatRejectMessage', () => {
  it('uses a default message when the zone has none', () => {
    assert.equal(
      plugin.formatRejectMessage('multi.surbl.org', 'example.com'),
      'example.com blacklisted in multi.surbl.org',
    )
  })

  it('interpolates {uri} and {zone} into a custom message', () => {
    assert.equal(
      plugin.formatRejectMessage('multi.uribl.com', 'example.com'),
      'example.com listed in multi.uribl.com; see http://lookup.uribl.com/?domain=example.com',
    )
  })
})

describe('buildLookup', () => {
  before(async () => {
    await tlds.ready
  })

  beforeEach(() => {
    connection = makeConnection()
  })

  it('returns the host unchanged for a plain zone', () => {
    assert.equal(
      plugin.buildLookup(
        'foo.example.com',
        'dbl.spamhaus.org',
        connection.results,
      ),
      'foo.example.com',
    )
  })

  it('strips to the registered domain when configured', () => {
    assert.equal(
      plugin.buildLookup(
        'foo.example.com',
        'multi.uribl.com',
        connection.results,
      ),
      'example.com',
    )
  })

  it('appends a configured dqs_key', () => {
    plugin.cfg['multi.surbl.org'].dqs_key = 'key123'
    try {
      assert.equal(
        plugin.buildLookup(
          'foo.example.com',
          'multi.surbl.org',
          connection.results,
        ),
        'example.com.key123',
      )
    } finally {
      delete plugin.cfg['multi.surbl.org'].dqs_key
    }
  })

  it('reverses an IPv4 derived from in-addr.arpa', () => {
    assert.equal(
      plugin.buildLookup(
        '61.133.210.138.in-addr.arpa',
        'multi.uribl.com',
        connection.results,
      ),
      '61.133.210.138',
    )
  })

  it('reverses an IPv6 host', () => {
    assert.equal(
      plugin.buildLookup('2001:db8::1', 'multi.uribl.com', connection.results),
      net_utils.ipv6_reverse('2001:db8::1'),
    )
  })

  it('returns undefined when the IP is skipped for the zone', () => {
    assert.equal(
      plugin.buildLookup(
        '4.3.2.1.in-addr.arpa',
        'dbl.spamhaus.org',
        connection.results,
      ),
      undefined,
    )
  })
})

describe('do_lookups', () => {
  beforeEach(() => {
    connection = makeConnection()
  })

  it('lookup_test_ip: 127.0.0.2', async () => {
    const result = await plugin.do_lookups(connection, ['127.0.0.2'], 'body')
    assert.equal(result, undefined)
  })

  it('lookup_test_ip: test.uribl.com', { timeout: 4000 }, async () => {
    const result = await plugin.do_lookups(
      connection,
      ['test.uribl.com'],
      'body',
    )
    assert.equal(result, undefined)
  })

  it('lookup_remote_ip: 66.128.51.165', async () => {
    const { rc, msg } = await callConnect(
      plugin,
      makeConnection({ ip: '66.128.51.165' }),
      'lookup_remote_ip',
    )
    assert.equal(rc, undefined)
    assert.equal(msg, undefined)
  })
})

// These tests drive the plugin's real node:dns queries at a local DNS server
// (haraka-test-fixtures' fixtures.dns) so the lookup/answer paths are
// deterministic without stubbing the resolver.
describe('do_lookups (local resolver)', () => {
  let dnsServer
  let savedServers

  before(async () => {
    await tlds.ready
    dnsServer = await require('haraka-test-fixtures').dns.start()
    savedServers = dns.getServers()
    dns.setServers([`127.0.0.1:${dnsServer.port}`])
  })

  after(async () => {
    dns.setServers(savedServers)
    await dnsServer.close()
  })

  beforeEach(() => {
    dnsServer.clearZones()
    connection = makeConnection()
  })

  const runLookups = async (hosts, type) => {
    const result = await plugin.do_lookups(connection, hosts, type)
    return [result?.code, result?.msg]
  }

  it('skips when there are no hosts', async () => {
    const [code] = await runLookups([], 'body')
    assert.equal(code, undefined)
    assert.ok(getResult(connection, plugin).skip.includes('body'))
  })

  it('accepts a bare string host', async () => {
    const [code] = await runLookups('clean.example.com', 'body')
    assert.equal(code, undefined)
  })

  it('skips excluded domains', async () => {
    const [code] = await runLookups(['test.com'], 'body')
    assert.equal(code, undefined)
    assert.ok(
      getResult(connection, plugin).skip.some((s) =>
        s.startsWith('excluded domain'),
      ),
    )
  })

  it('skips zones where the type is disabled', async () => {
    const [code] = await runLookups(['ehlo.example.com'], 'helo')
    assert.equal(code, undefined)
    assert.ok(
      getResult(connection, plugin).skip.some((s) =>
        s.startsWith('helo disabled'),
      ),
    )
  })

  it('passes when nothing is listed', async () => {
    const [code] = await runLookups(['clean.example.com'], 'body')
    assert.equal(code, undefined)
    assert.ok(getResult(connection, plugin).pass.includes('body'))
  })

  it('rejects with a custom message on a bitmask match', async () => {
    dnsServer.setZone('example.com.multi.uribl.com', { a: ['127.0.0.2'] })
    const [code, msg] = await runLookups(['black.example.com'], 'body')
    assert.equal(code, DENY)
    assert.match(msg, /example\.com listed in multi\.uribl\.com/)
  })

  it('does not record a pass once it has rejected', async () => {
    dnsServer.setZone('example.com.multi.uribl.com', { a: ['127.0.0.2'] })
    const [code] = await runLookups(['black.example.com'], 'body')
    assert.equal(code, DENY)
    assert.equal(getResult(connection, plugin).pass.length, 0)
  })

  it('rejects with a default message on a plain match', async () => {
    dnsServer.setZone('example.com.multi.surbl.org', { a: ['127.0.0.2'] })
    const [code, msg] = await runLookups(['plain.example.com'], 'body')
    assert.equal(code, DENY)
    assert.match(msg, /example\.com blacklisted in multi\.surbl\.org/)
  })

  it('ignores results that fail the validation regexp', async () => {
    dnsServer.setZone('example.com.multi.surbl.org', { a: ['10.0.0.1'] })
    const [code] = await runLookups(['novalidate.example.com'], 'body')
    assert.equal(code, undefined)
  })

  it('ignores results when the bitmask does not match', async () => {
    dnsServer.setZone('example.com.multi.uribl.com', { a: ['127.0.0.1'] })
    const [code] = await runLookups(['nomatch.example.com'], 'body')
    assert.equal(code, undefined)
  })

  it('reverses and queries an IPv4 from in-addr.arpa', async () => {
    dnsServer.setZone('61.133.210.138.multi.uribl.com', { a: ['127.0.0.2'] })
    const [code] = await runLookups(['61.133.210.138.in-addr.arpa'], 'body')
    assert.equal(code, DENY)
  })

  it('skips a private IPv4 from in-addr.arpa', async () => {
    const [code] = await runLookups(['1.0.168.192.in-addr.arpa'], 'body')
    assert.equal(code, undefined)
    assert.ok(getResult(connection, plugin).skip.includes('private IP'))
  })

  it('appends a dqs_key to the lookup', async () => {
    plugin.cfg['multi.surbl.org'].dqs_key = 'key123'
    dnsServer.setZone('example.com.key123.multi.surbl.org', {
      a: ['127.0.0.2'],
    })
    try {
      const [code] = await runLookups(['dqs.example.com'], 'body')
      assert.equal(code, DENY)
    } finally {
      delete plugin.cfg['multi.surbl.org'].dqs_key
    }
  })

  it('discards lookups beyond max_uris_per_list', async () => {
    plugin.cfg.main.max_uris_per_list = 1
    try {
      const [code] = await runLookups(['a.one.com', 'b.two.com'], 'body')
      assert.equal(code, undefined)
      assert.ok(
        getResult(connection, plugin).skip.some((s) =>
          s.startsWith('max query limit'),
        ),
      )
    } finally {
      plugin.cfg.main.max_uris_per_list = 20
    }
  })

  describe('hooks', () => {
    it('lookup_mailfrom rejects a listed sender domain', async () => {
      dnsServer.setZone('mail.example.com.dbl.spamhaus.org', {
        a: ['127.0.0.2'],
      })
      const { rc } = await callHook(plugin, 'lookup_mailfrom', connection, [
        { host: 'mail.example.com' },
      ])
      assert.equal(rc, DENY)
    })

    it('lookup_ehlo handles an IP literal', async () => {
      const { rc } = await callHook(
        plugin,
        'lookup_ehlo',
        connection,
        '[1.2.3.4]',
      )
      assert.equal(rc, undefined)
    })

    it('lookup_ehlo rejects a listed hostname', async () => {
      dnsServer.setZone('helo.example.com.dbl.spamhaus.org', {
        a: ['127.0.0.2'],
      })
      const { rc } = await callHook(
        plugin,
        'lookup_ehlo',
        connection,
        'helo.example.com',
      )
      assert.equal(rc, DENY)
    })

    it('lookup_remote_ip continues when the rDNS lookup fails', async () => {
      const conn = makeConnection({ ip: '203.0.113.7' })
      const { rc } = await callHook(plugin, 'lookup_remote_ip', conn)
      assert.equal(rc, undefined)
    })

    it('lookup_remote_ip continues on NXDOMAIN', async () => {
      dnsServer.setZone('7.113.0.203.in-addr.arpa', { rcode: 'NXDOMAIN' })
      const conn = makeConnection({ ip: '203.0.113.7' })
      const { rc } = await callHook(plugin, 'lookup_remote_ip', conn)
      assert.equal(rc, undefined)
    })

    it('enable_body_parsing sets parse_body on the transaction', async () => {
      const conn = makeConnection({ withTxn: true })
      await new Promise((next) => plugin.enable_body_parsing(next, conn))
      assert.equal(conn.transaction.parse_body, true)
    })

    it('enable_body_parsing tolerates a missing transaction', async () => {
      const conn = makeConnection()
      await new Promise((next) => plugin.enable_body_parsing(next, conn))
    })

    it('lookup_header_zones walks headers and the body', async () => {
      dnsServer.setZone('example.com.multi.uribl.com', { a: ['127.0.0.2'] })
      const conn = makeConnection({ withTxn: true })
      const { header } = conn.transaction
      header.add('From', 'Bob <bob@from.example.com>')
      header.add('Reply-To', 'reply@replyto.example.com')
      header.add('Message-ID', '<abc@msgid.example.com>')
      conn.transaction.body = {
        bodytext:
          'see http://spam.example.com/path, www.foo.example.org and http://192.0.2.5/img',
        children: [{ bodytext: 'http://deep.example.net/', children: [] }],
      }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, DENY)
    })

    it('lookup_header_zones passes with no headers or URLs', async () => {
      const conn = makeConnection({ withTxn: true })
      conn.transaction.body = { bodytext: '', children: [] }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, undefined)
    })

    it('extracts the real From domain despite a poisoned display name', async () => {
      dnsServer.setZone('real.example.com.dbl.spamhaus.org', {
        a: ['127.0.0.2'],
      })
      const conn = makeConnection({ withTxn: true })
      conn.transaction.header.add(
        'From',
        '"x@junk.example" <bob@real.example.com>',
      )
      conn.transaction.body = { bodytext: '', children: [] }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, DENY)
    })

    it('checks every address in a multi-address From header', async () => {
      dnsServer.setZone('second.example.com.dbl.spamhaus.org', {
        a: ['127.0.0.2'],
      })
      const conn = makeConnection({ withTxn: true })
      conn.transaction.header.add(
        'From',
        'A <a@first.example.com>, B <b@second.example.com>',
      )
      conn.transaction.body = { bodytext: '', children: [] }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, DENY)
    })

    it('extracts the Message-ID domain after the last @', async () => {
      dnsServer.setZone('real.example.com.dbl.spamhaus.org', {
        a: ['127.0.0.2'],
      })
      const conn = makeConnection({ withTxn: true })
      conn.transaction.header.add('Message-ID', '<a@b@real.example.com>')
      conn.transaction.body = { bodytext: '', children: [] }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, DENY)
    })

    it('tolerates an unparseable From header', async () => {
      const conn = makeConnection({ withTxn: true })
      conn.transaction.header.add('From', 'garbage no address here')
      conn.transaction.body = { bodytext: '', children: [] }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, undefined)
    })

    it('extracts body URLs on modern gTLDs (rebuilt regexps)', async () => {
      dnsServer.setZone('black.xyz.multi.uribl.com', { a: ['127.0.0.2'] })
      const conn = makeConnection({ withTxn: true })
      conn.transaction.body = {
        bodytext: 'visit http://black.xyz/promo today',
        children: [],
      }
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      assert.equal(rc, DENY)
    })

    it('extracts body URLs quickly on adversarial slash runs', async () => {
      const conn = makeConnection({ withTxn: true })
      conn.transaction.body = {
        bodytext: `http:${'/'.repeat(40000)}a@ and more text`,
        children: [],
      }
      const start = process.hrtime.bigint()
      const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
      const ms = Number(process.hrtime.bigint() - start) / 1e6
      assert.equal(rc, undefined)
      assert.ok(ms < 500, `body extraction took ${ms}ms`)
    })

    it('treats timeout="0" as the default, not an immediate fire', async () => {
      plugin.cfg.main.timeout = '0'
      try {
        const { rc } = await callHook(plugin, 'lookup_mailfrom', connection, [
          { host: 'clean.example.com' },
        ])
        assert.equal(rc, undefined)
        assert.ok(
          !getResult(connection, plugin).err.some((e) => /timeout/.test(e)),
        )
      } finally {
        delete plugin.cfg.main.timeout
      }
    })

    it('continues (fail-open) when a lookup rejects', async () => {
      plugin.do_lookups = async () => {
        throw new Error('boom')
      }
      const { rc } = await callHook(plugin, 'lookup_mailfrom', connection, [
        { host: 'x.example.com' },
      ])
      assert.equal(rc, undefined)
      assert.ok(getResult(connection, plugin).err.some((e) => /boom/.test(e)))
    })

    it('times out when lookups do not complete in time', async () => {
      plugin.cfg.main.timeout = 2 // (2 - 2) * 1000 => fire on next tick
      const delayMs = 100
      dnsServer.setZone('example.com.multi.uribl.com', {
        a: ['127.0.0.2'],
        delayMs,
      })
      dnsServer.setZone('example.com.multi.surbl.org', {
        a: ['127.0.0.2'],
        delayMs,
      })
      const conn = makeConnection({ withTxn: true })
      conn.transaction.body = {
        bodytext: 'http://slow.example.com/',
        children: [],
      }
      try {
        const { rc } = await callHook(plugin, 'lookup_header_zones', conn)
        assert.equal(rc, undefined)
        assert.ok(getResult(conn, plugin).err.some((e) => /timeout/.test(e)))

        // let the delayed answers land so they don't outlive the DNS server
        await new Promise((r) => setTimeout(r, delayMs * 3))
      } finally {
        delete plugin.cfg.main.timeout
      }
    })
  })
})
