'use strict'

// node.js built-in modules
const assert = require('node:assert')
const path = require('node:path')
const { beforeEach, describe, it } = require('node:test')

// npm modules
const { makeConnection, makePlugin } = require('haraka-test-fixtures')

// start of tests
//    assert: https://nodejs.org/api/assert.html
//    mocha: http://mochajs.org

let plugin, connection

beforeEach(() => {
  plugin = makePlugin('uribl', {
    configDir: path.resolve(__dirname, '../../config'),
  })
})

describe('uribl', () => {
  it('loads', () => {
    assert.ok(plugin)
  })
})

describe('load_uribl_ini', () => {
  it('loads uribl.ini from config/uribl.ini', () => {
    plugin.load_uribl_ini()
    assert.equal(plugin.cfg.main.max_uris_per_list, 20)
  })
})

describe('do_lookups', () => {
  beforeEach(() => {
    connection = makeConnection()
  })

  it('lookup_test_ip: 127.0.0.2', async () => {
    await new Promise((resolve) => {
      plugin.do_lookups(
        connection,
        (code, msg) => {
          // no result b/c private IP
          assert.equal(code, undefined)
          assert.equal(msg, undefined)
          resolve()
        },
        ['127.0.0.2'],
        'body',
      )
    })
  })

  it('lookup_test_ip: test.uribl.com', { timeout: 4000 }, async () => {
    await new Promise((resolve) => {
      plugin.do_lookups(
        connection,
        (code, msg) => {
          if (code) console.log(`code: ${code}, ${msg}`)
          assert.equal(code, undefined)
          assert.equal(msg, undefined)
          resolve()
        },
        ['test.uribl.com'],
        'body',
      )
    })
  })
})

describe('lookup_remote_ip', () => {
  beforeEach(() => {
    connection = makeConnection()
  })

  it('lookup_remote_ip: 66.128.51.165', async () => {
    connection.remote.ip = '66.128.51.165'
    await new Promise((resolve) => {
      plugin.lookup_remote_ip((code, msg) => {
        assert.equal(code, undefined)
        assert.equal(msg, undefined)
        // console.log(`test, code: ${code}, msg: ${msg}`)
        resolve()
      }, connection)
    })
  })
})
