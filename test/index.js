'use strict';

// node.js built-in modules
const assert   = require('assert')
const path     = require('path');

// npm modules
const fixtures = require('haraka-test-fixtures')

// start of tests
//    assert: https://nodejs.org/api/assert.html
//    mocha: http://mochajs.org

beforeEach(function () {
  this.plugin = new fixtures.plugin('uribl')
  this.plugin.config.root_path = path.resolve(__dirname, '../../config');

  this.plugin.register();
})

describe('uribl', function () {
  it('loads', function () {
    assert.ok(this.plugin)
  })
})

describe('load_uribl_ini', function () {
  it('loads uribl.ini from config/uribl.ini', function () {
    this.plugin.load_uribl_ini()
    assert.equal(this.plugin.cfg.main.max_uris_per_list, 20)
  })
})

describe('do_lookups', function () {

  beforeEach(function () {
    this.connection = fixtures.connection.createConnection();
  })

  it('lookup_test_ip: 127.0.0.2', function (done) {
    this.plugin.do_lookups(this.connection, (code, msg) => {
      // no result b/c private IP
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, ['127.0.0.2'], 'body')
  })

  it('lookup_test_ip: test.uribl.com', function (done) {
    this.timeout(4000)
    this.plugin.do_lookups(this.connection, (code, msg) => {
      if (code) console.log(`code: ${code}, ${msg}`)
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      done()
    }, ['test.uribl.com'], 'body')
  })
})

describe('lookup_remote_ip', function () {
  beforeEach(function () {
    this.connection = fixtures.connection.createConnection();
  })

  it('lookup_remote_ip: 66.128.51.165', function (done) {
    this.connection.remote.ip = '66.128.51.165'
    this.plugin.lookup_remote_ip((code, msg) => {
      assert.equal(code, undefined)
      assert.equal(msg, undefined)
      // console.log(`test, code: ${code}, msg: ${msg}`)
      done()
    }, this.connection)
  })
})
