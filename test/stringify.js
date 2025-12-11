'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const crypto = require('crypto')
const fs = require('fs')

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

test('serializes Integrity-likes', () => {
  const sriLike = {
    sha512: [{
      digest: 'foo',
      algorithm: 'sha512',
      options: ['ayy', 'woo'],
    }, {
      digest: 'bar',
      algorithm: 'sha512',
    }],
    whirlpool: [{
      digest: 'wut',
      algorithm: 'whirlpool',
    }],
  }
  assert.strictEqual(
    ssri.stringify(sriLike),
    'sha512-foo?ayy?woo sha512-bar whirlpool-wut',
    'stringification contains correct data for all entries'
  )
})

test('serializes Hash-likes', () => {
  const sriLike = {
    digest: 'foo',
    algorithm: 'sha512',
  }
  assert.strictEqual(
    ssri.stringify(sriLike),
    'sha512-foo',
    'serialization has correct data'
  )
})

test('serialized plain strings into a valid parsed version', () => {
  const sri = ' \tsha512-foo?bar    \n\n\nsha1-nope\r'
  assert.strictEqual(
    ssri.stringify(sri),
    'sha512-foo?bar sha1-nope',
    'cleaned-up string with identical contents generated'
  )
})

test('accepts a separator opt', () => {
  const sriLike = {
    sha512: [{
      algorithm: 'sha512',
      digest: 'foo',
    }, {
      algorithm: 'sha512',
      digest: 'bar',
    }],
  }
  assert.strictEqual(
    ssri.stringify(sriLike, { sep: '\n' }),
    'sha512-foo\nsha512-bar'
  )
  assert.strictEqual(
    ssri.stringify(sriLike, { sep: ' | ' }),
    'sha512-foo | sha512-bar'
  )
})

test('support strict serialization', () => {
  const sriLike = {
    // only sha256, sha384, and sha512 are allowed by the spec
    sha1: [{
      algorithm: 'sha1',
      digest: 'feh',
    }],
    sha256: [{
      algorithm: 'sha256',
      // Must be valid base64
      digest: 'wut!!!??!!??!',
    }, {
      algorithm: 'sha256',
      digest: hash(TEST_DATA, 'sha256'),
      options: ['foo'],
    }],
    sha512: [{
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
      // Options must use VCHAR
      options: ['\x01'],
    }],
  }
  assert.strictEqual(
    ssri.stringify(sriLike, { strict: true }),
    `sha256-${hash(TEST_DATA, 'sha256')}?foo`,
    'entries that do not conform to strict spec interpretation removed'
  )
  assert.strictEqual(
    /* eslint-disable-next-line max-len */
    ssri.stringify('sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=', { sep: ' \r|\n\t', strict: true }),
    /* eslint-disable-next-line max-len */
    'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== \r \n\tsha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'strict mode replaces non-whitespace characters in separator with space'
  )
})
