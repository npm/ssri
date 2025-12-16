'use strict'

const { test } = require('node:test')
const assert = require('node:assert')

const ssri = require('..')

test('toString()', () => {
  /* eslint-disable-next-line max-len */
  const sri = ssri.parse('sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE= sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=')
  assert.strictEqual(
    sri.toString(),
    'sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE= sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'integrity objects from ssri.parse() can use toString()'
  )
  assert.strictEqual(
    sri.toString({ strict: true }),
    'sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'accepts strict mode option'
  )
  assert.strictEqual(
    sri.toString({ sep: '\n' }),
    'sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE=\nsha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=',
    'accepts separator option'
  )
})

test('toJSON()', () => {
  const sri = ssri.parse('sha512-foo sha256-bar!')
  assert.strictEqual(
    sri.toJSON(),
    'sha512-foo sha256-bar!',
    'integrity objects from ssri.parse() can use toJSON()'
  )
  assert.strictEqual(
    sri.sha512[0].toJSON(),
    'sha512-foo',
    'hash objects should toJSON also'
  )
})

test('concat()', () => {
  const sri = ssri.parse('sha512-foo')
  assert.strictEqual(
    sri.concat('sha512-bar').toString(),
    'sha512-foo sha512-bar',
    'concatenates with a string'
  )
  assert.strictEqual(
    sri.concat({ digest: 'bar', algorithm: 'sha384' }).toString(),
    'sha512-foo sha384-bar',
    'concatenates with an Hash-like'
  )
  assert.strictEqual(
    sri.concat({
      sha384: [{ digest: 'bar', algorithm: 'sha384' }],
      sha1: [{ digest: 'baz', algorithm: 'sha1' }],
    }).toString(),
    'sha512-foo sha384-bar sha1-baz',
    'concatenates with an Integrity-like'
  )
  assert.strictEqual(
    sri.concat(
      { digest: 'bar', algorithm: 'sha1' }
    ).concat(
      'sha1-baz'
    ).concat(
      'sha512-quux'
    ).toString(),
    'sha512-foo sha512-quux sha1-bar sha1-baz',
    'preserves relative order for algorithms between different concatenations'
  )
  /* eslint-disable-next-line max-len */
  const strictSri = ssri.parse('sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw==')
  assert.strictEqual(
    strictSri.concat('sha1-eUN/Xt2hP5wGabl43XqQZt0gWfE=', {
      strict: true,
    }).toString(),
    /* eslint-disable-next-line max-len */
    'sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw==',
    'accepts strict mode option'
  )
})

test('match()', () => {
  const sri = ssri.parse('sha1-foo sha512-bar')
  const match1 = sri.match('sha1-foo')
  assert.strictEqual(match1.algorithm, 'sha1', 'returns the matching hash')
  assert.strictEqual(match1.digest, 'foo')

  const match2 = sri.match(ssri.parse('sha1-foo'))
  assert.strictEqual(match2.algorithm, 'sha1', 'accepts other Integrity objects')
  assert.strictEqual(match2.digest, 'foo')

  const match3 = sri.match(ssri.parse('sha1-foo'))
  assert.strictEqual(match3.algorithm, 'sha1', 'accepts other Hash objects')
  assert.strictEqual(match3.digest, 'foo')

  const match4 = sri.match({ digest: 'foo', algorithm: 'sha1' })
  assert.strictEqual(match4.algorithm, 'sha1', 'accepts Hash-like objects')
  assert.strictEqual(match4.digest, 'foo')

  const match5 = sri.match('sha1-bar sha512-bar')
  assert.strictEqual(match5.algorithm, 'sha512', 'returns the strongest match')
  assert.strictEqual(match5.digest, 'bar')

  assert.ok(!sri.match('sha512-foo'), 'falsy when match fails')
  assert.ok(!sri.match('sha384-foo'), 'falsy when match fails')
  assert.ok(!sri.match(null), 'falsy when integrity is null')
})

test('pickAlgorithm()', () => {
  const sri = ssri.parse('sha1-foo sha512-bar sha384-baz')
  assert.strictEqual(sri.pickAlgorithm(), 'sha512', 'picked best algorithm')
  assert.strictEqual(
    sri.pickAlgorithm({
      pickAlgorithm: () => 'sha384',
    }),
    'sha384',
    'custom pickAlgorithm function accepted'
  )
})

test('hexDigest()', () => {
  assert.strictEqual(
    ssri.parse('sha512-foo').hexDigest(),
    Buffer.from('foo', 'base64').toString('hex'),
    'returned hex version of base64 digest')
  assert.strictEqual(
    ssri.parse('sha512-bar', { single: true }).hexDigest(),
    Buffer.from('bar', 'base64').toString('hex'),
    'returned hex version of base64 digest')
})

test('isIntegrity and isHash', () => {
  const sri = ssri.parse('sha512-bar')
  assert.ok(sri.isIntegrity, 'full sri has !!.isIntegrity')
  assert.ok(
    sri.sha512[0].isHash,
    'sri hash has !!.isHash'
  )
})

test('semi-private', () => {
  assert.strictEqual(ssri.Integrity, undefined, 'Integrity class is module-private.')
})
