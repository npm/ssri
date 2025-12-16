'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs')
const { test } = require('node:test')
const assert = require('node:assert')

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

test('hashes should match when valid', () => {
  const integrity = `sha512-${hash(TEST_DATA, 'sha512')}`
  const otherIntegrity = `sha512-${hash('mismatch', 'sha512')}`
  const otherAlgorithm = `sha1-${hash(TEST_DATA, 'sha1')}`
  const parsed = ssri.parse(integrity, { single: true })
  assert.deepStrictEqual(
    parsed.match(integrity, { single: true }),
    parsed,
    'should return the same algo when digest is equal (single option)'
  )
  assert.deepStrictEqual(
    parsed.match('sha-233', { single: true }),
    false,
    'invalid integrity should not match (single option)'
  )
  assert.deepStrictEqual(
    parsed.match(null, { single: true }),
    false,
    'null integrity just returns false (single option)'
  )

  assert.deepStrictEqual(
    parsed.match(integrity),
    parsed,
    'should return the same algo when digest is equal'
  )
  assert.deepStrictEqual(
    parsed.match('sha-233'),
    false,
    'invalid integrity should not match'
  )
  assert.deepStrictEqual(
    parsed.match(null),
    false,
    'null integrity just returns false'
  )
  assert.deepStrictEqual(
    parsed.match(otherIntegrity),
    false,
    'should not match with a totally different integrity'
  )
  assert.deepStrictEqual(
    parsed.match(otherAlgorithm),
    false,
    'should not match with a totally different algorithm'
  )
})
