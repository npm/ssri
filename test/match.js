'use strict'

const crypto = require('crypto')
const fs = require('fs')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

test('hashes should match when valid', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  const parsed = ssri.parse(integrity, { single: true })
  t.same(
    parsed.match(integrity, { single: true }),
    parsed,
    'should return the same algo when digest is equal (single option)'
  )
  t.same(
    parsed.match('sha-233', { single: true }),
    false,
    'invalid integrity should not match (single option)'
  )
  t.same(
    parsed.match(null, { single: true }),
    false,
    'null integrity just returns false (single option)'
  )

  t.same(
    parsed.match(integrity),
    parsed,
    'should return the same algo when digest is equal'
  )
  t.same(
    parsed.match('sha-233'),
    false,
    'invalid integrity should not match'
  )
  t.same(
    parsed.match(null),
    false,
    'null integrity just returns false'
  )
  t.end()
})
