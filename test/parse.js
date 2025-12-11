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

test('parses single-entry integrity string', () => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  const parsed = ssri.parse(integrity)
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512.length, 1)
  assert.strictEqual(parsed.sha512[0].source, integrity)
  assert.strictEqual(parsed.sha512[0].digest, sha)
  assert.strictEqual(parsed.sha512[0].algorithm, 'sha512')
  assert.deepStrictEqual(parsed.sha512[0].options, [])
})

test('parses options from integrity string', () => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}?one?two?three`
  const parsed = ssri.parse(integrity)
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512.length, 1)
  assert.strictEqual(parsed.sha512[0].source, integrity)
  assert.strictEqual(parsed.sha512[0].digest, sha)
  assert.strictEqual(parsed.sha512[0].algorithm, 'sha512')
  assert.deepStrictEqual(parsed.sha512[0].options, ['one', 'two', 'three'])
})

test('parses options from integrity string in strict mode', () => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}?one?two?three`
  const parsed = ssri.parse(integrity, { strict: true })
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512.length, 1)
  assert.strictEqual(parsed.sha512[0].source, integrity)
  assert.strictEqual(parsed.sha512[0].digest, sha)
  assert.strictEqual(parsed.sha512[0].algorithm, 'sha512')
  assert.deepStrictEqual(parsed.sha512[0].options, ['one', 'two', 'three'])
})

test('can parse single-entry string directly into Hash', () => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  const parsed = ssri.parse(integrity, { single: true })
  assert.strictEqual(parsed.source, integrity)
  assert.strictEqual(parsed.digest, sha)
  assert.strictEqual(parsed.algorithm, 'sha512')
  assert.deepStrictEqual(parsed.options, [])
})

test('accepts Hash-likes as input', () => {
  const algorithm = 'sha512'
  const digest = hash(TEST_DATA, 'sha512')
  const sriLike = {
    algorithm,
    digest,
    options: ['foo'],
  }
  const parsed = ssri.parse(sriLike)
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512.length, 1)
  assert.strictEqual(parsed.sha512[0].source, `sha512-${digest}?foo`)
  assert.strictEqual(parsed.sha512[0].algorithm, algorithm)
  assert.strictEqual(parsed.sha512[0].digest, digest)
  assert.deepStrictEqual(parsed.sha512[0].options, ['foo'])
})

test('omits unsupported algos in strict mode only', () => {
  const xxx = new Array(50).join('x')

  const parsed1 = ssri.parse(`foo-${xxx}`, {
    strict: true,
    single: true,
  })
  assert.strictEqual(parsed1.source, `foo-${xxx}`)
  assert.strictEqual(parsed1.algorithm, '')
  assert.strictEqual(parsed1.digest, '')
  assert.deepStrictEqual(parsed1.options, [])

  const parsed2 = ssri.parse(`foo-${xxx}`, {
    strict: false,
    single: true,
  })
  assert.strictEqual(parsed2.source, `foo-${xxx}`)
  assert.strictEqual(parsed2.algorithm, 'foo')
  assert.strictEqual(parsed2.digest, xxx)
  assert.deepStrictEqual(parsed2.options, [])

  const parsed3 = ssri.parse(`sha512-${xxx}`, {
    strict: true,
    single: true,
  })
  assert.strictEqual(parsed3.source, `sha512-${xxx}`)
  assert.strictEqual(parsed3.algorithm, 'sha512')
  assert.strictEqual(parsed3.digest, xxx)
  assert.deepStrictEqual(parsed3.options, [])
})

test('use " " as sep when opts.sep is falsey', () => {
  const parsed = ssri.parse('yum-somehash foo-barbaz')
  assert.strictEqual(parsed.toString({ sep: false }), 'yum-somehash foo-barbaz')
  assert.strictEqual(parsed.toString({ sep: '\t' }), 'yum-somehash\tfoo-barbaz')
})

test('accepts Integrity-like as input', () => {
  const algorithm = 'sha512'
  const digest = hash(TEST_DATA, 'sha512')
  const sriLike = {
    sha512: [{
      algorithm,
      digest,
      options: ['foo'],
    }],
  }
  const parsed = ssri.parse(sriLike)
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512.length, 1)
  assert.strictEqual(parsed.sha512[0].source, `sha512-${digest}?foo`)
  assert.strictEqual(parsed.sha512[0].algorithm, algorithm)
  assert.strictEqual(parsed.sha512[0].digest, digest)
  assert.deepStrictEqual(parsed.sha512[0].options, ['foo'])
  assert.notStrictEqual(parsed, sriLike, 'Objects are separate instances.')
})

test('parses and groups multiple-entry strings', () => {
  const hashes = [
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha256-${hash(TEST_DATA, 'sha256')}`,
    'sha1-OthERhaSh',
    'unknown-WoWoWoWoW',
  ]
  const parsed = ssri.parse(hashes.join(' '))
  assert.ok(parsed.sha1)
  assert.strictEqual(parsed.sha1.length, 2)
  assert.strictEqual(parsed.sha1[0].source, hashes[0])
  assert.strictEqual(parsed.sha1[0].digest, hashes[0].split('-')[1])
  assert.strictEqual(parsed.sha1[0].algorithm, 'sha1')
  assert.deepStrictEqual(parsed.sha1[0].options, [])
  assert.strictEqual(parsed.sha1[1].source, hashes[2])
  assert.strictEqual(parsed.sha1[1].digest, hashes[2].split('-')[1])
  assert.strictEqual(parsed.sha1[1].algorithm, 'sha1')
  assert.deepStrictEqual(parsed.sha1[1].options, [])

  assert.ok(parsed.sha256)
  assert.strictEqual(parsed.sha256.length, 1)
  assert.strictEqual(parsed.sha256[0].source, hashes[1])
  assert.strictEqual(parsed.sha256[0].digest, hashes[1].split('-')[1])
  assert.strictEqual(parsed.sha256[0].algorithm, 'sha256')
  assert.deepStrictEqual(parsed.sha256[0].options, [])

  assert.ok(parsed.unknown)
  assert.strictEqual(parsed.unknown.length, 1)
  assert.strictEqual(parsed.unknown[0].source, hashes[3])
  assert.strictEqual(parsed.unknown[0].digest, hashes[3].split('-')[1])
  assert.strictEqual(parsed.unknown[0].algorithm, 'unknown')
  assert.deepStrictEqual(parsed.unknown[0].options, [])
})

test('parses any whitespace as entry separators', () => {
  const integrity = '\tsha512-foobarbaz \n\rsha384-bazbarfoo\n         \t  \t\t sha256-foo'
  const parsed = ssri.parse(integrity)
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512[0].source, 'sha512-foobarbaz')
  assert.strictEqual(parsed.sha512[0].algorithm, 'sha512')
  assert.strictEqual(parsed.sha512[0].digest, 'foobarbaz')
  assert.deepStrictEqual(parsed.sha512[0].options, [])

  assert.ok(parsed.sha384)
  assert.strictEqual(parsed.sha384[0].source, 'sha384-bazbarfoo')
  assert.strictEqual(parsed.sha384[0].algorithm, 'sha384')
  assert.strictEqual(parsed.sha384[0].digest, 'bazbarfoo')
  assert.deepStrictEqual(parsed.sha384[0].options, [])

  assert.ok(parsed.sha256)
  assert.strictEqual(parsed.sha256[0].source, 'sha256-foo')
  assert.strictEqual(parsed.sha256[0].algorithm, 'sha256')
  assert.strictEqual(parsed.sha256[0].digest, 'foo')
  assert.deepStrictEqual(parsed.sha256[0].options, [])
})

test('discards invalid format entries', () => {
  const missingDash = 'thisisbad'
  const missingAlgorithm = '-deadbeef'
  const missingDigest = 'sha512-'
  const valid = `sha512-${hash(TEST_DATA, 'sha512')}`
  assert.strictEqual(ssri.parse([
    missingDash,
    missingAlgorithm,
    missingDigest,
    valid,
  ].join(' ')).toString(), valid, 'invalid entries thrown out')
})

test('trims whitespace from either end', () => {
  const integrity = `      sha512-${hash(TEST_DATA, 'sha512')}    `
  const parsed = ssri.parse(integrity)
  assert.ok(parsed.sha512)
  assert.strictEqual(parsed.sha512[0].source, integrity.trim())
  assert.strictEqual(parsed.sha512[0].algorithm, 'sha512')
  assert.strictEqual(parsed.sha512[0].digest, hash(TEST_DATA, 'sha512'))
  assert.deepStrictEqual(parsed.sha512[0].options, [])
})

test('supports strict spec parsing', () => {
  const valid = `sha512-${hash(TEST_DATA, 'sha512')}`
  const badAlgorithm = `sha1-${hash(TEST_DATA, 'sha1')}`
  const badBase64 = 'sha512-@#$@%#$'
  const badOpts = `${valid}?\x01\x02`
  assert.deepStrictEqual(ssri.parse([
    badAlgorithm,
    badBase64,
    badOpts,
    valid,
  ].join(' '), {
    strict: true,
  }).toString(), valid, 'entries that fail strict check rejected')
})

test('does not allow weird stuff in sri', () => {
  const badInt = 'mdc2\u0000/../../../hello_what_am_I_doing_here-Juwtg9UFssfrRfwsXu+n/Q=='
  const bad = ssri.parse(badInt)
  const badStrict = ssri.parse(badInt, { strict: true })
  const expect = ssri.parse('')
  assert.deepStrictEqual(bad, expect)
  assert.deepStrictEqual(badStrict, expect)
})
