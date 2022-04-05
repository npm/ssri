'use strict'

const crypto = require('crypto')
const fs = require('fs')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

test('parses single-entry integrity string', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  t.same(ssri.parse(integrity), {
    sha512: [{
      source: integrity,
      digest: sha,
      algorithm: 'sha512',
      options: [],
    }],
  }, 'single entry parsed into full Integrity instance')
  t.end()
})

test('parses options from integrity string', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}?one?two?three`
  t.same(ssri.parse(integrity), {
    sha512: [{
      source: integrity,
      digest: sha,
      algorithm: 'sha512',
      options: ['one', 'two', 'three'],
    }],
  }, 'single entry parsed into full Integrity instance')
  t.end()
})

test('parses options from integrity string in strict mode', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}?one?two?three`
  t.same(ssri.parse(integrity, { strict: true }), {
    sha512: [{
      source: integrity,
      digest: sha,
      algorithm: 'sha512',
      options: ['one', 'two', 'three'],
    }],
  }, 'single entry parsed into full Integrity instance')
  t.end()
})

test('can parse single-entry string directly into Hash', t => {
  const sha = hash(TEST_DATA, 'sha512')
  const integrity = `sha512-${sha}`
  t.same(ssri.parse(integrity, { single: true }), {
    source: integrity,
    digest: sha,
    algorithm: 'sha512',
    options: [],
  }, 'single entry parsed into single Hash instance')
  t.end()
})

test('accepts Hash-likes as input', t => {
  const algorithm = 'sha512'
  const digest = hash(TEST_DATA, 'sha512')
  const sriLike = {
    algorithm,
    digest,
    options: ['foo'],
  }
  const parsed = ssri.parse(sriLike)
  t.same(parsed, {
    sha512: [{
      source: `sha512-${digest}?foo`,
      algorithm,
      digest,
      options: ['foo'],
    }],
  }, 'Metadata-like returned as full Integrity instance')
  t.end()
})

test('omits unsupported algos in strict mode only', t => {
  const xxx = new Array(50).join('x')

  t.match(ssri.parse(`foo-${xxx}`, {
    strict: true,
    single: true,
  }), {
    source: `foo-${xxx}`,
    algorithm: '',
    digest: '',
    options: [],
  })

  t.match(ssri.parse(`foo-${xxx}`, {
    strict: false,
    single: true,
  }), {
    source: `foo-${xxx}`,
    algorithm: 'foo',
    digest: xxx,
    options: [],
  })

  t.match(ssri.parse(`sha512-${xxx}`, {
    strict: true,
    single: true,
  }), {
    source: `sha512-${xxx}`,
    algorithm: 'sha512',
    digest: xxx,
    options: [],
  })

  t.end()
})

test('use " " as sep when opts.sep is falsey', t => {
  const parsed = ssri.parse('yum-somehash foo-barbaz')
  t.equal(parsed.toString({ sep: false }), 'yum-somehash foo-barbaz')
  t.equal(parsed.toString({ sep: '\t' }), 'yum-somehash\tfoo-barbaz')
  t.end()
})

test('accepts Integrity-like as input', t => {
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
  t.same(parsed, {
    sha512: [{
      source: `sha512-${digest}?foo`,
      algorithm,
      digest,
      options: ['foo'],
    }],
  }, 'Integrity-like returned as full Integrity instance')
  t.not(parsed, sriLike, 'Objects are separate instances.')
  t.end()
})

test('parses and groups multiple-entry strings', t => {
  const hashes = [
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha256-${hash(TEST_DATA, 'sha256')}`,
    'sha1-OthERhaSh',
    'unknown-WoWoWoWoW',
  ]
  t.same(ssri.parse(hashes.join(' ')), {
    sha1: [{
      source: hashes[0],
      digest: hashes[0].split('-')[1],
      algorithm: 'sha1',
      options: [],
    }, {
      source: hashes[2],
      digest: hashes[2].split('-')[1],
      algorithm: 'sha1',
      options: [],
    }],
    sha256: [{
      source: hashes[1],
      digest: hashes[1].split('-')[1],
      algorithm: 'sha256',
      options: [],
    }],
    unknown: [{
      source: hashes[3],
      digest: hashes[3].split('-')[1],
      algorithm: 'unknown',
      options: [],
    }],
  })
  t.end()
})

test('parses any whitespace as entry separators', t => {
  const integrity = '\tsha512-foobarbaz \n\rsha384-bazbarfoo\n         \t  \t\t sha256-foo'
  t.same(ssri.parse(integrity), {
    sha512: [{
      source: 'sha512-foobarbaz',
      algorithm: 'sha512',
      digest: 'foobarbaz',
      options: [],
    }],
    sha384: [{
      source: 'sha384-bazbarfoo',
      algorithm: 'sha384',
      digest: 'bazbarfoo',
      options: [],
    }],
    sha256: [{
      source: 'sha256-foo',
      algorithm: 'sha256',
      digest: 'foo',
      options: [],
    }],
  }, 'whitespace around metadata skipped and trimmed')
  t.end()
})

test('discards invalid format entries', t => {
  const missingDash = 'thisisbad'
  const missingAlgorithm = '-deadbeef'
  const missingDigest = 'sha512-'
  const valid = `sha512-${hash(TEST_DATA, 'sha512')}`
  t.equal(ssri.parse([
    missingDash,
    missingAlgorithm,
    missingDigest,
    valid,
  ].join(' ')).toString(), valid, 'invalid entries thrown out')
  t.end()
})

test('trims whitespace from either end', t => {
  const integrity = `      sha512-${hash(TEST_DATA, 'sha512')}    `
  t.same(ssri.parse(integrity), {
    sha512: [{
      source: integrity.trim(),
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
      options: [],
    }],
  }, 'whitespace is trimmed from source before parsing')
  t.end()
})

test('supports strict spec parsing', t => {
  const valid = `sha512-${hash(TEST_DATA, 'sha512')}`
  const badAlgorithm = `sha1-${hash(TEST_DATA, 'sha1')}`
  const badBase64 = 'sha512-@#$@%#$'
  const badOpts = `${valid}?\x01\x02`
  t.same(ssri.parse([
    badAlgorithm,
    badBase64,
    badOpts,
    valid,
  ].join(' '), {
    strict: true,
  }).toString(), valid, 'entries that fail strict check rejected')
  t.end()
})

test('does not allow weird stuff in sri', t => {
  const badInt = 'mdc2\u0000/../../../hello_what_am_I_doing_here-Juwtg9UFssfrRfwsXu+n/Q=='
  const bad = ssri.parse(badInt)
  const badStrict = ssri.parse(badInt, { strict: true })
  const expect = ssri.parse('')
  t.strictSame(bad, expect)
  t.strictSame(badStrict, expect)
  t.end()
})
