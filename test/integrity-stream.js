'use strict'

const { test } = require('node:test')
const assert = require('node:assert')

const ssri = require('..')

test('works with no options', (t, done) => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream()
  stream.write('foo')
  let integrity
  stream.on('integrity', i => {
    integrity = i
  })

  stream.on('end', () => {
    assert.deepStrictEqual(integrity, TARGET, 'matching integrity emitted')
    done()
  })

  stream.resume()
  stream.end()
})

test('generates integrity', (t, done) => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream({ integrity: TARGET })
  stream.write('foo')
  let collected = ''
  stream.on('data', d => {
    collected += d.toString()
  })
  let integrity
  stream.on('integrity', i => {
    integrity = i
  })
  let size
  stream.on('size', s => {
    size = s
  })
  let verified
  stream.on('verified', v => {
    verified = v
  })
  stream.on('end', () => {
    assert.strictEqual(collected, 'foo', 'stream output is complete')
    assert.strictEqual(size, 3, 'size emitted')
    assert.deepStrictEqual(integrity, TARGET, 'matching integrity emitted')
    assert.deepStrictEqual(verified, TARGET.sha512[0], 'verified emitted')
    done()
  })
  stream.end()
})

test('re-emits for late listeners', (t, done) => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream({ integrity: TARGET })
  stream.write('foo')
  let collected = ''
  stream.on('data', d => {
    collected += d.toString()
  })

  stream.on('end', () => {
    // we add the listeners _after_ the end event this time to ensure that the events
    // get emitted again for late listeners
    let integrity
    stream.on('integrity', i => {
      integrity = i
    })

    let size
    stream.on('size', s => {
      size = s
    })

    let verified
    stream.on('verified', v => {
      verified = v
    })
    assert.strictEqual(collected, 'foo', 'stream output is complete')
    assert.strictEqual(size, 3, 'size emitted')
    assert.deepStrictEqual(integrity, TARGET, 'matching integrity emitted')
    assert.deepStrictEqual(verified, TARGET.sha512[0], 'verified emitted')
    done()
  })
  stream.end()
})

test('optional algorithms option', (t, done) => {
  const TARGET = ssri.fromData('foo', { algorithms: ['sha1', 'sha256'] })
  const stream = ssri.integrityStream({ algorithms: ['sha1', 'sha256'] })
  stream.write('foo')
  stream.on('data', () => {})
  let integrity
  stream.on('integrity', i => {
    integrity = i
  })
  stream.on('end', () => {
    assert.deepStrictEqual(integrity, TARGET, 'matching integrity emitted')
    done()
  })
  stream.end()
})

test('verification for correct data succeeds', (t, done) => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream({
    integrity: TARGET,
  })
  stream.write('foo')
  let collected = ''
  stream.on('data', d => {
    collected += d.toString()
  })
  let integrity
  stream.on('integrity', i => {
    integrity = i
  })
  stream.on('end', () => {
    assert.strictEqual(collected, 'foo', 'stream output is complete')
    assert.deepStrictEqual(integrity, TARGET, 'matching integrity emitted')
    done()
  })
  stream.end()
})

test('verification for wrong data fails', (t, done) => {
  const stream = ssri.integrityStream({
    integrity: ssri.fromData('bar'),
  })
  stream.write('foo')
  stream.on('data', () => {})
  stream.on('error', err => {
    assert.strictEqual(err.code, 'EINTEGRITY', 'errors with EINTEGRITY on mismatch')
    done()
  })
  stream.end()
})
