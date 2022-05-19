'use strict'

const test = require('tap').test

const ssri = require('..')

test('works with no options', t => {
  const TARGET = ssri.fromData('foo')
  const stream = ssri.integrityStream()
  stream.write('foo')
  let integrity
  stream.on('integrity', i => {
    integrity = i
  })

  stream.on('end', () => {
    t.same(integrity, TARGET, 'matching integrity emitted')
    t.end()
  })

  stream.resume()
  stream.end()
})

test('generates integrity', t => {
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
    t.equal(collected, 'foo', 'stream output is complete')
    t.equal(size, 3, 'size emitted')
    t.same(integrity, TARGET, 'matching integrity emitted')
    t.same(verified, TARGET.sha512[0], 'verified emitted')
    t.end()
  })
  stream.end()
})

test('re-emits for late listeners', t => {
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
    t.equal(collected, 'foo', 'stream output is complete')
    t.equal(size, 3, 'size emitted')
    t.same(integrity, TARGET, 'matching integrity emitted')
    t.same(verified, TARGET.sha512[0], 'verified emitted')
    t.end()
  })
  stream.end()
})

test('optional algorithms option', t => {
  const TARGET = ssri.fromData('foo', { algorithms: ['sha1', 'sha256'] })
  const stream = ssri.integrityStream({ algorithms: ['sha1', 'sha256'] })
  stream.write('foo')
  stream.on('data', () => {})
  let integrity
  stream.on('integrity', i => {
    integrity = i
  })
  stream.on('end', () => {
    t.same(integrity, TARGET, 'matching integrity emitted')
    t.end()
  })
  stream.end()
})

test('verification for correct data succeeds', t => {
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
    t.equal(collected, 'foo', 'stream output is complete')
    t.same(integrity, TARGET, 'matching integrity emitted')
    t.end()
  })
  stream.end()
})

test('verification for wrong data fails', t => {
  const stream = ssri.integrityStream({
    integrity: ssri.fromData('bar'),
  })
  stream.write('foo')
  stream.on('data', () => {})
  stream.on('error', err => {
    t.equal(err.code, 'EINTEGRITY', 'errors with EINTEGRITY on mismatch')
    t.end()
  })
  stream.end()
})
