'use strict'

const { test } = require('node:test')
const assert = require('node:assert')
const { Readable } = require('node:stream')

const ssri = require('..')

test('counts the bytes emitted for string and binary chunks', async t => {
  const cases = [
    ['ASCII', ['plain ', 'text']],
    ['Unicode', ['café ', '雪', ' 💻']],
    ['split surrogate pair', ['\uD83D', '\uDCBB']],
    ['unpaired surrogates', ['\uD83D text \uDCBB']],
    ['mixed chunks', ['雪', Buffer.from([0, 255]), new Uint8Array([1, 2, 3])]],
    ['wide typed array', [new Uint16Array([256, 512])]],
    ['DataView slice', [new DataView(Uint8Array.from([0, 1, 2, 3]).buffer, 1, 2)]],
  ]

  for (const [name, chunks] of cases) {
    await t.test(name, async () => {
      const expected = Buffer.concat(chunks.map(chunk => typeof chunk === 'string'
        ? Buffer.from(chunk)
        : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)))
      const target = ssri.fromData(expected)
      const stream = ssri.integrityStream({ size: expected.length, integrity: target })
      let size
      let integrity
      let verified
      stream.on('size', value => {
        size = value
      })
      stream.on('integrity', value => {
        integrity = value
      })
      stream.on('verified', value => {
        verified = value
      })
      const output = stream.concat()
      for (const chunk of chunks) {
        stream.write(chunk)
      }
      stream.end()

      assert.deepStrictEqual(await output, expected)
      assert.strictEqual(stream.size, expected.length)
      assert.strictEqual(size, expected.length)
      assert.deepStrictEqual(integrity, target)
      assert.deepStrictEqual(verified, target.sha512[0])
      let lateSize
      stream.on('size', value => {
        lateSize = value
      })
      assert.strictEqual(lateSize, expected.length)
    })
  }
})

test('checks Unicode streams against their byte size', async () => {
  const chunks = ['café ', '雪', ' 💻']
  const data = Buffer.from(chunks.join(''))
  const target = ssri.fromData(data)
  assert.deepStrictEqual(
    await ssri.fromStream(Readable.from(chunks), { size: data.length }),
    target
  )
  assert.deepStrictEqual(
    await ssri.checkStream(Readable.from(chunks), target, { size: data.length }),
    target.sha512[0]
  )
  await assert.rejects(
    ssri.checkStream(Readable.from(chunks), target, { size: data.length - 1 }),
    { code: 'EBADSIZE', found: data.length, expected: data.length - 1 }
  )
  await assert.rejects(
    ssri.checkStream(Readable.from(chunks), ssri.fromData('different'), { size: data.length }),
    { code: 'EINTEGRITY' }
  )
})

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
