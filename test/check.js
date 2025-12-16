'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { test } = require('node:test')
const assert = require('node:assert')

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

function fileStream () {
  return fs.createReadStream(__filename)
}

test('checkData', () => {
  const sri = ssri.parse({
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512'),
  })
  const meta = sri.sha512[0]
  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA, sri),
    meta,
    'Buffer data successfully verified'
  )
  assert.doesNotThrow(() => {
    ssri.checkData(TEST_DATA, sri, { error: true })
  }, 'error not thrown when error: true and data verifies')
  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA, `sha512-${hash(TEST_DATA, 'sha512')}`),
    meta,
    'Accepts string SRI'
  )
  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA, {
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
    }),
    meta,
    'Accepts Hash-like SRI'
  )
  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA.toString('utf8'), sri),
    meta,
    'String data successfully verified'
  )
  assert.deepStrictEqual(
    ssri.checkData(
      TEST_DATA,
      `sha512-nope sha512-${hash(TEST_DATA, 'sha512')}`
    ),
    meta,
    'succeeds if any of the hashes under the chosen algorithm match'
  )
  assert.strictEqual(
    ssri.checkData('nope', sri),
    false,
    'returns false when verification fails'
  )
  assert.throws(() => {
    ssri.checkData('nope', sri, { error: true })
  }, /Integrity checksum failed/, 'integrity error thrown when error: true with bad data')
  assert.throws(() => {
    ssri.checkData('nope', sri, { error: true, size: 3 })
  }, /data size mismatch/, 'size error thrown when error: true with bad size')
  assert.strictEqual(
    ssri.checkData('nope', 'sha512-nope'),
    false,
    'returns false on invalid sri hash'
  )
  assert.strictEqual(
    ssri.checkData('nope', 'garbage'),
    false,
    'returns false on garbage sri input'
  )
  assert.strictEqual(
    ssri.checkData('nope', ''),
    false,
    'returns false on empty sri input'
  )
  assert.throws(() => {
    ssri.checkData('nope', '', { error: true })
  }, /No valid integrity hashes/, 'errors on empty sri input if error: true')

  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA, [
      'sha512-nope',
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha512-${hash(TEST_DATA, 'sha512')}`,
    ].join(' '), {
      pickAlgorithm: (a, b) => {
        if (a === 'sha1' || b === 'sha1') {
          return 'sha1'
        }
      },
    }),
    ssri.parse({
      algorithm: 'sha1', digest: hash(TEST_DATA, 'sha1'),
    }).sha1[0],
    'opts.pickAlgorithm can be used to customize which one is used.'
  )

  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA, [
      `sha256-${hash(TEST_DATA, 'sha256')}`,
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha512-${hash(TEST_DATA, 'sha512')}`,
    ].join(' '), {
      pickAlgorithm: () => {
        return false
      },
    }),
    ssri.parse({
      algorithm: 'sha256', digest: hash(TEST_DATA, 'sha256'),
    }).sha256[0],
    'opts.pickAlgorithm can return false to keep the first option'
  )

  assert.deepStrictEqual(
    ssri.checkData(TEST_DATA, [
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha384-${hash(TEST_DATA, 'sha384')}`,
      `sha256-${hash(TEST_DATA, 'sha256')}`,
    ].join(' ')),
    ssri.parse({
      algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
    }).sha384[0],
    'picks the "strongest" available algorithm, by default'
  )
})

test('checkStream', async () => {
  const sri = ssri.parse({
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512'),
  })
  const meta = sri.sha512[0]
  let streamEnded
  const stream = fileStream().on('end', () => {
    streamEnded = true
  })
  const res = await ssri.checkStream(stream, sri)
  assert.deepStrictEqual(res, meta, 'Stream data successfully verified')
  assert.ok(streamEnded, 'source stream ended')

  const res2 = await ssri.checkStream(
    fileStream(),
    `sha512-${hash(TEST_DATA, 'sha512')}`
  )
  assert.deepStrictEqual(res2, meta, 'Accepts string SRI')

  const res3 = await ssri.checkStream(fileStream(), {
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512'),
  })
  assert.deepStrictEqual(res3, meta, 'Accepts Hash-like SRI')

  const res4 = await ssri.checkStream(fileStream(), `sha512-${hash(TEST_DATA, 'sha512')}`, { single: true })
  assert.deepStrictEqual(res4, meta, 'Process successfully with single option')

  const res5 = await ssri.checkStream(
    fileStream(),
    `sha512-nope sha512-${hash(TEST_DATA, 'sha512')}`
  )
  assert.deepStrictEqual(
    res5,
    meta,
    'succeeds if any of the hashes under the chosen algorithm match'
  )

  await assert.rejects(
    ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      sri
    ),
    (err) => {
      assert.strictEqual(err.code, 'EINTEGRITY', 'checksum failure rejects the promise')
      return true
    }
  )

  await assert.rejects(
    ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      'garbage'
    ),
    (err) => {
      assert.strictEqual(err.code, 'EINTEGRITY', 'checksum failure if sri is garbage')
      return true
    }
  )

  await assert.rejects(
    ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      'sha512-nope'
    ),
    (err) => {
      assert.strictEqual(err.code, 'EINTEGRITY', 'checksum failure if sri has bad hash')
      return true
    }
  )

  const res6 = await ssri.checkStream(fileStream(), [
    'sha512-nope',
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha512-${hash(TEST_DATA, 'sha512')}`,
  ].join(' '), {
    pickAlgorithm: (a, b) => {
      if (a === 'sha1' || b === 'sha1') {
        return 'sha1'
      }
    },
  })
  assert.deepStrictEqual(
    res6,
    ssri.parse({
      algorithm: 'sha1', digest: hash(TEST_DATA, 'sha1'),
    }).sha1[0],
    'opts.pickAlgorithm can be used to customize which one is used.'
  )

  const res7 = await ssri.checkStream(fileStream(), [
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha384-${hash(TEST_DATA, 'sha384')}`,
    `sha256-${hash(TEST_DATA, 'sha256')}`,
  ].join(' '))
  assert.deepStrictEqual(
    res7,
    ssri.parse({
      algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
    }).sha384[0],
    'picks the "strongest" available algorithm, by default'
  )

  const res8 = await ssri.checkStream(fileStream(), [
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha384-${hash(TEST_DATA, 'sha384')}`,
    `sha256-${hash(TEST_DATA, 'sha256')}`,
  ].join(' '), {
    algorithms: ['sha256'],
  })
  assert.deepStrictEqual(
    res8,
    ssri.parse({
      algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
    }).sha384[0],
    'opts.algorithm still takes into account algo to check against'
  )

  const res9 = await ssri.checkStream(fileStream(), [
    `sha1-${hash(TEST_DATA, 'sha1')}`,
    `sha384-${hash(TEST_DATA, 'sha384')}`,
    `sha256-${hash(TEST_DATA, 'sha256')}`,
  ].join(' '), {
    algorithms: ['sha512'],
  })
  assert.deepStrictEqual(
    res9,
    ssri.parse({
      algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
    }).sha384[0],
    '...even if opts.algorithms includes a hash that is not present'
  )

  await assert.rejects(
    ssri.checkStream(
      fileStream(), `sha256-${hash(TEST_DATA, 'sha256')}`, {
        size: TEST_DATA.length - 1,
      }
    ),
    (err) => {
      assert.strictEqual(err.code, 'EBADSIZE', 'size check failure rejects the promise')
      return true
    }
  )
})
