'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

function fileStream () {
  return fs.createReadStream(__filename)
}

test('checkData', t => {
  const sri = ssri.parse({
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512'),
  })
  const meta = sri.sha512[0]
  t.same(
    ssri.checkData(TEST_DATA, sri),
    meta,
    'Buffer data successfully verified'
  )
  t.doesNotThrow(() => {
    ssri.checkData(TEST_DATA, sri, { error: true })
  }, 'error not thrown when error: true and data verifies')
  t.same(
    ssri.checkData(TEST_DATA, `sha512-${hash(TEST_DATA, 'sha512')}`),
    meta,
    'Accepts string SRI'
  )
  t.same(
    ssri.checkData(TEST_DATA, {
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
    }),
    meta,
    'Accepts Hash-like SRI'
  )
  t.same(
    ssri.checkData(TEST_DATA.toString('utf8'), sri),
    meta,
    'String data successfully verified'
  )
  t.same(
    ssri.checkData(
      TEST_DATA,
      `sha512-nope sha512-${hash(TEST_DATA, 'sha512')}`
    ),
    meta,
    'succeeds if any of the hashes under the chosen algorithm match'
  )
  t.equal(
    ssri.checkData('nope', sri),
    false,
    'returns false when verification fails'
  )
  t.throws(() => {
    ssri.checkData('nope', sri, { error: true })
  }, /Integrity checksum failed/, 'integrity error thrown when error: true with bad data')
  t.throws(() => {
    ssri.checkData('nope', sri, { error: true, size: 3 })
  }, /data size mismatch/, 'size error thrown when error: true with bad size')
  t.equal(
    ssri.checkData('nope', 'sha512-nope'),
    false,
    'returns false on invalid sri hash'
  )
  t.equal(
    ssri.checkData('nope', 'garbage'),
    false,
    'returns false on garbage sri input'
  )
  t.equal(
    ssri.checkData('nope', ''),
    false,
    'returns false on empty sri input'
  )
  t.throws(() => {
    ssri.checkData('nope', '', { error: true })
  }, /No valid integrity hashes/, 'errors on empty sri input if error: true')

  t.same(
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

  t.same(
    ssri.checkData(TEST_DATA, [
      `sha256-${hash(TEST_DATA, 'sha256')}`,
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha512-${hash(TEST_DATA, 'sha512')}`,
    ].join(' '), {
      pickAlgorithm: (a, b) => {
        return false
      },
    }),
    ssri.parse({
      algorithm: 'sha256', digest: hash(TEST_DATA, 'sha256'),
    }).sha256[0],
    'opts.pickAlgorithm can return false to keep the first option'
  )

  t.same(
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
  t.end()
})

test('checkStream', t => {
  const sri = ssri.parse({
    algorithm: 'sha512',
    digest: hash(TEST_DATA, 'sha512'),
  })
  const meta = sri.sha512[0]
  let streamEnded
  const stream = fileStream().on('end', () => {
    streamEnded = true
  })
  return ssri.checkStream(stream, sri).then(res => {
    t.same(res, meta, 'Stream data successfully verified')
    t.ok(streamEnded, 'source stream ended')
    return ssri.checkStream(
      fileStream(),
      `sha512-${hash(TEST_DATA, 'sha512')}`
    )
  }).then(res => {
    t.same(res, meta, 'Accepts string SRI')
    return ssri.checkStream(fileStream(), {
      algorithm: 'sha512',
      digest: hash(TEST_DATA, 'sha512'),
    })
  }).then(res => {
    t.same(res, meta, 'Accepts Hash-like SRI')
    return ssri.checkStream(
      fileStream(),
      `sha512-nope sha512-${hash(TEST_DATA, 'sha512')}`
    )
  }).then(res => {
    t.same(
      res,
      meta,
      'succeeds if any of the hashes under the chosen algorithm match'
    )
    return ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      sri
    ).then(() => {
      throw new Error('unexpected success')
    }, err => {
      t.equal(err.code, 'EINTEGRITY', 'checksum failure rejects the promise')
    })
  }).then(() => {
    return ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      'garbage'
    ).then(() => {
      throw new Error('unexpected success')
    }, err => {
      t.equal(err.code, 'EINTEGRITY', 'checksum failure if sri is garbage')
    })
  }).then(() => {
    return ssri.checkStream(
      fs.createReadStream(path.join(__dirname, '..', 'package.json')),
      'sha512-nope'
    ).then(() => {
      throw new Error('unexpected success')
    }, err => {
      t.equal(err.code, 'EINTEGRITY', 'checksum failure if sri has bad hash')
    })
  }).then(() => {
    return ssri.checkStream(fileStream(), [
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
  }).then(res => {
    t.same(
      res,
      ssri.parse({
        algorithm: 'sha1', digest: hash(TEST_DATA, 'sha1'),
      }).sha1[0],
      'opts.pickAlgorithm can be used to customize which one is used.'
    )
    return ssri.checkStream(fileStream(), [
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha384-${hash(TEST_DATA, 'sha384')}`,
      `sha256-${hash(TEST_DATA, 'sha256')}`,
    ].join(' '))
  }).then(res => {
    t.same(
      res,
      ssri.parse({
        algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
      }).sha384[0],
      'picks the "strongest" available algorithm, by default'
    )
    return ssri.checkStream(fileStream(), [
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha384-${hash(TEST_DATA, 'sha384')}`,
      `sha256-${hash(TEST_DATA, 'sha256')}`,
    ].join(' '), {
      algorithms: ['sha256'],
    })
  }).then(res => {
    t.same(
      res,
      ssri.parse({
        algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
      }).sha384[0],
      'opts.algorithm still takes into account algo to check against'
    )
    return ssri.checkStream(fileStream(), [
      `sha1-${hash(TEST_DATA, 'sha1')}`,
      `sha384-${hash(TEST_DATA, 'sha384')}`,
      `sha256-${hash(TEST_DATA, 'sha256')}`,
    ].join(' '), {
      algorithms: ['sha512'],
    })
  }).then(res => {
    t.same(
      res,
      ssri.parse({
        algorithm: 'sha384', digest: hash(TEST_DATA, 'sha384'),
      }).sha384[0],
      '...even if opts.algorithms includes a hash that is not present'
    )
    return ssri.checkStream(
      fileStream(), `sha256-${hash(TEST_DATA, 'sha256')}`, {
        size: TEST_DATA.length - 1,
      }
    ).then(() => {
      throw new Error('unexpected success')
    }, err => {
      t.equal(err.code, 'EBADSIZE', 'size check failure rejects the promise')
    })
  })
})
