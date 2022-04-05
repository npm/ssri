'use strict'

const crypto = require('crypto')
const fs = require('fs')
const test = require('tap').test

const ssri = require('..')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

function fileStream () {
  return fs.createReadStream(__filename)
}

test('fromHex', t => {
  t.equal(
    ssri.fromHex('deadbeef', 'sha1').toString(),
    'sha1-3q2+7w==',
    'created an Integrity object from a given hex + sha'
  )
  t.equal(
    ssri.fromHex('deadbeef', 'sha512', { options: ['a', 'b', 'c'] }).toString(),
    'sha512-3q2+7w==?a?b?c',
    'options added to entry'
  )
  t.end()
})

test('fromData', t => {
  t.equal(
    ssri.fromData(TEST_DATA).toString(),
    `sha512-${hash(TEST_DATA, 'sha512')}`,
    'generates sha512 integrity object from Buffer data'
  )
  t.equal(
    ssri.fromData(TEST_DATA.toString('utf8')).toString(),
    `sha512-${hash(TEST_DATA, 'sha512')}`,
    'generates sha512 integrity object from String data'
  )
  t.equal(
    ssri.fromData(TEST_DATA, { algorithms: ['sha256', 'sha384'] }).toString(),
    `sha256-${hash(TEST_DATA, 'sha256')} sha384-${hash(TEST_DATA, 'sha384')}`,
    'can generate multiple metadata entries with opts.algorithms'
  )
  t.equal(
    ssri.fromData(TEST_DATA, {
      algorithms: ['sha256', 'sha384'],
      options: ['foo', 'bar'],
    }).toString(), [
      `sha256-${hash(TEST_DATA, 'sha256')}?foo?bar`,
      `sha384-${hash(TEST_DATA, 'sha384')}?foo?bar`,
    ].join(' '),
    'can add opts.options to each entry'
  )
  t.end()
})

test('fromStream', t => {
  let streamEnded
  const stream = fileStream().on('end', () => {
    streamEnded = true
  })
  return ssri.fromStream(stream).then(integrity => {
    t.equal(
      integrity.toString(),
      `sha512-${hash(TEST_DATA, 'sha512')}`,
      'generates sha512 from a stream'
    )
    t.ok(streamEnded, 'source stream ended')
    return ssri.fromStream(fileStream(), {
      algorithms: ['sha256', 'sha384'],
    })
  }).then(integrity => {
    t.equal(
      integrity.toString(), [
        `sha256-${hash(TEST_DATA, 'sha256')}`,
        `sha384-${hash(TEST_DATA, 'sha384')}`,
      ].join(' '),
      'can generate multiple metadata entries with opts.algorithms'
    )
    return ssri.fromStream(fileStream(), {
      algorithms: ['sha256', 'sha384'],
      options: ['foo', 'bar'],
    })
  }).then(integrity => {
    t.equal(
      integrity.toString(), [
        `sha256-${hash(TEST_DATA, 'sha256')}?foo?bar`,
        `sha384-${hash(TEST_DATA, 'sha384')}?foo?bar`,
      ].join(' '),
      'can add opts.options to each entry'
    )
  })
})
