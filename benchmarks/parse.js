// From https://github.com/npm/ssri/pull/71
const Benchmark = require('benchmark')
const ssri = require('..')
const suite = new Benchmark.Suite()
const fs = require('fs')
const crypto = require('crypto')

const TEST_DATA = fs.readFileSync(__filename)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

const sha = hash(TEST_DATA, 'sha512')
const integrity = `sha512-${sha}`
const parsed = ssri.parse(integrity, { single: true })

suite
  .add('ssri.parse(base64, { single: true })', function () {
    ssri.parse(integrity, { single: true })
  })
  .add('ssri.parse(base64, { single: true, strict: true })', function () {
    ssri.parse(integrity, { single: true, strict: true })
  })
  .add('ssri.parse(parsed, { single: true })', function () {
    ssri.parse(parsed, { single: true })
  })
  .add('ssri.parse(parsed, { single: true, strict: true })', function () {
    ssri.parse(parsed, { single: true, strict: true })
  })
  .on('cycle', function (event) {
    console.log(String(event.target))
  })
  .run({ async: false })
