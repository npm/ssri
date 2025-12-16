const Benchmark = require('benchmark')
const ssri = require('..')
const suite = new Benchmark.Suite()
const fs = require('fs')
const crypto = require('crypto')

const TEST_DATA = fs.readFileSync(__filename)
const STATIC_DATA = 'static content'

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

const testSha = hash(TEST_DATA, 'sha512')
const testIntegrity = `sha512-${testSha}`
const testParsed = ssri.parse(testIntegrity, { single: true })

const staticSha = hash(STATIC_DATA, 'sha512')
const staticIntegrity = `sha512-${staticSha}`
const staticParsed = ssri.parse(staticIntegrity, { single: true })

suite
  .add('match to self', function () {
    testParsed.match(testParsed)
  })
  .add('match to other', function () {
    testParsed.match(staticParsed)
  })
  .on('cycle', function (event) {
    console.log(String(event.target))
  })
  .run({ async: false })
