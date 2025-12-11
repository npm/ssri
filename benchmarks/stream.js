// From https://github.com/npm/ssri/pull/71
const Benchmark = require('benchmark')
// const wtf = require("wtfnode");
// wtf.init();
const ssri = require('..')
const suite = new Benchmark.Suite()
const crypto = require('crypto')
const { Readable } = require('stream')

const largeText = 'a'.repeat(64).repeat(100)
const largeTextSplitted = largeText.split('')

const tinyText = 'a'.repeat(64)
const tinyTextSplitted = tinyText.split('')

const getStream = (text) => Readable.from(text)

function hash (data, algorithm) {
  return crypto.createHash(algorithm).update(data).digest('base64')
}

const largeIntegrity = `sha512-${hash(largeText, 'sha512')}`
const tinyIntegrity = `sha512-${hash(tinyText, 'sha512')}`

suite
  .add('ssri.fromStream(stream, largeIntegrity)', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(largeTextSplitted)

      return ssri.fromStream(stream, largeIntegrity).then(() => deferred.resolve())
    },
  })
  .add('ssri.fromStream(stream, tinyIntegrity)', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(tinyTextSplitted)

      return ssri.fromStream(stream, tinyIntegrity).then(() => deferred.resolve())
    },
  })
  .add('ssri.checkStream(stream, largeIntegrity)', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(largeTextSplitted)

      return ssri.checkStream(stream, largeIntegrity).then(() => deferred.resolve())
    },
  })
  .add('ssri.checkStream(stream, tinyIntegrity)', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(tinyTextSplitted)

      return ssri.checkStream(stream, tinyIntegrity).then(() => deferred.resolve())
    },
  })
  .add('ssri.checkStream(stream, largeIntegrity, { single: true })', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(largeTextSplitted)

      return ssri.checkStream(stream, largeIntegrity, {
        single: true,
      }).then(() => deferred.resolve())
    },
  })
  .add('ssri.checkStream(stream, tinyIntegrity, { single: true })', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(tinyTextSplitted)

      return ssri.checkStream(stream, tinyIntegrity, {
        single: true,
      }).then(() => deferred.resolve())
    },
  })
  .add('ssri + createHash (largeIntegrity)', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(largeTextSplitted)
      const parsed = ssri.parse(largeIntegrity, { single: true })
      const h = crypto.createHash(parsed.algorithm)

      stream.pipe(h)
      stream.on('end', () => {
        const digest = h.digest('base64')

        if (parsed.digest !== digest) {
          throw new Error('Integrity check failed')
        }
        deferred.resolve()
      })
    },
  })
  .add('ssri + createHash (tinyIntegrity)', {
    defer: true,
    fn: function (deferred) {
      const stream = getStream(tinyTextSplitted)
      const parsed = ssri.parse(tinyIntegrity, { single: true })
      const h = crypto.createHash(parsed.algorithm)

      stream.pipe(h)
      stream.on('end', () => {
        const digest = h.digest('base64')

        if (parsed.digest !== digest) {
          throw new Error('Integrity check failed')
        }
        deferred.resolve()
      })
    },
  })
  .on('cycle', function (event) {
    console.log(String(event.target))
    // wtf.dump();
  })
  .run({ async: false })
