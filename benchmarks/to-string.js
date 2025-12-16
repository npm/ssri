// From https://github.com/npm/ssri/pull/75
const Benchmark = require('benchmark')
const ssri = require('..')
const suite = new Benchmark.Suite()

const integrity = `sha512-WrLorGiX4iEWOOOaJSiCrmDIamA47exH+Bz7tVwIPb4sCU8w4iNqGCqYuspMMeU5pgz/sU7koP5u8W3RCUojGw== sha256-Qhx213Vjr6GRSEawEL0WTzlb00whAuXpngy5zxc8HYc=`
const parsed = ssri.parse(integrity)
const parsedStrict = ssri.parse(integrity, { strict: true })

suite
  .add('parsed.toString()', function () {
    parsed.toString()
  })
  .add('parsedStrict.toString()', function () {
    parsedStrict.toString()
  })
  .on('cycle', function (event) {
    console.log(String(event.target))
  })
  .run({ async: false })
