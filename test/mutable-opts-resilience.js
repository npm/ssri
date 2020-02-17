const ssri = require('../')
const t = require('tap')

const data = 'hello world'
const expectIntegrity = ssri.fromData(data, { algorithms: ['sha512'] })
const expectSize = data.length

t.test('support adding bad integrity later', t => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = ssri.parse('sha512-deepbeets')
  return t.rejects(stream.end(data).collect(), {
    code: 'EINTEGRITY'
  })
})

t.test('support adding bad integrity string later', t => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = 'sha512-deepbeets'
  return t.rejects(stream.end(data).collect(), {
    code: 'EINTEGRITY'
  })
})

t.test('support adding bad size later', t => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.size = 2
  return t.rejects(stream.end(data).collect(), {
    code: 'EBADSIZE'
  })
})

t.test('support adding good integrity later', t => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = expectIntegrity
  return stream.end(data).on('verified', match => {
    t.same(match, expectIntegrity.sha512[0])
  }).collect()
})

t.test('support adding good integrity string later', t => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = String(expectIntegrity)
  return stream.end(data).on('verified', match => {
    t.same(match, expectIntegrity.sha512[0])
  }).collect()
})

t.test('support adding good size later', t => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.size = expectSize
  return stream.end(data).on('size', size => {
    t.same(size, expectSize)
  }).collect()
})
