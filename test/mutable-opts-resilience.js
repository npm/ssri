const { test } = require('node:test')
const assert = require('node:assert')
const ssri = require('../')

const data = 'hello world'
const expectIntegrity = ssri.fromData(data, { algorithms: ['sha512'] })
const expectSize = data.length

test('support adding bad integrity later', async () => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = ssri.parse('sha512-deepbeets')
  await assert.rejects(stream.end(data).collect(), {
    code: 'EINTEGRITY',
  })
})

test('support adding bad integrity string later', async () => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = 'sha512-deepbeets'
  await assert.rejects(stream.end(data).collect(), {
    code: 'EINTEGRITY',
  })
})

test('support adding bad size later', async () => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.size = 2
  await assert.rejects(stream.end(data).collect(), {
    code: 'EBADSIZE',
  })
})

test('support adding good integrity later', async () => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = expectIntegrity
  await stream.end(data).on('verified', match => {
    assert.deepStrictEqual(match, expectIntegrity.sha512[0])
  }).collect()
})

test('support adding good integrity string later', async () => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.integrity = String(expectIntegrity)
  await stream.end(data).on('verified', match => {
    assert.deepStrictEqual(match, expectIntegrity.sha512[0])
  }).collect()
})

test('support adding good size later', async () => {
  const opts = {}
  const stream = ssri.integrityStream(opts)
  opts.size = expectSize
  await stream.end(data).on('size', size => {
    assert.deepStrictEqual(size, expectSize)
  }).collect()
})
