const ssri = require('../')
const { test } = require('node:test')
const assert = require('node:assert')

test('merge', () => {
  const i = ssri.parse('sha1-foo')
  const o = ssri.parse('sha512-bar')
  i.merge(o)
  assert.strictEqual(i.toString(), 'sha1-foo sha512-bar', 'added second algo')
  assert.throws(() => i.merge(ssri.parse('sha1-baz')), {
    message: 'hashes do not match, cannot update integrity',
  })
  i.merge(o)
  i.merge(ssri.parse('sha1-foo'))
  assert.strictEqual(i.toString(), 'sha1-foo sha512-bar', 'did not duplicate')
})
