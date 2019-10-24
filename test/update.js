const ssri = require('../')
const t = require('tap')

const i = ssri.parse('sha1-foo')
const o = ssri.parse('sha512-bar')
i.merge(o)
t.equal(i.toString(), 'sha1-foo sha512-bar', 'added second algo')
t.throws(() => i.merge(ssri.parse('sha1-baz')), {
  message: 'hashes do not match, cannot update integrity'
})
i.merge(o)
i.merge(ssri.parse('sha1-foo'))
t.equal(i.toString(), 'sha1-foo sha512-bar', 'did not duplicate')
