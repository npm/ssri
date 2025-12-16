'use strict'

const { test } = require('node:test')
const assert = require('node:assert')

const ssri = require('..')

test('works just like from', () => {
  const integrity = ssri.fromData('hi')
  const integrityCreate = ssri.create().update('hi').digest()

  assert.ok(integrityCreate instanceof integrity.constructor,
    'should be same Integrity that fromData returns')
  assert.strictEqual(integrity + '', integrityCreate + '', 'should be the sam as fromData')
})

test('pass in an algo multiple times', () => {
  const result = ssri.fromData('hi', {
    algorithms: ['sha512', 'sha512'],
  })
  assert.strictEqual(result.sha512.length, 2)
  assert.strictEqual(result.sha512[0].algorithm, 'sha512')
  /* eslint-disable-next-line max-len */
  assert.strictEqual(result.sha512[0].digest, 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==')
  assert.strictEqual(result.sha512[1].algorithm, 'sha512')
  /* eslint-disable-next-line max-len */
  assert.strictEqual(result.sha512[1].digest, 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==')

  const result2 = ssri.create({
    options: ['foo=bar', 'baz=quux'],
    algorithms: ['sha512', 'sha512'],
  }).update('hi').digest()
  assert.strictEqual(result2.sha512.length, 2)
  assert.strictEqual(result2.sha512[0].algorithm, 'sha512')
  /* eslint-disable-next-line max-len */
  assert.strictEqual(result2.sha512[0].digest, 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==')
  assert.strictEqual(result2.sha512[1].algorithm, 'sha512')
  /* eslint-disable-next-line max-len */
  assert.strictEqual(result2.sha512[1].digest, 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==')
})

test('can pass options', () => {
  const integrity = ssri.create({ algorithms: ['sha256', 'sha384'] }).update('hi').digest()

  assert.strictEqual(
    integrity + '',
    'sha256-j0NDRmSPa5bfid2pAcUXaxCm2Dlh3TwayItZstwyeqQ= ' +
    'sha384-B5EAbfgShHckT1PQ/c4hDbgfVXV1EOJqzuNcGKa86qKNzbv9bcBBubTcextU439S',
    'should be expected value'
  )
})
