'use strict'

const test = require('tap').test

const ssri = require('..')

test('works just like from', function (t) {
  const integrity = ssri.fromData('hi')
  const integrityCreate = ssri.create().update('hi').digest()

  t.ok(integrityCreate instanceof integrity.constructor,
    'should be same Integrity that fromData returns')
  t.equal(integrity + '', integrityCreate + '', 'should be the sam as fromData')
  t.end()
})

test('pass in an algo multiple times', t => {
  t.match(ssri.fromData('hi', {
    algorithms: ['sha512', 'sha512'],
  }), {
    sha512: [
      {
        /* eslint-disable-next-line max-len */
        source: 'sha512-FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        /* eslint-disable-next-line max-len */
        digest: 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        algorithm: 'sha512',
        options: [],
      },
      {
        /* eslint-disable-next-line max-len */
        source: 'sha512-FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        /* eslint-disable-next-line max-len */
        digest: 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        algorithm: 'sha512',
        options: [],
      },
    ],
  })
  t.match(ssri.create({
    options: ['foo=bar', 'baz=quux'],
    algorithms: ['sha512', 'sha512'],
  }).update('hi').digest(), {
    sha512: [
      {
        /* eslint-disable-next-line max-len */
        source: 'sha512-FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        /* eslint-disable-next-line max-len */
        digest: 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        algorithm: 'sha512',
        options: [],
      },
      {
        /* eslint-disable-next-line max-len */
        source: 'sha512-FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        /* eslint-disable-next-line max-len */
        digest: 'FQoU7VvqbMcxz4bEFWasQnqNtI7xuf1iZmSzv7uZBx+kySLzPd44cZuMg1Tit6udd+Dmf8EoQ5IKcS5z1Vjhlw==',
        algorithm: 'sha512',
        options: [],
      },
    ],
  })
  t.end()
})

test('can pass options', function (t) {
  const integrity = ssri.create({ algorithms: ['sha256', 'sha384'] }).update('hi').digest()

  t.equal(
    integrity + '',
    'sha256-j0NDRmSPa5bfid2pAcUXaxCm2Dlh3TwayItZstwyeqQ= ' +
    'sha384-B5EAbfgShHckT1PQ/c4hDbgfVXV1EOJqzuNcGKa86qKNzbv9bcBBubTcextU439S',
    'should be expected value'
  )
  t.end()
})
