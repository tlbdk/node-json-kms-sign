import { jsonBuffify, jsonDigest } from './json-digest'

describe('json-digest', () => {
  const sample = {
    string: 'string',
    int: 1,
    float: 1.1,
    null: null,
    false: false,
    true: true,
    intArray: [1, 2, 3, 4],
    object: {
      stringKey: 'string',
      intKey: 1
    },
    emptyArray: []
  }

  it('should generate JSON that produces the same object', async () => {
    const buffer = jsonBuffify(sample)
    expect(JSON.parse(buffer.toString('utf8'))).toEqual(sample)
    expect(jsonDigest(sample, 'sha256').toString('hex')).toEqual(
      'ad75e36470facbd64891946e96213c04addf95825cc59a6d9a68f276f13d65e2'
    )
  })
  it('should digest sample with sha256 to the expected value', async () => {
    expect(jsonDigest(sample, 'sha256').toString('hex')).toEqual(
      'ad75e36470facbd64891946e96213c04addf95825cc59a6d9a68f276f13d65e2'
    )
  })

  it('should digest parsed JSON with sha256 to the expected value', async () => {
    const sample2 = JSON.parse(JSON.stringify(sample, null, 4))
    expect(jsonDigest(sample2, 'sha256').toString('hex')).toEqual(
      'ad75e36470facbd64891946e96213c04addf95825cc59a6d9a68f276f13d65e2'
    )
  })
})
