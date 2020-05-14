import crypto from 'crypto'

// https://github.com/microsoft/TypeScript/issues/1897
export type Json = null | boolean | number | string | Json[] | { [prop: string]: Json }

const arrayOpen = Buffer.from('[', 'utf8')
const arrayClose = Buffer.from(']', 'utf8')
const objectOpen = Buffer.from('{', 'utf8')
const objectClose = Buffer.from('}', 'utf8')
const comma = Buffer.from(',', 'utf8')

export function jsonBuffify(json: Json): Buffer {
  if (json === null) {
    return Buffer.from('null', 'utf8')
  } else {
    const type = typeof json
    if (type === 'boolean') {
      return Buffer.from(json.toString(), 'utf8')
    } else if (type === 'number') {
      return Buffer.from(json.toString(), 'utf8')
    } else if (type === 'string') {
      return Buffer.from(JSON.stringify(json), 'utf8')
    } else if (type === 'object') {
      const values: Buffer[] = []
      if (Array.isArray(json)) {
        values.push(arrayOpen)
        for (const [i, value] of json.entries()) {
          values.push(jsonBuffify(value))
          if (i !== json.length - 1) {
            values.push(comma)
          }
        }
        values.push(arrayClose)
      } else {
        values.push(objectOpen)
        const obj = json as { [key: string]: Json }
        const keys = Object.keys(json).sort()
        for (const [i, key] of keys.entries()) {
          values.push(Buffer.from(JSON.stringify(key) + ':', 'utf8'))
          values.push(jsonBuffify(obj[key]))
          if (i !== keys.length - 1) {
            values.push(comma)
          }
        }
        values.push(objectClose)
      }
      return Buffer.concat(values)
    } else {
      throw new Error(`Non JSON type ${type}: ${json}`)
    }
  }
}

export function jsonDigest(json: Json, algorithm = 'sha256'): Buffer {
  const hash = crypto.createHash(algorithm)
  hash.update(jsonBuffify(json))
  return hash.digest()
}
