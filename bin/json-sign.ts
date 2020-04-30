import crypto from 'crypto'
import fs from 'fs'
import { Credentials, OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import http from 'http'
import os from 'os'
import url from 'url'

import { jsonBuffify } from '../src/json-digest'
import { KmsSigner } from '../src/ksm-signer'

const oauth2Config = {
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: 'http://localhost:3081/oauth2callback'
}

export function authenticate(scopes: string[]): Promise<OAuth2Client> {
  const scopesKey = crypto
    .createHash('sha1')
    .update(scopes.join(''))
    .digest('hex')
  const authCacheFile = `${os.tmpdir()}/json-sign-${scopesKey}-auth.json`

  return new Promise((resolve, reject) => {
    const oauth2Client = new google.auth.OAuth2(
      oauth2Config.clientId,
      oauth2Config.clientSecret,
      oauth2Config.redirectUri
    )

    if (fs.existsSync(authCacheFile)) {
      console.log(`Using auth cache file: ${authCacheFile}`)
      const token = JSON.parse(fs.readFileSync(authCacheFile).toString('utf8')) as Credentials
      const now = Date.now()
      if (token.expiry_date && token.expiry_date > now - 5 * 60 * 1000) {
        oauth2Client.credentials = token
        return resolve(oauth2Client)
      }
    }

    const authorizeUrl = oauth2Client.generateAuthUrl({
      // eslint-disable-next-line @typescript-eslint/camelcase
      access_type: 'online',
      scope: scopes.join(' ')
    })

    const server = http
      .createServer(async (req, res) => {
        try {
          // Disable keep alive
          res.setHeader('Connection', 'close')
          if (req.url && req.url.startsWith('/oauth2callback')) {
            const qs = new url.URL(req.url, 'http://localhost:3081').searchParams
            const code = qs.get('code')
            if (code == null) {
              throw Error(`url ${req.url} does not contain code`)
            }
            res.end('Authentication successful! Please return to the console.')
            const { tokens } = await oauth2Client.getToken(code)
            fs.writeFileSync(authCacheFile, Buffer.from(JSON.stringify(tokens)))
            oauth2Client.credentials = tokens
            server.close()
            resolve(oauth2Client)
          }
        } catch (e) {
          server.close()
          reject(e)
        } finally {
          res.end()
          if (res.connection != null) {
            res.connection.destroy()
          }
        }
      })
      .listen(3081, () => {
        console.log(`open ${authorizeUrl}`)
      })
  })
}

async function main(): Promise<number> {
  const scopes = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloudkms']
  const oAuth2Client = await authenticate(scopes)

  const kmsSign = new KmsSigner(
    oAuth2Client,
    'projects/connectedcars-testing/locations/europe-west1/keyRings/test/cryptoKeys/test2/cryptoKeyVersions/1',
    'sha256'
  )

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

  const sampleBuffer = jsonBuffify(sample)
  const signature = await kmsSign.sign(sampleBuffer)
  console.log(signature.toString('hex'))

  const pubKey =
    '-----BEGIN PUBLIC KEY-----\n' +
    'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtwjO7TLx2jCavYsA8y8F\n' +
    'E5E1zEibt6g4cwErqz2/xx0aGdxE17HJa8JHLJiXoHI0kDqxoSzwoc1DhJ7mOFdO\n' +
    'OMrOIy26Y6YUgVC7WlEg3nAv1LPVZW5VMO2V1IqXFkRI8ADRoFv+A2lDqr3saqrg\n' +
    'dN7nBPgfKxRTqMplB+i73cWfyDmAWUTdhMh5N0hi+3bInHLJaNVius3UrETfAM+l\n' +
    'nTpn8rhtb4rR69HGWMGSfoErlQidItyWZyrA+oWqHO1NLhgrBl3aIgWe2wDudWsS\n' +
    'qRevVGlM6T/f5lXxDeKfPgKEVXH/+Xrucc5AtTxCcYrZtybBSRUdn6qh/H71g7A0\n' +
    'FJnrGrTVH7ciCUurC59fCTC78rNE8yNhUAiBEukV84dqFHy9x7/QQVmwDfwJBmsG\n' +
    'F9tdgK6oTgULOqFz6PHwFjF9RDvR/ZnkSwdu4JavB6zonLRHDUFPy950AP7zc3wJ\n' +
    'UhBw10px4AB48VpTKaHfpzl71UO4lhoJc4YB1O4f1PP0PszkYFDXVsu2KYXSuhL7\n' +
    'weMhM1ripIDhHHr+ul1+kXdmdtMuH5FyCeINUvy3IWq9sN1qAwWdHYrkV3GlkFBh\n' +
    'UDxxKKImuLHbDE5mQplv3kwR7tc+MzYQdJF7NIL3anByoLFyCuq9lsBZ00IOuDA7\n' +
    'hMikpypB7VOU+7bWV/4rf6ECAwEAAQ==\n' +
    '-----END PUBLIC KEY-----'

  const verifier = crypto.createVerify('RSA-SHA256')
  verifier.update(sampleBuffer)
  const res = verifier.verify(pubKey, signature)
  console.log(res)

  return 0
}

main()
  .then(exitCode => {
    process.exit(exitCode)
  })
  .catch(e => {
    console.error(e)
    process.exit(0)
  })
