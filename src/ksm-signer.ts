import crypto from 'crypto'
import { OAuth2Client } from 'google-auth-library'
import { cloudkms_v1 as cloudKmsV1, google } from 'googleapis'

export class KmsSigner {
  private ksm: cloudKmsV1.Cloudkms
  private keyResourceId: string
  private algorithm: string
  public constructor(oAuth2Client: OAuth2Client, keyResourceId: string, algorithm: 'sha256' | 'sha384' | 'sha512') {
    this.ksm = google.cloudkms({ version: 'v1', auth: oAuth2Client })
    this.keyResourceId = keyResourceId
    this.algorithm = algorithm
    // TODO: Check that key can do the requested algorithm
  }

  public async sign(buffer: Buffer): Promise<Buffer> {
    const hash = crypto.createHash(this.algorithm)
    hash.update(buffer)
    const digestBase64 = hash.digest().toString('base64')

    const keysResponse = await this.ksm.projects.locations.keyRings.cryptoKeys.cryptoKeyVersions.asymmetricSign({
      name: this.keyResourceId,
      requestBody: {
        digest: {
          ...(this.algorithm === 'sha256' ? { sha256: digestBase64 } : {}),
          ...(this.algorithm === 'sha384' ? { sha384: digestBase64 } : {}),
          ...(this.algorithm === 'sha512' ? { sha384: digestBase64 } : {})
        }
      }
    })
    if (!keysResponse.data.signature) {
      throw new Error(`Request failed`)
    }
    return Buffer.from(keysResponse.data.signature, 'base64')
  }
}
