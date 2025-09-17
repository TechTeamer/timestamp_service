import { CertService } from '@techteamer/cert-utils'
import { FileOptions as TempFileOptions } from 'tmp'

import { TimestampInfo } from './TrustedTimestampInfo'
import { TrustedTimestampRequest } from './TrustedTimestampRequest'
import {
  checkSslPath,
  extractCertFromToken,
  generateTsReply,
  getTsQuery,
  getTsReply,
  getTsVerify
} from './TrustedTimestampCommand'
import { checkDigest, checkDigestFormat, normalizeDigestFormat } from './TrustedTimestampCheck'
import { TempFileService } from '../util/TempFileService'
import { CreateTimestampTokenError } from './error/create-timestamp-token.error'
import type { TimestampConfig } from './types/timestamp-config.type'
import type { TimestampProvider } from './types/timestamp-provider.type'
import type { CreatedTimestampToken, Timestamp } from './types/timestamp-token.type'

/**
 * OpenSSL docs: https://www.openssl.org/docs/manmaster/man1/ts.html
 *
 * Certificate Installation with OpenSSL: http://gagravarr.org/writing/openssl-certs/others.shtml
 *
 * Trustedtimestamp service implements the generate, import and verification of timestamps
 *
 * */
export class TrustedTimestampService {
  private readonly tmpOptions: TempFileOptions = { prefix: 'request-', postfix: '.tsr' }
  private tempFileService!: TempFileService
  private certService!: CertService
  private providers!: TimestampProvider[]
  private certsLocation!: string
  private timestampRequest!: TrustedTimestampRequest

  constructor(
    private readonly timestampInfoType: 'normal' | 'short' = 'normal',
    private readonly config: TimestampConfig = {} as TimestampConfig,
    private readonly encoding = 'latin1'
  ) {
    this._init()
  }

  /**
   * init method that sets the config and instantiates the required services
   * */
  private _init(): void {
    if (this.config) {
      if (!this.config?.certsLocation) {
        throw new Error('trustedTimestamp config "certsLocation" missing!')
      }

      if (!this.config?.providers?.length) {
        throw new Error('trustedTimestamp config "providers" missing or empty!')
      }

      this.tempFileService = new TempFileService()
      this.certService = new CertService(this.encoding)
      this.providers = this.config.providers
      this.certsLocation = this.config.certsLocation
      this.timestampRequest = new TrustedTimestampRequest(this.providers, this.tempFileService, this.tmpOptions)
    }
  }

  /**
   * Utility method that resolves to a TimestampInfo object containing parsed info from the tsr
   * */
  async getTimestampInfo(tsr: Buffer, isToken = false): Promise<TimestampInfo> {
    const cleanupTempFns: (() => unknown)[] = []
    let inputTempPath = ''

    try {
      const tsrtmp = await this.tempFileService.createTempFile(this.tmpOptions, tsr)
      inputTempPath = tsrtmp.tempPath
      cleanupTempFns.push(tsrtmp.cleanupCallback)

      const responseText = await getTsReply(inputTempPath, isToken)
      const timestampInfo = new TimestampInfo(this.timestampInfoType, responseText)

      // get cert info

      try {
        // get raw token if the input was a whole response (TimestampResponse->TimestampToken)
        let tstPath
        if (isToken) {
          tstPath = inputTempPath
        } else {
          const tmp = await this.tempFileService.createTempFile(this.tmpOptions)
          await generateTsReply(inputTempPath, tmp.tempPath)
          tstPath = tmp.tempPath
          cleanupTempFns.push(tmp.cleanupCallback)
        }

        // extract cert from token
        const x509Cert = await extractCertFromToken(tstPath)
        // parse cert
        const certInfo = await this.certService.parseCert(Buffer.from(x509Cert), '', this.certService.CertType.PEM)

        if (this.timestampInfoType === 'normal') {
          timestampInfo.setCertInfo(certInfo)
        }
      } catch (err) {
        throw new Error('Unable to get cert info from timestamp token', err as Error)
      }

      return timestampInfo
    } catch (err) {
      return new TimestampInfo(this.timestampInfoType, null!, (err as Error).message)
    } finally {
      for (const cleanUpFn of cleanupTempFns) {
        if (typeof cleanUpFn === 'function') {
          cleanUpFn()
        }
      }
    }
  }

  /**
   * Returns a TimestampToken instance for a hash digest and a hash algorithm.
   * It requests a token from the TSA and verifies the received response.
   * The returned timestamp token represents the token
   * and contains the tsr with the verification result.
   * */
  async createTimestampToken(digest: string, hashAlgorithm: string, dataSize: number): Promise<CreatedTimestampToken> {
    const digestFormat = normalizeDigestFormat(hashAlgorithm)

    try {
      if (!checkDigestFormat(digestFormat)) {
        throw new Error(`Unknown digest format: ${hashAlgorithm}`)
      }
      if (!checkDigest(digest)) {
        throw new Error(`Invalid digest: ${digest}`)
      }

      const tsQuery = await getTsQuery(digest, digestFormat)
      const { tsr, providerName, logHistory } = await this.timestampRequest.getTimestamp(tsQuery)
      if (!tsr) {
        throw new CreateTimestampTokenError('Failed to create trusted timestamp, no provider was available', {
          providerName,
          logHistory
        })
      }
      const timestampInfo = await this.getTimestampInfo(tsr, false)
      const certExpiry = timestampInfo.certInfo?.notAfter || null
      const tt: Timestamp = {
        digest,
        hashAlgorithm,
        dataSize,
        tsr,
        isToken: false,
        certExpiry,
        verified: null // not yet
      }

      tt.verified = await this.verifyToken(tt, digest, dataSize)

      return { timestamp: tt, providerName, logHistory }
    } catch (error) {
      if (error instanceof CreateTimestampTokenError) {
        throw error
      }

      throw new CreateTimestampTokenError(`Failed to create trusted timestamp ${(error as Error).message}`)
    }
  }

  /**
   * Verify if a timestamp token corresponds to a particular hash of data
   * */
  async verifyToken(timestampToken: Timestamp, digest: string, dataSize: number): Promise<boolean> {
    if (timestampToken.dataSize !== dataSize) {
      throw new Error(
        `Timestamp token verification failed: The provided data size (${dataSize}) does not match the time stamped size (${timestampToken.dataSize}).`
      )
    }

    if (timestampToken.digest !== digest) {
      throw new Error(
        `Timestamp token verification failed: The provided digest (${digest}) does not match the time stamped digest (${timestampToken.digest}).`
      )
    }

    // verify token
    return await this.verifyTsr(digest, timestampToken.tsr, timestampToken.isToken)
  }

  /**
   * Verify a hash digest against a timestamp response file
   * */
  async verifyTsr(digest: string, tsr: Buffer, isToken = false): Promise<boolean> {
    let cleanupTempFile = null

    try {
      if (!checkDigest(digest)) {
        throw new Error(`Invalid digest: ${digest}`)
      }

      // save the tsr on disk because openssl can only read it from file
      const { tempPath, cleanupCallback } = await this.tempFileService.createTempFile(this.tmpOptions, tsr)
      cleanupTempFile = cleanupCallback

      const stdout = await getTsVerify(digest, tempPath, isToken, this.certsLocation)

      const verificationResult = /Verification: OK/i.test(stdout)

      if (cleanupTempFile) {
        cleanupTempFile()
      }

      return verificationResult
    } catch (err) {
      if (typeof cleanupTempFile === 'function') {
        cleanupTempFile()
      }

      throw new Error(`Failed to verify tsr ${(err as Error).message}`)
    }
  }

  /**
   * testService method that check the ssl installation
   * */
  async testService(): Promise<string> {
    return await checkSslPath()
  }
}
