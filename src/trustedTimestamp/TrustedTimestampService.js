const TimestampInfo = require('./TrustedTimestampInfo')
const TrustedTimestampRequest = require('./TrustedTimestampRequest')
const { getTsQuery, getTsVerify, getTsReply, generateTsReply, extractCertFromToken, checkSslPath } = require('./TrustedTimestampCommand')
const { normalizeDigestFormat, checkDigestFormat, checkDigest } = require('./TrustedTimestampCheck')
const TempFileService = require('../util/TempFileService')
const CertUtils = require('@techteamer/cert-utils')

/**
 * OpenSSL docs: https://www.openssl.org/docs/manmaster/man1/ts.html
 *
 * Certificate Installation with OpenSSL: http://gagravarr.org/writing/openssl-certs/others.shtml
 *
 * Trustedtimestamp service implements the generate, import and verification of timestamps
 *
 * @class TrustedTimestampService
 * */
class TrustedTimestampService {
  /**
   * @typedef {object}  provider
   * @property {string} name provider name
   * @property {string | urlObject} url provider url
   * @property {object} [auth] optional auth setting
   * @property {number} [priority] optional provider priority
   *
   * @typedef {object}  urlObject
   * @property {string} getTokenUrl
   * @property {string} getTimestampUrl
   *
   * @typedef {object}  auth
   * @property {string} user username
   * @property {string} pass password
   *
   * @typedef {object}       config
   * @property {string}      [certsLocation="/etc/ssl/certs/"]
   * @property {provider[]}  [providers=[{provider}, {provider}, ...]]
   * @constructor
   * @param {string} timestampInfoType (normal, short)
   * @param {config} config
   * @param {string} encoding
   */
  constructor (timestampInfoType = 'normal', config, encoding = 'latin1') {
    this.timestampInfoType = timestampInfoType
    this.config = config
    this.encoding = encoding
    this._init()
  }

  /**
   * init method that sets the config and instantiates the required services
   *
   * @return void
   * @private
   * */
  _init () {
    this.tmpOptions = { prefix: 'request-', postfix: '.tsr' }

    if (this.config) {
      if (!this.config?.certsLocation) {
        throw new Error('trustedTimestamp config "certsLocation" missing!')
      }

      if (!this.config?.providers?.length) {
        throw new Error('trustedTimestamp config "providers" missing or empty!')
      }

      this.tempFileService = new TempFileService()
      this.certUtils = new CertUtils(this.encoding)
      this.providers = this.config.providers
      this.certsLocation = this.config.certsLocation
      this.timestampRequest = new TrustedTimestampRequest(this.providers, this.tempFileService, this.tmpOptions)
    }
  }

  /**
   * Utility method that resolves to a TimestampInfo object containing parsed info from the tsr
   *
   * @param tsr timestamp response
   * @param [isToken=false] true if the input is a timestamp token (not a whole timestamp response)
   * @return {Promise<TimestampInfo>}
   * */
  async getTimestampInfo (tsr, isToken = false) {
    const cleanupTempFns = []
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
          await generateTsReply(inputTempPath, tmp)
          tstPath = tmp.tempPath
          cleanupTempFns.push(tmp.cleanupCallback)
        }

        // extract cert from token
        const x509Cert = await extractCertFromToken(tstPath)
        // parse cert
        const certInfo = await this.certUtils.parseCert(Buffer.from(x509Cert), '', this.certUtils.CertType.PEM)

        if (this.timestampInfoType === 'normal') {
          timestampInfo.setCertInfo(certInfo)
        }
      } catch (err) {
        throw new Error('Unable to get cert info from timestamp token', err)
      }

      return timestampInfo
    } catch (err) {
      return new TimestampInfo(this.timestampInfoType, null, err.message)
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
   *
   * @typedef {object}  result
   * @property {object} timestamp
   * @property {string} providerName
   *
   * @typedef {object}  timestamp
   * @property {string} digest
   * @property {string} hashAlgorithm
   * @property {number} dataSize
   * @property {object} tsr
   * @property {boolean} isToken
   * @property {string} certExpiry
   * @property {boolean | null} verified
   *
   * @param {String} digest
   * @param {String} hashAlgorithm a valid option that openssl accepts (e.g: 'sha256', 'sha512')
   * @param {Number} dataSize the size of the data the digest is generated from
   * @return {Promise<result>}
   * */
  async createTimestampToken (digest, hashAlgorithm, dataSize) {
    const digestFormat = normalizeDigestFormat(hashAlgorithm)

    try {
      if (!checkDigestFormat(digestFormat)) {
        throw new Error(`Unknown digest format: ${hashAlgorithm}`)
      }
      if (!checkDigest(digest)) {
        throw new Error(`Invalid digest: ${digest}`)
      }

      const tsQuery = await getTsQuery(digest, digestFormat)
      const { tsr, providerName } = await this.timestampRequest.getTimestamp(tsQuery)
      if (!tsr) {
        throw new Error('Failed to create trusted timestamp, no provider was available')
      }
      const timestampInfo = await this.getTimestampInfo(tsr, false)
      const certExpiry = timestampInfo.certInfo?.notAfter || null
      const tt = {
        digest,
        hashAlgorithm,
        dataSize,
        tsr,
        isToken: false,
        certExpiry,
        verified: null // not yet
      }

      tt.verified = await this.verifyToken(tt, digest, dataSize)

      return { timestamp: tt, providerName }
    } catch (err) {
      throw new Error(`Failed to create trusted timestamp ${err.message}`)
    }
  }

  /**
   * Verify if a timestamp token corresponds to a particular hash of data
   *
   * @param timestampToken
   * @param {String} digest
   * @param {Number} dataSize
   * @return {Promise<boolean>}
   * */
  async verifyToken (timestampToken, digest, dataSize) {
    if (timestampToken.dataSize !== dataSize) {
      throw new Error(`Timestamp token verification failed: The provided data size (${dataSize}) does not match the time stamped size (${timestampToken.dataSize}).`)
    }

    if (timestampToken.digest !== digest) {
      throw new Error(`Timestamp token verification failed: The provided digest (${digest}) does not match the time stamped digest (${timestampToken.digest}).`)
    }

    // verify token
    return await this.verifyTsr(digest, timestampToken.tsr, timestampToken.isToken)
  }

  /**
   * Verify a hash digest against a timestamp response file
   *
   * @param {String} digest the hash of some data to verify against the response
   * @param {Buffer} tsr a timestamp response
   * @param {Boolean} [isToken=false] indicates that whether the input is a timestamp token or response
   * @return {Promise<boolean>}
   * */
  async verifyTsr (digest, tsr, isToken = false) {
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
      if (cleanupTempFile) {
        cleanupTempFile()
      }

      throw new Error(`Failed to verify tsr ${err.message}`)
    }
  }

  /**
   * testService method that check the ssl installation
   *
   * @return {Promise<string>}
   * */
  async testService () {
    return await checkSslPath()
  }
}

module.exports = TrustedTimestampService
