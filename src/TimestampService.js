const uuid = require('uuid')
const fs = require('fs').promises
const util = require('util')
const exec = util.promisify(require('child_process').exec)
const moment = require('moment')
const path = require('node:path')
const TimestampProvider = require('./providers/TimestampProvider')

/**
 * @class Timestamp
 * This class is responsible for creating and verifying timestamps
 *
 * A timestamp token is part of the timestamp (response).
 * You can extract the token from a timestamp but cannot
 * create the original timestamp response from a token.
 *
 * Defaults handle timestamp responses (not just timestamp tokens)
 * You can handle tokens too by using token specific calls or flags
 *
 * This class does not care about specific digest algorithms and digests.
 * You are free to use any hashing algorithm supported by openssl.
 */
class Timestamp {
  /**
   * @return {Array<String>}
   */
  static get SUPPORTED_ALGORITHMS () {
    // use: `openssl dgst -list` to check supported digests in your environment...
    return [
      'blake2b512',
      'blake2s256',
      'md5',
      'md5-sha1',
      'ripemd',
      'ripemd160',
      'rmd160',
      'sha1',
      'sha224',
      'sha256',
      'sha3-224',
      'sha3-256',
      'sha3-384',
      'sha3-512',
      'sha384',
      'sha512',
      'sha512-224',
      'sha512-256',
      'shake128',
      'shake256',
      'sm3',
      'ssl3-md5',
      'ssl3-sha1'
    ]
  }

  /**
   * @param {Array<TimestampProvider>} providers
   * @param {Object} config
   * @param {String} config.tsaCertDir location of trusted TSA Root certificates
   * @param {String} config.tempDir location to use for temp files
   * @param {String|null} config.algorithm algorithm to use for hashing (default: 'sha256')
   * @param {Console|Logger} logger
   */
  constructor (config, logger) {
    this.logger = logger
    this.providers = []
    this.tsaCertDir = config.tsaCertDir
    this.tempDir = config.tempDir
    this.algorithm = config.algorithm || 'sha256'
  }

  /**
   * Adds a TimestampProvider to this.providers
   *
   * @param {TimestampProvider} timestampProvider
   */
  addProvider (timestampProvider) {
    this.providers.push(timestampProvider)
  }
  /**
   * CREATION
   */

  /**
   * Iterates over the providers and tries to create a timestamp for the received query.
   * If the creation fails, it throws Error.
   * Otherwise, it returns the timestamp.
   *
   * @param {Buffer} query
   * @param {String} algorithm
   * @param {Array<string>|null} providers
   * @return {Promise<Buffer>} the timestamp data
   * @private
   */
  async _create (query, algorithm = this.algorithm, providers = null) {
    let timestampProviders = this.providers
    if (providers) {
      timestampProviders = timestampProviders.filter(provider => providers.includes(provider.name))
    }
    if (timestampProviders.length < 1) {
      throw new Error('Not timestamp providers found. Check your filters!')
    }

    for (const provider of timestampProviders) {
      try {
        const timestamp = await provider.create(query)
        this.logger.info(`Created timestamp using: ${provider.name} `)

        return timestamp
      } catch (error) {
        this.logger.warn(`Failed to create timestamp with provider: ${provider.name}` + error)
      }
    }
    throw new Error('Could not create timestamp with any provider!')
  }

  /**
   * Creates timestamp for the received data
   *
   * @param {Buffer|String} data
   * @param {String} algorithm
   * @param {Array<string>|null} providers
   * @return {Promise<Buffer>} the timestamp data
   */
  async create (data, algorithm = this.algorithm, providers = null) {
    const query = await this.createQuery(data, algorithm)
    return await this._create(query, algorithm, providers)
  }

  /**
   * Create Timestamp query-data for the data received in the parameter
   *
   * @param {Buffer|String} data
   * @param {String} algorithm
   * @return {Promise<Buffer>}
   */
  async createQuery (data, algorithm = this.algorithm) {
    this.verifyAlgorithmIsSupported(algorithm)
    const tempFile = path.join(this.tempDir, `timestamp-data-${uuid.v4()}`)
    const queryFile = `${tempFile}.tsq`
    try {
      await fs.writeFile(tempFile, data)
      await exec(`openssl ts -query -data ${tempFile} -${algorithm} -cert -out ${queryFile} &> /dev/null`)
      return await fs.readFile(queryFile)
    } finally {
      await fs.rm(tempFile, { force: true })
      await fs.rm(queryFile, { force: true })
    }
  }

  /**
   * Create timestamp using precalculated hex digest and given algorithm
   *
   * @param {String} digest
   * @param {String} algorithm
   * @param {Array<string>|null} providers
   * @return {Promise<Buffer>}
   */
  async createWithDigest (digest, algorithm = this.algorithm, providers = null) {
    const query = await this.createQueryWithDigest(digest, algorithm)
    return await this._create(query, algorithm, providers)
  }

  /**
   * Create Timestamp query-data for the digest received in the parameter
   *
   * @param {String} digest
   * @param {String} algorithm
   * @return {Promise<Buffer>}
   */
  async createQueryWithDigest (digest, algorithm = this.algorithm) {
    this.verifyAlgorithmIsSupported(algorithm)
    const tempFile = path.join(this.tempDir, `timestamp-data-${uuid.v4()}`)
    const queryFile = `${tempFile}.tsq`

    try {
      await exec(`openssl ts -query -digest ${digest} -${algorithm} -cert -out ${queryFile} &> /dev/null`)
      return await fs.readFile(queryFile)
    } finally {
      await fs.rm(tempFile, { force: true })
      await fs.rm(queryFile, { force: true })
    }
  }

  /**
   * Create timestamp and return with token
   *
   * @param {Buffer} data
   * @param {String} algorithm
   * @param {Array<string>|null} providers
   * @return {Promise<Buffer>}
   */
  async createToken (data, algorithm = this.algorithm, providers = null) {
    const timestamp = await this.create(data, algorithm, providers)
    return this.getTokenFromTimestamp(timestamp)
  }

  /**
   * Create timestamp and return with token using precalculated hex digest and given algorithm
   *
   * @param {String} digest
   * @param {String} algorithm
   * @param {Array<string>|null} providers
   * @return {Promise<Buffer>}
   */
  async createTokenWithDigest (digest, algorithm = this.algorithm, providers = null) {
    const timestamp = await this.createWithDigest(digest, algorithm, providers)
    return this.getTokenFromTimestamp(timestamp)
  }

  /**
   * VERIFICATION
   */

  /**
   * Throw if timestamp is invalid for data
   *
   * @param {Buffer} timestamp
   * @param {Buffer|String} data
   * @param {Boolean} isToken
   * @return {Promise<void>}
   */
  async verify (timestamp, data, isToken = false) {
    const tempDataFile = path.join(this.tempDir, `timestamp-data-${uuid.v4()}`)
    const tempTimestampFile = path.join(this.tempDir, `timestamp-${uuid.v4()}`)

    try {
      await fs.writeFile(tempDataFile, data)
      await fs.writeFile(tempTimestampFile, timestamp)

      const { stdout } = await exec(`openssl ts -verify -data ${tempDataFile} ${isToken ? '-token_in ' : ''}-in ${tempTimestampFile} -CApath ${this.tsaCertDir} 2> /dev/null`)

      if (!stdout.includes('Verification: OK')) {
        throw new Error('Timestamp failed verification!')
      }
    } finally {
      await fs.rm(tempDataFile, { force: true })
      await fs.rm(tempTimestampFile, { force: true })
    }
  }

  /**
   * Throw if timestamp token is invalid for data
   *
   * @param {Buffer} timestampToken
   * @param {Buffer} data
   * @return {Promise<void>}
   */
  async verifyToken (timestampToken, data) {
    return this.verify(timestampToken, data, true)
  }

  /**
   * Throw if timestamp is invalid for digest
   *
   * @param {Buffer} timestamp
   * @param {String} digest
   * @param {Boolean} isToken
   * @return {Promise<void>}
   */
  async verifyWithDigest (timestamp, digest, isToken = false) {
    const tempTimestampFile = path.join(this.tempDir, `timestamp-${uuid.v4()}`)

    try {
      await fs.writeFile(tempTimestampFile, timestamp)

      const { stdout } = await exec(`openssl ts -verify -digest ${digest} ${isToken ? '-token_in ' : ''}-in ${tempTimestampFile} -CApath ${this.tsaCertDir} 2> /dev/null`)

      if (!stdout.includes('Verification: OK')) {
        throw new Error('Timestamp failed verification!')
      }
    } finally {
      await fs.rm(tempTimestampFile, { force: true })
    }
  }

  /**
   * Throw if timestamp token is invalid for digest
   *
   * @param {Buffer} timestamp
   * @param {String} digest
   * @return {Promise<void>}
   */
  async verifyTokenWithDigest (timestamp, digest) {
    return this.verifyWithDigest(timestamp, digest, true)
  }

  /**
   * In this function, we verify the timestamp for the data received as a parameter.
   * If the timestamp is valid, it continues to check the date.
   * After the necessary formatting, if the date received as a parameter and the timestamp are the same, then the verification is successful
   *
   * @param {Buffer} timestamp
   * @param {moment.Moment} date
   * @param {Number} thresholdMs
   */
  async verifyCloseToDate (timestamp, date, thresholdMs = 3600000) {
    const dateInTimestamp = await this.getMoment(timestamp)
    const diffMs = Math.abs(date.diff(dateInTimestamp, 'ms'))
    if (diffMs > thresholdMs) {
      throw new Error(`Timestamp is out of range! Timestamp: ${dateInTimestamp.toISOString()} Expected date: ${date.toISOString()} [+-${thresholdMs}ms]`)
    }
  }

  /**
   * HELPERS
   */

  /**
   * Get timestamp token from timestamp (response)
   *
   * @param {Buffer} timestamp
   * @return {Promise<Buffer>}
   */
  async getTokenFromTimestamp (timestamp) {
    const tempFile = path.join(this.tempDir, `timestamp-${uuid.v4()}`)
    const tempOutput = path.join(this.tempDir, `timestamp-token-${uuid.v4()}`)

    try {
      await fs.writeFile(tempFile, timestamp)
      await exec(`openssl ts -reply -in ${tempFile} -token_out -out ${tempOutput} 2> /dev/null`)
      return await fs.readFile(tempOutput)
    } finally {
      await fs.rm(tempFile, { force: true })
      await fs.rm(tempOutput, { force: true })
    }
  }

  /**
   * Get timestamp text (you can parse this if you need more specifics)
   *
   * @param {Buffer} timestamp
   * @param {Boolean} isToken
   * @return {Promise<String>}
   */
  async getText (timestamp, isToken = false) {
    const tempFile = path.join(this.tempDir, `timestamp-${uuid.v4()}`)

    try {
      await fs.writeFile(tempFile, timestamp)
      const { stdout } = await exec(`openssl ts -reply -in ${tempFile} ${isToken ? '-token_in ' : ''} -text 2> /dev/null`)
      return stdout
    } finally {
      await fs.rm(tempFile, { force: true })
    }
  }

  /**
   * Get (TSA) cert from timestamp token
   *
   * @param {Buffer} timestampToken
   * @return {Promise<Buffer>}
   */
  async getCertFromToken (timestampToken) {
    const tempFile = path.join(this.tempDir, `timestamp-${uuid.v4()}`)
    const tempOutput = path.join(this.tempDir, `timestamp-certs-${uuid.v4()}`)

    try {
      await fs.writeFile(tempFile, timestampToken)
      await exec(`openssl pkcs7 -inform der -in "${tempFile}" -print_certs -out ${tempOutput}`)
      return await fs.readFile(tempOutput)
    } finally {
      await fs.rm(tempFile, { force: true })
      await fs.rm(tempOutput, { force: true })
    }
  }

  /**
   * Parse date from timestamp or timestamp token
   *
   * @param {Buffer} timestamp
   * @param {Boolean} isToken
   * @return {Promise<moment.Moment>}
   */
  async getMoment (timestamp, isToken = false) {
    const timestampText = await this.getText(timestamp, isToken)
    const date = RegExp(/Time stamp: (.*)/).exec(timestampText)[1]
    return moment(date, 'MMM DD HH:mm:ss YYYY [GMT]')
  }

  /**
   * Throw if algorithm is not supported!
   *
   * @param {String} algorithm
   * @throws
   */
  verifyAlgorithmIsSupported (algorithm) {
    if (!Timestamp.SUPPORTED_ALGORITHMS.includes(algorithm)) {
      throw new Error(`Algorithm ${algorithm} is not supported!`)
    }
  }
}

module.exports = Timestamp
