const { exec } = require('child_process')

/**
 * @class CertValidationError
 * @property {number} httpStatusCode
 * */
class CertValidationError extends Error {
  static get Reason () {
    return {
      INVALID: 'INVALID',
      MALFORMED: 'MALFORMED',
      EXPIRED: 'EXPIRED',
      REVOKED: 'REVOKED',
      NOT_ACTIVE_YET: 'NOT_ACTIVE_YET',
      INCORRECT_PASSWORD: 'INCORRECT_PASSWORD'
    }
  }

  get Reason () {
    return CertValidationError.Reason
  }

  constructor (reason, message = `Failed to validate certificate, reason: ${reason}`) {
    super(message)

    this.reason = reason
  }
}

/**
 * @class CertInfo
 * @property {Object} subject
 * @property {Object} issuer
 * @property {Date} notBefore
 * @property {Date} notAfter
 * @property {Boolean} decrypted
 * */
class CertInfo {
  constructor () {
    this.subject = null
    this.issuer = null
    this.notBefore = null
    this.notAfter = null
    this.decrypted = false
  }

  get isExpired () {
    return this.notAfter < Date.now()
  }

  get isEffective () {
    return this.notBefore < Date.now()
  }

  get isValid () {
    return !this.isExpired && this.isEffective
  }
}

class CertService {
  static get CertType () {
    return {
      P12: 'P12',
      PEM: 'PEM'
    }
  }

  get CertType () {
    return CertService.CertType
  }

  get CertInfo () {
    return CertInfo
  }

  /**
   * @param {Buffer} certBuf Buffer of a P12 cert, Buffer of a utf-8 encoded PEM string
   * @param {String} [password] Used for decrypting P12 containers, not required for PEM certs
   * @param {String} [certType='P12']
   * @returns {Promise<null|CertInfo>}
   */
  async parseCert (certBuf, password, certType = CertService.CertType.P12) {
    switch (certType) {
      case CertService.CertType.P12:
        return this.parsePkcs12Cert(certBuf, password)
      case CertService.CertType.PEM:
        return this.parsePemCert(certBuf)
      default:
        throw new Error('Invalid certType provided')
    }
  }

  /**
   * Decrypt and parse the cert from the specified p12 container
   * @param {Buffer} p12Buf
   * @param {String} password
   * @returns {Promise<null|CertInfo>}
   * @throws {CertValidationError}
   */
  async parsePkcs12Cert (p12Buf, password) {
    if (!(p12Buf instanceof Buffer)) {
      throw new Error('p12Buf argument must be a Buffer')
    }

    try {
      const command = 'openssl pkcs12 -nodes -passin env:PASSWORD | openssl x509 -noout -subject -issuer -enddate -startdate'
      const env = {
        PASSWORD: password
      }

      const opensslStdout = await this._execOpenSSLCLI(command, p12Buf, env)
      return this._parseOpenSSLCertOutput(opensslStdout)
    } catch (err) {
      if (err.message.includes('Mac verify error: invalid password?')) {
        throw new CertValidationError(CertValidationError.Reason.INCORRECT_PASSWORD)
      }

      throw new CertValidationError(CertValidationError.Reason.INVALID, `Error parsing PKCS12 certificate ${err}`)
    }
  }

  /**
   * @param {string | Buffer} pemCert String or a Buffer containing the utf-8 encoded PEM string. Individual cert in PEM format
   * @returns {Promise<CertInfo>}
   */
  async parsePemCert (pemCert) {
    pemCert = this._toPemBuffer(pemCert)

    try {
      const command = 'openssl x509 -noout -subject -issuer -enddate -startdate -serial'

      const opensslStdout = await this._execOpenSSLCLI(command, pemCert)
      const certInfo = this._parseOpenSSLCertOutput(opensslStdout)

      return certInfo
    } catch (err) {
      throw new CertValidationError(CertValidationError.Reason.INVALID, `Error parsing PEM certificate ${err}`)
    }
  }

  /**
   * @param {string | Buffer} pem
   * @returns {Buffer}
   */
  _toPemBuffer (pem) {
    if (typeof pem === 'string') {
      pem = Buffer.from(pem, 'utf8')
    }
    if (!(pem instanceof Buffer)) {
      throw new Error('pem must be a string or a Buffer')
    }

    return pem
  }

  /**
   * @param {string} command
   * @param {Buffer | null} [stdInputBuf]
   * @param {Record<string, string>} [env={}]
   * @returns {Promise<string>}
   */
  async _execOpenSSLCLI (command, stdInputBuf, env = {}) {
    return new Promise((resolve, reject) => {
      const options = { env }
      const callback = (err, result) => err ? reject(err) : resolve(result)
      const child = exec(command, options, callback)

      if (stdInputBuf) {
        child.stdin.write(stdInputBuf)
        child.stdin.end()
      }
    })
  }

  /**
   * @param {string} opensslStdout
   * @returns {CertInfo}
   */
  _parseOpenSSLCertOutput (opensslStdout) {
    /*
     * Example openssl stdout:
     * subject=C = HU, L = Budapest, O = Test Kft., organizationIdentifier = 00000000-20-00, CN = Teszt, GN = Richard, SN = Toth, emailAddress = teszt@localhost, serialNumber = 1.3.6.1.4.1.00000.2.2.99.00000
     * issuer=C = HU, L = Budapest, O = Microsec Ltd., OU = e-Szigno CA, CN = e-Szigno Test CA3
     * notAfter=Feb 27 11:54:00 2020 GMT
     * notBefore=Nov 26 11:54:00 2019 GMT
     * */

    const certInfo = new CertInfo()
    certInfo.decrypted = true

    const lines = opensslStdout.split(/\n/)

    for (const line of lines) {
      const [, prop, value] = line.match(/^\s*(\w+)\s*=\s*(.*)$/) || []
      switch (prop) {
        case 'serial':
          certInfo.serial = this._parseSerialLine(value)
          break
        case 'subject':
          certInfo.subject = this._parseSubjectLine(value)
          break
        case 'issuer':
          certInfo.issuer = this._parseSubjectLine(value)
          break
        case 'notAfter':
          certInfo.notAfter = new Date(value)
          break
        case 'notBefore':
          certInfo.notBefore = new Date(value)
          break
      }
    }

    return certInfo
  }

  /**
   * Inserts colons into the serial number
   * @param {String} serial
   * @return {String}
   * @private
   */
  _parseSerialLine (serial) {
    return serial.replace(/([A-Z0-9]{2})/ig, '$1:').slice(0, -1).toLowerCase()
  }

  /**
   * Turns a line likes this into an object of properties:
   * C = HU, L = Budapest, O = Microsec Ltd., OU = e-Szigno CA, CN = e-Szigno Test CA3
   * Where the keys are the symbol before equal sign the values are after until a comma
   * @param {String} line
   * @return {Object}
   * @private
   */
  _parseSubjectLine (line) {
    const obj = {}

    if (typeof line !== 'string') {
      return obj
    }

    // where the value contains delimiter
    const propMatches = Array.from(line.matchAll(/(\w+)\s*=\s*(?:"((?:[^"]|\\")+)"|([^,]+))(?:,|$)/g) || [])
    const props = propMatches.map(match => ({
      key: match[1],
      value: match[2] || match[3]
    }))

    for (const prop of props) {
      const { key, value } = prop

      if (key && value) {
        // unescape double quotes
        const unescaped = value.replace(/\\"/g, '"')

        // Get cert encoding expectations from config (use latin1 as default for backwards compatibility reasons)
        let encoding = config.get('certService.encoding', 'latin1')

        // Regular expression that matches all encoded special characters
        const regex = /((?:\\[A-Z\d]{2}){2,4})/g

        // If encoding is not utf8 but the input looks like utf8 the use that to parse the cert...
        // length is 6 => 2 bytes * (encoded as) 3 characters (1 escape character + 2 others)
        const matches = unescaped.match(regex)
        if (encoding !== 'utf8' && matches && matches.some(match => match.length === 6)) {
          serviceContainer.logger.warn(`Encoding was set as ${encoding}, but utf8 was detected. Using utf8 encoding for cert parsing...`)
          encoding = 'utf8'
        }

        // fix encodings of special characters
        const converted = unescaped
          .replace(regex, (str, group1) => {
            const hex = group1.replace(/\\/g, '')
            const buff = Buffer.from(hex, 'hex')
            const encoded = iconvLite.encode(buff, encoding)
            return encoded.toString()
          })
        obj[key] = converted
      }
    }

    return obj
  }
}

module.exports = CertService
