import { parseRegex } from '../util/regexParser.js'
/**
 * @class TimestampInfo
 * @property {Number} version
 * @property {String} policyOID
 * @property {String} hashAlgorithm
 * @property {String} hash
 * @property {String} serialNumber
 * @property {String} timeStamp
 * @property {Date} timeStampDate
 * @property {Number} accuracy
 * @property {Boolean} ordering
 * @property {String} nonce
 * @property {String} issuer
 * @property {Object} tsa
 * @property {String} tsa.C
 * @property {String} tsa.L
 * @property {String} tsa.O
 * @property {String} tsa.OU
 * @property {String} tsa.CN
 * @property {String|null} [error]
 * @property {CertInfo|null} [certInfo]
 *
 * Status info:
 * Status: Granted.
 * Status description: unspecified
 * Failure info: unspecified
 *
 * TST info:
 * Version: 1
 * Policy OID: 1.3.6.1.4.1.21528.2.2.99
 * Hash Algorithm: sha256
 * Message data:
 * 0000 - c5 3e 94 56 aa 61 ed 56-49 69 74 29 1e 01 d7 2a   .>.V.a.VIit)...*
 * 0010 - 64 cc 24 84 d2 a2 31 4d-33 b6 ca c8 98 23 03 b9   d.$...1M3....#..
 * Serial number: 0x0308441E
 * Time stamp: Jan 30 13:45:20 2018 GMT
 * Accuracy: 0x01 seconds, unspecified millis, unspecified micros
 * Ordering: no
 * Nonce: unspecified
 * TSA: DirName:/C=HU/L=Budapest/O=Microsec Ltd./OU=e-Szigno CA/CN=e-Szigno Test TSA2
 * Extensions:
 * */
class TimestampInfo {
  /**
  * @constructor
  * @param {string} timestampInfoType (normal, short)
  * @param {string} tsText
  * @param {string} error
  */
  constructor (timestampInfoType = 'normal', tsText, error = null) {
    this.error = null
    this.version = null
    this.policyOID = null
    this.hashAlgorithm = null
    this.serialNumber = null
    this.timeStamp = null
    this.accuracy = null
    this.ordering = null
    this.nonce = null
    this.tsa = null

    if (error) {
      this.error = error
    } else {
      if (timestampInfoType === 'short') {
        this.parseOpensslOutputShort(tsText)
      } else {
        this.hash = null
        this.timeStampDate = null
        this.issuer = null
        this.certInfo = null
        this.parseOpensslOutput(tsText)
      }
    }
  }

  /**
   * @param {CertInfo} certInfo
   */
  setCertInfo (certInfo) {
    this.certInfo = certInfo
  }

  /**
   * @param {string} tsText
   */
  parseOpensslOutput (tsText) {
    this.version = parseRegex(tsText, /Version:\s*([^\n\r]+)/, 1, parseInt)
    this.policyOID = parseRegex(tsText, /Policy OID:\s*([^\n\r]+)/, 1)
    this.hashAlgorithm = parseRegex(tsText, /Hash Algorithm:\s*([^\n\r]+)/, 1)
    this.hash = tsText.match(/\d{4} - .*?\s{2}/g).map(line => {
      return line.replace(/\d{4} - /g, '').replace(/[\s*-]/g, '')
    }).join('')
    this.serialNumber = parseRegex(tsText, /Serial number:\s*([^\n\r]+)/, 1)
    this.timeStamp = parseRegex(tsText, /Time stamp:\s*([^\n\r]+)/, 1)
    this.timeStampDate = new Date(this.timeStamp)
    this.accuracy = parseRegex(tsText, /Accuracy:\s*(.+) seconds, (.+) millis, (.+) micros/, ['s', 'm', 'u'], ({ s, m, u }) => {
      s = Number(s === 'unspecified' ? 0 : s)
      m = Number(m === 'unspecified' ? 0 : m)
      u = Number(u === 'unspecified' ? 0 : u)
      return s * 1000 + m + u / 1000
    })
    this.ordering = parseRegex(tsText, /Ordering:\s*([^\n\r]+)/, 1, ordering => ordering !== 'no')
    this.nonce = parseRegex(tsText, /Nonce:\s*([^\n\r]+)/, 1, nonce => nonce === 'unspecified' ? null : nonce)
    this.issuer = parseRegex(tsText, /TSA:\s*DirName:\s*([^\n\r]+)/, 1)
    this.tsa = parseRegex(tsText, /TSA:\s*DirName:\s*([^\n\r]+)/, 1, (result) => {
      const m = result.match(/\/\w{1,2}=[^/]+/g) || []

      return m.reduce((obj, part) => {
        const [, label, value] = part.match(/\/(\w{1,2})=([^/]+)/) || []
        if (!label || !value) {
          return obj
        }
        obj[label] = value
        return obj
      }, { C: null, L: null, O: null, OU: null, CN: null })
    })
  }

  /**
   * @param {string} tsText
   */
  parseOpensslOutputShort (tsText) {
    this.version = parseRegex(tsText, /Version:\s*([^\n\r]+)/, 1, parseInt)
    this.policyOID = parseRegex(tsText, /Policy OID:\s*([^\n\r]+)/, 1)
    this.hashAlgorithm = parseRegex(tsText, /Hash Algorithm:\s*([^\n\r]+)/, 1)
    this.serialNumber = parseRegex(tsText, /Serial number:\s*([^\n\r]+)/, 1)
    this.timeStamp = parseRegex(tsText, /Time stamp:\s*([^\n\r]+)/, 1, dateString => new Date(dateString))
    this.accuracy = parseRegex(tsText, /Accuracy:\s*(.+) seconds, (.+) millis, (.+) micros/, ['s', 'm', 'u'], ({ s, m, u }) => {
      s = Number(s === 'unspecified' ? 0 : s)
      m = Number(m === 'unspecified' ? 0 : m)
      u = Number(u === 'unspecified' ? 0 : u)
      return s * 1000 + m + u / 1000
    })
    this.ordering = parseRegex(tsText, /Ordering:\s*([^\n\r]+)/, 1, ordering => ordering !== 'no')
    this.nonce = parseRegex(tsText, /Nonce:\s*([^\n\r]+)/, 1, nonce => nonce === 'unspecified' ? null : nonce)
    this.tsa = parseRegex(tsText, /TSA:\s*([^\n\r]+)/, 1, (v) => {
      const m = v.match(/\/\w{1,2}=[^/]+/g) || []

      return m.reduce((obj, part) => {
        const [, label, value] = part.match(/\/(\w{1,2})=([^/]+)/) || []
        if (!label || !value) {
          return obj
        }
        obj[label] = value
        return obj
      }, { C: null, L: null, O: null, OU: null, CN: null })
    })
  }
}

export default TimestampInfo
