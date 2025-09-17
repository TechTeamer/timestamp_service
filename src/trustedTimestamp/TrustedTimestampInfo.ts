import { CertService } from '@techteamer/cert-utils'
import { parseRegex } from '../util/regexParser'

interface TSA {
  C: string | null
  L: string | null
  O: string | null
  OU: string | null
  CN: string | null
}

/**
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
export class TimestampInfo {
  error: string | null = null
  version: number | null = null
  policyOID: string | null = null
  hashAlgorithm: string | null = null
  hash: string | null = null
  serialNumber: string | null = null
  timeStamp: Date | null = null
  timeStampDate: Date | null = null
  accuracy: number | null = null
  ordering: boolean | null = null
  nonce: string | null = null
  issuer: string | null = null
  tsa: TSA | null = null
  certInfo: CertService['CertInfo'] | null = null

  constructor(timestampInfoType: 'normal' | 'short' = 'normal', tsText: string, error: string | null = null) {
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

  setCertInfo(certInfo: CertService['CertInfo'] | null): void {
    this.certInfo = certInfo
  }

  parseOpensslOutput(tsText: string): void {
    this.version = parseRegex(tsText, /Version:\s*([^\n\r]+)/, 1, parseInt)!
    this.policyOID = parseRegex(tsText, /Policy OID:\s*([^\n\r]+)/, 1)!
    this.hashAlgorithm = parseRegex(tsText, /Hash Algorithm:\s*([^\n\r]+)/, 1)!
    this.hash = tsText
      .match(/\d{4} - .*?\s{2}/g)!
      .map(line => {
        return line.replace(/\d{4} - /g, '').replace(/[\s*-]/g, '')
      })
      .join('')
    this.serialNumber = parseRegex(tsText, /Serial number:\s*([^\n\r]+)/, 1)!
    this.timeStamp = parseRegex(tsText, /Time stamp:\s*([^\n\r]+)/, 1)!
    this.timeStampDate = new Date(this.timeStamp)
    this.accuracy = parseRegex(
      tsText,
      /Accuracy:\s*(.+) seconds, (.+) millis, (.+) micros/,
      ['s', 'm', 'u'],
      ({ s, m, u }) => {
        const _s = Number(s === 'unspecified' ? 0 : s)
        const _m = Number(m === 'unspecified' ? 0 : m)
        const _u = Number(u === 'unspecified' ? 0 : u)
        return _s * 1000 + _m + _u / 1000
      }
    )!
    this.ordering = parseRegex(tsText, /Ordering:\s*([^\n\r]+)/, 1, ordering => ordering !== 'no')!
    this.nonce = parseRegex(tsText, /Nonce:\s*([^\n\r]+)/, 1, nonce => (nonce === 'unspecified' ? null : nonce))!
    this.issuer = parseRegex(tsText, /TSA:\s*DirName:\s*([^\n\r]+)/, 1)!
    this.tsa = parseRegex(tsText, /TSA:\s*DirName:\s*([^\n\r]+)/, 1, (result): TSA => {
      const m = result.match(/\/\w{1,2}=[^/]+/g) || []

      return m.reduce(
        (obj, part) => {
          const [, label, value] = part.match(/\/(\w{1,2})=([^/]+)/) || []
          if (!label || !value) {
            return obj
          }
          obj[label as keyof TSA] = value
          return obj
        },
        { C: null, L: null, O: null, OU: null, CN: null } as TSA
      )
    })!
  }

  parseOpensslOutputShort(tsText: string): void {
    this.version = parseRegex(tsText, /Version:\s*([^\n\r]+)/, 1, parseInt)!
    this.policyOID = parseRegex(tsText, /Policy OID:\s*([^\n\r]+)/, 1)!
    this.hashAlgorithm = parseRegex(tsText, /Hash Algorithm:\s*([^\n\r]+)/, 1)!
    this.serialNumber = parseRegex(tsText, /Serial number:\s*([^\n\r]+)/, 1)!
    this.timeStamp = parseRegex(tsText, /Time stamp:\s*([^\n\r]+)/, 1, dateString => new Date(dateString))!
    this.accuracy = parseRegex(
      tsText,
      /Accuracy:\s*(.+) seconds, (.+) millis, (.+) micros/,
      ['s', 'm', 'u'],
      ({ s, m, u }) => {
        const _s = Number(s === 'unspecified' ? 0 : s)
        const _m = Number(m === 'unspecified' ? 0 : m)
        const _u = Number(u === 'unspecified' ? 0 : u)
        return _s * 1000 + _m + _u / 1000
      }
    )!
    this.ordering = parseRegex(tsText, /Ordering:\s*([^\n\r]+)/, 1, ordering => ordering !== 'no')!
    this.nonce = parseRegex(tsText, /Nonce:\s*([^\n\r]+)/, 1, nonce => (nonce === 'unspecified' ? null : nonce))!
    this.tsa = parseRegex(tsText, /TSA:\s*([^\n\r]+)/, 1, v => {
      const m = v.match(/\/\w{1,2}=[^/]+/g) || []

      return m.reduce(
        (obj, part) => {
          const [, label, value] = part.match(/\/(\w{1,2})=([^/]+)/) || []
          if (!label || !value) {
            return obj
          }
          obj[label as keyof TSA] = value
          return obj
        },
        { C: null, L: null, O: null, OU: null, CN: null } as TSA
      )
    })!
  }
}
