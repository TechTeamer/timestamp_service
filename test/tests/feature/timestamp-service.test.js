import { vi, expect, it, beforeEach, describe } from 'vitest'
import nock from 'nock'
import '../mocks/TrustedTimestampCommand.mock.js'
import { TrustedTimestampService } from '../../../src/trustedTimestamp/TrustedTimestampService.js'

vi.mock('@techteamer/cert-utils', () => ({
  CertService: vi.fn().mockImplementation(() => ({
    get CertType () {
      return {
        P12: 'P12',
        PEM: 'PEM'
      }
    },
    parseCert: () => { /**/ }
  }))
}))

describe('TrustedTimestampService.js (feature-test)', () => {
  // Mocks
  beforeEach(() => {
    vi.resetModules()
  })

  describe('TrustedTimestampService - config check', () => {
    vi.resetModules()
    it('success test - config ok', async () => {
      const result = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            name: 'bteszt',
            url: 'https://bteszt.e-szigno.hu/tsa',
            auth: {
              user: 'username',
              pass: 'password'
            }
          },
          {
            priority: 999,
            name: 'infocertB',
            url: 'http://localhost?token=xxxxx'
          },
          {
            name: 'microsecA',
            url: 'http//localhost?token=xxxx'
          },
          {
            name: 'microsecB',
            url: 'http//localhost?token=xxxx'
          }
        ]
      })

      await expect(result)
    })

    it('success test - config ouath ok', async () => {
      const result = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            name: 'infocert 1 test',
            url: {
              getTokenUrl: 'http://localhost/token',
              getTimestampUrl: 'http://localhost/timestamp'
            },
            auth: {
              user: '<username>',
              pass: '<password>'
            },
            body: {
              grant_type: 'client_credentials',
              scope: 'timestamp'
            }
          }
        ]
      })

      await expect(result)
    })

    it('fail test - config missing providers', async () => {
      expect(() => new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/'
      })).toThrow('trustedTimestamp config "providers" missing or empty!')
    })

    it('fail test - config missing certsLocation', async () => {
      expect(() => new TrustedTimestampService('normal', {
        providers: [
          {
            name: 'bteszt',
            url: 'https://bteszt.e-szigno.hu/tsa',
            auth: {
              user: 'username',
              pass: 'password'
            }
          }
        ]
      })).toThrow('trustedTimestamp config "certsLocation" missing!')
    })
  })

  describe('TrustedTimestampService - createTimestampToken()', () => {
    vi.resetModules()
    it('success test - createTimestampToken - create ok basic auth', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            name: 'bteszt',
            url: 'https://bteszt.e-szigno.hu/tsa',
            auth: {
              user: 'username',
              pass: 'password'
            }
          }
        ]
      })

      const digest = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
      const hashAlgorithm = 'sha256'
      const dataSize = 210893

      const scope = nock('https://bteszt.e-szigno.hu')
        .post('/tsa')
        .reply(200, { })
      scope.persist(false)

      const { timestamp, providerName } = await trustedTimestampServiceInstance.createTimestampToken(digest, hashAlgorithm, dataSize)
      await expect(providerName).not.toBe(null)
      await expect(timestamp).not.toBe(null)
      await expect(timestamp.verified).toBe(true)
    })

    it('success test - createTimestampToken - create ok oauth', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            name: 'infocert 1 test',
            url: {
              getTokenUrl: 'http://localhost/token',
              getTimestampUrl: 'http://localhost/timestamp'
            },
            auth: {
              user: '<username>',
              pass: '<password>'
            },
            body: {
              grant_type: 'client_credentials',
              scope: 'timestamp'
            }
          }
        ]
      })

      const digest = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
      const hashAlgorithm = 'sha256'
      const dataSize = 210893

      const scope = nock('http://localhost')
        .post('/token')
        .reply(200, { access_token: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      const scope2 = nock('http://localhost')
        .post('/timestamp')
        .reply(200, { access_token: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope2.persist(false)

      const { timestamp, providerName } = await trustedTimestampServiceInstance.createTimestampToken(digest, hashAlgorithm, dataSize)
      await expect(providerName).not.toBe(null)
      await expect(timestamp).not.toBe(null)
      await expect(timestamp.verified).toBe(true)
    })

    it('success test - createTimestampToken - create ok wrong provider use next provider', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            name: 'wrong provider',
            url: 'https://localhost/wrong',
            auth: {
              user: 'username',
              pass: 'password'
            }
          },
          {
            name: 'infocert 1 test',
            url: {
              getTokenUrl: 'http://localhost/token',
              getTimestampUrl: 'http://localhost/timestamp'
            },
            auth: {
              user: '<username>',
              pass: '<password>'
            },
            body: {
              grant_type: 'client_credentials',
              scope: 'timestamp'
            }
          }
        ]
      })

      const digest = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
      const hashAlgorithm = 'sha256'
      const dataSize = 210893

      const scope = nock('http://localhost')
        .post('/token')
        .reply(200, { access_token: 'f1d44c9a9f3c6d12536f46e8f06bbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      const scope2 = nock('http://localhost')
        .post('/timestamp')
        .reply(200, { })
      scope2.persist(false)

      const { timestamp, providerName } = await trustedTimestampServiceInstance.createTimestampToken(digest, hashAlgorithm, dataSize)
      await expect(providerName).not.toBe(null)
      await expect(timestamp).not.toBe(null)
      await expect(timestamp.verified).toBe(true)
    })
  })

  describe('TrustedTimestampService - getTimestampInfo()', () => {
    vi.resetModules()

    it('success test - getTimestampInfo - create ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            priority: 999,
            name: 'infocertB',
            url: 'http://127.0.0.1?token=xxxxx'
          }
        ]
      })

      const tsr = Buffer.from(JSON.stringify({
        digest: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0',
        hashAlgorithm: 'sha256',
        dataSize: 210893,
        tsr: {},
        isToken: false,
        certExpiry: null,
        verified: null
      }))

      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { })
      scope.persist(false)

      const result = await trustedTimestampServiceInstance.getTimestampInfo(tsr, false)
      await expect(result?.error).toBe(null)
    })
  })

  describe('TrustedTimestampService - verifyToken()', () => {
    vi.resetModules()

    it('success test - verifyToken', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            priority: 999,
            name: 'infocertB',
            url: 'http://127.0.0.1?token=xxxxx'
          }
        ]
      })

      const timestampToken = {
        digest: '7c86796d0bba6cda5805fe327200528f65fbab8847d7c847f2fc29dfede24343',
        hashAlgorithm: 'sha256',
        dataSize: 458,
        tsr: '',
        isToken: false,
        certExpiry: null,
        verified: null
      }
      const digest = '7c86796d0bba6cda5805fe327200528f65fbab8847d7c847f2fc29dfede24343'
      const dataSize = 458

      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { })
      scope.persist(false)

      const result = await trustedTimestampServiceInstance.verifyToken(timestampToken, digest, dataSize)
      await expect(result).toBe(true)
    })
  })

  describe('TrustedTimestampService - verifyTsr()', () => {
    vi.resetModules()

    it('success test - verifyTsr', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            priority: 999,
            name: 'infocertB',
            url: 'http://127.0.0.1?token=xxxxx'
          }
        ]
      })

      const tsr = Buffer.from('test')
      const digest = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
      const isToken = false
      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { })
      scope.persist(false)

      const result = await trustedTimestampServiceInstance.verifyTsr(digest, tsr, isToken)
      await expect(result).toBe(true)
    })
  })

  describe('TrustedTimestampService - testService()', () => {
    vi.resetModules()

    it('success test - ssl config ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('normal', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            name: 'bteszt',
            url: 'https://bteszt.e-szigno.hu/tsa',
            auth: {
              user: 'username',
              pass: 'password'
            }
          },
          {
            priority: 999,
            name: 'infocertB',
            url: 'http://localhost?token=xxxxx'
          },
          {
            name: 'microsecA',
            url: 'http//localhost?token=xxxx'
          },
          {
            name: 'microsecB',
            url: 'http//localhost?token=xxxx'
          }
        ]
      })

      const result = await trustedTimestampServiceInstance.testService()
      await expect(result).not.toBe(null)
    })
  })
})
