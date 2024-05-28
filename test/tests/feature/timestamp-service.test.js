const nock = require('nock')

jest.mock('../../../src/trustedTimestamp/TrustedTimestampCommand.js', () => ({
  getTsQuery: jest.fn().mockResolvedValue(Buffer.from([{test:'test'}])),
  getTsVerify: jest.fn().mockResolvedValue('Verification: ok'),
  getTsReply: jest.fn().mockResolvedValue('Message data:\n' +
    '        0000 - eb 0c 81 b5 01 05 7f 2a-23 1d 2e af e0 a2 c3 60   .......*#......`\n' +
    '        0010 - 12 08 67 f6 fd e6 ab 0f-50 cb 8b 90 84 0f f7 c4   ..g.....P.......\n'),
  generateTsReply: jest.fn().mockResolvedValue(Buffer.from([{test:'test'}])),
  extractCertFromToken: jest.fn().mockResolvedValue(Buffer.from([{test:'test'}])),
  checkSslPath: jest.fn().mockResolvedValue(Buffer.from([{test:'test'}])),
}))

describe('TrustedTimestampService.js (feature-test)', () => {
  // Mocks
  beforeEach(() => {
    jest.resetModules()
  })

  describe('TrustedTimestampService - config check', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - config ok', async () => {
      const result = new TrustedTimestampService('vuer', {
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

    it('fail test - config missing providers', async () => {
      try {
        const result = new TrustedTimestampService('vuer', {
          certsLocation: '/etc/ssl/certs/'
        })
      } catch (error) {
        expect(error).toHaveProperty('message', 'trustedTimestamp config "providers" missing or empty!')
      }
    })

    it('fail test - config missing certsLocation', async () => {
      try {
        const result = new TrustedTimestampService('vuer', {
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
      } catch (error) {
        expect(error).toHaveProperty('message', 'trustedTimestamp config "certsLocation" missing!')
      }
    })
  })

  describe('TrustedTimestampService - createTimestampToken()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - createTimestampToken - create ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('vuer', {
        certsLocation: '/etc/ssl/certs/',
        providers: [
          {
            priority: 999,
            name: 'infocertB',
            url: 'http://127.0.0.1?token=xxxxx'
          }
        ]
      })

      const digest = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
      const hashAlgorithm = 'sha256'
      const dataSize = 210893

      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      try {
        const result = await trustedTimestampServiceInstance.createTimestampToken(digest, hashAlgorithm, dataSize)
        await expect(result).not.toBe(null)
        await expect(result.verified).toBe(true)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response')
      }
    })
  })

  describe('TrustedTimestampService - getTimestampInfo()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - getTimestampInfo - create ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('vuer', {
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
        tsr: {
          id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
        },
        isToken: false,
        certExpiry: null,
        verified: null
      }))

      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      try {
        const result = await trustedTimestampServiceInstance.getTimestampInfo(tsr, true)
        await expect(result).not.toBe(null)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response')
      }
    })
  })

  describe('TrustedTimestampService - verifyToken()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - verifyToken', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('vuer', {
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
        .reply(200, { id: '7c86796d0bba6cda5805fe327200528f65fbab8847d7c847f2fc29dfede24343' })
      scope.persist(false)

      try {
        const result = await trustedTimestampServiceInstance.verifyToken(timestampToken, digest, dataSize)
        await expect(result).toBe(true)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response')
      }
    })
  })

  describe('TrustedTimestampService - verifyTsr()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - verifyTsr', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('vuer', {
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
        .reply(200, { id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      try {
        const result = await trustedTimestampServiceInstance.verifyTsr(digest, tsr, isToken)
        await expect(result).toBe(true)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response')
      }
    })
  })

  describe('TrustedTimestampService - testService()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - ssl config ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService('vuer', {
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

      trustedTimestampServiceInstance.testService()
      await expect()
    })
  })
})
