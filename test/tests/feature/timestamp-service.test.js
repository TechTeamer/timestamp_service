const nock = require('nock')

jest.mock('../../../src/trustedTimestamp/TrustedTimestampCommand.js', () => ({
  getTsQuery: jest.fn().mockResolvedValue('test' ),
  getTsVerify: jest.fn().mockResolvedValue('test' ),
  getTsReply: jest.fn().mockResolvedValue('test' ),
  generateTsReply: jest.fn().mockResolvedValue('test' ),
  extractCertFromToken: jest.fn().mockResolvedValue('test' ),
  checkSslPath: jest.fn().mockResolvedValue('test' ),
}));

describe('TrustedTimestampService.js (feature-test)', () => {
  // Mocks
  beforeEach(() => {
    jest.resetModules()
  })

  describe('TrustedTimestampService - config check', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - config ok', async () => {
      new TrustedTimestampService({
        "certsLocation": "/etc/ssl/certs/",
        "providers": [
          {
            "name": "bteszt",
            "url": "https://bteszt.e-szigno.hu/tsa",
            "auth": {
              "user": "username",
              "pass": "password"
            }
          },
          {
            "priority": 999,
            "name": "infocertB",
            "url": "http://localhost?token=xxxxx"
          },
          {
            "name": "microsecA",
            "url": "http//localhost?token=xxxx"
          },
          {
            "name": "microsecB",
            "url": "http//localhost?token=xxxx"
          }
        ]})

      await expect()
    })

    it('fail test - config missing providers', async () => {
      try {
        new TrustedTimestampService({
          "certsLocation": "/etc/ssl/certs/"
        })
      } catch (error) {
        expect(error).toHaveProperty('message', 'trustedTimestamp config "providers" missing or empty!');
      }
    })

    it('fail test - config missing certsLocation', async () => {
      try {
        new TrustedTimestampService({
          "providers": [
            {
              "name": "bteszt",
              "url": "https://bteszt.e-szigno.hu/tsa",
              "auth": {
                "user": "username",
                "pass": "password"
              }
            }
            ]
        })
      } catch (error) {
        expect(error).toHaveProperty('message', 'trustedTimestamp config "certsLocation" missing!');
      }
    })
  })

  describe('TrustedTimestampService - createTimestampToken()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - createTimestampToken - create ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService({
        "certsLocation": "/etc/ssl/certs/",
        "providers": [
          {
            "priority": 999,
            "name": "infocertB",
            "url": "http://127.0.0.1?token=xxxxx"
          }
        ]})

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
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response');
      }
    })
  })

  describe('TrustedTimestampService - getTimestampInfo()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - getTimestampInfo - create ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService({
        "certsLocation": "/etc/ssl/certs/",
        "providers": [
          {
            "priority": 999,
            "name": "infocertB",
            "url": "http://127.0.0.1?token=xxxxx"
          }
        ]})

      const tsr =     {
        digest: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0',
        hashAlgorithm: 'sha256',
        dataSize: 210893,
        tsr: {
          id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
        },
        isToken: false,
        certExpiry: null,
        verified: null
      }

      const token = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'

      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      try {
        const result = await trustedTimestampServiceInstance.getTimestampInfo(tsr, token)
        await expect(result).not.toBe(null)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response');
      }
    })
  })

  describe('TrustedTimestampService - verifyToken()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - verifyToken', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService({
        "certsLocation": "/etc/ssl/certs/",
        "providers": [
          {
            "priority": 999,
            "name": "infocertB",
            "url": "http://127.0.0.1?token=xxxxx"
          }
        ]})

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
        await expect(result).not.toBe(null)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response');
      }
    })
  })

  describe('TrustedTimestampService - verifyTsr()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - verifyTsr', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService({
        "certsLocation": "/etc/ssl/certs/",
        "providers": [
          {
            "priority": 999,
            "name": "infocertB",
            "url": "http://127.0.0.1?token=xxxxx"
          }
        ]})

      const tsr =     Buffer.from('test')
      const digest = 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0'
      const isToken = false
      const scope = nock('http://127.0.0.1')
        .post('/?token=xxxxx')
        .reply(200, { id: 'f1d44c9a9f3c6f12536f46e8f06cbe3001954e9e684ccabb99dd36ca296f7bd0' })
      scope.persist(false)

      try {
        const result = await trustedTimestampServiceInstance.verifyTsr(digest, tsr, isToken)
        await expect(result).not.toBe(null)
      } catch (error) {
        expect(error).toHaveProperty('message', 'test response');
      }
    })
  })

  describe('TrustedTimestampService - testService()', () => {
    jest.resetModules()
    const { TrustedTimestampService } = require('../../../index')

    it('success test - ssl config ok', async () => {
      const trustedTimestampServiceInstance = new TrustedTimestampService({
        "certsLocation": "/etc/ssl/certs/",
        "providers": [
          {
            "name": "bteszt",
            "url": "https://bteszt.e-szigno.hu/tsa",
            "auth": {
              "user": "username",
              "pass": "password"
            }
          },
          {
            "priority": 999,
            "name": "infocertB",
            "url": "http://localhost?token=xxxxx"
          },
          {
            "name": "microsecA",
            "url": "http//localhost?token=xxxx"
          },
          {
            "name": "microsecB",
            "url": "http//localhost?token=xxxx"
          }
        ]})

      trustedTimestampServiceInstance.testService()
      await expect()
    })
  })
})
