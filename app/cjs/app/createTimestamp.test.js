const path = require('path')
const { TrustedTimestampService: TrustedTimestampServiceLib, CreateTimestampTokenError } = require('@techteamer/timestamp')

const certPath = path.join(__dirname, '..', '..', 'cert');

const config = {
  certsLocation: certPath,
  providers: [
    {
      name: 'bteszt',
      url: 'http://wiremock:8080/tsa',
      auth: {
        user: 'username',
        pass: 'password'
      },
      proxy: {
        url: 'http://localhost:8080'
      }
    }
  ]
}

async function createTimestampToken () {
  const trustedTimestampServiceInstance = new TrustedTimestampServiceLib('normal', config)
  const digest = 'ca447095370ccb6f66157119a7dd100ee889a7c6baf69a52b37d0c4040c19e68'
  const hashAlgorithm = 'sha256'
  const dataSize = 20

  try {
    const { timestamp, providerName } = await trustedTimestampServiceInstance.createTimestampToken(
      digest,
      hashAlgorithm,
      dataSize
    )
    console.info({ timestamp, providerName })
  } catch (err) {
    if (err instanceof CreateTimestampTokenError) {
      const { providerName, logHistory } = err.context

      console.error(
        'Failed to create trusted timestamp.',
        `Provider: ${providerName},`,
        `history: ${JSON.stringify(logHistory, null, 2)}`
      )
    }

    console.error('Failed to create trusted timestamp', err)
    throw new Error('Failed to create trusted timestamp')
  }


}

createTimestampToken()
