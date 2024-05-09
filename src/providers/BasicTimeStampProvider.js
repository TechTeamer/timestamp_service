const TimestampProvider = require('./TimestampProvider')

class BasicTimestampProvider extends TimestampProvider {
  constructor (options) {
    super(options)
    if (!options.basicAuth) {
      throw new Error(`Missing basicAuth in ${this.name}`)
    }
    this.basicAuth = options.basicAuth
  }

  /**
   * @inheritDoc
   */
  async getAuthorizationHeader () {
    return `Basic ${Buffer.from(this.basicAuth).toString('base64')}`
  }
}

module.exports = BasicTimestampProvider
