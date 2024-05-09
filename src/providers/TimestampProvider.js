const promiseRetry = require('promise-retry')
const fetch = require('node-fetch')
const https = require('https')

/**
 * @class TimestampProvider
 * This is an interface That has to be extended by every timestamp provider
 */
class TimestampProvider {
  /**
   * You can set up a proxy through the agent param if you need.
   * @see https://www.npmjs.com/package/https-proxy-agent
   *
   * @param {string} url
   * @param {https.Agent|http.Agent} agent
   * @param {Object} retryOptions
   */
  constructor ({
    url,
    agent = new https.Agent(),
    retryOptions = null
  }) {
    if (!url) {
      throw new Error(`Missing URL in constructor of ${this.name}`)
    }

    this.url = url
    this.agent = agent
    this.retryOptions = retryOptions || {
      retries: 3, // max 3 tries
      factor: 1, // no exponential wait between tries
      minTimeout: 1000 // 1000ms timeout before retrying
    }
  }

  get name () {
    return this.constructor.name
  }

  /**
   * This function gets a timestamp query as a Buffer and tries to create a timestamp for it.
   * If the creation is successful, it returns the timestamp.
   *
   * @param {Buffer} query
   * @return {Promise<Buffer>}
   * @throws
   */
  async create (query) {
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query',
        Authorization: await this.getAuthorizationHeader()
      },
      body: query,
      agent: this.agent
    }
    const response = await this.fetchWithRetry(this.url, options)
    return await response.buffer()
  }

  /**
   * Get authorization header for timestamp creation
   *
   * @abstract
   * @return {Promise<String>}
   */
  async getAuthorizationHeader () {
    throw new Error(`Implement TimestampProvider.getAuthorizationHeader on your TimestampProvider ${this.name}`)
  }

  /**
   * Helper for calling timestamp services with built-in retry logic.
   *
   * @param url
   * @param options
   * @return {Promise}
   */
  async fetchWithRetry (url, options) {
    // Add default agent to options
    options = { agent: this.agent, ...options }

    return promiseRetry(async retry => {
      try {
        const timestampResponse = await fetch(url, options)
        if (!timestampResponse.ok) {
          retry(new Error('Time stamp response was not ok. Status code: ' + timestampResponse.status))
        }
        return timestampResponse
      } catch (error) {
        retry(error)
      }
    }, this.retryOptions)
  }
}

module.exports = TimestampProvider
