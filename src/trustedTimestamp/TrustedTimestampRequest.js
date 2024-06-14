const fetch = require('node-fetch')
const TimestampRequest = require('./TimestampRequest')

/**
* TrustedTimestampRequest service implements timestamp request and sorted providers
*
* @class TrustedTimestampRequest
* */
class TrustedTimestampRequest {
  /**
   * @typedef {object}  provider
   * @property {string} name provider name
   * @property {string | urlObject} url provider url
   * @property {object} [auth] optional auth setting
   * @property {number} [priority] optional provider priority
   *
   * @typedef {object}  urlObject
   * @property {string} getTokenUrl
   * @property {string} getTimestampUrl
   *
   * @typedef {object}  auth
   * @property {string} user username
   * @property {string} pass password
   *
   * @constructor
   * @param {provider[]} providers
   * @param tempFileService
   * @param {object} tmpOptions
   */
  constructor (providers, tempFileService, tmpOptions) {
    this.tempFileService = tempFileService
    this.tmpOptions = tmpOptions
    this.cleanupTempFns = []
    this.providers = this._sortedProviders(providers)
  }

  /**
   * getTimestamp method that calls the service providers in sequence, requesting a timestamp
   *
   * @typedef {object}  result
   * @property {Buffer} tsr
   * @property {string} providerName
   *
   * @param {string} tsQuery
   * @return {Promise<result>}
   **/
  async getTimestamp (tsQuery) {
    let timestampToken = null
    let providerName = ''

    for (const provider of this.providers) {
      if (!timestampToken) {
        const { name, url, auth, body, proxy } = provider

        if (!name) {
          throw new Error('Provider name is missing')
        }
        if (!url) {
          throw new Error('Provider url is missing')
        }

        timestampToken = await this._getTimeStampToken(url, auth, body, proxy, tsQuery)
        providerName = name
      }
    }

    return { tsr: timestampToken, providerName }
  }

  /**
   * sortedProviders method that sorting the providers according to priority
   *
   * @return array
   * @Private
   **/
  _sortedProviders (providers) {
    const priorityProviders = []
    const nonPriorityProviders = []

    providers.forEach((provider) => {
      if (provider?.priority) {
        priorityProviders.push(provider)
      } else {
        nonPriorityProviders.push(provider)
      }
    })

    const sortedProviders = priorityProviders.sort((a, b) => a.priority - b.priority)

    return sortedProviders.concat(nonPriorityProviders)
  }

  /**
   * @typedef {object}  urlObject
   * @property {string} getTokenUrl
   * @property {string} getTimestampUrl
   *
   **/

  /**
   * sendTimestampRequest method that calls the provider
   *
   * @param {string| urlObject} url
   * @param {string} [auth]
   * @param {string} [proxy]
   * @param {string} [body]
   * @param {string} tsQuery
   * @return {Promise<Buffer>}
   * @Private
   **/
  async _getTimeStampToken (url, auth, body, proxy, tsQuery) {
    const { requestUrl, tsRequest } = await this._getTimestampRequest(url, body, auth, proxy, tsQuery)
    return await fetch(requestUrl, tsRequest).then(async (response) => {
      if (response.status !== 200) {
        throw new Error(`TSA response unsatisfactory: ${response.status} ${response.statusText}`)
      }

      return Buffer.from(await response.arrayBuffer(), 'utf8')
    }).catch(() => {
      // nothing to do
    }).finally(() => {
      for (const cleanUpFn of this.cleanupTempFns) {
        if (typeof cleanUpFn === 'function') {
          cleanUpFn()
        }
      }
    })
  }

  /**
   * getTimestampRequestSettings method that set the request settings
   *
   * @param {object | string} url
   * @param {string} [body]
   * @param {string} [auth]
   * @param {string} [proxy]
   * @param {string} [body]
   * @param {string} tsQuery
   * @return {object}
   * @Private
   **/
  async _getTimestampRequest (url, body, auth, proxy, tsQuery) {
    // send the request to the TSA
    const tsRequest = new TimestampRequest(this.tempFileService, this.tmpOptions, this.cleanupTempFns)

    if (proxy && proxy?.url) {
      tsRequest.setProxy(proxy.url)
    }

    let requestType
    if (url?.getTokenUrl && tsQuery) {
      requestType = 'oauth'
    }
    if (!url?.getTokenUrl && auth?.user && auth?.pass && tsQuery) {
      requestType = 'basic'
    }
    if (!url?.getTokenUrl && !auth?.user) {
      requestType = 'noAuth'
    }

    return await tsRequest.authStrategy(requestType, url, auth, body, proxy, tsQuery)
  }
}

module.exports = TrustedTimestampRequest
