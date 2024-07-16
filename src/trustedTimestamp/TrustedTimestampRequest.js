import fetch from 'node-fetch'
import TimestampRequest from './TimestampRequest.js'

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
   * @typedef {returnObject}  result
   * @property {Buffer} tsr
   * @property {string} providerName
   * @property {array} logHistory
   *
   * @param {string} tsQuery
   * @return {returnObject}
   **/
  async getTimestamp (tsQuery) {
    let tsr = null
    let providerName = ''
    const logHistory = []

    for (const provider of this.providers) {
      if (!tsr) {
        const { name, url, auth, body, proxy } = provider

        if (!name) {
          throw new Error('Provider name is missing')
        }
        if (!url) {
          throw new Error('Provider url is missing')
        }

        const { timestampToken, log } = await this._getTimeStampToken(name, url, auth, body, proxy, tsQuery)
        logHistory.push(log)
        tsr = timestampToken
        providerName = name
      }
    }

    return { tsr, providerName, logHistory }
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
   * @typedef {object}  returnObject
   * @property {Promise<Buffer>} timestampToken
   * @property {logObject} log
   *
   * @typedef {object}  logObject
   * @property {infoObject} info
   * @property {object} errorTrace
   *
   * @typedef {object}  infoObject
   * @property {string} name
   * @property {string} info
   * @property {string} date
   * @property {urlObject} url
   * @property {string} response
   * @property {string} error
   **/

  /**
   * sendTimestampRequest method that calls the provider
   *
   * @param {string} name - provider name
   * @param {string| urlObject} url
   * @param {string} [auth]
   * @param {string} [proxy]
   * @param {string} [body]
   * @param {string} tsQuery
   * @return {returnObject}
   * @Private
   **/
  async _getTimeStampToken (name, url, auth, body, proxy, tsQuery) {
    const { requestUrl, tsRequest, error } = await this._getTimestampRequest(url, body, auth, proxy, tsQuery)
    if (error) {
      return { timestampToken: null, log: { info: { name, info: null, date: new Date(), url, response: null, error: error?.message }, errorTrace: error?.trace } }
    }
    return await fetch(requestUrl, tsRequest).then(async (response) => {
      if (response.status !== 200) {
        throw new Error(`TSA response unsatisfactory: ${response.status} ${response.statusText}`)
      }

      return { timestampToken: Buffer.from(await response.arrayBuffer(), 'utf8'), log: { info: { name, date: new Date(), url, response: `${response.status}, ${response.statusText}`, error: null }, errorTrace: null } }
    }).catch((err) => {
      return { timestampToken: null, log: { info: { name, date: new Date(), url, reponse: null, error: err.message }, errorTrace: err } }
    }).finally(() => {
      for (const cleanUpFn of this.cleanupTempFns) {
        if (typeof cleanUpFn === 'function') {
          cleanUpFn()
        }
      }
    })
  }

  /**
   * @typedef {object}  resultObject
   * @property {string} requestUrl
   * @property {string} tsRequest
   * @property {string} error
   *
   **/

  /**
   * getTimestampRequestSettings method that set the request settings
   *
   * @param {object | string} url
   * @param {string} [body]
   * @param {string} [auth]
   * @param {string} [proxy]
   * @param {string} [body]
   * @param {string} tsQuery
   * @return {resultObject}
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

export default TrustedTimestampRequest
