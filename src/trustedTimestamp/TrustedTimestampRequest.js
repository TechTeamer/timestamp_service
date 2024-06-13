const fetch = require('node-fetch')
const fs = require('fs')

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
  constructor(providers, tempFileService, tmpOptions) {
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
   * getOauth method that get oauth access_token
   *
   * @param {string} url
   * @param {object} auth
   * @param {object} body
   * @param {string} [proxy]
   * @return {object}
   * @Private
   **/
  async _getOauth (url, auth, body, proxy) {
    const tsRequest = await this._getOauthRequestSettings(auth, body, proxy)
    return await fetch(url, tsRequest).then((response) => {
      return response.json()
    }).catch((err) => {
      return {
        error: {
          message: err.message
        }
      }
    })
  }

  /**
   * getTimestampRequestSettings method that set the request settings
   *
   * @param {string} [url]
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
    const tsRequest = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query'
      }
    }

    // create: tsRequst
    // strategy: oauth, basic, noAuth
    // set tsRequest url, header, body
    // return

    let accessToken
    let requestUrl

    if (url?.getTokenUrl && url?.getTimestampUrl) {
      const oauth = await this._getOauth(url.getTokenUrl, auth, body, proxy)
      if (!oauth?.access_token) {
        // skip
      }
      accessToken = oauth?.access_token
      requestUrl = url.getTimestampUrl
    } else {
      requestUrl = url
    }

    if (proxy && proxy?.url) {
      tsRequest.proxy = proxy.url
    }

    if (!accessToken) {
      tsRequest.encoding = null // we expect binary data in a buffer: ensure that the response is not decoded unnecessarily
      tsRequest.resolveWithFullResponse = true

      if (tsQuery) {
        tsRequest.body = tsQuery
      }
    }

    if (auth && !accessToken) {
      tsRequest.headers = {
        ...tsRequest.headers,
        Authorization: `Basic ${Buffer.from(auth.user + ':' + auth.pass).toString('base64')}`
      }
    }

    if (accessToken) {
      tsRequest.headers = {
        ...tsRequest.headers,
        Authorization: `Bearer ${accessToken}`
      }

      const { tempPath, cleanupCallback } = await this.tempFileService.createTempFile(this.tmpOptions, Buffer.from(tsQuery))
      this.cleanupTempFns.push(cleanupCallback)

      const stats = fs.statSync(tempPath)
      const fileSizeInBytes = stats.size
      tsRequest.body = fs.createReadStream(tempPath)
      tsRequest.headers = {
        ...tsRequest.headers,
        'Content-length': fileSizeInBytes
      }
    }

    return { requestUrl, tsRequest }
  }

  /**
   * getOauthRequestSettings method that set the request oath settings
   *
   * @param {object} auth
   * @param {object} body
   * @param {string} [proxy]
   * @return {object}
   * @Private
   **/
  async _getOauthRequestSettings (auth, body, proxy) {
    const tsRequest = {
      method: 'POST'
    }

    tsRequest.headers = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${Buffer.from(auth.user + ':' + auth.pass).toString('base64')}`
    }

    tsRequest.body = new URLSearchParams(body)

    if (proxy && proxy?.url) {
      tsRequest.proxy = proxy.url
    }

    return tsRequest
  }
}

module.exports = TrustedTimestampRequest
