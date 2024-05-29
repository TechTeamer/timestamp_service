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
  constructor (providers, tempFileService, tmpOptions) {
    this.providers = providers
    this.tempFileService = tempFileService
    this.tmpOptions = tmpOptions
    this.cleanupTempFns = []
  }

  /**
   * getTimestamp method that calls the service providers in sequence, requesting a timestamp
   *
   * @param {string} tsQuery
   * @return {Promise<response.body>}
   **/
  async getTimestamp (tsQuery) {
    let timestampExists = null

    for (const provider of this.sortedProviders()) {
      if (!timestampExists) {
        const { name, url, auth, body, proxy } = provider
        if (name && url) {
          timestampExists = await this.sendTimestampRequest(name, url, auth, body, proxy, tsQuery)
        } else {
          if (!name) {
            throw new Error('Provider name is missing')
          }
          if (!url) {
            throw new Error('Provider url is missing')
          }
        }
      }
    }

    return timestampExists
  }

  /**
   * sortedProviders method that sorting the providers according to priority
   *
   * @return array
   **/
  sortedProviders () {
    const priorityProviders = []
    const nonPriorityProviders = []

    this.providers.forEach((provider) => {
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
   * sendTimestampRequest method that calls the provider
   *
   * @typedef {object}  urlObject
   * @property {string} getTokenUrl
   * @property {string} getTimestampUrl
   *
   * @param {string} name
   * @param {string| urlObject} url
   * @param {string} [auth]
   * @param {string} [proxy]
   * @param {string} [body]
   * @param {string} tsQuery
   * @return {Promise<Buffer>}
   **/
  async sendTimestampRequest (name, url, auth, body, proxy, tsQuery) {
    let accessToken
    let requestUrl
    if (url?.getTokenUrl && url?.getTimestampUrl) {
      const oauth = await this.getOauth(name, url.getTokenUrl, auth, body, proxy)
      accessToken = oauth?.access_token
      requestUrl = url.getTimestampUrl
    } else {
      requestUrl = url
    }

    const tsRequest = await this.getTimestampRequestSettings(name, url, auth, body, proxy, tsQuery, accessToken)
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
   * @param {string} name
   * @param {string} url
   * @param {object} auth
   * @param {object} body
   * @param {string} [proxy]
   * @return {object}
   **/
  async getOauth (name, url, auth, body, proxy) {
    const tsRequest = await this.getOauthRequestSettings(auth, body, proxy)
    return await fetch(url, tsRequest).then(async (response) => {
      return await response.json()
    })
  }

  /**
   * getTimestampRequestSettings method that set the request settings
   *
   * @param {string} name
   * @param {object | string} url
   * @param {string} [auth]
   * @param {string} [proxy]
   * @param {string} [body]
   * @param {string} tsQuery
   * @param {string} accessToken
   * @return {object}
   **/
  async getTimestampRequestSettings (name, url, auth, body, proxy, tsQuery, accessToken) {
    // send the request to the TSA
    const tsRequest = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query'
      }
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

    return tsRequest
  }

  /**
   * getOauthRequestSettings method that set the request oath settings
   *
   * @param {object} auth
   * @param {object} body
   * @param {string} [proxy]
   * @return {object}
   **/
  async getOauthRequestSettings (auth, body, proxy) {
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
