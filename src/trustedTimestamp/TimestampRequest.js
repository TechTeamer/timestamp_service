import fetch from 'node-fetch'
import fs from 'fs'

/**
 * TimestampRequest class implements timestamp request
 *
 * @class TimestampRequest
 * */
class TimestampRequest {
  /**
   * @constructor
   * @param tempFileService
   * @param cleanupTempFns
   * @param {object} tmpOptions
   */
  constructor (tempFileService, tmpOptions, cleanupTempFns) {
    this.tempFileService = tempFileService
    this.tmpOptions = tmpOptions
    this.cleanupTempFns = cleanupTempFns
    this.tsRequest = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/timestamp-query'
      }
    }
  }

  /**
   * set request header
   * @param {object} headers
   * */
  setHeader (headers) {
    this.tsRequest = {
      ...this.tsRequest,
      headers
    }
  }

  /**
   * set request body
   * @param {object} body
   * */
  setBody (body) {
    this.tsRequest.body = body
  }

  /**
   * set request proxy
   * @param {string} proxyUrl
   * */
  setProxy (proxyUrl) {
    this.tsRequest.proxy = proxyUrl
  }

  /**
   * set request encoding
   * @param {string} encoding
   * */
  setEncoding (encoding) {
    this.tsRequest.encoding = encoding
  }

  /**
   * set request encoding
   * @param {boolean} resolveWithFullResponse
   * */
  setResolveWithFullResponse (resolveWithFullResponse) {
    this.tsRequest.resolveWithFullResponse = resolveWithFullResponse
  }

  /**
   * return tsRequest
   * @return {object}
   * */
  get () {
    return this.tsRequest
  }

  /**
   * authStrategy method that set no auth request
   * @param requestType
   * @param {object | string} url
   * @param {object} [auth]
   * @param {object} [body]
   * @param {string} [proxy]
   * @param {string} tsQuery
   * @return {object}
   * */
  async authStrategy (requestType, url, auth, body, proxy, tsQuery) {
    switch (requestType) {
      case 'basic':
        return this._getTimestampRequestBasic(url, auth, tsQuery)
      case 'oauth':
        return await this._getTimestampRequestOauth(url, auth, body, proxy, tsQuery)
      case 'noAuth':
        return this._getTimestampRequestNoAuth(url, tsQuery)
      default:
        return this._getTimestampRequestNoAuth(url, tsQuery)
    }
  }

  /**
   * _getTimestampRequestBasic method that set basic auth request
   * @param {object | string} url
   * @param {object} [auth]
   * @param {string} tsQuery
   * @return {object}
   * @Private
   * */
  _getTimestampRequestBasic (url, auth, tsQuery) {
    this.setHeader({
      ...this.tsRequest.headers,
      Authorization: `Basic ${Buffer.from(auth.user + ':' + auth.pass).toString('base64')}`
    })

    this.setEncoding(null) // we expect binary data in a buffer: ensure that the response is not decoded unnecessarily
    this.setResolveWithFullResponse(true)
    this.setBody(tsQuery)

    return { requestUrl: url, tsRequest: this.get() }
  }

  /**
   * _getTimestampRequestOauth method that set oauth request
   * @param {object | string} url
   * @param {object} [auth]
   * @param {object} [body]
   * @param {string} [proxy]
   * @param {string} tsQuery
   * @return {object}
   * @Private
   * */
  async _getTimestampRequestOauth (url, auth, body, proxy, tsQuery) {
    const oauthResult = await this._getOauth(url.getTokenUrl, auth, body, proxy)
    if (!oauthResult?.access_token) {
      return { requestUrl: null, tsRequest: null, error: null }
    }

    if (oauthResult?.error) {
      return { requestUrl: null, tsRequest: null, error: oauthResult?.error }
    }

    const accessToken = oauthResult?.access_token

    if (accessToken) {
      this.setHeader({
        ...this.tsRequest.headers,
        Authorization: `Bearer ${accessToken}`
      })

      const {
        tempPath,
        cleanupCallback
      } = await this.tempFileService.createTempFile(this.tmpOptions, Buffer.from(tsQuery))
      this.cleanupTempFns.push(cleanupCallback)

      const stats = fs.statSync(tempPath)
      const fileSizeInBytes = stats.size
      this.setBody(fs.createReadStream(tempPath))
      this.setHeader({
        ...this.tsRequest.headers,
        'Content-length': fileSizeInBytes
      })
    }

    return { requestUrl: url?.getTimestampUrl, tsRequest: this.get(), error: null }
  }

  /**
   * _getTimestampRequestNoAuth method that set no auth request
   * @param {string} url
   * @return {object}
   * @Private
   * */
  _getTimestampRequestNoAuth (url, tsQuery) {
    this.setEncoding(null) // we expect binary data in a buffer: ensure that the response is not decoded unnecessarily
    this.setResolveWithFullResponse(true)
    this.setBody(tsQuery)

    return { requestUrl: url, tsRequest: this.get() }
  }

  /**
   * _getOauth method that get oauth access_token
   *
   * @param {string} url
   * @param {object} auth
   * @param {object} body
   * @param {string} [proxy]
   * @return {Promise<object>}
   * @Private
   **/
  async _getOauth (url, auth, body, proxy) {
    const tsRequest = await this._getOauthRequestSettings(auth, body, proxy)
    return await fetch(url, tsRequest).then((response) => {
      return response.json()
    }).catch((err) => {
      return {
        message: err.message,
        trace: err
      }
    })
  }

  /**
   * _getOauthRequestSettings method that set the request oath settings
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

export default TimestampRequest
