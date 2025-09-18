import fetch, { BodyInit } from 'node-fetch'
import fs from 'node:fs'
import { ProxyAgent } from 'proxy-agent'
import type { FileOptions } from 'tmp'

import type {
  TimestampRequestAuthResult,
  TimestampRequestAuthTypes,
  TimestampRequestError,
  TimestampRequestOptions
} from './types/timestamp-request.type'
import type {
  TimestampProviderAuth,
  TimestampProviderBody,
  TimestampProviderOAuthUrl,
  TimestampProviderProxyConfig,
  TimestampProviderUrl
} from './types/timestamp-provider.type'
import type { TempFileService } from '../util/TempFileService'

/**
 * TimestampRequest class implements timestamp request
 * */
export class TimestampRequest {
  private tsRequest: TimestampRequestOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/timestamp-query'
    }
  }

  constructor(
    private readonly tempFileService: TempFileService,
    private readonly tmpOptions: FileOptions,
    private readonly cleanupTempFns: ((...args: unknown[]) => unknown)[]
  ) {}

  /**
   * set request header
   * */
  setHeader(headers: Record<string, string>): void {
    this.tsRequest = {
      ...this.tsRequest,
      headers
    }
  }

  /**
   * set request body
   * */
  setBody(body: BodyInit): void {
    this.tsRequest.body = body
  }

  /**
   * set request proxy
   * */
  setProxy(proxy: TimestampProviderProxyConfig): void {
    this.tsRequest.agent = new ProxyAgent({
      getProxyForUrl: (): string => proxy.url,
      rejectUnauthorized: !(proxy.allowUnauthorized ?? false)
    })
  }

  /**
   * set request encoding
   * */
  setEncoding(encoding: string | null): void {
    this.tsRequest.encoding = encoding
  }

  /**
   * set request encoding
   * */
  setResolveWithFullResponse(resolveWithFullResponse: boolean): void {
    this.tsRequest.resolveWithFullResponse = resolveWithFullResponse
  }

  /**
   * return tsRequest
   * */
  get(): TimestampRequestOptions {
    return this.tsRequest
  }

  /**
   * authStrategy method that set no auth request
   * */
  async authStrategy(
    requestType: TimestampRequestAuthTypes | undefined,
    url: TimestampProviderUrl,
    auth: TimestampProviderAuth | undefined,
    body: TimestampProviderBody | undefined,
    proxy: TimestampProviderProxyConfig | undefined,
    tsQuery: string
  ): Promise<TimestampRequestAuthResult> {
    switch (requestType) {
      case 'basic':
        return this._getTimestampRequestBasic(url as string, auth!, tsQuery)
      case 'oauth':
        return await this._getTimestampRequestOauth(url as TimestampProviderOAuthUrl, auth!, body, proxy, tsQuery)
      case 'noAuth':
        return this._getTimestampRequestNoAuth(url as string, tsQuery)
      default:
        return this._getTimestampRequestNoAuth(url as string, tsQuery)
    }
  }

  /**
   * _getTimestampRequestBasic method that set basic auth request
   * */
  private _getTimestampRequestBasic(
    url: string,
    auth: TimestampProviderAuth,
    tsQuery: string
  ): TimestampRequestAuthResult {
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
   * */
  private async _getTimestampRequestOauth(
    url: TimestampProviderOAuthUrl,
    auth: TimestampProviderAuth,
    body: TimestampProviderBody | undefined,
    proxy: TimestampProviderProxyConfig | undefined,
    tsQuery: string
  ): Promise<TimestampRequestAuthResult> {
    const oauthResult = await this._getOauth<{
      access_token?: string
      error?: TimestampRequestError
    }>(url.getTokenUrl, auth, body, proxy)
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

      const { tempPath, cleanupCallback } = await this.tempFileService.createTempFile(
        this.tmpOptions,
        Buffer.from(tsQuery)
      )
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
   * */
  private _getTimestampRequestNoAuth(url: string, tsQuery: string): TimestampRequestAuthResult {
    this.setEncoding(null) // we expect binary data in a buffer: ensure that the response is not decoded unnecessarily
    this.setResolveWithFullResponse(true)
    this.setBody(tsQuery)

    return { requestUrl: url, tsRequest: this.get() }
  }

  /**
   * _getOauth method that get oauth access_token
   **/
  private async _getOauth<ResponseType extends { error?: TimestampRequestError }>(
    url: string,
    auth: TimestampProviderAuth,
    body: TimestampProviderBody | undefined,
    proxy: TimestampProviderProxyConfig | undefined
  ): Promise<ResponseType> {
    const tsRequest = await this._getOauthRequestSettings(auth, body, proxy)
    try {
      const response = await fetch(url, tsRequest)
      return (await response.json()) as ResponseType
    } catch (error) {
      return {
        error: {
          message: (error as Error).message,
          trace: error as Error
        }
      } as ResponseType
    }
  }

  /**
   * _getOauthRequestSettings method that set the request oath settings
   **/
  private async _getOauthRequestSettings(
    auth: TimestampProviderAuth,
    body: TimestampProviderBody | undefined,
    proxy: TimestampProviderProxyConfig | undefined
  ): Promise<TimestampRequestOptions<ProxyAgent>> {
    const tsRequest: TimestampRequestOptions<ProxyAgent> = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(auth.user + ':' + auth.pass).toString('base64')}`
      },
      body: new URLSearchParams(body)
    }

    if (proxy?.url) {
      tsRequest.agent = new ProxyAgent({
        getProxyForUrl: (): string => proxy.url,
        rejectUnauthorized: !(proxy.allowUnauthorized ?? false)
      })
    }

    return tsRequest
  }
}
