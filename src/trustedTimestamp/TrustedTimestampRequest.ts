import fetch from 'node-fetch'
import { FileOptions as TempFileOptions } from 'tmp'

import { TimestampRequest } from './TimestampRequest'
import { TempFileService } from '../util/TempFileService'
import type { TimestampRequestAuthResult, TimestampRequestAuthTypes } from './types/timestamp-request.type'
import type {
  TimestampProvider,
  TimestampProviderAuth,
  TimestampProviderBody,
  TimestampProviderOAuthUrl,
  TimestampProviderProxyConfig,
  TimestampProviderUrl
} from './types/timestamp-provider.type'
import type { TimestampLog } from './types/timestamp-log.type'

/**
 * TrustedTimestampRequest service implements timestamp request and sorted providers
 * */
export class TrustedTimestampRequest {
  private readonly cleanupTempFns: (() => unknown)[] = []
  private readonly providers: TimestampProvider[]

  constructor(
    providers: TimestampProvider[],
    private readonly tempFileService: TempFileService,
    private readonly tmpOptions: TempFileOptions
  ) {
    this.providers = this._sortedProviders(providers)
  }

  /**
   * getTimestamp method that calls the service providers in sequence, requesting a timestamp
   **/
  async getTimestamp(
    tsQuery: string
  ): Promise<{ tsr: Buffer | null; providerName: string; logHistory: TimestampLog[] }> {
    let tsr = null
    let providerName = ''
    const logHistory: TimestampLog[] = []

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
   **/
  private _sortedProviders(providers: TimestampProvider[]): TimestampProvider[] {
    const priorityProviders: TimestampProvider[] = []
    const nonPriorityProviders: TimestampProvider[] = []

    providers.forEach(provider => {
      if (provider?.priority) {
        priorityProviders.push(provider)
      } else {
        nonPriorityProviders.push(provider)
      }
    })

    const sortedProviders = priorityProviders.toSorted((a, b) => a.priority! - b.priority!)

    return sortedProviders.concat(nonPriorityProviders)
  }

  /**
   * sendTimestampRequest method that calls the provider
   **/
  private async _getTimeStampToken(
    name: string,
    url: TimestampProviderUrl,
    auth: TimestampProviderAuth | undefined,
    body: TimestampProviderBody | undefined,
    proxy: TimestampProviderProxyConfig | undefined,
    tsQuery: string
  ): Promise<{
    timestampToken: null | Buffer
    log: TimestampLog
  }> {
    const { requestUrl, tsRequest, error } = await this._getTimestampRequest(url, body, auth, proxy, tsQuery)
    if (error) {
      return {
        timestampToken: null,
        log: {
          info: { name, info: null, date: new Date(), url, response: null, error: error?.message },
          errorTrace: error?.trace
        }
      }
    }
    try {
      const response = await fetch(requestUrl!, tsRequest!)
      if (response.status !== 200) {
        throw new Error(`TSA response unsatisfactory: ${response.status} ${response.statusText}`)
      }

      return {
        timestampToken: Buffer.from((await response.arrayBuffer()) as unknown as string, 'utf8'), // TODO: fix type
        log: {
          info: { name, date: new Date(), url, response: `${response.status}, ${response.statusText}`, error: null },
          errorTrace: null
        }
      }
    } catch (error) {
      return {
        timestampToken: null,
        log: {
          info: { name, date: new Date(), url, response: null, error: (error as Error).message },
          errorTrace: error as Error
        }
      }
    } finally {
      for (const cleanUpFn of this.cleanupTempFns) {
        if (typeof cleanUpFn === 'function') {
          cleanUpFn()
        }
      }
    }
  }

  /**
   * getTimestampRequestSettings method that set the request settings
   **/
  private async _getTimestampRequest(
    url: TimestampProviderUrl,
    body: TimestampProviderBody | undefined,
    auth: TimestampProviderAuth | undefined,
    proxy: TimestampProviderProxyConfig | undefined,
    tsQuery: string
  ): Promise<TimestampRequestAuthResult> {
    // send the request to the TSA
    const tsRequest = new TimestampRequest(this.tempFileService, this.tmpOptions, this.cleanupTempFns)

    if (proxy?.url) {
      tsRequest.setProxy(proxy)
    }

    let requestType: TimestampRequestAuthTypes | undefined
    if ((url as TimestampProviderOAuthUrl)?.getTokenUrl && tsQuery) {
      requestType = 'oauth'
    }
    if (!(url as TimestampProviderOAuthUrl)?.getTokenUrl && auth?.user && auth?.pass && tsQuery) {
      requestType = 'basic'
    }
    if (!(url as TimestampProviderOAuthUrl)?.getTokenUrl && !auth?.user) {
      requestType = 'noAuth'
    }

    return await tsRequest.authStrategy(requestType, url, auth, body, proxy, tsQuery)
  }
}
