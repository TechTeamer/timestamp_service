import type { BodyInit } from 'node-fetch';
import type { FileOptions } from 'tmp';
import type { TimestampRequestAuthResult, TimestampRequestAuthTypes, TimestampRequestOptions } from './types/timestamp-request.type';
import type { TimestampProviderAuth, TimestampProviderBody, TimestampProviderProxyConfig, TimestampProviderUrl } from './types/timestamp-provider.type';
import type { TempFileService } from '../util/TempFileService';
/**
 * TimestampRequest class implements timestamp request
 * */
export declare class TimestampRequest {
    private readonly tempFileService;
    private readonly tmpOptions;
    private readonly cleanupTempFns;
    private tsRequest;
    constructor(tempFileService: TempFileService, tmpOptions: FileOptions, cleanupTempFns: ((...args: unknown[]) => unknown)[]);
    /**
     * set request header
     * */
    setHeader(headers: Record<string, string>): void;
    /**
     * set request body
     * */
    setBody(body: BodyInit): void;
    /**
     * set request proxy
     * */
    setProxy(proxy: TimestampProviderProxyConfig): void;
    /**
     * set request encoding
     * */
    setEncoding(encoding: string | null): void;
    /**
     * set request encoding
     * */
    setResolveWithFullResponse(resolveWithFullResponse: boolean): void;
    /**
     * return tsRequest
     * */
    get(): TimestampRequestOptions;
    /**
     * authStrategy method that set no auth request
     * */
    authStrategy(requestType: TimestampRequestAuthTypes | undefined, url: TimestampProviderUrl, auth: TimestampProviderAuth | undefined, body: TimestampProviderBody | undefined, proxy: TimestampProviderProxyConfig | undefined, tsQuery: string): Promise<TimestampRequestAuthResult>;
    /**
     * _getTimestampRequestBasic method that set basic auth request
     * */
    private _getTimestampRequestBasic;
    /**
     * _getTimestampRequestOauth method that set oauth request
     * */
    private _getTimestampRequestOauth;
    /**
     * _getTimestampRequestNoAuth method that set no auth request
     * */
    private _getTimestampRequestNoAuth;
    /**
     * _getOauth method that get oauth access_token
     **/
    private _getOauth;
    /**
     * _getOauthRequestSettings method that set the request oath settings
     **/
    private _getOauthRequestSettings;
}
