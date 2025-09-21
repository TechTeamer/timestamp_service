import { FileOptions as TempFileOptions } from 'tmp';
import { TempFileService } from '../util/TempFileService';
import type { TimestampProvider } from './types/timestamp-provider.type';
import type { TimestampLog } from './types/timestamp-log.type';
/**
 * TrustedTimestampRequest service implements timestamp request and sorted providers
 * */
export declare class TrustedTimestampRequest {
    private readonly tempFileService;
    private readonly tmpOptions;
    private readonly cleanupTempFns;
    private readonly providers;
    constructor(providers: TimestampProvider[], tempFileService: TempFileService, tmpOptions: TempFileOptions);
    /**
     * getTimestamp method that calls the service providers in sequence, requesting a timestamp
     **/
    getTimestamp(tsQuery: string): Promise<{
        tsr: Buffer | null;
        providerName: string;
        logHistory: TimestampLog[];
    }>;
    /**
     * sortedProviders method that sorting the providers according to priority
     **/
    private _sortedProviders;
    /**
     * sendTimestampRequest method that calls the provider
     **/
    private _getTimeStampToken;
    /**
     * getTimestampRequestSettings method that set the request settings
     **/
    private _getTimestampRequest;
}
