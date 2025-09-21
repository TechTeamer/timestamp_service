import { TimestampInfo } from './TrustedTimestampInfo';
import type { TimestampConfig } from './types/timestamp-config.type';
import type { CreatedTimestampToken, Timestamp } from './types/timestamp-token.type';
/**
 * OpenSSL docs: https://www.openssl.org/docs/manmaster/man1/ts.html
 *
 * Certificate Installation with OpenSSL: http://gagravarr.org/writing/openssl-certs/others.shtml
 *
 * Trustedtimestamp service implements the generate, import and verification of timestamps
 *
 * */
export declare class TrustedTimestampService {
    private readonly timestampInfoType;
    private readonly config;
    private readonly encoding;
    private readonly tmpOptions;
    private tempFileService;
    private certService;
    private providers;
    private certsLocation;
    private timestampRequest;
    constructor(timestampInfoType?: 'normal' | 'short', config?: TimestampConfig, encoding?: string);
    /**
     * init method that sets the config and instantiates the required services
     * */
    private _init;
    /**
     * Utility method that resolves to a TimestampInfo object containing parsed info from the tsr
     * */
    getTimestampInfo(tsr: Buffer, isToken?: boolean): Promise<TimestampInfo>;
    /**
     * Returns a TimestampToken instance for a hash digest and a hash algorithm.
     * It requests a token from the TSA and verifies the received response.
     * The returned timestamp token represents the token
     * and contains the tsr with the verification result.
     * */
    createTimestampToken(digest: string, hashAlgorithm: string, dataSize: number): Promise<CreatedTimestampToken>;
    /**
     * Verify if a timestamp token corresponds to a particular hash of data
     * */
    verifyToken(timestampToken: Timestamp, digest: string, dataSize: number): Promise<boolean>;
    /**
     * Verify a hash digest against a timestamp response file
     * */
    verifyTsr(digest: string, tsr: Buffer, isToken?: boolean): Promise<boolean>;
    /**
     * testService method that check the ssl installation
     * */
    testService(): Promise<string>;
}
