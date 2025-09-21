import { TimestampLog } from './timestamp-log.type';
export interface Timestamp {
    digest: string;
    hashAlgorithm: string;
    dataSize: number;
    tsr: Buffer;
    isToken: boolean;
    certExpiry: Date | null;
    verified: boolean | null;
}
export interface CreatedTimestampToken {
    timestamp: Timestamp;
    providerName: string;
    logHistory: TimestampLog[];
}
