import { TimestampProviderUrl } from './timestamp-provider.type';
export interface TimestampLog {
    info: {
        name: string;
        info?: null;
        date: Date;
        url: TimestampProviderUrl;
        response: string | null;
        error: string | null;
    };
    errorTrace: Error | null;
}
