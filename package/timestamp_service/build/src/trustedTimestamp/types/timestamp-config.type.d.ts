import type { TimestampProvider } from './timestamp-provider.type';
export interface TimestampConfig {
    certsLocation: string;
    providers: TimestampProvider[];
}
