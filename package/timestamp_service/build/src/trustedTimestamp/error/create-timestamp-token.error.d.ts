import { CreatedTimestampToken } from '../types/timestamp-token.type';
export type CreateTimestampTokenErrorContext = Partial<Pick<CreatedTimestampToken, 'logHistory' | 'providerName'>>;
/**
 * Custom error class that encapsulates context about token creation, including the provider used and the associated log history
 */
export declare class CreateTimestampTokenError extends Error {
    readonly context: CreateTimestampTokenErrorContext;
    constructor(message: string, context?: CreateTimestampTokenErrorContext, options?: ErrorOptions);
}
