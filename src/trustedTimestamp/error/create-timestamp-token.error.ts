import { CreatedTimestampToken } from '../types/timestamp-token.type'

export type CreateTimestampTokenErrorContext = Partial<Pick<CreatedTimestampToken, 'logHistory' | 'providerName'>>

/**
 * Custom error class that encapsulates context about token creation, including the provider used and the associated log history
 */
export class CreateTimestampTokenError extends Error {
  constructor(
    message: string,
    readonly context: CreateTimestampTokenErrorContext = {},
    options?: ErrorOptions
  ) {
    super(message, options)
  }
}
