import { CreatedTimestampToken } from '../types/timestamp-token.type.js'

export type CreateTimestampTokenErrorContext = Partial<Pick<CreatedTimestampToken, 'logHistory' | 'providerName'>>

export class CreateTimestampTokenError extends Error {
  constructor (
    message: string,
        readonly context: CreateTimestampTokenErrorContext = {},
        options?: ErrorOptions) {
    super(message, options)
  }
}
