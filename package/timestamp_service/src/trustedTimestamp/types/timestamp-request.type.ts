import type { Agent } from 'http'
import type { BodyInit } from 'node-fetch'

export type TimestampRequestAuthTypes = 'oauth' | 'basic' | 'noAuth'

export interface TimestampRequestOptions<AgentType extends Agent = Agent> {
  method: string
  headers: Record<string, string>
  encoding?: string | null
  resolveWithFullResponse?: boolean
  body?: BodyInit
  agent?: AgentType
}

export interface TimestampRequestError {
  message: string
  trace: Error | null
}

export interface TimestampRequestAuthResult {
  requestUrl: string | null
  tsRequest: TimestampRequestOptions | null
  error?: TimestampRequestError | null
}
