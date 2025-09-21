export interface TimestampProviderProxyConfig {
  url: string
  allowUnauthorized?: boolean
}

export interface TimestampProviderOAuthUrl {
  getTokenUrl: string
  getTimestampUrl: string
}

export type TimestampProviderUrl = string | TimestampProviderOAuthUrl

export interface TimestampProviderAuth {
  user: string
  pass: string
}

export type TimestampProviderBody = Record<string, string>

export interface TimestampProvider {
  name: string
  url: TimestampProviderUrl
  auth?: TimestampProviderAuth
  priority?: number
  body?: TimestampProviderBody
  proxy?: TimestampProviderProxyConfig
}
