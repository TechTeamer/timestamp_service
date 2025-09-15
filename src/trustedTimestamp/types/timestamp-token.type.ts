export interface Timestamp {
  digest: string
  hashAlgorithm: string
  dataSize: number
  tsr: unknown
  isToken: boolean
  certExpiry: string
  verified: boolean | null
}

export interface CreatedTimestampToken {
  timestamp: Timestamp
  providerName: string
  logHistory: string[]
}
