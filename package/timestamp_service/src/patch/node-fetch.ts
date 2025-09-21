import type { RequestInfo, RequestInit, Response } from 'node-fetch'

export const fetch = async (url: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
  const { default: fetch } = await import('node-fetch')
  return fetch(url, init)
}
