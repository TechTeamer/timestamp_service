import type { RequestInfo, RequestInit, Response } from 'node-fetch';
export declare const fetch: (url: URL | RequestInfo, init?: RequestInit) => Promise<Response>;
