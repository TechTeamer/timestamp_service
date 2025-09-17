const supportedDigestForamts = [
  'sha',
  'sha1',
  'mdc2',
  'ripemd160',
  'sha224',
  'sha256',
  'sha384',
  'sha512',
  'md2',
  'md4',
  'md5',
  'dss1'
]

export function checkDigestFormat(format: string): boolean {
  return supportedDigestForamts.includes(format)
}

export function checkDigest(digest: string): boolean {
  return /^([0-9A-F])+$/i.test(digest)
}

export function normalizeDigestFormat(format: string): string {
  return format
    .replace(/^-/, '') // -sha256
    .replace(/-/g, '') // sha-256
}
