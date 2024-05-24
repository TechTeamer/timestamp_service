const supportedDigestForamts = [
  'sha', 'sha1', 'mdc2', 'ripemd160', 'sha224', 'sha256', 'sha384', 'sha512', 'md2', 'md4', 'md5', 'dss1'
]

/**
 * @param format
 * @return {boolean}
 */
function checkDigestFormat (format) {
  return supportedDigestForamts.includes(format)
}

/**
 * @param digest
 * @return {boolean}
 */
function checkDigest (digest) {
  return /^([0-9A-F])+$/i.test(digest)
}

/**
 * @param {string} format
 * @return {string}
 */
function normalizeDigestFormat (format) {
  return format
    .replace(/^-/, '') // -sha256
    .replace(/-/g, '') // sha-256
}

module.exports = { checkDigestFormat, checkDigest, normalizeDigestFormat }
