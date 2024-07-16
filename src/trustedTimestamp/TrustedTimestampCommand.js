import { exec } from '../util/child_process_promise.js'

/**
 * @param digest
 * @param digestFormat
 * @return {Promise<string>}
 */
async function getTsQuery (digest, digestFormat) {
  // create a time stamp request based on the hash of a data file
  const queryCommand = `openssl ts -query -digest ${digest} -no_nonce -${digestFormat} -cert`

  return await exec(queryCommand, { encoding: 'buffer' }).catch((err) => {
    throw new Error(`Failed to execute openssl ts -query command "${queryCommand}" ${err.message}`)
  })
}

/**
 * @param digest
 * @param tempPath
 * @param isToken
 * @param certsLocation
 * @return {Promise<string>}
 */
function getTsVerify (digest, tempPath, isToken, certsLocation) {
  // verify the response with openssl
  const verifyCommand = isToken
    ? `openssl ts -verify -digest ${digest} -token_in -in ${tempPath} -CApath ${certsLocation}`
    : `openssl ts -verify -digest ${digest} -in ${tempPath} -CApath ${certsLocation}`

  return exec(verifyCommand).catch((err) => {
    throw new Error(`Failed to verify tsr "${verifyCommand}" ${err.message}`)
  })
}

/**
 * @param inputTempPath
 * @param isToken
 * @return {Promise<string>}
 */
async function getTsReply (inputTempPath, isToken) {
  // get token info
  const replyCommand = isToken
    ? `openssl ts -reply -token_in -in ${inputTempPath} -text`
    : `openssl ts -reply -in ${inputTempPath} -text`
  return await exec(replyCommand).catch((err) => {
    throw new Error(`Error executing openssl ts -reply command "${replyCommand}" ${err.message}`)
  })
}

/**
 * @param inputTempPath
 * @param tmp
 * @return {Promise<string>}
 */
async function generateTsReply (inputTempPath, tmp) {
  await exec(`openssl ts -reply -in "${inputTempPath}" -token_out -out "${tmp.tempPath}"`).catch((err) => {
    throw new Error(`Error executing openssl ts -reply command "${inputTempPath}" ${err.message}`)
  })
}

/**
 * @param tstPath
 * @return {Promise<string>}
 */
async function extractCertFromToken (tstPath) {
  return await exec(`openssl pkcs7 -inform der -in "${tstPath}" -print_certs`).catch((err) => {
    throw new Error(`Error executing openssl pkcs7 command ${err.message}`)
  })
}

/**
 * @return {Promise<string>}
 */
async function checkSslPath () {
  return await exec('which openssl').catch((err) => {
    throw new Error(`Unable to verify openssl installation ${err.message}`)
  }).then((stdout) => {
    if (!stdout.toString()) {
      throw new Error('openssl is unavailable')
    }
    return stdout
  })
}

export { getTsQuery, getTsVerify, getTsReply, generateTsReply, extractCertFromToken, checkSslPath }
