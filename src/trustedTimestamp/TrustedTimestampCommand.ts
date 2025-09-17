import { exec } from '../util/child_process_promise'

export async function getTsQuery(digest: string, digestFormat: string): Promise<string> {
  // create a time stamp request based on the hash of a data file
  const queryCommand = `openssl ts -query -digest ${digest} -no_nonce -${digestFormat} -cert`

  return await exec(queryCommand, { encoding: 'buffer' }).catch(err => {
    throw new Error(`Failed to execute openssl ts -query command "${queryCommand}" ${err.message}`)
  })
}

export function getTsVerify(
  digest: string,
  tempPath: string,
  isToken: boolean,
  certsLocation: string
): Promise<string> {
  // verify the response with openssl
  const verifyCommand = isToken
    ? `openssl ts -verify -digest ${digest} -token_in -in ${tempPath} -CApath ${certsLocation}`
    : `openssl ts -verify -digest ${digest} -in ${tempPath} -CApath ${certsLocation}`

  return exec(verifyCommand).catch(err => {
    throw new Error(`Failed to verify tsr "${verifyCommand}" ${err.message}`)
  })
}

export async function getTsReply(inputTempPath: string, isToken: boolean): Promise<string> {
  // get token info
  const replyCommand = isToken
    ? `openssl ts -reply -token_in -in ${inputTempPath} -text`
    : `openssl ts -reply -in ${inputTempPath} -text`
  return await exec(replyCommand).catch(err => {
    throw new Error(`Error executing openssl ts -reply command "${replyCommand}" ${err.message}`)
  })
}

export async function generateTsReply(inputTempPath: string, tempPath: string): Promise<void> {
  await exec(`openssl ts -reply -in "${inputTempPath}" -token_out -out "${tempPath}"`).catch(err => {
    throw new Error(`Error executing openssl ts -reply command "${inputTempPath}" ${err.message}`)
  })
}

export async function extractCertFromToken(tstPath: string): Promise<string> {
  return await exec(`openssl pkcs7 -inform der -in "${tstPath}" -print_certs`).catch(err => {
    throw new Error(`Error executing openssl pkcs7 command ${err.message}`)
  })
}

export async function checkSslPath(): Promise<string> {
  try {
    const stdout = await exec('which openssl')
    if (!stdout.toString()) {
      throw new Error('openssl is unavailable')
    }
    return stdout
  } catch (error) {
    throw new Error(`Unable to verify openssl installation ${(error as Error).message}`)
  }
}
