const fs = require('fs-extra')
const util = require('util')

const tmp = require('tmp')
tmp.setGracefulCleanup()

const tmpFile = util.promisify((options, cb) => {
  tmp.file(options, (err, ...results) => cb(err, results))
})

class TempFileService {
  /**
   * Utility to create a temp file with content
   *
   * @param {Object} options
   * @param {Buffer} content
   * @return {Promise<{tempPath, fd, cleanupCallback}>}
   * */
  async createTempFile (options = {}, content) {
    try {
      const [tempPath, fd, cleanupCallback] = await tmpFile(options)
      if (content) {
        await fs.writeFile(tempPath, content)
      }
      return { tempPath, fd, cleanupCallback }
    } catch (err) {
      throw new Error(`Failed to create temp file ${err}`)
    }
  }
}

module.exports = TempFileService
