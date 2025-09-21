import fs from 'node:fs/promises'
import util from 'node:util'
import tmp from 'tmp'

tmp.setGracefulCleanup()

const tmpFile = util.promisify(
  (
    options: tmp.FileOptions,
    cb: (error: Error | null, results: [string, number | undefined, () => void]) => unknown
  ) => {
    tmp.file(options, (err, ...results) => cb(err, results))
  }
)

export class TempFileService {
  /**
   * Utility to create a temp file with content
   * */
  async createTempFile(
    options: tmp.FileOptions,
    content?: Buffer
  ): Promise<{ tempPath: string; fd: number | undefined; cleanupCallback: () => void }> {
    try {
      const [tempPath, fd, cleanupCallback] = await tmpFile(options)
      if (content) {
        await fs.writeFile(tempPath, content as unknown as string)
      }
      return { tempPath, fd, cleanupCallback }
    } catch (err) {
      throw new Error(`Failed to create temp file ${err}`)
    }
  }
}
