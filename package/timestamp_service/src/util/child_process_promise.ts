import * as childProcess from 'node:child_process'
import type { ExecOptions } from 'node:child_process'

interface Logger {
  info: (log: string, ...args: unknown[]) => unknown
  error: (log: string, ...args: unknown[]) => unknown
}

export function exec<ReturnType = string>(
  command: string,
  options: {
    encoding?: 'buffer'
  } & ExecOptions = {},
  logger?: Logger
): Promise<ReturnType> {
  return new Promise<ReturnType>((resolve, reject) => {
    const process = childProcess.exec(command, options, (err, stdout, stderr) => {
      if (err) {
        return reject(err || new Error(stderr.toString() || `Failed to execute command: ${command}`))
      }

      return resolve(stdout as ReturnType)
    })

    if (logger) {
      process.stdout!.on('data', message => {
        message = message.trim()
        if (message) {
          logger.info(message)
        }
      })

      process.stderr!.on('data', message => {
        message = message.trim()
        if (message) {
          logger.error(message)
        }
      })
    }
  })
}

export class ExecFileError extends Error {
  public stdout?: string
  public stderr?: string
}

export function execFile(command: string, args: string[], options = {}): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    childProcess.execFile(command, args, options, (err, stdout, stderr) => {
      if (err) {
        const error = new ExecFileError(err ? err.message : stderr.toString() || `Failed to execute file: ${command}`)
        error.stdout = stdout
        error.stderr = stderr
        return reject(error)
      }

      resolve({ stdout, stderr })
    })
  })
}
