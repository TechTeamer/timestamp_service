import * as childProcess from 'node:child_process'

export function exec (command, options = {}, logger) {
  return new Promise((resolve, reject) => {
    const process = childProcess.exec(command, options, (err, stdout, stderr) => {
      if (err) {
        return reject(err || new Error(stderr.toString('utf8') || `Failed to execute command: ${command}`))
      }

      return resolve(stdout)
    })

    if (logger) {
      process.stdout.on('data', (message) => {
        message = message.trim()
        if (message) {
          logger.info(message)
        }
      })

      process.stderr.on('data', (message) => {
        message = message.trim()
        if (message) {
          logger.error(message)
        }
      })
    }
  })
}

export function execFile (command, args, options = {}) {
  return new Promise((resolve, reject) => {
    childProcess.execFile(command, args, options, (err, stdout, stderr) => {
      if (err) {
        const error = new Error(err ? err.message : stderr.toString('utf8') || `Failed to execute file: ${command}`)
        error.stdout = stdout
        error.stderr = stderr
        return reject(error)
      }

      resolve({ stdout, stderr })
    })
  })
}
