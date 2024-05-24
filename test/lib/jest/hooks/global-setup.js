const net = require('net')
const path = require('path')
const serviceContainer = require('../../../../server/service_container')
const logger = require('../../../../server/logger')
const { createSharedContextHandler } = require('../../shared-context')

process.env.TZ = 'Etc/UTC'

module.exports = async () => {
  serviceContainer.logger = logger

  try {
    serviceContainer.logger.info('Starting shared context server...')

    const socksPath = path.resolve(__dirname, '../../../sharedContext.sock')

    const serverHandler = await createSharedContextHandler(serviceContainer.logger)
    global.vuerTestServer = net.createServer(serverHandler)
    global.vuerTestServer.on('error', err => {
      serviceContainer.logger.error('Test server error', err)
      throw err
    })
    global.vuerTestServer.listen(socksPath, () => serviceContainer.logger.info(`Shared context server listening on ${socksPath}`))
  } catch (err) {
    logger.error('Error setting up test environment', err)
    throw err
  }
}
