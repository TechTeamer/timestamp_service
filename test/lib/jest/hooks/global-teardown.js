const serviceContainer = require('../../../../server/service_container')

module.exports = async () => {
  if (serviceContainer.db) {
    await serviceContainer.db.close()
  }

  if (global.vuerTestServer) {
    serviceContainer.logger.info('Shutting down test server')
    global.vuerTestServer.close(() => global.vuerTestServer.unref())
  }
}
