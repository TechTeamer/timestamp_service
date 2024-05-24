const NodeEnvironment = require('jest-environment-node')

class TestEnvironment extends NodeEnvironment.default {
  constructor (config, context) {
    super(config, context)
  }
}

module.exports = TestEnvironment
