const path = require('path')

module.exports = {
  testSequencer: '<rootDir>/test/lib/jest/test.sequencer',
  testEnvironment: '<rootDir>/test/lib/jest/test.environment',
  roots: [path.resolve(__dirname, '..')],
  rootDir: path.resolve(__dirname, '..'),
  testPathIgnorePatterns: ['/node_modules/', '/web/', '/yarn-offline-cache/'],
  collectCoverage: true,
  coverageReporters: ['lcovonly'],
  coverageProvider: 'v8',
  coveragePathIgnorePatterns: ['/node_modules/', '<rootDir>/test', '<rootDir>/customization/test'],
  coverageDirectory: '<rootDir>/test/coverage/jest',
  transform: {},
  testTimeout: 30000,
  moduleNameMapper: {
    service_container$: '<rootDir>/test/__mocks__/service_container.js'
  }
}
