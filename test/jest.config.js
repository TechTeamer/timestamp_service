const path = require('path')

module.exports = {
  roots: [path.resolve(__dirname, '..')],
  rootDir: path.resolve(__dirname, '..'),
  testPathIgnorePatterns: ['/node_modules/', '/web/', '/yarn-offline-cache/'],
  collectCoverage: true,
  coverageReporters: ['lcovonly'],
  coverageProvider: 'v8',
  coveragePathIgnorePatterns: ['/node_modules/', '<rootDir>/test', '<rootDir>/customization/test'],
  coverageDirectory: '<rootDir>/test/coverage/jest',
  transform: {},
  testTimeout: 30000
}
