import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    exclude: ['node_modules/**', 'web/**', 'yarn-offline-cache/**'],
    coverage: {
      enabled: true,
      reporter: ['lcovonly'],
      provider: 'v8',
      exclude: ['node_modules/', 'test', 'customization/test'],
      reportsDirectory: 'test/coverage/vitest'
    },
    timeout: 30000
  }
})
