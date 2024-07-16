import dts from 'rollup-plugin-dts'
import build from 'rollup-plugin-esbuild'
import path from 'node:path'

const name = './build/timestamp_config'

const bundle = config => ({
  ...config,
  input: 'src/index.js',
  external: id => !/^[./]/.test(id)
})

export default [
  bundle({
    plugins: [build({
      tsconfig: path.resolve('tsconfig.json'),
      target: 'es2022'
    })],
    output: [
      {
        file: `${name}.cjs`,
        format: 'cjs',
        sourcemap: true
      },
      {
        file: `${name}.mjs`,
        format: 'es',
        sourcemap: true
      }
    ]
  }),
  bundle({
    plugins: [dts()],
    output: {
      file: `${name}.d.ts`,
      format: 'es'
    }
  })
]
