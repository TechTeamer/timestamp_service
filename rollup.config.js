import typescript from '@rollup/plugin-typescript'

const name = './build/timestamp_config'

const bundle = config => ({
  ...config,
  input: 'src/index.ts',
  external: id => !/^[./]/.test(id)
})

export default [
  bundle({
    plugins: [typescript()],
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
  })
]
