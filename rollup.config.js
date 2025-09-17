import typescript from '@rollup/plugin-typescript'

const name = './build/timestamp_config'

const bundle = config => ({
  ...config,
  input: 'src/index.ts',
  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
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
