import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['./src/argon2.ts'],
  format: ['esm', 'cjs'],
  sourcemap: true,
})
