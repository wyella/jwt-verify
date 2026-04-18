import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/middleware.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  target: 'es2022',
  platform: 'neutral',
  external: ['next', 'next/server'],
  splitting: false,
  treeshake: true,
});
