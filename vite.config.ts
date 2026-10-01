import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
  },
  test: {
    environment: 'node',
    setupFiles: ['tests/setup.ts'],
    include: ['tests/**/*.test.ts'],
    // PBKDF2 在测试里用低迭代次数，整体应很快；留足余量即可
    testTimeout: 20_000,
  },
});
