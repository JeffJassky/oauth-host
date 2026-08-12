import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    exclude: ['docs/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
    testTimeout: 30000,
    hookTimeout: 60000,
    // mongodb-memory-server downloads and binds a mongod per instance. Running
    // suites in parallel makes startup nondeterministic on CI runners with few
    // cores, and the failures look like flaky tests rather than contention.
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/index.ts'],
    },
  },
});
