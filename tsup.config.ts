import { defineConfig } from 'tsup';

// Dual ESM/CJS output. The source is ESM-only, but hosts compiled to CommonJS
// (ts-node/tsc with module:CommonJS) can only `require()` — an ESM-only package
// fails there with ERR_REQUIRE_ESM. Shipping both keeps a plain
// `import { createOAuthHost } from '@jeffjassky/oauth-host'` working either way.
//
// `dts` is deliberately OFF. The published declarations are the hand-written
// ones in `types/`, and generating them here would overwrite a curated public
// contract with whatever the internals happen to infer. `tsc --noEmit` is what
// keeps the two honest — see standards/house-style.md and traps.md #21.
//
// One entry, no `dist/ui`: this package ships no browser code. The OAuth
// *client* is Claude or ChatGPT, and the consent screen is the host's — see
// plans/build-plan.md §5. That is also why traps #7 (`import.meta.url` under
// CJS) and #8 (SPA base href) do not apply here.
//
// express/mongoose stay external: they are peers, and bundling a peer means the
// host gets two copies of mongoose and a model registry that does not match
// itself.
export default defineConfig({
  entry: { index: 'src/server/index.ts' },
  format: ['esm', 'cjs'],
  dts: false,
  sourcemap: true,
  clean: true,
  target: 'node20',
  outExtension: ({ format }) => ({
    js: format === 'cjs' ? '.cjs' : '.js',
  }),
  splitting: false,
  treeshake: true,
});
