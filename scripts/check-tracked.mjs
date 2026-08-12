#!/usr/bin/env node
/**
 * Fail if a source file is missing from git.
 *
 * A contributor's global gitignore (`core.excludesFile`) applies to every repo
 * they touch, and a bare rule like `config.js` will silently drop files that
 * exist on their disk and in every local test run. That is exactly how
 * `src/server/config.js` and `docs/.vitepress/config.js` missed featureboard's
 * first push: the build broke only on CI, and the docs deployed without a nav.
 *
 * This walks the source directories and compares what is on disk to what git
 * tracks, so the gap fails loudly and locally instead. Run it FIRST in CI —
 * before typecheck, before build — because every later step passes against the
 * working tree, which is precisely the thing that is lying.
 *
 * See standards/traps.md #1.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ROOTS = ['src', 'test', 'types', 'docs', 'examples', 'scripts', '.github'];

// Genuinely-not-source things that live under those roots.
const ALLOWED = [
  /(^|\/)\.DS_Store$/,
  /(^|\/)node_modules(\/|$)/,
  /^docs\/\.vitepress\/(dist|cache)(\/|$)/,
];

const tracked = new Set(
  execFileSync('git', ['ls-files', ...ROOTS], { encoding: 'utf8' })
    .split('\n')
    .filter(Boolean),
);

function walk(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out; // root not present in this checkout
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (ALLOWED.some((re) => re.test(p))) continue;
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const untracked = ROOTS.flatMap((r) => walk(r)).filter((p) => !tracked.has(p));

if (untracked.length) {
  console.error('Source files exist on disk but are not tracked by git:\n');
  for (const p of untracked) {
    let why = '';
    try {
      why = execFileSync('git', ['check-ignore', '-v', p], { encoding: 'utf8' }).trim();
    } catch {
      why = '(not ignored — just never added)';
    }
    console.error(`  ${p}\n    ${why}`);
  }
  console.error(
    '\nIf a global gitignore is the cause, add a negation to this repo\'s '
    + '.gitignore — repo rules outrank core.excludesFile.',
  );
  process.exit(1);
}

console.log(`check-tracked: ${tracked.size} source files tracked, none missing.`);
