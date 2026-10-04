#!/usr/bin/env node
// Copies the canonical GEL design files (tokens and brand assets) into each consuming app.
// Copies are committed because each Docker build context only sees its own app directory.
//
//   node design/sync-tokens.mjs          write copies
//   node design/sync-tokens.mjs --check  exit 1 if any copy is missing or stale

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { basename, dirname, extname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const designDir = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(designDir, '..')

const TARGETS = [
  { file: 'tokens.css', to: ['frontend/src/styles/design', 'wallet-ui/src/styles/design', 'docs/starlight/src/styles/design'] },
  { file: 'tailwind-theme.css', to: ['frontend/src/styles/design', 'wallet-ui/src/styles/design'] },
  { file: 'brand/wordmark.generated.ts', to: ['frontend/src/components/common'] },
  { file: 'brand/wordmark-dark.svg', to: ['frontend/public/brand', 'wallet-ui/public/brand', 'docs/starlight/src/assets'] },
  { file: 'brand/wordmark-light.svg', to: ['frontend/public/brand', 'docs/starlight/src/assets'] },
]

const check = process.argv.includes('--check')

const BANNERS = {
  '.css': (file) => `/* GENERATED from ProtocolLens/design/${file} by design/sync-tokens.mjs. Do not edit. */\n`,
  '.ts': (file) => `// GENERATED from ProtocolLens/design/${file} by design/sync-tokens.mjs. Do not edit.\n`,
  '.svg': (file) => `<!-- GENERATED from ProtocolLens/design/${file} by design/sync-tokens.mjs. Do not edit. -->\n`,
}

const stale = []
for (const { file, to } of TARGETS) {
  const expected = BANNERS[extname(file)](file) + readFileSync(join(designDir, file), 'utf8').replace(/\r\n/g, '\n')
  for (const dir of to) {
    const target = join(repoRoot, dir, basename(file))
    const current = existsSync(target) ? readFileSync(target, 'utf8').replace(/\r\n/g, '\n') : null
    if (current === expected) continue
    if (check) {
      stale.push(relative(repoRoot, target))
      continue
    }
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, expected)
    console.log(`wrote ${relative(repoRoot, target)}`)
  }
}

if (check) {
  if (stale.length > 0) {
    console.error('GEL copies are out of date. Run `node design/sync-tokens.mjs` from ProtocolLens/:')
    for (const path of stale) console.error(`  ${path}`)
    process.exit(1)
  }
  console.log('GEL copies are in sync.')
}
