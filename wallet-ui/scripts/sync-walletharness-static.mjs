import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const sourceDir = resolve(__dirname, '..', 'out')
const targetDir = resolve(__dirname, '..', '..', 'backend', 'cmd', 'walletharness', 'static')

function pruneEmptyDirs(dir) {
  let hasEntries = false
  for (const entry of readdirSync(dir)) {
    const entryPath = resolve(dir, entry)
    if (statSync(entryPath).isDirectory()) {
      if (pruneEmptyDirs(entryPath)) {
        hasEntries = true
      } else {
        rmSync(entryPath, { recursive: true, force: true })
      }
    } else {
      hasEntries = true
    }
  }
  return hasEntries
}

if (!existsSync(sourceDir)) {
  console.error(`Next.js export directory not found: ${sourceDir}`)
  console.error('Run "next build" with output: "export" first.')
  process.exit(1)
}

if (existsSync(targetDir)) {
  rmSync(targetDir, { recursive: true, force: true })
}
mkdirSync(targetDir, { recursive: true })

cpSync(sourceDir, targetDir, { recursive: true })
pruneEmptyDirs(targetDir)
writeFileSync(resolve(targetDir, '.gitkeep'), '')

console.log(`Synced wallet static files: ${sourceDir} -> ${targetDir}`)
