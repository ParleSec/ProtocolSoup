import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const sourceDir = resolve(__dirname, '..', 'out')
const targetDir = resolve(__dirname, '..', '..', 'backend', 'cmd', 'walletharness', 'static')

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

console.log(`Synced wallet static files: ${sourceDir} -> ${targetDir}`)
