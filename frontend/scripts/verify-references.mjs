#!/usr/bin/env node
// Verifies the {label, href} reference pairs we ship in protocol-catalog-data.ts
// and src/protocols/explainers/*.ts against the live spec documents. For each
// href: confirms the URL returns 200, then (when an anchor is present) fetches
// the page, locates the anchor, and fuzzy-matches the section number and title
// from our label against the heading text we find next to the anchor.
//
// Usage: npm run verify-refs
//        npm run verify-refs -- --only=oid4vp     filter by file basename
//        npm run verify-refs -- --strict          exit non-zero on warnings too

import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(HERE, '..')
const FILES_TO_SCAN = [
  path.join(ROOT, 'src/protocols/presentation/protocol-catalog-data.ts'),
]

const args = process.argv.slice(2)
const onlyArg = args.find((a) => a.startsWith('--only='))
const onlyFilter = onlyArg ? onlyArg.split('=')[1] : null
const strict = args.includes('--strict')

const REFERENCE_REGEX =
  /\{\s*category:\s*'(?<category>[^']+)'\s*,\s*label:\s*'(?<label>(?:[^'\\]|\\.)*)'\s*,\s*href:\s*'(?<href>[^']+)'(?:\s*,\s*note:\s*'(?:[^'\\]|\\.)*')?\s*,?\s*\}/g

const SIMPLE_REF_REGEX =
  /label:\s*'(?<label>(?:[^'\\]|\\.)*)'\s*,\s*href:\s*'(?<href>[^']+)'/g

const MAX_PARALLEL = 6
const FETCH_TIMEOUT_MS = 15_000
const USER_AGENT =
  'ProtocolSoup-ref-verifier/1.0 (+https://github.com/ParleSec/ProtocolSoup)'

const STOP_WORDS = new Set([
  'the', 'a', 'an', 'and', 'or', 'of', 'for', 'to', 'in', 'on', 'at', 'by',
  'with', 'from', 'as', 'is', 'are', 'be', 'via', 'using',
])

async function main() {
  const explainerDir = path.join(ROOT, 'src/protocols/explainers')
  for (const entry of await readdir(explainerDir)) {
    if (entry.endsWith('.ts') && entry !== 'index.ts') {
      FILES_TO_SCAN.push(path.join(explainerDir, entry))
    }
  }

  const refs = []
  const seenPairs = new Set()
  for (const file of FILES_TO_SCAN) {
    const basename = path.basename(file, '.ts')
    if (onlyFilter && !basename.includes(onlyFilter)) continue
    for (const ref of await extractRefs(file)) {
      const key = `${ref.file}${ref.label}${ref.href}`
      if (seenPairs.has(key)) continue
      seenPairs.add(key)
      refs.push(ref)
    }
  }

  console.log(`Scanning ${refs.length} reference entries from ${FILES_TO_SCAN.length} files\n`)

  const cache = new Map()
  const issues = []

  let inFlight = 0
  let nextIndex = 0
  await new Promise((resolve) => {
    const launchNext = () => {
      while (inFlight < MAX_PARALLEL && nextIndex < refs.length) {
        const ref = refs[nextIndex++]
        inFlight++
        verifyRef(ref, cache)
          .then((problems) => {
            for (const p of problems) issues.push(p)
          })
          .catch((err) => {
            issues.push({
              level: 'error',
              ref,
              message: `unhandled error: ${err.message}`,
            })
          })
          .finally(() => {
            inFlight--
            if (nextIndex >= refs.length && inFlight === 0) resolve()
            else launchNext()
          })
      }
    }
    launchNext()
  })

  reportIssues(issues)

  const errorCount = issues.filter((i) => i.level === 'error').length
  const warnCount = issues.filter((i) => i.level === 'warn').length
  console.log(`\n${refs.length} refs checked. ${errorCount} error(s), ${warnCount} warning(s).`)
  if (errorCount > 0 || (strict && warnCount > 0)) process.exit(1)
}

async function extractRefs(file) {
  const src = await readFile(file, 'utf8')
  const out = []
  const seenAtOffset = new Set()

  for (const match of src.matchAll(REFERENCE_REGEX)) {
    const { label, href } = match.groups
    out.push({ file, label: unquote(label), href, line: lineOf(src, match.index) })
    seenAtOffset.add(match.index)
  }

  for (const match of src.matchAll(SIMPLE_REF_REGEX)) {
    if (seenAtOffset.has(match.index)) continue
    const { label, href } = match.groups
    out.push({ file, label: unquote(label), href, line: lineOf(src, match.index) })
  }

  return out
}

function unquote(s) {
  return s.replace(/\\'/g, "'").replace(/\\\\/g, '\\')
}

function lineOf(src, index) {
  return src.slice(0, index).split('\n').length
}

async function verifyRef(ref, cache) {
  const problems = []
  const url = new URL(ref.href)
  const baseUrl = `${url.origin}${url.pathname}${url.search}`
  const anchor = url.hash ? url.hash.slice(1) : null

  let page = cache.get(baseUrl)
  if (!page) {
    page = await fetchOnce(baseUrl)
    cache.set(baseUrl, page)
  }

  if (!page.ok) {
    problems.push({
      level: 'error',
      ref,
      message: `URL returned HTTP ${page.status}`,
    })
    return problems
  }

  if (page.contentType.includes('pdf')) {
    // Can't introspect PDF anchors meaningfully; just confirm liveness.
    return problems
  }

  // For non-spec hosts (blog posts, advisory sites) we only confirm liveness;
  // those pages don't follow predictable section structures.
  if (!isSpecUrl(url)) return problems

  if (!anchor) return problems

  const anchorContext = locateAnchor(page.body, anchor)
  if (!anchorContext) {
    problems.push({
      level: 'error',
      ref,
      message: `anchor #${anchor} not found in page`,
    })
    return problems
  }

  const labelSection = extractSectionNumber(ref.label)
  const labelTitle = extractTitle(ref.label)

  if (labelSection) {
    const ok = anchorContext.sectionsNearby.some((s) =>
      sectionMatches(labelSection, s),
    )
    if (!ok) {
      problems.push({
        level: 'error',
        ref,
        message: `label says §${labelSection} but anchor sits near sections [${anchorContext.sectionsNearby.join(', ') || 'none'}]`,
      })
    }
  }

  if (labelTitle) {
    const titleScore = scoreTitleMatch(labelTitle, anchorContext.text)
    if (titleScore.matched.length === 0 && titleScore.totalKeywords > 0) {
      problems.push({
        level: 'warn',
        ref,
        message: `label title "${labelTitle}" does not overlap with heading "${anchorContext.headingText}"`,
      })
    } else if (
      titleScore.totalKeywords >= 3 &&
      titleScore.matched.length === 1
    ) {
      problems.push({
        level: 'warn',
        ref,
        message: `weak title overlap: label "${labelTitle}" vs heading "${anchorContext.headingText}" (matched only: ${titleScore.matched.join(', ')})`,
      })
    }
  }

  return problems
}

async function fetchOnce(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,application/pdf' },
      redirect: 'follow',
      signal: controller.signal,
    })
    const contentType = res.headers.get('content-type') || ''
    if (!res.ok) {
      return { ok: false, status: res.status, contentType, body: '' }
    }
    if (contentType.includes('pdf')) {
      return { ok: true, status: res.status, contentType, body: '' }
    }
    const body = await res.text()
    return { ok: true, status: res.status, contentType, body }
  } finally {
    clearTimeout(timer)
  }
}

function locateAnchor(html, anchor) {
  const escAnchor = anchor.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const idMatch = new RegExp(`(?:id|name)\\s*=\\s*"${escAnchor}"`, 'i').exec(html)
  if (!idMatch) return null

  const start = Math.max(0, idMatch.index - 200)
  const end = Math.min(html.length, idMatch.index + 1500)
  const window = html.slice(start, end)

  const headingText = extractHeadingText(window, idMatch.index - start)
  const text = stripTags(window)
  const sectionsNearby = collectSectionNumbers(window, text)

  return { headingText, text, sectionsNearby }
}

function extractHeadingText(window, anchorOffset) {
  const after = window.slice(anchorOffset)
  const before = window.slice(0, anchorOffset)
  const headingPatterns = [
    /<h[1-6][^>]*>([\s\S]*?)<\/h[1-6]>/i,
    /<span[^>]*class="h[1-6]"[^>]*>([\s\S]*?)<\/span>/i,
  ]
  for (const pattern of headingPatterns) {
    const m = pattern.exec(after) || pattern.exec(before)
    if (m) return collapseWhitespace(stripTags(m[1]))
  }
  // Fallback: jump past the current attribute/tag boundary so we don't pick
  // up stray attributes (id="...", href="...") in the heading text.
  const tagEnd = after.indexOf('>')
  const slice = tagEnd >= 0 ? after.slice(tagEnd + 1, tagEnd + 401) : after.slice(0, 200)
  return collapseWhitespace(stripTags(slice))
}

function collectSectionNumbers(window, plainText) {
  const out = new Set()
  const anchorMatches = window.matchAll(/(?:id|name|href)\s*=\s*"#?section-([\d.]+)"/gi)
  for (const m of anchorMatches) out.add(m[1])
  const textMatches = plainText.matchAll(/\b(\d+(?:\.\d+){0,3})\.?\s+[A-Z]/g)
  for (const m of textMatches) out.add(m[1])
  return [...out]
}

function stripTags(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
}

function collapseWhitespace(s) {
  return s.replace(/\s+/g, ' ').trim()
}

function extractSectionNumber(label) {
  const m = /§\s*([\d.]+)/.exec(label)
  return m ? m[1] : null
}

function sectionMatches(labelSection, foundSection) {
  if (labelSection === foundSection) return true
  // §4 should match nearby [4.1, 4.2, ...] (parent label, child anchor).
  if (foundSection.startsWith(labelSection + '.')) return true
  // §4.1.2 may legitimately resolve to anchor that lands at §4.1 (parent of
  // the more specific subsection we cite). Tolerate one level of imprecision.
  const labelParts = labelSection.split('.')
  const foundParts = foundSection.split('.')
  if (foundParts.length === labelParts.length - 1) {
    return labelParts.slice(0, foundParts.length).join('.') === foundSection
  }
  return false
}

function extractTitle(label) {
  // Prefer trailing parenthesised content: handles "RFC 8417 §2.2 (events claim — token-type discriminator)".
  const trailingParen = /\(([^()]+)\)\s*$/.exec(label)
  if (trailingParen) return trailingParen[1].trim()
  const dash = label.split(/—|–|--/)
  if (dash.length > 1) {
    return dash
      .slice(1)
      .join(' ')
      .trim()
      .replace(/\)$/, '')
  }
  return null
}

const SPEC_HOSTS = new Set([
  'datatracker.ietf.org',
  'openid.net',
  'spiffe.io',
  'docs.oasis-open.org',
  'www.w3.org',
])

function isSpecUrl(url) {
  return SPEC_HOSTS.has(url.host)
}

function scoreTitleMatch(title, haystack) {
  const keywords = title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length >= 3 && !STOP_WORDS.has(w))
  const lower = haystack.toLowerCase()
  const matched = keywords.filter((w) => lower.includes(w))
  return { totalKeywords: keywords.length, matched }
}

function reportIssues(issues) {
  if (issues.length === 0) {
    console.log('All references look consistent.')
    return
  }
  const byFile = new Map()
  for (const issue of issues) {
    const list = byFile.get(issue.ref.file) || []
    list.push(issue)
    byFile.set(issue.ref.file, list)
  }
  for (const [file, list] of byFile) {
    console.log(`\n${path.relative(ROOT, file)}`)
    for (const issue of list) {
      const tag = issue.level === 'error' ? 'ERROR' : 'WARN '
      console.log(`  [${tag}] line ${issue.ref.line}: ${issue.message}`)
      console.log(`           label: ${issue.ref.label}`)
      console.log(`           href:  ${issue.ref.href}`)
    }
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(2)
})
