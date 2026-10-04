#!/usr/bin/env node
// Builds the ProtocolSoup wordmark from JetBrains Mono Bold outlines.
//
// The wordmark is artwork, not typed text: every surface (app header, hero,
// docs, OG cards) renders the same vector paths, so it looks identical whether
// or not a web font has loaded, and the indexable name is always the plain
// string "ProtocolSoup" supplied next to it (alt text or visually hidden text).
//
//   cd ProtocolSoup/design && npm install && npm run build:brand
//
// Outputs (committed, then copied into apps by sync-tokens.mjs):
//   brand/wordmark.generated.ts   geometry for the React/Satori renderer
//   brand/wordmark-dark.svg       static bare wordmark for dark surfaces
//   brand/wordmark-light.svg      static bare wordmark for light surfaces

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import opentype from 'opentype.js'

const here = dirname(fileURLToPath(import.meta.url))
const fontPath = join(here, '..', 'node_modules', '@fontsource', 'jetbrains-mono', 'files', 'jetbrains-mono-latin-700-normal.woff')
const font = opentype.parse(readFileSync(fontPath).buffer)

// Units: 1 em = 100. Baseline at y = 0, ascenders negative (SVG y-down).
const EM = 100
const ADVANCE = (font.charToGlyph('P').advanceWidth / font.unitsPerEm) * EM
const TRACKING = -2.5 // --ps-tracking-heading (-0.025em)
const CELL = ADVANCE + TRACKING

// Bowl glyph, drawn in its own 60x78 box (one mono cell wide, baseline to cap).
const BOWL = {
  box: { w: 60, h: 78 },
  steam: ['M17 22 Q13 15 17 6', 'M30 20 Q26 12 30 2', 'M43 22 Q47 15 43 6'],
  body: 'M3 34 Q3 77 30 77 Q57 77 57 34 Z',
  rim: { cx: 30, cy: 34, rx: 27, ry: 6 },
}
const CURSOR = { gap: 6, w: 60, h: 11, y: -7 }
const TOP = -82
const BOTTOM = 26

function outline(text, startX) {
  let x = startX
  let d = ''
  for (const ch of text) {
    d += font.getPath(ch, x, 0, EM).toPathData(2)
    x += CELL
  }
  return { d, end: x }
}

const protocol = outline('Protocol', 0)
const s = outline('S', protocol.end)
const bowlX = s.end
const up = outline('up', bowlX + CELL)
const cursorX = up.end + CURSOR.gap
const width = Math.ceil(up.end)
const liveWidth = Math.ceil(cursorX + CURSOR.w)
const height = BOTTOM - TOP

// The bare wordmark is the default everywhere. The cursor is only drawn, blinking,
// in the homepage hero, so it gets its own wider viewBox.
const geometry = {
  viewBox: `0 ${TOP} ${width} ${height}`,
  liveViewBox: `0 ${TOP} ${liveWidth} ${height}`,
  width,
  liveWidth,
  height,
  top: TOP,
  // Baseline position as a fraction of total height, for aligning typed text next to the mark.
  baseline: (0 - TOP) / height,
  textPath: protocol.d,
  accentPath: s.d + up.d,
  bowlX: Number(bowlX.toFixed(2)),
  bowlY: -BOWL.box.h,
  bowl: BOWL,
  cursor: { x: Number(cursorX.toFixed(2)), y: CURSOR.y, w: CURSOR.w, h: CURSOR.h },
}

function staticSvg({ fg, accent, steam }) {
  const g = geometry
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${g.viewBox}" role="img" aria-label="ProtocolSoup">
  <title>ProtocolSoup</title>
  <defs><linearGradient id="soup" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="${steam[0]}"/><stop offset="0.5" stop-color="${steam[1]}"/><stop offset="1" stop-color="${steam[2]}"/></linearGradient></defs>
  <path fill="${fg}" d="${g.textPath}"/>
  <path fill="${accent}" d="${g.accentPath}"/>
  <g transform="translate(${g.bowlX} ${g.bowlY})">
    ${BOWL.steam.map((d, i) => `<path d="${d}" stroke="${steam[i]}" stroke-width="5" fill="none" stroke-linecap="round"/>`).join('\n    ')}
    <path d="${BOWL.body}" fill="${accent}"/>
    <ellipse cx="${BOWL.rim.cx}" cy="${BOWL.rim.cy}" rx="${BOWL.rim.rx}" ry="${BOWL.rim.ry}" fill="url(#soup)"/>
  </g>
</svg>
`
}

// Hex values mirror design/tokens.css: dark = ink-1 / hue-purple / hue-cyan,
// light = slate-950 / hue-purple-deep / hue-cyan-deep (steam uses the deep trio).
const DARK = { fg: '#e4e4e7', accent: '#a855f7', steam: ['#f97316', '#a855f7', '#06b6d4'] }
const LIGHT = { fg: '#020617', accent: '#7c3aed', steam: ['#ea580c', '#7c3aed', '#0e7490'] }

const ts = `// Geometry for the ProtocolSoup wordmark. 1 em = 100 units, baseline at y = 0.
// Rendered by Wordmark in Brand.tsx; the static SVGs next to this file are the
// bare wordmark (no cursor) with fixed colours.
export const WORDMARK = ${JSON.stringify(geometry, null, 2)} as const
`

writeFileSync(join(here, 'wordmark.generated.ts'), ts)
writeFileSync(join(here, 'wordmark-dark.svg'), staticSvg(DARK))
writeFileSync(join(here, 'wordmark-light.svg'), staticSvg(LIGHT))
console.log(`wordmark ${width}x${height} (cell ${CELL.toFixed(2)}, bowl at ${geometry.bowlX}, cursor at ${geometry.cursor.x})`)
