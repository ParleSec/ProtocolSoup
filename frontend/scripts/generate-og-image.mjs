import fs from 'node:fs/promises'
import path from 'node:path'
import sharp from 'sharp'

const WIDTH = 1200
const HEIGHT = 627

function escapeXml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}

async function main() {
  const outPath = path.join(process.cwd(), 'public', 'og-image.png')

  const title = 'Protocol Soup'
  const subtitle = 'An Interactive Protocol Sandbox'
  const tagline = 'Real flows against real infrastructure'
  const chips = ['OAuth 2.0', 'OIDC', 'SAML', 'SPIFFE/SPIRE', 'SCIM 2.0', 'SSF (Shared Signals)']

  // Embed fonts to make rendering deterministic across machines/CI (avoid system font differences).
  const fontDir = path.join(process.cwd(), 'node_modules', '@fontsource', 'space-grotesk', 'files')
  const woff2_500 = await fs.readFile(path.join(fontDir, 'space-grotesk-latin-500-normal.woff2'))
  const woff2_600 = await fs.readFile(path.join(fontDir, 'space-grotesk-latin-600-normal.woff2'))
  const woff2_700 = await fs.readFile(path.join(fontDir, 'space-grotesk-latin-700-normal.woff2'))
  const font500DataUrl = `data:font/woff2;base64,${woff2_500.toString('base64')}`
  const font600DataUrl = `data:font/woff2;base64,${woff2_600.toString('base64')}`
  const font700DataUrl = `data:font/woff2;base64,${woff2_700.toString('base64')}`

  const faviconSvg = await fs.readFile(path.join(process.cwd(), 'public', 'favicon.svg'), 'utf8')
  const faviconDataUrl = `data:image/svg+xml;base64,${Buffer.from(faviconSvg).toString('base64')}`

  // Simple chip layout with wrapping + centering per-row
  // Chip styling tuned for crisp rendering (Sharp/libvips baseline quirks)
  const CHIP_H = 40
  const CHIP_GAP = 10
  const CHIP_SIDE_PAD = 16
  const CHIP_DOT_R = 5
  const CHIP_DOT_X = CHIP_SIDE_PAD
  const CHIP_TEXT_X = CHIP_DOT_X + CHIP_DOT_R + 10
  const CHIP_TEXT_SIZE = 17
  const CHAR_W = 8.6 // tuned approximation for system-ui at ~17px
  // Text y in SVG is BASELINE; compute a stable baseline so it visually centers with the dot.
  const CHIP_TEXT_BASELINE_Y = Math.round(CHIP_H / 2 + CHIP_TEXT_SIZE * 0.36)
  const chipWidth = (label) =>
    // dot + gap + text + right padding
    Math.ceil(CHIP_TEXT_X + label.length * CHAR_W + CHIP_SIDE_PAD)

  // Align chips with the text block (under the title), not the icon.
  const TEXT_LEFT = 244
  const RIGHT_PAD = 72 // match card padding visually
  const CONTENT_W = WIDTH - TEXT_LEFT - RIGHT_PAD
  const rows = []
  let current = []
  let currentW = 0
  for (const label of chips) {
    const w = chipWidth(label)
    const nextW = current.length === 0 ? w : currentW + CHIP_GAP + w
    if (nextW > CONTENT_W && current.length > 0) {
      rows.push(current)
      current = [label]
      currentW = w
    } else {
      current.push(label)
      currentW = nextW
    }
  }
  if (current.length) rows.push(current)

  const chipsSvg = rows
    .slice(0, 2) // wrap if needed, but with tighter sizing this should stay 1 row
    .map((row, rowIdx) => {
      const widths = row.map(chipWidth)
      const rowW = widths.reduce((acc, w) => acc + w, 0) + CHIP_GAP * (row.length - 1)
      // Left-align under the text block. If wrapping occurs, keep each row left-aligned.
      let x = 0
      const y = rowIdx * (CHIP_H + 12)
      return row
        .map((label, i) => {
          const w = widths[i]
          // Keep coordinates integer-aligned for crisper strokes
          const xi = Math.round(x)
          const yi = Math.round(y)
          const g = `
            <g transform="translate(${xi} ${yi})">
              <rect x="0" y="0" width="${w}" height="${CHIP_H}" rx="${Math.floor(CHIP_H / 2)}" fill="#111827" stroke="#334155" stroke-width="2"/>
              <circle cx="${CHIP_DOT_X}" cy="${CHIP_H / 2}" r="${CHIP_DOT_R}" fill="url(#accent)"/>
              <text x="${CHIP_TEXT_X}" y="${CHIP_TEXT_BASELINE_Y}" fill="#e2e8f0" font-size="${CHIP_TEXT_SIZE}" font-weight="600" font-family="PSpaceGrotesk, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif">${escapeXml(label)}</text>
            </g>
          `
          x += w + CHIP_GAP
          return g
        })
        .join('')
    })
    .join('')

  // SVG → PNG keeps the generator lightweight and deterministic.
  // (We avoid downloading fonts; render uses system defaults inside sharp/libvips.)
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" viewBox="0 0 ${WIDTH} ${HEIGHT}" shape-rendering="geometricPrecision" text-rendering="geometricPrecision">
  <defs>
    <style><![CDATA[
      @font-face {
        font-family: "PSpaceGrotesk";
        src: url("${font500DataUrl}") format("woff2");
        font-weight: 500;
        font-style: normal;
      }
      @font-face {
        font-family: "PSpaceGrotesk";
        src: url("${font600DataUrl}") format("woff2");
        font-weight: 600;
        font-style: normal;
      }
      @font-face {
        font-family: "PSpaceGrotesk";
        src: url("${font700DataUrl}") format("woff2");
        font-weight: 700;
        font-style: normal;
      }
    ]]></style>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#020617"/>
      <stop offset="55%" stop-color="#0b1228"/>
      <stop offset="100%" stop-color="#1f2937"/>
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#f97316"/>
      <stop offset="100%" stop-color="#f59e0b"/>
    </linearGradient>
    <filter id="softShadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#000000" flood-opacity="0.45" />
    </filter>
  </defs>

  <!-- background -->
  <rect width="${WIDTH}" height="${HEIGHT}" fill="url(#bg)"/>

  <!-- subtle grid -->
  <g opacity="0.10">
    ${Array.from({ length: 17 }, (_, i) => `<line x1="${i * 80}" y1="0" x2="${i * 80}" y2="${HEIGHT}" stroke="#94a3b8" stroke-width="1"/>`).join('')}
    ${Array.from({ length: 10 }, (_, i) => `<line x1="0" y1="${i * 70}" x2="${WIDTH}" y2="${i * 70}" stroke="#94a3b8" stroke-width="1"/>`).join('')}
  </g>

  <!-- card -->
  <g filter="url(#softShadow)">
    <rect x="72" y="88" width="${WIDTH - 144}" height="${HEIGHT - 176}" rx="28" fill="#0b1220" opacity="0.92" stroke="#1f2937" stroke-width="2"/>
    <rect x="72" y="88" width="${WIDTH - 144}" height="10" rx="28" fill="url(#accent)"/>
  </g>

  <!-- icon -->
  <g transform="translate(132 170)">
    <rect x="0" y="0" width="84" height="84" rx="20" fill="#0f172a" stroke="#334155" stroke-width="2"/>
    <image href="${faviconDataUrl}" x="8" y="8" width="68" height="68" />
  </g>

  <!-- title -->
  <text x="244" y="222" fill="#ffffff" font-size="68" font-weight="700" font-family="PSpaceGrotesk, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif">
    ${escapeXml(title)}
  </text>
  <text x="244" y="274" fill="#cbd5e1" font-size="30" font-weight="600" font-family="PSpaceGrotesk, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif">
    ${escapeXml(tagline)}
  </text>
  <text x="244" y="314" fill="#94a3b8" font-size="24" font-weight="500" font-family="PSpaceGrotesk, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif">
    ${escapeXml(subtitle)}
  </text>

  <!-- chips -->
  <g transform="translate(${TEXT_LEFT} 360)">
    ${chipsSvg}
  </g>

  <!-- footer -->
  <text x="244" y="${HEIGHT - 150}" fill="#94a3b8" font-size="22" font-weight="500" font-family="PSpaceGrotesk, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif">
    Inspect requests • Decode tokens • Learn protocol security
  </text>
  <text x="244" y="${HEIGHT - 112}" fill="#64748b" font-size="20" font-weight="500" font-family="PSpaceGrotesk, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif">
    protocolsoup.com
  </text>
</svg>`

  await fs.mkdir(path.dirname(outPath), { recursive: true })

  await sharp(Buffer.from(svg))
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toFile(outPath)

  console.log(`✅ Generated OG image: ${outPath}`)
}

main().catch((err) => {
  console.error('Failed to generate og-image.png:', err)
  process.exitCode = 1
})

