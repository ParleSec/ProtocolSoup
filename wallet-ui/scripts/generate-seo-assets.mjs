import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import sharp from 'sharp'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const rootDir = path.resolve(__dirname, '..')
const publicDir = path.join(rootDir, 'public')
const OG_WIDTH = 1200
const OG_HEIGHT = 630

function escapeXml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}

function encodeIco(images) {
  const count = images.length
  const headerSize = 6 + 16 * count
  let offset = headerSize
  const placed = images.map((image) => {
    const entry = { ...image, offset }
    offset += image.buffer.length
    return entry
  })
  const out = Buffer.alloc(offset)
  out.writeUInt16LE(0, 0)
  out.writeUInt16LE(1, 2)
  out.writeUInt16LE(count, 4)
  let entryAt = 6
  for (const image of placed) {
    out.writeUInt8(image.width >= 256 ? 0 : image.width, entryAt)
    out.writeUInt8(image.height >= 256 ? 0 : image.height, entryAt + 1)
    out.writeUInt8(0, entryAt + 2)
    out.writeUInt8(0, entryAt + 3)
    out.writeUInt16LE(1, entryAt + 4)
    out.writeUInt16LE(32, entryAt + 6)
    out.writeUInt32LE(image.buffer.length, entryAt + 8)
    out.writeUInt32LE(image.offset, entryAt + 12)
    image.buffer.copy(out, image.offset)
    entryAt += 16
  }
  return out
}

function cardSvg({
  title,
  tagline,
  subtitle,
  footer,
  host,
  chips,
  faviconDataUrl,
  fontFaces,
  accentStops,
}) {
  const CHIP_H = 40
  const CHIP_GAP = 10
  const CHIP_SIDE_PAD = 16
  const CHIP_DOT_R = 5
  const CHIP_DOT_X = CHIP_SIDE_PAD
  const CHIP_TEXT_X = CHIP_DOT_X + CHIP_DOT_R + 10
  const CHIP_TEXT_SIZE = 17
  const CHAR_W = 8.6
  const CHIP_TEXT_BASELINE_Y = Math.round(CHIP_H / 2 + CHIP_TEXT_SIZE * 0.36)
  const chipWidth = (label) => Math.ceil(CHIP_TEXT_X + label.length * CHAR_W + CHIP_SIDE_PAD)
  const TEXT_LEFT = 244
  const CONTENT_W = OG_WIDTH - TEXT_LEFT - 72
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
    .slice(0, 2)
    .map((row, rowIdx) => {
      const widths = row.map(chipWidth)
      let x = 0
      const y = rowIdx * (CHIP_H + 12)
      return row
        .map((label, i) => {
          const w = widths[i]
          const g = `
            <g transform="translate(${Math.round(x)} ${Math.round(y)})">
              <rect x="0" y="0" width="${w}" height="${CHIP_H}" rx="${Math.floor(CHIP_H / 2)}" fill="#111827" stroke="#334155" stroke-width="2"/>
              <circle cx="${CHIP_DOT_X}" cy="${CHIP_H / 2}" r="${CHIP_DOT_R}" fill="url(#accent)"/>
              <text x="${CHIP_TEXT_X}" y="${CHIP_TEXT_BASELINE_Y}" fill="#e2e8f0" font-size="${CHIP_TEXT_SIZE}" font-weight="600" font-family="PSpaceGrotesk, system-ui, sans-serif">${escapeXml(label)}</text>
            </g>
          `
          x += w + CHIP_GAP
          return g
        })
        .join('')
    })
    .join('')

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${OG_WIDTH}" height="${OG_HEIGHT}" viewBox="0 0 ${OG_WIDTH} ${OG_HEIGHT}">
  <defs>
    <style><![CDATA[
      ${fontFaces}
    ]]></style>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#020617"/>
      <stop offset="55%" stop-color="#0b1228"/>
      <stop offset="100%" stop-color="#1f2937"/>
    </linearGradient>
    <linearGradient id="accent" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="${accentStops[0]}"/>
      <stop offset="50%" stop-color="${accentStops[1]}"/>
      <stop offset="100%" stop-color="${accentStops[2]}"/>
    </linearGradient>
    <filter id="softShadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="10" stdDeviation="18" flood-color="#000000" flood-opacity="0.45"/>
    </filter>
  </defs>
  <rect width="${OG_WIDTH}" height="${OG_HEIGHT}" fill="url(#bg)"/>
  <g opacity="0.10">
    ${Array.from({ length: 17 }, (_, i) => `<line x1="${i * 80}" y1="0" x2="${i * 80}" y2="${OG_HEIGHT}" stroke="#94a3b8" stroke-width="1"/>`).join('')}
    ${Array.from({ length: 10 }, (_, i) => `<line x1="0" y1="${i * 70}" x2="${OG_WIDTH}" y2="${i * 70}" stroke="#94a3b8" stroke-width="1"/>`).join('')}
  </g>
  <g filter="url(#softShadow)">
    <rect x="72" y="88" width="${OG_WIDTH - 144}" height="${OG_HEIGHT - 176}" rx="28" fill="#0b1220" opacity="0.92" stroke="#1f2937" stroke-width="2"/>
    <rect x="72" y="88" width="${OG_WIDTH - 144}" height="10" rx="28" fill="url(#accent)"/>
  </g>
  <g transform="translate(132 170)">
    <rect x="0" y="0" width="84" height="84" rx="20" fill="#0f172a" stroke="#334155" stroke-width="2"/>
    <image href="${faviconDataUrl}" x="8" y="8" width="68" height="68"/>
  </g>
  <text x="244" y="222" fill="#ffffff" font-size="64" font-weight="700" font-family="PSpaceGrotesk, system-ui, sans-serif">${escapeXml(title)}</text>
  <text x="244" y="274" fill="#cbd5e1" font-size="28" font-weight="600" font-family="PSpaceGrotesk, system-ui, sans-serif">${escapeXml(tagline)}</text>
  <text x="244" y="314" fill="#94a3b8" font-size="22" font-weight="500" font-family="PSpaceGrotesk, system-ui, sans-serif">${escapeXml(subtitle)}</text>
  <g transform="translate(${TEXT_LEFT} 360)">${chipsSvg}</g>
  <text x="244" y="${OG_HEIGHT - 150}" fill="#94a3b8" font-size="22" font-weight="500" font-family="PSpaceGrotesk, system-ui, sans-serif">${escapeXml(footer)}</text>
  <text x="244" y="${OG_HEIGHT - 112}" fill="#64748b" font-size="20" font-weight="500" font-family="PSpaceGrotesk, system-ui, sans-serif">${escapeXml(host)}</text>
</svg>`
}

async function rasterizeSvg(svg, size) {
  return sharp(Buffer.from(svg), { density: 384 })
    .resize(size, size)
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toBuffer()
}

async function main() {
  const faviconSvg = await readFile(path.join(publicDir, 'favicon.svg'))
  const maskableSvg = await readFile(path.join(publicDir, 'icons', 'icon-maskable-512.svg'))
  const fontDir = path.join(rootDir, 'node_modules', '@fontsource', 'space-grotesk', 'files')
  const [font500, font600, font700] = await Promise.all([
    readFile(path.join(fontDir, 'space-grotesk-latin-500-normal.woff2')),
    readFile(path.join(fontDir, 'space-grotesk-latin-600-normal.woff2')),
    readFile(path.join(fontDir, 'space-grotesk-latin-700-normal.woff2')),
  ])
  const fontFaces = `
    @font-face {
      font-family: "PSpaceGrotesk";
      src: url("data:font/woff2;base64,${font500.toString('base64')}") format("woff2");
      font-weight: 500;
      font-style: normal;
    }
    @font-face {
      font-family: "PSpaceGrotesk";
      src: url("data:font/woff2;base64,${font600.toString('base64')}") format("woff2");
      font-weight: 600;
      font-style: normal;
    }
    @font-face {
      font-family: "PSpaceGrotesk";
      src: url("data:font/woff2;base64,${font700.toString('base64')}") format("woff2");
      font-weight: 700;
      font-style: normal;
    }
  `
  const faviconDataUrl = `data:image/svg+xml;base64,${faviconSvg.toString('base64')}`

  const icoImages = await Promise.all(
    [16, 32, 48].map(async (size) => ({
      width: size,
      height: size,
      buffer: await rasterizeSvg(faviconSvg, size),
    })),
  )
  await writeFile(path.join(publicDir, 'favicon.ico'), encodeIco(icoImages))

  await sharp(maskableSvg, { density: 384 })
    .resize(180, 180)
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toFile(path.join(publicDir, 'apple-touch-icon.png'))

  const sharedCopy = {
    title: 'ProtocolSoup Wallet',
    chips: ['OID4VCI', 'OID4VP', 'mdoc', 'SD-JWT VC', 'HAIP'],
    faviconDataUrl,
    fontFaces,
    host: 'wallet.protocolsoup.com',
  }

  await sharp(
    Buffer.from(
      cardSvg({
        ...sharedCopy,
        tagline: 'OID4VCI issuance and OID4VP presentation',
        subtitle: 'Real holder hops against live issuers and verifiers',
        footer: 'Issue • Present • Inspect live credential traffic',
        accentStops: ['#f97316', '#a855f7', '#06b6d4'],
      }),
    ),
  )
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toFile(path.join(publicDir, 'opengraph-image.png'))

  await sharp(
    Buffer.from(
      cardSvg({
        ...sharedCopy,
        tagline: 'Live OID4VCI and OID4VP holder',
        subtitle: 'mdoc and SD-JWT credentials, HAIP attestation, QR handoffs',
        footer: 'The holder origin — not Looking Glass',
        accentStops: ['#06b6d4', '#a855f7', '#f97316'],
      }),
    ),
  )
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toFile(path.join(publicDir, 'twitter-image.png'))

  console.log('Generated wallet SEO assets in public/')
}

await mkdir(publicDir, { recursive: true })
await main()
