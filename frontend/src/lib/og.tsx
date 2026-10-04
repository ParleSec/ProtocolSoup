import type { ReactNode } from 'react'
import { WORDMARK_DARK, WordmarkArt } from '@/components/common/Brand'

/** Shared frame for the next/og social cards so every share preview carries the same lockup. */

export const OG_SIZE = { width: 1200, height: 630 }
export const OG_CONTENT_TYPE = 'image/png'
export const OG_FONT = 'JetBrains Mono'

// Satori needs static TTF/OTF/WOFF data; the variable woff2 the app uses is not supported.
// The URLs must be literal so the bundler ships only these two files.
async function fontData(url: URL) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`OG font fetch failed: ${res.status} ${url}`)
  return res.arrayBuffer()
}

export async function ogFonts() {
  const [regular, bold] = await Promise.all([
    fontData(new URL('../../node_modules/@fontsource/jetbrains-mono/files/jetbrains-mono-latin-400-normal.woff', import.meta.url)),
    fontData(new URL('../../node_modules/@fontsource/jetbrains-mono/files/jetbrains-mono-latin-700-normal.woff', import.meta.url)),
  ])
  return [
    { name: OG_FONT, data: regular, weight: 400 as const, style: 'normal' as const },
    { name: OG_FONT, data: bold, weight: 700 as const, style: 'normal' as const },
  ]
}

export function OgCard({
  kicker,
  title,
  description,
  footer,
  host,
}: {
  kicker?: string
  title: ReactNode
  description: string
  footer: string
  host: string
}) {
  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        padding: '56px 64px',
        background:
          'radial-gradient(circle at 90% 10%, rgba(168,85,247,0.30), transparent 42%), radial-gradient(circle at 10% 90%, rgba(6,182,212,0.24), transparent 40%), linear-gradient(135deg, #05070f 0%, #0b0e18 100%)',
        color: '#e4e4e7',
        fontFamily: OG_FONT,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <WordmarkArt id="og" colors={WORDMARK_DARK} height={44} />
        {kicker ? <span style={{ fontSize: 24, color: '#a1a1aa', letterSpacing: '0.02em' }}>{kicker}</span> : null}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        <div style={{ fontSize: 54, lineHeight: 1.08, fontWeight: 700, letterSpacing: '-0.025em', maxWidth: 1040 }}>
          {title}
        </div>
        <div style={{ fontSize: 24, lineHeight: 1.4, color: '#a1a1aa', maxWidth: 1040 }}>{description}</div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 20, color: '#71717a' }}>
        <span style={{ color: '#06b6d4' }}>{host}</span>
        <span>{footer}</span>
      </div>
    </div>
  )
}
