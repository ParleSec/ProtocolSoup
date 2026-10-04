import { useId } from 'react'
import { WORDMARK } from './wordmark.generated'

function useSvgId(prefix: string) {
  return `${prefix}${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
}

/** Brand mark from public/favicon.svg without the tile background. */
export function SoupMark({ className }: { className?: string }) {
  const id = useSvgId('soupmark')
  const soup = `${id}-soup`
  const bowl = `${id}-bowl`
  return (
    <svg viewBox="10 6 80 80" className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={soup} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="var(--ps-hue-orange)" />
          <stop offset="50%" stopColor="var(--ps-hue-purple)" />
          <stop offset="100%" stopColor="var(--ps-hue-cyan)" />
        </linearGradient>
        <linearGradient id={bowl} x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" stopColor="var(--ps-slate-500)" />
          <stop offset="100%" stopColor="var(--ps-slate-700)" />
        </linearGradient>
      </defs>
      <path d="M35 28 Q32 22, 35 16" stroke="var(--ps-hue-orange)" strokeWidth="2.5" fill="none" strokeLinecap="round" opacity="0.8" />
      <path d="M50 24 Q47 17, 50 10" stroke="var(--ps-hue-purple)" strokeWidth="2.5" fill="none" strokeLinecap="round" opacity="0.8" />
      <path d="M65 28 Q68 22, 65 16" stroke="var(--ps-hue-cyan)" strokeWidth="2.5" fill="none" strokeLinecap="round" opacity="0.8" />
      <ellipse cx="50" cy="42" rx="32" ry="8" fill={`url(#${bowl})`} />
      <ellipse cx="50" cy="42" rx="28" ry="6" fill={`url(#${soup})`} opacity="0.9" />
      <path d="M18 42 Q18 75, 50 78 Q82 75, 82 42" fill={`url(#${bowl})`} />
      <circle cx="35" cy="50" r="5" fill="var(--ps-hue-orange)" opacity="0.9" />
      <circle cx="50" cy="55" r="6" fill="var(--ps-hue-purple)" opacity="0.9" />
      <circle cx="65" cy="48" r="4" fill="var(--ps-hue-cyan)" opacity="0.9" />
      <circle cx="42" cy="60" r="3" fill="#22c55e" opacity="0.8" />
      <circle cx="58" cy="62" r="3.5" fill="#eab308" opacity="0.8" />
      <ellipse cx="50" cy="82" rx="14" ry="4" fill="var(--ps-slate-600)" />
    </svg>
  )
}

export interface WordmarkColors {
  fg: string
  accent: string
  cursor: string
  steam: readonly [string, string, string]
}

/** Theme-following colours for in-app use; resolve through the GEL tokens. */
const THEME_COLORS: WordmarkColors = {
  fg: 'currentColor',
  accent: 'var(--ps-brand)',
  cursor: 'var(--ps-interactive)',
  steam: ['var(--ps-hue-orange)', 'var(--ps-hue-purple)', 'var(--ps-hue-cyan)'],
}

/** Fixed colours for rasterised surfaces (OG cards) where CSS variables do not resolve. */
export const WORDMARK_DARK: WordmarkColors = {
  fg: '#e4e4e7',
  accent: '#a855f7',
  cursor: '#06b6d4',
  steam: ['#f97316', '#a855f7', '#06b6d4'],
}

/**
 * The wordmark artwork with blinking cursor
 */
export function WordmarkArt({
  id,
  colors = THEME_COLORS,
  height,
  className,
  live = false,
}: {
  id: string
  colors?: WordmarkColors
  height?: number
  className?: string
  live?: boolean
}) {
  const g = WORDMARK
  const soup = `${id}-soup`
  const dims = height ? { width: (height * (live ? g.liveWidth : g.width)) / g.height, height } : {}
  return (
    <svg viewBox={live ? g.liveViewBox : g.viewBox} {...dims} className={className} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={soup} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor={colors.steam[0]} />
          <stop offset="0.5" stopColor={colors.steam[1]} />
          <stop offset="1" stopColor={colors.steam[2]} />
        </linearGradient>
      </defs>
      <path fill={colors.fg} d={g.textPath} />
      <path fill={colors.accent} d={g.accentPath} />
      <g transform={`translate(${g.bowlX} ${g.bowlY})`}>
        {g.bowl.steam.map((d, i) => (
          <path key={d} d={d} stroke={colors.steam[i]} strokeWidth="5" fill="none" strokeLinecap="round" />
        ))}
        <path d={g.bowl.body} fill={colors.accent} />
        <ellipse cx={g.bowl.rim.cx} cy={g.bowl.rim.cy} rx={g.bowl.rim.rx} ry={g.bowl.rim.ry} fill={`url(#${soup})`} />
      </g>
      {live ? (
        <rect x={g.cursor.x} y={g.cursor.y} width={g.cursor.w} height={g.cursor.h} fill={colors.cursor} className="animate-caret" />
      ) : null}
    </svg>
  )
}

/**
 * ProtocolSoup wordmark for the app
 */
export function Wordmark({ className = '', live = false }: { className?: string; live?: boolean }) {
  const id = useSvgId('wordmark')
  return (
    <span className={`relative inline-flex items-center whitespace-nowrap text-fg ${className}`}>
      <WordmarkArt id={id} live={live} className="h-[1.08em] w-auto select-none" />
      <span className="absolute left-0 top-[-0.04em] font-mono font-bold leading-none tracking-tight text-transparent selection:bg-interactive/30 selection:text-transparent">
        ProtocolSoup
      </span>
    </span>
  )
}
