'use client'

import { Suspense } from 'react'

import { Palette } from '@/components/palette/Palette'

const shellClass =
  'p-0 sm:rounded-xl sm:border sm:border-white/10 sm:bg-surface-900/30 sm:p-5'

function HomepagePaletteInner() {
  return (
    <section className={shellClass}>
      <Palette variant="homepage" autoFocus={false} />
    </section>
  )
}

/**
 * HomepagePalette wraps the shared Palette component for the homepage mount
 * point.
 *
 * On mobile the outer card chrome is omitted so the input reads as part of
 * the hero, not a second boxed panel stacked under the tagline.
 *
 * Suspense is required because Palette reads `useSearchParams()` for URL
 * persistence on the homepage.
 */
export function HomepagePalette() {
  return (
    <Suspense
      fallback={
        <section className={shellClass}>
          <div
            className="h-11 animate-pulse rounded-lg border border-white/10 bg-surface-900/60 sm:h-14"
            aria-hidden="true"
          />
        </section>
      }
    >
      <HomepagePaletteInner />
    </Suspense>
  )
}
