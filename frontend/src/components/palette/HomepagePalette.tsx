'use client'

import { Palette } from './Palette'

/**
 * HomepagePalette wraps the shared Palette component for the homepage mount
 * point. Renders below the tagline as the single prominent retrieval surface
 * for protocolsoup.com — no separate hero search, no separate "browse" link.
 */
export function HomepagePalette() {
  return (
    <section className="rounded-xl border border-white/10 bg-surface-900/30 p-3.5 sm:p-5">
      <Palette variant="homepage" autoFocus={false} />
    </section>
  )
}
