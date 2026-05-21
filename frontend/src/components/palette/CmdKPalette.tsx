'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { usePathname } from 'next/navigation'

import { Palette } from './Palette'

/**
 * CmdKPalette mounts the shared Palette as a global keyboard-driven overlay.
 *
 * Bindings:
 * - Cmd/Ctrl+K toggles the overlay on non-home pages; on `/` it focuses the
 *   homepage palette input via `palette:focus-home`.
 * - "/" opens the overlay when focus is outside an editable element.
 * - Esc closes it (handled inside Palette for the cmdk variant).
 * - `window.dispatchEvent(new CustomEvent('palette:open'))` from any other
 *   component (e.g. the site header Search chip) opens the overlay; the
 *   header stays decoupled from the modal implementation.
 *
 * The overlay is suppressed on the homepage because the homepage already
 * carries a prominent input. Suppressing avoids two visible palette inputs
 * fighting for the same focus.
 */
export function CmdKPalette() {
  const pathname = usePathname()
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLElement | null>(null)

  const isHomepage = pathname === '/' || pathname === ''

  const close = useCallback(() => {
    setOpen(false)
    triggerRef.current?.focus()
    triggerRef.current = null
  }, [])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null
      const isEditable =
        !!target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        if (isHomepage) {
          window.dispatchEvent(new CustomEvent('palette:focus-home'))
          return
        }
        triggerRef.current = (document.activeElement as HTMLElement) ?? null
        setOpen((v) => !v)
        return
      }

      if (isHomepage) return

      if (event.key === '/' && !isEditable && !open) {
        event.preventDefault()
        triggerRef.current = (document.activeElement as HTMLElement) ?? null
        setOpen(true)
      }
    }

    function onPaletteOpen() {
      if (isHomepage) return
      triggerRef.current = (document.activeElement as HTMLElement) ?? null
      setOpen(true)
    }

    window.addEventListener('keydown', onKey)
    window.addEventListener('palette:open', onPaletteOpen)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('palette:open', onPaletteOpen)
    }
  }, [isHomepage, open])

  // Close the overlay automatically when the route changes.
  useEffect(() => {
    if (!open) return
    setOpen(false)
    triggerRef.current = null
  }, [pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!open) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = previous
    }
  }, [open])

  if (isHomepage || !open) {
    return null
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Search palette"
      className="fixed inset-0 z-[200] flex items-start justify-center pt-[12vh] px-3 sm:px-4"
    >
      <button
        type="button"
        aria-label="Close palette"
        onClick={close}
        className="absolute inset-0 bg-surface-950/80 backdrop-blur-sm"
      />
      <div className="relative z-10 flex w-full max-w-2xl flex-col rounded-xl border border-white/10 bg-surface-900/95 shadow-2xl max-h-[78vh] overflow-hidden">
        <div className="flex min-h-0 flex-1 flex-col p-3 sm:p-4">
          <Palette variant="cmdk" autoFocus onClose={close} />
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-white/5 bg-surface-900/95 px-3 py-2 text-[10px] text-surface-500 sm:px-4">
          <ShortcutHint keys={['\u2191', '\u2193']} label="navigate" />
          <ShortcutHint keys={['Enter']} label="open" />
          <ShortcutHint keys={['Tab']} label="narrow" />
          <ShortcutHint keys={['Esc']} label="close" />
        </div>
      </div>
    </div>
  )
}

function ShortcutHint({ keys, label }: { keys: string[]; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      {keys.map((k, i) => (
        <kbd
          key={`${k}-${i}`}
          className="inline-flex h-[18px] min-w-[18px] items-center justify-center rounded border border-white/10 bg-surface-800/60 px-1 font-mono text-[10px] text-surface-300"
        >
          {k}
        </kbd>
      ))}
      <span className="text-surface-500">{label}</span>
    </span>
  )
}
