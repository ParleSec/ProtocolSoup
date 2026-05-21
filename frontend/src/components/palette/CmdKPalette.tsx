'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { usePathname } from 'next/navigation'

import { Palette } from './Palette'

/**
 * CmdKPalette mounts the shared Palette as a global keyboard-driven overlay.
 *
 * Bindings:
 * - Cmd/Ctrl+K toggles the overlay.
 * - "/" opens the overlay when focus is outside an editable element.
 * - Esc closes it (handled inside Palette for the cmdk variant).
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
    if (isHomepage) return

    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null
      const isEditable =
        !!target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)

      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        triggerRef.current = (document.activeElement as HTMLElement) ?? null
        setOpen((v) => !v)
        return
      }

      if (event.key === '/' && !isEditable && !open) {
        event.preventDefault()
        triggerRef.current = (document.activeElement as HTMLElement) ?? null
        setOpen(true)
      }
    }

    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
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
      <div className="relative z-10 w-full max-w-2xl rounded-xl border border-white/10 bg-surface-900/95 shadow-2xl p-3 sm:p-4 max-h-[78vh] overflow-y-auto">
        <Palette variant="cmdk" autoFocus onClose={close} />
      </div>
    </div>
  )
}
