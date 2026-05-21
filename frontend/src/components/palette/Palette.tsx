'use client'

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react'
import { useRouter } from 'next/navigation'
import { Search, Loader2, X } from 'lucide-react'

import { AXIS_LABEL, axisValueLabel } from './labels'
import { resolveFlowHandoff } from './runDispatch'
import { usePaletteQuery } from './usePaletteQuery'
import { PaletteResultRow } from './PaletteResultRow'
import type {
  PaletteFilter,
  PaletteRefinementChip,
  PaletteResult,
  PaletteScope,
} from './types'

const HOMEPAGE_PLACEHOLDERS = [
  'Show me an OAuth flow',
  'What does PKCE require',
  'Federating with another IdP',
  'Let users sign in to my app',
  'Mobile app needs to call our API',
  'Issuing verifiable credentials',
]

const CMDK_PLACEHOLDERS = [
  'Type a protocol, concept, or use case',
  'Search "PKCE"',
  'Try "step-up authentication"',
]

const ENTRY_CHIPS: { label: string; q: string }[] = [
  { label: "I'm building a mobile app", q: 'mobile app' },
  { label: 'Federating with another IdP', q: 'federation' },
  { label: 'Issuing verifiable credentials', q: 'credential issuance' },
  { label: 'Just exploring', q: '' },
]

interface PaletteProps {
  variant: 'homepage' | 'cmdk'
  onClose?: () => void
  autoFocus?: boolean
}

/**
 * Palette renders the shared multi-axis content retrieval surface used on
 * the homepage and inside the global cmd+K portal.
 *
 * The component is fully keyboard-operable:
 * - ArrowUp / ArrowDown navigate result rows.
 * - Enter opens the row (or dispatches a runnable flow into Looking Glass).
 * - Tab applies the first refinement chip as an additional filter.
 * - Esc closes the cmd+K variant (no-op for the homepage variant).
 */
export function Palette({ variant, onClose, autoFocus }: PaletteProps) {
  const router = useRouter()
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)
  const headingId = useId()
  const listboxId = useId()

  const [q, setQ] = useState('')
  const [scope, setScope] = useState<PaletteScope | undefined>(undefined)
  const [filters, setFilters] = useState<PaletteFilter[]>([])
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [placeholderIndex, setPlaceholderIndex] = useState(0)

  const placeholderPool = variant === 'homepage' ? HOMEPAGE_PLACEHOLDERS : CMDK_PLACEHOLDERS

  useEffect(() => {
    if (!autoFocus) return
    inputRef.current?.focus()
  }, [autoFocus])

  // Cycle the placeholder. Stops cycling as soon as the user types.
  useEffect(() => {
    if (q.length > 0) return
    const handle = window.setInterval(() => {
      setPlaceholderIndex((i) => (i + 1) % placeholderPool.length)
    }, 3200)
    return () => window.clearInterval(handle)
  }, [q.length, placeholderPool.length])

  const { data, loading, error } = usePaletteQuery({
    q,
    scope,
    filters,
    enabled: q.trim().length > 0 || filters.length > 0,
  })

  const results = useMemo(() => data?.results ?? [], [data])
  const refinement = useMemo(() => data?.refinement_chips ?? [], [data])
  const resolved = useMemo(() => data?.resolved_aliases ?? [], [data])

  useEffect(() => {
    setSelectedIndex(0)
  }, [q, scope, filters])

  const activeResult: PaletteResult | undefined = results[selectedIndex]

  const activate = useCallback(
    (result: PaletteResult) => {
      const handoff = resolveFlowHandoff(result)
      if (handoff) {
        router.push(handoff.lookingGlassPath)
        onClose?.()
        return
      }
      // Inline-only artefact types (concept, walkthrough, spec-assertion)
      // have no canonical page; the backend marks them by leaving `href`
      // empty (see palette.Artefact.DefaultHref). Activating them just
      // confirms inline expansion — never `router.push('')`, which would
      // silently send the user back to the homepage.
      if (!result.href) {
        return
      }
      router.push(result.href)
      onClose?.()
    },
    [router, onClose],
  )

  // Called when a user clicks a related-concept chip inside an expanded
  // result row. Re-queries the palette with the concept's ID so the chip
  // navigates *within the palette* instead of trying to open a
  // /concept/{id} page that does not exist.
  const goToConcept = useCallback((conceptId: string) => {
    setQ(conceptId)
    setFilters([])
    setSelectedIndex(0)
    inputRef.current?.focus()
  }, [])

  const applyRefinement = useCallback((chip: PaletteRefinementChip) => {
    setFilters((prev) => {
      if (prev.some((f) => f.axis === chip.axis && f.value === chip.value)) {
        return prev
      }
      return [...prev, { axis: chip.axis, value: chip.value }]
    })
  }, [])

  const applyFirstRefinement = useCallback(() => {
    const chip = refinement[0]
    if (!chip) return
    applyRefinement(chip)
  }, [refinement, applyRefinement])

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLInputElement>) => {
      if (event.key === 'ArrowDown') {
        event.preventDefault()
        setSelectedIndex((i) => Math.min(i + 1, Math.max(results.length - 1, 0)))
        return
      }
      if (event.key === 'ArrowUp') {
        event.preventDefault()
        setSelectedIndex((i) => Math.max(i - 1, 0))
        return
      }
      if (event.key === 'Enter') {
        if (activeResult) {
          event.preventDefault()
          activate(activeResult)
        }
        return
      }
      if (event.key === 'Tab' && !event.shiftKey) {
        if (refinement.length > 0) {
          event.preventDefault()
          applyFirstRefinement()
        }
        return
      }
      if (event.key === 'Escape') {
        if (variant === 'cmdk') {
          event.preventDefault()
          onClose?.()
        }
        return
      }
    },
    [activate, activeResult, applyFirstRefinement, onClose, refinement.length, results.length, variant],
  )

  useEffect(() => {
    const li = listRef.current?.querySelector<HTMLLIElement>(`[data-index="${selectedIndex}"]`)
    if (!li) return
    li.scrollIntoView({ block: 'nearest' })
  }, [selectedIndex])

  const removeFilter = useCallback((target: PaletteFilter) => {
    setFilters((prev) => prev.filter((f) => !(f.axis === target.axis && f.value === target.value)))
  }, [])

  const setEntryChip = useCallback((chipQ: string) => {
    setQ(chipQ)
    inputRef.current?.focus()
  }, [])

  const isEmptyQuery = q.trim().length === 0 && filters.length === 0

  return (
    <div className={variant === 'homepage' ? 'w-full' : 'w-full max-w-2xl'} role="search" aria-labelledby={headingId}>
      <h2 id={headingId} className="sr-only">Palette search</h2>

      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-500" />
        <input
          ref={inputRef}
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholderPool[placeholderIndex]}
          autoComplete="off"
          spellCheck={false}
          aria-autocomplete="list"
          aria-controls={listboxId}
          aria-activedescendant={
            activeResult ? `${listboxId}-${activeResult.id}` : undefined
          }
          className={`w-full rounded-lg border border-white/10 bg-surface-900/60 pl-9 pr-3 text-white placeholder-surface-500 focus:outline-none focus:border-amber-400/60 focus:ring-1 focus:ring-amber-400/30 transition ${
            variant === 'homepage'
              ? 'py-3.5 text-base sm:py-4 sm:text-lg'
              : 'py-2.5 text-sm sm:text-base'
          }`}
        />
        {loading && (
          <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 animate-spin text-surface-500" />
        )}
      </div>

      {filters.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] text-surface-500">Filters:</span>
          {filters.map((f) => (
            <button
              key={`${f.axis}-${f.value}`}
              type="button"
              onClick={() => removeFilter(f)}
              className="inline-flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-0.5 text-[11px] text-amber-200 hover:bg-amber-400/20 transition-colors"
            >
              <span className="text-amber-300/80">{AXIS_LABEL[f.axis]}:</span>
              <span>{axisValueLabel(f.value)}</span>
              <X className="h-3 w-3" />
            </button>
          ))}
        </div>
      )}

      {!isEmptyQuery && refinement.length > 0 && (
        <RefinementChipBar
          chips={refinement}
          existingFilters={filters}
          onApply={applyRefinement}
        />
      )}

      {!isEmptyQuery && resolved.length > 0 && (
        <p className="mt-2 text-[11px] text-surface-500">
          Resolved: {resolved.map((r) => `"${r.matched_token}" → ${r.value || r.artefact}`).join('; ')}
        </p>
      )}

      <div className="mt-3" aria-live="polite">
        {error && (
          <p className="text-xs text-amber-300">
            {error}
          </p>
        )}

        {!isEmptyQuery && !loading && results.length === 0 && !error && data && (
          <p className="text-xs text-surface-400">
            No results. Try removing a filter or broadening the query.
          </p>
        )}

        {isEmptyQuery && (
          <EmptyState variant={variant} onPick={setEntryChip} />
        )}

        {results.length > 0 && (
          <ul
            ref={listRef}
            id={listboxId}
            role="listbox"
            aria-label="Palette results"
            className="mt-2 space-y-1.5"
          >
            {results.map((result, idx) => (
              <div key={result.id} data-index={idx} id={`${listboxId}-${result.id}`}>
                <PaletteResultRow
                  result={result}
                  selected={idx === selectedIndex}
                  onSelect={() => setSelectedIndex(idx)}
                  onActivate={() => activate(result)}
                  onRelatedConceptClick={goToConcept}
                />
              </div>
            ))}
          </ul>
        )}

        {data && results.length > 0 && (
          <p className="mt-2 text-[10px] text-surface-600">
            {data.results.length} of {data.total_candidates} candidate
            {data.total_candidates === 1 ? '' : 's'} — {(data.elapsed_micros / 1000).toFixed(1)} ms server time
          </p>
        )}
      </div>

      {!isEmptyQuery && results.length > 0 && (
        <ScopeRail scope={scope} onChange={setScope} />
      )}
    </div>
  )
}


function RefinementChipBar({
  chips,
  existingFilters,
  onApply,
}: {
  chips: PaletteRefinementChip[]
  existingFilters: PaletteFilter[]
  onApply: (chip: PaletteRefinementChip) => void
}) {
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1.5">
      <span className="text-[11px] text-surface-500">Narrow by:</span>
      {chips.slice(0, 6).map((chip) => {
        const already = existingFilters.some(
          (f) => f.axis === chip.axis && f.value === chip.value,
        )
        return (
          <button
            key={`${chip.axis}-${chip.value}`}
            type="button"
            onClick={() => !already && onApply(chip)}
            disabled={already}
            className="inline-flex items-center gap-1 rounded-full border border-white/15 bg-surface-800/60 px-2 py-0.5 text-[11px] text-surface-200 hover:border-amber-400/40 hover:bg-amber-400/5 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <span className="text-surface-500">{AXIS_LABEL[chip.axis]}:</span>
            <span>{axisValueLabel(chip.value)}</span>
            <span className="text-surface-500">·</span>
            <span className="text-surface-500">{chip.count}</span>
          </button>
        )
      })}
    </div>
  )
}

function ScopeRail({
  scope,
  onChange,
}: {
  scope: PaletteScope | undefined
  onChange: (s: PaletteScope | undefined) => void
}) {
  const scopes: { id: PaletteScope; label: string }[] = [
    { id: 'protocol', label: 'Protocols' },
    { id: 'flow', label: 'Flows' },
    { id: 'concept', label: 'Concepts' },
    { id: 'spec', label: 'Spec' },
  ]
  return (
    <div className="mt-3 flex flex-wrap items-center gap-1.5">
      <span className="text-[11px] text-surface-500">Filter to:</span>
      <button
        type="button"
        onClick={() => onChange(undefined)}
        className={`rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
          scope === undefined
            ? 'border-amber-400/50 bg-amber-400/10 text-amber-200'
            : 'border-white/10 bg-surface-800/60 text-surface-300 hover:border-white/20'
        }`}
      >
        All
      </button>
      {scopes.map((s) => (
        <button
          key={s.id}
          type="button"
          onClick={() => onChange(s.id === scope ? undefined : s.id)}
          className={`rounded-full border px-2 py-0.5 text-[11px] transition-colors ${
            scope === s.id
              ? 'border-amber-400/50 bg-amber-400/10 text-amber-200'
              : 'border-white/10 bg-surface-800/60 text-surface-300 hover:border-white/20'
          }`}
        >
          {s.label}
        </button>
      ))}
    </div>
  )
}

function EmptyState({
  variant,
  onPick,
}: {
  variant: 'homepage' | 'cmdk'
  onPick: (q: string) => void
}) {
  return (
    <div className="mt-2">
      <p className="text-[11px] text-surface-500 mb-1.5">
        {variant === 'homepage' ? "Don't know where to start?" : 'Curated entry points'}
      </p>
      <div className="flex flex-wrap gap-1.5">
        {ENTRY_CHIPS.map((chip) => (
          <button
            key={chip.label}
            type="button"
            onClick={() => onPick(chip.q)}
            className="rounded-full border border-white/10 bg-surface-800/60 px-2.5 py-1 text-[12px] text-surface-200 hover:border-amber-400/40 hover:bg-amber-400/5 transition-colors"
          >
            {chip.label}
          </button>
        ))}
      </div>
      {variant === 'cmdk' && (
        <p className="mt-3 text-[11px] text-surface-500">
          Tip: prefix a query with{' '}
          <code className="rounded bg-surface-800/80 px-1 py-0.5 text-surface-300">flow:</code>,{' '}
          <code className="rounded bg-surface-800/80 px-1 py-0.5 text-surface-300">protocol:</code>, or{' '}
          <code className="rounded bg-surface-800/80 px-1 py-0.5 text-surface-300">concept:</code>{' '}
          to limit results.
        </p>
      )}
    </div>
  )
}
