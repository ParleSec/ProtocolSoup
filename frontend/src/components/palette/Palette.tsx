'use client'

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Search, Loader2, X, ChevronDown, ChevronUp, Clock } from 'lucide-react'

import { AXIS_LABEL, axisValueLabel } from '@/components/palette/labels'
import {
  aliasSearchTarget,
  buildPalettePathname,
  parsePaletteUrlState,
} from '@/components/palette/paletteUrlState'
import { resolveFlowHandoff } from '@/components/palette/runDispatch'
import {
  usePaletteQuery,
  usePlatformShortcutLabel,
  useRecentSearches,
} from '@/components/palette/usePaletteQuery'
import { PaletteResultRow } from '@/components/palette/PaletteResultRow'
import type {
  PaletteFilter,
  PaletteRefinementChip,
  PaletteResolvedAlias,
  PaletteResult,
  PaletteScope,
} from '@/components/palette/types'

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
  const searchParams = useSearchParams()
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)
  const headingId = useId()
  const listboxId = useId()

  // URL persistence is enabled for the homepage variant only.
  const urlPersist = variant === 'homepage'

  // Hydrate initial state from URL once on mount.
  const initial = useMemo(() => {
    if (!urlPersist || !searchParams) return null
    return parsePaletteUrlState(searchParams)
    // We intentionally only compute this once on mount; subsequent URL updates are driven by state changes
  }, [])

  const [q, setQ] = useState(() => initial?.q ?? '')
  const [scope, setScope] = useState<PaletteScope | undefined>(
    () => initial?.scope,
  )
  const [filters, setFilters] = useState<PaletteFilter[]>(
    () => initial?.filters ?? [],
  )
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [placeholderIndex, setPlaceholderIndex] = useState(0)
  const [statusMessage, setStatusMessage] = useState('')
  // Results-list visibility cap. Default 5 keeps the surface short
  const DEFAULT_VISIBLE = 5
  const [visibleCount, setVisibleCount] = useState(DEFAULT_VISIBLE)

  const shortcutLabel = usePlatformShortcutLabel()

  // localStorage-backed recent searches. Only used in the empty state.
  const { recent: recentSearches, push: pushRecent, clear: clearRecent } =
    useRecentSearches()

  const resetPalette = useCallback(() => {
    setQ('')
    setScope(undefined)
    setFilters([])
    setSelectedIndex(0)
    setVisibleCount(DEFAULT_VISIBLE)
    inputRef.current?.focus()
  }, [])

  const placeholderPool = variant === 'homepage' ? HOMEPAGE_PLACEHOLDERS : CMDK_PLACEHOLDERS

  useEffect(() => {
    if (!autoFocus) return
    inputRef.current?.focus()
  }, [autoFocus])

  // Homepage: cmd+K / Ctrl+K focuses the prominent input instead of opening modal
  useEffect(() => {
    if (variant !== 'homepage') return
    function onFocusHome() {
      inputRef.current?.focus()
      inputRef.current?.select()
    }
    window.addEventListener('palette:focus-home', onFocusHome)
    return () => window.removeEventListener('palette:focus-home', onFocusHome)
  }, [variant])

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
  const isEmptyQuery = q.trim().length === 0 && filters.length === 0

  useEffect(() => {
    setSelectedIndex(0)
    setVisibleCount(DEFAULT_VISIBLE)
  }, [q, scope, filters])

  useEffect(() => {
    if (!urlPersist) return
    if (typeof window === 'undefined') return
    const next = buildPalettePathname(window.location.pathname, { q, scope, filters })
    if (next === window.location.pathname + window.location.search) return
    router.replace(next, { scroll: false })
  }, [urlPersist, q, scope, filters, router])

  const resultCount = data?.results.length ?? 0
  useEffect(() => {
    const trimmed = q.trim()
    if (trimmed.length < 2) return
    if (loading) return
    if (resultCount === 0) return
    const handle = window.setTimeout(() => {
      pushRecent(trimmed)
    }, 1500)
    return () => window.clearTimeout(handle)
  }, [q, resultCount, loading, pushRecent])

  // Screen-reader status: announce result counts once a query settles.
  useEffect(() => {
    if (isEmptyQuery) {
      setStatusMessage('')
      return
    }
    if (loading) {
      setStatusMessage('Searching…')
      return
    }
    if (error) {
      setStatusMessage(error)
      return
    }
    if (!data) return
    if (resultCount === 0) {
      setStatusMessage('No results found.')
      return
    }
    setStatusMessage(
      `${resultCount} result${resultCount === 1 ? '' : 's'} found.`,
    )
  }, [isEmptyQuery, loading, error, data, resultCount])

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
        setSelectedIndex((i) => {
          const next = Math.min(i + 1, Math.max(results.length - 1, 0))
          // Power users: arrow past the visible cap auto-expands the list
          // so the highlighted row is always rendered and scrollable.
          if (next >= visibleCount) setVisibleCount(results.length)
          return next
        })
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
        } else if (!isEmptyQuery) {
          event.preventDefault()
          resetPalette()
        }
        return
      }
    },
    [activate, activeResult, applyFirstRefinement, isEmptyQuery, onClose, refinement.length, resetPalette, results.length, variant, visibleCount],
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

  const applyAliasSuggestion = useCallback((alias: PaletteResolvedAlias) => {
    const target = aliasSearchTarget(alias)
    if (!target) return
    setQ(target)
    setFilters([])
    setSelectedIndex(0)
    inputRef.current?.focus()
  }, [])

  const listExpanded = !isEmptyQuery && (loading || results.length > 0 || Boolean(data))

  const showResolvedHint = !isEmptyQuery && results.length > 0 && resolved.length > 0
  const showZeroResultAliases =
    !isEmptyQuery && !loading && results.length === 0 && !error && data && resolved.length > 0

  const inputTrailing = loading ? (
    <Loader2 className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 animate-spin text-surface-500" />
  ) : q.length > 0 ? (
    <button
      type="button"
      onClick={resetPalette}
      aria-label="Clear search"
      title="Clear search"
      className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1.5 text-surface-500 hover:text-surface-200 hover:bg-white/10 focus:outline-none focus:ring-1 focus:ring-amber-400/40 transition-colors"
    >
      <X className="h-3.5 w-3.5" />
    </button>
  ) : variant === 'homepage' && shortcutLabel ? (
    <kbd
      aria-hidden="true"
      className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 rounded border border-white/10 bg-surface-800/60 px-1.5 py-0.5 font-mono text-[10px] text-surface-400 sm:inline-flex"
    >
      {shortcutLabel}
    </kbd>
  ) : null

  const controls = (
    <>
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-surface-500" />
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholderPool[placeholderIndex]}
          autoComplete="off"
          spellCheck={false}
          aria-autocomplete="list"
          aria-expanded={listExpanded}
          aria-haspopup="listbox"
          aria-controls={listboxId}
          aria-activedescendant={
            activeResult ? `${listboxId}-${activeResult.id}` : undefined
          }
          className={`w-full rounded-lg border border-white/10 bg-surface-900/60 pl-9 text-white placeholder-surface-500 focus:outline-none focus:border-amber-400/60 focus:ring-1 focus:ring-amber-400/30 transition ${
            q.length > 0 || (variant === 'homepage' && shortcutLabel)
              ? 'pr-9'
              : 'pr-3'
          } ${
            variant === 'homepage'
              ? 'py-2.5 text-sm sm:py-4 sm:text-lg'
              : 'py-2.5 text-sm sm:text-base'
          }`}
        />
        {inputTrailing}
      </div>

      {!isEmptyQuery && (
        <ScopeRail scope={scope} onChange={setScope} />
      )}

      {filters.length > 0 && (
        <div className="mt-2 max-w-full overflow-hidden">
          <div className="overflow-x-auto overscroll-x-contain pb-0.5 [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden sm:overflow-visible">
            <div className="flex w-max min-w-full flex-nowrap items-center gap-1.5 sm:w-auto sm:flex-wrap">
            <span className="shrink-0 text-[11px] text-surface-500">Filters:</span>
            {filters.map((f) => (
              <button
                key={`${f.axis}-${f.value}`}
                type="button"
                onClick={() => removeFilter(f)}
                className="inline-flex shrink-0 min-h-9 items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-2.5 py-1.5 text-[11px] text-amber-200 hover:bg-amber-400/20 transition-colors sm:min-h-0 sm:px-2 sm:py-0.5"
              >
                <span className="text-amber-300/80">{AXIS_LABEL[f.axis]}:</span>
                <span>{axisValueLabel(f.value)}</span>
                <X className="h-3 w-3" />
              </button>
            ))}
            {filters.length >= 2 && (
              <button
                type="button"
                onClick={() => setFilters([])}
                className="inline-flex shrink-0 min-h-9 items-center gap-1 rounded-full border border-white/10 bg-surface-800/60 px-2.5 py-1.5 text-[11px] text-surface-400 hover:border-amber-400/40 hover:text-amber-200 transition-colors sm:min-h-0 sm:px-2 sm:py-0.5"
                aria-label="Clear all filters"
                title="Clear all filters"
              >
                Clear all
                <X className="h-3 w-3" />
              </button>
            )}
            </div>
          </div>
        </div>
      )}

      {!isEmptyQuery && refinement.length > 0 && (
        <RefinementChipBar
          chips={refinement}
          existingFilters={filters}
          onApply={applyRefinement}
        />
      )}

      {showResolvedHint && (
        <p className="mt-2 hidden text-[11px] text-surface-500 sm:block">
          Resolved: {resolved.map((r) => `"${r.matched_token}" → ${r.value || r.artefact}`).join('; ')}
        </p>
      )}

      {showZeroResultAliases && (
        <ZeroResultAliases resolved={resolved} onApply={applyAliasSuggestion} />
      )}
    </>
  )

  const resultsPanel = (
    <>
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {statusMessage}
      </p>

      {error && (
        <p className="text-xs text-amber-300" role="alert">
          {error}
        </p>
      )}

      {!isEmptyQuery && !loading && results.length === 0 && !error && data && !showZeroResultAliases && (
        <p className="text-xs text-surface-400">
          No results. Try removing a filter or broadening the query.
        </p>
      )}

      {isEmptyQuery && (
        <EmptyState
          variant={variant}
          onPick={setEntryChip}
          recent={recentSearches}
          onClearRecent={clearRecent}
        />
      )}

      {results.length > 0 && (
        <>
          <ul
            ref={listRef}
            id={listboxId}
            role="listbox"
            aria-label="Palette results"
            className="mt-2 space-y-1.5"
          >
            {results.slice(0, visibleCount).map((result, idx) => (
              <PaletteResultRow
                key={result.id}
                id={`${listboxId}-${result.id}`}
                dataIndex={idx}
                result={result}
                selected={idx === selectedIndex}
                onSelect={() => setSelectedIndex(idx)}
                onActivate={() => activate(result)}
                onRelatedConceptClick={goToConcept}
              />
            ))}
          </ul>

          {results.length > DEFAULT_VISIBLE && (
            <button
              type="button"
              onClick={() =>
                setVisibleCount((v) => (v >= results.length ? DEFAULT_VISIBLE : results.length))
              }
              className="mt-2 inline-flex min-h-10 w-full items-center justify-center gap-1.5 rounded-md border border-white/10 bg-surface-900/40 px-3 py-2 text-xs text-surface-300 hover:border-amber-400/40 hover:text-amber-200 transition-colors sm:min-h-0 sm:py-1.5"
              aria-expanded={visibleCount >= results.length}
              aria-controls={listboxId}
            >
              {visibleCount >= results.length ? (
                <>
                  <ChevronUp className="h-3.5 w-3.5" />
                  Show top {DEFAULT_VISIBLE}
                </>
              ) : (
                <>
                  <ChevronDown className="h-3.5 w-3.5" />
                  Show all {results.length} results
                </>
              )}
            </button>
          )}
        </>
      )}

      {data && results.length > 0 && (
        <p className="mt-2 text-[10px] text-surface-600" aria-hidden="true">
          Showing {Math.min(visibleCount, results.length)} of {results.length} ranked result
          {results.length === 1 ? '' : 's'}
          <span className="hidden sm:inline">
            {' '}({data.total_candidates} candidate
            {data.total_candidates === 1 ? '' : 's'} scored in {(data.elapsed_micros / 1000).toFixed(1)} ms)
          </span>
        </p>
      )}
    </>
  )

  const shellClass =
    variant === 'homepage'
      ? 'w-full'
      : 'flex min-h-0 w-full max-w-2xl flex-1 flex-col'

  return (
    <div className={shellClass} role="search" aria-labelledby={headingId}>
      <h2 id={headingId} className="sr-only">Palette search</h2>

      {variant === 'cmdk' ? (
        <>
          <div className="shrink-0">{controls}</div>
          <div
            className="mt-3 min-h-0 flex-1 overflow-y-auto"
            aria-busy={loading}
          >
            {resultsPanel}
          </div>
        </>
      ) : (
        <>
          {controls}
          <div className="mt-3" aria-busy={loading}>
            {resultsPanel}
          </div>
        </>
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
  const [open, setOpen] = useState(false)

  const chipButtons = chips.slice(0, 6).map((chip) => {
    const already = existingFilters.some(
      (f) => f.axis === chip.axis && f.value === chip.value,
    )
    return (
      <button
        key={`${chip.axis}-${chip.value}`}
        type="button"
        onClick={() => !already && onApply(chip)}
        disabled={already}
        className="inline-flex shrink-0 min-h-9 items-center gap-1 rounded-full border border-white/15 bg-surface-800/60 px-2.5 py-1.5 text-[11px] text-surface-200 hover:border-amber-400/40 hover:bg-amber-400/5 disabled:opacity-40 disabled:cursor-not-allowed transition-colors sm:min-h-0 sm:px-2 sm:py-0.5"
      >
        <span className="text-surface-500">{AXIS_LABEL[chip.axis]}:</span>
        <span>{axisValueLabel(chip.value)}</span>
        <span className="text-surface-500">·</span>
        <span className="text-surface-500">{chip.count}</span>
      </button>
    )
  })

  return (
    <>
      {/* Mobile: collapsed by default so results stay above the fold. */}
      <div className="mt-2 sm:hidden">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="inline-flex min-h-9 w-full items-center justify-between gap-2 rounded-md border border-white/10 bg-surface-900/40 px-3 py-2 text-xs text-surface-300 hover:border-amber-400/40 hover:text-amber-200 transition-colors"
        >
          <span>Narrow by ({chips.length})</span>
          <ChevronDown className={`h-3.5 w-3.5 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
        </button>
        {open && (
          <div className="mt-1.5 max-w-full overflow-hidden">
            <div className="overflow-x-auto overscroll-x-contain pb-0.5 [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden">
              <div className="flex w-max gap-1.5">{chipButtons}</div>
            </div>
          </div>
        )}
      </div>

      {/* Desktop: always visible, wraps naturally. */}
      <div className="mt-2 hidden flex-wrap items-center gap-1.5 sm:flex">
        <span className="text-[11px] text-surface-500">Narrow by:</span>
        {chipButtons}
      </div>
    </>
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
  const scopeButtons = (
    <>
      <button
        type="button"
        onClick={() => onChange(undefined)}
        className={`shrink-0 min-h-9 rounded-full border px-2.5 py-1.5 text-[11px] transition-colors sm:min-h-0 sm:px-2 sm:py-0.5 ${
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
          className={`shrink-0 min-h-9 rounded-full border px-2.5 py-1.5 text-[11px] transition-colors sm:min-h-0 sm:px-2 sm:py-0.5 ${
            scope === s.id
              ? 'border-amber-400/50 bg-amber-400/10 text-amber-200'
              : 'border-white/10 bg-surface-800/60 text-surface-300 hover:border-white/20'
          }`}
        >
          {s.label}
        </button>
      ))}
    </>
  )

  return (
    <div className="mt-2 max-w-full overflow-hidden">
      <div className="overflow-x-auto overscroll-x-contain pb-0.5 [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden sm:overflow-visible">
        <div className="flex w-max min-w-full flex-nowrap items-center gap-1.5 sm:w-auto sm:flex-wrap">
          <span className="shrink-0 text-[11px] text-surface-500">Show:</span>
          {scopeButtons}
        </div>
      </div>
    </div>
  )
}

function ZeroResultAliases({
  resolved,
  onApply,
}: {
  resolved: PaletteResolvedAlias[]
  onApply: (alias: PaletteResolvedAlias) => void
}) {
  const suggestions = resolved
    .map((alias) => ({ alias, target: aliasSearchTarget(alias) }))
    .filter((entry): entry is { alias: PaletteResolvedAlias; target: string } => entry.target !== null)

  if (suggestions.length === 0) return null

  return (
    <div className="mt-2">
      <p className="text-xs text-surface-400">No exact matches.</p>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {suggestions.map(({ alias, target }) => (
          <button
            key={`${alias.matched_token}-${target}`}
            type="button"
            onClick={() => onApply(alias)}
            className="inline-flex min-h-9 items-center rounded-full border border-amber-400/30 bg-amber-400/5 px-3 py-1.5 text-[12px] text-amber-200 hover:border-amber-400/50 hover:bg-amber-400/10 transition-colors sm:min-h-0 sm:px-2.5 sm:py-1"
          >
            Did you mean &ldquo;{target}&rdquo;?
          </button>
        ))}
      </div>
    </div>
  )
}

function EmptyState({
  variant,
  onPick,
  recent,
  onClearRecent,
}: {
  variant: 'homepage' | 'cmdk'
  onPick: (q: string) => void
  recent: string[]
  onClearRecent: () => void
}) {
  const chipClass =
    'inline-flex max-w-[14rem] shrink-0 items-center truncate rounded-full border border-white/10 bg-surface-800/60 px-2.5 py-1 text-[11px] text-surface-200 hover:border-amber-400/40 hover:bg-amber-400/5 transition-colors sm:max-w-none sm:px-3 sm:py-1.5 sm:text-[12px]'
  const recentChipClass =
    'inline-flex max-w-[12rem] shrink-0 items-center gap-1 truncate rounded-full border border-amber-400/25 bg-amber-400/5 px-2.5 py-1 text-[11px] text-amber-100 hover:border-amber-400/40 hover:bg-amber-400/10 transition-colors sm:max-w-none sm:px-3 sm:py-1.5 sm:text-[12px]'

  const starterLabel =
    variant === 'homepage'
      ? recent.length > 0
        ? 'Try'
        : 'Try:'
      : recent.length > 0
        ? 'Curated'
        : 'Curated entry points'

  return (
    <div className="mt-1.5 max-w-full overflow-hidden sm:mt-2">
      <div className="overflow-x-auto overscroll-x-contain [scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden sm:overflow-visible">
        <div className="flex w-max max-w-full items-center gap-1.5 sm:w-auto sm:flex-wrap">
          {recent.map((entry) => (
            <button
              key={entry}
              type="button"
              onClick={() => onPick(entry)}
              className={recentChipClass}
              title={entry}
            >
              <Clock className="h-3 w-3 shrink-0 text-amber-300/70" aria-hidden="true" />
              <span className="truncate">{entry}</span>
            </button>
          ))}

          {recent.length > 0 && (
            <span
              className="h-4 w-px shrink-0 bg-white/10 sm:hidden"
              aria-hidden="true"
            />
          )}

          <span className="shrink-0 text-[10px] text-surface-500 sm:text-[11px]">
            {starterLabel}
          </span>

          {ENTRY_CHIPS.map((chip) => (
            <button
              key={chip.label}
              type="button"
              onClick={() => onPick(chip.q)}
              className={chipClass}
            >
              {chip.label}
            </button>
          ))}
        </div>
      </div>

      {recent.length > 0 && (
        <button
          type="button"
          onClick={onClearRecent}
          className="mt-1 text-[10px] text-surface-600 hover:text-surface-400 transition-colors sm:text-[11px]"
          aria-label="Clear recent searches"
        >
          Clear recent
        </button>
      )}

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
