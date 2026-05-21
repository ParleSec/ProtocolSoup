'use client'

import { forwardRef } from 'react'
import {
  Beaker,
  BookOpen,
  Box,
  ChevronRight,
  Compass,
  ExternalLink,
  FileBadge,
  Play,
  Workflow,
} from 'lucide-react'

import {
  artefactTypeLabel,
  AXIS_LABEL,
  axisValueLabel,
} from './labels'
import { MarkdownLite } from './MarkdownLite'
import type {
  PaletteAxisChip,
  PaletteMatchReason,
  PaletteResult,
} from './types'

const TYPE_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  protocol: Box,
  flow: Workflow,
  concept: Compass,
  walkthrough: BookOpen,
  'spec-assertion': FileBadge,
}

const NORMATIVE_LEVEL_STYLE: Record<string, string> = {
  'MUST': 'bg-red-500/10 border-red-500/40 text-red-300',
  'MUST NOT': 'bg-red-500/10 border-red-500/40 text-red-300',
  'SHOULD': 'bg-amber-500/10 border-amber-500/40 text-amber-300',
  'SHOULD NOT': 'bg-amber-500/10 border-amber-500/40 text-amber-300',
  'MAY': 'bg-blue-500/10 border-blue-500/40 text-blue-300',
}

interface PaletteResultRowProps {
  result: PaletteResult
  selected: boolean
  onSelect: () => void
  onActivate: () => void
  /**
   * Called when the user clicks a related-concept chip inside the
   * expanded body. The palette re-queries with the concept ID so the
   * chip navigates *within the palette* rather than to /concept/{id},
   * which does not exist as a Next.js route (concepts are inline-only;
   * their full body, anchors, and chips render in the expanded row).
   */
  onRelatedConceptClick?: (conceptId: string) => void
}

/**
 * PaletteResultRow renders one result, switching presentation on artefact
 * type. Every row carries at least one match-reason chip — the backend
 * guarantees this (see `Service.Query`).
 */
export const PaletteResultRow = forwardRef<HTMLLIElement, PaletteResultRowProps>(
  function PaletteResultRow(
    { result, selected, onSelect, onActivate, onRelatedConceptClick },
    ref,
  ) {
    const Icon = TYPE_ICON[result.type] ?? Beaker
    // An empty href means the artefact has no canonical page (inline-only
    // type). The chevron and "Open page" affordance lie when href is empty,
    // so we hide them and rely on the inline expansion as the answer.
    const hasPage = Boolean(result.href)

    const handleClick = () => {
      onSelect()
      onActivate()
    }

    const outerClasses = [
      'group relative rounded-lg border transition-colors',
      selected
        ? 'border-amber-400/60 bg-amber-500/[0.06]'
        : 'border-white/5 bg-surface-900/40 hover:border-white/15',
    ].join(' ')

    return (
      <li ref={ref} className={`list-none ${outerClasses}`}>
        <button
          type="button"
          onClick={handleClick}
          onMouseEnter={onSelect}
          onFocus={onSelect}
          className="flex w-full items-stretch gap-3 rounded-lg px-3 py-2.5 sm:px-3.5 sm:py-3 text-left"
          aria-current={selected}
          data-result-id={result.id}
        >
          <span className="flex-shrink-0 mt-0.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-md bg-surface-800/80 border border-white/10">
              <Icon className="h-4 w-4 text-surface-300" />
            </span>
          </span>

          <span className="flex-1 min-w-0">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="text-[10px] uppercase tracking-wider text-surface-500">
                {artefactTypeLabel(result.type)}
                {result.protocol ? ` · ${result.protocol}` : ''}
              </span>
              {result.runnable && (
                <span className="inline-flex items-center gap-1 rounded-full bg-green-500/10 border border-green-500/30 px-1.5 py-0.5 text-[10px] font-medium text-green-300">
                  <Play className="h-2.5 w-2.5" /> Runnable
                </span>
              )}
              {result.status && result.status !== 'live' && (
                <span className="rounded-full bg-amber-500/10 border border-amber-500/30 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-amber-300">
                  {result.status}
                </span>
              )}
            </span>
            <div className="mt-0.5 flex items-baseline gap-2">
              <span className="text-sm sm:text-base font-medium text-white truncate">
                {result.name}
              </span>
            </div>

            {result.type !== 'spec-assertion' && (
              <ResultSummaryLine result={result} expanded={selected} />
            )}

            {result.spec_assertion && (
              <div className="mt-2 space-y-1">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider ${
                      NORMATIVE_LEVEL_STYLE[result.spec_assertion.normative_level] ??
                      'border-white/15 text-surface-300'
                    }`}
                  >
                    {result.spec_assertion.normative_level}
                  </span>
                  {result.spec_assertion.anchors.map((anchor) => (
                    <span
                      key={`${anchor.rfc}-${anchor.sections.join('.')}`}
                      className="rounded bg-surface-800/80 border border-white/10 px-1.5 py-0.5 text-[10px] font-mono text-surface-300"
                    >
                      {anchor.rfc} §{anchor.sections.join(', ')}
                    </span>
                  ))}
                </div>
                <p className="text-xs sm:text-[13px] text-surface-200 leading-relaxed">
                  {result.spec_assertion.assertion_text}
                </p>
              </div>
            )}

            <div className="mt-2 flex flex-wrap items-center gap-1">
              {result.axis_chips.slice(0, 4).map((chip) => (
                <AxisChipTag key={`${chip.axis}-${chip.value}`} chip={chip} />
              ))}
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-1">
              {result.match_reasons.map((reason, idx) => (
                <MatchReasonChip key={`${reason.kind}-${idx}`} reason={reason} />
              ))}
            </div>
          </span>

          {hasPage && (
            <span className="self-center text-surface-500 group-hover:text-surface-300 transition-colors">
              <ChevronRight className="h-4 w-4" />
            </span>
          )}
        </button>

        {selected && result.type !== 'spec-assertion' && result.body && (
          <div className="px-3 pb-3 sm:px-3.5">
            <ExpandedBody result={result} onRelatedConceptClick={onRelatedConceptClick} />
          </div>
        )}
      </li>
    )
  },
)

/**
 * ResultSummaryLine renders the always-visible row excerpt. When a
 * query-aware snippet is available it wins (with `<mark>` highlights);
 * otherwise we fall back to the static `body_preview`; otherwise to the
 * frontmatter `summary`.
 */
function ResultSummaryLine({
  result,
  expanded,
}: {
  result: PaletteResult
  expanded: boolean
}) {
  if (result.snippet) {
    return (
      <div className={`mt-1 text-xs sm:text-[13px] text-surface-300 ${expanded ? '' : 'line-clamp-2'}`}>
        <MarkdownLite
          source={result.snippet}
          allowMark
          className="inline text-xs sm:text-[13px] text-surface-300"
        />
      </div>
    )
  }
  const text = result.body_preview || result.summary
  if (!text) return null
  return (
    <p className={`mt-1 text-xs sm:text-[13px] text-surface-400 ${expanded ? '' : 'line-clamp-2'}`}>
      {text}
    </p>
  )
}

/**
 * ExpandedBody renders the full markdown body of the selected row plus
 * structured metadata — normative anchors and related-concept chips.
 *
 * For artefact types with a canonical page (protocol, flow), an "Open
 * page" link appears under the body. For inline-only types (concept,
 * walkthrough, spec-assertion) the panel itself *is* the canonical
 * surface, so no link is shown.
 *
 * Related-concept chips dispatch through onRelatedConceptClick so they
 * navigate within the palette (re-querying with the concept's ID) rather
 * than to a phantom /concept/{id} route.
 */
function ExpandedBody({
  result,
  onRelatedConceptClick,
}: {
  result: PaletteResult
  onRelatedConceptClick?: (conceptId: string) => void
}) {
  return (
    <div className="mt-3 rounded-md border border-white/5 bg-surface-950/40 p-3">
      <MarkdownLite source={result.body ?? ''} />

      {result.normative_anchors && result.normative_anchors.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1">
          <span className="text-[10px] uppercase tracking-wider text-surface-500 pr-1">
            Anchors
          </span>
          {result.normative_anchors.map((anchor) => {
            // `sections` is required by the schema and the backend validator
            // refuses anchors with zero sections, but defend against an
            // upstream regression (e.g. a stale index from a previous build)
            // because rendering crashes here take the whole homepage down.
            const sections = Array.isArray(anchor.sections) ? anchor.sections : []
            return (
              <span
                key={`${anchor.rfc}-${sections.join('.')}`}
                className="rounded bg-surface-800/80 border border-white/10 px-1.5 py-0.5 text-[10px] font-mono text-surface-200"
              >
                {anchor.rfc}
                {sections.length > 0 ? ` §${sections.join(', ')}` : ''}
              </span>
            )
          })}
        </div>
      )}

      {result.related_concepts && result.related_concepts.length > 0 && (
        <div className="mt-2 flex flex-wrap items-center gap-1">
          <span className="text-[10px] uppercase tracking-wider text-surface-500 pr-1">
            Related
          </span>
          {result.related_concepts.map((id) => (
            <button
              key={id}
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onRelatedConceptClick?.(id)
              }}
              className="rounded-full border border-white/10 bg-surface-800/60 px-2 py-0.5 text-[10px] text-surface-200 hover:border-amber-400/40"
              title={`Open ${id} in the palette`}
            >
              {id}
            </button>
          ))}
        </div>
      )}

      {(result.href || (result.runnable && result.type === 'flow')) && (
        <div className="mt-3 flex items-center gap-3 text-[11px]">
          {result.href && (
            <a
              href={result.href}
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1 text-amber-300 hover:text-amber-200"
            >
              Open page <ExternalLink className="h-3 w-3" />
            </a>
          )}
          {result.runnable && result.type === 'flow' && (
            <span className="inline-flex items-center gap-1 text-green-300">
              <Play className="h-3 w-3" /> Press Enter to run in Looking Glass
            </span>
          )}
        </div>
      )}
    </div>
  )
}

function AxisChipTag({ chip }: { chip: PaletteAxisChip }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-white/10 bg-surface-800/60 px-2 py-0.5 text-[10px] text-surface-300"
      title={AXIS_LABEL[chip.axis]}
    >
      <span className="text-surface-500">{AXIS_LABEL[chip.axis]}:</span>
      <span>{axisValueLabel(chip.value)}</span>
    </span>
  )
}

function MatchReasonChip({ reason }: { reason: PaletteMatchReason }) {
  let label = ''
  let tone = 'border-cyan-500/30 bg-cyan-500/5 text-cyan-200'

  switch (reason.kind) {
    case 'axis':
      label = reason.axis
        ? `Matched on ${AXIS_LABEL[reason.axis].toLowerCase()}: ${axisValueLabel(reason.value || '')}`
        : 'Matched on axis'
      tone = 'border-amber-500/30 bg-amber-500/5 text-amber-200'
      break
    case 'alias':
      label = reason.matched_token
        ? `Alias: "${reason.matched_token}"`
        : 'Alias match'
      tone = 'border-purple-500/30 bg-purple-500/5 text-purple-200'
      break
    case 'fts':
      label = reason.matched_phrase
        ? `Text match`
        : 'Text match'
      tone = 'border-blue-500/30 bg-blue-500/5 text-blue-200'
      break
    case 'edge':
      label = reason.artefact
        ? `Related to ${reason.artefact}`
        : 'Related'
      tone = 'border-emerald-500/30 bg-emerald-500/5 text-emerald-200'
      break
    case 'runnable':
      label = 'Runnable boost'
      tone = 'border-green-500/30 bg-green-500/5 text-green-200'
      break
    case 'protocol-name':
      label = reason.matched_token
        ? `Protocol "${reason.matched_token}"`
        : 'Protocol name'
      tone = 'border-orange-500/30 bg-orange-500/5 text-orange-200'
      break
  }

  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] ${tone}`}
      title={`weight ${reason.weight.toFixed(2)}`}
    >
      {label}
    </span>
  )
}
