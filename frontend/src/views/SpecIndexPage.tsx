import Link from 'next/link'
import { ExternalLink } from 'lucide-react'
import type { ConformanceRequirementRow, ConformanceSpecResponse } from '@/lib/conformance.server'
import { requirementPath } from '@/lib/conformance.server'
import type { ProtocolCatalogDataItem } from '@/protocols/presentation/protocol-catalog-data'
import { NOT_EVALUATED, SELF_TEST_SENTENCE, VerdictBadge, formatReportDate } from './RequirementPage'

/** Groups rows by the leading segment of their section, preserving spec order. */
function groupByTopLevelSection(rows: ConformanceRequirementRow[]): Array<{ key: string; rows: ConformanceRequirementRow[] }> {
  const groups: Array<{ key: string; rows: ConformanceRequirementRow[] }> = []
  for (const row of rows) {
    const key = row.section.split('.')[0].trim()
    const last = groups[groups.length - 1]
    if (last && last.key === key) {
      last.rows.push(row)
    } else {
      groups.push({ key, rows: [row] })
    }
  }
  return groups
}

function groupHeading(key: string): string {
  return /^\d+$/.test(key) ? `Section ${key}` : key
}

interface SpecIndexPageProps {
  spec: ConformanceSpecResponse
  relatedProtocol?: ProtocolCatalogDataItem
}

export function SpecIndexPage({ spec, relatedProtocol }: SpecIndexPageProps) {
  const groups = groupByTopLevelSection(spec.requirements)
  const evaluated = spec.report_valid && spec.commit

  return (
    <article className="space-y-6 sm:space-y-8 px-1 sm:px-0">
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs sm:text-sm text-surface-400">
        <Link href="/protocols" className="hover:text-white transition-colors">Protocols</Link>
        <span aria-hidden="true">/</span>
        <span className="text-surface-300">{spec.short_title}</span>
      </nav>

      <header className="space-y-2">
        <h1 className="font-display text-2xl sm:text-3xl font-bold text-white">
          {spec.title}: normative requirements
        </h1>
        {/* Visible separators keep the markdown rendering readable: turndown
            collapses adjacent inline elements without whitespace. */}
        <p className="text-sm sm:text-base text-surface-400 flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>{spec.version}</span>
          <span aria-hidden="true">{' · '}</span>
          <a
            href={spec.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-amber-300 underline-offset-2 hover:underline"
          >
            Read the specification
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
          <span aria-hidden="true">{' · '}</span>
          <span>{spec.requirement_count} requirements tracked in the ProtocolSoup registry</span>
        </p>
      </header>

      <section className="rounded-xl border border-white/10 bg-surface-900/40 p-4 sm:p-5">
        <h2 className="text-base sm:text-lg font-semibold text-white mb-2">Self-test verdicts</h2>
        {evaluated ? (
          <p className="text-sm text-surface-300">
            Verdicts are for commit{' '}
            <a
              href={`https://github.com/ParleSec/ProtocolSoup/commit/${spec.commit}`}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-amber-300 underline-offset-2 hover:underline"
            >
              {spec.commit!.slice(0, 7)}
            </a>
            {spec.generated_at && (
              <>
                , evaluated <time dateTime={spec.generated_at}>{formatReportDate(spec.generated_at)}</time>
              </>
            )}
            .
          </p>
        ) : (
          <p className="text-sm text-surface-300">{NOT_EVALUATED}</p>
        )}
        <p className="text-xs sm:text-sm text-surface-400 mt-2">{SELF_TEST_SENTENCE}</p>
      </section>

      {groups.map((group) => (
        <section key={group.key}>
          <h2 className="text-sm uppercase tracking-wider text-surface-500 mb-2">{groupHeading(group.key)}</h2>
          <ul className="divide-y divide-white/5 rounded-xl border border-white/10 bg-surface-900/40 overflow-hidden">
            {group.rows.map((row) => (
              <li key={row.id}>
                <Link
                  href={requirementPath(spec.id, row.id)}
                  className="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4 px-4 py-3 hover:bg-white/[0.03] transition-colors"
                >
                  <span className="font-mono text-xs text-surface-400 sm:w-24 flex-shrink-0">{row.id}</span>{' '}
                  <span className="flex-1 min-w-0 text-sm text-surface-100">{row.title}</span>{' '}
                  <span className="text-xs text-surface-500 sm:w-24 flex-shrink-0">§{row.section}</span>{' '}
                  <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-surface-300 flex-shrink-0">
                    {row.level}
                  </span>{' '}
                  <span className="flex-shrink-0 sm:w-28 sm:text-right">
                    <VerdictBadge verdict={row.verdict} size="sm" />
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
      ))}

      {relatedProtocol && (
        <p className="text-sm text-surface-400">
          Related protocol page:{' '}
          <Link href={`/protocol/${relatedProtocol.id}`} className="text-amber-300 underline-offset-2 hover:underline">
            {relatedProtocol.name}
          </Link>
        </p>
      )}
    </article>
  )
}

export default SpecIndexPage
