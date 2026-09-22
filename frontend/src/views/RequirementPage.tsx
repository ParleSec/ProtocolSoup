import Link from 'next/link'
import { ArrowLeft, ArrowRight, ExternalLink, FileCode2, FlaskConical } from 'lucide-react'
import { MarkdownLite } from '@/components/palette/MarkdownLite'
import type {
  ConformanceRequirementResponse,
  ConformanceVerdict,
} from '@/lib/conformance.server'
import { requirementPath, specPath } from '@/lib/conformance.server'
import type { ProtocolCatalogDataItem } from '@/protocols/presentation/protocol-catalog-data'

/**
 * Fixed wording required on every verdict block. Do not reword: the page must
 * never read as a certification of ProtocolSoup or of any other product.
 */
export const SELF_TEST_SENTENCE =
  "This is ProtocolSoup's result against its own implementation at the commit shown. It is not a certification of ProtocolSoup or of any other product."

export const NOT_EVALUATED = 'Not evaluated for this build'

export const STATEMENT_LABEL = 'Requirement as recorded in the ProtocolSoup registry'

const VERDICT_STYLES: Record<ConformanceVerdict, { label: string; className: string }> = {
  PASS: { label: 'Pass', className: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' },
  FAIL: { label: 'Fail', className: 'bg-red-500/15 text-red-300 border-red-500/30' },
  CHECK: { label: 'Check', className: 'bg-amber-500/15 text-amber-300 border-amber-500/30' },
  MISSING_TEST: { label: 'Missing test', className: 'bg-red-500/15 text-red-300 border-red-500/30' },
  'N/A': { label: 'Not applicable', className: 'bg-surface-700/60 text-surface-200 border-white/10' },
  DEVIATION: { label: 'Deviation', className: 'bg-purple-500/15 text-purple-300 border-purple-500/30' },
}

export function VerdictBadge({ verdict, size = 'md' }: { verdict?: ConformanceVerdict; size?: 'sm' | 'md' }) {
  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-3 py-1 text-sm'
  if (!verdict) {
    return (
      <span className={`inline-flex items-center rounded-md border border-white/10 bg-white/[0.03] font-medium text-surface-400 ${sizeClass}`}>
        {size === 'sm' ? 'Not evaluated' : NOT_EVALUATED}
      </span>
    )
  }
  const style = VERDICT_STYLES[verdict]
  return (
    <span className={`inline-flex items-center rounded-md border font-medium ${style.className} ${sizeClass}`}>
      {style.label}
    </span>
  )
}

export function formatReportDate(generatedAt?: string): string {
  if (!generatedAt) return ''
  const parsed = new Date(generatedAt)
  if (Number.isNaN(parsed.getTime())) return generatedAt
  return parsed.toISOString().slice(0, 10)
}

function sourceHref(baseUrl: string | undefined, file: string, line?: number): string | null {
  if (!baseUrl) return null
  return `${baseUrl}${file}${line && line > 0 ? `#L${line}` : ''}`
}

function SourceLink({ href, label, mono = true }: { href: string | null; label: string; mono?: boolean }) {
  const className = `${mono ? 'font-mono' : ''} text-sm break-all`
  if (!href) {
    return <span className={`${className} text-surface-200`}>{label}</span>
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`${className} text-amber-300 underline-offset-2 hover:underline inline-flex items-start gap-1`}
    >
      {label}
      <ExternalLink className="w-3 h-3 mt-1 flex-shrink-0" />
    </a>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-white/10 bg-surface-900/40 p-4 sm:p-5">
      <h2 className="text-base sm:text-lg font-semibold text-white mb-3">{title}</h2>
      {children}
    </section>
  )
}

interface RequirementPageProps {
  requirement: ConformanceRequirementResponse
  relatedProtocol?: ProtocolCatalogDataItem
}

export function RequirementPage({ requirement, relatedProtocol }: RequirementPageProps) {
  const spec = requirement.specification
  const commit = requirement.commit
  const shortCommit = commit ? commit.slice(0, 7) : ''
  const showADR = requirement.verdict === 'DEVIATION' || requirement.verdict === 'N/A' ||
    requirement.applicability === 'deviation' || requirement.applicability === 'not_applicable'

  return (
    <article className="space-y-6 sm:space-y-8 px-1 sm:px-0">
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-xs sm:text-sm text-surface-400">
        <Link href="/protocols" className="hover:text-white transition-colors">Protocols</Link>
        <span aria-hidden="true">/</span>
        <Link href={specPath(spec.id)} className="hover:text-white transition-colors">{spec.short_title}</Link>
        <span aria-hidden="true">/</span>
        <span className="font-mono text-surface-300">{requirement.id}</span>
      </nav>

      <header className="space-y-2">
        <h1 className="font-display text-2xl sm:text-3xl font-bold text-white">{requirement.title}</h1>
        {/* Visible separators keep the markdown rendering readable: turndown
            collapses adjacent inline spans without whitespace. */}
        <p className="text-sm sm:text-base text-surface-400 flex flex-wrap items-center gap-x-2 gap-y-1">
          <span>{spec.short_title} §{requirement.section}</span>
          <span aria-hidden="true">{' · '}</span>
          <span className="font-mono text-xs px-2 py-0.5 rounded bg-white/5 border border-white/10 text-surface-200">{requirement.level}</span>
          <span aria-hidden="true">{' · '}</span>
          <span>Roles: {requirement.roles.join(', ')}</span>
        </p>
      </header>

      <Section title={STATEMENT_LABEL}>
        <p className="text-surface-100 leading-relaxed">{requirement.statement}</p>
        <a
          href={requirement.section_url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex items-center gap-1.5 text-sm text-amber-300 underline-offset-2 hover:underline"
        >
          Read §{requirement.section} in {spec.short_title}
          <ExternalLink className="w-3.5 h-3.5" />
        </a>
      </Section>

      <Section title="Self-test verdict">
        {requirement.verdict && commit ? (
          <div className="space-y-3">
            <p className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={requirement.verdict} />
              <span aria-hidden="true">{' · '}</span>
              <span className="text-sm text-surface-300">
                Commit{' '}
                <a
                  href={`https://github.com/ParleSec/ProtocolSoup/commit/${commit}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-amber-300 underline-offset-2 hover:underline"
                >
                  {shortCommit}
                </a>
              </span>
              {requirement.generated_at && (
                <>
                  <span aria-hidden="true">{' · '}</span>
                  <span className="text-sm text-surface-400">
                    Evaluated <time dateTime={requirement.generated_at}>{formatReportDate(requirement.generated_at)}</time>
                  </span>
                </>
              )}
            </p>
            <p className="text-xs sm:text-sm text-surface-400">{SELF_TEST_SENTENCE}</p>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-surface-200">{NOT_EVALUATED}</p>
            <p className="text-xs sm:text-sm text-surface-400">{SELF_TEST_SENTENCE}</p>
          </div>
        )}
      </Section>

      <Section title="Tests">
        <ul className="space-y-2">
          {requirement.tests.map((test) => (
            <li key={`${test.package}/${test.name}`} className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-1 sm:gap-4">
              <div className="min-w-0 flex items-start gap-2">
                <FlaskConical className="w-4 h-4 mt-0.5 text-surface-500 flex-shrink-0" />
                <div className="min-w-0">
                  <SourceLink href={sourceHref(requirement.source_base_url, test.file, test.line)} label={test.name} />
                  <p className="text-xs text-surface-500 font-mono break-all">{test.package}</p>
                </div>
              </div>
              <div className="flex-shrink-0">
                <VerdictBadge verdict={test.verdict} size="sm" />
              </div>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Implementation">
        <ul className="space-y-1.5">
          {requirement.implementation.map((file) => (
            <li key={file} className="flex items-start gap-2">
              <FileCode2 className="w-4 h-4 mt-0.5 text-surface-500 flex-shrink-0" />
              <SourceLink href={sourceHref(requirement.source_base_url, file)} label={file} />
            </li>
          ))}
        </ul>
      </Section>

      {showADR && (requirement.adr || requirement.notes) && (
        <Section title="Decision record">
          {requirement.adr && (
            <p className="text-sm mb-2">
              <SourceLink href={sourceHref(requirement.source_base_url, requirement.adr)} label={requirement.adr} />
            </p>
          )}
          {requirement.notes && <p className="text-sm text-surface-200 leading-relaxed">{requirement.notes}</p>}
        </Section>
      )}

      {requirement.explainer_markdown && (
        <Section title="Explainer">
          {/* Explainer `##` headings sit under the h2 "Explainer", so they become h3. */}
          <MarkdownLite
            source={requirement.explainer_markdown}
            headingLevel={2}
            className="space-y-2 text-sm leading-relaxed text-surface-200"
          />
        </Section>
      )}

      <Section title="Related requirements">
        {requirement.siblings.length > 0 && (
          <div className="mb-4">
            <h3 className="text-xs uppercase tracking-wider text-surface-500 mb-2">Also in §{requirement.section}</h3>
            <ul className="space-y-1">
              {requirement.siblings.map((sibling) => (
                <li key={sibling.id}>
                  <Link href={requirementPath(spec.id, sibling.id)} className="text-sm text-surface-200 hover:text-white transition-colors">
                    <span className="font-mono text-surface-400 mr-2">{sibling.id}</span>
                    {sibling.title}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="flex flex-col sm:flex-row sm:justify-between gap-2 text-sm">
          {requirement.previous ? (
            <Link href={requirementPath(spec.id, requirement.previous.id)} className="inline-flex items-center gap-1.5 text-surface-300 hover:text-white transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="font-mono text-surface-400">{requirement.previous.id}</span>
              <span className="truncate">{requirement.previous.title}</span>
            </Link>
          ) : <span />}
          {requirement.next && (
            <Link href={requirementPath(spec.id, requirement.next.id)} className="inline-flex items-center gap-1.5 text-surface-300 hover:text-white transition-colors sm:text-right">
              <span className="font-mono text-surface-400">{requirement.next.id}</span>
              <span className="truncate">{requirement.next.title}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          )}
        </div>
      </Section>

      <p className="text-sm text-surface-400">
        <Link href={specPath(spec.id)} className="text-amber-300 underline-offset-2 hover:underline">
          All {spec.short_title} requirements
        </Link>
        {relatedProtocol && (
          <>
            {' · '}
            <Link href={`/protocol/${relatedProtocol.id}`} className="text-amber-300 underline-offset-2 hover:underline">
              {relatedProtocol.name} protocol page
            </Link>
          </>
        )}
      </p>
    </article>
  )
}

export default RequirementPage
