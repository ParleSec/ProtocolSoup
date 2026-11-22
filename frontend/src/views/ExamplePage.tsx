import Link from 'next/link'
import { CheckCircle2, Circle, ExternalLink, Play } from 'lucide-react'
import type {
  ConformanceArtefactActor,
  ConformanceExampleField,
  ConformanceExamplePart,
  ConformanceExampleResponse,
  ConformanceExampleVerification,
} from '@/lib/conformance.server'
import { ExchangeView, formatUTC } from '@/views/RequirementArtefacts'
import { Section } from '@/views/RequirementPage'

/**
 * Fixed wording for an example value. Do not soften it: the page must say
 * the message is real and that nothing in it was edited.
 */
export const EXAMPLE_SENTENCE =
  'Captured from the deployed ProtocolSoup at the commit shown. The message is shown exactly as it was sent.'

/** Fixed wording: why a reader who tries a token from this page finds it inactive. */
export const EXAMPLE_TOKENS_SENTENCE =
  'Every token in these exchanges was revoked, or had expired, before this page published them.'

/**
 * Who sent the requests in an example's exchanges. The requirement pages'
 * actor notes describe deliberately malformed requests, which an example
 * never contains, so these say only who the sender was.
 */
const SENDERS: Record<ConformanceArtefactActor, string> = {
  conformance_client: 'Requests sent by ProtocolSoup’s conformance client.',
  hosted_wallet: 'Requests sent by the hosted wallet.',
  counterparty: 'Messages from the conformance counterparty.',
}

/** The decoded parts of a compact JWS, in the terms of RFC 7515 and RFC 7519. */
const PART_TITLES: Record<string, string> = {
  header: 'JOSE Header',
  payload: 'JWT Claims Set',
}

/** How a message format is named on the page. */
function formatLabel(format: ConformanceExampleResponse['format']): string {
  switch (format) {
    case 'jwt':
      return 'JWT, compact serialization'
  }
}

function memberName(path: string): string {
  return path.slice(path.indexOf('.') + 1)
}

/** One member: its value as sent, then the specification text that defines it. */
function MemberRow({ path, value, field }: { path: string; value?: string; field?: ConformanceExampleField }) {
  const nested = memberName(path).includes('.')
  return (
    <li className={`rounded-lg border border-white/10 bg-surface-950/40 p-3 space-y-2 ${nested ? 'ml-4 sm:ml-6' : ''}`}>
      <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-sm">
        <code className="font-semibold text-white">{memberName(path)}</code>
        {value !== undefined && <code className="min-w-0 break-all text-surface-200">{value}</code>}
      </p>
      {field ? (
        <>
          <blockquote className="border-l-2 border-white/15 pl-3 text-sm leading-relaxed text-surface-200">
            {field.statement}
          </blockquote>
          <p className="text-xs">
            <a
              href={field.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-amber-300 underline-offset-2 hover:underline"
            >
              {field.reference}
              <ExternalLink className="w-3 h-3" aria-hidden="true" />
            </a>
          </p>
          {field.note && <p className="text-sm leading-relaxed text-surface-300">{field.note}</p>}
          {field.requirements.length > 0 && (
            <ul className="space-y-1">
              {field.requirements.map((requirement) => (
                <li key={requirement.id}>
                  <Link href={requirement.path} className="text-sm text-surface-200 hover:text-white transition-colors">
                    <span className="font-mono text-surface-400">{requirement.id}</span>
                    {' '}
                    {requirement.question}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </>
      ) : (
        <p className="text-xs text-surface-400">The registry records no specification text for this member.</p>
      )}
    </li>
  )
}

function PartView({ part, fields }: { part: ConformanceExamplePart; fields: Map<string, ConformanceExampleField> }) {
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-white">{PART_TITLES[part.name] ?? part.name}</h3>
      <pre className="rounded-lg border border-white/10 bg-surface-950 p-3 text-xs leading-relaxed text-surface-100 overflow-x-auto whitespace-pre">
        {part.indented}
      </pre>
      <ul className="space-y-2">
        {part.members.map((member) => (
          <MemberRow key={member.path} path={member.path} value={member.value} field={fields.get(member.path)} />
        ))}
      </ul>
    </div>
  )
}

/** Status is icon + label + colour: the signature check is an outcome. */
function VerificationView({ verification }: { verification: ConformanceExampleVerification }) {
  return (
    <div className="space-y-3">
      <p>
        <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-300">
          <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
          Signature verified when captured
        </span>
      </p>
      {verification.method === 'jwks' ? (
        <p className="text-sm leading-relaxed text-surface-200">
          The capture run verified the {verification.algorithm} signature with the key whose <code>kid</code> is{' '}
          <code className="break-all">{verification.key_id}</code>, from the JWK Set fetched in exchange{' '}
          {(verification.jwks_exchange ?? 0) + 1} below. Keys rotate, so check this message against that JWK Set, not
          against the one published today.
        </p>
      ) : (
        <p className="text-sm leading-relaxed text-surface-200">
          The capture run verified the {verification.algorithm} signature with the public key in the message&apos;s own{' '}
          <code>jwk</code> header parameter. The message carries its own verification key, so no JWK Set is involved.
        </p>
      )}
    </div>
  )
}

export function ExamplePage({ example }: { example: ConformanceExampleResponse }) {
  const commit = example.commit
  const fields = new Map(example.fields.map((field) => [field.path, field]))
  const published = example.status === 'published'

  return (
    <article className="space-y-6 sm:space-y-8 px-1 sm:px-0">
      <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-2 text-xs sm:text-sm text-surface-400">
        <Link href="/protocols" className="hover:text-white transition-colors">Protocols</Link>
        <span aria-hidden="true">/</span>
        <span>Examples</span>
        <span aria-hidden="true">/</span>
        <span className="text-surface-300">{example.title}</span>
      </nav>

      <header className="space-y-3">
        <h1 className="text-2xl sm:text-3xl font-bold text-white">{example.question}</h1>
        <p className="text-base leading-relaxed text-surface-100">{example.summary}</p>
        {/* Visible separators keep the markdown rendering readable: turndown
            collapses adjacent inline spans without whitespace. */}
        <p className="text-sm text-surface-400 flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-surface-200">{example.title}</span>
          <span aria-hidden="true">{' · '}</span>
          <span>{formatLabel(example.format)}</span>
        </p>
      </header>

      <Section title={`A real ${example.title}`}>
        {published && example.value ? (
          <div className="space-y-3">
            <p className="flex flex-wrap items-center gap-2 text-sm text-surface-300">
              <span>
                Issued <time dateTime={example.issued_at}>{formatUTC(example.issued_at)}</time>
              </span>
              {commit && (
                <>
                  <span aria-hidden="true">{' · '}</span>
                  <span>
                    Commit{' '}
                    <a
                      href={`https://github.com/ParleSec/ProtocolSoup/commit/${commit}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-mono text-amber-300 underline-offset-2 hover:underline"
                    >
                      {commit.slice(0, 7)}
                    </a>
                  </span>
                </>
              )}
            </p>
            <p className="text-xs sm:text-sm text-surface-400">{EXAMPLE_SENTENCE}</p>
            <pre className="rounded-lg border border-white/10 bg-surface-950 p-3 text-xs leading-relaxed text-surface-100 overflow-x-auto whitespace-pre">
              {example.value}
            </pre>
            {example.source && (
              <p className="text-sm text-surface-300">
                Taken from {example.source.location}, in the {example.source.message} of exchange{' '}
                {example.source.exchange + 1} below.
              </p>
            )}
          </div>
        ) : example.status === 'pending' ? (
          <p className="inline-flex items-center gap-2 text-sm text-surface-200">
            <Circle className="w-4 h-4 text-surface-400 animate-pulse-slow" aria-hidden="true" />
            Published at <time dateTime={example.publish_after}>{formatUTC(example.publish_after)}</time>, once every
            token, code and nonce in its exchanges has expired.
          </p>
        ) : (
          <p className="text-surface-200">Not captured for this build.</p>
        )}
      </Section>

      <Section title="Every field, with the specification text that defines it">
        {published && example.parts ? (
          <div className="space-y-6">
            {example.parts.map((part) => (
              <PartView key={part.name} part={part} fields={fields} />
            ))}
          </div>
        ) : (
          <ul className="space-y-2">
            {example.fields.map((field) => (
              <MemberRow key={field.path} path={field.path} field={field} />
            ))}
          </ul>
        )}
      </Section>

      {published && example.verification && (
        <Section title="How it was verified">
          <VerificationView verification={example.verification} />
        </Section>
      )}

      {published && example.exchanges && example.exchanges.length > 0 && (
        <Section title="The exchanges that carried it">
          <div className="space-y-3">
            {example.actor && (
              <>
                <p className="text-sm text-surface-200 leading-relaxed">{example.description}</p>
                <p className="text-xs text-surface-400">{SENDERS[example.actor]}</p>
              </>
            )}
            <p className="text-xs text-surface-400">{EXAMPLE_TOKENS_SENTENCE}</p>
            <ol className="space-y-4">
              {example.exchanges.map((exchange, index) => (
                <ExchangeView key={exchange.id} exchange={exchange} index={index} />
              ))}
            </ol>
          </div>
        </Section>
      )}

      <Section title="Run it live">
        <p className="text-sm text-surface-200 leading-relaxed mb-3">
          Looking Glass runs the flow that produces this message against the same server and decodes it as it happens.
        </p>
        <Link
          href={example.run_url}
          className="inline-flex items-center gap-1.5 text-sm text-amber-300 underline-offset-2 hover:underline"
        >
          <Play className="w-3.5 h-3.5" aria-hidden="true" />
          Open the flow in Looking Glass
        </Link>
      </Section>
    </article>
  )
}

export default ExamplePage
