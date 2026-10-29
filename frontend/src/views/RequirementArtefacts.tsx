import { CheckCircle2, Circle, XCircle } from 'lucide-react'
import type {
  ConformanceArtefact,
  ConformanceArtefactActor,
  ConformanceArtefactKind,
  ConformanceRequirementArtefacts,
} from '@/lib/conformance.server'
import type { WireCapturedExchange, WireCapturedPayload } from '@/lookingglass/types'

/**
 * Fixed wording for the captured-exchange block. Do not soften it: the page
 * must say exactly who sent the requests and that nothing is edited.
 */
export const ARTEFACTS_SENTENCE =
  'Captured from the deployed ProtocolSoup at the commit shown. Every request and response is shown exactly as sent and received.'

const ACTOR_LABELS: Record<ConformanceArtefactActor, string> = {
  conformance_client: 'Conformance client',
  hosted_wallet: 'Hosted wallet',
  counterparty: 'Conformance counterparty',
}

const ACTOR_NOTES: Record<ConformanceArtefactActor, string> = {
  conformance_client:
    'Requests from ProtocolSoup’s conformance client, which sends malformed messages on purpose. The hosted wallet never sends these.',
  hosted_wallet: 'Requests sent by the hosted wallet itself.',
  counterparty:
    'Messages from a deliberately broken conformance counterparty, to show how the hosted wallet refuses them.',
}

const KIND_TITLES: Record<ConformanceArtefactKind, string> = {
  passing: 'Passing exchange',
  failing: 'Failing exchange',
}

function formatUTC(value?: string): string {
  if (!value) return ''
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return `${parsed.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

/** Status is icon + label + colour, measured against what a conformant server does. */
function OutcomeBadge({ artefact }: { artefact: ConformanceArtefact }) {
  const asRequired = artefact.outcome === artefact.expected_outcome
  const Icon = asRequired ? CheckCircle2 : XCircle
  const verb = artefact.outcome === 'accepted' ? 'Accepted' : 'Rejected'
  const label = asRequired ? `${verb}, as required` : `${verb}; a conformant server would not`
  const className = asRequired
    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
    : 'bg-red-500/10 text-red-300 border-red-500/30'
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium ${className}`}>
      <Icon className="w-3.5 h-3.5" aria-hidden="true" />
      {label}
    </span>
  )
}

function WireText({ payload }: { payload?: WireCapturedPayload }) {
  if (!payload?.data) {
    return <p className="text-xs text-surface-400">No bytes captured.</p>
  }
  return (
    <div className="space-y-1">
      {payload.encoding === 'base64' && (
        <p className="text-xs text-surface-400">Binary message, shown as base64.</p>
      )}
      <pre className="rounded-lg border border-white/10 bg-surface-950 p-3 text-xs leading-relaxed text-surface-100 overflow-x-auto whitespace-pre">
        {payload.data}
      </pre>
    </div>
  )
}

function ExchangeView({ exchange, index }: { exchange: WireCapturedExchange; index: number }) {
  const { request, response, tls } = exchange
  const tlsLine = tls?.version
    ? [tls.version, tls.cipherSuite, tls.negotiatedProtocol].filter(Boolean).join(' · ')
    : ''
  return (
    <li className="space-y-2">
      <p className="text-sm text-surface-200 break-all">
        <span className="text-surface-400 mr-2">{index + 1}.</span>
        <span className="font-semibold">{request.method}</span> {request.url}
        <span aria-hidden="true">{' → '}</span>
        <span className="font-semibold">{response.status}</span> {response.statusText}
      </p>
      {tlsLine && <p className="text-xs text-surface-400">TLS: {tlsLine}</p>}
      <div className="grid gap-2 lg:grid-cols-2">
        <div className="min-w-0 space-y-1">
          <h4 className="text-xs uppercase tracking-wider text-surface-400">Request</h4>
          <WireText payload={request.raw} />
        </div>
        <div className="min-w-0 space-y-1">
          <h4 className="text-xs uppercase tracking-wider text-surface-400">Response</h4>
          <WireText payload={response.raw} />
        </div>
      </div>
    </li>
  )
}

function ArtefactView({ kind, artefact, unavailable }: {
  kind: ConformanceArtefactKind
  artefact?: ConformanceArtefact
  unavailable?: string
}) {
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-white">{KIND_TITLES[kind]}</h3>
      {artefact ? (
        <>
          <p className="flex flex-wrap items-center gap-2 text-xs text-surface-300">
            <OutcomeBadge artefact={artefact} />
            <span aria-hidden="true">{' · '}</span>
            <span>{ACTOR_LABELS[artefact.actor]}</span>
          </p>
          <p className="text-sm text-surface-200 leading-relaxed">{artefact.description}</p>
          <p className="text-xs text-surface-400">{ACTOR_NOTES[artefact.actor]}</p>
          <ol className="space-y-4">
            {artefact.exchanges.map((exchange, index) => (
              <ExchangeView key={exchange.id} exchange={exchange} index={index} />
            ))}
          </ol>
        </>
      ) : (
        <p className="text-sm text-surface-300">
          {unavailable ? `Not captured: ${unavailable}` : 'Not captured for this build.'}
        </p>
      )}
    </div>
  )
}

export function RequirementArtefacts({ artefacts }: { artefacts: ConformanceRequirementArtefacts }) {
  const commit = artefacts.commit
  const shortCommit = commit ? commit.slice(0, 7) : ''

  if (artefacts.status === 'not_captured') {
    return <p className="text-surface-200">Not captured for this build.</p>
  }

  return (
    <div className="space-y-5">
      <p className="flex flex-wrap items-center gap-2 text-sm text-surface-300">
        <span>
          Captured <time dateTime={artefacts.captured_at}>{formatUTC(artefacts.captured_at)}</time>
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
                {shortCommit}
              </a>
            </span>
          </>
        )}
      </p>
      <p className="text-xs sm:text-sm text-surface-400">{ARTEFACTS_SENTENCE}</p>

      {artefacts.status === 'pending' ? (
        <p className="inline-flex items-center gap-2 text-sm text-surface-200">
          <Circle className="w-4 h-4 text-surface-400 animate-pulse-slow" aria-hidden="true" />
          Published at <time dateTime={artefacts.publish_after}>{formatUTC(artefacts.publish_after)}</time>, once every
          token, code and nonce in these exchanges has expired.
        </p>
      ) : (
        <div className="space-y-8">
          <ArtefactView kind="passing" artefact={artefacts.passing} unavailable={artefacts.unavailable?.passing} />
          <ArtefactView kind="failing" artefact={artefacts.failing} unavailable={artefacts.unavailable?.failing} />
        </div>
      )}
    </div>
  )
}
