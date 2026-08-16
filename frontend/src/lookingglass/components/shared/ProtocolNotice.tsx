import { AlertTriangle, Info } from 'lucide-react'
import type { ReactNode } from 'react'
import { explainLookingGlassFailure } from '../../wallet-client'

export type ProtocolNoticeTone = 'error' | 'warning' | 'info'

interface ProtocolNoticeProps {
  tone: ProtocolNoticeTone
  title?: string
  specReference?: string
  protocolError?: string | null
  children?: ReactNode
}

const TONE_STYLES: Record<ProtocolNoticeTone, { border: string; bg: string; title: string; body: string }> = {
  error: {
    border: 'border-red-500/30',
    bg: 'bg-red-500/5',
    title: 'text-red-300',
    body: 'text-red-200/90',
  },
  warning: {
    border: 'border-amber-500/30',
    bg: 'bg-amber-500/5',
    title: 'text-amber-300',
    body: 'text-amber-100/90',
  },
  info: {
    border: 'border-cyan-500/30',
    bg: 'bg-cyan-500/5',
    title: 'text-cyan-300',
    body: 'text-cyan-100/90',
  },
}

/**
 * Preventative callout or post-failure explanation. Protocol error text stays
 * intact so Looking Glass never substitutes a gloss for the real response.
 */
export function ProtocolNotice({
  tone,
  title,
  specReference,
  protocolError,
  children,
}: ProtocolNoticeProps) {
  const explained = protocolError ? explainLookingGlassFailure(protocolError) : null
  const resolvedTitle = explained?.title || title || (protocolError ? 'Protocol error' : '')
  const resolvedSpec = explained?.specReference || specReference
  const resolvedGuidance = children || explained?.guidance
  if (!resolvedTitle && !resolvedGuidance && !protocolError) {
    return null
  }

  const styles = TONE_STYLES[tone]
  const Icon = tone === 'info' ? Info : AlertTriangle

  return (
    <div className={`rounded-lg border p-2.5 sm:p-3 ${styles.border} ${styles.bg}`}>
      <div className="flex items-start gap-2">
        <Icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${styles.title}`} />
        <div className="min-w-0 space-y-1.5">
          {resolvedTitle && (
            <div className="flex flex-wrap items-center gap-1.5">
              <p className={`text-[11px] sm:text-xs font-medium ${styles.title}`}>{resolvedTitle}</p>
              {resolvedSpec && (
                <span className={`px-1 py-0.5 rounded text-[10px] font-mono ${styles.title} bg-black/20`}>
                  {resolvedSpec}
                </span>
              )}
            </div>
          )}
          {resolvedGuidance && (
            <div className={`text-[11px] sm:text-xs leading-relaxed ${styles.body}`}>{resolvedGuidance}</div>
          )}
          {protocolError && (
            <div>
              <p className={`text-[10px] uppercase tracking-wide ${styles.title} opacity-80`}>
                What the protocol returned
              </p>
              <p className={`mt-0.5 text-[11px] sm:text-xs font-mono break-words ${styles.body}`}>
                {protocolError}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
