import { CheckCircle, Key } from 'lucide-react'
import { CopyButton } from '../shared'
import type { DecodedToken } from '../../flows/base'

function eventEntries(payload: Record<string, unknown> | undefined): Array<{ uri: string; body: unknown }> {
  const events = payload?.events
  if (!events || typeof events !== 'object') return []
  return Object.entries(events as Record<string, unknown>).map(([uri, body]) => ({ uri, body }))
}

function categoryForUri(uri: string): 'CAEP' | 'RISC' | 'SSF' {
  if (uri.includes('/caep/')) return 'CAEP'
  if (uri.includes('/risc/')) return 'RISC'
  return 'SSF'
}

export function SETOverlay({ tokens }: { tokens: DecodedToken[] }) {
  const sets = tokens.filter((token) => token.type === 'set')
  if (sets.length === 0) {
    return null
  }

  return (
    <div className="space-y-3">
      {sets.map((token, index) => {
        const events = eventEntries(token.payload)
        const primary = events[0]
        const category = primary ? categoryForUri(primary.uri) : 'SSF'
        return (
          <div key={`${token.raw}-${index}`} className={`p-3 rounded-lg border ${
            category === 'CAEP'
              ? 'bg-blue-500/5 border-blue-500/20'
              : category === 'RISC'
                ? 'bg-amber-500/5 border-amber-500/20'
                : 'bg-surface-900/50 border-white/10'
          }`}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-2 min-w-0">
                <Key className="w-4 h-4 text-amber-400 flex-shrink-0" />
                <span className="text-sm text-white truncate">Security Event Token</span>
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                  category === 'CAEP' ? 'bg-blue-500 text-white' : category === 'RISC' ? 'bg-amber-500 text-white' : 'bg-surface-700 text-white'
                }`}>
                  {category}
                </span>
              </div>
              <span className="flex items-center gap-1 text-[10px] text-green-400">
                <CheckCircle className="w-3 h-3" />
                RFC 8417
              </span>
            </div>
            <p className="text-xs text-surface-400 mb-2">
              Session id travels on <code>X-Looking-Glass-Session</code>, not inside this SET.
            </p>
            {events.map((event) => (
              <div key={event.uri} className="text-xs font-mono text-surface-300 break-all mb-1">
                {event.uri}
              </div>
            ))}
            <div className="mt-2 flex justify-end">
              <CopyButton text={token.raw} />
            </div>
          </div>
        )
      })}
    </div>
  )
}
