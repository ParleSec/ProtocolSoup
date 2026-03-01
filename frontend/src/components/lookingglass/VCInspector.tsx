import { useMemo, useState, type ElementType } from 'react'
import {
  Check,
  Copy,
  Eye,
  FileText,
  KeyRound,
  QrCode,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'
import type { VCArtifact } from '../../lookingglass/flows/base'

interface VCInspectorProps {
  artifacts: VCArtifact[]
}

export function VCInspector({ artifacts }: VCInspectorProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const sortedArtifacts = useMemo(
    () => [...artifacts].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime()),
    [artifacts]
  )

  if (sortedArtifacts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center">
        <Eye className="w-10 h-10 text-surface-600 mb-2" />
        <p className="text-surface-400 text-sm">No VC artifacts captured yet</p>
        <p className="text-surface-400 text-xs">Run an OID4VCI or OID4VP flow to inspect artifacts</p>
      </div>
    )
  }

  const copyText = async (value: string, id: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  return (
    <div className="space-y-3">
      {sortedArtifacts.map((artifact) => {
        const icon = artifactIcon(artifact.type)
        const Icon = icon.icon
        const metadata = artifact.metadata || {}
        const jwtDecoded = artifact.raw ? decodeJWTWithoutValidation(artifact.raw) : null
        const checks = getCheckList(metadata)
        const reasons = getReasonList(metadata)

        return (
          <div key={artifact.id} className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
            <div className="p-3 border-b border-white/5 flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <div className={`p-1.5 rounded ${icon.bg}`}>
                  <Icon className={`w-4 h-4 ${icon.fg}`} />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-white truncate">{artifact.title}</div>
                  <div className="text-[11px] text-surface-400">
                    {artifact.type}
                    {artifact.format ? ` • ${artifact.format}` : ''}
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-surface-500 shrink-0">
                {artifact.timestamp.toLocaleTimeString()}
              </div>
            </div>

            <div className="p-3 space-y-2">
              {artifact.rfcReference && (
                <div className="text-[11px] text-indigo-400 font-mono">{artifact.rfcReference}</div>
              )}

              {checks.length > 0 && (
                <div className="p-2 rounded bg-surface-950 border border-white/5">
                  <div className="text-xs text-surface-300 mb-1">Verifier checks</div>
                  <div className="grid grid-cols-2 gap-1 text-xs">
                    {checks.map((check) => (
                      <div key={check.label} className="flex items-center gap-1.5">
                        {check.value ? (
                          <ShieldCheck className="w-3.5 h-3.5 text-green-400" />
                        ) : (
                          <ShieldX className="w-3.5 h-3.5 text-red-400" />
                        )}
                        <span className="text-surface-300">{check.label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {reasons.length > 0 && (
                <div className="p-2 rounded bg-red-500/5 border border-red-500/20">
                  <div className="text-xs text-red-300">Policy reasons: {reasons.join(', ')}</div>
                </div>
              )}

              {Object.keys(metadata).length > 0 && (
                <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                  {JSON.stringify(metadata, null, 2)}
                </pre>
              )}

              {jwtDecoded && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                    {JSON.stringify(jwtDecoded.header, null, 2)}
                  </pre>
                  <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                    {JSON.stringify(jwtDecoded.payload, null, 2)}
                  </pre>
                </div>
              )}

              {artifact.raw && (
                <div className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs text-surface-400">Raw artifact</span>
                    <button
                      onClick={() => copyText(artifact.raw || '', artifact.id)}
                      className="flex items-center gap-1 text-xs text-surface-300 hover:text-white"
                    >
                      {copiedId === artifact.id ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedId === artifact.id ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="p-2 rounded bg-surface-950 text-[11px] text-surface-300 overflow-x-auto">
                    {artifact.raw}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function artifactIcon(type: VCArtifact['type']): { icon: ElementType; fg: string; bg: string } {
  switch (type) {
    case 'wallet_handoff':
      return { icon: QrCode, fg: 'text-cyan-400', bg: 'bg-cyan-500/10' }
    case 'credential':
      return { icon: KeyRound, fg: 'text-emerald-400', bg: 'bg-emerald-500/10' }
    case 'verification_result':
      return { icon: ShieldCheck, fg: 'text-violet-400', bg: 'bg-violet-500/10' }
    default:
      return { icon: FileText, fg: 'text-amber-400', bg: 'bg-amber-500/10' }
  }
}

function decodeJWTWithoutValidation(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  const parts = token.split('.')
  if (parts.length !== 3) {
    return null
  }
  try {
    const decodePart = (value: string): Record<string, unknown> => {
      const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
      const padding = '='.repeat((4 - (base64.length % 4)) % 4)
      return JSON.parse(atob(base64 + padding)) as Record<string, unknown>
    }
    return {
      header: decodePart(parts[0]),
      payload: decodePart(parts[1]),
    }
  } catch {
    return null
  }
}

function getCheckList(metadata: Record<string, unknown>): Array<{ label: string; value: boolean }> {
  const checks = metadata.checks as Record<string, unknown> | undefined
  if (!checks || typeof checks !== 'object') {
    return []
  }
  return [
    { label: 'Nonce', value: Boolean(checks.nonceValidated) },
    { label: 'Audience', value: Boolean(checks.audienceValidated) },
    { label: 'Expiry', value: Boolean(checks.expiryValidated) },
    { label: 'Holder Binding', value: Boolean(checks.holderBindingVerified) },
  ]
}

function getReasonList(metadata: Record<string, unknown>): string[] {
  const reasons = metadata.reasons
  if (!Array.isArray(reasons)) {
    return []
  }
  return reasons.map((reason) => String(reason))
}
