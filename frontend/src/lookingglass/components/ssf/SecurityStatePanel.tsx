import { User } from 'lucide-react'
import type { SecurityState } from '../../ssf/types'

export function SecurityStatePanel({
  state,
  onReset,
}: {
  state: SecurityState | null
  onReset?: () => void
}) {
  if (!state) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <User className="w-12 h-12 text-surface-600 mb-3" />
        <p className="text-surface-400">No security state</p>
        <p className="text-surface-400 text-sm">Fire an event to see RP posture before and after the SET</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-surface-900/50 border border-white/5 overflow-hidden">
        <div className="p-3 border-b border-white/5 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4 text-purple-400" />
            <span className="font-medium text-white text-sm">RP security state: {state.email}</span>
          </div>
          {onReset && (
            <button
              type="button"
              onClick={onReset}
              className="text-xs px-2 py-1 rounded bg-surface-800 text-surface-400 hover:text-white transition-colors"
            >
              Reset RP state
            </button>
          )}
        </div>
        <div className="p-3 grid grid-cols-2 gap-3">
          <StateItem label="Active Sessions" value={state.sessions_active.toString()} status={state.sessions_active > 0 ? 'good' : 'neutral'} />
          <StateItem label="Account Status" value={state.account_enabled ? 'Enabled' : 'Disabled'} status={state.account_enabled ? 'good' : 'bad'} />
          <StateItem label="Tokens" value={state.tokens_valid ? 'Valid' : 'Invalid'} status={state.tokens_valid ? 'good' : 'bad'} />
          <StateItem label="Password Reset" value={state.password_reset_required ? 'Required' : 'Not Required'} status={state.password_reset_required ? 'warn' : 'good'} />
        </div>
        <div className="px-3 pb-3 text-xs text-surface-400">
          Last modified: {new Date(state.last_modified).toLocaleString()} by {state.modified_by}
        </div>
      </div>
    </div>
  )
}

function StateItem({
  label,
  value,
  status,
}: {
  label: string
  value: string
  status: 'good' | 'warn' | 'bad' | 'neutral'
}) {
  const colors = {
    good: 'text-green-400',
    warn: 'text-amber-400',
    bad: 'text-red-400',
    neutral: 'text-surface-300',
  }
  return (
    <div className="rounded-lg bg-surface-950/70 border border-white/5 p-2">
      <div className="text-[10px] uppercase tracking-wide text-surface-500">{label}</div>
      <div className={`text-sm font-medium ${colors[status]}`}>{value}</div>
    </div>
  )
}
