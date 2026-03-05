import type { ElementType } from 'react'
import { ChevronRight } from 'lucide-react'

interface FlowButtonProps {
  icon: ElementType
  label: string
  sublabel: string
  color: 'blue' | 'green' | 'orange' | 'purple' | 'cyan'
  onClick: () => void
}

const FLOW_BUTTON_COLORS: Record<FlowButtonProps['color'], { border: string; bg: string; text: string }> = {
  blue: { border: 'border-blue-500/20 hover:border-blue-500/40 active:border-blue-500/60', bg: 'bg-blue-500/10', text: 'text-blue-400' },
  green: { border: 'border-green-500/20 hover:border-green-500/40 active:border-green-500/60', bg: 'bg-green-500/10', text: 'text-green-400' },
  orange: { border: 'border-orange-500/20 hover:border-orange-500/40 active:border-orange-500/60', bg: 'bg-orange-500/10', text: 'text-orange-400' },
  purple: { border: 'border-purple-500/20 hover:border-purple-500/40 active:border-purple-500/60', bg: 'bg-purple-500/10', text: 'text-purple-400' },
  cyan: { border: 'border-cyan-500/20 hover:border-cyan-500/40 active:border-cyan-500/60', bg: 'bg-cyan-500/10', text: 'text-cyan-400' },
}

export function FlowButton({ icon: Icon, label, sublabel, color, onClick }: FlowButtonProps) {
  const styles = FLOW_BUTTON_COLORS[color]

  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2.5 sm:gap-4 p-2.5 sm:p-4 rounded-xl border ${styles.border} bg-gradient-to-br from-white/[0.02] to-transparent hover:from-white/[0.04] active:from-white/[0.06] transition-all text-left group touch-manipulation`}
    >
      <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-lg ${styles.bg} flex items-center justify-center flex-shrink-0`}>
        <Icon className={`w-4 h-4 sm:w-5 sm:h-5 ${styles.text}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-medium text-white text-xs sm:text-base truncate">{label}</div>
        <div className="text-[10px] sm:text-sm text-surface-400">{sublabel}</div>
      </div>
      <ChevronRight className="w-4 h-4 sm:w-5 sm:h-5 text-surface-600 group-hover:text-surface-400 transition-colors flex-shrink-0" />
    </button>
  )
}

interface TokenButtonProps {
  label: string
  color: 'green' | 'orange' | 'blue'
  active: boolean
  onClick: () => void
}

export function TokenButton({ label, color, active, onClick }: TokenButtonProps) {
  const colors = {
    green: active ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-green-400',
    orange: active ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-orange-400',
    blue: active ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' : 'bg-surface-800 text-surface-400 border-transparent hover:text-blue-400',
  }

  return (
    <button
      onClick={onClick}
      className={`px-2.5 py-1.5 rounded-md text-xs font-mono border transition-all whitespace-nowrap flex-shrink-0 ${colors[color]}`}
    >
      {label}
    </button>
  )
}
