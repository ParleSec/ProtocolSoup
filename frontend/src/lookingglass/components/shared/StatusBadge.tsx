import type { ElementType } from 'react'

export interface StatusBadgeVariant {
  bg: string
  border: string
  text: string
  label: string
  shortLabel?: string
  icon?: ElementType
  iconClassName?: string
}

interface StatusBadgeProps {
  status: string
  variants: Record<string, StatusBadgeVariant>
  fallback?: StatusBadgeVariant
  className?: string
}

const DEFAULT_FALLBACK: StatusBadgeVariant = {
  bg: 'bg-surface-800',
  border: 'border-white/10',
  text: 'text-surface-400',
  label: 'Unknown',
  shortLabel: 'Unknown',
}

export function StatusBadge({ status, variants, fallback = DEFAULT_FALLBACK, className = '' }: StatusBadgeProps) {
  const variant = variants[status] ?? {
    ...fallback,
    label: status || fallback.label,
    shortLabel: status || fallback.shortLabel || fallback.label,
  }

  const Icon = variant.icon

  return (
    <div className={`px-2 sm:px-3 py-1 sm:py-1.5 rounded-full ${variant.bg} border ${variant.border} flex-shrink-0 ${className}`.trim()}>
      <span className={`inline-flex items-center gap-1.5 text-xs sm:text-sm font-medium ${variant.text} whitespace-nowrap`}>
        {Icon && <Icon className={`w-3.5 h-3.5 flex-shrink-0 ${variant.iconClassName ?? ''}`.trim()} aria-hidden="true" />}
        <span className="hidden sm:inline">{variant.label}</span>
        <span className="sm:hidden">{variant.shortLabel || variant.label}</span>
      </span>
    </div>
  )
}
