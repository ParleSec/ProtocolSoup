import type { ReactNode } from 'react'

interface FieldRowProps {
  label: string
  value: ReactNode
  mono?: boolean
  className?: string
  labelClassName?: string
  valueClassName?: string
}

export function FieldRow({
  label,
  value,
  mono = false,
  className = 'flex flex-wrap gap-1',
  labelClassName = 'text-surface-500',
  valueClassName = 'text-surface-300',
}: FieldRowProps) {
  return (
    <div className={className}>
      <span className={labelClassName}>{label}:</span>
      <span className={`${mono ? 'font-mono text-[10px]' : ''} ${valueClassName}`.trim()}>
        {value}
      </span>
    </div>
  )
}
