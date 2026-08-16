export type SegmentedChoiceAccent = 'cyan' | 'amber' | 'violet'

export interface SegmentedChoiceOption<T extends string> {
  id: T
  label: string
  disabled?: boolean
  accent?: SegmentedChoiceAccent
}

const SELECTED_ACCENT: Record<SegmentedChoiceAccent, string> = {
  cyan: 'border-cyan-500/50 bg-cyan-500/10 text-cyan-300',
  amber: 'border-amber-500/50 bg-amber-500/10 text-amber-300',
  violet: 'border-violet-500/40 bg-violet-500/15 text-violet-200',
}

const COLUMN_CLASS: Record<2 | 3 | 4, string> = {
  2: 'grid-cols-2',
  3: 'grid-cols-2 sm:grid-cols-3',
  4: 'grid-cols-2 sm:grid-cols-4',
}

interface SegmentedChoiceProps<T extends string> {
  value: T
  onChange: (value: T) => void
  options: SegmentedChoiceOption<T>[]
  columns?: 2 | 3 | 4
  'aria-label'?: string
}

export function SegmentedChoice<T extends string>({
  value,
  onChange,
  options,
  columns = 2,
  'aria-label': ariaLabel,
}: SegmentedChoiceProps<T>) {
  return (
    <div role="group" aria-label={ariaLabel} className={`grid ${COLUMN_CLASS[columns]} gap-2`}>
      {options.map((option) => {
        const selected = option.id === value
        return (
          <button
            key={option.id}
            type="button"
            disabled={option.disabled}
            aria-pressed={selected}
            onClick={() => {
              if (!option.disabled && option.id !== value) {
                onChange(option.id)
              }
            }}
            className={`rounded-lg border px-3 py-2 text-xs font-mono transition-colors disabled:opacity-40 disabled:hover:text-surface-400 ${
              selected
                ? SELECTED_ACCENT[option.accent || 'cyan']
                : 'border-white/10 bg-surface-900 text-surface-400 hover:text-white'
            }`}
          >
            {option.label}
          </button>
        )
      })}
    </div>
  )
}
