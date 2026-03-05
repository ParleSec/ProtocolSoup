import { useState } from 'react'
import { Check, Copy } from 'lucide-react'

interface CopyButtonProps {
  text: string
  title?: string
  className?: string
  iconClassName?: string
  copiedClassName?: string
  copyClassName?: string
  copiedMs?: number
  showLabel?: boolean
  copiedLabel?: string
  copyLabel?: string
  labelClassName?: string
}

export function CopyButton({
  text,
  title = 'Copy to clipboard',
  className = 'p-1.5 sm:p-1 rounded hover:bg-white/10 active:bg-white/20 transition-colors flex-shrink-0',
  iconClassName = 'w-3.5 h-3.5 sm:w-3 sm:h-3',
  copiedClassName = 'text-green-400',
  copyClassName = 'text-surface-400',
  copiedMs = 2000,
  showLabel = false,
  copiedLabel = 'Copied',
  copyLabel = 'Copy',
  labelClassName = 'text-xs',
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), copiedMs)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button onClick={handleCopy} className={className} title={title}>
      <span className="flex items-center gap-1.5">
        {copied ? (
          <Check className={`${iconClassName} ${copiedClassName}`.trim()} />
        ) : (
          <Copy className={`${iconClassName} ${copyClassName}`.trim()} />
        )}
        {showLabel && (
          <span className={labelClassName}>
            {copied ? copiedLabel : copyLabel}
          </span>
        )}
      </span>
    </button>
  )
}
