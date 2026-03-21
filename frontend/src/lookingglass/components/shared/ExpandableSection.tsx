import type { ReactNode } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

interface ExpandableSectionProps {
  isExpanded: boolean
  onToggle: () => void
  header: ReactNode
  children: ReactNode
  containerClassName?: string
  headerClassName?: string
  contentClassName?: string
  transitionDuration?: number
}

export function ExpandableSection({
  isExpanded,
  onToggle,
  header,
  children,
  containerClassName = '',
  headerClassName = 'w-full text-left',
  contentClassName = '',
  transitionDuration = 0.2,
}: ExpandableSectionProps) {
  return (
    <div className={containerClassName}>
      <button onClick={onToggle} className={headerClassName}>
        {header}
      </button>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: transitionDuration }}
            className="overflow-hidden"
          >
            <div className={contentClassName}>
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
