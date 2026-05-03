'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  HelpCircle,
  Info,
  Unlock,
  Bug,
  Zap,
  ExternalLink,
} from 'lucide-react'
import {
  getParameterExplainer,
  type ParameterExplainer as ParameterExplainerData,
} from '@/protocols/explainers'

interface ParameterExplainerProps {
  protocolId: string
  name: string
  value: string
}

export function ParameterExplainer({
  protocolId,
  name,
  value,
}: ParameterExplainerProps) {
  const [open, setOpen] = useState(false)
  const explainer = getParameterExplainer(protocolId, name)

  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-col sm:flex-row sm:gap-3 text-xs sm:text-sm">
        <div className="flex items-center gap-1.5 sm:flex-shrink-0">
          <code className="text-cyan-400 font-mono break-all">{name}</code>
          {explainer && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                setOpen((prev) => !prev)
              }}
              aria-expanded={open}
              aria-label={`Why ${name} matters`}
              className={`inline-flex items-center justify-center rounded-full text-surface-500 hover:text-cyan-300 hover:bg-cyan-500/10 transition-colors p-0.5 ${
                open ? 'text-cyan-300 bg-cyan-500/10' : ''
              }`}
            >
              <HelpCircle className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
            </button>
          )}
        </div>
        <span className="text-surface-400 break-words">{value}</span>
      </div>

      <AnimatePresence>
        {open && explainer && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <ExplainerPanel explainer={explainer} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function ExplainerPanel({ explainer }: { explainer: ParameterExplainerData }) {
  return (
    <div className="mt-1 sm:mt-1.5 rounded-lg border border-cyan-500/20 bg-cyan-500/[0.03] p-2.5 sm:p-3 space-y-2.5 sm:space-y-3">
      <Section
        icon={Info}
        label="Purpose"
        accent="text-cyan-300"
        iconBg="bg-cyan-500/10"
        body={explainer.purpose}
      />
      <Section
        icon={Unlock}
        label="Without it"
        accent="text-amber-300"
        iconBg="bg-amber-500/10"
        body={explainer.withoutIt}
      />
      <Section
        icon={Bug}
        label="Attack"
        accent="text-rose-300"
        iconBg="bg-rose-500/10"
        body={explainer.attack}
      />
      <Section
        icon={Zap}
        label="Impact"
        accent="text-rose-300"
        iconBg="bg-rose-500/10"
        body={explainer.impact}
      />

      {explainer.references && explainer.references.length > 0 && (
        <div className="flex flex-wrap gap-1.5 pt-1">
          {explainer.references.map((ref) => (
            <a
              key={ref.href}
              href={ref.href}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] sm:text-xs font-medium bg-white/5 text-surface-300 border border-white/10 hover:bg-white/10 hover:text-white transition-colors"
            >
              {ref.label}
              <ExternalLink className="w-2.5 h-2.5" />
            </a>
          ))}
        </div>
      )}
    </div>
  )
}

function Section({
  icon: Icon,
  label,
  accent,
  iconBg,
  body,
}: {
  icon: React.ElementType
  label: string
  accent: string
  iconBg: string
  body: string
}) {
  return (
    <div className="flex gap-2 sm:gap-2.5">
      <div
        className={`w-5 h-5 sm:w-6 sm:h-6 rounded-md flex items-center justify-center flex-shrink-0 ${iconBg}`}
      >
        <Icon className={`w-3 h-3 sm:w-3.5 sm:h-3.5 ${accent}`} />
      </div>
      <div className="flex-1 min-w-0">
        <div className={`text-[10px] sm:text-xs font-medium uppercase tracking-wide ${accent} mb-0.5`}>
          {label}
        </div>
        <p className="text-xs sm:text-sm text-surface-200 leading-relaxed">{body}</p>
      </div>
    </div>
  )
}
