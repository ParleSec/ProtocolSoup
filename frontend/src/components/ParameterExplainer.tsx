'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  HelpCircle,
  Info,
  Bug,
  Zap,
  ShieldCheck,
  ExternalLink,
  AlertCircle,
} from 'lucide-react'
import {
  getParameterExplainer,
  type Attack,
  type FlowDirection,
  type Mitigation,
  type ResolvedParameterExplainer,
} from '@/protocols/explainers'

interface ParameterExplainerProps {
  protocolId: string
  name: string
  value: string
  flowId?: string
  stepOrder?: number
  direction?: FlowDirection
}

export function ParameterExplainer({
  protocolId,
  name,
  value,
  flowId,
  stepOrder,
  direction,
}: ParameterExplainerProps) {
  const [open, setOpen] = useState(false)
  const explainer = getParameterExplainer(protocolId, name, {
    flowId,
    stepOrder,
    direction,
  })

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

function ExplainerPanel({ explainer }: { explainer: ResolvedParameterExplainer }) {
  return (
    <div className="mt-1 sm:mt-1.5 rounded-lg border border-cyan-500/20 bg-cyan-500/[0.03] p-2.5 sm:p-3 space-y-3 sm:space-y-3.5">
      {explainer.contextualNote && (
        <ContextualNote note={explainer.contextualNote} />
      )}

      <PurposeSection body={explainer.purpose} />

      {explainer.attacks.length > 0 && (
        <div className="space-y-3 sm:space-y-3.5">
          {explainer.attacks.map((attack) => {
            const mitigations = explainer.mitigations.filter((m) =>
              m.mitigates.includes(attack.id),
            )
            return (
              <AttackBlock
                key={attack.id}
                attack={attack}
                mitigations={mitigations}
              />
            )
          })}
        </div>
      )}

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

function ContextualNote({ note }: { note: string }) {
  return (
    <div className="flex gap-2 sm:gap-2.5 rounded-md border border-amber-500/20 bg-amber-500/[0.05] p-2 sm:p-2.5">
      <AlertCircle className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-amber-300 flex-shrink-0 mt-0.5" />
      <p className="text-xs sm:text-sm text-amber-100/90 leading-relaxed">
        {note}
      </p>
    </div>
  )
}

function PurposeSection({ body }: { body: string }) {
  return (
    <div className="flex gap-2 sm:gap-2.5">
      <div className="w-5 h-5 sm:w-6 sm:h-6 rounded-md flex items-center justify-center flex-shrink-0 bg-cyan-500/10">
        <Info className="w-3 h-3 sm:w-3.5 sm:h-3.5 text-cyan-300" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-[10px] sm:text-xs font-medium uppercase tracking-wide text-cyan-300 mb-0.5">
          Purpose
        </div>
        <p className="text-xs sm:text-sm text-surface-200 leading-relaxed">
          {body}
        </p>
      </div>
    </div>
  )
}

function AttackBlock({
  attack,
  mitigations,
}: {
  attack: Attack
  mitigations: Mitigation[]
}) {
  return (
    <div className="rounded-md border border-rose-500/15 bg-rose-500/[0.025] p-2.5 sm:p-3 space-y-2 sm:space-y-2.5">
      <div className="flex gap-2 sm:gap-2.5 items-start">
        <div className="w-5 h-5 sm:w-6 sm:h-6 rounded-md flex items-center justify-center flex-shrink-0 bg-rose-500/15">
          <Bug className="w-3 h-3 sm:w-3.5 sm:h-3.5 text-rose-300" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-[11px] sm:text-xs font-semibold uppercase tracking-wide text-rose-300 mb-0.5">
            Attack
          </div>
          <div className="text-xs sm:text-sm font-medium text-rose-100/95 mb-1">
            {attack.name}
          </div>
          <p className="text-xs sm:text-sm text-surface-200 leading-relaxed">
            {attack.scenario}
          </p>
        </div>
      </div>

      <div className="flex gap-2 sm:gap-2.5 items-start ml-1.5 sm:ml-2 pl-4 sm:pl-5 border-l border-rose-500/15">
        <Zap className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-rose-300 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="text-[10px] sm:text-xs font-medium uppercase tracking-wide text-rose-300 mb-0.5">
            Impact
          </div>
          <p className="text-xs sm:text-sm text-surface-200 leading-relaxed">
            {attack.impact}
          </p>
        </div>
      </div>

      {mitigations.length > 0 && (
        <div className="flex gap-2 sm:gap-2.5 items-start ml-1.5 sm:ml-2 pl-4 sm:pl-5 border-l border-emerald-500/20">
          <ShieldCheck className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-300 flex-shrink-0 mt-0.5" />
          <div className="flex-1 min-w-0">
            <div className="text-[10px] sm:text-xs font-medium uppercase tracking-wide text-emerald-300 mb-1">
              Mitigations
            </div>
            <ul className="space-y-1.5">
              {mitigations.map((m, i) => (
                <li
                  key={i}
                  className="text-xs sm:text-sm text-surface-200 leading-relaxed"
                >
                  <span>{m.action}</span>
                  {m.rationale && (
                    <span className="block text-[11px] sm:text-xs text-surface-400 italic mt-0.5">
                      {m.rationale}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
