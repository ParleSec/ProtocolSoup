/**
 * StepDetail Component
 * 
 * Displays detailed information about a flow step including
 * parameters, security notes, and code examples.
 */

import { motion, AnimatePresence } from 'framer-motion'
import { 
  ArrowRight, Shield, AlertTriangle, Info, Terminal, 
  Copy, Check, Lock, Eye
} from 'lucide-react'
import { useState } from 'react'
import type { LookingGlassStep, LookingGlassParameter, LookingGlassSecurity } from '../types'

interface StepDetailProps {
  step: LookingGlassStep | null
  stepNumber?: number
}

export function StepDetail({ step, stepNumber }: StepDetailProps) {
  const [copied, setCopied] = useState(false)

  if (!step) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <div className="w-16 h-16 rounded-full bg-surface-800 flex items-center justify-center mb-4">
          <Eye className="w-8 h-8 text-surface-600" />
        </div>
        <p className="text-surface-400">Select a step to see details</p>
        <p className="text-surface-400 text-sm mt-1">Click any step in the flow visualization</p>
      </div>
    )
  }

  const copyCode = () => {
    if (step.codeExample) {
      navigator.clipboard.writeText(step.codeExample)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={step.id}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        className="space-y-4"
      >
        {/* Step Header */}
        <div className="flex items-start gap-3">
          <div className="w-12 h-12 rounded-xl bg-indigo-500/20 flex items-center justify-center text-indigo-400 font-bold text-lg">
            {stepNumber ?? step.order}
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-white">{step.name}</h3>
            <p className="text-sm text-surface-400 mt-1">{step.description}</p>
          </div>
        </div>

        {/* Flow Direction */}
        <div className="flex items-center gap-2 p-3 rounded-lg bg-surface-800/50">
          <span className="text-sm text-cyan-400">{step.from}</span>
          <ArrowRight className="w-4 h-4 text-surface-400" />
          <span className="text-sm text-green-400">{step.to}</span>
          <span className="ml-auto text-xs px-2 py-0.5 rounded bg-surface-700 text-surface-400 uppercase">
            {step.type}
          </span>
        </div>

        {/* Parameters */}
        {step.parameters && step.parameters.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-surface-300 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              Parameters
            </h4>
            <div className="space-y-2">
              {step.parameters.map((param, i) => (
                <ParameterItem key={i} parameter={param} />
              ))}
            </div>
          </div>
        )}

        {/* Security Notes */}
        {step.security && step.security.length > 0 && (
          <div className="space-y-2">
            <h4 className="text-sm font-semibold text-surface-300 uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Security Considerations
            </h4>
            <div className="space-y-2">
              {step.security.map((note, i) => (
                <SecurityNote key={i} security={note} />
              ))}
            </div>
          </div>
        )}

        {/* Code Example */}
        {step.codeExample && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-surface-300 uppercase tracking-wider flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                Example
              </h4>
              <button
                onClick={copyCode}
                className="flex items-center gap-1 text-xs text-surface-400 hover:text-white transition-colors"
              >
                {copied ? (
                  <><Check className="w-3.5 h-3.5 text-green-400" /> Copied</>
                ) : (
                  <><Copy className="w-3.5 h-3.5" /> Copy</>
                )}
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-surface-900 border border-white/10 overflow-x-auto">
              <code className="text-xs text-surface-300 font-mono whitespace-pre">
                {step.codeExample}
              </code>
            </pre>
          </div>
        )}
      </motion.div>
    </AnimatePresence>
  )
}

/**
 * Parameter display item
 */
function ParameterItem({ parameter }: { parameter: LookingGlassParameter }) {
  const sensitivityColors = {
    public: 'text-green-400 bg-green-500/10',
    internal: 'text-yellow-400 bg-yellow-500/10',
    secret: 'text-red-400 bg-red-500/10',
  }

  const colors = sensitivityColors[parameter.sensitivity || 'public']

  return (
    <div className="flex items-start gap-2 p-2 rounded-lg bg-surface-800/30">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <code className="text-sm text-cyan-400 font-mono">{parameter.name}</code>
          {parameter.required && (
            <span className="text-[10px] px-1 py-0.5 rounded bg-red-500/20 text-red-400 uppercase">
              required
            </span>
          )}
          {parameter.sensitivity === 'secret' && (
            <Lock className="w-3 h-3 text-red-400" />
          )}
        </div>
        <p className="text-xs text-surface-400 mt-0.5">{parameter.description}</p>
        {parameter.example && (
          <p className="text-xs text-surface-400 mt-1 font-mono">
            Example: <span className="text-surface-400">{parameter.example}</span>
          </p>
        )}
      </div>
      <span className={`text-[10px] px-1.5 py-0.5 rounded ${colors} uppercase`}>
        {parameter.sensitivity || 'public'}
      </span>
    </div>
  )
}

/**
 * Security note display
 */
function SecurityNote({ security }: { security: LookingGlassSecurity }) {
  const typeConfig = {
    info: {
      icon: Info,
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/20',
      iconColor: 'text-blue-400',
      textColor: 'text-blue-200',
    },
    warning: {
      icon: AlertTriangle,
      bg: 'bg-yellow-500/10',
      border: 'border-yellow-500/20',
      iconColor: 'text-yellow-400',
      textColor: 'text-yellow-200',
    },
    critical: {
      icon: AlertTriangle,
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
      iconColor: 'text-red-400',
      textColor: 'text-red-200',
    },
    best_practice: {
      icon: Shield,
      bg: 'bg-green-500/10',
      border: 'border-green-500/20',
      iconColor: 'text-green-400',
      textColor: 'text-green-200',
    },
  }

  const config = typeConfig[security.type]
  const Icon = config.icon

  return (
    <div className={`p-3 rounded-lg ${config.bg} border ${config.border}`}>
      <div className="flex items-start gap-2">
        <Icon className={`w-4 h-4 ${config.iconColor} flex-shrink-0 mt-0.5`} />
        <div>
          <h5 className={`text-sm font-medium ${config.textColor}`}>{security.title}</h5>
          <p className="text-xs text-surface-400 mt-0.5">{security.description}</p>
          {security.reference && (
            <p className="text-xs text-surface-400 mt-1">Ref: {security.reference}</p>
          )}
        </div>
      </div>
    </div>
  )
}

