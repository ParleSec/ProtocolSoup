/**
 * FlowVisualizer Component
 * 
 * Protocol-agnostic flow visualization that works with any LookingGlassFlow.
 * Renders steps as an interactive progress indicator.
 */

import { motion } from 'framer-motion'
import { 
  CheckCircle, User, Shield, Key, Database, Globe, Server
} from 'lucide-react'
import type { LookingGlassFlow, LookingGlassStep, LookingGlassActor } from '../types'

interface FlowVisualizerProps {
  flow: LookingGlassFlow
  actors: LookingGlassActor[]
  currentStepIndex: number
  completedSteps: Set<number>
  onStepClick?: (step: LookingGlassStep, index: number) => void
  selectedStepIndex?: number
  isAnimating?: boolean
}

// Actor icon mapping
const actorIcons: Record<string, React.ElementType> = {
  client: Globe,
  user: User,
  auth_server: Shield,
  idp: Key,
  resource_server: Database,
  server: Server,
}

// Step type colors
const stepTypeColors: Record<string, { bg: string; border: string; text: string }> = {
  request: { bg: 'bg-blue-500/20', border: 'border-blue-500', text: 'text-blue-400' },
  response: { bg: 'bg-green-500/20', border: 'border-green-500', text: 'text-green-400' },
  redirect: { bg: 'bg-yellow-500/20', border: 'border-yellow-500', text: 'text-yellow-400' },
  internal: { bg: 'bg-purple-500/20', border: 'border-purple-500', text: 'text-purple-400' },
  user_action: { bg: 'bg-cyan-500/20', border: 'border-cyan-500', text: 'text-cyan-400' },
}

export function FlowVisualizer({
  flow,
  actors,
  currentStepIndex,
  completedSteps,
  onStepClick,
  selectedStepIndex,
  isAnimating = false,
}: FlowVisualizerProps) {
  const totalSteps = flow.steps.length

  return (
    <div className="space-y-6">
      {/* Progress Bar */}
      <div className="relative">
        <div className="absolute top-6 left-0 right-0 h-0.5 bg-surface-700">
          <motion.div
            className="h-full bg-gradient-to-r from-cyan-500 to-green-500"
            initial={{ width: '0%' }}
            animate={{ width: `${(completedSteps.size / totalSteps) * 100}%` }}
            transition={{ duration: 0.5 }}
          />
        </div>

        {/* Step Nodes */}
        <div className="relative flex justify-between">
          {flow.steps.map((step, index) => {
            const isCompleted = completedSteps.has(index)
            const isCurrent = index === currentStepIndex && isAnimating
            const isSelected = index === selectedStepIndex
            const colors = stepTypeColors[step.type] || stepTypeColors.request

            return (
              <button
                key={step.id}
                onClick={() => onStepClick?.(step, index)}
                className="flex flex-col items-center gap-2 group z-10"
                title={step.name}
              >
                <motion.div
                  className={`w-12 h-12 rounded-full flex items-center justify-center border-2 transition-all ${
                    isSelected
                      ? `${colors.bg} ${colors.border} ${colors.text}`
                      : isCompleted
                      ? 'bg-green-500/20 border-green-500 text-green-400'
                      : isCurrent
                      ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400 animate-pulse'
                      : 'bg-surface-800 border-surface-700 text-surface-400 group-hover:border-surface-500'
                  }`}
                  animate={isCurrent ? { scale: [1, 1.1, 1] } : {}}
                  transition={{ repeat: Infinity, duration: 1 }}
                >
                  {isCompleted && !isSelected ? (
                    <CheckCircle className="w-5 h-5" />
                  ) : (
                    <span className="text-sm font-bold">{index + 1}</span>
                  )}
                </motion.div>
                <span className={`text-xs font-medium text-center max-w-[80px] line-clamp-2 ${
                  isSelected ? 'text-white' : 'text-surface-400'
                }`}>
                  {step.name}
                </span>
              </button>
            )
          })}
        </div>
      </div>

      {/* Actors Legend */}
      <div className="flex flex-wrap gap-3 justify-center pt-4 border-t border-white/10">
        {actors.map(actor => {
          const Icon = actorIcons[actor.type] || Server
          return (
            <div
              key={actor.id}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-800/50 text-sm"
            >
              <Icon className="w-4 h-4 text-surface-400" />
              <span className="text-surface-300">{actor.name}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/**
 * Compact flow progress indicator
 */
export function FlowProgressBar({
  flow,
  currentStepIndex,
  completedSteps,
}: {
  flow: LookingGlassFlow
  currentStepIndex: number
  completedSteps: Set<number>
}) {
  const progress = (completedSteps.size / flow.steps.length) * 100

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-surface-400">
        <span>Progress</span>
        <span>{completedSteps.size} / {flow.steps.length} steps</span>
      </div>
      <div className="h-2 bg-surface-800 rounded-full overflow-hidden">
        <motion.div
          className="h-full bg-gradient-to-r from-cyan-500 to-green-500"
          initial={{ width: 0 }}
          animate={{ width: `${progress}%` }}
          transition={{ duration: 0.3 }}
        />
      </div>
      {currentStepIndex >= 0 && currentStepIndex < flow.steps.length && (
        <p className="text-sm text-surface-300">
          Current: <span className="text-white">{flow.steps[currentStepIndex].name}</span>
        </p>
      )}
    </div>
  )
}

/**
 * Mini step indicator for compact displays
 */
export function StepIndicator({
  step,
  index,
  isCompleted,
  isCurrent,
  isSelected,
  onClick,
}: {
  step: LookingGlassStep
  index: number
  isCompleted: boolean
  isCurrent: boolean
  isSelected: boolean
  onClick?: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all ${
        isSelected
          ? 'bg-indigo-500 text-white'
          : isCompleted
          ? 'bg-green-500/20 text-green-400 border border-green-500/50'
          : isCurrent
          ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 animate-pulse'
          : 'bg-surface-800 text-surface-400 hover:bg-surface-700'
      }`}
      title={step.name}
    >
      {isCompleted ? <CheckCircle className="w-4 h-4" /> : index + 1}
    </button>
  )
}

