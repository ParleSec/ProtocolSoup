/**
 * ProtocolSelector Component
 * 
 * Allows users to select a protocol and flow for inspection.
 */

import { motion, AnimatePresence } from 'framer-motion'
import { 
  ChevronDown, Key, Shield, Fingerprint, Smartphone, Lock,
  Play, Eye, ChevronRight, Loader2
} from 'lucide-react'
import { useState } from 'react'
import type { LookingGlassProtocol, LookingGlassFlow } from '../types'

interface ProtocolSelectorProps {
  protocols: LookingGlassProtocol[]
  selectedProtocol: LookingGlassProtocol | null
  selectedFlow: LookingGlassFlow | null
  onProtocolSelect: (protocol: LookingGlassProtocol) => void
  onFlowSelect: (flow: LookingGlassFlow) => void
  loading?: boolean
}

// Protocol icons
const protocolIcons: Record<string, React.ElementType> = {
  oauth2: Key,
  oidc: Fingerprint,
  saml: Shield,
  webauthn: Smartphone,
  fido2: Lock,
}

// Protocol colors
const protocolColors: Record<string, string> = {
  oauth2: 'from-blue-500 to-cyan-500',
  oidc: 'from-orange-500 to-yellow-500',
  saml: 'from-purple-500 to-pink-500',
  webauthn: 'from-green-500 to-emerald-500',
  fido2: 'from-cyan-500 to-teal-500',
}

export function ProtocolSelector({
  protocols,
  selectedProtocol,
  selectedFlow,
  onProtocolSelect,
  onFlowSelect,
  loading = false,
}: ProtocolSelectorProps) {
  const [isProtocolOpen, setIsProtocolOpen] = useState(false)
  const [isFlowOpen, setIsFlowOpen] = useState(false)

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="w-6 h-6 text-accent-cyan animate-spin" />
        <span className="ml-2 text-surface-400">Loading protocols...</span>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Click outside to close dropdowns */}
      {(isProtocolOpen || isFlowOpen) && (
        <div 
          className="fixed inset-0 z-40" 
          onClick={() => {
            setIsProtocolOpen(false)
            setIsFlowOpen(false)
          }}
        />
      )}

      {/* Protocol Selector */}
      <div className="relative z-10">
        <label className="block text-sm font-medium text-surface-400 mb-2">
          Protocol
        </label>
        <button
          onClick={() => setIsProtocolOpen(!isProtocolOpen)}
          className="w-full flex items-center justify-between gap-3 p-4 rounded-xl bg-surface-800/50 border border-white/10 hover:border-white/20 transition-colors"
        >
          {selectedProtocol ? (
            <div className="flex items-center gap-3">
              <ProtocolIcon protocolId={selectedProtocol.id} />
              <div className="text-left">
                <p className="font-medium text-white">{selectedProtocol.name}</p>
                <p className="text-xs text-surface-400">{selectedProtocol.version}</p>
              </div>
            </div>
          ) : (
            <span className="text-surface-500">Select a protocol...</span>
          )}
          <ChevronDown className={`w-5 h-5 text-surface-400 transition-transform ${
            isProtocolOpen ? 'rotate-180' : ''
          }`} />
        </button>

        <AnimatePresence>
          {isProtocolOpen && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="absolute z-50 w-full mt-2 py-2 rounded-xl bg-surface-900 border border-white/10 shadow-2xl backdrop-blur-sm"
            >
              {protocols.map(protocol => (
                <button
                  key={protocol.id}
                  onClick={() => {
                    onProtocolSelect(protocol)
                    setIsProtocolOpen(false)
                    setIsFlowOpen(false)
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-white/5 transition-colors ${
                    selectedProtocol?.id === protocol.id ? 'bg-white/5' : ''
                  }`}
                >
                  <ProtocolIcon protocolId={protocol.id} />
                  <div className="text-left flex-1">
                    <p className="font-medium text-white">{protocol.name}</p>
                    <p className="text-xs text-surface-400">{protocol.description}</p>
                  </div>
                  <span className="text-xs text-surface-500">
                    {protocol.flows.length} flow{protocol.flows.length !== 1 ? 's' : ''}
                  </span>
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Flow Selector */}
      {selectedProtocol && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="relative z-10"
        >
          <label className="block text-sm font-medium text-surface-400 mb-2">
            Flow
          </label>
          <button
            onClick={() => setIsFlowOpen(!isFlowOpen)}
            className="w-full flex items-center justify-between gap-3 p-4 rounded-xl bg-surface-800/50 border border-white/10 hover:border-white/20 transition-colors"
          >
            {selectedFlow ? (
              <div className="text-left">
                <p className="font-medium text-white">{selectedFlow.name}</p>
                <p className="text-xs text-surface-400 line-clamp-1">{selectedFlow.description}</p>
              </div>
            ) : (
              <span className="text-surface-500">Select a flow...</span>
            )}
            <ChevronDown className={`w-5 h-5 text-surface-400 transition-transform ${
              isFlowOpen ? 'rotate-180' : ''
            }`} />
          </button>

          <AnimatePresence>
            {isFlowOpen && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="absolute z-50 w-full mt-2 py-2 rounded-xl bg-surface-900 border border-white/10 shadow-2xl backdrop-blur-sm max-h-[300px] overflow-y-auto"
              >
                {selectedProtocol.flows.map(flow => (
                  <button
                    key={flow.id}
                    onClick={() => {
                      onFlowSelect(flow)
                      setIsFlowOpen(false)
                    }}
                    className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-white/5 transition-colors ${
                      selectedFlow?.id === flow.id ? 'bg-white/5' : ''
                    }`}
                  >
                    <div className="w-8 h-8 rounded-lg bg-surface-700 flex items-center justify-center">
                      <Play className="w-4 h-4 text-surface-400" />
                    </div>
                    <div className="text-left flex-1">
                      <p className="font-medium text-white">{flow.name}</p>
                      <p className="text-xs text-surface-400 line-clamp-1">{flow.description}</p>
                    </div>
                    <span className="text-xs text-surface-500">
                      {flow.steps.length} steps
                    </span>
                    <ChevronRight className="w-4 h-4 text-surface-500" />
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      )}

      {/* Quick Summary */}
      {selectedFlow && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="p-4 rounded-xl bg-gradient-to-r from-surface-800/50 to-surface-800/30 border border-white/5"
        >
          <div className="flex items-center gap-3 mb-3">
            <Eye className="w-5 h-5 text-accent-cyan" />
            <span className="font-medium text-white">Ready to Inspect</span>
          </div>
          <p className="text-sm text-surface-400">
            {selectedFlow.description}
          </p>
          <div className="flex items-center gap-4 mt-3 text-xs text-surface-500">
            <span>{selectedFlow.steps.length} steps</span>
            {selectedFlow.reference && (
              <span>Ref: {selectedFlow.reference}</span>
            )}
          </div>
        </motion.div>
      )}
    </div>
  )
}

/**
 * Protocol icon with gradient background
 */
function ProtocolIcon({ protocolId }: { protocolId: string }) {
  const Icon = protocolIcons[protocolId] || Key
  const gradient = protocolColors[protocolId] || 'from-gray-500 to-gray-600'

  return (
    <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${gradient} flex items-center justify-center`}>
      <Icon className="w-5 h-5 text-white" />
    </div>
  )
}

/**
 * Compact protocol/flow badge for headers
 */
export function ProtocolFlowBadge({
  protocol,
  flow,
}: {
  protocol: LookingGlassProtocol | null
  flow: LookingGlassFlow | null
}) {
  if (!protocol) return null

  return (
    <div className="flex items-center gap-2">
      <ProtocolIcon protocolId={protocol.id} />
      <div className="text-sm">
        <span className="text-white font-medium">{protocol.name}</span>
        {flow && (
          <>
            <span className="text-surface-500 mx-1">/</span>
            <span className="text-surface-300">{flow.name}</span>
          </>
        )}
      </div>
    </div>
  )
}

/**
 * Flow card for grid display
 */
export function FlowCard({
  flow,
  protocol,
  onClick,
  isSelected,
}: {
  flow: LookingGlassFlow
  protocol: LookingGlassProtocol
  onClick: () => void
  isSelected?: boolean
}) {
  const gradient = protocolColors[protocol.id] || 'from-gray-500 to-gray-600'

  return (
    <motion.button
      onClick={onClick}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      className={`w-full p-4 rounded-xl text-left transition-all ${
        isSelected
          ? 'bg-indigo-500/10 border-2 border-indigo-500/50'
          : 'bg-surface-800/50 border border-white/10 hover:border-white/20'
      }`}
    >
      <div className="flex items-start gap-3">
        <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${gradient} flex items-center justify-center flex-shrink-0`}>
          <Play className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="font-medium text-white truncate">{flow.name}</h3>
          <p className="text-xs text-surface-400 mt-0.5 line-clamp-2">{flow.description}</p>
          <div className="flex items-center gap-3 mt-2 text-xs text-surface-500">
            <span>{flow.steps.length} steps</span>
            <span className="w-1 h-1 rounded-full bg-surface-600" />
            <span className="truncate">{protocol.name}</span>
          </div>
        </div>
      </div>
    </motion.button>
  )
}

