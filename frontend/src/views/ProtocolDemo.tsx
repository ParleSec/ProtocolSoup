'use client'

import Link from 'next/link'
import { motion } from 'framer-motion'
import { 
  ArrowLeft, ArrowRight, Shield, Key,
  Fingerprint, Zap, Eye, Radio,
  Users, KeyRound
} from 'lucide-react'
import type { FlowDefinition, Protocol } from '../protocols/registry'
import { protocolMeta } from '../protocols/registry'
import { FLOW_PRESENTATION_META, getFeatureDescription } from '../protocols/presentation/flow-meta'
import { getFlowRouteId } from '../protocols/presentation/protocol-catalog-data'

interface ProtocolDemoProps {
  protocolId: string
  protocol: Protocol
  flows: FlowDefinition[]
}

export function ProtocolDemo({
  protocolId,
  protocol,
  flows,
}: ProtocolDemoProps) {

  const meta = protocolMeta[protocolId] || protocolMeta.oauth2
  const getProtocolIcon = (id: string) => {
    switch (id) {
      case 'oidc': return Fingerprint
      case 'oid4vci': return KeyRound
      case 'oid4vp': return Eye
      case 'spiffe': return Shield
      case 'saml': return Key
      case 'scim': return Users
      case 'ssf': return Radio
      default: return Shield
    }
  }
  const ProtocolIcon = getProtocolIcon(protocolId)

  // Get first recommended flow for quick action
  const recommendedFlow = flows.find(f => FLOW_PRESENTATION_META[f.id]?.recommended) || flows[0]

  return (
    <div className="space-y-6 sm:space-y-8 px-1 sm:px-0">
      {/* Header */}
      <div className="flex items-start sm:items-center gap-3 sm:gap-4">
        <Link
          href="/"
          className="p-1.5 sm:p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors flex-shrink-0"
        >
          <ArrowLeft className="w-4 h-4 sm:w-5 sm:h-5" />
        </Link>
        <div className="flex-1 min-w-0">
          <h1 className="font-display text-xl sm:text-3xl font-bold text-white flex items-center gap-2 sm:gap-3">
            <ProtocolIcon className="w-6 h-6 sm:w-8 sm:h-8 text-accent-orange flex-shrink-0" />
            <span className="truncate">{protocol.name}</span>
          </h1>
          <p className="text-surface-400 mt-1.5 sm:mt-2 max-w-3xl text-sm sm:text-base">{protocol.description}</p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="flex flex-col sm:flex-row gap-2 sm:gap-3">
        {recommendedFlow && (
          <Link
            href={`/protocol/${protocolId}/flow/${getFlowRouteId(protocolId, recommendedFlow.id)}`}
            className="inline-flex items-center justify-center gap-2 px-4 sm:px-5 py-2.5 rounded-xl bg-gradient-to-r from-accent-orange to-accent-purple text-white text-sm sm:text-base font-medium hover:opacity-90 transition-opacity"
          >
            <Zap className="w-4 h-4" />
            <span className="hidden sm:inline">Start with Recommended Flow</span>
            <span className="sm:hidden">Recommended Flow</span>
          </Link>
        )}
        <Link
          href={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
          className="inline-flex items-center justify-center gap-2 px-4 sm:px-5 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white text-sm sm:text-base font-medium hover:bg-white/10 transition-colors"
        >
          {protocolId === 'ssf' ? <Radio className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          {protocolId === 'ssf' ? 'Open SSF Sandbox' : 'Open Looking Glass'}
        </Link>
      </div>

      {/* Flows Grid - Data from modular plugins */}
      <div>
        <h2 className="font-display text-lg sm:text-xl font-semibold text-white mb-3 sm:mb-4">
          Available Flows
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
          {flows.map((flow, idx) => {
            const meta = FLOW_PRESENTATION_META[flow.id] || { 
              icon: Shield, 
              color: 'from-gray-500 to-gray-600',
              features: []
            }
            const FlowIcon = meta.icon
            
            return (
              <motion.div
                key={flow.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.1 }}
              >
                <Link
                  href={`/protocol/${protocolId}/flow/${getFlowRouteId(protocolId, flow.id)}`}
                  className="block relative overflow-hidden rounded-xl sm:rounded-2xl p-4 sm:p-6 bg-surface-900/50 border border-white/5 hover:border-white/10 transition-all group hover:shadow-xl"
                >
                  {/* Gradient accent */}
                  <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${meta.color}`} />
                  

                  <div className="flex items-start gap-3 sm:gap-4">
                    <div className={`w-10 h-10 sm:w-14 sm:h-14 rounded-lg sm:rounded-xl bg-gradient-to-br ${meta.color} flex items-center justify-center shadow-lg flex-shrink-0`}>
                      <FlowIcon className="w-5 h-5 sm:w-7 sm:h-7 text-white" />
                    </div>
                    <div className="flex-1 min-w-0 pr-6 sm:pr-8">
                      <h3 className="font-display text-base sm:text-lg font-semibold text-white group-hover:text-white transition-colors">
                        {flow.name}
                      </h3>
                      <p className="text-surface-400 text-xs sm:text-sm mt-1 line-clamp-2">
                        {flow.description}
                      </p>
                    </div>
                  </div>

                  {/* Features */}
                  {meta.features.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 sm:gap-2 mt-3 sm:mt-4">
                      {meta.features.map(feature => (
                        <span 
                          key={feature}
                          className="px-2 sm:px-2.5 py-0.5 sm:py-1 rounded-lg bg-white/5 text-[10px] sm:text-xs text-surface-400"
                        >
                          {feature}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Action hint */}
                  <div className="flex items-center gap-1 mt-3 sm:mt-4 text-xs sm:text-sm text-surface-400 group-hover:text-accent-orange transition-colors">
                    <span>View flow diagram</span>
                    <ArrowRight className="w-3.5 h-3.5 sm:w-4 sm:h-4 group-hover:translate-x-1 transition-transform" />
                  </div>
                </Link>
              </motion.div>
            )
          })}
        </div>
      </div>

      {/* Protocol Features - from modular meta */}
      <div className="glass rounded-xl p-4 sm:p-6">
        <h2 className="font-display text-base sm:text-lg font-semibold text-white mb-3 sm:mb-4">
          {protocol.name} Features
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 sm:gap-4">
          {meta.features.slice(0, 3).map((feature, i) => (
            <FeatureCard
              key={feature}
              title={feature}
              description={getFeatureDescription(feature)}
              color={['blue', 'green', 'purple'][i % 3]}
            />
          ))}
        </div>
      </div>
    </div>
  )
}

export default ProtocolDemo

function FeatureCard({ title, description, color }: {
  title: string
  description: string
  color: string
}) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
    green: 'bg-green-500/10 border-green-500/20 text-green-400',
    purple: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
  }

  return (
    <div className={`p-3 sm:p-4 rounded-xl border ${colorClasses[color]}`}>
      <h3 className="font-medium text-white mb-1 text-sm sm:text-base">{title}</h3>
      <p className="text-xs sm:text-sm text-surface-400">{description}</p>
    </div>
  )
}
