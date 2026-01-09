import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  User, Globe, Shield, Database, Key, X, Users
} from 'lucide-react'

interface FlowStep {
  order: number
  name: string
  description: string
  from: string
  to: string
  type: string
  parameters?: Record<string, string>
  security?: string[]
}

interface FlowDiagramProps {
  steps: FlowStep[]
  activeStep?: number
  onStepClick?: (step: number) => void
}

// Actor configurations - supports OAuth 2.0, OIDC, SAML, and SPIFFE terminology
const actorConfig: Record<string, { 
  icon: React.ElementType
  label: string
  shortLabel: string
  color: string
}> = {
  'Client': { 
    icon: Globe, 
    label: 'Client Application',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'Client Application': { 
    icon: Globe, 
    label: 'Client Application',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'Client Backend': { 
    icon: Globe, 
    label: 'Client Backend',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'Client (Backend Service)': { 
    icon: Globe, 
    label: 'Client Backend',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'Relying Party (Client)': { 
    icon: Globe, 
    label: 'Relying Party',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'Relying Party Backend': { 
    icon: Globe, 
    label: 'Relying Party Backend',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'User': { 
    icon: User, 
    label: 'Resource Owner',
    shortLabel: 'User',
    color: '#4ade80', // green
  },
  'Resource Owner (User)': { 
    icon: User, 
    label: 'Resource Owner',
    shortLabel: 'User',
    color: '#4ade80', // green
  },
  'End-User': { 
    icon: User, 
    label: 'End-User',
    shortLabel: 'User',
    color: '#4ade80', // green
  },
  'Authorization Server': { 
    icon: Shield, 
    label: 'Authorization Server',
    shortLabel: 'Auth Server',
    color: '#c084fc', // purple
  },
  // OIDC terminology (same as Auth Server but with OIDC naming)
  'OpenID Provider': { 
    icon: Shield, 
    label: 'OpenID Provider',
    shortLabel: 'Auth Server',
    color: '#c084fc', // purple
  },
  'Resource Server': { 
    icon: Database, 
    label: 'Resource Server',
    shortLabel: 'API',
    color: '#fb923c', // orange
  },
  'Resource Server (API)': { 
    icon: Database, 
    label: 'Resource Server',
    shortLabel: 'API',
    color: '#fb923c', // orange
  },
  // For token validation steps (self-referential)
  'Browser': { 
    icon: Globe, 
    label: 'Browser',
    shortLabel: 'Browser',
    color: '#60a5fa', // blue
  },
  // SAML actors
  'Service Provider': { 
    icon: Globe, 
    label: 'Service Provider',
    shortLabel: 'SP',
    color: '#60a5fa', // blue
  },
  'Identity Provider': { 
    icon: Shield, 
    label: 'Identity Provider',
    shortLabel: 'IdP',
    color: '#c084fc', // purple
  },
  'Service Providers': { 
    icon: Database, 
    label: 'Service Providers',
    shortLabel: 'SPs',
    color: '#fb923c', // orange
  },
  'Other Service Providers': { 
    icon: Database, 
    label: 'Other Service Providers',
    shortLabel: 'Other SPs',
    color: '#fb923c', // orange
  },
  'Both Parties': { 
    icon: Shield, 
    label: 'Both Parties',
    shortLabel: 'Both',
    color: '#9ca3af', // gray
  },
  // SPIFFE/SPIRE actors
  'Workload': {
    icon: Globe,
    label: 'Workload',
    shortLabel: 'Workload',
    color: '#60a5fa', // blue
  },
  'SPIRE Agent': {
    icon: Shield,
    label: 'SPIRE Agent',
    shortLabel: 'Agent',
    color: '#4ade80', // green
  },
  'SPIRE Server': {
    icon: Database,
    label: 'SPIRE Server',
    shortLabel: 'Server',
    color: '#c084fc', // purple
  },
  'Key Manager': {
    icon: Key,
    label: 'Key Manager',
    shortLabel: 'Keys',
    color: '#fbbf24', // yellow
  },
  'Certificate Authority': {
    icon: Shield,
    label: 'Certificate Authority',
    shortLabel: 'CA',
    color: '#f472b6', // pink
  },
  'CA': {
    icon: Shield,
    label: 'Certificate Authority',
    shortLabel: 'CA',
    color: '#f472b6', // pink
  },
  'Workload Attestor': {
    icon: Shield,
    label: 'Workload Attestor',
    shortLabel: 'Attestor',
    color: '#fb923c', // orange
  },
  'Registration Cache': {
    icon: Database,
    label: 'Registration Cache',
    shortLabel: 'Registry',
    color: '#9ca3af', // gray
  },
  'JWT Signer': {
    icon: Key,
    label: 'JWT Signer',
    shortLabel: 'Signer',
    color: '#fbbf24', // yellow
  },
  'Trust Bundle': {
    icon: Shield,
    label: 'Trust Bundle',
    shortLabel: 'Bundle',
    color: '#4ade80', // green
  },
  'Server': {
    icon: Database,
    label: 'Server',
    shortLabel: 'Server',
    color: '#c084fc', // purple
  },
  'Client Service': {
    icon: Globe,
    label: 'Client Service',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  'Server Service': {
    icon: Database,
    label: 'Server Service',
    shortLabel: 'Server',
    color: '#c084fc', // purple
  },
  'Both Services': {
    icon: Shield,
    label: 'Both Services',
    shortLabel: 'Both',
    color: '#9ca3af', // gray
  },
  'Both': {
    icon: Shield,
    label: 'Both Parties',
    shortLabel: 'Both',
    color: '#9ca3af', // gray
  },
  'TLS Stack': {
    icon: Shield,
    label: 'TLS Stack',
    shortLabel: 'TLS',
    color: '#4ade80', // green
  },
  'SVID Cache': {
    icon: Database,
    label: 'SVID Cache',
    shortLabel: 'Cache',
    color: '#fb923c', // orange
  },
  // SCIM 2.0 actors
  'SCIM Server': {
    icon: Users,
    label: 'SCIM Server',
    shortLabel: 'SCIM',
    color: '#a855f7', // purple
  },
  'SCIM Client': {
    icon: Globe,
    label: 'SCIM Client',
    shortLabel: 'Client',
    color: '#60a5fa', // blue
  },
  // IdP is a common short form for Identity Provider (used in SCIM flows)
  'IdP': {
    icon: Shield,
    label: 'Identity Provider',
    shortLabel: 'IdP',
    color: '#c084fc', // purple
  },
  // Additional SCIM actors for outbound provisioning flows
  'Admin': {
    icon: User,
    label: 'Administrator',
    shortLabel: 'Admin',
    color: '#4ade80', // green
  },
  'External Server': {
    icon: Database,
    label: 'External SCIM Server',
    shortLabel: 'External',
    color: '#fb923c', // orange
  },
  'Database': {
    icon: Database,
    label: 'Database',
    shortLabel: 'DB',
    color: '#9ca3af', // gray
  },
}

// Message type colors - more muted
const messageColors: Record<string, { stroke: string; label: string }> = {
  'request': { stroke: '#60a5fa', label: 'Request' },
  'response': { stroke: '#4ade80', label: 'Response' },
  'redirect': { stroke: '#fbbf24', label: 'Redirect' },
  'internal': { stroke: '#9ca3af', label: 'Internal' },
}

export function FlowDiagram({ steps, activeStep = -1, onStepClick }: FlowDiagramProps) {
  const [selectedStep, setSelectedStep] = useState<number | null>(null)
  const [hoveredStep, setHoveredStep] = useState<number | null>(null)

  // Get unique actors in order of appearance
  const actors = useMemo(() => {
    const seen = new Set<string>()
    const result: string[] = []
    steps.forEach(step => {
      if (!seen.has(step.from)) {
        seen.add(step.from)
        result.push(step.from)
      }
      if (!seen.has(step.to)) {
        seen.add(step.to)
        result.push(step.to)
      }
    })
    return result.filter(a => actorConfig[a])
  }, [steps])

  const handleStepClick = (order: number) => {
    const newSelection = selectedStep === order ? null : order
    setSelectedStep(newSelection)
    onStepClick?.(newSelection ?? -1)
  }

  // Calculate dimensions - larger for better visibility
  const actorWidth = 120
  const leftPadding = 60  // Extra space for step numbers
  const rightPadding = 40
  const actorSpacing = 180
  const headerHeight = 100
  const rowHeight = 70

  // Get actor center X position
  const getActorCenterX = (actorName: string) => {
    const index = actors.indexOf(actorName)
    return leftPadding + actorWidth / 2 + index * actorSpacing
  }

  const totalWidth = leftPadding + rightPadding + actorWidth + (actors.length - 1) * actorSpacing
  const diagramHeight = headerHeight + steps.length * rowHeight + 40
  
  // Allow full height for flows with many steps (8+ steps need ~700px)
  const maxHeight = Math.max(diagramHeight, 400)

  const selectedStepData = selectedStep !== null ? steps.find(s => s.order === selectedStep) : null

  return (
    <div className="space-y-4">
      {/* Sequence Diagram */}
      <div className="relative overflow-auto">
        <svg 
          viewBox={`0 0 ${totalWidth} ${diagramHeight}`}
          className="w-full"
          style={{ minWidth: 500, maxWidth: Math.max(totalWidth + 40, 800), height: maxHeight, margin: '0 auto', display: 'block' }}
          preserveAspectRatio="xMidYMin meet"
        >
          <defs>
            {/* Arrow markers */}
            {Object.entries(messageColors).map(([type, colors]) => (
              <marker
                key={type}
                id={`arrow-${type}`}
                markerWidth="8"
                markerHeight="6"
                refX="7"
                refY="3"
                orient="auto"
              >
                <path d="M0,0 L8,3 L0,6 L2,3 Z" fill={colors.stroke} />
              </marker>
            ))}
          </defs>

          {/* Actor lifelines */}
          {actors.map((actorName) => {
            const centerX = getActorCenterX(actorName)
            return (
              <line
                key={`lifeline-${actorName}`}
                x1={centerX}
                y1={headerHeight}
                x2={centerX}
                y2={diagramHeight - 10}
                stroke="#374151"
                strokeWidth="1"
                strokeDasharray="6 4"
                opacity="0.6"
              />
            )
          })}

          {/* Actor headers */}
          {actors.map((actorName) => {
            const actor = actorConfig[actorName]
            const centerX = getActorCenterX(actorName)
            const Icon = actor.icon
            
            return (
              <g key={actorName}>
                {/* Actor box */}
                <rect
                  x={centerX - actorWidth / 2}
                  y={12}
                  width={actorWidth}
                  height={65}
                  rx="8"
                  fill="#111827"
                  stroke={actor.color}
                  strokeWidth="1.5"
                  opacity="0.9"
                />
                {/* Icon */}
                <foreignObject x={centerX - 12} y={22} width="24" height="24">
                  <div className="flex items-center justify-center w-full h-full">
                    <Icon className="w-5 h-5" style={{ color: actor.color, opacity: 0.8 }} />
                  </div>
                </foreignObject>
                {/* Label */}
                <text
                  x={centerX}
                  y={68}
                  textAnchor="middle"
                  fill={actor.color}
                  fontSize="13"
                  fontWeight="500"
                  opacity="0.9"
                >
                  {actor.shortLabel}
                </text>
              </g>
            )
          })}

          {/* Messages */}
          {steps.map((step, index) => {
            const fromX = getActorCenterX(step.from)
            const toX = getActorCenterX(step.to)
            const y = headerHeight + index * rowHeight + rowHeight / 2 + 5
            
            const isHovered = hoveredStep === step.order
            const isSelected = selectedStep === step.order
            const isActive = activeStep === step.order
            const highlight = isHovered || isSelected || isActive
            
            const msgColor = messageColors[step.type] || messageColors['request']
            const isSelfMessage = step.from === step.to
            const isLeftToRight = fromX < toX
            const arrowOffset = 6

            return (
              <g 
                key={step.order}
                onClick={() => handleStepClick(step.order)}
                onMouseEnter={() => setHoveredStep(step.order)}
                onMouseLeave={() => setHoveredStep(null)}
                className="cursor-pointer"
                opacity={highlight ? 1 : 0.85}
              >
                {/* Row highlight */}
                {highlight && (
                  <rect
                    x={10}
                    y={y - rowHeight / 2 + 5}
                    width={totalWidth - 20}
                    height={rowHeight - 10}
                    rx="6"
                    fill={msgColor.stroke}
                    fillOpacity="0.08"
                  />
                )}

                {/* Step number */}
                <circle
                  cx={30}
                  cy={y}
                  r="14"
                  fill={highlight ? msgColor.stroke : "#1f2937"}
                  fillOpacity={highlight ? 0.9 : 1}
                  stroke={msgColor.stroke}
                  strokeWidth="1.5"
                  strokeOpacity={highlight ? 1 : 0.5}
                />
                <text
                  x={30}
                  y={y + 4}
                  textAnchor="middle"
                  fill={highlight ? "#fff" : "#9ca3af"}
                  fontSize="11"
                  fontWeight="600"
                >
                  {step.order}
                </text>

                {isSelfMessage ? (
                  // Self-referencing loop
                  <g>
                    <path
                      d={`M ${fromX + 5} ${y - 6}
                          Q ${fromX + 40} ${y - 6},
                            ${fromX + 40} ${y}
                          Q ${fromX + 40} ${y + 6},
                            ${fromX + 5} ${y + 6}`}
                      fill="none"
                      stroke={msgColor.stroke}
                      strokeWidth={highlight ? 2 : 1.5}
                      strokeOpacity={highlight ? 1 : 0.7}
                      markerEnd={`url(#arrow-${step.type})`}
                    />
                    <text
                      x={fromX + 55}
                      y={y + 4}
                      fill={highlight ? "#f3f4f6" : "#9ca3af"}
                      fontSize="12"
                      fontWeight={highlight ? "500" : "400"}
                    >
                      {step.name}
                    </text>
                  </g>
                ) : (
                  // Arrow between actors
                  <g>
                    <line
                      x1={fromX + (isLeftToRight ? arrowOffset : -arrowOffset)}
                      y1={y}
                      x2={toX + (isLeftToRight ? -arrowOffset - 6 : arrowOffset + 6)}
                      y2={y}
                      stroke={msgColor.stroke}
                      strokeWidth={highlight ? 2 : 1.5}
                      strokeOpacity={highlight ? 1 : 0.7}
                      markerEnd={`url(#arrow-${step.type})`}
                    />
                    
                    {/* Message label */}
                    <text
                      x={(fromX + toX) / 2}
                      y={y - 12}
                      textAnchor="middle"
                      fill={highlight ? "#f3f4f6" : "#9ca3af"}
                      fontSize="12"
                      fontWeight={highlight ? "500" : "400"}
                    >
                      {step.name}
                    </text>

                  </g>
                )}
              </g>
            )
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center justify-center gap-6 text-xs text-surface-400 py-2">
        {Object.entries(messageColors).map(([type, config]) => (
          <div key={type} className="flex items-center gap-2">
            <div 
              className="w-8 h-0.5 rounded"
              style={{ backgroundColor: config.stroke, opacity: 0.8 }}
            />
            <span className="capitalize">{config.label}</span>
          </div>
        ))}
      </div>

      {/* Detail Panel */}
      <AnimatePresence>
        {selectedStepData && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="relative rounded-xl border border-white/10 bg-surface-900/80 p-5"
          >
            <button
              onClick={() => setSelectedStep(null)}
              className="absolute top-3 right-3 p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            >
              <X className="w-4 h-4 text-surface-400" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div 
                className="w-9 h-9 rounded-lg flex items-center justify-center font-bold text-sm text-white"
                style={{ backgroundColor: messageColors[selectedStepData.type]?.stroke || '#6366f1', opacity: 0.9 }}
              >
                {selectedStepData.order}
              </div>
              <div>
                <h3 className="font-medium text-white">{selectedStepData.name}</h3>
                <p className="text-xs text-surface-400">
                  {actorConfig[selectedStepData.from]?.shortLabel || selectedStepData.from}
                  {' → '}
                  {actorConfig[selectedStepData.to]?.shortLabel || selectedStepData.to}
                </p>
              </div>
            </div>

            <p className="text-sm text-surface-400 mb-4">{selectedStepData.description}</p>

            {selectedStepData.parameters && Object.keys(selectedStepData.parameters).length > 0 && (
              <div className="mb-4">
                <h4 className="flex items-center gap-2 text-xs font-medium text-surface-400 uppercase tracking-wider mb-2">
                  <Key className="w-3 h-3" />
                  Parameters
                </h4>
                <div className="space-y-1.5">
                  {Object.entries(selectedStepData.parameters).map(([key, value]) => (
                    <div key={key} className="flex gap-3 p-2 rounded-lg bg-surface-800/50 text-sm">
                      <code className="text-cyan-400/80 font-mono text-xs">{key}</code>
                      <span className="text-surface-400 text-xs">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// Re-export flow data from the protocols module for backwards compatibility
// eslint-disable-next-line react-refresh/only-export-components
export { fallbackFlows as flowData } from '../../protocols/fallback-data'
