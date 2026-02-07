import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  User, Globe, Shield, Database, Key, X, Users
} from 'lucide-react'

// Native SVG icon paths for reliable rendering inside SVG (no foreignObject needed)
// Each renders centered at (0,0) within a given size
function SvgActorIcon({ type, cx, cy, size, color }: { 
  type: React.ElementType; cx: number; cy: number; size: number; color: string 
}) {
  const s = size / 2 // half-size for centering
  const opacity = 0.8
  const sw = size * 0.08 // stroke width proportional to size

  // Globe icon
  if (type === Globe) {
    return (
      <g transform={`translate(${cx},${cy})`} opacity={opacity}>
        <circle cx={0} cy={0} r={s * 0.85} fill="none" stroke={color} strokeWidth={sw} />
        <ellipse cx={0} cy={0} rx={s * 0.4} ry={s * 0.85} fill="none" stroke={color} strokeWidth={sw * 0.7} />
        <line x1={-s * 0.85} y1={0} x2={s * 0.85} y2={0} stroke={color} strokeWidth={sw * 0.7} />
      </g>
    )
  }

  // Shield icon
  if (type === Shield) {
    return (
      <g transform={`translate(${cx},${cy})`} opacity={opacity}>
        <path
          d={`M 0 ${-s * 0.9} L ${s * 0.75} ${-s * 0.45} L ${s * 0.75} ${s * 0.2} Q ${s * 0.6} ${s * 0.75} 0 ${s * 0.95} Q ${-s * 0.6} ${s * 0.75} ${-s * 0.75} ${s * 0.2} L ${-s * 0.75} ${-s * 0.45} Z`}
          fill="none" stroke={color} strokeWidth={sw} strokeLinejoin="round"
        />
      </g>
    )
  }

  // User icon
  if (type === User) {
    return (
      <g transform={`translate(${cx},${cy})`} opacity={opacity}>
        <circle cx={0} cy={-s * 0.3} r={s * 0.35} fill="none" stroke={color} strokeWidth={sw} />
        <path
          d={`M ${-s * 0.65} ${s * 0.9} Q ${-s * 0.65} ${s * 0.15} 0 ${s * 0.15} Q ${s * 0.65} ${s * 0.15} ${s * 0.65} ${s * 0.9}`}
          fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round"
        />
      </g>
    )
  }

  // Database icon
  if (type === Database) {
    const ry = s * 0.25
    const top = -s * 0.7
    const bot = s * 0.7
    return (
      <g transform={`translate(${cx},${cy})`} opacity={opacity}>
        <ellipse cx={0} cy={top} rx={s * 0.7} ry={ry} fill="none" stroke={color} strokeWidth={sw} />
        <line x1={-s * 0.7} y1={top} x2={-s * 0.7} y2={bot} stroke={color} strokeWidth={sw} />
        <line x1={s * 0.7} y1={top} x2={s * 0.7} y2={bot} stroke={color} strokeWidth={sw} />
        <path d={`M ${-s * 0.7} ${bot} Q ${-s * 0.7} ${bot + ry} 0 ${bot + ry} Q ${s * 0.7} ${bot + ry} ${s * 0.7} ${bot}`} fill="none" stroke={color} strokeWidth={sw} />
      </g>
    )
  }

  // Key icon
  if (type === Key) {
    return (
      <g transform={`translate(${cx},${cy})`} opacity={opacity}>
        <circle cx={-s * 0.3} cy={0} r={s * 0.4} fill="none" stroke={color} strokeWidth={sw} />
        <line x1={s * 0.1} y1={0} x2={s * 0.85} y2={0} stroke={color} strokeWidth={sw} />
        <line x1={s * 0.6} y1={0} x2={s * 0.6} y2={s * 0.3} stroke={color} strokeWidth={sw} />
        <line x1={s * 0.8} y1={0} x2={s * 0.8} y2={s * 0.25} stroke={color} strokeWidth={sw} />
      </g>
    )
  }

  // Users icon
  if (type === Users) {
    return (
      <g transform={`translate(${cx},${cy})`} opacity={opacity}>
        <circle cx={-s * 0.2} cy={-s * 0.35} r={s * 0.28} fill="none" stroke={color} strokeWidth={sw} />
        <path d={`M ${-s * 0.7} ${s * 0.8} Q ${-s * 0.7} ${s * 0.1} ${-s * 0.2} ${s * 0.1} Q ${s * 0.15} ${s * 0.1} ${s * 0.2} ${s * 0.5}`} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" />
        <circle cx={s * 0.35} cy={-s * 0.25} r={s * 0.24} fill="none" stroke={color} strokeWidth={sw} />
        <path d={`M ${s * 0.0} ${s * 0.85} Q ${s * 0.05} ${s * 0.25} ${s * 0.35} ${s * 0.2} Q ${s * 0.7} ${s * 0.2} ${s * 0.8} ${s * 0.7}`} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" />
      </g>
    )
  }

  // Fallback: simple circle
  return (
    <circle cx={cx} cy={cy} r={s * 0.6} fill="none" stroke={color} strokeWidth={sw} opacity={opacity} />
  )
}

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
  // SSF (Shared Signals Framework) actors
  'Transmitter': {
    icon: Shield,
    label: 'Transmitter',
    shortLabel: 'Transmitter',
    color: '#f59e0b', // amber
  },
  'Receiver': {
    icon: Globe,
    label: 'Receiver',
    shortLabel: 'Receiver',
    color: '#60a5fa', // blue
  },
  'Receiver (RP)': {
    icon: Globe,
    label: 'Receiver (Relying Party)',
    shortLabel: 'Receiver',
    color: '#60a5fa', // blue
  },
  'All Subscribed Receivers': {
    icon: Users,
    label: 'All Subscribed Receivers',
    shortLabel: 'Receivers',
    color: '#60a5fa', // blue
  },
  'Session Store': {
    icon: Database,
    label: 'Session Store',
    shortLabel: 'Sessions',
    color: '#fb923c', // orange
  },
  'Token Store': {
    icon: Database,
    label: 'Token Store',
    shortLabel: 'Tokens',
    color: '#fb923c', // orange
  },
  'User Store': {
    icon: Database,
    label: 'User Store',
    shortLabel: 'Users',
    color: '#a855f7', // purple
  },
  'Access Control': {
    icon: Shield,
    label: 'Access Control',
    shortLabel: 'Access',
    color: '#ef4444', // red
  },
  'Credential Cache': {
    icon: Database,
    label: 'Credential Cache',
    shortLabel: 'Creds',
    color: '#fb923c', // orange
  },
  'Security Operations': {
    icon: Shield,
    label: 'Security Operations',
    shortLabel: 'SecOps',
    color: '#ef4444', // red
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

  // Calculate dimensions - responsive for mobile
  const isMobile = typeof window !== 'undefined' && window.innerWidth < 640
  const actorWidth = isMobile ? 90 : 120
  const leftPadding = isMobile ? 40 : 60  // Extra space for step numbers
  const rightPadding = isMobile ? 20 : 40
  const actorSpacing = isMobile ? 130 : 180
  const headerHeight = isMobile ? 85 : 100
  const rowHeight = isMobile ? 60 : 70

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
      <div className="relative overflow-x-auto overflow-y-hidden scrollbar-hide">
        <svg 
          viewBox={`0 0 ${totalWidth} ${diagramHeight}`}
          className="w-full"
          style={{ minWidth: Math.min(totalWidth, 420), maxWidth: Math.max(totalWidth + 40, 800), height: maxHeight, margin: '0 auto', display: 'block' }}
          preserveAspectRatio="xMinYMin meet"
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
            const boxHeight = isMobile ? 55 : 65
            const fontSize = isMobile ? 11 : 13
            const iconSize = isMobile ? 16 : 20
            const iconCY = 12 + (boxHeight - (isMobile ? 18 : 22)) / 2

            return (
              <g key={actorName}>
                {/* Actor box */}
                <rect
                  x={centerX - actorWidth / 2}
                  y={12}
                  width={actorWidth}
                  height={boxHeight}
                  rx="8"
                  fill="#111827"
                  stroke={actor.color}
                  strokeWidth="1.5"
                  opacity="0.9"
                />
                {/* Icon - native SVG, no foreignObject */}
                <SvgActorIcon
                  type={actor.icon}
                  cx={centerX}
                  cy={iconCY}
                  size={iconSize}
                  color={actor.color}
                />
                {/* Label */}
                <text
                  x={centerX}
                  y={isMobile ? 58 : 68}
                  textAnchor="middle"
                  fill={actor.color}
                  fontSize={fontSize}
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
                  cx={isMobile ? 20 : 30}
                  cy={y}
                  r={isMobile ? 12 : 14}
                  fill={highlight ? msgColor.stroke : "#1f2937"}
                  fillOpacity={highlight ? 0.9 : 1}
                  stroke={msgColor.stroke}
                  strokeWidth="1.5"
                  strokeOpacity={highlight ? 1 : 0.5}
                />
                <text
                  x={isMobile ? 20 : 30}
                  y={y + 4}
                  textAnchor="middle"
                  fill={highlight ? "#fff" : "#9ca3af"}
                  fontSize={isMobile ? "10" : "11"}
                  fontWeight="600"
                >
                  {step.order}
                </text>

                {isSelfMessage ? (
                  // Self-referencing loop
                  <g>
                    <path
                      d={`M ${fromX + 5} ${y - 6}
                          Q ${fromX + (isMobile ? 30 : 40)} ${y - 6},
                            ${fromX + (isMobile ? 30 : 40)} ${y}
                          Q ${fromX + (isMobile ? 30 : 40)} ${y + 6},
                            ${fromX + 5} ${y + 6}`}
                      fill="none"
                      stroke={msgColor.stroke}
                      strokeWidth={highlight ? 2 : 1.5}
                      strokeOpacity={highlight ? 1 : 0.7}
                      markerEnd={`url(#arrow-${step.type})`}
                    />
                    <text
                      x={fromX + (isMobile ? 40 : 55)}
                      y={y + 4}
                      fill={highlight ? "#f3f4f6" : "#9ca3af"}
                      fontSize={isMobile ? "10" : "12"}
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
                      y={y - (isMobile ? 10 : 12)}
                      textAnchor="middle"
                      fill={highlight ? "#f3f4f6" : "#9ca3af"}
                      fontSize={isMobile ? "10" : "12"}
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
      <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 sm:gap-6 text-[10px] sm:text-xs text-surface-400 py-2">
        {Object.entries(messageColors).map(([type, config]) => (
          <div key={type} className="flex items-center gap-1.5 sm:gap-2">
            <div 
              className="w-5 sm:w-8 h-0.5 rounded"
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
            className="relative rounded-xl border border-white/10 bg-surface-900/80 p-3 sm:p-5"
          >
            <button
              onClick={() => setSelectedStep(null)}
              className="absolute top-2 right-2 sm:top-3 sm:right-3 p-1.5 rounded-lg hover:bg-white/5 transition-colors"
            >
              <X className="w-4 h-4 text-surface-400" />
            </button>

            <div className="flex items-center gap-2.5 sm:gap-3 mb-3 sm:mb-4 pr-8">
              <div 
                className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg flex items-center justify-center font-bold text-xs sm:text-sm text-white flex-shrink-0"
                style={{ backgroundColor: messageColors[selectedStepData.type]?.stroke || '#6366f1', opacity: 0.9 }}
              >
                {selectedStepData.order}
              </div>
              <div className="min-w-0">
                <h3 className="font-medium text-white text-sm sm:text-base truncate">{selectedStepData.name}</h3>
                <p className="text-xs text-surface-400">
                  {actorConfig[selectedStepData.from]?.shortLabel || selectedStepData.from}
                  {' → '}
                  {actorConfig[selectedStepData.to]?.shortLabel || selectedStepData.to}
                </p>
              </div>
            </div>

            <p className="text-xs sm:text-sm text-surface-400 mb-3 sm:mb-4">{selectedStepData.description}</p>

            {selectedStepData.parameters && Object.keys(selectedStepData.parameters).length > 0 && (
              <div className="mb-3 sm:mb-4">
                <h4 className="flex items-center gap-2 text-xs font-medium text-surface-400 uppercase tracking-wider mb-2">
                  <Key className="w-3 h-3" />
                  Parameters
                </h4>
                <div className="space-y-1.5">
                  {Object.entries(selectedStepData.parameters).map(([key, value]) => (
                    <div key={key} className="flex flex-col sm:flex-row sm:gap-3 p-2 rounded-lg bg-surface-800/50">
                      <code className="text-cyan-400/80 font-mono text-xs break-all">{key}</code>
                      <span className="text-surface-400 text-xs break-words">{value}</span>
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

