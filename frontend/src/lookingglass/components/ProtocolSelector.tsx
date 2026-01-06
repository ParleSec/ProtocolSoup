/**
 * ProtocolSelector Component
 * 
 * Clean, terminal-style dropdowns for protocol and flow selection.
 * Uses React Portal to ensure dropdowns appear above all other content.
 */

import { AnimatePresence, motion } from 'framer-motion'
import { ChevronDown, Loader2, Check } from 'lucide-react'
import { useState, useRef, useEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'
import type { LookingGlassProtocol, LookingGlassFlow } from '../types'

interface ProtocolSelectorProps {
  protocols: LookingGlassProtocol[]
  selectedProtocol: LookingGlassProtocol | null
  selectedFlow: LookingGlassFlow | null
  onProtocolSelect: (protocol: LookingGlassProtocol) => void
  onFlowSelect: (flow: LookingGlassFlow) => void
  loading?: boolean
}

interface DropdownPosition {
  top: number
  left: number
  width: number
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
  const [protocolDropdownPos, setProtocolDropdownPos] = useState<DropdownPosition | null>(null)
  const [flowDropdownPos, setFlowDropdownPos] = useState<DropdownPosition | null>(null)
  
  const protocolButtonRef = useRef<HTMLButtonElement>(null)
  const flowButtonRef = useRef<HTMLButtonElement>(null)

  const updateProtocolPosition = useCallback(() => {
    if (protocolButtonRef.current) {
      const rect = protocolButtonRef.current.getBoundingClientRect()
      const isMobile = window.innerWidth < 640
      const dropdownWidth = isMobile ? Math.min(rect.width, window.innerWidth - 32) : Math.max(rect.width, 200)
      const leftPos = isMobile ? Math.max(16, rect.left) : rect.left
      setProtocolDropdownPos({
        top: rect.bottom + 4,
        left: leftPos,
        width: dropdownWidth,
      })
    }
  }, [])

  const updateFlowPosition = useCallback(() => {
    if (flowButtonRef.current) {
      const rect = flowButtonRef.current.getBoundingClientRect()
      const isMobile = window.innerWidth < 640
      const dropdownWidth = isMobile ? Math.min(window.innerWidth - 32, 320) : Math.max(rect.width, 280)
      const leftPos = isMobile ? 16 : rect.left
      setFlowDropdownPos({
        top: rect.bottom + 4,
        left: leftPos,
        width: dropdownWidth,
      })
    }
  }, [])

  useEffect(() => {
    if (isProtocolOpen) {
      updateProtocolPosition()
      window.addEventListener('scroll', updateProtocolPosition, true)
      window.addEventListener('resize', updateProtocolPosition)
      return () => {
        window.removeEventListener('scroll', updateProtocolPosition, true)
        window.removeEventListener('resize', updateProtocolPosition)
      }
    }
  }, [isProtocolOpen, updateProtocolPosition])

  useEffect(() => {
    if (isFlowOpen) {
      updateFlowPosition()
      window.addEventListener('scroll', updateFlowPosition, true)
      window.addEventListener('resize', updateFlowPosition)
      return () => {
        window.removeEventListener('scroll', updateFlowPosition, true)
        window.removeEventListener('resize', updateFlowPosition)
      }
    }
  }, [isFlowOpen, updateFlowPosition])

  // Close on click/touch outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node
      if (
        protocolButtonRef.current && 
        !protocolButtonRef.current.contains(target) &&
        !(target as Element).closest?.('[data-protocol-dropdown]')
      ) {
        setIsProtocolOpen(false)
      }
      if (
        flowButtonRef.current && 
        !flowButtonRef.current.contains(target) &&
        !(target as Element).closest?.('[data-flow-dropdown]')
      ) {
        setIsFlowOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('touchstart', handleClickOutside)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('touchstart', handleClickOutside)
    }
  }, [])

  // Close on escape
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsProtocolOpen(false)
        setIsFlowOpen(false)
      }
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [])

  const handleProtocolSelect = (protocol: LookingGlassProtocol) => {
    onProtocolSelect(protocol)
    setIsProtocolOpen(false)
  }

  const handleFlowSelect = (flow: LookingGlassFlow) => {
    onFlowSelect(flow)
    setIsFlowOpen(false)
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-surface-400 text-xs sm:text-sm">
        <Loader2 className="w-3.5 h-3.5 sm:w-4 sm:h-4 animate-spin" />
        <span className="font-mono">loading...</span>
      </div>
    )
  }

  return (
    <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-2 sm:gap-3">
      {/* Protocol Select */}
      <div className="flex items-center gap-1.5 sm:gap-2">
        <span className="text-surface-600 text-xs sm:text-sm font-mono w-14 sm:w-auto flex-shrink-0">protocol:</span>
        <button
          ref={protocolButtonRef}
          onClick={() => {
            setIsFlowOpen(false)
            setIsProtocolOpen(!isProtocolOpen)
          }}
          className="flex items-center gap-2 px-2.5 sm:px-3 py-1.5 sm:py-1.5 rounded bg-surface-900 border border-white/10 hover:border-white/20 active:border-white/30 text-xs sm:text-sm font-mono transition-colors flex-1 sm:flex-initial sm:min-w-[140px] touch-manipulation"
        >
          <span className={`truncate ${selectedProtocol ? 'text-white' : 'text-surface-400'}`}>
            {selectedProtocol?.id || 'select'}
          </span>
          <ChevronDown className={`w-3 h-3 sm:w-3.5 sm:h-3.5 text-surface-400 ml-auto flex-shrink-0 transition-transform ${isProtocolOpen ? 'rotate-180' : ''}`} />
        </button>
      </div>

      {/* Flow Select */}
      <div className="flex items-center gap-1.5 sm:gap-2">
        <span className="text-surface-600 text-xs sm:text-sm font-mono w-14 sm:w-auto flex-shrink-0">flow:</span>
        <button
          ref={flowButtonRef}
          onClick={() => {
            if (!selectedProtocol) return
            setIsProtocolOpen(false)
            setIsFlowOpen(!isFlowOpen)
          }}
          disabled={!selectedProtocol}
          className={`flex items-center gap-2 px-2.5 sm:px-3 py-1.5 sm:py-1.5 rounded bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono transition-colors flex-1 sm:flex-initial sm:min-w-[200px] touch-manipulation ${
            selectedProtocol 
              ? 'hover:border-white/20 active:border-white/30' 
              : 'opacity-50 cursor-not-allowed'
          }`}
        >
          <span className={`${selectedFlow ? 'text-white' : 'text-surface-400'} truncate`}>
            {selectedFlow?.id || 'select'}
          </span>
          <ChevronDown className={`w-3 h-3 sm:w-3.5 sm:h-3.5 text-surface-400 ml-auto flex-shrink-0 transition-transform ${isFlowOpen ? 'rotate-180' : ''}`} />
        </button>
      </div>

      {/* Protocol Dropdown Portal */}
      {createPortal(
        <AnimatePresence>
          {isProtocolOpen && protocolDropdownPos && (
            <motion.div
              data-protocol-dropdown
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.1 }}
              style={{
                position: 'fixed',
                top: protocolDropdownPos.top,
                left: protocolDropdownPos.left,
                width: protocolDropdownPos.width,
                zIndex: 99999,
              }}
              className="rounded border border-white/10 bg-surface-900 shadow-xl overflow-hidden"
            >
              {protocols.map((protocol) => (
                <button
                  key={protocol.id}
                  onClick={() => handleProtocolSelect(protocol)}
                  className={`w-full flex items-center justify-between px-3 py-3 sm:py-2 text-sm font-mono transition-colors touch-manipulation ${
                    selectedProtocol?.id === protocol.id
                      ? 'bg-accent-cyan/10 text-accent-cyan'
                      : 'text-surface-300 hover:bg-white/5 active:bg-white/10 hover:text-white'
                  }`}
                >
                  <span>{protocol.id}</span>
                  {selectedProtocol?.id === protocol.id && (
                    <Check className="w-3.5 h-3.5" />
                  )}
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>,
        document.body
      )}

      {/* Flow Dropdown Portal */}
      {createPortal(
        <AnimatePresence>
          {isFlowOpen && flowDropdownPos && selectedProtocol && (
            <motion.div
              data-flow-dropdown
              initial={{ opacity: 0, y: -4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.1 }}
              style={{
                position: 'fixed',
                top: flowDropdownPos.top,
                left: flowDropdownPos.left,
                width: flowDropdownPos.width,
                zIndex: 99999,
              }}
              className="rounded border border-white/10 bg-surface-900 shadow-xl overflow-hidden max-h-64 overflow-y-auto"
            >
              {selectedProtocol.flows.map((flow) => (
                <button
                  key={flow.id}
                  onClick={() => handleFlowSelect(flow)}
                  className={`w-full flex items-center justify-between px-3 py-3 sm:py-2 text-left transition-colors touch-manipulation ${
                    selectedFlow?.id === flow.id
                      ? 'bg-accent-cyan/10 text-accent-cyan'
                      : 'text-surface-300 hover:bg-white/5 active:bg-white/10 hover:text-white'
                  }`}
                >
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-mono truncate">{flow.id}</div>
                    <div className="text-xs text-surface-400 truncate">{flow.name}</div>
                  </div>
                  {selectedFlow?.id === flow.id && (
                    <Check className="w-3.5 h-3.5 flex-shrink-0 ml-2" />
                  )}
                </button>
              ))}
            </motion.div>
          )}
        </AnimatePresence>,
        document.body
      )}
    </div>
  )
}
