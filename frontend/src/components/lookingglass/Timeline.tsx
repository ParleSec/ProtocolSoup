import { motion, AnimatePresence } from 'framer-motion'
import { 
  CheckCircle, XCircle, Clock, AlertTriangle, ChevronRight,
  Key, ArrowRightLeft, Shield, Lock, FileCode, Send, Download
} from 'lucide-react'

export interface TimelineEvent {
  id: string
  type: string
  timestamp: Date
  status: 'success' | 'error' | 'pending' | 'warning'
  title: string
  description?: string
  duration?: number
  data?: Record<string, unknown>
  /** Category for icon selection */
  category?: 'auth' | 'token' | 'request' | 'response' | 'security' | 'crypto'
}

interface TimelineProps {
  events: TimelineEvent[]
  onEventClick?: (event: TimelineEvent) => void
  selectedEventId?: string
  /** Show live indicator for real-time events */
  isLive?: boolean
  /** Maximum events to display */
  maxEvents?: number
}

export function Timeline({ 
  events, 
  onEventClick, 
  selectedEventId,
  isLive = false,
  maxEvents
}: TimelineProps) {
  // Limit events if maxEvents specified
  const displayEvents = maxEvents ? events.slice(-maxEvents) : events

  const getStatusIcon = (status: TimelineEvent['status']) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="w-4 h-4 text-green-400" />
      case 'error':
        return <XCircle className="w-4 h-4 text-red-400" />
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />
      default:
        return <Clock className="w-4 h-4 text-blue-400 animate-spin" />
    }
  }

  const getCategoryIcon = (category?: TimelineEvent['category'], eventType?: string) => {
    // Use event type to determine icon if category not provided
    if (!category && eventType) {
      if (eventType.includes('token')) return <Key className="w-4 h-4" />
      if (eventType.includes('request')) return <Send className="w-4 h-4" />
      if (eventType.includes('response')) return <Download className="w-4 h-4" />
      if (eventType.includes('security')) return <Shield className="w-4 h-4" />
      if (eventType.includes('crypto')) return <Lock className="w-4 h-4" />
      if (eventType.includes('flow')) return <ArrowRightLeft className="w-4 h-4" />
    }
    
    switch (category) {
      case 'auth':
        return <Key className="w-4 h-4" />
      case 'token':
        return <FileCode className="w-4 h-4" />
      case 'request':
        return <Send className="w-4 h-4" />
      case 'response':
        return <Download className="w-4 h-4" />
      case 'security':
        return <Shield className="w-4 h-4" />
      case 'crypto':
        return <Lock className="w-4 h-4" />
      default:
        return <ArrowRightLeft className="w-4 h-4" />
    }
  }

  const getStatusColor = (status: TimelineEvent['status']) => {
    switch (status) {
      case 'success':
        return 'bg-green-500/20 border-green-500/30'
      case 'error':
        return 'bg-red-500/20 border-red-500/30'
      case 'warning':
        return 'bg-yellow-500/20 border-yellow-500/30'
      default:
        return 'bg-blue-500/20 border-blue-500/30'
    }
  }

  if (displayEvents.length === 0) {
    return (
      <div className="text-center py-12 text-surface-400">
        <Clock className="w-12 h-12 mx-auto mb-3 opacity-50" />
        <p>No events yet</p>
        <p className="text-sm mt-1">Start a demo flow to see events appear here</p>
        {isLive && (
          <div className="mt-4 flex items-center justify-center gap-2">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs text-green-400">Listening for events...</span>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* Live indicator */}
      {isLive && (
        <div className="flex items-center gap-2 p-2 rounded-lg bg-green-500/10 border border-green-500/20">
          <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-xs text-green-400 font-medium">Live</span>
          <span className="text-xs text-surface-400 ml-auto">
            {displayEvents.length} event{displayEvents.length !== 1 ? 's' : ''}
          </span>
        </div>
      )}
      
      <AnimatePresence mode="popLayout">
        {displayEvents.map((event, index) => (
          <motion.div
            key={event.id}
            layout
            initial={{ opacity: 0, x: -20, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 20, scale: 0.95 }}
            transition={{ 
              type: 'spring', 
              stiffness: 500, 
              damping: 30,
              delay: index * 0.02 
            }}
            onClick={() => onEventClick?.(event)}
            className={`relative flex items-start gap-3 p-4 rounded-xl border cursor-pointer transition-all ${
              selectedEventId === event.id
                ? 'bg-indigo-500/10 border-indigo-500/30 ring-2 ring-indigo-500/20'
                : `${getStatusColor(event.status)} hover:bg-white/5`
            }`}
          >
            {/* Timeline connector */}
            {index < displayEvents.length - 1 && (
              <div className="absolute left-[1.625rem] top-14 bottom-0 w-0.5 bg-surface-700" />
            )}

            {/* Category icon */}
            <div className={`w-8 h-8 rounded-full flex items-center justify-center ${getStatusColor(event.status)}`}>
              {getCategoryIcon(event.category, event.type)}
            </div>

            {/* Status badge */}
            <div className="absolute top-3 right-3">
              {getStatusIcon(event.status)}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0 pr-8">
              <div className="flex items-center gap-2 mb-1">
                <h4 className="font-medium text-white truncate">{event.title}</h4>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-700 text-surface-400 uppercase tracking-wide">
                  {event.type.split('.').pop()}
                </span>
              </div>
              {event.description && (
                <p className="text-sm text-surface-400 line-clamp-2">{event.description}</p>
              )}
              <div className="flex items-center gap-3 mt-2">
                <p className="text-xs text-surface-400">
                  {event.timestamp.toLocaleTimeString(undefined, { 
                    hour: '2-digit', 
                    minute: '2-digit', 
                    second: '2-digit'
                  })}.{event.timestamp.getMilliseconds().toString().padStart(3, '0')}
                </p>
                {event.duration && (
                  <span className="text-xs text-surface-400 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {event.duration}ms
                  </span>
                )}
              </div>
            </div>

            {/* Expand indicator */}
            <ChevronRight className={`w-5 h-5 text-surface-400 transition-transform absolute right-4 bottom-4 ${
              selectedEventId === event.id ? 'rotate-90' : ''
            }`} />
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
