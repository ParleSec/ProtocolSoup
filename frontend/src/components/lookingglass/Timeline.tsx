import { motion } from 'framer-motion'
import { CheckCircle, XCircle, Clock, AlertTriangle, ChevronRight } from 'lucide-react'

export interface TimelineEvent {
  id: string
  type: string
  timestamp: Date
  status: 'success' | 'error' | 'pending' | 'warning'
  title: string
  description?: string
  duration?: number
  data?: Record<string, unknown>
}

interface TimelineProps {
  events: TimelineEvent[]
  onEventClick?: (event: TimelineEvent) => void
  selectedEventId?: string
}

export function Timeline({ events, onEventClick, selectedEventId }: TimelineProps) {
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

  if (events.length === 0) {
    return (
      <div className="text-center py-12 text-surface-500">
        <Clock className="w-12 h-12 mx-auto mb-3 opacity-50" />
        <p>No events yet</p>
        <p className="text-sm mt-1">Start a demo flow to see events appear here</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {events.map((event, index) => (
        <motion.div
          key={event.id}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.05 }}
          onClick={() => onEventClick?.(event)}
          className={`relative flex items-start gap-3 p-4 rounded-xl border cursor-pointer transition-all ${
            selectedEventId === event.id
              ? 'bg-indigo-500/10 border-indigo-500/30'
              : `${getStatusColor(event.status)} hover:bg-white/5`
          }`}
        >
          {/* Timeline connector */}
          {index < events.length - 1 && (
            <div className="absolute left-[1.625rem] top-14 bottom-0 w-0.5 bg-surface-700" />
          )}

          {/* Status indicator */}
          <div className={`w-8 h-8 rounded-full flex items-center justify-center ${getStatusColor(event.status)}`}>
            {getStatusIcon(event.status)}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2 mb-1">
              <h4 className="font-medium text-white truncate">{event.title}</h4>
              {event.duration && (
                <span className="text-xs text-surface-500 whitespace-nowrap">
                  {event.duration}ms
                </span>
              )}
            </div>
            {event.description && (
              <p className="text-sm text-surface-400 line-clamp-2">{event.description}</p>
            )}
            <p className="text-xs text-surface-500 mt-1">
              {event.timestamp.toLocaleTimeString()}
            </p>
          </div>

          {/* Expand indicator */}
          <ChevronRight className={`w-5 h-5 text-surface-500 transition-transform ${
            selectedEventId === event.id ? 'rotate-90' : ''
          }`} />
        </motion.div>
      ))}
    </div>
  )
}
