import { useState, useMemo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  ChevronDown, ChevronRight, Copy, Check, 
  ArrowUp, ArrowDown, Clock, Globe, Terminal,
  AlertTriangle, CheckCircle
} from 'lucide-react'

interface RequestViewerProps {
  method: string
  url: string
  headers?: Record<string, string>
  body?: string | object | null | undefined
  response?: {
    status: number
    statusText: string
    headers?: Record<string, string>
    body?: string | object | null | undefined
  }
  duration?: number
  /** Show cURL equivalent */
  showCurl?: boolean
  /** Highlight security-relevant headers */
  highlightSecurity?: boolean
}

// Security-relevant headers to highlight
const SECURITY_HEADERS = [
  'authorization', 'x-csrf-token', 'x-xsrf-token', 'content-security-policy',
  'strict-transport-security', 'x-content-type-options', 'x-frame-options',
  'cache-control', 'pragma', 'www-authenticate', 'set-cookie'
]

export function RequestViewer({ 
  method, 
  url, 
  headers, 
  body, 
  response, 
  duration,
  showCurl = true,
  highlightSecurity = true
}: RequestViewerProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['request']))
  const [copied, setCopied] = useState<string | null>(null)

  // Generate cURL equivalent
  const curlCommand = useMemo(() => {
    let curl = `curl -X ${method.toUpperCase()} '${url}'`
    
    if (headers) {
      Object.entries(headers).forEach(([key, value]) => {
        // Mask authorization header values for security
        const displayValue = key.toLowerCase() === 'authorization' 
          ? value.replace(/Bearer .+/, 'Bearer <TOKEN>')
          : value
        curl += ` \\\n  -H '${key}: ${displayValue}'`
      })
    }
    
    if (body) {
      const bodyStr = typeof body === 'string' ? body : JSON.stringify(body)
      curl += ` \\\n  -d '${bodyStr}'`
    }
    
    return curl
  }, [method, url, headers, body])

  // Check if a header is security-relevant
  const isSecurityHeader = (key: string) => 
    highlightSecurity && SECURITY_HEADERS.includes(key.toLowerCase())

  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections)
    if (newExpanded.has(section)) {
      newExpanded.delete(section)
    } else {
      newExpanded.add(section)
    }
    setExpandedSections(newExpanded)
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopied(id)
    setTimeout(() => setCopied(null), 2000)
  }

  const formatBody = (body: string | object | null | undefined): string => {
    if (!body) return ''
    if (typeof body === 'string') {
      try {
        return JSON.stringify(JSON.parse(body), null, 2)
      } catch {
        return body
      }
    }
    return JSON.stringify(body, null, 2)
  }

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'bg-green-500/20 text-green-400'
      case 'POST':
        return 'bg-blue-500/20 text-blue-400'
      case 'PUT':
        return 'bg-yellow-500/20 text-yellow-400'
      case 'DELETE':
        return 'bg-red-500/20 text-red-400'
      default:
        return 'bg-gray-500/20 text-gray-400'
    }
  }

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-green-400'
    if (status >= 300 && status < 400) return 'text-yellow-400'
    if (status >= 400) return 'text-red-400'
    return 'text-gray-400'
  }

  return (
    <div className="rounded-xl bg-surface-900 border border-white/10 overflow-hidden">
      {/* Summary Header */}
      <div className="flex items-center gap-3 p-4 bg-surface-800 border-b border-white/10">
        <span className={`px-2.5 py-1 rounded-lg text-xs font-bold ${getMethodColor(method)}`}>
          {method.toUpperCase()}
        </span>
        <code className="flex-1 text-sm text-surface-300 font-mono truncate">{url}</code>
        {duration && (
          <span className="flex items-center gap-1 text-xs text-surface-400">
            <Clock className="w-3.5 h-3.5" />
            {duration}ms
          </span>
        )}
        {response && (
          <span className={`flex items-center gap-1 text-sm font-medium ${getStatusColor(response.status)}`}>
            {response.status} {response.statusText}
          </span>
        )}
      </div>

      {/* Request Section */}
      <Section
        title="Request"
        icon={<ArrowUp className="w-4 h-4 text-blue-400" />}
        isExpanded={expandedSections.has('request')}
        onToggle={() => toggleSection('request')}
      >
        {/* Headers */}
        {headers && Object.keys(headers).length > 0 && (
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider">Headers</h4>
              <button
                onClick={() => copyToClipboard(JSON.stringify(headers, null, 2), 'req-headers')}
                className="text-xs text-surface-400 hover:text-white transition-colors"
              >
                {copied === 'req-headers' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <div className="space-y-1">
              {Object.entries(headers).map(([key, value]) => (
                <div key={key} className={`flex gap-2 text-xs font-mono p-1.5 rounded ${
                  isSecurityHeader(key) ? 'bg-yellow-500/10 border border-yellow-500/20' : ''
                }`}>
                  <span className={isSecurityHeader(key) ? 'text-yellow-400' : 'text-cyan-400'}>
                    {key}:
                  </span>
                  <span className="text-surface-300 break-all">{value}</span>
                  {isSecurityHeader(key) && (
                    <span title="Security-relevant header">
                      <AlertTriangle className="w-3 h-3 text-yellow-400 flex-shrink-0" />
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
        
        {/* cURL Command */}
        {showCurl && (
          <div className="mt-4">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5" />
                cURL Equivalent
              </h4>
              <button
                onClick={() => copyToClipboard(curlCommand, 'curl')}
                className="text-xs text-surface-400 hover:text-white transition-colors"
              >
                {copied === 'curl' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-black/30 overflow-x-auto">
              <code className="text-xs text-green-400 font-mono whitespace-pre">
                {curlCommand}
              </code>
            </pre>
          </div>
        )}

        {/* Body */}
        {body && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider">Body</h4>
              <button
                onClick={() => copyToClipboard(formatBody(body), 'req-body')}
                className="text-xs text-surface-400 hover:text-white transition-colors"
              >
                {copied === 'req-body' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-black/30 overflow-x-auto">
              <code className="text-xs text-surface-300 font-mono whitespace-pre">
                {formatBody(body)}
              </code>
            </pre>
          </div>
        )}
      </Section>

      {/* Response Section */}
      {response && (
        <Section
          title="Response"
          icon={<ArrowDown className="w-4 h-4 text-green-400" />}
          isExpanded={expandedSections.has('response')}
          onToggle={() => toggleSection('response')}
        >
          {/* Status with visual indicator */}
          <div className="mb-4 p-3 rounded-lg bg-surface-800/50 flex items-center gap-3">
            {response.status >= 200 && response.status < 300 ? (
              <CheckCircle className="w-5 h-5 text-green-400" />
            ) : response.status >= 400 ? (
              <AlertTriangle className="w-5 h-5 text-red-400" />
            ) : (
              <Globe className="w-5 h-5 text-yellow-400" />
            )}
            <div>
              <span className={`text-lg font-bold ${getStatusColor(response.status)}`}>
                {response.status}
              </span>
              <span className="text-surface-400 ml-2">{response.statusText}</span>
            </div>
            {duration && (
              <span className="ml-auto text-xs text-surface-400">
                {duration}ms
              </span>
            )}
          </div>

          {/* Headers */}
          {response.headers && Object.keys(response.headers).length > 0 && (
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider">Headers</h4>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(response.headers, null, 2), 'res-headers')}
                  className="text-xs text-surface-400 hover:text-white transition-colors"
                >
                  {copied === 'res-headers' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="space-y-1">
                {Object.entries(response.headers).map(([key, value]) => (
                  <div key={key} className={`flex gap-2 text-xs font-mono p-1.5 rounded ${
                    isSecurityHeader(key) ? 'bg-yellow-500/10 border border-yellow-500/20' : ''
                  }`}>
                    <span className={isSecurityHeader(key) ? 'text-yellow-400' : 'text-cyan-400'}>
                      {key}:
                    </span>
                    <span className="text-surface-300 break-all">{value}</span>
                    {isSecurityHeader(key) && (
                      <span title="Security-relevant header">
                        <AlertTriangle className="w-3 h-3 text-yellow-400 flex-shrink-0" />
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Body */}
          {response.body && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider">Body</h4>
                <button
                  onClick={() => copyToClipboard(formatBody(response.body), 'res-body')}
                  className="text-xs text-surface-400 hover:text-white transition-colors"
                >
                  {copied === 'res-body' ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-black/30 overflow-x-auto">
                <code className="text-xs text-surface-300 font-mono whitespace-pre">
                  {formatBody(response.body)}
                </code>
              </pre>
            </div>
          )}
        </Section>
      )}
    </div>
  )
}

// Section component
function Section({ 
  title, 
  icon, 
  isExpanded, 
  onToggle, 
  children 
}: {
  title: string
  icon: React.ReactNode
  isExpanded: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  return (
    <div className="border-b border-white/5 last:border-0">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-white/5 transition-colors"
      >
        {icon}
        <span className="flex-1 font-medium text-white">{title}</span>
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-surface-400" />
        ) : (
          <ChevronRight className="w-4 h-4 text-surface-400" />
        )}
      </button>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4">
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
