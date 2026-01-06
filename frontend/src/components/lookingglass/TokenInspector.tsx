import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Shield, AlertTriangle, CheckCircle, XCircle, Clock, 
  User, Key, Lock, Globe, Info, ChevronDown, Copy, Check,
  FileText, Fingerprint, Calendar
} from 'lucide-react'

interface TokenInspectorProps {
  token: string
}

interface DecodedToken {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  isValid: boolean
  error?: string
}

// Standard JWT claim explanations
const claimInfo: Record<string, { label: string; description: string; icon: React.ElementType }> = {
  iss: { label: 'Issuer', description: 'Entity that issued the token', icon: Globe },
  sub: { label: 'Subject', description: 'Unique identifier of the user', icon: User },
  aud: { label: 'Audience', description: 'Intended recipient (your app)', icon: FileText },
  exp: { label: 'Expiration', description: 'When the token expires', icon: Clock },
  nbf: { label: 'Not Before', description: 'Token not valid before this time', icon: Calendar },
  iat: { label: 'Issued At', description: 'When the token was created', icon: Calendar },
  jti: { label: 'Token ID', description: 'Unique identifier for this token', icon: Fingerprint },
  nonce: { label: 'Nonce', description: 'Replay attack prevention (OIDC)', icon: Lock },
  azp: { label: 'Authorized Party', description: 'Client ID the token was issued to', icon: Key },
  scope: { label: 'Scope', description: 'Permissions granted to this token', icon: Shield },
  email: { label: 'Email', description: 'User\'s email address', icon: User },
  name: { label: 'Name', description: 'User\'s full name', icon: User },
  preferred_username: { label: 'Username', description: 'User\'s preferred username', icon: User },
  email_verified: { label: 'Email Verified', description: 'Whether email has been verified', icon: CheckCircle },
}

export function TokenInspector({ token }: TokenInspectorProps) {
  const [expandedSection, setExpandedSection] = useState<'header' | 'payload' | 'signature' | null>('payload')
  const [copiedClaim, setCopiedClaim] = useState<string | null>(null)

  const decoded = useMemo((): DecodedToken | null => {
    if (!token || !token.includes('.')) return null

    try {
      const parts = token.split('.')
      if (parts.length !== 3) {
        return {
          header: {},
          payload: {},
          signature: '',
          isValid: false,
          error: 'Invalid JWT format: expected 3 parts separated by dots'
        }
      }

      const [headerB64, payloadB64, signature] = parts

      const decodeBase64Url = (str: string): string => {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
        const padding = '='.repeat((4 - (base64.length % 4)) % 4)
        return atob(base64 + padding)
      }

      const header = JSON.parse(decodeBase64Url(headerB64))
      const payload = JSON.parse(decodeBase64Url(payloadB64))

      // Check expiration
      const isExpired = payload.exp && Date.now() / 1000 > payload.exp
      const isNotYetValid = payload.nbf && Date.now() / 1000 < payload.nbf

      return {
        header,
        payload,
        signature,
        isValid: !isExpired && !isNotYetValid,
        error: isExpired ? 'Token has expired' : isNotYetValid ? 'Token is not yet valid' : undefined
      }
    } catch (e) {
      return {
        header: {},
        payload: {},
        signature: '',
        isValid: false,
        error: `Failed to decode token: ${e instanceof Error ? e.message : 'Unknown error'}`
      }
    }
  }, [token])

  const copyToClipboard = (text: string, claim: string) => {
    navigator.clipboard.writeText(text)
    setCopiedClaim(claim)
    setTimeout(() => setCopiedClaim(null), 2000)
  }

  if (!decoded) {
    return (
      <div className="p-4 sm:p-6 rounded-xl bg-surface-900/50 border border-white/5 text-center">
        <Info className="w-6 h-6 sm:w-8 sm:h-8 text-surface-400 mx-auto mb-2" />
        <p className="text-surface-400 text-sm sm:text-base">Paste a valid JWT token to inspect</p>
      </div>
    )
  }

  // Format timestamp claims
  const formatTimestamp = (value: number): string => {
    const date = new Date(value * 1000)
    return date.toLocaleString()
  }

  // Check if a value is a timestamp
  const isTimestamp = (key: string): boolean => {
    return ['exp', 'iat', 'nbf', 'auth_time', 'updated_at'].includes(key)
  }

  // Get time until expiration
  const getExpirationStatus = () => {
    if (!decoded.payload.exp) return null
    const exp = decoded.payload.exp as number
    const now = Date.now() / 1000
    const diff = exp - now

    if (diff < 0) {
      return { status: 'expired', text: `Expired ${Math.abs(Math.floor(diff / 60))} minutes ago` }
    } else if (diff < 300) {
      return { status: 'expiring', text: `Expires in ${Math.floor(diff)} seconds` }
    } else if (diff < 3600) {
      return { status: 'valid', text: `Expires in ${Math.floor(diff / 60)} minutes` }
    } else {
      return { status: 'valid', text: `Expires in ${Math.floor(diff / 3600)} hours` }
    }
  }

  const expStatus = getExpirationStatus()

  return (
    <div className="space-y-3 sm:space-y-4">
      {/* Token Status Banner */}
      <div className={`flex items-start sm:items-center gap-3 p-3 sm:p-4 rounded-xl border ${
        decoded.error
          ? 'bg-red-500/10 border-red-500/30'
          : decoded.isValid
          ? 'bg-green-500/10 border-green-500/30'
          : 'bg-yellow-500/10 border-yellow-500/30'
      }`}>
        {decoded.error ? (
          <XCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5 sm:mt-0" />
        ) : decoded.isValid ? (
          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5 sm:mt-0" />
        ) : (
          <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5 sm:mt-0" />
        )}
        <div className="flex-1 min-w-0">
          <p className={`font-medium text-sm sm:text-base ${
            decoded.error ? 'text-red-400' : decoded.isValid ? 'text-green-400' : 'text-yellow-400'
          }`}>
            {decoded.error || (decoded.isValid ? 'Valid Token' : 'Token Validation Warning')}
          </p>
          {expStatus && (
            <p className={`text-xs sm:text-sm ${
              expStatus.status === 'expired' ? 'text-red-300' :
              expStatus.status === 'expiring' ? 'text-yellow-300' :
              'text-green-300'
            }`}>
              {expStatus.text}
            </p>
          )}
        </div>
        {decoded.header.alg !== undefined && (
          <span className="px-2 sm:px-3 py-1 rounded-full bg-white/10 text-xs font-medium text-white flex-shrink-0">
            {String(decoded.header.alg)}
          </span>
        )}
      </div>

      {/* Visual Token Breakdown */}
      <div className="p-3 sm:p-4 rounded-xl bg-surface-900/50 border border-white/5">
        <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider mb-3">Token Structure</h4>
        <div className="flex flex-wrap sm:flex-nowrap gap-1 font-mono text-xs overflow-x-auto pb-2 scrollbar-hide">
          <motion.button 
            className="px-3 py-2 rounded-lg bg-red-500/20 text-red-400 cursor-pointer hover:bg-red-500/30 active:bg-red-500/40 transition-colors flex-shrink-0"
            onClick={() => setExpandedSection(expandedSection === 'header' ? null : 'header')}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            Header
          </motion.button>
          <span className="text-surface-600 self-center hidden sm:inline">.</span>
          <motion.button 
            className="px-3 py-2 rounded-lg bg-purple-500/20 text-purple-400 cursor-pointer hover:bg-purple-500/30 active:bg-purple-500/40 transition-colors flex-shrink-0"
            onClick={() => setExpandedSection(expandedSection === 'payload' ? null : 'payload')}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            Payload
          </motion.button>
          <span className="text-surface-600 self-center hidden sm:inline">.</span>
          <motion.button 
            className="px-3 py-2 rounded-lg bg-cyan-500/20 text-cyan-400 cursor-pointer hover:bg-cyan-500/30 active:bg-cyan-500/40 transition-colors flex-shrink-0"
            onClick={() => setExpandedSection(expandedSection === 'signature' ? null : 'signature')}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            Signature
          </motion.button>
        </div>
      </div>

      {/* Expandable Sections */}
      <div className="space-y-3">
        {/* Header Section */}
        <TokenSection
          title="Header"
          subtitle="Algorithm & token type"
          icon={Key}
          color="red"
          isExpanded={expandedSection === 'header'}
          onToggle={() => setExpandedSection(expandedSection === 'header' ? null : 'header')}
        >
          <div className="space-y-2">
            {Object.entries(decoded.header).map(([key, value]) => (
              <ClaimRow 
                key={key}
                claim={key}
                value={value}
                onCopy={() => copyToClipboard(String(value), key)}
                isCopied={copiedClaim === key}
              />
            ))}
          </div>
        </TokenSection>

        {/* Payload Section */}
        <TokenSection
          title="Payload"
          subtitle="Claims & user data"
          icon={FileText}
          color="purple"
          isExpanded={expandedSection === 'payload'}
          onToggle={() => setExpandedSection(expandedSection === 'payload' ? null : 'payload')}
        >
          <div className="space-y-2">
            {/* Standard claims first */}
            {Object.entries(decoded.payload)
              .sort(([a], [b]) => {
                const standardOrder = ['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti']
                const aIdx = standardOrder.indexOf(a)
                const bIdx = standardOrder.indexOf(b)
                if (aIdx === -1 && bIdx === -1) return a.localeCompare(b)
                if (aIdx === -1) return 1
                if (bIdx === -1) return -1
                return aIdx - bIdx
              })
              .map(([key, value]) => (
                <ClaimRow 
                  key={key}
                  claim={key}
                  value={isTimestamp(key) && typeof value === 'number' ? formatTimestamp(value) : value}
                  rawValue={value}
                  info={claimInfo[key]}
                  onCopy={() => copyToClipboard(String(value), key)}
                  isCopied={copiedClaim === key}
                  isExpired={key === 'exp' && expStatus?.status === 'expired'}
                />
              ))}
          </div>
        </TokenSection>

        {/* Signature Section */}
        <TokenSection
          title="Signature"
          subtitle="Cryptographic verification"
          icon={Shield}
          color="cyan"
          isExpanded={expandedSection === 'signature'}
          onToggle={() => setExpandedSection(expandedSection === 'signature' ? null : 'signature')}
        >
          <div className="space-y-3">
            <div className="p-2.5 sm:p-3 rounded-lg bg-surface-800">
              <p className="text-xs text-surface-400 mb-1">Signature (Base64URL)</p>
              <p className="font-mono text-[10px] sm:text-xs text-cyan-400 break-all overflow-x-auto scrollbar-hide">
                {decoded.signature || 'No signature'}
              </p>
            </div>
            <div className="p-2.5 sm:p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <p className="text-xs sm:text-sm text-blue-300 flex items-start gap-2">
                <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>
                  To verify this signature, fetch the public key from the issuer's 
                  JWKS endpoint and verify using the {String(decoded.header.alg || 'specified')} algorithm.
                </span>
              </p>
            </div>
          </div>
        </TokenSection>
      </div>
    </div>
  )
}

// Token Section Component
function TokenSection({ 
  title, 
  subtitle,
  icon: Icon, 
  color, 
  isExpanded, 
  onToggle, 
  children 
}: {
  title: string
  subtitle: string
  icon: React.ElementType
  color: string
  isExpanded: boolean
  onToggle: () => void
  children: React.ReactNode
}) {
  const colorClasses: Record<string, string> = {
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
    purple: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  }

  return (
    <div className={`rounded-xl border overflow-hidden transition-all ${
      isExpanded ? colorClasses[color] : 'bg-surface-900/30 border-white/5'
    }`}>
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 sm:gap-3 p-3 sm:p-4 text-left active:bg-white/5"
      >
        <div className={`w-9 h-9 sm:w-10 sm:h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
          isExpanded ? colorClasses[color] : 'bg-surface-800'
        }`}>
          <Icon className={`w-4 h-4 sm:w-5 sm:h-5 ${isExpanded ? colorClasses[color].split(' ')[0] : 'text-surface-400'}`} />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className={`font-medium text-sm sm:text-base ${isExpanded ? 'text-white' : 'text-surface-300'}`}>{title}</h3>
          <p className="text-xs text-surface-400 truncate">{subtitle}</p>
        </div>
        <ChevronDown className={`w-5 h-5 text-surface-400 transition-transform flex-shrink-0 ${isExpanded ? 'rotate-180' : ''}`} />
      </button>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-3 sm:px-4 pb-3 sm:pb-4 pt-0">
              {children}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

// Claim Row Component
function ClaimRow({ 
  claim, 
  value, 
  info,
  onCopy,
  isCopied,
  isExpired
}: {
  claim: string
  value: unknown
  rawValue?: unknown // Keep in type for API compatibility
  info?: { label: string; description: string; icon: React.ElementType }
  onCopy: () => void
  isCopied: boolean
  isExpired?: boolean
}) {
  const [showTooltip, setShowTooltip] = useState(false)
  const Icon = info?.icon || Key

  const formatValue = (val: unknown): string => {
    if (val === null) return 'null'
    if (val === undefined) return 'undefined'
    if (typeof val === 'boolean') return val ? 'true' : 'false'
    if (typeof val === 'object') return JSON.stringify(val, null, 2)
    return String(val)
  }

  return (
    <div 
      className={`flex items-start gap-2 sm:gap-3 p-2.5 sm:p-3 rounded-lg transition-colors group ${
        isExpired ? 'bg-red-500/10' : 'bg-surface-900/50 hover:bg-surface-800/50 active:bg-surface-800/70'
      }`}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
      onClick={onCopy}
    >
      <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${isExpired ? 'text-red-400' : 'text-surface-400'}`} />
      <div className="flex-1 min-w-0 overflow-hidden">
        <div className="flex flex-wrap items-center gap-1 sm:gap-2 mb-0.5">
          <span className={`text-xs sm:text-sm font-medium ${isExpired ? 'text-red-400' : 'text-white'}`}>
            {info?.label || claim}
          </span>
          <code className="text-[10px] sm:text-xs text-surface-400 font-mono">({claim})</code>
          {isExpired && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-500/20 text-red-400">
              EXPIRED
            </span>
          )}
        </div>
        <p className="text-xs sm:text-sm text-surface-300 font-mono break-all overflow-x-auto scrollbar-hide">
          {formatValue(value)}
        </p>
        {info && showTooltip && (
          <p className="text-xs text-surface-400 mt-1 hidden sm:block">{info.description}</p>
        )}
      </div>
      <button
        onClick={(e) => { e.stopPropagation(); onCopy(); }}
        className="opacity-100 sm:opacity-0 group-hover:opacity-100 p-1.5 rounded-md hover:bg-white/10 active:bg-white/20 transition-all flex-shrink-0"
      >
        {isCopied ? (
          <Check className="w-3.5 h-3.5 text-green-400" />
        ) : (
          <Copy className="w-3.5 h-3.5 text-surface-400" />
        )}
      </button>
    </div>
  )
}
