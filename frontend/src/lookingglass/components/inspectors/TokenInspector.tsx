import { useEffect, useMemo, useState, type ElementType, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Clock,
  User, Key, Lock, Globe, Info, ChevronDown, Copy, Check,
  FileText, Fingerprint, Calendar, ShieldQuestion
} from 'lucide-react'
import { decodeJWTWithoutValidation, jwkThumbprint } from '../../../utils/crypto'
import { FieldRow } from '../shared'

interface TokenInspectorProps {
  token: string
  /**
   * OAuth 2.0 token_type (RFC 6749 Section 5.1), e.g. "Bearer" or "DPoP".
   * Only meaningful for an access token, so callers pass this only when
   * `token` is the currently-held access token -- id_token, refresh_token,
   * client_assertion, and manually-pasted tokens have no token_type and
   * must leave this undefined rather than guessing "Bearer".
   */
  tokenType?: string
}

interface DecodedToken {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  signature: string
  isValid: boolean
  error?: string
}

// KeyBindingInfo mirrors TLSInspector's TokenBindingInfo pattern (compute a
// real thumbprint, compare, report match/mismatch/missing) but as its own
// type rather than a shared one, because RFC 7800 cnf.jwk/cnf.jkt has more
// partial-data shapes than RFC 8705's cnf.x5t#S256 (which only ever
// compares against a TLS-layer certificate thumbprint that either exists
// or doesn't): a token can carry jwk without jkt, jkt without jwk, or a
// jwk whose kty this codebase's thumbprint helper cannot compute for.
// 'unsupported_kty' is deliberately its own state, never folded into
// 'mismatch': an unknown future kty must never render as a failed
// comparison when no comparison was actually possible.
type KeyBindingInfo =
  | { status: 'not_bound' }
  | { status: 'jwk_only'; jwk: Record<string, unknown> }
  | { status: 'jkt_only'; jkt: string }
  | { status: 'unsupported_kty'; jwk: Record<string, unknown>; jkt: string; kty: string }
  | { status: 'match'; jwk: Record<string, unknown>; jkt: string; computedThumbprint: string }
  | { status: 'mismatch'; jwk: Record<string, unknown>; jkt: string; computedThumbprint: string }

// Standard JWT claim explanations
const claimInfo: Record<string, { label: string; description: string; icon: ElementType }> = {
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
  email: { label: 'Email', description: "User's email address", icon: User },
  name: { label: 'Name', description: "User's full name", icon: User },
  preferred_username: { label: 'Username', description: "User's preferred username", icon: User },
  email_verified: { label: 'Email Verified', description: 'Whether email has been verified', icon: CheckCircle },
  cnf: { label: 'Confirmation Key', description: 'Proof-of-possession key binding (RFC 7800)', icon: Fingerprint },
}

export function TokenInspector({ token, tokenType }: TokenInspectorProps) {
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

      const decodedToken = decodeJWTWithoutValidation(token)
      if (!decodedToken) {
        throw new Error('Invalid base64url segments in JWT')
      }
      const header = decodedToken.header
      const payload = decodedToken.payload
      const { signature } = decodedToken

      // Check expiration
      const exp = typeof payload.exp === 'number' ? payload.exp : undefined
      const nbf = typeof payload.nbf === 'number' ? payload.nbf : undefined
      const isExpired = exp !== undefined && Date.now() / 1000 > exp
      const isNotYetValid = nbf !== undefined && Date.now() / 1000 < nbf

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

  const [keyBinding, setKeyBinding] = useState<KeyBindingInfo | null>(null)

  // jwkThumbprint is async (crypto.subtle.digest), so the RFC 7638 compare
  // cannot live in the useMemo above. `cancelled` guards against a stale
  // computation from a previous token resolving after a newer one has
  // already started, which would otherwise render the wrong verdict for a
  // moment.
  useEffect(() => {
    let cancelled = false
    const cnf = decoded?.payload.cnf as Record<string, unknown> | undefined
    const jwk = cnf?.jwk && typeof cnf.jwk === 'object' ? (cnf.jwk as Record<string, unknown>) : undefined
    const jkt = typeof cnf?.jkt === 'string' ? cnf.jkt : undefined

    if (!cnf) {
      setKeyBinding(null)
      return
    }
    if (!jwk && !jkt) {
      setKeyBinding({ status: 'not_bound' })
      return
    }
    if (!jwk || !jkt) {
      // Exactly one of the two is present: "both absent" already
      // returned above, so this is jwk-only or jkt-only. TypeScript can
      // narrow a single `!a || !b` condition; it cannot deduce "both
      // present" from three separate prior if-statements the way a human
      // reader can, which is why this is one combined check rather than
      // a third `if (jwk && !jkt) ... if (jkt && !jwk) ...` pair.
      if (jwk) {
        setKeyBinding({ status: 'jwk_only', jwk })
      } else if (jkt) {
        setKeyBinding({ status: 'jkt_only', jkt })
      }
      return
    }

    // Both present here. Rebinding to new consts (rather than relying on
    // jwk/jkt directly) keeps them narrowed to defined inside the .then()
    // closure below without a non-null assertion at each use.
    const boundJwk = jwk
    const boundJkt = jkt

    jwkThumbprint(boundJwk).then((computed) => {
      if (cancelled) return
      if (computed === null) {
        setKeyBinding({
          status: 'unsupported_kty',
          jwk: boundJwk,
          jkt: boundJkt,
          kty: typeof boundJwk.kty === 'string' ? boundJwk.kty : 'unknown',
        })
      } else {
        setKeyBinding({
          status: computed === boundJkt ? 'match' : 'mismatch',
          jwk: boundJwk,
          jkt: boundJkt,
          computedThumbprint: computed,
        })
      }
    })

    return () => {
      cancelled = true
    }
  }, [decoded])

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
    const exp = decoded.payload.exp
    if (typeof exp !== 'number') return null
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
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          {tokenType && (
            // DPoP (RFC 9449) is sender-constrained -- a stolen token is
            // useless without the matching private key -- while Bearer
            // (RFC 6750) is not. That distinction must be visible at a
            // glance, not just present as differing text in the same pill.
            <span className={`flex items-center gap-1 px-2 sm:px-3 py-1 rounded-full text-xs font-medium ${
              tokenType.toLowerCase() === 'dpop'
                ? 'bg-amber-500/20 text-amber-300'
                : 'bg-indigo-500/20 text-indigo-300'
            }`}>
              {tokenType.toLowerCase() === 'dpop' && <Lock className="w-3 h-3" />}
              {tokenType}
            </span>
          )}
          {decoded.header.alg !== undefined && (
            <span className="px-2 sm:px-3 py-1 rounded-full bg-white/10 text-xs font-medium text-white">
              {String(decoded.header.alg)}
            </span>
          )}
        </div>
      </div>

      {/* Key Binding (RFC 7800) */}
      <KeyBindingBlock binding={keyBinding} />

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

// KeyBindingBlock renders RFC 7800 confirmation-key binding, modelled on
// TLSInspector's Certificate Binding (RFC 8705) treatment: a real
// thumbprint is computed from cnf.jwk and compared against the claimed
// cnf.jkt rather than the panel trusting either value on its own. Renders
// nothing for a token with no cnf claim at all -- a token that was never
// meant to be key-bound gets no block, rather than a block reporting
// "not bound" as if that were itself a finding.
function KeyBindingBlock({ binding }: { binding: KeyBindingInfo | null }) {
  if (!binding || binding.status === 'not_bound') {
    return null
  }

  const { icon: Icon, tone, label } = keyBindingStatusDisplay(binding.status)
  const kty = keyBindingKty(binding)

  return (
    <div className="p-3 sm:p-4 rounded-xl bg-surface-900/50 border border-white/5">
      <div className="flex items-center gap-2 mb-2">
        <Fingerprint className="w-4 h-4 text-surface-400" />
        <h4 className="text-xs font-semibold text-surface-400 uppercase tracking-wider">Key Binding (RFC 7800)</h4>
      </div>
      <div className="rounded-lg bg-surface-950 p-2.5 text-xs space-y-1.5">
        <div className={`flex items-center gap-1.5 font-medium ${tone}`}>
          <Icon className="w-3.5 h-3.5" />
          {label}
        </div>
        {kty && <FieldRow label="cnf.jwk.kty" value={kty} />}
        {binding.status === 'jkt_only' && <FieldRow label="cnf.jkt" value={binding.jkt} mono />}
        {(binding.status === 'unsupported_kty' || binding.status === 'match' || binding.status === 'mismatch') && (
          <FieldRow label="cnf.jkt (claimed)" value={binding.jkt} mono />
        )}
        {(binding.status === 'match' || binding.status === 'mismatch') && (
          <FieldRow
            label="Computed thumbprint"
            value={binding.computedThumbprint}
            mono
            valueClassName={binding.status === 'match' ? 'text-green-300' : 'text-red-300'}
          />
        )}
      </div>
    </div>
  )
}

// keyBindingKty reads kty for display: 'unsupported_kty' carries it as its
// own field (computed before the jwkThumbprint call, since that call is
// exactly what failed to produce a usable kty branch), every other
// jwk-bearing state reads it straight off the jwk, and 'jkt_only' has no
// jwk at all to read one from.
function keyBindingKty(binding: KeyBindingInfo): string | undefined {
  switch (binding.status) {
    case 'not_bound':
    case 'jkt_only':
      return undefined
    case 'unsupported_kty':
      return binding.kty
    case 'jwk_only':
    case 'match':
    case 'mismatch':
      return typeof binding.jwk.kty === 'string' ? binding.jwk.kty : 'unknown'
  }
}

function keyBindingStatusDisplay(status: KeyBindingInfo['status']): { icon: ElementType; tone: string; label: string } {
  switch (status) {
    case 'match':
      return { icon: CheckCircle, tone: 'text-green-400', label: 'jkt matches the jwk thumbprint' }
    case 'mismatch':
      return { icon: XCircle, tone: 'text-red-400', label: 'jkt does not match the jwk thumbprint' }
    case 'unsupported_kty':
      return { icon: ShieldQuestion, tone: 'text-yellow-400', label: 'Cannot compute a thumbprint for this key type' }
    case 'jwk_only':
      return { icon: AlertTriangle, tone: 'text-yellow-400', label: 'cnf.jwk present, no cnf.jkt to compare against' }
    case 'jkt_only':
      return { icon: AlertTriangle, tone: 'text-yellow-400', label: 'cnf.jkt present, no cnf.jwk to verify against' }
    case 'not_bound':
      return { icon: Info, tone: 'text-surface-400', label: 'Not key-bound' }
  }
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
  icon: ElementType
  color: string
  isExpanded: boolean
  onToggle: () => void
  children: ReactNode
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
  info?: { label: string; description: string; icon: ElementType }
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
