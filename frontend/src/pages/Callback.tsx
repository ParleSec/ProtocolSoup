/**
 * OAuth Callback Page
 * 
 * Handles OAuth 2.0 / OIDC callbacks from the authorization server.
 * Supports multiple callback types:
 * - Authorization Code: code in query string
 * - Implicit: tokens in URL fragment
 * - Hybrid: code and/or tokens in fragment
 */

import { useEffect, useState } from 'react'
import { useSearchParams, useLocation, Link } from 'react-router-dom'
import { CheckCircle, XCircle, Loader2, ArrowLeft, AlertTriangle } from 'lucide-react'

type CallbackType = 'authorization_code' | 'implicit' | 'hybrid' | 'error' | 'unknown'

interface CallbackData {
  type: CallbackType
  // Authorization code flow
  code?: string
  // Common
  state?: string
  // Implicit/Hybrid tokens
  access_token?: string
  id_token?: string
  token_type?: string
  expires_in?: number
  // Error
  error?: string
  error_description?: string
}

export function Callback() {
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing')
  const [callbackData, setCallbackData] = useState<CallbackData | null>(null)

  useEffect(() => {
    // Parse both query string and fragment
    const queryParams = Object.fromEntries(searchParams.entries())
    const fragmentParams = parseFragment(location.hash)
    
    // Determine callback type and extract data
    const data = extractCallbackData(queryParams, fragmentParams)
    setCallbackData(data)

    // Send to parent window if this is a popup
    if (window.opener) {
      sendToParent(data)
      
      if (data.error) {
        setStatus('error')
      } else if (data.code || data.access_token || data.id_token) {
        setStatus('success')
        // Auto-close after brief delay
        setTimeout(() => window.close(), 1500)
      }
    } else {
      // Standalone page
      if (data.error) {
        setStatus('error')
      } else if (data.code || data.access_token || data.id_token) {
        setStatus('success')
      } else {
        setStatus('error')
      }
    }
  }, [searchParams, location.hash])

  return (
    <div className="min-h-[80vh] flex items-center justify-center">
      <div className="glass rounded-xl p-8 max-w-lg w-full">
        {status === 'processing' && (
          <div className="text-center">
            <Loader2 className="w-16 h-16 mx-auto text-accent-cyan animate-spin mb-4" />
            <h1 className="text-xl font-bold text-white mb-2">Processing...</h1>
            <p className="text-surface-400">Handling authorization callback</p>
          </div>
        )}

        {status === 'success' && callbackData && (
          <div className="text-center">
            <div className="w-16 h-16 mx-auto rounded-full bg-green-500/10 flex items-center justify-center mb-4">
              <CheckCircle className="w-10 h-10 text-green-400" />
            </div>
            <h1 className="text-xl font-bold text-white mb-2">Authorization Successful!</h1>
            <p className="text-surface-400 mb-4">
              {window.opener 
                ? 'This window will close automatically.' 
                : 'Authorization complete.'}
            </p>

            {/* Callback Details */}
            <CallbackDetails data={callbackData} />

            {!window.opener && (
              <Link
                to="/looking-glass"
                className="inline-flex items-center gap-2 mt-6 px-4 py-2 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan hover:bg-accent-cyan/20 transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
                Back to Looking Glass
              </Link>
            )}
          </div>
        )}

        {status === 'error' && callbackData && (
          <div className="text-center">
            <div className="w-16 h-16 mx-auto rounded-full bg-red-500/10 flex items-center justify-center mb-4">
              <XCircle className="w-10 h-10 text-red-400" />
            </div>
            <h1 className="text-xl font-bold text-white mb-2">Authorization Failed</h1>
            <p className="text-red-400 mb-4">
              {callbackData.error_description || callbackData.error || 'Unknown error'}
            </p>

            {callbackData.error && (
              <div className="text-left mt-6 p-4 rounded-lg bg-red-500/5 border border-red-500/20">
                <h3 className="text-sm font-medium text-red-300 mb-2">Error Details:</h3>
                <div className="space-y-1 text-xs font-mono text-red-400">
                  <div>
                    <span className="text-red-300">error:</span> {callbackData.error}
                  </div>
                  {callbackData.error_description && (
                    <div>
                      <span className="text-red-300">description:</span>{' '}
                      {callbackData.error_description}
                    </div>
                  )}
                </div>
              </div>
            )}

            <Link
              to="/looking-glass"
              className="inline-flex items-center gap-2 mt-6 px-4 py-2 rounded-lg bg-surface-800 border border-white/10 text-surface-300 hover:text-white hover:bg-surface-700 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Looking Glass
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * Parse URL fragment into key-value pairs
 */
function parseFragment(hash: string): Record<string, string> {
  if (!hash || hash === '#') return {}
  
  const fragment = hash.startsWith('#') ? hash.slice(1) : hash
  const params = new URLSearchParams(fragment)
  return Object.fromEntries(params.entries())
}

/**
 * Extract callback data from query and fragment params
 */
function extractCallbackData(
  query: Record<string, string>,
  fragment: Record<string, string>
): CallbackData {
  // Check for errors first (can be in query or fragment)
  const error = query.error || fragment.error
  if (error) {
    return {
      type: 'error',
      error,
      error_description: query.error_description || fragment.error_description,
      state: query.state || fragment.state,
    }
  }

  // Authorization code in query string
  if (query.code) {
    return {
      type: 'authorization_code',
      code: query.code,
      state: query.state,
    }
  }

  // Implicit or Hybrid: tokens in fragment
  if (fragment.access_token || fragment.id_token) {
    const hasCode = !!fragment.code
    return {
      type: hasCode ? 'hybrid' : 'implicit',
      code: fragment.code,
      access_token: fragment.access_token,
      id_token: fragment.id_token,
      token_type: fragment.token_type,
      expires_in: fragment.expires_in ? parseInt(fragment.expires_in, 10) : undefined,
      state: fragment.state,
    }
  }

  // Hybrid with just code in fragment
  if (fragment.code) {
    return {
      type: 'hybrid',
      code: fragment.code,
      state: fragment.state,
    }
  }

  return { type: 'unknown' }
}

/**
 * Send callback data to parent window
 */
function sendToParent(data: CallbackData): void {
  if (!window.opener) return

  // Determine message type based on callback type
  let messageType = 'oauth_callback'
  
  if (data.type === 'implicit') {
    messageType = 'oauth_implicit_callback'
  } else if (data.type === 'hybrid') {
    messageType = 'oidc_hybrid_callback'
  }

  // Exclude the 'type' field from data since we're setting our own message type
  const { type: _callbackType, ...callbackData } = data
  
  window.opener.postMessage({
    type: messageType,
    ...callbackData,
  }, window.location.origin)
}

/**
 * Display callback details
 */
function CallbackDetails({ data }: { data: CallbackData }) {
  return (
    <div className="text-left mt-6 p-4 rounded-lg bg-surface-900/50 border border-white/10">
      <h3 className="text-sm font-medium text-surface-300 mb-3 flex items-center gap-2">
        <span className={`px-2 py-0.5 rounded text-xs ${
          data.type === 'authorization_code' ? 'bg-blue-500/10 text-blue-400' :
          data.type === 'implicit' ? 'bg-orange-500/10 text-orange-400' :
          data.type === 'hybrid' ? 'bg-purple-500/10 text-purple-400' :
          'bg-surface-700 text-surface-400'
        }`}>
          {data.type.replace('_', ' ').toUpperCase()}
        </span>
        Callback Parameters
      </h3>

      <div className="space-y-2 text-xs font-mono">
        {data.code && (
          <div className="flex items-start gap-2">
            <span className="text-green-400 shrink-0">code:</span>
            <span className="text-surface-300 break-all">
              {data.code.substring(0, 40)}...
            </span>
          </div>
        )}

        {data.access_token && (
          <div className="flex items-start gap-2">
            <span className="text-cyan-400 shrink-0">access_token:</span>
            <span className="text-surface-300 break-all">
              {data.access_token.substring(0, 40)}...
            </span>
          </div>
        )}

        {data.id_token && (
          <div className="flex items-start gap-2">
            <span className="text-orange-400 shrink-0">id_token:</span>
            <span className="text-surface-300 break-all">
              {data.id_token.substring(0, 40)}...
            </span>
          </div>
        )}

        {data.state && (
          <div className="flex items-start gap-2">
            <span className="text-blue-400 shrink-0">state:</span>
            <span className="text-surface-300">{data.state}</span>
          </div>
        )}

        {data.token_type && (
          <div className="flex items-start gap-2">
            <span className="text-purple-400 shrink-0">token_type:</span>
            <span className="text-surface-300">{data.token_type}</span>
          </div>
        )}

        {data.expires_in && (
          <div className="flex items-start gap-2">
            <span className="text-yellow-400 shrink-0">expires_in:</span>
            <span className="text-surface-300">{data.expires_in}s</span>
          </div>
        )}
      </div>

      {data.type === 'implicit' && (
        <div className="mt-3 p-2 rounded bg-orange-500/5 border border-orange-500/20">
          <div className="flex items-center gap-2 text-xs text-orange-400">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Implicit flow - tokens returned in URL fragment</span>
          </div>
        </div>
      )}
    </div>
  )
}
