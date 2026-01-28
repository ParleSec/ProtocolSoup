import { useParams, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { 
  ArrowLeft, ArrowRight, Shield, Lock, Key, 
  Unlock, Fingerprint, Zap, Eye, Loader2, Radio, 
  Users, AlertTriangle, Send
} from 'lucide-react'
import { useProtocol, useProtocolFlows } from '../protocols'
import { protocolMeta } from '../protocols/registry'
import { SEO } from '../components/common/SEO'
import { getProtocolSEO } from '../config/seo'
import { generateProtocolPageSchema } from '../utils/schema'
import { SITE_CONFIG } from '../config/seo'

// Flow UI metadata (icons, colors) - modular extension point
const flowMeta: Record<string, { 
  icon: React.ElementType
  color: string
  features: string[]
  recommended?: boolean 
}> = {
  // OAuth 2.0 flows
  'authorization_code': {
    icon: Shield,
    color: 'from-purple-500 to-indigo-600',
    features: ['Server-side Apps', 'Confidential Clients', 'Client Secret'],
  },
  'authorization_code_pkce': {
    icon: Lock,
    color: 'from-cyan-500 to-blue-600',
    features: ['Single Page Apps', 'Mobile Apps', 'No Client Secret'],
    recommended: true,
  },
  'client_credentials': {
    icon: Key,
    color: 'from-orange-500 to-red-600',
    features: ['Microservices', 'Background Jobs', 'No User Context'],
  },
  'refresh_token': {
    icon: Unlock,
    color: 'from-green-500 to-emerald-600',
    features: ['Token Rotation', 'Long Sessions', 'Silent Refresh'],
  },
  // OIDC flows
  'oidc_authorization_code': {
    icon: Fingerprint,
    color: 'from-purple-500 to-pink-600',
    features: ['ID Token (JWT)', 'UserInfo Endpoint', 'Verified Identity'],
    recommended: true,
  },
  'oidc_implicit': {
    icon: Unlock,
    color: 'from-amber-500 to-orange-600',
    features: ['Legacy Flow', 'Direct Token Response', 'Not Recommended'],
  },
  // SPIFFE/SPIRE flows
  'x509-svid-issuance': {
    icon: Shield,
    color: 'from-green-500 to-emerald-600',
    features: ['X.509 Certificate', 'Workload Identity', 'mTLS Ready'],
    recommended: true,
  },
  'jwt-svid-issuance': {
    icon: Key,
    color: 'from-teal-500 to-cyan-600',
    features: ['JWT Token', 'API Authentication', 'Short-Lived'],
  },
  'mtls-handshake': {
    icon: Lock,
    color: 'from-emerald-500 to-green-600',
    features: ['Mutual TLS', 'Zero Trust', 'Service-to-Service'],
  },
  'certificate-rotation': {
    icon: Zap,
    color: 'from-lime-500 to-green-600',
    features: ['Auto-Rotation', 'Zero Downtime', 'Streaming API'],
  },
  // SSF (Shared Signals Framework) flows
  'ssf_stream_configuration': {
    icon: Radio,
    color: 'from-amber-500 to-orange-600',
    features: ['Stream Setup', 'Discovery', 'JWKS'],
    recommended: true,
  },
  'ssf_push_delivery': {
    icon: Send,
    color: 'from-green-500 to-emerald-600',
    features: ['Real-time', 'RFC 8935', 'Immediate'],
  },
  'ssf_poll_delivery': {
    icon: Zap,
    color: 'from-blue-500 to-indigo-600',
    features: ['Receiver-initiated', 'RFC 8936', 'Firewall-friendly'],
  },
  'caep_session_revoked': {
    icon: Lock,
    color: 'from-blue-500 to-cyan-600',
    features: ['CAEP', 'Session Mgmt', 'Zero Trust'],
  },
  'caep_credential_change': {
    icon: Key,
    color: 'from-purple-500 to-indigo-600',
    features: ['CAEP', 'Credential Events', 'Re-auth'],
  },
  'risc_account_disabled': {
    icon: Shield,
    color: 'from-amber-500 to-red-600',
    features: ['RISC', 'High Severity', 'Block Access'],
  },
  'risc_credential_compromise': {
    icon: AlertTriangle,
    color: 'from-red-500 to-rose-600',
    features: ['RISC', 'CRITICAL', 'Emergency'],
  },
  // SCIM 2.0 flows
  'scim_user_lifecycle': {
    icon: Users,
    color: 'from-purple-500 to-violet-600',
    features: ['User CRUD', 'Provisioning', 'IdP Sync'],
    recommended: true,
  },
  'scim_group_management': {
    icon: Users,
    color: 'from-blue-500 to-indigo-600',
    features: ['Group Sync', 'Membership', 'Access Control'],
  },
  'scim_filter_queries': {
    icon: Zap,
    color: 'from-cyan-500 to-blue-600',
    features: ['RFC 7644', 'Filter Syntax', 'Pagination'],
  },
  'scim_schema_discovery': {
    icon: Eye,
    color: 'from-teal-500 to-cyan-600',
    features: ['Auto-Config', 'Capabilities', 'Schemas'],
  },
  'scim_bulk_operations': {
    icon: Zap,
    color: 'from-orange-500 to-amber-600',
    features: ['Batch Processing', 'Atomic', 'Efficient'],
  },
}

// Map flow IDs to URL slugs
function flowIdToSlug(id: string): string {
  return id.replace(/_/g, '-')
}

export function ProtocolDemo() {
  const { protocolId } = useParams()
  
  // Fetch from modular plugin system
  const { protocol, loading: protocolLoading } = useProtocol(protocolId)
  const { flows, loading: flowsLoading, error: flowsError } = useProtocolFlows(protocolId)
  
  const loading = protocolLoading || flowsLoading
  
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Loader2 className="w-8 h-8 text-accent-orange animate-spin" />
      </div>
    )
  }
  
  if (!protocol) {
    return (
      <div className="text-center py-20">
        <h1 className="text-2xl font-bold text-white mb-4">Protocol Not Found</h1>
        <Link to="/" className="text-accent-orange hover:underline">
          Back to Dashboard
        </Link>
      </div>
    )
  }

  if (flowsError) {
    return (
      <div className="text-center py-20">
        <h1 className="text-2xl font-bold text-white mb-4">Protocol Data Unavailable</h1>
        <p className="text-surface-400 mb-6">{flowsError.message}</p>
        <Link to="/" className="text-accent-orange hover:underline">
          Back to Dashboard
        </Link>
      </div>
    )
  }

  const meta = protocolMeta[protocolId || ''] || protocolMeta.oauth2
  const getProtocolIcon = (id: string | undefined) => {
    switch (id) {
      case 'oidc': return Fingerprint
      case 'spiffe': return Shield
      case 'saml': return Key
      case 'scim': return Users
      case 'ssf': return Radio
      default: return Shield
    }
  }
  const ProtocolIcon = getProtocolIcon(protocolId)

  // Get first recommended flow for quick action
  const recommendedFlow = flows.find(f => flowMeta[f.id]?.recommended) || flows[0]

  // Generate SEO data
  const seoData = getProtocolSEO(protocolId || '')
  const structuredData = generateProtocolPageSchema(
    protocol.name,
    protocol.description,
    `${SITE_CONFIG.baseUrl}/protocol/${protocolId}`,
    flows.map(f => ({ name: f.name, description: f.description }))
  )

  return (
    <>
      <SEO
        title={seoData.title}
        description={seoData.description}
        canonical={`/protocol/${protocolId}`}
        ogType="article"
        keywords={seoData.keywords}
        structuredData={structuredData}
      />
      <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          to="/"
          className="p-2 rounded-lg bg-white/5 hover:bg-white/10 transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex-1">
          <h1 className="font-display text-3xl font-bold text-white flex items-center gap-3">
            <ProtocolIcon className="w-8 h-8 text-accent-orange" />
            {protocol.name}
          </h1>
          <p className="text-surface-400 mt-2 max-w-3xl">{protocol.description}</p>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="flex flex-wrap gap-3">
        {recommendedFlow && (
          <Link
            to={`/protocol/${protocolId}/flow/${flowIdToSlug(recommendedFlow.id)}`}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-accent-orange to-accent-purple text-white font-medium hover:opacity-90 transition-opacity"
          >
            <Zap className="w-4 h-4" />
            Start with Recommended Flow
          </Link>
        )}
        <Link
          to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/5 border border-white/10 text-white font-medium hover:bg-white/10 transition-colors"
        >
          {protocolId === 'ssf' ? <Radio className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
          {protocolId === 'ssf' ? 'Open SSF Sandbox' : 'Open Looking Glass'}
        </Link>
      </div>

      {/* Flows Grid - Data from modular plugins */}
      <div>
        <h2 className="font-display text-xl font-semibold text-white mb-4">
          Available Flows
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {flows.map((flow, idx) => {
            const meta = flowMeta[flow.id] || { 
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
                  to={`/protocol/${protocolId}/flow/${flowIdToSlug(flow.id)}`}
                  className="block relative overflow-hidden rounded-2xl p-6 bg-surface-900/50 border border-white/5 hover:border-white/10 transition-all group hover:shadow-xl"
                >
                  {/* Gradient accent */}
                  <div className={`absolute top-0 left-0 right-0 h-1 bg-gradient-to-r ${meta.color}`} />
                  

                  <div className="flex items-start gap-4">
                    <div className={`w-14 h-14 rounded-xl bg-gradient-to-br ${meta.color} flex items-center justify-center shadow-lg`}>
                      <FlowIcon className="w-7 h-7 text-white" />
                    </div>
                    <div className="flex-1 min-w-0 pr-8">
                      <h3 className="font-display text-lg font-semibold text-white group-hover:text-white transition-colors">
                        {flow.name}
                      </h3>
                      <p className="text-surface-400 text-sm mt-1 line-clamp-2">
                        {flow.description}
                      </p>
                    </div>
                  </div>

                  {/* Features */}
                  {meta.features.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-4">
                      {meta.features.map(feature => (
                        <span 
                          key={feature}
                          className="px-2.5 py-1 rounded-lg bg-white/5 text-xs text-surface-400"
                        >
                          {feature}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Action hint */}
                  <div className="flex items-center gap-1 mt-4 text-sm text-surface-400 group-hover:text-accent-orange transition-colors">
                    <span>View flow diagram</span>
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </div>
                </Link>
              </motion.div>
            )
          })}
        </div>
      </div>

      {/* Protocol Features - from modular meta */}
      <div className="glass rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold text-white mb-4">
          {protocol.name} Features
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
    </>
  )
}

// Feature descriptions for protocol features
function getFeatureDescription(feature: string): string {
  const descriptions: Record<string, string> = {
    // OAuth 2.0 features
    'Authorization Code Flow': 'Standard flow for server-side applications',
    'PKCE for Public Clients': 'Enhanced security for SPAs and mobile apps (RFC 7636)',
    'Client Credentials': 'Machine-to-machine authentication',
    'Refresh Token Rotation': 'Secure token refresh with rotation',
    'Token Introspection': 'Verify token validity and metadata (RFC 7662)',
    'Token Revocation': 'Invalidate access/refresh tokens (RFC 7009)',
    // OAuth 2.0 standards compliance
    'RFC 6749 Compliant': 'Full OAuth 2.0 Authorization Framework compliance',
    'RFC 7636 PKCE Validation': 'Strict 43-128 char verifier with character validation',
    'RFC 7009 Token Revocation': 'Both access and refresh token revocation support',
    // OIDC features
    'ID Token (JWT)': 'JWT containing verified identity claims (sub, name, email)',
    'UserInfo Endpoint': 'API endpoint returning additional user claims',
    'Discovery Document': 'Auto-configuration via /.well-known/openid-configuration',
    'Standard Claims': 'Standardized user attributes (sub, name, email, picture)',
    'Nonce Protection': 'Required for id_token response types (OIDC Core §3.2.2.1)',
    'Signature Verification': 'Validate tokens using JWKS public keys',
    'Claims & Scopes': 'Request specific user data with standard scopes',
    'Hybrid Flows': 'Combined response types for flexibility',
    'Session Management': 'Track and manage user sessions',
    // OIDC Core 1.0 compliance
    'at_hash / c_hash Claims': 'Hash claims for hybrid/implicit flow integrity (§3.3.2.11)',
    'Hybrid Flow Support': 'Full support for code+id_token response types',
    'azp Claim for Multi-Audience': 'Authorized party claim per OIDC Core §2',
    // SCIM 2.0 features
    'User Provisioning': 'Automated user account creation and management',
    'Group Management': 'Sync groups and memberships between IdP and SP',
    'Filter Queries': 'RFC 7644 compliant filter syntax for queries',
    'PATCH Operations': 'Partial updates with SCIM PATCH operations',
    'Bulk Operations': 'Batch multiple operations in single request',
    'Schema Discovery': 'Auto-discover server capabilities and schemas',
    'ETag Support': 'Optimistic locking with entity tags',
    'IdP Integration': 'Connect to identity providers like Okta, Azure AD',
    // SSF (Shared Signals Framework) features
    'Security Event Tokens (SET)': 'RFC 8417 signed JWTs for security events',
    'CAEP Events': 'Continuous Access Evaluation Profile events',
    'RISC Events': 'Risk Incident Sharing and Coordination events',
    'Push Delivery': 'Real-time event delivery via HTTP POST (RFC 8935)',
    'Poll Delivery': 'Receiver-initiated polling for events (RFC 8936)',
    'Stream Management': 'Configure and manage event streams',
    'Real-time Signals': 'Immediate notification of security events',
    'Zero Trust Ready': 'Enable continuous access evaluation',
  }
  return descriptions[feature] || feature
}

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
    <div className={`p-4 rounded-xl border ${colorClasses[color]}`}>
      <h3 className="font-medium text-white mb-1">{title}</h3>
      <p className="text-sm text-surface-400">{description}</p>
    </div>
  )
}
