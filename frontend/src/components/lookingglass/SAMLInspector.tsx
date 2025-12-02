/**
 * SAML Inspector Component
 * 
 * Visualizes SAML assertions, requests, and responses with
 * XML syntax highlighting and parsed attribute views.
 */

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface SAMLInspectorProps {
  /** Raw XML content */
  xml?: string
  /** Parsed assertion data */
  assertion?: SAMLAssertion
  /** Type of SAML message */
  messageType?: 'assertion' | 'authnRequest' | 'response' | 'logoutRequest' | 'logoutResponse'
  /** Whether signature is valid */
  signatureValid?: boolean
  /** Signature validation errors */
  signatureErrors?: string[]
}

interface SAMLAssertion {
  id: string
  issuer: string
  issueInstant: string
  subject?: {
    nameId: string
    nameIdFormat?: string
    subjectConfirmation?: {
      method: string
      notOnOrAfter?: string
      recipient?: string
      inResponseTo?: string
    }
  }
  conditions?: {
    notBefore?: string
    notOnOrAfter?: string
    audience?: string[]
  }
  authnStatement?: {
    authnInstant: string
    sessionIndex?: string
    sessionNotOnOrAfter?: string
    authnContextClassRef?: string
  }
  attributes?: Record<string, string[]>
}

type TabId = 'parsed' | 'xml' | 'signature' | 'conditions'

export function SAMLInspector({
  xml,
  assertion,
  messageType = 'assertion',
  signatureValid,
  signatureErrors,
}: SAMLInspectorProps) {
  const [activeTab, setActiveTab] = useState<TabId>('parsed')

  const tabs: { id: TabId; label: string; icon: string }[] = [
    { id: 'parsed', label: 'Parsed', icon: '📋' },
    { id: 'xml', label: 'Raw XML', icon: '📄' },
    { id: 'signature', label: 'Signature', icon: '🔐' },
    { id: 'conditions', label: 'Conditions', icon: '⏱️' },
  ]

  const getMessageTypeLabel = () => {
    switch (messageType) {
      case 'assertion':
        return 'SAML Assertion'
      case 'authnRequest':
        return 'AuthnRequest'
      case 'response':
        return 'SAML Response'
      case 'logoutRequest':
        return 'LogoutRequest'
      case 'logoutResponse':
        return 'LogoutResponse'
      default:
        return 'SAML Message'
    }
  }

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-700 overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 bg-slate-800/50 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🔖</span>
          <div>
            <h3 className="font-semibold text-white">{getMessageTypeLabel()}</h3>
            {assertion && (
              <p className="text-xs text-slate-400 font-mono">{assertion.id}</p>
            )}
          </div>
        </div>
        
        {signatureValid !== undefined && (
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium ${
            signatureValid 
              ? 'bg-emerald-500/20 text-emerald-400' 
              : 'bg-red-500/20 text-red-400'
          }`}>
            <span>{signatureValid ? '✓' : '✗'}</span>
            <span>{signatureValid ? 'Valid Signature' : 'Invalid Signature'}</span>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-blue-400 border-b-2 border-blue-400 bg-slate-800/30'
                : 'text-slate-400 hover:text-slate-300 hover:bg-slate-800/20'
            }`}
          >
            <span>{tab.icon}</span>
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        <motion.div
          key={activeTab}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          transition={{ duration: 0.15 }}
          className="p-4"
        >
          {activeTab === 'parsed' && assertion && (
            <ParsedView assertion={assertion} />
          )}
          
          {activeTab === 'xml' && xml && (
            <XMLView xml={xml} />
          )}
          
          {activeTab === 'signature' && (
            <SignatureView 
              valid={signatureValid} 
              errors={signatureErrors} 
            />
          )}
          
          {activeTab === 'conditions' && assertion?.conditions && (
            <ConditionsView conditions={assertion.conditions} />
          )}
          
          {!assertion && !xml && (
            <div className="text-center py-8 text-slate-400">
              No SAML data available
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  )
}

function ParsedView({ assertion }: { assertion: SAMLAssertion }) {
  return (
    <div className="space-y-4">
      {/* Basic Info */}
      <Section title="Basic Information">
        <InfoRow label="ID" value={assertion.id} mono />
        <InfoRow label="Issuer" value={assertion.issuer} />
        <InfoRow label="Issue Instant" value={formatDateTime(assertion.issueInstant)} />
      </Section>

      {/* Subject */}
      {assertion.subject && (
        <Section title="Subject">
          <InfoRow label="NameID" value={assertion.subject.nameId} highlight />
          {assertion.subject.nameIdFormat && (
            <InfoRow 
              label="Format" 
              value={formatNameIdFormat(assertion.subject.nameIdFormat)} 
              mono 
            />
          )}
          {assertion.subject.subjectConfirmation && (
            <>
              <InfoRow 
                label="Confirmation Method" 
                value={formatConfirmationMethod(assertion.subject.subjectConfirmation.method)} 
              />
              {assertion.subject.subjectConfirmation.recipient && (
                <InfoRow label="Recipient" value={assertion.subject.subjectConfirmation.recipient} mono />
              )}
            </>
          )}
        </Section>
      )}

      {/* Authentication Statement */}
      {assertion.authnStatement && (
        <Section title="Authentication">
          <InfoRow label="Authn Instant" value={formatDateTime(assertion.authnStatement.authnInstant)} />
          {assertion.authnStatement.sessionIndex && (
            <InfoRow label="Session Index" value={assertion.authnStatement.sessionIndex} mono />
          )}
          {assertion.authnStatement.authnContextClassRef && (
            <InfoRow 
              label="Context Class" 
              value={formatAuthnContext(assertion.authnStatement.authnContextClassRef)} 
            />
          )}
        </Section>
      )}

      {/* Attributes */}
      {assertion.attributes && Object.keys(assertion.attributes).length > 0 && (
        <Section title="Attributes">
          {Object.entries(assertion.attributes).map(([name, values]) => (
            <div key={name} className="py-2 border-b border-slate-700/50 last:border-0">
              <div className="text-xs text-slate-400 mb-1 font-mono">
                {formatAttributeName(name)}
              </div>
              <div className="flex flex-wrap gap-2">
                {values.map((value, i) => (
                  <span 
                    key={i}
                    className="px-2 py-1 bg-blue-500/20 text-blue-300 rounded text-sm"
                  >
                    {value}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </Section>
      )}
    </div>
  )
}

function XMLView({ xml }: { xml: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(xml)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Simple XML syntax highlighting
  const highlightXML = (xmlString: string) => {
    return xmlString
      .replace(/(&lt;|<)(\/?[\w:]+)/g, '<span class="text-pink-400">&lt;$2</span>')
      .replace(/(\s)([\w:]+)=/g, '$1<span class="text-yellow-400">$2</span>=')
      .replace(/"([^"]*)"/g, '<span class="text-emerald-400">"$1"</span>')
      .replace(/(&gt;|>)/g, '<span class="text-pink-400">&gt;</span>')
  }

  return (
    <div className="relative">
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 rounded text-sm text-slate-300 transition-colors"
      >
        {copied ? '✓ Copied' : 'Copy'}
      </button>
      <pre className="bg-slate-950 rounded-lg p-4 overflow-x-auto text-sm leading-relaxed">
        <code 
          className="text-slate-300"
          dangerouslySetInnerHTML={{ __html: highlightXML(escapeHtml(xml)) }}
        />
      </pre>
    </div>
  )
}

function SignatureView({ 
  valid, 
  errors 
}: { 
  valid?: boolean
  errors?: string[] 
}) {
  return (
    <div className="space-y-4">
      <div className={`p-4 rounded-lg ${
        valid === undefined
          ? 'bg-slate-800'
          : valid
            ? 'bg-emerald-500/10 border border-emerald-500/30'
            : 'bg-red-500/10 border border-red-500/30'
      }`}>
        <div className="flex items-center gap-3">
          <span className="text-2xl">
            {valid === undefined ? '❓' : valid ? '✅' : '❌'}
          </span>
          <div>
            <h4 className="font-medium text-white">
              {valid === undefined 
                ? 'Signature Not Verified' 
                : valid 
                  ? 'Signature Valid' 
                  : 'Signature Invalid'}
            </h4>
            <p className="text-sm text-slate-400">
              {valid === undefined
                ? 'The XML signature has not been verified'
                : valid
                  ? 'The XML digital signature was successfully verified'
                  : 'The XML digital signature could not be verified'}
            </p>
          </div>
        </div>
      </div>

      {errors && errors.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-red-400">Validation Errors</h4>
          {errors.map((error, i) => (
            <div 
              key={i}
              className="px-3 py-2 bg-red-500/10 border border-red-500/20 rounded text-sm text-red-300"
            >
              {error}
            </div>
          ))}
        </div>
      )}

      <Section title="Signature Information">
        <InfoRow label="Algorithm" value="RSA-SHA256" />
        <InfoRow label="Canonicalization" value="Exclusive XML Canonicalization (exc-c14n)" />
        <InfoRow label="Reference" value="SAML 2.0 Core Section 5" />
      </Section>
    </div>
  )
}

function ConditionsView({ 
  conditions 
}: { 
  conditions: NonNullable<SAMLAssertion['conditions']> 
}) {
  const now = new Date()
  const notBefore = conditions.notBefore ? new Date(conditions.notBefore) : null
  const notOnOrAfter = conditions.notOnOrAfter ? new Date(conditions.notOnOrAfter) : null

  const isValid = (!notBefore || now >= notBefore) && (!notOnOrAfter || now < notOnOrAfter)

  return (
    <div className="space-y-4">
      {/* Validity Status */}
      <div className={`p-4 rounded-lg ${
        isValid 
          ? 'bg-emerald-500/10 border border-emerald-500/30' 
          : 'bg-red-500/10 border border-red-500/30'
      }`}>
        <div className="flex items-center gap-3">
          <span className="text-2xl">{isValid ? '✅' : '⚠️'}</span>
          <div>
            <h4 className="font-medium text-white">
              {isValid ? 'Conditions Valid' : 'Conditions Invalid'}
            </h4>
            <p className="text-sm text-slate-400">
              {isValid 
                ? 'The assertion is within its validity period'
                : 'The assertion is outside its validity period'}
            </p>
          </div>
        </div>
      </div>

      {/* Time Window */}
      <Section title="Validity Window">
        {conditions.notBefore && (
          <InfoRow 
            label="Not Before" 
            value={formatDateTime(conditions.notBefore)}
            status={notBefore && now >= notBefore ? 'valid' : 'invalid'}
          />
        )}
        {conditions.notOnOrAfter && (
          <InfoRow 
            label="Not On Or After" 
            value={formatDateTime(conditions.notOnOrAfter)}
            status={notOnOrAfter && now < notOnOrAfter ? 'valid' : 'invalid'}
          />
        )}
      </Section>

      {/* Audience Restriction */}
      {conditions.audience && conditions.audience.length > 0 && (
        <Section title="Audience Restriction">
          <p className="text-sm text-slate-400 mb-2">
            This assertion is only valid for the following audiences:
          </p>
          {conditions.audience.map((aud, i) => (
            <div 
              key={i}
              className="px-3 py-2 bg-slate-800 rounded text-sm text-slate-300 font-mono mb-2 last:mb-0"
            >
              {aud}
            </div>
          ))}
        </Section>
      )}
    </div>
  )
}

// Helper Components

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <div className="px-4 py-2 bg-slate-800/50 border-b border-slate-700">
        <h4 className="text-sm font-medium text-slate-300">{title}</h4>
      </div>
      <div className="p-4 space-y-2">
        {children}
      </div>
    </div>
  )
}

function InfoRow({ 
  label, 
  value, 
  mono = false,
  highlight = false,
  status,
}: { 
  label: string
  value: string
  mono?: boolean
  highlight?: boolean
  status?: 'valid' | 'invalid'
}) {
  return (
    <div className="flex justify-between items-start gap-4 py-1">
      <span className="text-sm text-slate-400 shrink-0">{label}</span>
      <span className={`text-sm text-right break-all ${
        mono ? 'font-mono' : ''
      } ${
        highlight ? 'text-blue-400 font-medium' : 'text-slate-200'
      } ${
        status === 'valid' ? 'text-emerald-400' : ''
      } ${
        status === 'invalid' ? 'text-red-400' : ''
      }`}>
        {value}
        {status && (
          <span className="ml-2">{status === 'valid' ? '✓' : '✗'}</span>
        )}
      </span>
    </div>
  )
}

// Helper Functions

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function formatDateTime(isoString: string): string {
  try {
    const date = new Date(isoString)
    return date.toLocaleString()
  } catch {
    return isoString
  }
}

function formatNameIdFormat(format: string): string {
  const shortNames: Record<string, string> = {
    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified': 'unspecified',
    'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress': 'emailAddress',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent': 'persistent',
    'urn:oasis:names:tc:SAML:2.0:nameid-format:transient': 'transient',
  }
  return shortNames[format] || format
}

function formatConfirmationMethod(method: string): string {
  const shortNames: Record<string, string> = {
    'urn:oasis:names:tc:SAML:2.0:cm:bearer': 'Bearer',
    'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key': 'Holder-of-Key',
    'urn:oasis:names:tc:SAML:2.0:cm:sender-vouches': 'Sender-Vouches',
  }
  return shortNames[method] || method
}

function formatAuthnContext(context: string): string {
  const shortNames: Record<string, string> = {
    'urn:oasis:names:tc:SAML:2.0:ac:classes:Password': 'Password',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport': 'Password + TLS',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:X509': 'X.509 Certificate',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified': 'Unspecified',
  }
  return shortNames[context] || context.split(':').pop() || context
}

function formatAttributeName(name: string): string {
  // Try to extract friendly name from OID format
  const oidMappings: Record<string, string> = {
    'urn:oid:0.9.2342.19200300.100.1.3': 'mail',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.5.4.4': 'sn (surname)',
    'urn:oid:2.5.4.3': 'cn (commonName)',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'eduPersonPrincipalName',
  }
  return oidMappings[name] || name
}

export default SAMLInspector

