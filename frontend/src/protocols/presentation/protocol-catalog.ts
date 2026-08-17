import type { ElementType } from 'react'
import { Eye, Fingerprint, FileKey, Key, KeyRound, Radio, Shield, Users } from 'lucide-react'
import { advertisedProtocolCatalogData, type ProtocolReference } from './protocol-catalog-data'

export interface ProtocolFlowSummary {
  id: string
  name: string
  rfc: string
}

/** Homepage grid is 2 columns; adjacent families share a hue region. */
export type ProtocolAccent = 'blue' | 'sky' | 'orange' | 'amber' | 'green' | 'teal' | 'cyan' | 'indigo'

export interface ProtocolCatalogItem {
  id: string
  name: string
  description: string
  icon: ElementType
  color: ProtocolAccent
  spec: string
  specUrl: string
  flows: ProtocolFlowSummary[]
  references: ProtocolReference[]
}

export interface ComingSoonProtocol {
  name: string
  description: string
}

export const PROTOCOL_ACCENT_CLASSES: Record<ProtocolAccent, {
  border: string
  borderHover: string
  accent: string
  bg: string
  text: string
  tag: string
}> = {
  blue: {
    border: 'border-blue-500/20',
    borderHover: 'hover:border-blue-500/40',
    accent: 'bg-blue-500/50',
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    tag: 'bg-blue-500/10 text-blue-300 border-blue-500/20',
  },
  sky: {
    border: 'border-sky-500/20',
    borderHover: 'hover:border-sky-500/40',
    accent: 'bg-sky-500/50',
    bg: 'bg-sky-500/10',
    text: 'text-sky-400',
    tag: 'bg-sky-500/10 text-sky-300 border-sky-500/20',
  },
  orange: {
    border: 'border-orange-500/20',
    borderHover: 'hover:border-orange-500/40',
    accent: 'bg-orange-500/50',
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    tag: 'bg-orange-500/10 text-orange-300 border-orange-500/20',
  },
  amber: {
    border: 'border-amber-500/20',
    borderHover: 'hover:border-amber-500/40',
    accent: 'bg-amber-500/50',
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    tag: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
  },
  green: {
    border: 'border-green-500/20',
    borderHover: 'hover:border-green-500/40',
    accent: 'bg-green-500/50',
    bg: 'bg-green-500/10',
    text: 'text-green-400',
    tag: 'bg-green-500/10 text-green-300 border-green-500/20',
  },
  teal: {
    border: 'border-teal-500/20',
    borderHover: 'hover:border-teal-500/40',
    accent: 'bg-teal-500/50',
    bg: 'bg-teal-500/10',
    text: 'text-teal-400',
    tag: 'bg-teal-500/10 text-teal-300 border-teal-500/20',
  },
  cyan: {
    border: 'border-cyan-500/20',
    borderHover: 'hover:border-cyan-500/40',
    accent: 'bg-cyan-500/50',
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-400',
    tag: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20',
  },
  indigo: {
    border: 'border-indigo-500/20',
    borderHover: 'hover:border-indigo-500/40',
    accent: 'bg-indigo-500/50',
    bg: 'bg-indigo-500/10',
    text: 'text-indigo-400',
    tag: 'bg-indigo-500/10 text-indigo-300 border-indigo-500/20',
  },
}

const ICON_BY_PROTOCOL: Record<string, ElementType> = {
  oauth2: Key,
  oidc: Fingerprint,
  oid4vci: KeyRound,
  oid4vp: Eye,
  saml: FileKey,
  spiffe: Shield,
  scim: Users,
  ssf: Radio,
}

const COLOR_BY_PROTOCOL: Record<string, ProtocolAccent> = {
  oauth2: 'blue',
  oidc: 'sky',
  saml: 'orange',
  scim: 'amber',
  spiffe: 'green',
  ssf: 'teal',
  oid4vci: 'cyan',
  oid4vp: 'indigo',
}

const HOMEPAGE_BLURB: Record<string, string> = {
  oauth2: 'Authorization framework for delegated access',
  oidc: 'Authentication layer built on OAuth 2.0',
  saml: 'XML-based federated identity and SSO',
  scim: 'Cross-domain identity provisioning',
  spiffe: 'Zero-trust workload identity',
  ssf: 'CAEP and RISC security event sharing',
  oid4vci: 'Verifiable credential issuance over OpenID',
  oid4vp: 'Verifiable presentation requests and verification',
}

export const PROTOCOL_CATALOG: ProtocolCatalogItem[] = advertisedProtocolCatalogData().map((item) => ({
  id: item.id,
  name: item.name,
  description: item.description,
  icon: ICON_BY_PROTOCOL[item.id] || Shield,
  color: COLOR_BY_PROTOCOL[item.id] || 'blue',
  spec: item.spec,
  specUrl: item.specUrl,
  flows: item.flows,
  references: item.references,
}))

export const COMING_SOON_PROTOCOLS: ComingSoonProtocol[] = [
  {
    name: 'WebAuthn',
    description: 'Passwordless public-key credentials, including hardware authenticators',
  },
  {
    name: 'FIDO2',
    description: 'Software and hardware authenticator flows, including roaming devices',
  },
]

export function protocolHomepageBlurb(id: string, fallback: string): string {
  return HOMEPAGE_BLURB[id] || fallback
}
