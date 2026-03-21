import type { ElementType } from 'react'
import { Eye, Fingerprint, FileKey, Key, KeyRound, Radio, Shield, Users } from 'lucide-react'
import { PROTOCOL_CATALOG_DATA } from './protocol-catalog-data'

export interface ProtocolFlowSummary {
  id: string
  name: string
  rfc: string
}

export interface ProtocolCatalogItem {
  id: string
  name: string
  description: string
  icon: ElementType
  color: 'blue' | 'orange' | 'cyan' | 'green' | 'purple' | 'amber'
  spec: string
  specUrl: string
  flows: ProtocolFlowSummary[]
}

export interface ComingSoonProtocol {
  name: string
  description: string
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

const COLOR_BY_PROTOCOL: Record<string, ProtocolCatalogItem['color']> = {
  oauth2: 'blue',
  oidc: 'orange',
  oid4vci: 'green',
  oid4vp: 'purple',
  saml: 'cyan',
  spiffe: 'green',
  scim: 'purple',
  ssf: 'amber',
}

export const PROTOCOL_CATALOG: ProtocolCatalogItem[] = PROTOCOL_CATALOG_DATA.map((item) => ({
  id: item.id,
  name: item.name,
  description: item.description,
  icon: ICON_BY_PROTOCOL[item.id] || Shield,
  color: COLOR_BY_PROTOCOL[item.id] || 'blue',
  spec: item.spec,
  specUrl: item.specUrl,
  flows: item.flows,
}))

export const COMING_SOON_PROTOCOLS: ComingSoonProtocol[] = [
  { name: 'WebAuthn', description: 'Passwordless authentication' },
  { name: 'FIDO2', description: 'Strong authentication framework' },
]
