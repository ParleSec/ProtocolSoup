/**
 * Human-readable labels for axis values and axis names.
 *
 * These exist so the palette UI can render the controlled vocabulary in
 * sentence-case without each result row inventing its own translation. The
 * source of truth for the vocabulary lives in `content/taxonomy.yaml`; this
 * file is a presentation-only mirror for the values currently in use.
 */

import type { PaletteAxis } from './types'

export const AXIS_LABEL: Record<PaletteAxis, string> = {
  use_cases: 'Use case',
  actors: 'Actor',
  patterns: 'Pattern',
  problem_domains: 'Domain',
}

const VALUE_LABEL_OVERRIDES: Record<string, string> = {
  // Use cases
  'user-login-via-own-idp': 'User login (own IdP)',
  'user-login-via-social': 'Social login',
  'service-to-service-auth': 'Service-to-service',
  'step-up-authentication': 'Step-up auth',
  'credential-issuance': 'Credential issuance',
  'credential-presentation': 'Credential presentation',
  'continuous-evaluation': 'Continuous evaluation',
  'workload-attestation': 'Workload attestation',
  'user-provisioning': 'User provisioning',
  'single-sign-on': 'SSO',
  'single-logout': 'SLO',
  'token-introspection': 'Token introspection',
  'token-revocation': 'Token revocation',
  'token-refresh': 'Token refresh',
  'delegated-api-access': 'Delegated API access',
  'mobile-app-login': 'Mobile login',
  'single-page-app-login': 'SPA login',
  'federation-trust-establishment': 'Federation trust',
  'pkce-protection': 'PKCE',
  'discovery': 'Discovery',

  // Actors
  'public-client': 'Public client',
  'confidential-client': 'Confidential client',
  'authorization-server': 'Authorization server',
  'resource-server': 'Resource server',
  'identity-provider': 'IdP',
  'service-provider': 'SP',
  'relying-party': 'RP',
  'wallet': 'Wallet',
  'verifier': 'Verifier',
  'issuer': 'Issuer',
  'holder': 'Holder',
  'workload': 'Workload',
  'user-agent': 'User agent',
  'transmitter': 'Transmitter',
  'receiver': 'Receiver',
  'scim-client': 'SCIM client',
  'scim-service-provider': 'SCIM SP',
  'client': 'Client',

  // Patterns
  'front-channel-redirect': 'Front channel',
  'back-channel': 'Back channel',
  'out-of-band': 'Out of band',
  'certificate-bound': 'Cert-bound',
  'key-bound': 'Key-bound',
  'push-based': 'Push',
  'polling': 'Poll',
  'signed-assertion': 'Signed assertion',
  'pre-authorized': 'Pre-authorized',
  'pkce-bound': 'PKCE-bound',
  'nonce-bound': 'Nonce-bound',
  'xml-signed': 'XML-signed',
  'qr-code-handoff': 'QR handoff',
  'metadata-discovery': 'Metadata discovery',
  'audience-restricted': 'Audience-bound',
  'attestation-bound': 'Attestation-bound',
  'mutual-tls': 'mTLS',
  'bearer': 'Bearer',

  // Problem domains
  'authentication': 'Authentication',
  'authorization': 'Authorization',
  'federation': 'Federation',
  'provisioning': 'Provisioning',
  'verifiable-credentials': 'Verifiable credentials',
  'security-events': 'Security events',
  'workload-identity': 'Workload identity',
  'session-management': 'Session mgmt',
  'key-management': 'Key mgmt',
}

export function axisValueLabel(value: string): string {
  return VALUE_LABEL_OVERRIDES[value] ?? value
}

const TYPE_LABEL: Record<string, string> = {
  protocol: 'Protocol',
  flow: 'Flow',
  concept: 'Concept',
  walkthrough: 'Walkthrough',
  'spec-assertion': 'Spec assertion',
}

export function artefactTypeLabel(type: string): string {
  return TYPE_LABEL[type] ?? type
}
