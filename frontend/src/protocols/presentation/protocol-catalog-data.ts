export type ProtocolReferenceCategory = 'core' | 'security' | 'companion' | 'profile'

export interface ProtocolReference {
  category: ProtocolReferenceCategory
  label: string
  href: string
  note?: string
}

export interface ProtocolFlowCatalogData {
  id: string
  name: string
  rfc: string
  backendId?: string
  references?: ProtocolReference[]
}

export interface ProtocolCatalogDataItem {
  id: string
  name: string
  description: string
  spec: string
  specUrl: string
  flows: ProtocolFlowCatalogData[]
  references: ProtocolReference[]
}

// Build-safe route and sitemap source: no UI component imports.
export const PROTOCOL_CATALOG_DATA: ProtocolCatalogDataItem[] = [
  {
    id: 'oauth2',
    name: 'OAuth 2.0',
    description: 'The industry-standard authorization framework for delegated access. Enables applications to obtain limited access to user accounts without exposing credentials.',
    spec: 'RFC 6749',
    specUrl: 'https://datatracker.ietf.org/doc/html/rfc6749',
    flows: [
      {
        id: 'authorization-code',
        backendId: 'authorization_code',
        name: 'Authorization Code',
        rfc: '§4.1',
        references: [
          { category: 'core', label: 'RFC 6749 §4.1 — Authorization Code Grant', href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-4.1' },
          { category: 'security', label: 'RFC 9700 §2.1 — Protecting Redirect-Based Flows', href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.1' },
        ],
      },
      {
        id: 'authorization-code-pkce',
        backendId: 'authorization_code_pkce',
        name: 'Authorization Code + PKCE',
        rfc: 'RFC 7636',
        references: [
          { category: 'core', label: 'RFC 6749 §4.1 — Authorization Code Grant', href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-4.1' },
          { category: 'core', label: 'RFC 7636 — Proof Key for Code Exchange', href: 'https://datatracker.ietf.org/doc/html/rfc7636' },
          { category: 'security', label: 'RFC 9700 §2.1.1 — PKCE for All Clients', href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1' },
        ],
      },
      {
        id: 'client-credentials',
        backendId: 'client_credentials',
        name: 'Client Credentials',
        rfc: '§4.4',
        references: [
          { category: 'core', label: 'RFC 6749 §4.4 — Client Credentials Grant', href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-4.4' },
          { category: 'security', label: 'RFC 9700 §2.5 — Client Authentication', href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.5' },
        ],
      },
      {
        id: 'refresh-token',
        backendId: 'refresh_token',
        name: 'Refresh Token',
        rfc: '§6',
        references: [
          { category: 'core', label: 'RFC 6749 §6 — Refreshing an Access Token', href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-6' },
          { category: 'security', label: 'RFC 9700 §4.14 — Refresh Token Protection', href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.14' },
        ],
      },
      {
        id: 'token-introspection',
        backendId: 'token_introspection',
        name: 'Token Introspection',
        rfc: 'RFC 7662',
        references: [
          { category: 'core', label: 'RFC 7662 — Token Introspection', href: 'https://datatracker.ietf.org/doc/html/rfc7662' },
          { category: 'security', label: 'RFC 7662 §4 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc7662#section-4' },
        ],
      },
      {
        id: 'token-revocation',
        backendId: 'token_revocation',
        name: 'Token Revocation',
        rfc: 'RFC 7009',
        references: [
          { category: 'core', label: 'RFC 7009 — Token Revocation', href: 'https://datatracker.ietf.org/doc/html/rfc7009' },
          { category: 'security', label: 'RFC 7009 §5 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc7009#section-5' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'RFC 6749 — OAuth 2.0 Authorization Framework', href: 'https://datatracker.ietf.org/doc/html/rfc6749' },
      { category: 'core', label: 'RFC 6750 — Bearer Token Usage', href: 'https://datatracker.ietf.org/doc/html/rfc6750' },
      { category: 'security', label: 'RFC 9700 — OAuth 2.0 Security Best Current Practice (BCP 240)', href: 'https://datatracker.ietf.org/doc/html/rfc9700', note: 'The canonical security guidance for modern OAuth deployments.' },
      { category: 'security', label: 'RFC 6819 — OAuth 2.0 Threat Model and Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc6819', note: 'Original threat model; superseded in practice by RFC 9700.' },
      { category: 'companion', label: 'RFC 7636 — Proof Key for Code Exchange (PKCE)', href: 'https://datatracker.ietf.org/doc/html/rfc7636' },
      { category: 'companion', label: 'RFC 7662 — Token Introspection', href: 'https://datatracker.ietf.org/doc/html/rfc7662' },
      { category: 'companion', label: 'RFC 7009 — Token Revocation', href: 'https://datatracker.ietf.org/doc/html/rfc7009' },
      { category: 'companion', label: 'RFC 8414 — Authorization Server Metadata', href: 'https://datatracker.ietf.org/doc/html/rfc8414' },
      { category: 'companion', label: 'RFC 8693 — Token Exchange', href: 'https://datatracker.ietf.org/doc/html/rfc8693' },
      { category: 'companion', label: 'RFC 8707 — Resource Indicators', href: 'https://datatracker.ietf.org/doc/html/rfc8707' },
      { category: 'companion', label: 'RFC 9207 — Authorization Server Issuer Identification', href: 'https://datatracker.ietf.org/doc/html/rfc9207', note: 'AS Mix-Up defence.' },
      { category: 'companion', label: 'RFC 9449 — DPoP (Demonstrating Proof of Possession)', href: 'https://datatracker.ietf.org/doc/html/rfc9449' },
      { category: 'companion', label: 'RFC 9101 — JWT-Secured Authorization Request (JAR)', href: 'https://datatracker.ietf.org/doc/html/rfc9101' },
      { category: 'companion', label: 'RFC 9126 — Pushed Authorization Requests (PAR)', href: 'https://datatracker.ietf.org/doc/html/rfc9126' },
    ],
  },
  {
    id: 'oidc',
    name: 'OpenID Connect',
    description: 'An identity layer built on top of OAuth 2.0. Adds authentication to authorization, enabling clients to verify user identity and obtain basic profile information.',
    spec: 'OpenID Connect Core 1.0',
    specUrl: 'https://openid.net/specs/openid-connect-core-1_0.html',
    flows: [
      {
        id: 'oidc-authorization-code',
        backendId: 'oidc_authorization_code',
        name: 'Authorization Code Flow',
        rfc: '§3.1',
        references: [
          { category: 'core', label: 'OIDC Core §3.1 — Authentication using the Authorization Code Flow', href: 'https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth' },
          { category: 'security', label: 'OIDC Core §16 — Security Considerations', href: 'https://openid.net/specs/openid-connect-core-1_0.html#Security' },
          { category: 'security', label: 'OIDC Core §15.5.2 — Nonce Implementation Notes', href: 'https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes' },
        ],
      },
      {
        id: 'oidc-implicit',
        backendId: 'oidc_implicit',
        name: 'Implicit Flow (Legacy)',
        rfc: '§3.2',
        references: [
          { category: 'core', label: 'OIDC Core §3.2 — Authentication using the Implicit Flow', href: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth' },
          { category: 'security', label: 'RFC 9700 §2.1.2 — Implicit Grant SHOULD NOT Be Used', href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2', note: 'Modern guidance: prefer Authorization Code + PKCE.' },
        ],
      },
      {
        id: 'hybrid',
        backendId: 'oidc_hybrid',
        name: 'Hybrid Flow',
        rfc: '§3.3',
        references: [
          { category: 'core', label: 'OIDC Core §3.3 — Authentication using the Hybrid Flow', href: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth' },
          { category: 'security', label: 'OIDC Core §3.3.2 — Hybrid Flow Authorization Endpoint', href: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridAuthorizationEndpoint' },
          { category: 'security', label: 'OIDC Core §3.3.3 — Hybrid Flow Token Endpoint', href: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridTokenEndpoint' },
        ],
      },
      {
        id: 'userinfo',
        backendId: 'oidc_userinfo',
        name: 'UserInfo Endpoint',
        rfc: '§5.3',
        references: [
          { category: 'core', label: 'OIDC Core §5.3 — UserInfo Endpoint', href: 'https://openid.net/specs/openid-connect-core-1_0.html#UserInfo' },
          { category: 'security', label: 'OIDC Core §16.11 — Token Substitution', href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenSubstitution' },
        ],
      },
      {
        id: 'discovery',
        backendId: 'oidc_discovery',
        name: 'Discovery',
        rfc: 'Discovery 1.0',
        references: [
          { category: 'core', label: 'OpenID Connect Discovery 1.0', href: 'https://openid.net/specs/openid-connect-discovery-1_0.html' },
          { category: 'security', label: 'Discovery 1.0 §7 — Security Considerations', href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#Security' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'OpenID Connect Core 1.0', href: 'https://openid.net/specs/openid-connect-core-1_0.html' },
      { category: 'core', label: 'OpenID Connect Discovery 1.0', href: 'https://openid.net/specs/openid-connect-discovery-1_0.html' },
      { category: 'core', label: 'OpenID Connect Dynamic Client Registration 1.0', href: 'https://openid.net/specs/openid-connect-registration-1_0.html' },
      { category: 'core', label: 'OpenID Connect RP-Initiated Logout 1.0', href: 'https://openid.net/specs/openid-connect-rpinitiated-1_0.html' },
      { category: 'core', label: 'OpenID Connect Back-Channel Logout 1.0', href: 'https://openid.net/specs/openid-connect-backchannel-1_0.html' },
      { category: 'core', label: 'OpenID Connect Front-Channel Logout 1.0', href: 'https://openid.net/specs/openid-connect-frontchannel-1_0.html' },
      { category: 'security', label: 'OpenID Connect Core §16 — Security Considerations', href: 'https://openid.net/specs/openid-connect-core-1_0.html#Security', note: 'Section dedicated to OIDC-specific threats above OAuth 2.0.' },
      { category: 'companion', label: 'RFC 7519 — JSON Web Token (JWT)', href: 'https://datatracker.ietf.org/doc/html/rfc7519' },
      { category: 'companion', label: 'RFC 7515 — JSON Web Signature (JWS)', href: 'https://datatracker.ietf.org/doc/html/rfc7515' },
      { category: 'companion', label: 'RFC 7516 — JSON Web Encryption (JWE)', href: 'https://datatracker.ietf.org/doc/html/rfc7516' },
      { category: 'companion', label: 'RFC 7517 — JSON Web Key (JWK)', href: 'https://datatracker.ietf.org/doc/html/rfc7517' },
      { category: 'companion', label: 'RFC 7518 — JSON Web Algorithms (JWA)', href: 'https://datatracker.ietf.org/doc/html/rfc7518' },
      { category: 'companion', label: 'RFC 9493 — Subject Identifiers for SETs', href: 'https://datatracker.ietf.org/doc/html/rfc9493' },
      { category: 'profile', label: 'FAPI 2.0 Security Profile', href: 'https://openid.net/specs/fapi-security-profile-2_0.html', note: 'High-assurance profile for financial-grade APIs.' },
      { category: 'profile', label: 'FAPI 2.0 Message Signing', href: 'https://openid.net/specs/fapi-message-signing-2_0.html' },
    ],
  },
  {
    id: 'oid4vci',
    name: 'OID4VCI',
    description: 'OpenID for Verifiable Credential Issuance. Demonstrates credential offers, pre-authorized code token exchange, nonce-bound proof validation, and multi-format VC issuance (dc+sd-jwt, jwt_vc_json, jwt_vc_json-ld, ldp_vc).',
    spec: 'OpenID4VCI 1.0',
    specUrl: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html',
    flows: [
      {
        id: 'oid4vci-pre-authorized',
        name: 'Pre-Authorized Code',
        rfc: 'OID4VCI §4, §6.1, §8',
        references: [
          { category: 'core', label: 'OID4VCI 1.0 §4 — Credential Offer', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-offer' },
          { category: 'core', label: 'OID4VCI 1.0 §3.5 — Pre-Authorized Code Flow', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-pre-authorized-code-flow' },
          { category: 'core', label: 'OID4VCI 1.0 §8 — Credential Endpoint', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-credential-endpoint' },
          { category: 'security', label: 'OID4VCI 1.0 §13.6 — Pre-Authorized Code Flow Security Considerations', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-pre-authorized-code-flow-2' },
        ],
      },
      {
        id: 'oid4vci-pre-authorized-tx-code',
        name: 'Pre-Authorized + tx_code',
        rfc: 'OID4VCI §6.1',
        references: [
          { category: 'core', label: 'OID4VCI 1.0 §6.1 — Token Request', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-token-request' },
          { category: 'security', label: 'OID4VCI 1.0 §13.6.2 — Transaction Code Phishing', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-transaction-code-phishing' },
        ],
      },
      {
        id: 'oid4vci-deferred-issuance',
        name: 'Deferred Issuance',
        rfc: 'OID4VCI Deferred Endpoint',
        references: [
          { category: 'core', label: 'OID4VCI 1.0 §9 — Deferred Credential Endpoint', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-deferred-credential-endpoin' },
          { category: 'security', label: 'OID4VCI 1.0 §13 — Security Considerations', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-security-considerations' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'OpenID for Verifiable Credential Issuance 1.0', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html' },
      { category: 'security', label: 'OID4VCI 1.0 §13 — Security Considerations', href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html#name-security-considerations' },
      { category: 'security', label: 'OpenID Foundation — Formal Security Analysis of OpenID for VCs', href: 'https://openid.net/formal-security-analysis-openid-verifiable-credentials/', note: 'Independent formal analysis covering OID4VCI and OID4VP.' },
      { category: 'companion', label: 'IETF SD-JWT (Selective Disclosure for JWTs)', href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/' },
      { category: 'companion', label: 'IETF SD-JWT VC (SD-JWT-based Verifiable Credentials)', href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/' },
      { category: 'companion', label: 'W3C Verifiable Credentials Data Model 2.0', href: 'https://www.w3.org/TR/vc-data-model-2.0/' },
      { category: 'companion', label: 'ISO/IEC 18013-5 — Mobile Driving Licence (mDL)', href: 'https://www.iso.org/standard/69084.html' },
      { category: 'companion', label: 'RFC 7800 — Proof-of-Possession Key Semantics for JWTs', href: 'https://datatracker.ietf.org/doc/html/rfc7800', note: 'cnf claim used for credential key binding.' },
      { category: 'companion', label: 'RFC 7636 — Proof Key for Code Exchange (PKCE)', href: 'https://datatracker.ietf.org/doc/html/rfc7636' },
      { category: 'profile', label: 'OpenID4VC High Assurance Interoperability Profile (HAIP)', href: 'https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html', note: 'Required-feature profile for eIDAS 2 and similar high-assurance regimes.' },
    ],
  },
  {
    id: 'oid4vp',
    name: 'OID4VP',
    description: 'OpenID for Verifiable Presentations. Shows DCQL request contracts, request object validation, direct_post/direct_post.jwt responses, and verifier policy decisions.',
    spec: 'OpenID4VP 1.0',
    specUrl: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html',
    flows: [
      {
        id: 'oid4vp-direct-post',
        name: 'DCQL + direct_post',
        rfc: 'OID4VP §5, §8.2',
        references: [
          { category: 'core', label: 'OID4VP 1.0 §5 — Authorization Request', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-authorization-request' },
          { category: 'core', label: 'OID4VP 1.0 §6.1 — DCQL (Digital Credentials Query Language)', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-digital-credentials-query-l' },
          { category: 'core', label: 'OID4VP 1.0 §8.2 — direct_post Response Mode', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-response-mode-direct_post' },
          { category: 'security', label: 'OID4VP 1.0 §14.1 — Verifier Impersonation (Preventing Replay of Verifiable Presentations)', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-preventing-replay-of-verifi' },
        ],
      },
      {
        id: 'oid4vp-direct-post-jwt',
        name: 'DCQL + direct_post.jwt',
        rfc: 'OID4VP §8.3.1',
        references: [
          { category: 'core', label: 'OID4VP 1.0 §8.3.1 — direct_post.jwt Response Mode', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-response-mode-direct_postjw' },
          { category: 'core', label: 'RFC 7516 — JSON Web Encryption (JWE)', href: 'https://datatracker.ietf.org/doc/html/rfc7516' },
          { category: 'security', label: 'OID4VP 1.0 §14.1.2 — Verifiable Presentations (Nonce Binding)', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-verifiable-presentations' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'OpenID for Verifiable Presentations 1.0', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html' },
      { category: 'security', label: 'OID4VP 1.0 §14 — Security Considerations', href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-security-considerations' },
      { category: 'security', label: 'OpenID Foundation — Formal Security Analysis of OpenID for VCs', href: 'https://openid.net/formal-security-analysis-openid-verifiable-credentials/' },
      { category: 'companion', label: 'RFC 9101 — JWT-Secured Authorization Request (JAR)', href: 'https://datatracker.ietf.org/doc/html/rfc9101' },
      { category: 'companion', label: 'RFC 7516 — JSON Web Encryption (JWE)', href: 'https://datatracker.ietf.org/doc/html/rfc7516', note: 'Underlies direct_post.jwt response encryption.' },
      { category: 'companion', label: 'W3C Digital Credentials API', href: 'https://w3c-fedid.github.io/digital-credentials/', note: 'Browser API for presenting VCs to verifiers.' },
      { category: 'companion', label: 'digitalcredentials.dev', href: 'https://digitalcredentials.dev/', note: 'Experimental verifier and wallet playground for OID4VP and W3C credentials.' },
      { category: 'profile', label: 'OpenID4VC High Assurance Interoperability Profile (HAIP)', href: 'https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html' },
    ],
  },
  {
    id: 'saml',
    name: 'SAML 2.0',
    description: 'XML-based standard for exchanging authentication and authorization data between identity providers and service providers. Enables enterprise single sign-on.',
    spec: 'SAML 2.0 Core',
    specUrl: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf',
    flows: [
      {
        id: 'sp-initiated-sso',
        backendId: 'sp_initiated_sso',
        name: 'SP-Initiated SSO',
        rfc: 'Profiles §4.1',
        references: [
          { category: 'core', label: 'SAML 2.0 Profiles §4.1 — Web Browser SSO Profile', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf' },
          { category: 'core', label: 'SAML 2.0 Bindings — HTTP-POST and HTTP-Redirect', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf' },
          { category: 'security', label: 'SAML Security and Privacy Considerations §6.4 — Stolen Assertion / Replay', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf' },
        ],
      },
      {
        id: 'idp-initiated-sso',
        backendId: 'idp_initiated_sso',
        name: 'IdP-Initiated SSO',
        rfc: 'Profiles §4.1.5',
        references: [
          { category: 'core', label: 'SAML 2.0 Profiles §4.1.5 — Unsolicited Responses', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf' },
          { category: 'security', label: 'SAML Security and Privacy Considerations §6.4 — Replay without InResponseTo', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf', note: 'IdP-initiated has no AuthnRequest to bind against — assertion-ID cache is mandatory.' },
        ],
      },
      {
        id: 'single-logout',
        backendId: 'single_logout',
        name: 'Single Logout (SLO)',
        rfc: 'Profiles §4.4',
        references: [
          { category: 'core', label: 'SAML 2.0 Profiles §4.4 — Single Logout Profile', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf' },
          { category: 'security', label: 'SAML Security and Privacy Considerations §7.1.4 — Single Logout Profile', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf' },
        ],
      },
      {
        id: 'metadata',
        name: 'Metadata Exchange',
        rfc: 'Metadata',
        references: [
          { category: 'core', label: 'SAML 2.0 Metadata', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf' },
          { category: 'security', label: 'SAML Security and Privacy Considerations §6.5 — Trust Establishment', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'SAML 2.0 Core', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf' },
      { category: 'core', label: 'SAML 2.0 Bindings', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf' },
      { category: 'core', label: 'SAML 2.0 Profiles', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf' },
      { category: 'core', label: 'SAML 2.0 Metadata', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf' },
      { category: 'core', label: 'SAML 2.0 Authentication Context', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-authn-context-2.0-os.pdf' },
      { category: 'core', label: 'SAML 2.0 Conformance', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf' },
      { category: 'security', label: 'SAML 2.0 Security and Privacy Considerations', href: 'https://docs.oasis-open.org/security/saml/v2.0/saml-sec-consider-2.0-os.pdf', note: 'OASIS-published threat model and countermeasures specific to SAML.' },
      { category: 'security', label: 'SAML 2.0 Approved Errata', href: 'https://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.html', note: 'Includes security-relevant clarifications.' },
      { category: 'companion', label: 'W3C XML Signature Syntax and Processing', href: 'https://www.w3.org/TR/xmldsig-core/' },
      { category: 'companion', label: 'W3C XML Encryption Syntax and Processing', href: 'https://www.w3.org/TR/xmlenc-core1/' },
    ],
  },
  {
    id: 'spiffe',
    name: 'SPIFFE/SPIRE',
    description: 'Secure Production Identity Framework for Everyone. Provides cryptographic workload identity for zero-trust architectures via X.509 and JWT SVIDs.',
    spec: 'SPIFFE Specifications',
    specUrl: 'https://spiffe.io/docs/latest/spiffe-about/overview/',
    flows: [
      {
        id: 'x509-svid-issuance',
        name: 'X.509-SVID Acquisition',
        rfc: 'X.509-SVID',
        references: [
          { category: 'core', label: 'SPIFFE X.509-SVID', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/' },
          { category: 'core', label: 'SPIFFE Workload API §5.2.1 — FetchX509SVID', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/#521-fetchx509svid' },
          { category: 'security', label: 'X.509-SVID §4 — Constraints and Usage', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#4-constraints-and-usage' },
        ],
      },
      {
        id: 'jwt-svid-issuance',
        name: 'JWT-SVID Acquisition',
        rfc: 'JWT-SVID',
        references: [
          { category: 'core', label: 'SPIFFE JWT-SVID', href: 'https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/' },
          { category: 'core', label: 'SPIFFE Workload API §6.2.1 — FetchJWTSVID', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/#621-fetchjwtsvid' },
          { category: 'security', label: 'JWT-SVID §7 — Security Considerations', href: 'https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/#7-security-considerations' },
        ],
      },
      {
        id: 'mtls-handshake',
        name: 'mTLS with X.509-SVIDs',
        rfc: 'RFC 8446',
        references: [
          { category: 'core', label: 'SPIFFE X.509-SVID §5 — Validation', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#5-validation' },
          { category: 'core', label: 'RFC 8446 — TLS 1.3', href: 'https://datatracker.ietf.org/doc/html/rfc8446' },
          { category: 'security', label: 'X.509-SVID §4 — Constraints and Usage', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#4-constraints-and-usage' },
        ],
      },
      {
        id: 'certificate-rotation',
        name: 'Certificate Rotation',
        rfc: 'Workload API',
        references: [
          { category: 'core', label: 'SPIFFE Workload API §4.2 — Connection Lifetime', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/#42-connection-lifetime' },
          { category: 'security', label: 'X.509-SVID §4 — Constraints and Usage', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#4-constraints-and-usage' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'SPIFFE-ID', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe-id/' },
      { category: 'core', label: 'SPIFFE X.509-SVID', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/' },
      { category: 'core', label: 'SPIFFE JWT-SVID', href: 'https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/' },
      { category: 'core', label: 'SPIFFE Workload API', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/' },
      { category: 'core', label: 'SPIFFE Trust Domain and Bundle', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/' },
      { category: 'core', label: 'SPIFFE Federation', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/' },
      { category: 'security', label: 'X.509-SVID §4 — Constraints and Usage', href: 'https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#4-constraints-and-usage' },
      { category: 'security', label: 'JWT-SVID §7 — Security Considerations', href: 'https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/#7-security-considerations' },
      { category: 'security', label: 'Federation §7 — Security Considerations', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_federation/#7-security-considerations' },
      { category: 'security', label: 'Trust Domain and Bundle §6 — Security Considerations', href: 'https://spiffe.io/docs/latest/spiffe-specs/spiffe_trust_domain_and_bundle/#6-security-considerations' },
      { category: 'companion', label: 'RFC 8446 — TLS 1.3', href: 'https://datatracker.ietf.org/doc/html/rfc8446', note: 'Underlying transport for X.509-SVID mTLS.' },
      { category: 'companion', label: 'SPIRE Documentation', href: 'https://spiffe.io/docs/latest/spire-about/spire-concepts/', note: 'Reference implementation of SPIFFE.' },
    ],
  },
  {
    id: 'scim',
    name: 'SCIM 2.0',
    description: 'System for Cross-domain Identity Management (SCIM). Standards-based protocol for automating user provisioning and lifecycle management between identity providers and service providers.',
    spec: 'System for Cross-domain Identity Management (RFC 7642, 7643, 7644)',
    specUrl: 'https://datatracker.ietf.org/doc/html/rfc7644',
    flows: [
      {
        id: 'user-lifecycle',
        name: 'User Lifecycle',
        rfc: 'RFC 7644 §3.2-3.6',
        references: [
          { category: 'core', label: 'RFC 7644 §3.3 — Creating Resources', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.3' },
          { category: 'core', label: 'RFC 7644 §3.5 — Modifying with PATCH', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5' },
          { category: 'core', label: 'RFC 7643 §4.1 — User Resource Schema', href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.1' },
          { category: 'security', label: 'RFC 7644 §7 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7' },
        ],
      },
      {
        id: 'group-management',
        backendId: 'group-membership',
        name: 'Group Management',
        rfc: 'RFC 7644 §3.2-3.6',
        references: [
          { category: 'core', label: 'RFC 7643 §4.2 — Group Resource Schema', href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.2' },
          { category: 'core', label: 'RFC 7644 §3.5.2 — PATCH Operations', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2' },
          { category: 'security', label: 'RFC 7644 §7 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7' },
        ],
      },
      {
        id: 'filter-queries',
        backendId: 'user-discovery',
        name: 'Filter Queries',
        rfc: 'RFC 7644 §3.4.2',
        references: [
          { category: 'core', label: 'RFC 7644 §3.4.2 — Querying Resources', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2' },
          { category: 'core', label: 'RFC 7644 §3.4.2.2 — Filtering Grammar', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.2' },
        ],
      },
      {
        id: 'schema-discovery',
        name: 'Schema Discovery',
        rfc: 'RFC 7644 §4',
        references: [
          { category: 'core', label: 'RFC 7644 §4 — Service Provider Configuration', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-4' },
          { category: 'core', label: 'RFC 7643 §7 — Schema Definition', href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-7' },
        ],
      },
      {
        id: 'bulk-operations',
        name: 'Bulk Operations',
        rfc: 'RFC 7644 §3.7',
        references: [
          { category: 'core', label: 'RFC 7644 §3.7 — Bulk Operations', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.7' },
          { category: 'security', label: 'RFC 7644 §7 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'RFC 7642 — SCIM Definitions, Overview, Concepts, Requirements', href: 'https://datatracker.ietf.org/doc/html/rfc7642' },
      { category: 'core', label: 'RFC 7643 — SCIM Core Schema', href: 'https://datatracker.ietf.org/doc/html/rfc7643' },
      { category: 'core', label: 'RFC 7644 — SCIM Protocol', href: 'https://datatracker.ietf.org/doc/html/rfc7644' },
      { category: 'security', label: 'RFC 7644 §7 — Security Considerations (Protocol)', href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7' },
      { category: 'security', label: 'RFC 7643 §9 — Security Considerations (Schema)', href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-9' },
    ],
  },
  {
    id: 'ssf',
    name: 'Shared Signals (SSF)',
    description: 'OpenID Shared Signals Framework for real-time security event sharing. Enables continuous access evaluation (CAEP) and risk incident coordination (RISC) between identity providers and relying parties.',
    spec: 'SSF 1.0, CAEP 1.0, RISC 1.0, RFC 8417',
    specUrl: 'https://openid.net/specs/openid-sharedsignals-framework-1_0.html',
    flows: [
      {
        id: 'ssf-stream-configuration',
        name: 'Stream Configuration',
        rfc: 'SSF §4',
        references: [
          { category: 'core', label: 'OpenID SSF §8 — Management API for SET Event Streams', href: 'https://openid.net/specs/openid-sharedsignals-framework-1_0.html' },
        ],
      },
      {
        id: 'ssf-push-delivery',
        name: 'Push Delivery',
        rfc: 'SSF §5.2.1',
        references: [
          { category: 'core', label: 'RFC 8935 — SET Delivery via HTTP Push', href: 'https://datatracker.ietf.org/doc/html/rfc8935' },
          { category: 'security', label: 'RFC 8935 §5 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc8935#section-5' },
        ],
      },
      {
        id: 'ssf-poll-delivery',
        name: 'Poll Delivery',
        rfc: 'SSF §5.2.2',
        references: [
          { category: 'core', label: 'RFC 8936 — SET Delivery via HTTP Polling', href: 'https://datatracker.ietf.org/doc/html/rfc8936' },
          { category: 'security', label: 'RFC 8936 §4 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc8936#section-4' },
        ],
      },
      {
        id: 'caep-session-revoked',
        name: 'Session Revoked (CAEP)',
        rfc: 'CAEP §3.1',
        references: [
          { category: 'core', label: 'OpenID CAEP §3.1 — session-revoked', href: 'https://openid.net/specs/openid-caep-1_0-final.html' },
          { category: 'core', label: 'RFC 8417 — Security Event Token', href: 'https://datatracker.ietf.org/doc/html/rfc8417' },
        ],
      },
      {
        id: 'caep-credential-change',
        name: 'Credential Change (CAEP)',
        rfc: 'CAEP §3.2',
        references: [
          { category: 'core', label: 'OpenID CAEP §3.3 — credential-change', href: 'https://openid.net/specs/openid-caep-1_0-final.html' },
        ],
      },
      {
        id: 'risc-account-disabled',
        name: 'Account Disabled (RISC)',
        rfc: 'RISC §2.2',
        references: [
          { category: 'core', label: 'OpenID RISC §2.3 — account-disabled', href: 'https://openid.net/specs/openid-risc-1_0.html' },
        ],
      },
      {
        id: 'risc-credential-compromise',
        name: 'Credential Compromise (RISC)',
        rfc: 'RISC §2.1',
        references: [
          { category: 'core', label: 'OpenID RISC §2.7 — credential-compromise', href: 'https://openid.net/specs/openid-risc-1_0.html' },
          { category: 'security', label: 'RISC §2.7 — Privacy Warning (do not include credential values)', href: 'https://openid.net/specs/openid-risc-1_0.html' },
        ],
      },
    ],
    references: [
      { category: 'core', label: 'OpenID Shared Signals Framework 1.0', href: 'https://openid.net/specs/openid-sharedsignals-framework-1_0.html' },
      { category: 'core', label: 'OpenID CAEP — Continuous Access Evaluation Profile', href: 'https://openid.net/specs/openid-caep-1_0-final.html' },
      { category: 'core', label: 'OpenID RISC Profile 1.0', href: 'https://openid.net/specs/openid-risc-1_0.html' },
      { category: 'core', label: 'RFC 8417 — Security Event Token (SET)', href: 'https://datatracker.ietf.org/doc/html/rfc8417' },
      { category: 'security', label: 'RFC 8417 §5 — Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-5' },
      { category: 'security', label: 'RFC 8935 §5 — SET Push Delivery Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc8935#section-5' },
      { category: 'security', label: 'RFC 8936 §4 — SET Poll Delivery Security Considerations', href: 'https://datatracker.ietf.org/doc/html/rfc8936#section-4' },
      { category: 'companion', label: 'RFC 8935 — SET Delivery Using HTTP Push (POST)', href: 'https://datatracker.ietf.org/doc/html/rfc8935' },
      { category: 'companion', label: 'RFC 8936 — SET Delivery Using HTTP Polling', href: 'https://datatracker.ietf.org/doc/html/rfc8936' },
      { category: 'companion', label: 'RFC 9493 — Subject Identifiers for SETs', href: 'https://datatracker.ietf.org/doc/html/rfc9493' },
      { category: 'companion', label: 'RFC 7519 — JSON Web Token (JWT)', href: 'https://datatracker.ietf.org/doc/html/rfc7519' },
      { category: 'companion', label: 'RFC 7515 — JSON Web Signature (JWS)', href: 'https://datatracker.ietf.org/doc/html/rfc7515' },
    ],
  },
]

export const PROTOCOL_IDS = PROTOCOL_CATALOG_DATA.map((protocol) => protocol.id)

const PROTOCOL_CATALOG_BY_ID = new Map(
  PROTOCOL_CATALOG_DATA.map((protocol) => [protocol.id, protocol]),
)

export function getCatalogProtocol(protocolId: string): ProtocolCatalogDataItem | undefined {
  return PROTOCOL_CATALOG_BY_ID.get(protocolId)
}

export function getCatalogFlow(
  protocolId: string,
  flowRouteId: string,
): ProtocolFlowCatalogData | undefined {
  return getCatalogProtocol(protocolId)?.flows.find((flow) => flow.id === flowRouteId)
}

export function getBackendFlowId(
  protocolId: string,
  flowRouteId: string,
): string | null {
  const catalogFlow = getCatalogFlow(protocolId, flowRouteId)
  if (!catalogFlow) {
    return null
  }
  return catalogFlow.backendId || catalogFlow.id
}

export function getFlowRouteId(
  protocolId: string,
  backendFlowId: string,
): string {
  const protocol = getCatalogProtocol(protocolId)
  if (!protocol) {
    return backendFlowId.replace(/_/g, '-')
  }

  const catalogFlow = protocol.flows.find(
    (flow) => (flow.backendId || flow.id) === backendFlowId,
  )
  if (catalogFlow) {
    return catalogFlow.id
  }

  return backendFlowId.replace(/_/g, '-')
}

export function getAllowedBackendFlowIds(protocolId: string): Set<string> {
  const protocol = getCatalogProtocol(protocolId)
  if (!protocol) {
    return new Set()
  }
  return new Set(protocol.flows.map((flow) => flow.backendId || flow.id))
}
