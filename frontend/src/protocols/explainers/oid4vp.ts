/**
 * OpenID for Verifiable Presentations (OID4VP) — Parameter Explainers
 *
 * Presentation-side entries: VP token replay, DCQL query manipulation,
 * verifier impersonation via client_id_scheme, response_mode confidentiality,
 * KB-JWT binding.
 *
 * Per-protocol overrides:
 *   `oid4vp:nonce`     — VP-binding semantics (different from OIDC ID Token nonce)
 *   `oid4vp:client_id` — verifier identity with cryptographic scheme prefix
 */

import type { ParameterExplainer } from './index'

export const OID4VP_EXPLAINERS: Record<string, ParameterExplainer> = {
  vp_token: {
    purpose:
      'The Verifiable Presentation token returned by the wallet. Contains ' +
      'one or more credentials (or selective disclosures of them) plus a ' +
      'Holder Binding signature proving the wallet controls the key the ' +
      'credential is bound to. The cryptographic deliverable of the entire ' +
      'OID4VP flow.',
    attacks: [
      {
        id: 'vp-token-replay-forwarding',
        name: 'VP token replay / forwarding',
        scenario:
          'Mallory captures a vp_token from any flow she observes ' +
          '(compromised wallet plugin, captured response on a non-TLS ' +
          'internal hop, leaked log). She replays it to a *different* ' +
          'verifier — or back to the same verifier under a fresh state ' +
          'value. Without strict `nonce` and `aud` validation on the inner ' +
          'Key Binding JWT, the new verifier sees a cryptographically valid ' +
          'presentation and authenticates Mallory as Alice. The VP itself ' +
          'signs over the verifier\'s nonce and audience precisely to ' +
          'prevent this — the attack opens up wherever those checks are ' +
          'weak.',
        impact:
          'Authentication bypass via captured-presentation replay.',
      },
      {
        id: 'vp-validation-skip',
        name: 'Validation step skipped',
        scenario:
          'Verifiers commonly skip one of: signature on the issuer ' +
          'credential, KB-JWT signature, nonce binding, audience binding, ' +
          'expiry check, `typ=kb+jwt` check, alg=none rejection. Each skip ' +
          'turns a useless captured token into a usable authentication.',
        impact:
          'Each skipped check independently breaks the protocol\'s ' +
          'authentication guarantee.',
      },
    ],
    mitigations: [
      {
        action:
          'Verify the issuer signature on the credential against the ' +
          'issuer\'s JWKS.',
        mitigates: ['vp-validation-skip'],
      },
      {
        action:
          'Verify the Holder Binding / KB-JWT signature against the ' +
          '`cnf.jwk` embedded in the credential.',
        mitigates: ['vp-token-replay-forwarding', 'vp-validation-skip'],
      },
      {
        action:
          'Verify `nonce` in the KB-JWT matches the value this verifier ' +
          'sent in the request.',
        mitigates: ['vp-token-replay-forwarding', 'vp-validation-skip'],
      },
      {
        action:
          'Verify `aud` matches this verifier\'s client_id.',
        mitigates: ['vp-token-replay-forwarding', 'vp-validation-skip'],
      },
      {
        action:
          'Verify creation time within an acceptable window; verify ' +
          '`typ=kb+jwt` for SD-JWT KB-JWTs; reject `alg=none`.',
        mitigates: ['vp-validation-skip'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §8 (Response)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response',
      },
      {
        label: 'SD-JWT §5.4 (Key Binding JWT validation)',
        href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/',
      },
      {
        label: 'OID4VP 1.0 §14.1 (Preventing Replay of Verifiable Presentations)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-preventing-replay-of-verifi',
      },
    ],
  },

  dcql_query: {
    purpose:
      'Digital Credentials Query Language object the verifier sends to ' +
      'specify which credentials and which claims it wants the wallet to ' +
      'present. Replaces the older Presentation Exchange ' +
      '`presentation_definition` (removed from OID4VP draft 26+). Encodes ' +
      'credential type filters, claim path requirements, and disclosure ' +
      'preferences.',
    attacks: [
      {
        id: 'over-broad-query-privacy-harvest',
        name: 'Over-broad-query privacy harvest',
        scenario:
          'A verifier that needs to confirm the user is over 18 issues a ' +
          'DCQL query for the entire driver\'s license credential — full ' +
          'name, address, license number, photograph. The user, trusting ' +
          'the wallet UI, approves. The verifier now has data it had no ' +
          'legitimate business reason to collect, in a cryptographically ' +
          'authenticated package. SD-JWT selective disclosure mitigates ' +
          'this when the query is narrowly written (request only ' +
          '`age_over_18`); blown when the query is loose.',
        impact:
          'Privacy violation under data-minimisation regimes (GDPR, eIDAS 2). ' +
          'The credential is cryptographically authentic, so the user has ' +
          'no plausible deniability about the disclosure.',
      },
    ],
    mitigations: [
      {
        action:
          'Verifier writes the narrowest DCQL query that satisfies the ' +
          'legitimate purpose — request `age_over_18`, not the whole ' +
          'driver\'s license.',
        mitigates: ['over-broad-query-privacy-harvest'],
      },
      {
        action:
          'Wallet shows the user *exactly* which claims will be disclosed ' +
          'before signing the presentation — not "share your driver\'s ' +
          'license" but "share: age_over_18".',
        mitigates: ['over-broad-query-privacy-harvest'],
      },
      {
        action:
          'Use credential formats that support selective disclosure ' +
          '(SD-JWT-VC, mdoc) so the wallet can reveal only the requested ' +
          'fields.',
        mitigates: ['over-broad-query-privacy-harvest'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §6.1 (DCQL)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l',
      },
      {
        label: 'OID4VP 1.0 §14 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-security-considerations',
      },
    ],
  },

  client_id_scheme: {
    purpose:
      'The cryptographic scheme by which the verifier (Client) authenticates ' +
      'itself to the wallet. Encoded as a prefix on `client_id` in current ' +
      'OID4VP drafts (e.g. `x509_san_dns:verifier.example.com`, ' +
      '`did:web:verifier.example.com`, `verifier_attestation:...`). The ' +
      'scheme tells the wallet how to verify that the request actually came ' +
      'from the named verifier.',
    attacks: [
      {
        id: 'verifier-impersonation',
        name: 'Verifier impersonation',
        scenario:
          'With `client_id_scheme=redirect_uri` (the legacy default), the ' +
          'wallet has only the URL to identify the verifier — same trust ' +
          'model as OAuth2 redirect. Mallory hosts a fake verifier UI at ' +
          '`accounts.googel.com` (typo) and sends Alice\'s wallet a ' +
          'presentation request claiming to be `accounts.google.com`. The ' +
          'wallet has no cryptographic basis to distinguish a legitimate ' +
          'verifier from an attacker who registered a similar-looking ' +
          'domain or hijacked DNS for the request URL — the domain typo ' +
          'passes muster. Alice presents her credential to Mallory ' +
          'thinking Mallory is Google.',
        impact:
          'Verifier impersonation = credential phishing at scale. The ' +
          'credential, once disclosed, is cryptographically authentic ' +
          'evidence the user holds it.',
      },
    ],
    mitigations: [
      {
        action:
          'Use schemes that ground the verifier identity in a key the ' +
          'wallet can cryptographically verify: `x509_san_dns` (X.509 cert ' +
          'whose SAN MUST contain the claimed domain), ' +
          '`verifier_attestation` (signed assertion from a trusted issuer), ' +
          '`did:web` with proper resolution.',
        mitigates: ['verifier-impersonation'],
      },
      {
        action:
          'Do not use the legacy `redirect_uri` scheme outside development ' +
          'environments.',
        mitigates: ['verifier-impersonation'],
      },
      {
        action:
          'For high-assurance flows, follow OpenID4VC HAIP 1.0 which ' +
          'mandates signed Authorization Requests (JAR) with X.509 cert ' +
          'chains.',
        mitigates: ['verifier-impersonation'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §5.9 (Client Identifier Prefix)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an',
      },
      {
        label: 'OID4VP 1.0 §14.1 (Verifier Impersonation — Preventing Replay)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-preventing-replay-of-verifi',
      },
      {
        label: 'OpenID4VC HAIP 1.0',
        href: 'https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html',
      },
    ],
  },

  response_mode: {
    purpose:
      'Tells the wallet how to deliver the authorization response. ' +
      '`direct_post` POSTs `vp_token` + `state` as form parameters to ' +
      '`response_uri`. `direct_post.jwt` POSTs an encrypted JWE wrapping a ' +
      'signed inner JWT. `dc_api` / `dc_api.jwt` (added in OID4VP 1.0 ' +
      'final) deliver the response via the W3C Digital Credentials browser ' +
      'API instead of an HTTP POST. Legacy `query` and `fragment` modes ' +
      'return the response in the redirect URL.',
    attacks: [
      {
        id: 'fragment-leak-response-mode',
        name: 'Response leakage in fragment / query modes',
        scenario:
          'With `response_mode=fragment`, the vp_token sits in ' +
          '`window.location.hash` on the wallet-callback page. Mallory\'s ' +
          'analytics tag on that page reads `location.hash` and exfiltrates ' +
          'the vp_token. Browser history and Referer headers expose it ' +
          'further. `query` mode is similar with the response in the URL ' +
          'query string.',
        impact:
          'Direct credential disclosure to anything with script access on ' +
          'the wallet callback page.',
      },
      {
        id: 'edge-tier-credential-capture',
        name: 'Edge-tier credential capture in plain direct_post',
        scenario:
          'With `response_mode=direct_post` (plain), the response runs ' +
          'server-to-server but in plaintext over TLS. A TLS-terminating ' +
          'load balancer or compromised CDN at the verifier sees the full ' +
          'response — typically with full SD-JWT disclosures including PII ' +
          'fields the verifier had no business decrypting at the edge. ' +
          'Mallory works at a CDN provider that does TLS termination for ' +
          'the verifier; every vp_token she sees in proxy logs includes ' +
          'the user\'s full disclosure set.',
        impact:
          'PII / credential disclosure at intermediate trust boundaries the ' +
          'user did not consent to.',
      },
    ],
    mitigations: [
      {
        action:
          'For high-assurance / privacy-sensitive presentations (mDL, ' +
          'health credentials, regulated identity), use `direct_post.jwt` ' +
          'with verifier-key-bound encryption.',
        rationale:
          'JWE only opens at the verifier\'s actual private key — ' +
          'TLS-terminating intermediaries see only ciphertext.',
        mitigates: [
          'fragment-leak-response-mode',
          'edge-tier-credential-capture',
        ],
      },
      {
        action:
          'For lower-stakes attribute checks, `direct_post` over TLS is ' +
          'acceptable.',
        mitigates: ['fragment-leak-response-mode'],
      },
      {
        action:
          'Never use `fragment` or `query` modes for VP responses outside ' +
          'test environments.',
        mitigates: ['fragment-leak-response-mode'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §8.2 (Response Mode "direct_post")',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post',
      },
      {
        label: 'OID4VP 1.0 §14 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-security-considerations',
      },
    ],
  },

  response_uri: {
    purpose:
      'The verifier endpoint to which the wallet POSTs the authorization ' +
      'response when `response_mode=direct_post` or `direct_post.jwt`. ' +
      'Replaces `redirect_uri` for direct_post modes — the wallet does not ' +
      'redirect a browser; it does a server-side POST.',
    attacks: [
      {
        id: 'response-collection-hijack',
        name: 'Response-collection hijack',
        scenario:
          'Mallory crafts a presentation request with `client_id` claiming ' +
          'to be a legit verifier but `response_uri` pointing at her own ' +
          'server. If the wallet does not bind `response_uri` to the ' +
          'verifier\'s authenticated identity (via `client_id_scheme`), ' +
          'the wallet POSTs the credential to Mallory.',
        impact:
          'Credential exfiltration directly to attacker.',
      },
    ],
    mitigations: [
      {
        action:
          'Wallet MUST verify `response_uri` matches an allowlist tied to ' +
          'the authenticated verifier — for `x509_san_dns` scheme, verify ' +
          '`response_uri` host appears in the certificate\'s SAN.',
        mitigates: ['response-collection-hijack'],
      },
      {
        action:
          'Use `direct_post.jwt` so even hijacked POSTs cannot be ' +
          'decrypted by an attacker without the verifier\'s private key.',
        mitigates: ['response-collection-hijack'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §8.2 (response_uri / direct_post)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post',
      },
      {
        label: 'OID4VP 1.0 §14 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-security-considerations',
      },
    ],
  },

  request_uri: {
    purpose:
      'A URL the wallet fetches to obtain the full authorization request as ' +
      'a signed JWT (a JAR — JWT-Secured Authorization Request). Lets ' +
      'verifiers send long, signed, integrity-protected requests via a ' +
      'short URL that fits in a QR code.',
    attacks: [
      {
        id: 'request-object-tampering',
        name: 'Request-object tampering (no JAR)',
        scenario:
          'Without JAR, the entire authorization request travels in the ' +
          'QR\'s URL parameters. An intermediate (malicious app handling ' +
          'the URL scheme, compromised browser extension, rogue clipboard ' +
          'manager) modifies the request URL to swap `response_uri` to an ' +
          'attacker endpoint or relax the DCQL query to disclose more ' +
          'claims. The wallet has no signature to verify, so it trusts the ' +
          'modified request. With JAR fetched via `request_uri`, the ' +
          'wallet validates the verifier\'s signature on the request JWT ' +
          'before processing — modifications fail.',
        impact:
          'Credential exfiltration to attacker endpoint, or over-disclosure ' +
          'beyond the verifier\'s intent.',
      },
    ],
    mitigations: [
      {
        action:
          'Use `request_uri` (JAR) for any production OID4VP deployment — ' +
          'the wallet validates the verifier\'s signature on the request ' +
          'JWT before processing.',
        mitigates: ['request-object-tampering'],
      },
      {
        action:
          'Combine with cryptographic `client_id_scheme` so the wallet can ' +
          'verify the signature against a key it actually trusts for the ' +
          'claimed verifier identity. HAIP 1.0 mandates this combination.',
        mitigates: ['request-object-tampering'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §5 (Authorization Request)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request',
      },
      {
        label: 'RFC 9101 (JAR)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9101',
      },
      {
        label: 'OID4VP 1.0 §14 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-security-considerations',
      },
    ],
  },

  response: {
    purpose:
      'In `response_mode=direct_post.jwt`, the encrypted JWE the wallet ' +
      'POSTs to `response_uri`. Wraps a signed inner JWT ' +
      '(typ=`oauth-authz-resp+jwt`) which carries `vp_token` and `state`. ' +
      'The JWE is encrypted to a key the verifier published in its client ' +
      'metadata.',
    attacks: [
      {
        id: 'response-inner-jwt-validation-skip',
        name: 'Inner JWT validation skipped after decryption',
        scenario:
          'Verifier decrypts the JWE successfully and extracts the inner ' +
          'JWT, but skips validation of the inner JWT\'s claims — `typ`, ' +
          '`aud`, `state`, signature. An attacker who can produce a JWE ' +
          'encrypted to the verifier\'s public key (which is published in ' +
          'client metadata) could submit a crafted inner JWT.',
        impact:
          'Validation bypass at the inner-token layer despite the JWE ' +
          'envelope being legitimately encrypted.',
      },
    ],
    mitigations: [
      {
        action:
          'Validate the inner JWT thoroughly: `typ=oauth-authz-resp+jwt`, ' +
          '`aud=response_uri`, state consistency, signature verification.',
        mitigates: ['response-inner-jwt-validation-skip'],
      },
      {
        action:
          'For privacy-sensitive credentials (especially under GDPR / ' +
          'eIDAS 2 high-assurance regimes), require `direct_post.jwt` — ' +
          'plain `direct_post` may not satisfy data-minimisation or ' +
          'encryption-in-transit requirements.',
        mitigates: ['response-inner-jwt-validation-skip'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §8.3.1 (direct_post.jwt)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_postjw',
      },
      {
        label: 'RFC 7516 (JWE)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7516',
      },
      {
        label: 'OID4VP 1.0 §14 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-security-considerations',
      },
    ],
  },

  // Per-protocol override: in OID4VP, `nonce` binds the *presentation* to
  // the verifier's challenge for this transaction (different scope from
  // OIDC's nonce, which binds an ID Token to an authentication session).
  'oid4vp:nonce': {
    purpose:
      'A high-entropy random value the verifier generates per presentation ' +
      'request, included in the request, and required to appear in the ' +
      'KB-JWT (Key Binding JWT) inside the vp_token. Ties the cryptographic ' +
      'proof of holder possession to this specific verifier transaction. ' +
      'OIDC `nonce` binds an ID Token to an authentication session; OID4VP ' +
      '`nonce` binds a presentation to a verification transaction.',
    attacks: [
      {
        id: 'cross-verifier-vp-replay',
        name: 'Cross-verifier vp_token replay',
        scenario:
          'Without nonce binding, a vp_token is reusable. Verifier A is ' +
          'honest. Verifier B is Mallory. Alice presents to A; Mallory is ' +
          'on the network path or operates a proxy and captures the ' +
          'vp_token. Without nonce checking, Mallory replays the captured ' +
          'token to her own infrastructure (claiming to be a third ' +
          'verifier C) or to verifier A under a fresh session — and the ' +
          'credential authenticates her. The verifier-issued nonce inside ' +
          'the KB-JWT is the only thing that ties the proof to *this* ' +
          'request.',
        impact:
          'Authentication bypass via captured-presentation replay across ' +
          'verifiers — the entire selling point of "fresh" cryptographic ' +
          'proof of possession evaporates.',
      },
    ],
    mitigations: [
      {
        action:
          'Wallet MUST sign over the verifier-issued nonce in the KB-JWT.',
        mitigates: ['cross-verifier-vp-replay'],
      },
      {
        action:
          'Verifier MUST generate a fresh nonce per request; verify the ' +
          'KB-JWT nonce matches the request nonce.',
        mitigates: ['cross-verifier-vp-replay'],
      },
      {
        action:
          'Verifier MUST reject KB-JWTs older than an acceptable window ' +
          'and consume nonces on use (single-use enforcement).',
        mitigates: ['cross-verifier-vp-replay'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §14.1.2 (Verifiable Presentations — nonce binding)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifiable-presentations',
      },
      {
        label: 'SD-JWT §4.3 (Key Binding JWT)',
        href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/',
      },
    ],
  },

  // Per-protocol override: OID4VP client_id is the *verifier identity*,
  // typically prefixed with a client_id_scheme, and is cryptographically
  // bound by the request signature — substantively different from OAuth2.
  'oid4vp:client_id': {
    purpose:
      'The verifier\'s identifier, typically prefixed by a `client_id_' +
      'scheme` (e.g. `x509_san_dns:verifier.example.com`). Unlike OAuth2 ' +
      'where `client_id` is a public lookup key, in OID4VP the client_id IS ' +
      'the cryptographic identity that the request signature binds to — ' +
      'wallets verify the request signature against keys derived from this ' +
      'identifier.',
    attacks: [
      {
        id: 'oid4vp-verifier-impersonation',
        name: 'Verifier impersonation via non-cryptographic client_id',
        scenario:
          'A client_id without a verifiable scheme (the legacy ' +
          '`redirect_uri` scheme just uses the URL) gives the wallet no ' +
          'cryptographic basis to authenticate the verifier. Same trust ' +
          'model as web SSO — and the same phishing surface. The ' +
          'verifier-impersonation attack hinges on the wallet\'s inability ' +
          'to distinguish "the verifier this request claims to be" from ' +
          '"the verifier whose key signed this request". See ' +
          '`client_id_scheme` for the full attack walk-through.',
        impact:
          'Credential phishing at scale, equivalent in effect to the ' +
          '`client_id_scheme` verifier-impersonation attack.',
      },
    ],
    mitigations: [
      {
        action:
          'Use only schemes that ground the verifier identity in a key the ' +
          'wallet can independently verify (`x509_san_dns`, ' +
          '`verifier_attestation`, `did:web`).',
        mitigates: ['oid4vp-verifier-impersonation'],
      },
      {
        action:
          'Pair with JAR (`request_uri`) so the request itself is signed. ' +
          'HAIP 1.0 (the eIDAS 2 compliance profile) mandates this ' +
          'combination.',
        mitigates: ['oid4vp-verifier-impersonation'],
      },
    ],
    references: [
      {
        label: 'OID4VP 1.0 §5.9 (client_id and Client Identifier Prefix)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-prefix-an',
      },
      {
        label: 'OID4VP 1.0 §14.1 (Verifier Impersonation — Preventing Replay)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-preventing-replay-of-verifi',
      },
    ],
  },
}
