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
    withoutIt:
      'The risk is in *how the verifier validates the vp_token*, not in ' +
      'omitting it. Verifiers commonly skip one of: signature on the issuer ' +
      'credential, KB-JWT signature, nonce binding, audience binding, ' +
      'expiry. Each skip turns a useless captured token into a usable ' +
      'authentication.',
    attack:
      'VP Token replay / forwarding. Mallory captures a vp_token from any ' +
      'flow she observes (compromised wallet plugin, captured response on ' +
      'a non-TLS internal hop, leaked log). She replays it to a *different* ' +
      'verifier — or back to the same verifier under a fresh state value. ' +
      'Without strict `nonce` and `aud` validation on the inner Key Binding ' +
      'JWT, the new verifier sees a cryptographically valid presentation ' +
      'and authenticates Mallory as Alice. The VP itself signs over the ' +
      'verifier\'s nonce and audience precisely to prevent this — the ' +
      'attack opens up wherever those checks are weak.',
    impact:
      'Authentication bypass via captured-presentation replay. Verifier ' +
      'MUST validate, in order: (1) issuer signature on the credential ' +
      'against issuer\'s JWKS; (2) Holder Binding / KB-JWT signature ' +
      'against `cnf.jwk` in the credential; (3) `nonce` matches the value ' +
      'this verifier sent in the request; (4) `aud` matches this verifier\'s ' +
      'client_id; (5) creation time within an acceptable window; (6) ' +
      '`typ=kb+jwt` for SD-JWT KB-JWTs; (7) reject `alg=none`. Skip any ' +
      'one of these and the protocol\'s authentication guarantee evaporates.',
    references: [
      {
        label: 'OID4VP 1.0 §6 (Authorization Response)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-response',
      },
      {
        label: 'SD-JWT §5.4 (Key Binding JWT validation)',
        href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/',
      },
      {
        label: 'OID4VP 1.0 §11.1 (Verifier Impersonation Threat)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-impersonation',
      },
    ],
  },

  dcql_query: {
    purpose:
      'Digital Credentials Query Language object the verifier sends to ' +
      'specify which credentials and which claims it wants the wallet to ' +
      'present. Replaces the older Presentation Exchange `presentation_' +
      'definition` (which is removed from OID4VP draft 26+). Encodes ' +
      'credential type filters, claim path requirements, and disclosure ' +
      'preferences.',
    withoutIt:
      'Without DCQL the verifier must rely on `scope` for selection, which ' +
      'is too coarse. With DCQL but without careful query design, two ' +
      'failure modes appear: (1) verifier requests *more* claims than its ' +
      'business purpose actually requires (privacy-leak amplification); ' +
      '(2) verifier accepts presentations that match the query schema but ' +
      'satisfy it via attacker-controlled credentials.',
    attack:
      'Over-broad-query privacy harvest. A verifier that needs to confirm ' +
      'the user is over 18 issues a DCQL query for the entire driver\'s ' +
      'license credential — full name, address, license number, ' +
      'photograph. The user, trusting the wallet UI, approves. The verifier ' +
      'now has data it had no legitimate business reason to collect, in a ' +
      'cryptographically authenticated package. SD-JWT selective disclosure ' +
      'mitigates this when the query is narrowly written (request only ' +
      '`age_over_18`); blown when the query is loose.',
    impact:
      'Wallet-displayed consent screens are the user\'s only protection — ' +
      'and most users approve quickly. Verifier-side: write the narrowest ' +
      'DCQL query that satisfies the legitimate purpose. Wallet-side: show ' +
      'the user *exactly* which claims will be disclosed before signing the ' +
      'presentation. Regulator-side: GDPR / data-minimisation principles ' +
      'apply.',
    references: [
      {
        label: 'OID4VP 1.0 §6.1 (DCQL)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l',
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
    withoutIt:
      'With `redirect_uri` scheme (the legacy default), the wallet has only ' +
      'the URL to identify the verifier — same trust model as OAuth2, which ' +
      'is the gap. Without a cryptographic scheme, the wallet cannot ' +
      'distinguish a legitimate verifier from an attacker who registered a ' +
      'similar-looking domain or hijacked DNS for the request URL.',
    attack:
      'Verifier impersonation. Mallory hosts a fake verifier UI at ' +
      '`accounts.googel.com` (typo) and sends Alice\'s wallet a ' +
      'presentation request claiming to be `accounts.google.com`. With ' +
      '`client_id_scheme=redirect_uri`, the wallet has only the URL to go ' +
      'on — domain typo passes muster. With `x509_san_dns`, the request is ' +
      'signed by a certificate whose SAN MUST contain the claimed domain; ' +
      'the wallet verifies the chain to a trusted root before trusting the ' +
      'verifier identity. Without that, Alice presents her credential to ' +
      'Mallory thinking Mallory is Google.',
    impact:
      'Verifier impersonation = credential phishing at scale. Use schemes ' +
      'that ground the verifier identity in something the wallet can ' +
      'cryptographically verify (`x509_san_dns`, `verifier_attestation`, ' +
      '`did:web` with proper resolution). The OpenID4VC High Assurance ' +
      'Interoperability Profile (HAIP) 1.0 mandates signed Authorization ' +
      'Requests (JAR) with X.509 cert chains specifically to close this ' +
      'gap.',
    references: [
      {
        label: 'OID4VP 1.0 §5 (Client Identifier Scheme)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme',
      },
      {
        label: 'OID4VP 1.0 §11.1 (Verifier Impersonation)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-impersonation',
      },
      {
        label: 'OpenID4VC HAIP 1.0 (mandatory signed requests)',
        href: 'https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html',
      },
    ],
  },

  response_mode: {
    purpose:
      'Tells the wallet how to deliver the authorization response. ' +
      '`direct_post` POSTs `vp_token` + `state` as form parameters to ' +
      '`response_uri`. `direct_post.jwt` POSTs an encrypted JWE wrapping a ' +
      'signed inner JWT. Legacy `query` and `fragment` modes return the ' +
      'response in the redirect URL.',
    withoutIt:
      'The choice is the entire confidentiality/integrity story for the ' +
      'response. `query`/`fragment` exposes the vp_token to browser ' +
      'history, referer headers, and any JS on the redirect page. ' +
      '`direct_post` runs server-to-server but in plaintext over TLS. ' +
      '`direct_post.jwt` adds end-to-end encryption so even a TLS-' +
      'terminating proxy at the verifier doesn\'t see the credential ' +
      'contents.',
    attack:
      'Response leakage scaled by mode. With `fragment`, Mallory\'s ' +
      'analytics tag on the wallet-callback page reads `location.hash` and ' +
      'exfiltrates the vp_token. With `direct_post`, a TLS-terminating ' +
      'load balancer or compromised CDN at the verifier sees the full ' +
      'response — typically with full SD-JWT disclosures including PII ' +
      'fields the verifier had no business decrypting at the edge. With ' +
      '`direct_post.jwt`, the JWE only opens at the verifier\'s actual ' +
      'private key.',
    impact:
      'For high-assurance / privacy-sensitive presentations (mDL, ' +
      'health credentials, regulated identity) use `direct_post.jwt` with ' +
      'verifier-key-bound encryption. For lower-stakes attribute checks, ' +
      '`direct_post` over TLS is acceptable. Never use `fragment`/`query` ' +
      'for VP responses outside test environments.',
    references: [
      {
        label: 'OID4VP 1.0 §7 (Response Mode)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-modes',
      },
    ],
  },

  response_uri: {
    purpose:
      'The verifier endpoint to which the wallet POSTs the authorization ' +
      'response when `response_mode=direct_post` or `direct_post.jwt`. ' +
      'Replaces `redirect_uri` for direct_post modes — the wallet does not ' +
      'redirect a browser; it does a server-side POST.',
    withoutIt:
      'Same exact-match story as OAuth2 `redirect_uri`. The wallet must ' +
      'verify that `response_uri` is consistent with the verifier identity ' +
      '(`client_id_scheme` cryptographic check) — otherwise an attacker ' +
      'who controls the request can redirect responses to their own ' +
      'collection endpoint.',
    attack:
      'Response-collection hijack. Mallory crafts a presentation request ' +
      'with `client_id` claiming to be a legit verifier but `response_uri` ' +
      'pointing at her own server. If the wallet does not bind ' +
      '`response_uri` to the verifier\'s authenticated identity (via ' +
      '`client_id_scheme`), the wallet POSTs the credential to Mallory.',
    impact:
      'Credential exfiltration directly to attacker. Defence: wallet MUST ' +
      'verify `response_uri` matches an allowlist tied to the authenticated ' +
      'verifier (e.g. for `x509_san_dns` scheme, verify ' +
      '`response_uri` host appears in the certificate\'s SAN). ' +
      '`direct_post.jwt` adds defence-in-depth via verifier-key-bound JWE ' +
      'so even hijacked POSTs cannot be decrypted by the attacker.',
    references: [
      {
        label: 'OID4VP 1.0 §7.1 (response_uri)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-modes',
      },
    ],
  },

  request_uri: {
    purpose:
      'A URL the wallet fetches to obtain the full authorization request ' +
      'as a signed JWT (a JAR — JWT-Secured Authorization Request). ' +
      'Lets verifiers send long, signed, integrity-protected requests via ' +
      'a short URL that fits in a QR code.',
    withoutIt:
      'Without JAR, the entire authorization request travels in the QR\'s ' +
      'URL parameters — query-string-tampering attacks become possible if ' +
      'the request reaches the wallet via any intermediate channel that ' +
      'can modify URLs. With JAR, parameters are wrapped in a verifier-' +
      'signed JWT; tampering becomes detectable.',
    attack:
      'Request-object tampering. Without JAR, an intermediate (malicious ' +
      'app handling the URL scheme, compromised browser extension, ' +
      'rogue clipboard manager) modifies the request URL to swap ' +
      '`response_uri` to an attacker endpoint or relax the DCQL query to ' +
      'disclose more claims. The wallet has no signature to verify, so it ' +
      'trusts the modified request. With JAR fetched via `request_uri`, ' +
      'the wallet validates the verifier\'s signature on the request JWT ' +
      'before processing — modifications fail.',
    impact:
      'Use `request_uri` (JAR) for any production OID4VP deployment. ' +
      'Combine with cryptographic `client_id_scheme` so the wallet can ' +
      'verify the signature against a key it actually trusts for the ' +
      'claimed verifier identity. HAIP 1.0 mandates this combination.',
    references: [
      {
        label: 'OID4VP 1.0 §5 (Authorization Request)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request',
      },
      {
        label: 'RFC 9101 (JAR)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9101',
      },
    ],
  },

  response: {
    purpose:
      'In `response_mode=direct_post.jwt`, the encrypted JWE the wallet ' +
      'POSTs to `response_uri`. Wraps a signed inner JWT (typ=' +
      '`oauth-authz-resp+jwt`) which carries `vp_token` and `state`. The ' +
      'JWE is encrypted to a key the verifier published in its client ' +
      'metadata.',
    withoutIt:
      'Without the JWE wrapper (i.e. plain `direct_post`), the response ' +
      'is exposed to anything between the wallet and the verifier that ' +
      'terminates TLS — load balancers, WAFs, edge proxies, observability ' +
      'pipelines. Sensitive credential disclosures (PII, biometrics) sit ' +
      'in cleartext in any of those layers.',
    attack:
      'Edge-tier credential capture. Mallory works at a CDN provider that ' +
      'does TLS termination for the verifier. Without `direct_post.jwt`, ' +
      'every vp_token she sees in proxy logs includes the user\'s full ' +
      'disclosure set. With `direct_post.jwt`, the JWE is opaque to ' +
      'everything except the verifier\'s actual private key — TLS ' +
      'termination at the edge sees only ciphertext.',
    impact:
      'For privacy-sensitive credentials (especially under GDPR / eIDAS 2 ' +
      'high-assurance regimes), plain `direct_post` may not satisfy ' +
      '"data minimisation" or "encryption in transit" requirements. ' +
      '`direct_post.jwt` is the conformant choice for regulated VP flows. ' +
      'Validate the inner JWT thoroughly: `typ=oauth-authz-resp+jwt`, ' +
      '`aud=response_uri`, state consistency, signature.',
    references: [
      {
        label: 'OID4VP 1.0 §7.2 (direct_post.jwt)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-modes',
      },
      {
        label: 'RFC 7516 (JWE)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7516',
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
      'KB-JWT (Key Binding JWT) inside the vp_token. Ties the *cryptographic ' +
      'proof* of holder possession to *this specific verifier transaction*.',
    withoutIt:
      'Without nonce binding, a vp_token is reusable. Captured once, it ' +
      'authenticates the wallet to any verifier that accepts the same ' +
      'credential — the entire selling point of "fresh" cryptographic ' +
      'proof of possession evaporates.',
    attack:
      'Cross-verifier vp_token replay. Verifier A is honest. Verifier B is ' +
      'Mallory. Alice presents to A; Mallory is on the network path or ' +
      'operates a proxy and captures the vp_token. Without nonce checking, ' +
      'Mallory replays the captured token to her own infrastructure ' +
      '(claiming to be a third verifier C) or to verifier A under a fresh ' +
      'session — and the credential authenticates her. The verifier-issued ' +
      'nonce inside the KB-JWT is the only thing that ties the proof to ' +
      '*this* request.',
    impact:
      'Authentication bypass via captured-presentation replay across ' +
      'verifiers. Wallet MUST sign over verifier nonce in the KB-JWT. ' +
      'Verifier MUST: (1) generate fresh nonce per request, (2) verify ' +
      'nonce in KB-JWT matches request nonce, (3) reject KB-JWTs older ' +
      'than acceptable window, (4) consume nonce on use. ' +
      'OIDC `nonce` binds an ID Token to an authentication session; ' +
      'OID4VP `nonce` binds a presentation to a verification transaction.',
    references: [
      {
        label: 'OID4VP 1.0 §11.2 (Nonce Binding)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-replay-of-vp-tokens',
      },
      {
        label: 'SD-JWT §4.3 (Key Binding JWT)',
        href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/',
      },
    ],
  },

  // Per-protocol override: OID4VP client_id is the *verifier identity*,
  // typically prefixed with a client_id_scheme, and is cryptographically
  // bound by the request signature — a substantively different concept
  // from OAuth2's "public application identifier" client_id.
  'oid4vp:client_id': {
    purpose:
      'The verifier\'s identifier, typically prefixed by a `client_id_' +
      'scheme` (e.g. `x509_san_dns:verifier.example.com`). Unlike ' +
      'OAuth2 where `client_id` is a public lookup key, in OID4VP the ' +
      'client_id IS the cryptographic identity that the request ' +
      'signature binds to — wallets verify the request signature ' +
      'against keys derived from this identifier.',
    withoutIt:
      'A client_id without a verifiable scheme (the legacy `redirect_uri` ' +
      'scheme just uses the URL) gives the wallet no cryptographic basis ' +
      'to authenticate the verifier. Same trust model as web SSO — and ' +
      'the same phishing surface.',
    attack:
      'See `client_id_scheme` for the full attack walk-through. Short ' +
      'form: a verifier-impersonation attack hinges on the wallet\'s ' +
      'inability to distinguish "the verifier this request claims to be" ' +
      'from "the verifier whose key signed this request". Cryptographic ' +
      'schemes (`x509_san_dns`, `verifier_attestation`, `did:web`) close ' +
      'the gap; the legacy `redirect_uri` scheme leaves it open.',
    impact:
      'Use only schemes that ground the verifier identity in a key the ' +
      'wallet can independently verify. Pair with JAR (`request_uri`) so ' +
      'the request itself is signed. HAIP 1.0 (the eIDAS 2 compliance ' +
      'profile) mandates this combination.',
    references: [
      {
        label: 'OID4VP 1.0 §5 (client_id and client_id_scheme)',
        href: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-client-identifier-scheme',
      },
    ],
  },
}
