/**
 * OpenID for Verifiable Credential Issuance (OID4VCI) — Parameter Explainers
 *
 * Issuance-specific entries: credential offer phishing, pre-authorized
 * code interception, c_nonce freshness, holder binding via proof JWT,
 * deferred issuance, format confusion.
 */

import type { ParameterExplainer } from './index'

export const OID4VCI_EXPLAINERS: Record<string, ParameterExplainer> = {
  credential_offer_uri: {
    purpose:
      'A reference URL the Credential Issuer publishes containing the ' +
      'credential offer payload. Delivered to the wallet out-of-band — ' +
      'typically as a QR code, deep link, push notification, or email link. ' +
      'The wallet fetches the URL to learn what credential is being offered ' +
      'and which grant types are supported.',
    attacks: [
      {
        id: 'cross-device-offer-phishing',
        name: 'Cross-device credential offer phishing',
        scenario:
          'The offer URI travels over an unauthenticated out-of-band channel ' +
          '(QR, deep link, email) with no protocol-level binding between ' +
          '"the user who scanned this" and "the user this credential will be ' +
          'issued to". Mallory hosts a malicious website ("upgrade your ' +
          'driver\'s license now!") with a QR code or deep link embedding ' +
          'her own `credential_offer_uri`. Alice scans, the wallet fetches ' +
          'Mallory\'s offer, and Mallory\'s issuer serves a real-looking ' +
          'but attacker-controlled credential — or, in the more subtle ' +
          'variant, Alice approves an issuance flow that hands *Mallory\'s* ' +
          'wallet a credential bound to *Alice\'s* identity, because the ' +
          'cross-device protocol has no link between the device that ' +
          'initiated the offer and the device that completes it. ' +
          'SquarePhish2 / Graphish OAuth phishing kits (active 2025) ' +
          'demonstrate the QR + cross-device attack pattern and translate ' +
          'directly to OID4VCI. The OpenID Foundation\'s formal security ' +
          'analysis confirms cross-device flows are inherently phishable.',
        impact:
          'Either malicious credentials installed in legitimate wallets, or ' +
          'legitimate credentials installed in attacker-controlled wallets.',
      },
    ],
    mitigations: [
      {
        action:
          'Wallet pins a list of trusted issuers; refuses to process offers ' +
          'from unknown origins.',
        mitigates: ['cross-device-offer-phishing'],
      },
      {
        action:
          'Prefer same-device flows where the offer link opens directly in ' +
          'the wallet on the same device the user initiated the request ' +
          'from. Same-device flows are formally proven secure.',
        mitigates: ['cross-device-offer-phishing'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §4.1 (Credential Offer)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer',
      },
      {
        label: 'OpenID Foundation — Formal Security Analysis of OpenID for VCs',
        href: 'https://openid.net/formal-security-analysis-openid-verifiable-credentials/',
      },
      {
        label: 'ETH Zurich — Formal Analysis of OID4VCI (Zischg)',
        href: 'https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/information-security-group-dam/research/software/zischg-oid4vci.pdf',
      },
      {
        label: 'OID4VCI 1.0 §13 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-security-considerations',
      },
    ],
  },

  'pre-authorized_code': {
    purpose:
      'A short-lived bearer code embedded in a credential offer that ' +
      'authorizes the wallet to obtain an access token without an ' +
      'interactive authorization-code flow. Used when the issuer has already ' +
      'authenticated the user out-of-band (e.g. a kiosk after a driver\'s ' +
      'license renewal) and just needs to hand the credential to whichever ' +
      'wallet shows up with this code.',
    attacks: [
      {
        id: 'pre-authorized-code-interception',
        name: 'Pre-authorized code interception',
        scenario:
          'Without an additional binding factor, the code is bearer-style — ' +
          'whoever receives the offer and presents the code at /token gets ' +
          'the credential. Mallory eavesdrops on Alice\'s credential offer ' +
          'transmission (shoulder-surfs the QR code, intercepts the email, ' +
          'captures the deep-link via a malicious app with the same scheme ' +
          'registration). She redeems the code at the issuer\'s /token ' +
          'endpoint before Alice\'s wallet does. The race is winnable ' +
          'because pre-authorized codes are typically valid for minutes.',
        impact:
          'Credential issued to attacker.',
      },
    ],
    mitigations: [
      {
        action:
          'Pair the code with a `tx_code` (PIN delivered via separate ' +
          'channel) so possession of the code alone is insufficient.',
        rationale:
          'There is no PKCE-style client-binding in this flow — `tx_code` ' +
          'is the primary defence.',
        mitigates: ['pre-authorized-code-interception'],
      },
      {
        action:
          'Short expiry (a few minutes) per OID4VCI 1.0 §3.5; bind to a ' +
          'specific wallet identity where possible.',
        mitigates: ['pre-authorized-code-interception'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §3.5 (Pre-Authorized Code Flow)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow',
      },
      {
        label: 'OID4VCI 1.0 §13.6 (Pre-Authorized Code Flow Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow-2',
      },
    ],
  },

  tx_code: {
    purpose:
      'A short user-entered code (typically 4-8 digits) the issuer delivers ' +
      'to the user out-of-band via a separate channel from the credential ' +
      'offer (SMS to a known phone, email to a known address, displayed on ' +
      'a kiosk screen). The wallet prompts the user to type it and forwards ' +
      'it to /token alongside the pre-authorized code. Adds a second factor ' +
      '(something the user knows / received separately) that an interceptor ' +
      'of the offer alone cannot supply.',
    attacks: [
      {
        id: 'pin-channel-cross-protocol-phishing',
        name: 'PIN-channel cross-protocol phishing',
        scenario:
          'Documented IN the OID4VCI specification §11.3. Mallory operates ' +
          'a malicious credential issuer and convinces Alice to scan its ' +
          'credential offer. In parallel, Mallory triggers Alice\'s real ' +
          'bank or payment service to send a transaction-confirmation PIN ' +
          'via SMS. The malicious wallet UX, showing Mallory\'s offer, ' +
          'prompts Alice for "the PIN you just received". Alice enters her ' +
          'bank\'s PIN, the wallet POSTs it as `tx_code` to Mallory\'s ' +
          '/token endpoint — and Mallory now has a valid PIN for Alice\'s ' +
          'payment service. The PIN was for the wrong protocol entirely, ' +
          'but the user\'s mental model conflated them.',
        impact:
          'Credential issuance becomes a phishing primitive for PINs from ' +
          'unrelated services. The spec acknowledges this is a known design ' +
          'tension with no clean protocol-level fix.',
      },
    ],
    mitigations: [
      {
        action:
          'Wallet UX clearly attributes the PIN prompt to the specific ' +
          'issuer (display issuer name, logo, domain).',
        mitigates: ['pin-channel-cross-protocol-phishing'],
      },
      {
        action: 'Wallet refuses offers from untrusted issuers.',
        mitigates: ['pin-channel-cross-protocol-phishing'],
      },
      {
        action:
          'Wallet never auto-fills PINs from notifications — requires ' +
          'manual user entry to break the muscle-memory shortcut.',
        mitigates: ['pin-channel-cross-protocol-phishing'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §6.1 (Token Request — tx_code)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request',
      },
      {
        label: 'OID4VCI 1.0 §13.6.2 (Transaction Code Phishing)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-transaction-code-phishing',
      },
    ],
  },

  c_nonce: {
    purpose:
      'Challenge nonce the Credential Issuer returns from /token (and ' +
      'subsequently from /credential). The wallet MUST include this exact ' +
      'value in the `nonce` claim of the proof JWT it sends with its ' +
      'credential request. Single-use; consumed on each call. ' +
      'OIDC `nonce` binds an ID Token to an authentication session; ' +
      '`c_nonce` binds a proof JWT to a specific issuance request.',
    attacks: [
      {
        id: 'proof-jwt-replay',
        name: 'Proof-JWT replay against credential endpoint',
        scenario:
          'Without `c_nonce` freshness, a wallet\'s proof JWT is ' +
          'replayable. Mallory captures one of Alice\'s proof JWTs ' +
          '(network tap on a non-TLS internal hop, malicious browser ' +
          'extension, leaked log). Without c_nonce enforcement, she ' +
          'replays the proof against the issuer\'s /credential endpoint ' +
          'and gets a fresh credential bound to Alice\'s wallet key. Even ' +
          'though Mallory cannot use that credential (she lacks Alice\'s ' +
          'private key for later presentation), she has now forced the ' +
          'issuer to mint duplicate credentials and may correlate ' +
          'identities or exhaust issuance budgets.',
        impact:
          'Credential-replay leading to issuance amplification and ' +
          'identity correlation.',
      },
    ],
    mitigations: [
      {
        action:
          'Issuer MUST consume `c_nonce` on use and reject replays. ' +
          'Track consumed nonces for the validity window.',
        mitigates: ['proof-jwt-replay'],
      },
      {
        action:
          'Wallet MUST treat each c_nonce as single-use and refresh it ' +
          'from the next response before issuing a new proof.',
        mitigates: ['proof-jwt-replay'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §7.2 (Nonce Response — c_nonce)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response',
      },
      {
        label: 'OID4VCI 1.0 §13.6.1 (Replay Prevention)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-replay-prevention',
      },
    ],
  },

  proof: {
    purpose:
      'A wallet-signed JWT (or similar) that proves the wallet controls the ' +
      'private key the issued credential will be bound to. Sent on the ' +
      'credential request. JWT MUST contain header `typ=' +
      'openid4vci-proof+jwt`, payload claims `iss` (wallet/client ID), ' +
      '`aud` (credential issuer identifier), `iat`, `exp`, `nonce` (equal ' +
      'to current `c_nonce`), and `cnf.jwk` (the wallet\'s public key the ' +
      'credential will be bound to).',
    attacks: [
      {
        id: 'credential-lift-and-replay',
        name: 'Credential lift-and-replay (no holder binding)',
        scenario:
          'Without proof, the issued credential is bearer-style — whoever ' +
          'holds the credential file can present it as their own. Mallory ' +
          'steals Alice\'s credential file (laptop backup, exfiltrated ' +
          'wallet database, malicious wallet extension) and presents it ' +
          'directly to verifiers as her own credential. Verifiers trusting ' +
          'a non-key-bound credential have no way to detect the swap. With ' +
          'proof-of-possession binding, the credential is bound to Alice\'s ' +
          'wallet key (`cnf.jwk` in the credential), and presentation ' +
          'requires signing a Key Binding JWT with that key — Mallory has ' +
          'the credential but not the key.',
        impact:
          'Trivial credential transfer attacks. Holder binding is the ' +
          'entire reason verifiable credentials are "verifiable" rather ' +
          'than just "signed assertions".',
      },
    ],
    mitigations: [
      {
        action:
          'Issuer MUST reject credential requests without valid proofs ' +
          '(where `proof_types_supported` declares them required).',
        mitigates: ['credential-lift-and-replay'],
      },
      {
        action:
          'Issuer MUST verify the proof JWT signature against the embedded ' +
          '`cnf.jwk` and bind that key into the issued credential.',
        mitigates: ['credential-lift-and-replay'],
      },
      {
        action:
          'Issuer MUST verify `aud` matches its own credential_issuer ' +
          'identifier and `nonce` matches the active `c_nonce`.',
        mitigates: ['credential-lift-and-replay'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 Appendix F.1 (jwt Proof Type)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-jwt-proof-type',
      },
      {
        label: 'RFC 7800 (Proof-of-Possession Key Semantics — cnf claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7800',
      },
      {
        label: 'OID4VCI 1.0 §13.8 (Proof Replay)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-replay',
      },
    ],
  },

  credential: {
    purpose:
      'The issuer-signed verifiable credential returned to the wallet. ' +
      'Format depends on `credential_configuration_id` — typically SD-JWT-VC ' +
      '(`dc+sd-jwt`), JWT-VC JSON, JWT-VC JSON-LD, or LDP-VC. Each format ' +
      'has its own signature and integrity model.',
    attacks: [
      {
        id: 'issuer-signature-skip',
        name: 'Issuer signature skip',
        scenario:
          'The wallet stores any credential the endpoint returns without ' +
          'verifying the signature against the issuer\'s advertised JWKS. ' +
          'A man-in-the-middle (compromised TLS, rogue CA in some ' +
          'jurisdictions, leaked private key) substitutes the credential ' +
          'and the wallet accepts it.',
        impact:
          'Forged credentials silently accepted into the wallet, then ' +
          'presentable at every verifier that trusts the issuer.',
      },
      {
        id: 'sd-jwt-disclosure-tampering',
        name: 'SD-JWT disclosure tampering',
        scenario:
          'For SD-JWT-VC credentials, the wallet stores the issued credential ' +
          'plus a set of disclosure objects. A wallet that doesn\'t verify ' +
          'each disclosure\'s hash matches the value committed in the ' +
          'signed JWT can be tricked into presenting an attacker-modified ' +
          'disclosure (omitted field, substituted value) that the verifier ' +
          'then accepts.',
        impact:
          'Selective-disclosure forgery — claims the issuer never made ' +
          'appear in presentations.',
      },
      {
        id: 'json-ld-context-confusion',
        name: 'JSON-LD context expansion ambiguity',
        scenario:
          'For LDP-VC credentials, two distinct JSON-LD documents can ' +
          'canonicalise to the same RDF graph. An attacker crafts a ' +
          'credential whose JSON-LD differs from the issuer\'s intent but ' +
          'canonicalises identically — the signature verifies but the ' +
          'consumed claims differ.',
        impact:
          'Credential content manipulation that bypasses signature ' +
          'verification at the canonicalisation step.',
      },
      {
        id: 'credential-alg-confusion',
        name: 'Signature algorithm confusion (alg=none, RS256→HS256)',
        scenario:
          'The same JWT-attack family that affects ID Tokens applies to ' +
          'any signed-JWT credential format. Wallet libraries that pick ' +
          'verification alg from the credential header instead of issuer ' +
          'metadata are exploitable.',
        impact:
          'Forged credentials accepted with no real cryptographic check.',
      },
    ],
    mitigations: [
      {
        action:
          'Verify the issuer signature on receipt against the issuer\'s ' +
          'advertised JWKS — never trust the credential blindly because ' +
          'the endpoint returned it.',
        mitigates: [
          'issuer-signature-skip',
          'credential-alg-confusion',
        ],
      },
      {
        action:
          'Pin expected issuer key and signing algorithms from issuer ' +
          'metadata; reject tokens whose header alg is not on the pinned ' +
          'list.',
        mitigates: ['credential-alg-confusion'],
      },
      {
        action:
          'Use battle-tested format libraries — do not hand-roll SD-JWT ' +
          'disclosure logic, JSON-LD canonicalisation, or JWT verification.',
        mitigates: [
          'sd-jwt-disclosure-tampering',
          'json-ld-context-confusion',
          'credential-alg-confusion',
        ],
      },
      {
        action:
          'Store credentials in OS-level secure storage / TEE where ' +
          'available — protects against post-issuance tampering.',
        mitigates: ['sd-jwt-disclosure-tampering'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §8.3 (Credential Response)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-response',
      },
      {
        label: 'SD-JWT-VC Draft (IETF)',
        href: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/',
      },
      {
        label: 'W3C Verifiable Credentials Data Model 2.0',
        href: 'https://www.w3.org/TR/vc-data-model-2.0/',
      },
      {
        label: 'OID4VCI 1.0 §13 (Security Considerations — credential format profiles)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-security-considerations',
      },
    ],
  },

  transaction_id: {
    purpose:
      'Opaque identifier returned by the issuer when credential issuance ' +
      'cannot complete synchronously (manual review, batch processing, KYC ' +
      'backlog). The wallet polls the deferred-credential endpoint with ' +
      'this ID until the credential is ready.',
    attacks: [
      {
        id: 'deferred-credential-interception',
        name: 'Deferred-credential interception',
        scenario:
          'Mallory steals Alice\'s `transaction_id` from any leakage path ' +
          '(logs, leaked backups, malicious wallet extension). She polls ' +
          'the deferred endpoint continuously and retrieves the credential ' +
          'the moment the issuer completes its review — possibly minutes ' +
          'before Alice\'s own wallet gets it. The credential is bound to ' +
          'Alice\'s key (per `cnf.jwk` from the original proof) so Mallory ' +
          'can\'t directly *use* it, but she has now learned: (a) Alice ' +
          'was issued this credential, (b) any metadata in the credential. ' +
          'Most deferred-poll implementations have no client authentication ' +
          'beyond the transaction_id itself.',
        impact:
          'Issuance-event correlation and metadata leak.',
      },
      {
        id: 'polling-timing-leak',
        name: 'Polling-timing operational leak',
        scenario:
          'The issuer\'s response timing ("not ready", "not ready", ..., ' +
          '"ready") leaks operational information about how long manual ' +
          'review takes — useful for an attacker timing follow-up ' +
          'phishing or social engineering against the user.',
        impact:
          'Operational-pattern disclosure that aids targeted attacks.',
      },
    ],
    mitigations: [
      {
        action:
          'Short transaction_id lifetime — bound by the longest plausible ' +
          'review window.',
        mitigates: ['deferred-credential-interception'],
      },
      {
        action:
          'Bind transaction_id to the original access_token (require both ' +
          'on poll); reject polls without matching access token.',
        mitigates: ['deferred-credential-interception'],
      },
      {
        action:
          'Rate-limit polling per transaction_id; backoff on excess polls.',
        mitigates: [
          'deferred-credential-interception',
          'polling-timing-leak',
        ],
      },
      {
        action:
          'Consider sender-constrained tokens (DPoP) on the deferred ' +
          'endpoint so the polling client must hold a key, not just the ID.',
        mitigates: ['deferred-credential-interception'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §9 (Deferred Credential Endpoint)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin',
      },
      {
        label: 'OID4VCI 1.0 §13 (Security Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-security-considerations',
      },
    ],
  },

  format: {
    purpose:
      'Identifies the credential format being issued or presented. Common ' +
      'values: `dc+sd-jwt` (SD-JWT-VC, selective disclosure JWT), ' +
      '`jwt_vc_json` (JWT-encoded W3C VC), `jwt_vc_json-ld` (JWT-encoded ' +
      'JSON-LD VC), `ldp_vc` (Linked Data Proofs VC), `mso_mdoc` ' +
      '(ISO 18013-5 mobile drivers license).',
    attacks: [
      {
        id: 'format-confusion-bypass',
        name: 'Format-confusion bypass',
        scenario:
          'A verifier configured to accept format A receives a credential ' +
          'labelled format A but actually structured as format B. The ' +
          'verifier accepts both `jwt_vc_json` and `ldp_vc`. Mallory crafts ' +
          'a credential that parses successfully under both formats but ' +
          'encodes different claims under each parser (JWT payload says ' +
          'one thing, JSON-LD canonicalisation says another). The ' +
          'verifier\'s integrity check operates on whichever subset of ' +
          'bytes the parser cared about, and Mallory\'s "bad" claims slip ' +
          'through the unverified portion. Variants exist specific to ' +
          'JSON-LD context-expansion ambiguity.',
        impact:
          'Credential content manipulation that bypasses integrity checks.',
      },
    ],
    mitigations: [
      {
        action:
          'Verifiers accept exactly one format per credential configuration ' +
          'and reject anything ambiguous.',
        mitigates: ['format-confusion-bypass'],
      },
      {
        action:
          'Where multiple formats are supported, parse and validate ' +
          'strictly per the declared `format` value — not "first parser ' +
          'that doesn\'t crash".',
        mitigates: ['format-confusion-bypass'],
      },
    ],
    references: [
      {
        label: 'OID4VCI 1.0 §11.4 (Credential Format Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html',
      },
    ],
  },
}
