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
      'typically as a QR code, deep link, push notification, or email ' +
      'link. The wallet fetches the URL to learn what credential is being ' +
      'offered and which grant types are supported.',
    withoutIt:
      'The offer URI travels over an unauthenticated out-of-band channel ' +
      '(QR, deep link, email) with no protocol-level binding between ' +
      '"the user who scanned this" and "the user this credential will be ' +
      'issued to". The OpenID Foundation\'s formal security analysis ' +
      'confirms cross-device flows in OID4VCI are inherently phishable ' +
      'and require user attention to be secure.',
    attack:
      'Cross-device credential offer phishing. Mallory hosts a malicious ' +
      'website ("upgrade your driver\'s license now!") with a QR code or ' +
      'deep link embedding her own `credential_offer_uri`. Alice scans, the ' +
      'wallet fetches Mallory\'s offer, and Mallory\'s issuer serves a ' +
      'real-looking but attacker-controlled credential — or, in the more ' +
      'subtle variant, Alice approves an issuance flow that hands ' +
      '*Mallory\'s* wallet a credential bound to *Alice\'s* identity, ' +
      'because the cross-device protocol has no link between the device ' +
      'that initiated the offer and the device that completes it. ' +
      'SquarePhish2 / Graphish OAuth phishing kits (active 2025) ' +
      'demonstrate the QR + cross-device attack pattern and translate ' +
      'directly to OID4VCI.',
    impact:
      'Either malicious credentials installed in legitimate wallets, or ' +
      'legitimate credentials installed in attacker-controlled wallets. ' +
      'Defences are operational: wallet should pin a list of trusted ' +
      'issuers; same-device flows (where the offer link opens directly in ' +
      'the wallet on the same device the user initiated the request from) ' +
      'are formally proven secure and should be preferred.',
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
    ],
  },

  'pre-authorized_code': {
    purpose:
      'A short-lived bearer code embedded in a credential offer that ' +
      'authorizes the wallet to obtain an access token without an ' +
      'interactive authorization-code flow. Used when the issuer has ' +
      'already authenticated the user out-of-band (e.g. a kiosk after a ' +
      'driver\'s license renewal) and just needs to hand the credential ' +
      'to whichever wallet shows up with this code.',
    withoutIt:
      'Without an additional binding factor, the `pre-authorized_code` ' +
      'is bearer-style — whoever receives the offer and presents the code ' +
      'at /token gets the credential. There is no authentication step; ' +
      'possession is sufficient.',
    attack:
      'Pre-authorized code interception. Mallory eavesdrops on Alice\'s ' +
      'credential offer transmission (shoulder-surfs the QR code, ' +
      'intercepts the email, captures the deep-link via a malicious app ' +
      'with the same scheme registration). She redeems the code at the ' +
      'issuer\'s /token endpoint before Alice\'s wallet does, and the ' +
      'issuer happily issues the credential to Mallory\'s wallet. The race ' +
      'is winnable because pre-authorized codes are typically valid for ' +
      'minutes.',
    impact:
      'Credential issued to attacker. Mitigation: pair the code with a ' +
      '`tx_code` (PIN delivered via separate channel) so possession of ' +
      'the code alone is insufficient. OID4VCI 1.0 §3.5 recommends short ' +
      'expiry (a few minutes) and binding to a specific wallet identity ' +
      'where possible. There is no PKCE-style client-binding in this ' +
      'flow — `tx_code` is the primary defence.',
    references: [
      {
        label: 'OID4VCI 1.0 §3.5 (Pre-Authorized Code Flow)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow',
      },
    ],
  },

  tx_code: {
    purpose:
      'A short user-entered code (typically 4-8 digits) the issuer ' +
      'delivers to the user out-of-band via a separate channel from the ' +
      'credential offer (SMS to a known phone, email to a known address, ' +
      'displayed on a kiosk screen). The wallet prompts the user to type ' +
      'it and forwards it to /token alongside the pre-authorized code.',
    withoutIt:
      'Pre-authorized code without `tx_code` collapses to bearer security ' +
      '— see the `pre-authorized_code` attack. `tx_code` introduces a ' +
      'second factor (something the user knows / received separately) that ' +
      'an interceptor of the offer alone cannot supply.',
    attack:
      'PIN-channel cross-protocol phishing (documented IN the OID4VCI ' +
      'specification §11.3). Mallory operates a malicious credential issuer ' +
      'and convinces Alice to scan its credential offer. In parallel, ' +
      'Mallory triggers Alice\'s real bank or payment service to send a ' +
      'transaction-confirmation PIN via SMS. The malicious wallet UX, ' +
      'showing Mallory\'s offer, prompts Alice for "the PIN you just ' +
      'received". Alice enters her bank\'s PIN, the wallet POSTs it as ' +
      '`tx_code` to Mallory\'s /token endpoint — and Mallory now has ' +
      'a valid PIN for Alice\'s payment service. The PIN was for the ' +
      'wrong protocol entirely, but the user\'s mental model conflated ' +
      'them.',
    impact:
      'Credential issuance becomes a phishing primitive for PINs from ' +
      'unrelated services. Mitigations are squarely on wallet UX: clearly ' +
      'attribute the PIN prompt to the specific issuer; refuse offers from ' +
      'untrusted issuers; never auto-fill PINs from notifications. The ' +
      'spec is explicit: this is a known design tension with no clean ' +
      'protocol-level fix.',
    references: [
      {
        label: 'OID4VCI 1.0 §3.5.1 (tx_code)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request',
      },
      {
        label: 'OID4VCI 1.0 §11.3 (PIN Phishing)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-trust-between-wallet-and-is',
      },
    ],
  },

  c_nonce: {
    purpose:
      'Challenge nonce the Credential Issuer returns from /token (and ' +
      'subsequently from /credential). The wallet MUST include this exact ' +
      'value in the `nonce` claim of the proof JWT it sends with its ' +
      'credential request. Single-use; consumed on each call.',
    withoutIt:
      'Without `c_nonce` freshness, a wallet\'s proof JWT becomes ' +
      'replayable. Anyone who captures a single proof can re-present it to ' +
      'the issuer indefinitely and receive new credentials bound to the ' +
      'wallet\'s key — turning a one-shot proof into a credential-issuing ' +
      'oracle.',
    attack:
      'Proof-JWT replay against credential endpoint. Mallory captures one ' +
      'of Alice\'s proof JWTs (network tap on a non-TLS internal hop, ' +
      'malicious browser extension, leaked log). Without c_nonce ' +
      'enforcement, Mallory replays the proof against the issuer\'s ' +
      '/credential endpoint and gets a fresh credential bound to Alice\'s ' +
      'wallet key. Even though Mallory cannot use that credential (she ' +
      'lacks Alice\'s private key for later presentation), she has now ' +
      'forced the issuer to mint duplicate credentials and may correlate ' +
      'identities or exhaust issuance budgets.',
    impact:
      'Credential-replay leading to issuance amplification and ' +
      'correlation. The issuer MUST consume `c_nonce` on use and reject ' +
      'replays. Wallet MUST treat each c_nonce as single-use and refresh ' +
      'from the next response. ' +
      'OIDC `nonce` binds an ID Token to an authentication session; ' +
      '`c_nonce` binds a proof JWT to a specific issuance request.',
    references: [
      {
        label: 'OID4VCI 1.0 §7.2.1 (c_nonce)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-request',
      },
    ],
  },

  proof: {
    purpose:
      'A wallet-signed JWT (or similar) that proves the wallet controls ' +
      'the private key the issued credential will be bound to. Sent on the ' +
      'credential request. JWT MUST contain header `typ=' +
      'openid4vci-proof+jwt`, payload claims `iss` (wallet/client ID), ' +
      '`aud` (credential issuer identifier), `iat`, `exp`, `nonce` ' +
      '(equal to current `c_nonce`), and `cnf.jwk` (the wallet\'s public ' +
      'key the credential will be bound to).',
    withoutIt:
      'No holder binding. The issued credential becomes bearer-style — ' +
      'whoever holds the credential file can present it as their own. ' +
      'This breaks the entire trust model of verifiable credentials, ' +
      'where the verifier expects the holder to demonstrate possession ' +
      'of a key tied to the credential.',
    attack:
      'Credential lift-and-replay. Without proof, Mallory who steals ' +
      'Alice\'s credential file (laptop backup, exfiltrated wallet ' +
      'database, malicious wallet extension) can present it directly to ' +
      'verifiers as her own credential. Verifiers trusting a non-key-bound ' +
      'credential have no way to detect the swap. With proof-of-possession ' +
      'binding, the credential is bound to Alice\'s wallet key (`cnf.jwk` ' +
      'in the credential), and presentation requires signing a Key Binding ' +
      'JWT with that key — Mallory has the credential but not the key.',
    impact:
      'Without holder binding: trivial credential transfer attacks. The ' +
      'OID4VCI proof and the resulting `cnf.jwk` claim in SD-JWT-VC / ' +
      'mDoc credentials are the entire reason verifiable credentials are ' +
      '"verifiable" rather than just "signed assertions". Issuer MUST ' +
      'reject credential requests without valid proofs (where ' +
      'proof_types_supported declares them required), MUST verify the ' +
      'proof JWT signature against the embedded `cnf.jwk`, and MUST ' +
      'verify `aud` matches its own credential_issuer identifier.',
    references: [
      {
        label: 'OID4VCI 1.0 §7.2.1.1 (Proof JWT)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types',
      },
      {
        label: 'RFC 7800 (Proof-of-Possession Key Semantics — cnf claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7800',
      },
    ],
  },

  credential: {
    purpose:
      'The issuer-signed verifiable credential returned to the wallet. ' +
      'Format depends on `credential_configuration_id` — typically ' +
      'SD-JWT-VC (`dc+sd-jwt`), JWT-VC JSON, JWT-VC JSON-LD, or LDP-VC. ' +
      'Each format has its own signature and integrity model.',
    withoutIt:
      'The risk is in *how the wallet validates and stores* the received ' +
      'credential. A wallet that doesn\'t verify the issuer signature, ' +
      'check the credential\'s `iss`/`vct`/`aud` against the issuer ' +
      'metadata, or store the credential in a tamper-evident container ' +
      'collapses the trust chain.',
    attack:
      '(1) Issuer signature skip — the wallet stores any credential the ' +
      'endpoint returns without verifying the signature against the ' +
      'issuer\'s advertised JWKS. A man-in-the-middle (compromised TLS, ' +
      'rogue CA in some jurisdictions) can substitute credentials. ' +
      '(2) Format-specific attacks: SD-JWT disclosure tampering (omit ' +
      'or substitute disclosure values); JSON-LD context expansion ' +
      'attacks (different graphs canonicalize identically); signature ' +
      'algorithm confusion (alg=none, RS256→HS256 — applicable to any ' +
      'signed-JWT credential format).',
    impact:
      'Forged or tampered credentials silently accepted into the ' +
      'wallet. Defences: verify issuer signature on receipt; pin ' +
      'expected issuer key and signing algorithms from issuer metadata; ' +
      'use battle-tested format libraries (do not hand-roll SD-JWT ' +
      'disclosure logic); store credentials in OS-level secure ' +
      'storage / TEE where available.',
    references: [
      {
        label: 'OID4VCI 1.0 §7.3 (Credential Response)',
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
    ],
  },

  transaction_id: {
    purpose:
      'Opaque identifier returned by the issuer when credential issuance ' +
      'cannot complete synchronously (manual review, batch processing, ' +
      'KYC backlog). The wallet polls the deferred-credential endpoint ' +
      'with this ID until the credential is ready.',
    withoutIt:
      'Two distinct risks: (1) **Bearer secret** — anyone with the ' +
      'transaction_id can poll the deferred endpoint and retrieve the ' +
      'eventual credential. There is no client authentication on most ' +
      'deferred-poll implementations beyond the transaction_id itself. ' +
      '(2) **Polling-timing leak** — the issuer\'s response timing ' +
      '("not ready", "not ready", ..., "ready") leaks operational ' +
      'information about how long manual review takes.',
    attack:
      'Deferred-credential interception. Mallory steals Alice\'s ' +
      '`transaction_id` from any leakage path (logs, leaked backups, ' +
      'malicious wallet extension). She polls the deferred endpoint ' +
      'continuously and retrieves the credential the moment the issuer ' +
      'completes its review — possibly minutes before Alice\'s own wallet ' +
      'gets it. The credential is bound to Alice\'s key (per `cnf.jwk` ' +
      'from the original proof) so Mallory can\'t directly *use* it, but ' +
      'she has now learned: (a) Alice was issued this credential, (b) any ' +
      'metadata in the credential.',
    impact:
      'Issuance-event correlation and metadata leak. Defences: short ' +
      'transaction_id lifetime; bind transaction_id to the original ' +
      'access_token (require both on poll); rate-limit polling; consider ' +
      'sender-constrained tokens (DPoP) on the deferred endpoint.',
    references: [
      {
        label: 'OID4VCI 1.0 §9 (Deferred Credential Endpoint)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-endpoin',
      },
    ],
  },

  format: {
    purpose:
      'Identifies the credential format being issued or presented. ' +
      'Common values: `dc+sd-jwt` (SD-JWT-VC, selective disclosure JWT), ' +
      '`jwt_vc_json` (JWT-encoded W3C VC), `jwt_vc_json-ld` (JWT-encoded ' +
      'JSON-LD VC), `ldp_vc` (Linked Data Proofs VC), `mso_mdoc` ' +
      '(ISO 18013-5 mobile drivers license).',
    withoutIt:
      'The risk is *format-confusion attacks*: a verifier configured to ' +
      'accept format A receives a credential labelled format A but ' +
      'actually structured as format B. The verifier\'s parser, expecting ' +
      'A\'s integrity model, may skip checks that B\'s model relies on.',
    attack:
      'Format-confusion bypass. Verifier accepts both `jwt_vc_json` and ' +
      '`ldp_vc`. Mallory crafts a credential that parses successfully ' +
      'under both formats but encodes different claims under each parser ' +
      '(JWT payload says one thing, JSON-LD canonicalisation says ' +
      'another). The verifier\'s integrity check operates on whichever ' +
      'subset of bytes the parser cared about, and Mallory\'s "bad" ' +
      'claims slip through the unverified portion. Variants exist ' +
      'specific to JSON-LD context-expansion ambiguity.',
    impact:
      'Credential content manipulation that bypasses integrity checks. ' +
      'Verifiers should accept exactly one format per credential ' +
      'configuration and reject anything ambiguous. Where multiple ' +
      'formats are supported, parse and validate strictly per the ' +
      'declared `format` value, not per "first parser that doesn\'t ' +
      'crash".',
    references: [
      {
        label: 'OID4VCI 1.0 §11.4 (Credential Format Considerations)',
        href: 'https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html',
      },
    ],
  },
}
