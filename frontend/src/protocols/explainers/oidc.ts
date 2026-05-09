/**
 * OpenID Connect — Parameter Explainers
 *
 * OIDC-specific entries plus per-protocol overrides for OAuth2 entries
 * whose semantics differ in OIDC (e.g. `oidc:aud` for ID Token audience).
 */

import type { ParameterExplainer } from './index'

export const OIDC_EXPLAINERS: Record<string, ParameterExplainer> = {
  nonce: {
    purpose:
      'A high-entropy random value the client generates per authentication ' +
      'request, persisted in the user\'s session, and required to appear ' +
      'unchanged in the `nonce` claim of the ID Token. Binds the issued ID ' +
      'Token to this specific authentication request — OIDC\'s `nonce` ' +
      'is to the *token* what OAuth\'s `state` is to the *redirect ' +
      'callback*; both are needed.',
    attacks: [
      {
        id: 'id-token-replay',
        name: 'ID Token Replay',
        scenario:
          'Mallory captures a legitimate ID Token bearing Alice\'s identity ' +
          'from any leakage path — browser history of an implicit-flow ' +
          'redirect, a referer header, a server log, an old session ' +
          'backup. Some time later (still within the token\'s exp window, ' +
          'or against a client with lax exp checks) Mallory injects the ' +
          'captured ID Token into a fresh authentication response landing ' +
          'at the client. Without nonce binding, the signature still ' +
          'verifies, the `iss` and `aud` still match, and the client ' +
          'accepts the token as the result of "the authentication that ' +
          'just happened" — signing Mallory in as Alice.',
        impact:
          'Account takeover via stale-token replay. Real-world ' +
          'implementation flaw — academic study of OIDC deployments found ' +
          'nonce checking is one of the most commonly broken validation ' +
          'steps because it requires session-state plumbing the developer ' +
          'has to wire up explicitly.',
      },
    ],
    mitigations: [
      {
        action:
          'Generate a fresh per-request nonce, persist it in the user ' +
          'session, and compare the ID Token\'s nonce claim against the ' +
          'session-stored value before trusting any other claim.',
        mitigates: ['id-token-replay'],
      },
      {
        action:
          'Reject tokens whose `nonce` is missing, mismatched, or already ' +
          'consumed. Clear the session nonce after use.',
        mitigates: ['id-token-replay'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §15.5.2 (Nonce Implementation Notes)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes',
      },
      {
        label: 'OpenID Connect Core 1.0 §3.1.3.7 (ID Token Validation)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
      },
      {
        label: 'OpenID Connect Core §16.9 (Token Reuse)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenReuse',
      },
      {
        label: 'OpenID Connect Core §16.11 (Token Substitution)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenSubstitution',
      },
    ],
  },

  id_token: {
    purpose:
      'A signed JWT carrying authentication assertions about the end user — ' +
      'the *identity* output of OIDC. Claims include `iss`, `sub`, `aud`, ' +
      '`exp`, `iat`, `nonce`, optionally `auth_time`, `acr`, `amr`, `azp`, ' +
      '`at_hash`, `c_hash`. Its signature is verified against the OP\'s JWKS.',
    attacks: [
      {
        id: 'alg-none',
        name: 'alg=none signature stripping',
        scenario:
          'Attacker sets the JWT header to `{"alg":"none"}`, strips the ' +
          'signature, and the library accepts the unsigned token (CVE-2026-' +
          '31946 OpenOlat OIDC, multiple historical CVEs).',
        impact:
          'Authentication bypass: anyone can craft a JWT and have it ' +
          'accepted without cryptographic protection.',
      },
      {
        id: 'alg-confusion-rs256-hs256',
        name: 'Algorithm confusion (RS256 → HS256)',
        scenario:
          'Server is configured to verify with an RSA public key but the ' +
          'library, on receiving a token with `alg:HS256`, treats the ' +
          'public key as an HMAC secret. An attacker who has the public ' +
          'key (it\'s public!) forges arbitrary tokens.',
        impact:
          'Authentication bypass via library-level type confusion between ' +
          'asymmetric and symmetric verification paths.',
      },
      {
        id: 'alg-default-fallback',
        name: 'Default-fallback verification (fail-open)',
        scenario:
          'CVE-2026-28802 in Authlib defaulted to HMAC verification when ' +
          '`alg` was missing or unknown — fail-open. An attacker omits or ' +
          'mangles `alg` and the library quietly accepts.',
        impact:
          'Authentication bypass via fail-open verification when the alg ' +
          'is not on the expected path.',
      },
      {
        id: 'skipped-claim-validation',
        name: 'Skipped claim validation',
        scenario:
          'Signature passes but `iss`, `aud`, `exp`, `nonce` are not ' +
          'checked. A valid signature on the wrong token (different RP, ' +
          'expired, replayed) becomes a successful login.',
        impact:
          'Authentication bypass via token-context confusion despite ' +
          'cryptographically valid signatures.',
      },
    ],
    mitigations: [
      {
        action:
          'Pin allowed `alg` values on the verifying side from the OP\'s ' +
          'discovery metadata; do not honour the JWT header\'s alg field ' +
          'for algorithm selection.',
        mitigates: [
          'alg-none',
          'alg-confusion-rs256-hs256',
          'alg-default-fallback',
        ],
      },
      {
        action:
          'Fail closed on unknown or missing `alg` — never default to a ' +
          'permissive verification path.',
        mitigates: ['alg-default-fallback'],
      },
      {
        action:
          'Validate the full claim set on every token: `iss` matches the ' +
          'expected issuer, `aud` contains this client, `exp` is in the ' +
          'future, `iat` is not absurdly old, `nonce` matches the session.',
        mitigates: ['skipped-claim-validation'],
      },
      {
        action:
          'Use a single battle-tested, currently-patched library for token ' +
          'verification — never hand-rolled.',
        rationale:
          'The above CVEs are all in widely-deployed libraries; rolling ' +
          'your own multiplies the surface.',
        mitigates: [
          'alg-none',
          'alg-confusion-rs256-hs256',
          'alg-default-fallback',
          'skipped-claim-validation',
        ],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.1.3.7 (ID Token Validation)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
      },
      {
        label: 'CVE-2026-31946 (OpenOlat OIDC signature skip)',
        href: 'https://www.thehackerwire.com/critical-jwt-signature-bypass-in-openolat-openid-connect/',
      },
      {
        label: 'CVE-2026-28802 (Authlib alg default fail-open)',
        href: 'https://www.armosec.io/blog/authlib-cve-2026-28802-jwt-signature-verification-bypass/',
      },
      {
        label: 'JWT alg confusion (RS256 to HS256)',
        href: 'https://portswigger.net/web-security/jwt/algorithm-confusion',
      },
      {
        label: 'OpenID Connect Core §16.3 (Token Manufacture / Modification)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenManufacture',
      },
      {
        label: 'OpenID Connect Core §16.13 (Other Crypto-Related Attacks)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#OtherCryptoAttacks',
      },
    ],
  },

  at_hash: {
    purpose:
      'Access Token Hash claim in the ID Token. Equals BASE64URL(left-half(' +
      'hash(access_token))) using the hash matching the ID Token\'s `alg`. ' +
      'Cryptographically binds the ID Token to the access token delivered ' +
      'alongside it in the same response.',
    attacks: [
      {
        id: 'access-token-substitution',
        name: 'Access token substitution in front-channel responses',
        scenario:
          'In flows where both an ID Token and an access token come back ' +
          'through the front-channel (implicit, hybrid), Mallory runs a ' +
          'malicious browser extension or a script on a redirect-page ' +
          'subresource. When Alice\'s response lands in ' +
          '`window.location.hash`, Mallory swaps `access_token=…` for one ' +
          'tied to her own IdP identity while leaving the ID Token (signed) ' +
          'intact. The client validates the ID Token (signature OK) and ' +
          'uses the swapped access token for subsequent UserInfo / API ' +
          'calls — which return data for *Mallory*, not Alice. Without ' +
          '`at_hash` validation, the swap is undetectable.',
        impact:
          'Privilege confusion: client logs Alice in (per ID Token) but its ' +
          'API calls run as Mallory.',
      },
    ],
    mitigations: [
      {
        action:
          'Compute the hash over the received access_token using the ID ' +
          'Token\'s `alg`, take the left-half, base64url-encode, and ' +
          'compare to the `at_hash` claim. Reject mismatches.',
        mitigates: ['access-token-substitution'],
      },
      {
        action:
          'Verify libraries fail *closed* on unknown alg — Authlib ' +
          'CVE-2026-28498 silently returned `True` when the ID Token\'s alg ' +
          'was unknown, defeating at_hash validation.',
        mitigates: ['access-token-substitution'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.2.2.9 (Implicit Flow — Access Token Validation, at_hash check)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation',
      },
      {
        label: 'CVE-2026-28498 (Authlib at_hash/c_hash fail-open)',
        href: 'https://advisories.gitlab.com/pkg/pypi/authlib/CVE-2026-28498/',
      },
      {
        label: 'OpenID Connect Core §16.11 (Token Substitution)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenSubstitution',
      },
      {
        label: 'OpenID Connect Core §16.16 (Implicit Flow Threats)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowThreats',
      },
    ],
  },

  c_hash: {
    purpose:
      'Code Hash claim in the ID Token, used in the Hybrid Flow. Equals ' +
      'BASE64URL(left-half(hash(code))). Binds the ID Token (delivered ' +
      'immediately on the front-channel) to the authorization code that ' +
      'will later be exchanged on the back-channel.',
    attacks: [
      {
        id: 'code-substitution-hybrid',
        name: 'Code substitution in hybrid flow',
        scenario:
          'Hybrid flow returns a `code` and an `id_token` together in the ' +
          'same redirect. Mallory captures her own valid authorization ' +
          'code from the OP, then runs a malicious extension or ' +
          'subresource on the client\'s redirect page. When Alice\'s ' +
          'response arrives, Mallory rewrites `code=…` to her own captured ' +
          'code while leaving the (signed) ID Token unchanged. The client ' +
          'validates the ID Token, reads the rewritten code, exchanges it ' +
          'for tokens at /token — and gets tokens for Mallory\'s identity, ' +
          'which it then links into Alice\'s session. The OIDC ' +
          'manifestation of the OAuth Authorization Code Injection attack ' +
          'class.',
        impact:
          'Account-linking takeover via swapped code.',
      },
    ],
    mitigations: [
      {
        action:
          'Compute hash(code) using the hash function tied to the ID ' +
          'Token\'s `alg` (RS256/ES256/HS256 → SHA-256, RS384/ES384 → ' +
          'SHA-384, RS512/ES512 → SHA-512), take the left-half, base64url-' +
          'encode, and compare to the `c_hash` claim. Reject mismatches ' +
          'before exchanging the code at /token.',
        mitigates: ['code-substitution-hybrid'],
      },
      {
        action:
          'Use PKCE — the token exchange will fail for any captured code ' +
          'whose verifier does not match the original challenge.',
        rationale:
          'Where PKCE is unavailable, c_hash is the primary defence; with ' +
          'PKCE both layers apply.',
        mitigates: ['code-substitution-hybrid'],
      },
      {
        action:
          'Verify libraries fail *closed* on unknown alg — Authlib ' +
          'CVE-2026-28498 affects c_hash validation specifically.',
        mitigates: ['code-substitution-hybrid'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.3.2.11 (c_hash)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken',
      },
      {
        label: 'CVE-2026-28498 (Authlib at_hash/c_hash fail-open)',
        href: 'https://advisories.gitlab.com/pkg/pypi/authlib/CVE-2026-28498/',
      },
      {
        label: 'OpenID Connect Core §16.10 (Eavesdropping or Leaking Authorization Codes)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#AuthCodeCapture',
      },
    ],
  },

  azp: {
    purpose:
      'Authorized Party claim in the ID Token. OIDC Core §2 defines `azp` ' +
      'as OPTIONAL — it appears in practice only when extensions beyond ' +
      'base OIDC are in use, and the spec advises implementations not ' +
      'using such extensions to "not use azp and to ignore it when it does ' +
      'occur". §3.1.3.7 step 4 says that if `azp` is present, the client ' +
      'SHOULD verify it equals the receiver\'s client_id. Lets a recipient ' +
      'distinguish "I am in the audience" from "I am the audience the ' +
      'token was minted for" — but only when the deployment populates it.',
    attacks: [
      {
        id: 'cross-client-id-token-reuse',
        name: 'Cross-client ID Token reuse',
        scenario:
          'Service A and Service B both list themselves in the AS audience ' +
          'configuration (one ID Token issued to a primary app and several ' +
          'backend microservices). Mallory operates Service A and persuades ' +
          'Alice to sign in. Mallory takes the resulting ID Token and ' +
          'replays it to Service B, which sees `aud` containing its own ' +
          'client_id and accepts the login. The base OIDC defence here is ' +
          'the §3.1.3.7 step 3 check (`client_id ∈ aud`) — but that check ' +
          'still passes for Service B. `azp`, when populated, lets Service ' +
          'B distinguish "originally minted for Service A".',
        impact:
          'Cross-service identity bleed in shared-audience configurations.',
      },
    ],
    mitigations: [
      {
        action:
          'When `azp` is present, validate `azp == this client_id` per ' +
          'OIDC Core §3.1.3.7 step 4 (SHOULD). Operationally, deployments ' +
          'that issue multi-audience ID Tokens often elevate this from ' +
          'SHOULD to MUST as part of their security profile (e.g. several ' +
          'IdPs unconditionally emit `azp`).',
        mitigates: ['cross-client-id-token-reuse'],
      },
      {
        action:
          'Prefer single-audience tokens — issue a separate ID Token per ' +
          'recipient instead of "saving tokens" by reusing one across ' +
          'services. Removes the need to rely on `azp` at all.',
        mitigates: ['cross-client-id-token-reuse'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §2 (ID Token — azp claim)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
      },
      {
        label: 'OpenID Connect Core §3.1.3.7 (ID Token Validation, steps 4–5 — azp validation)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
      },
      {
        label: 'OpenID Connect Core §16.11 (Token Substitution)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenSubstitution',
      },
    ],
  },

  prompt: {
    purpose:
      'Controls how the OP interacts with the user during authentication. ' +
      'Values: `none` (return immediately without UI — fail if interaction ' +
      'needed), `login` (force re-auth even if a session exists), `consent` ' +
      '(force consent re-prompt), `select_account` (account picker).',
    attacks: [
      {
        id: 'silent-reauth-clickjacking',
        name: 'Silent re-auth clickjacking',
        scenario:
          'Clients use `prompt=none` for silent re-auth in iframes — refresh ' +
          'an expired session without interrupting the user. The iframe is ' +
          'invisible by design; that same invisibility is a clickjacking ' +
          'primitive when the OP doesn\'t block framing. Mallory hosts a ' +
          'page containing a hidden iframe pointing at the OP\'s ' +
          '`/authorize?prompt=none&...` for her own malicious client_id. ' +
          'Alice visits Mallory\'s page; if Alice has an active session at ' +
          'the OP, the frame returns tokens to Mallory\'s callback without ' +
          'any visible UI — Alice has no way to notice she just authorized ' +
          'a third-party app.',
        impact:
          'Silent token issuance to attacker-controlled clients. Compounds ' +
          'with consent phishing and over-broad scope: a malicious client ' +
          'with `offline_access` plus `prompt=none` clickjack gets a ' +
          'refresh token with no user interaction.',
      },
    ],
    mitigations: [
      {
        action:
          'OP sends `X-Frame-Options: DENY` and ' +
          '`Content-Security-Policy: frame-ancestors \'none\'` on ' +
          'authorization endpoints by default.',
        mitigates: ['silent-reauth-clickjacking'],
      },
      {
        action:
          'Allowlist legitimate silent-auth origins explicitly in ' +
          '`frame-ancestors` rather than disabling framing controls.',
        mitigates: ['silent-reauth-clickjacking'],
      },
      {
        action:
          'For high-stakes scopes (offline_access, admin operations), the ' +
          'OP refuses `prompt=none` and forces explicit consent.',
        mitigates: ['silent-reauth-clickjacking'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.1.2.1 (Authentication Request)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest',
      },
      {
        label: 'OAuth Clickjacking write-up',
        href: 'https://melmanm.github.io/misc/2023/10/01/article10-oauth-clickjacking.html',
      },
      {
        label: 'OpenID Connect Core §16.16 (Implicit Flow / silent-auth Threats)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowThreats',
      },
    ],
  },

  email_verified: {
    purpose:
      'Boolean claim asserting the OP has verified the user\'s email. ' +
      'Intended for relying parties to use as a signal when linking accounts ' +
      'across providers ("if Google says the email is verified, treat it as ' +
      'authoritative").',
    attacks: [
      {
        id: 'noauth-cross-tenant',
        name: 'nOAuth — cross-tenant impersonation via email claim',
        scenario:
          'Mallory creates her own Entra tenant where she has admin rights. ' +
          'She assigns Alice\'s corporate email address to an account she ' +
          'controls in her tenant. The token Entra mints carries ' +
          '`email: alice@corp.com` and (in some configurations) ' +
          '`email_verified: true`. Mallory signs into a target SaaS app ' +
          'via "Sign in with Microsoft" using her tenant. The SaaS app — ' +
          'which matches accounts by `email` because it\'s convenient — ' +
          'links Mallory\'s sign-in to Alice\'s existing account. ' +
          'Disclosed by Descope in June 2023; ~9% of Entra multi-tenant ' +
          'SaaS apps still vulnerable per a 2025 study. The OPs vary ' +
          'wildly in how they set this claim: some always set true; some ' +
          'never set the field; some let users in their tenant set ' +
          'arbitrary unverified email values. OIDC Core §5.7 explicitly ' +
          'warns that `email` is not stable or unique and that RPs should ' +
          'not key user accounts on it.',
        impact:
          'Full account takeover. MFA does not help, EDR does not help, ' +
          'the attack uses the federation exactly as designed.',
      },
    ],
    mitigations: [
      {
        action:
          'Use the immutable `sub` claim (paired with `iss` for tenant ' +
          'scope) for account matching — never `email` or ' +
          '`email_verified`.',
        mitigates: ['noauth-cross-tenant'],
      },
      {
        action:
          'If account linking by email is unavoidable, perform an ' +
          'out-of-band email verification step on the RP side — do not ' +
          'trust the IdP\'s assertion.',
        mitigates: ['noauth-cross-tenant'],
      },
      {
        action:
          'Where the IdP supports it (Entra has added these in 2024-25), ' +
          'consume domain-verified-email claims that distinguish ' +
          'tenant-verified-domain emails from arbitrarily-typed ones.',
        mitigates: ['noauth-cross-tenant'],
      },
    ],
    references: [
      {
        label: 'Descope nOAuth disclosure',
        href: 'https://www.descope.com/blog/post/noauth',
      },
      {
        label: 'Semperis nOAuth Cross-Tenant Takeover',
        href: 'https://www.semperis.com/blog/noauth-abuse-alert-full-account-takeover/',
      },
      {
        label: 'OpenID Connect Core 1.0 §5.7 (Claim Stability and Uniqueness)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability',
      },
    ],
  },

  id_token_signing_alg_values_supported: {
    purpose:
      'Discovery-document field listing which JWS algorithms the OP will use ' +
      'to sign ID Tokens (e.g. `["RS256", "ES256"]`). Clients use this to ' +
      'configure their verifying side.',
    attacks: [
      {
        id: 'alg-from-token-header',
        name: 'Alg selection from attacker-controlled token header',
        scenario:
          'A client that selects the verification algorithm from the JWT ' +
          'header instead of the metadata opens up the full JWT-attack ' +
          'family — alg=none signature stripping, RS256→HS256 confusion, ' +
          'fail-open on unknown alg. The discovery field is the *correct* ' +
          'source of truth for which alg the client will accept; the JWT ' +
          'header is the *attacker-controlled* source.',
        impact:
          'Authentication bypass via algorithm-selection redirection. ' +
          'Trust order matters: discovery is trusted, token header is not.',
      },
      {
        id: 'symmetric-alg-on-public-key-op',
        name: 'Symmetric algorithm advertised by a public-key OP',
        scenario:
          'The OP advertises `HS256` (or another HMAC algorithm) in this ' +
          'list while using public-key signing in practice. A misconfigured ' +
          'client treats the OP\'s public key as an HMAC secret — and the ' +
          'public key is, by definition, public.',
        impact:
          'Anyone with access to the OP\'s published JWKS can forge ' +
          'arbitrary tokens.',
      },
    ],
    mitigations: [
      {
        action:
          'Pin verification to the discovery doc\'s advertised alg(s); ' +
          'reject tokens whose header `alg` is not on that list before ' +
          'doing any cryptographic work.',
        mitigates: ['alg-from-token-header'],
      },
      {
        action:
          'For public-key OPs, never list symmetric algorithms (HS256, ' +
          'HS384, HS512) in this field — the "shared secret" would be the ' +
          'OP\'s public key.',
        mitigates: ['symmetric-alg-on-public-key-op'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Discovery 1.0 §3 (Provider Metadata)',
        href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
      },
      {
        label: 'OpenID Connect Core §16.13 (Other Crypto-Related Attacks)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#OtherCryptoAttacks',
      },
      {
        label: 'OpenID Connect Core §16.19 (Symmetric Key Entropy)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#SymmetricKeyEntropy',
      },
    ],
  },

  auth_time: {
    purpose:
      'Time of the user\'s last actual authentication at the OP, as a Unix ' +
      'timestamp — when the user last typed a password / completed MFA, ' +
      'not when this token was minted. Used by RPs to enforce step-up: ' +
      '"for this sensitive operation, require authentication within the ' +
      'last N seconds".',
    attacks: [
      {
        id: 'stale-session-privilege-escalation',
        name: 'Stale-session privilege escalation',
        scenario:
          'Mallory finds Alice\'s laptop unlocked. Alice signed into the OP ' +
          'days ago and has SSO sessions across the org. Without ' +
          '`auth_time` enforcement on sensitive RPs, Mallory can perform ' +
          'admin/financial actions immediately because the silent-auth ' +
          'flow returns a fresh ID Token with `iat=now` — looks recent — ' +
          'even though the actual user authentication is two days old.',
        impact:
          'A long-lived OP session silently authenticates high-assurance ' +
          'operations the user has not consciously approved in days.',
      },
    ],
    mitigations: [
      {
        action:
          'Sensitive RPs MUST send `max_age` on the request and verify ' +
          '`auth_time + max_age >= now` on the response.',
        mitigates: ['stale-session-privilege-escalation'],
      },
      {
        action:
          'Pair with `prompt=login` when re-authentication must be visible ' +
          '— the OP forces fresh credential entry regardless of existing ' +
          'session.',
        mitigates: ['stale-session-privilege-escalation'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §2 (auth_time)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
      },
    ],
  },

  sub: {
    purpose:
      'Subject identifier — the immutable, unique-per-user (per-OP) string ' +
      'that names the end user. Stable across logins. The ONE identifier ' +
      'the OIDC spec calls out as the right thing to key user accounts on.',
    attacks: [
      {
        id: 'cross-tenant-via-mutable-claim',
        name: 'Cross-tenant identity confusion via mutable-claim matching',
        scenario:
          'RPs key user accounts on a mutable claim (`email`, ' +
          '`preferred_username`) rather than `sub`. An attacker who ' +
          'controls a tenant in a multi-tenant IdP assigns a target user\'s ' +
          'email to her own account; the IdP issues a token where `email` ' +
          'matches the target but `sub` does not. RPs that key on `email` ' +
          'link the attacker\'s sign-in to the target\'s account.',
        impact:
          'Account takeover. The same shape as nOAuth (see ' +
          '`email_verified`).',
      },
    ],
    mitigations: [
      {
        action:
          'Use `(iss, sub)` as the composite primary key for federated ' +
          'accounts. RPs that key on `(iss, sub)` are immune; RPs that key ' +
          'on `email` are exposed.',
        mitigates: ['cross-tenant-via-mutable-claim'],
      },
      {
        action:
          'For privacy-sensitive deployments, accept PPID (Pairwise ' +
          'Pseudonymous Identifier) — different RPs receive a different ' +
          '`sub` for the same user. Each RP just remembers its own pair.',
        mitigates: ['cross-tenant-via-mutable-claim'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §5.7 (Claim Stability and Uniqueness)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability',
      },
      {
        label: 'OpenID Connect Core 1.0 §8 (Subject Identifier Types)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes',
      },
    ],
  },

  issuer: {
    purpose:
      'The OP\'s canonical identifier URL, returned in the discovery ' +
      'document and required to match the `iss` claim on every ID Token ' +
      'verbatim. Anchors the chain of trust: discovery → JWKS → token ' +
      'signature → iss comparison.',
    attacks: [
      {
        id: 'as-impersonation-via-metadata',
        name: 'AS impersonation via metadata',
        scenario:
          'Mallory registers `accounts.googel.com` (typo) and hosts a full ' +
          'discovery document pointing at her own JWKS. She tricks the ' +
          'client (via configuration mistake, DNS hijack, or attacker-' +
          'controlled federation) into using that issuer. Tokens she mints ' +
          'pass signature, iss, aud, exp checks — all derived from her ' +
          'own metadata.',
        impact:
          'If the client trusts whatever issuer the token claims and ' +
          'looks up the JWKS based on the token\'s issuer, the attacker ' +
          'controls the trust chain end-to-end.',
      },
    ],
    mitigations: [
      {
        action:
          'Pin the expected issuer string at deployment time; never derive ' +
          'it from the token.',
        mitigates: ['as-impersonation-via-metadata'],
      },
      {
        action:
          'Fetch discovery metadata over HTTPS with strict cert validation; ' +
          'pin the issuer\'s domain at the configuration layer.',
        mitigates: ['as-impersonation-via-metadata'],
      },
      {
        action:
          'In multi-AS federation, pair issuer pinning with the RFC 9207 ' +
          '`iss` parameter on the authorization response so the mix-up ' +
          'class of attacks is also closed.',
        mitigates: ['as-impersonation-via-metadata'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Discovery 1.0 §3 (Issuer Identifier)',
        href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
      },
      {
        label: 'RFC 9207 (Authorization Server Issuer Identification)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9207',
      },
      {
        label: 'OpenID Connect Core §16.2 (Server Masquerading)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ServerMasquerading',
      },
      {
        label: 'OpenID Connect Core §16.15 (Issuer Identifier)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IssuerIdentifier',
      },
    ],
  },

  jwks_uri: {
    purpose:
      'URL where the OP publishes its current set of public verification ' +
      'keys (JWK Set). Clients fetch this to verify ID Token and (often) ' +
      'access token signatures.',
    attacks: [
      {
        id: 'stale-jwks-cache',
        name: 'Stale JWKS cache after key rotation',
        scenario:
          'The OP rotated keys hours ago and the cached set no longer ' +
          'contains the active signing key. Tokens signed with the new key ' +
          'fail to verify, breaking logins.',
        impact:
          'Availability impact — failed logins, support tickets — until ' +
          'the cache is refreshed.',
      },
      {
        id: 'jwks-refresh-amplification',
        name: 'Per-request JWKS refetch amplification',
        scenario:
          'The client refetches JWKS every time it sees an unrecognized ' +
          '`kid`. An attacker who can submit tokens (legitimate or ' +
          'crafted) with random kids drives the client to hammer the OP\'s ' +
          'JWKS endpoint.',
        impact:
          'Denial-of-wallet on the OP side; performance impact on the ' +
          'client side.',
      },
      {
        id: 'jwks-driven-ssrf',
        name: 'JWKS-driven SSRF',
        scenario:
          'If the client honours `jwks_uri` from the discovery doc without ' +
          'strict allowlisting, an attacker who can poison the discovery ' +
          'cache (or who controls a federation entry) points it at ' +
          '`http://169.254.169.254/...` (cloud metadata service) or an ' +
          'internal service. The client fetches "JWKS" from that URL and ' +
          'hands the response back to the attacker via error messages, log ' +
          'inclusion, or side-channel timing.',
        impact:
          'Information disclosure of internal services or cloud metadata ' +
          '(IAM credentials, instance identity).',
      },
    ],
    mitigations: [
      {
        action:
          'Cache JWKS with sane TTL aligned to the OP\'s rotation cadence.',
        mitigates: ['stale-jwks-cache'],
      },
      {
        action:
          'On unknown `kid`, refetch *once* with a cooldown — never per-' +
          'request.',
        mitigates: ['jwks-refresh-amplification'],
      },
      {
        action:
          'Pin `jwks_uri` to the OP\'s domain via configuration; do not ' +
          'trust discovery for endpoint URLs in security-critical paths ' +
          'without an allowlist.',
        mitigates: ['jwks-driven-ssrf'],
      },
    ],
    references: [
      {
        label: 'RFC 7517 (JSON Web Key)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7517',
      },
      {
        label: 'OpenID Connect Discovery 1.0 §3 (Provider Metadata — jwks_uri)',
        href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
      },
      {
        label: 'OpenID Connect Core §16.13 (Crypto-Related Attacks)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#OtherCryptoAttacks',
      },
    ],
  },

  kid: {
    purpose:
      'Key Identifier in the JWT header. Tells the verifying side which key ' +
      'in the JWKS produced this signature. Enables key rotation: the OP ' +
      'can publish multiple active keys and rotate by changing which `kid` ' +
      'signs new tokens.',
    attacks: [
      {
        id: 'kid-trivial-mismatch',
        name: 'kid mismatch ignored',
        scenario:
          'The verifier accepts the first key in the JWKS regardless of ' +
          '`kid`, defeating rotation\'s ability to revoke a compromised ' +
          'key. After a rotation, tokens signed with the now-revoked key ' +
          'continue to be accepted because the verifier looked up by index ' +
          'rather than identifier.',
        impact:
          'Compromised-key revocation does not actually take effect.',
      },
      {
        id: 'kid-injection',
        name: 'kid-injection token forgery',
        scenario:
          'The verifier uses the JWT-supplied `kid` as a lookup key into a ' +
          'filesystem path or SQL query without validation. Mallory crafts ' +
          'an ID Token with `{"alg":"HS256","kid":"../../public/static/' +
          'attacker_uploaded.txt"}`. The verifier reads the file at that ' +
          'path, treats its contents as the HMAC key, and validates the ' +
          'token. Mallory now has a forged token signed with a "key" of ' +
          'her choosing. Variant: `kid="\' OR 1=1 --"` for SQLi-style ' +
          'lookups.',
        impact:
          'Authentication bypass — attacker chooses both the signing key ' +
          'and the token contents.',
      },
    ],
    mitigations: [
      {
        action:
          'Treat `kid` as untrusted input — look it up in an in-memory ' +
          'JWKS cache, never use it directly as a path or query value.',
        mitigates: ['kid-injection'],
      },
      {
        action:
          'Reject tokens whose `kid` is not in the current JWKS.',
        mitigates: ['kid-trivial-mismatch', 'kid-injection'],
      },
      {
        action:
          'Maintain a brief grace window for recently-rotated keys to ' +
          'avoid breaking clients during rotation.',
        mitigates: ['kid-trivial-mismatch'],
      },
    ],
    references: [
      {
        label: 'RFC 7515 §4.1.4 (kid Header Parameter)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4',
      },
      {
        label: 'PortSwigger — JWT attacks (kid injection)',
        href: 'https://portswigger.net/web-security/jwt',
      },
      {
        label: 'OpenID Connect Core §16.13 (Crypto-Related Attacks)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#OtherCryptoAttacks',
      },
    ],
  },

  // Per-protocol override: in OIDC, `aud` carries identity-token semantics
  // (must contain client_id) on top of the OAuth2 audience-confusion story.
  'oidc:aud': {
    purpose:
      'On an OIDC ID Token, `aud` MUST contain the requesting client\'s ' +
      'client_id. May be a string (single audience) or an array (multiple). ' +
      'When multiple, `azp` indicates the actual authorized party.',
    attacks: [
      {
        id: 'cross-client-token-forwarding',
        name: 'Cross-client token forwarding',
        scenario:
          'A malicious sibling app at the same OP (different client_id, ' +
          'same signing key) forwards an ID Token it received to a target ' +
          'client that does not verify `aud`. The target accepts the login ' +
          'because the signature is valid and iss/exp are fine — unaware ' +
          'that the token was issued for a different RP entirely. In a ' +
          'multi-tenant SaaS, that means tokens from any tenant\'s sign-in ' +
          'flow can be replayed at any other tenant\'s login endpoint.',
        impact:
          'Cross-RP authentication bypass against any client that accepts ' +
          'signed tokens from the OP without verifying its own client_id ' +
          'appears in `aud`.',
      },
    ],
    mitigations: [
      {
        action: 'Verify `client_id` appears in `aud` on every ID Token.',
        mitigates: ['cross-client-token-forwarding'],
      },
      {
        action:
          'When `aud` is a multi-element array, additionally verify `azp` ' +
          'equals this client_id.',
        mitigates: ['cross-client-token-forwarding'],
      },
    ],
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.1.3.7 (ID Token Validation, item 3)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
      },
      {
        label: 'OpenID Connect Core §16.11 (Token Substitution)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#TokenSubstitution',
      },
    ],
  },
}
