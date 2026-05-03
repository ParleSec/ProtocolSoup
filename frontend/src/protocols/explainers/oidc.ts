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
    withoutIt:
      'Without `nonce`, the client cannot tell whether the ID Token it just ' +
      'received was minted for *this* authentication or replayed from an ' +
      'earlier session. The signature still verifies, the `iss` and `aud` ' +
      'still match — but the token may have been captured weeks earlier and ' +
      'replayed now.',
    attack:
      'ID Token Replay. Mallory captures a legitimate ID Token bearing Alice\'s ' +
      'identity from any leakage path — browser history of an implicit-flow ' +
      'redirect, a referer header, a server log, an old session backup. Some ' +
      'time later (still within the token\'s exp window, or against a client ' +
      'with lax exp checks) Mallory injects the captured ID Token into a fresh ' +
      'authentication response landing at the client. Without nonce binding, ' +
      'the client accepts the token as the result of "the authentication that ' +
      'just happened" and signs Mallory in as Alice.',
    impact:
      'Account takeover via stale-token replay. Real-world implementation ' +
      'flaw — academic study of OIDC deployments found nonce checking is one ' +
      'of the most commonly broken validation steps because it requires ' +
      'session-state plumbing the developer has to wire up explicitly. RFC ' +
      'requires the client to compare the ID Token\'s nonce claim against ' +
      'the session-stored value before trusting any other claim.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §15.5.2 (Nonce Implementation Notes)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes',
      },
      {
        label: 'OpenID Connect Core 1.0 §3.1.3.7 (ID Token Validation)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
      },
    ],
  },

  id_token: {
    purpose:
      'A signed JWT carrying authentication assertions about the end user — ' +
      'the *identity* output of OIDC. Claims include `iss`, `sub`, `aud`, ' +
      '`exp`, `iat`, `nonce`, optionally `auth_time`, `acr`, `amr`, `azp`, ' +
      '`at_hash`, `c_hash`. Its signature is verified against the OP\'s JWKS.',
    withoutIt:
      'The risks are not in receiving an ID Token but in *how it is validated*. ' +
      'A non-trivial percentage of OIDC libraries and integrations ship with ' +
      'one or more validation flaws that a forged token slips through.',
    attack:
      'Multiple distinct, repeatedly-CVE\'d patterns: (1) **alg=none** — ' +
      'attacker sets the JWT header to `{"alg":"none"}`, strips the signature, ' +
      'and the library accepts the unsigned token (CVE-2026-31946 OpenOlat ' +
      'OIDC, multiple historical CVEs). (2) **Algorithm confusion (RS256 → ' +
      'HS256)** — server is configured to verify with an RSA public key but ' +
      'the library, on receiving a token with `alg:HS256`, treats the public ' +
      'key as an HMAC secret; attacker who has the public key (it\'s public!) ' +
      'forges arbitrary tokens. (3) **Default-fallback verification** — ' +
      'CVE-2026-28802 in Authlib defaulted to HMAC verification when `alg` ' +
      'was missing or unknown, fail-open. (4) **Skipped claim validation** — ' +
      'signature passes but `iss`, `aud`, `exp`, `nonce` are not checked, ' +
      'turning a valid signature on the wrong token into a successful login.',
    impact:
      'Authentication bypass for anyone who can craft a JWT — i.e. anyone, ' +
      'since JWT structure is public. Mitigations: pin allowed `alg` values ' +
      'on the verifying side (do not honour the JWT header\'s alg field for ' +
      'algorithm selection); fail closed on unknown alg; validate the full ' +
      'claim set (iss, aud, exp, nbf, iat-recency, nonce) on every token; ' +
      'use a single battle-tested library, not hand-rolled verification.',
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
        label: 'JWT alg confusion (RS256 → HS256)',
        href: 'https://medium.com/@instatunnel/jwt-algorithm-confusion-turning-rs256-tokens-into-hs256-disasters-db1923774873',
      },
    ],
  },

  at_hash: {
    purpose:
      'Access Token Hash claim in the ID Token. Equals BASE64URL(left-half(' +
      'hash(access_token))) using the hash matching the ID Token\'s `alg`. ' +
      'Cryptographically binds the ID Token to the access token delivered ' +
      'alongside it in the same response.',
    withoutIt:
      'In flows where both an ID Token and an access token come back through ' +
      'the front-channel (implicit, hybrid), there is nothing else linking the ' +
      'two — an attacker who can substitute the access token in transit can ' +
      'pair an honest ID Token with an attacker-controlled access token, or ' +
      'vice versa.',
    attack:
      'Access token substitution in front-channel responses. Mallory runs a ' +
      'malicious browser extension or a script on a redirect-page subresource. ' +
      'When Alice\'s implicit/hybrid response lands in `window.location.hash`, ' +
      'Mallory swaps `access_token=…` for one tied to her own IdP identity ' +
      'while leaving the ID Token (signed) intact. The client validates the ' +
      'ID Token (signature OK) and uses the swapped access token for ' +
      'subsequent UserInfo / API calls — which then return data for *Mallory*, ' +
      'not Alice. Without `at_hash` validation, the swap is undetectable.',
    impact:
      'Effective: client logs Alice in (per ID Token) but its API calls run ' +
      'as Mallory — privilege confusion. **Fail-open vulnerabilities** are ' +
      'real: Authlib CVE-2026-28498 silently returned `True` when the ID ' +
      'Token\'s alg was unknown, defeating at_hash validation. Verify ' +
      'libraries fail *closed* on unknown alg.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.2.2.10 (at_hash)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation',
      },
      {
        label: 'CVE-2026-28498 (Authlib at_hash/c_hash fail-open)',
        href: 'https://advisories.gitlab.com/pkg/pypi/authlib/CVE-2026-28498/',
      },
    ],
  },

  c_hash: {
    purpose:
      'Code Hash claim in the ID Token, used in the Hybrid Flow. Equals ' +
      'BASE64URL(left-half(hash(code))). Binds the ID Token (delivered ' +
      'immediately on the front-channel) to the authorization code that ' +
      'will later be exchanged on the back-channel.',
    withoutIt:
      'Hybrid flow returns a `code` and an `id_token` together in the same ' +
      'redirect. Without `c_hash`, an attacker who can swap one for another ' +
      'in the front-channel can pair an honest ID Token with a substituted ' +
      'code — the OIDC manifestation of the OAuth Authorization Code ' +
      'Injection attack class.',
    attack:
      'Code substitution in hybrid flow. Mallory captures her own valid ' +
      'authorization code from the OP, then runs a malicious extension or ' +
      'subresource on the client\'s redirect page. When Alice\'s response ' +
      'arrives, Mallory rewrites `code=…` to her own captured code while ' +
      'leaving the (signed) ID Token unchanged. The client validates the ID ' +
      'Token, reads the rewritten code, exchanges it for tokens at /token — ' +
      'and gets tokens for Mallory\'s identity, which it then links into ' +
      'Alice\'s session.',
    impact:
      'Account-linking takeover via swapped code. PKCE additionally ' +
      'prevents the token exchange from succeeding for a code the attacker ' +
      'captured (her verifier does not match). Where PKCE is unavailable, ' +
      'c_hash is the primary defence. Authlib CVE-2026-28498 affects ' +
      'c_hash validation specifically.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.3.2.11 (c_hash)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken',
      },
      {
        label: 'CVE-2026-28498 (Authlib at_hash/c_hash fail-open)',
        href: 'https://advisories.gitlab.com/pkg/pypi/authlib/CVE-2026-28498/',
      },
    ],
  },

  azp: {
    purpose:
      'Authorized Party claim in the ID Token. When the token\'s `aud` ' +
      'contains multiple audiences (or one audience that is not the ' +
      'requesting client), `azp` MUST equal the client_id of the party the ' +
      'token was actually issued to. Lets a recipient distinguish "I am the ' +
      'audience" from "I am the audience the token was minted for".',
    withoutIt:
      'In multi-audience deployments (one ID Token shared across a primary ' +
      'app and several backend microservices) the recipient cannot tell ' +
      'which client started the flow. A malicious client in the same audience ' +
      'set can forward an ID Token it received and have a sibling service ' +
      'accept it as if that service had been the original RP.',
    attack:
      'Cross-client ID Token reuse. Service A and Service B both list ' +
      'themselves in the AS audience configuration. Mallory operates ' +
      'Service A and persuades Alice to sign in. Mallory takes the resulting ' +
      'ID Token and replays it to Service B, which sees `aud` containing its ' +
      'own client_id and accepts the login. Without `azp` validation Service ' +
      'B has no way to know the token was originally minted for Service A.',
    impact:
      'Cross-service identity bleed in shared-audience configurations. ' +
      'Recipients in multi-audience tokens MUST validate `azp == this ' +
      'client_id` in addition to `client_id ∈ aud`. Most production setups ' +
      'avoid the issue by issuing single-audience tokens; the failure mode ' +
      'kicks in when teams "save tokens" by reusing one across services.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §2 (azp claim)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
      },
    ],
  },

  prompt: {
    purpose:
      'Controls how the OP interacts with the user during authentication. ' +
      'Values: `none` (return immediately without UI — fail if interaction ' +
      'needed), `login` (force re-auth even if a session exists), `consent` ' +
      '(force consent re-prompt), `select_account` (account picker).',
    withoutIt:
      'The risks are around `prompt=none` specifically. Clients use it for ' +
      'silent re-auth in iframes — refresh an expired session without ' +
      'interrupting the user. The iframe is invisible by design; that same ' +
      'invisibility is a phishing/clickjacking primitive when the OP doesn\'t ' +
      'block framing.',
    attack:
      'Silent re-auth clickjacking. Mallory hosts a page containing a hidden ' +
      'iframe pointing at the OP\'s `/authorize?prompt=none&...` for her own ' +
      'malicious client_id. Alice visits Mallory\'s page; if Alice has an ' +
      'active session at the OP, the frame returns tokens to Mallory\'s ' +
      'callback without any visible UI — Alice has no way to notice she just ' +
      'authorized a third-party app. Defence is OP-side: send `X-Frame-' +
      'Options: DENY` and `Content-Security-Policy: frame-ancestors \'none\'` ' +
      'on authorization endpoints, with explicit allowlist for legitimate ' +
      'silent-auth origins.',
    impact:
      'Silent token issuance to attacker-controlled clients. Compounds with ' +
      'consent phishing and over-broad scope: a malicious client with ' +
      '`offline_access` plus `prompt=none` clickjack gets a refresh token ' +
      'with no user interaction.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.1.2.1 (Authentication Request)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest',
      },
      {
        label: 'OAuth Clickjacking write-up',
        href: 'https://melmanm.github.io/misc/2023/10/01/article10-oauth-clickjacking.html',
      },
    ],
  },

  email_verified: {
    purpose:
      'Boolean claim asserting the OP has verified the user\'s email. ' +
      'Intended for relying parties to use as a signal when linking accounts ' +
      'across providers ("if Google says the email is verified, treat it as ' +
      'authoritative").',
    withoutIt:
      'The trap is *trusting* `email_verified` blindly. OPs vary wildly: some ' +
      'always set true; some never set the field; some let users in their ' +
      'tenant set arbitrary unverified email values. The OIDC spec itself ' +
      'says: "ultimately it is unsafe to rely on the Issuer to verify the ' +
      'email of a user."',
    attack:
      'nOAuth (Descope, June 2023; ~9% of Entra multi-tenant SaaS apps still ' +
      'vulnerable per 2025 study). Mallory creates her own Entra tenant where ' +
      'she has admin rights. She assigns Alice\'s corporate email address to ' +
      'an account she controls in her tenant. The token Entra mints carries ' +
      '`email: alice@corp.com` and (in some configurations) `email_verified: ' +
      'true`. Mallory signs into a target SaaS app via "Sign in with ' +
      'Microsoft" using her tenant. The SaaS app — which matches accounts by ' +
      '`email` because it\'s convenient — links Mallory\'s sign-in to ' +
      'Alice\'s existing account. Full account takeover, MFA does not help, ' +
      'EDR does not help, the attack uses Entra exactly as designed.',
    impact:
      'Cross-tenant account takeover. Use the immutable `sub` claim (paired ' +
      'with `iss` for tenant scope) for account matching, never `email` or ' +
      '`email_verified`. If account linking by email is unavoidable, perform ' +
      'an out-of-band email verification step on the RP side — do not trust ' +
      'the IdP\'s assertion. Microsoft has added domain-verified-email ' +
      'claims in 2024-25 to mitigate; many integrations still use the old ' +
      'pattern.',
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
        label: 'OpenID Connect Core 1.0 §5.7 (Claim Stability)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability',
      },
    ],
  },

  id_token_signing_alg_values_supported: {
    purpose:
      'Discovery-document field listing which JWS algorithms the OP will use ' +
      'to sign ID Tokens (e.g. `["RS256", "ES256"]`). Clients use this to ' +
      'configure their verifying side.',
    withoutIt:
      'The risk is in *how the client uses this list*. If the client trusts ' +
      'the JWT header\'s own `alg` field to choose the verification ' +
      'algorithm, every JWT-validation attack opens up — alg=none, RS256→' +
      'HS256 confusion, fail-open on unknown alg.',
    attack:
      'The discovery field is the *correct* source of truth for which alg ' +
      'the client will accept; the JWT header is the *attacker-controlled* ' +
      'source. A client that selects the verification algorithm from the ' +
      'token header instead of the metadata opens up the full JWT-attack ' +
      'family (alg=none, RS256→HS256 confusion, fail-open on unknown ' +
      'alg). Trust order matters.',
    impact:
      'Pin verification to the discovery doc\'s advertised alg(s); reject ' +
      'tokens whose header `alg` is not on that list before doing any ' +
      'cryptographic work. Symmetric algorithms (`HS256`) on this list for ' +
      'a public-key OP are a misconfiguration on their own — the "shared ' +
      'secret" is the OP\'s public key, which is public.',
    references: [
      {
        label: 'OpenID Connect Discovery 1.0 §3 (Provider Metadata)',
        href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
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
    withoutIt:
      'A long-lived OP session (the user logged in once two days ago and ' +
      'has been getting silent re-auth ever since) silently authenticates ' +
      'high-assurance operations the user has not consciously approved in ' +
      'days.',
    attack:
      'Stale-session privilege escalation. Mallory finds Alice\'s laptop ' +
      'unlocked. Alice signed into the OP days ago and has SSO sessions ' +
      'across the org. Without `auth_time` enforcement on sensitive RPs, ' +
      'Mallory can perform admin/financial actions immediately because the ' +
      'silent-auth flow returns a fresh ID Token with `iat=now` — looks ' +
      'recent — even though the actual user authentication is two days old.',
    impact:
      'Sensitive RPs MUST also send `max_age` on the request and verify ' +
      '`auth_time + max_age >= now` on the response. Pair with `prompt=login` ' +
      'when re-auth must be visible. Without this discipline the OP\'s ' +
      'long-lived session becomes the weakest link.',
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
      'that names the end user. Stable across logins. The ONE identifier the ' +
      'OIDC spec calls out as the right thing to key user accounts on.',
    withoutIt:
      'Using `email`, `preferred_username`, or any other user-mutable ' +
      'attribute as the account-matching key is the gap. `sub` is the only ' +
      'claim guaranteed stable, unique, and not user-controllable.',
    attack:
      'Cross-tenant identity confusion when RPs key user accounts on a ' +
      'mutable claim (`email`, `preferred_username`) rather than `sub`. An ' +
      'attacker who controls a tenant in a multi-tenant IdP assigns a ' +
      'target user\'s email to her own account; the IdP issues a token ' +
      'where `email` matches the target but `sub` does not. RPs that key ' +
      'on `(iss, sub)` are immune; RPs that key on `email` link the ' +
      'attacker\'s sign-in to the target\'s account.',
    impact:
      'Use `(iss, sub)` as the composite primary key for federated accounts. ' +
      'PPID (Pairwise Pseudonymous Identifier) variants exist where ' +
      'different RPs each receive a different `sub` for the same user — ' +
      'good for privacy, fine for account matching as long as the RP ' +
      'remembers its own pair.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §5.7 (Claim Stability)',
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
      'The OP\'s canonical identifier URL, returned in the discovery document ' +
      'and required to match the `iss` claim on every ID Token verbatim. ' +
      'Anchors the chain of trust: discovery → JWKS → token signature → iss ' +
      'comparison.',
    withoutIt:
      'If the client trusts whatever issuer the token claims and looks up ' +
      'the JWKS based on the token\'s issuer, an attacker who can host their ' +
      'own discovery document can mint tokens that pass every check.',
    attack:
      'AS impersonation via metadata. Mallory registers ' +
      '`accounts.googel.com` (typo) and hosts a full discovery document ' +
      'pointing at her own JWKS. She tricks the client (via configuration ' +
      'mistake, DNS hijack, or attacker-controlled federation) into using ' +
      'that issuer. Tokens she mints pass signature, iss, aud, exp checks ' +
      '— all derived from her own metadata.',
    impact:
      'Pin the expected issuer string at deployment time; never derive it ' +
      'from the token. Always fetch discovery metadata over HTTPS with ' +
      'cert validation. In multi-AS federation, pair issuer pinning with ' +
      'the RFC 9207 `iss` parameter on the authorization response so the ' +
      'mix-up class of attacks is also closed.',
    references: [
      {
        label: 'OpenID Connect Discovery 1.0 §3 (Issuer Identifier)',
        href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
      },
      {
        label: 'RFC 9207 (Authorization Server Issuer Identification)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9207',
      },
    ],
  },

  jwks_uri: {
    purpose:
      'URL where the OP publishes its current set of public verification ' +
      'keys (JWK Set). Clients fetch this to verify ID Token and (often) ' +
      'access token signatures.',
    withoutIt:
      'Two failure modes: (1) Caching stale JWKS — the OP rotated keys ' +
      'hours ago and the cached set no longer contains the active signing ' +
      'key; tokens signed with the new key fail to verify, breaking logins. ' +
      '(2) Refreshing too aggressively — every unrecognized `kid` triggers ' +
      'a JWKS refetch, opening a denial-of-wallet / amplification path ' +
      'against the OP and a potential SSRF if `jwks_uri` is not pinned.',
    attack:
      'JWKS-driven SSRF. If the client honours `jwks_uri` from the discovery ' +
      'doc without strict allowlisting, an attacker who can poison the ' +
      'discovery cache (or who controls a federation entry) points it at ' +
      '`http://169.254.169.254/...` (cloud metadata service) or an internal ' +
      'service. The client fetches "JWKS" from that URL and hands the ' +
      'response back to the attacker via error messages, log inclusion, or ' +
      'side-channel timing.',
    impact:
      'Cache JWKS with sane TTL aligned to the OP\'s rotation cadence; on ' +
      'unknown `kid`, refetch *once* with a cooldown — never per-request. ' +
      'Pin `jwks_uri` to the OP\'s domain via configuration; do not trust ' +
      'discovery for endpoint URLs in security-critical paths without ' +
      'allowlisting.',
    references: [
      {
        label: 'RFC 7517 (JSON Web Key)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7517',
      },
      {
        label: 'OpenID Connect Discovery 1.0 §3 (jwks_uri)',
        href: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata',
      },
    ],
  },

  kid: {
    purpose:
      'Key Identifier in the JWT header. Tells the verifying side which key ' +
      'in the JWKS produced this signature. Enables key rotation: the OP can ' +
      'publish multiple active keys and rotate by changing which `kid` ' +
      'signs new tokens.',
    withoutIt:
      'Two attack classes: (1) **Trivial mismatch** — verifier accepts the ' +
      'first key in JWKS regardless of `kid`, defeating rotation\'s ability ' +
      'to revoke a compromised key. (2) **kid-injection** — verifier uses ' +
      'the JWT-supplied `kid` as a lookup key into a filesystem path or SQL ' +
      'query without validation; attacker sets `kid` to `../../etc/passwd` ' +
      'or `\' OR 1=1 --` and gets path traversal / SQLi or, more usefully, ' +
      'points the verifier at a key the attacker controls.',
    attack:
      'kid-injection token forgery. Mallory crafts an ID Token with ' +
      '`{"alg":"HS256","kid":"../../public/static/file_under_attacker_' +
      'control.txt"}`. The verifier reads the file at that path, treats its ' +
      'contents as the HMAC key, and validates the token. Mallory now has ' +
      'a forged token signed with a "key" of her choosing.',
    impact:
      'Treat `kid` as untrusted input — look it up in an in-memory JWKS ' +
      'cache, never use it directly as a path or query value. Reject tokens ' +
      'whose `kid` is not in the current JWKS. Maintain a brief grace window ' +
      'for recently-rotated keys to avoid breaking clients during rotation.',
    references: [
      {
        label: 'RFC 7515 §4.1.4 (kid Header Parameter)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.4',
      },
      {
        label: 'PortSwigger — JWT attacks (kid injection)',
        href: 'https://portswigger.net/web-security/jwt',
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
    withoutIt:
      'A client that accepts an ID Token without verifying its own ' +
      'client_id appears in `aud` will accept tokens minted for any other ' +
      'client at the same OP. In a multi-tenant SaaS, that means tokens ' +
      'from any tenant\'s sign-in flow can be replayed at any other tenant\'s ' +
      'login endpoint.',
    attack:
      'Cross-client token forwarding. A malicious sibling app at the same ' +
      'OP (different client_id, same signing key) forwards an ID Token it ' +
      'received to a target client that does not verify `aud`. The target ' +
      'accepts the login because the signature is valid and iss/exp are ' +
      'fine — unaware that the token was issued for a different RP ' +
      'entirely. When `aud` is a multi-element array, the `azp` claim ' +
      'names the actual authorized party — recipients in multi-audience ' +
      'tokens MUST validate `azp` matches their client_id.',
    impact:
      'Always verify `client_id` appears in `aud`. When `aud` is a ' +
      'multi-element array, additionally verify `azp` equals this ' +
      'client_id. RP libraries that accept any signed token from the ' +
      'configured OP are common and consistently exploitable.',
    references: [
      {
        label: 'OpenID Connect Core 1.0 §3.1.3.7 (ID Token Validation, item 3)',
        href: 'https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation',
      },
    ],
  },
}
