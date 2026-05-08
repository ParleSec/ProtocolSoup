/**
 * OAuth 2.0 — Parameter Explainers
 *
 * Entries reused across OIDC, OID4VCI, OID4VP and other protocols that
 * build on OAuth2. Lookup is by parameter name; per-protocol overrides
 * (e.g. `oidc:aud`) live in the relevant protocol file.
 */

import type { ParameterExplainer } from './index'

export const OAUTH2_EXPLAINERS: Record<string, ParameterExplainer> = {
  state: {
    purpose:
      'An opaque, unguessable value the client generates per authorization ' +
      'request, persisted in the user session, and required to match on the ' +
      'redirect callback. Lets the client confirm that the response it ' +
      'received belongs to the flow it actually started.',
    attacks: [
      {
        id: 'csrf-account-linking',
        name: 'Account-linking CSRF',
        scenario:
          'Mallory starts an authorization flow at the IdP under her own ' +
          'credentials and stops at the redirect, capturing a valid `code` ' +
          'tied to her IdP identity. She crafts a link or auto-submitting ' +
          'iframe pointing at the client\'s redirect_uri carrying that code, ' +
          'and tricks Alice (already signed in to the client) into loading ' +
          'it. The client exchanges Mallory\'s code, receives tokens for ' +
          'Mallory\'s IdP identity, and links that identity to Alice\'s ' +
          'session. Without `state`, the /authorize endpoint and the ' +
          'redirect_uri callback both still complete normally for legitimate ' +
          'users — the attack succeeds precisely because nothing functionally ' +
          'misbehaves; the client just has no way to know whether *it* ' +
          'started the flow that produced the code it received.',
        impact:
          'Persistent account takeover: Mallory now logs into Alice\'s ' +
          'account at the client by signing in with her own IdP ' +
          'credentials. Particularly dangerous for "add a social login" ' +
          'flows on accounts that already have local credentials — the ' +
          'link is silent and survives password resets.',
      },
    ],
    mitigations: [
      {
        action:
          'Generate cryptographically random `state` per authorization ' +
          'request, persist in the user session, and require exact match ' +
          'on the redirect callback before processing the response.',
        mitigates: ['csrf-account-linking'],
      },
      {
        action:
          'PKCE (mandatory for all clients in RFC 9700) cryptographically ' +
          'binds the code to the client instance, breaking the ' +
          'code-injection variant of this attack.',
        rationale:
          '`state` remains the explicit CSRF check; PKCE is layered ' +
          'defence-in-depth.',
        mitigates: ['csrf-account-linking'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §10.12 (CSRF)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-10.12',
      },
      {
        label: 'RFC 6819 §4.4.1.8 (Threat Model)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6819#section-4.4.1.8',
      },
      {
        label: 'RFC 9700 §4.7 (CSRF Protection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.7',
      },
    ],
  },

  redirect_uri: {
    purpose:
      'The exact URL the Authorization Server will return the user to after ' +
      'consent. Pre-registered with the client and matched byte-for-byte at ' +
      'runtime.',
    attacks: [
      {
        id: 'code-interception-loose-match',
        name: 'Authorization code interception via loose redirect_uri matching',
        scenario:
          'Loose matching takes many forms: prefix match, wildcard subdomain, ' +
          'ignored query string, "any path under the registered host", or an ' +
          'open-redirect endpoint at `/redirect?to=…` under a registered ' +
          'host. Mallory crafts an authorize URL using the legit client_id ' +
          'but a redirect_uri pointing at her own callback ' +
          '(`https://app.example.com/attacker-controlled/cb` or ' +
          '`https://app.example.com/redirect?to=https://mallory.example`). ' +
          'Alice clicks, authenticates, consents — and the AS hands the ' +
          '`code` to Mallory.',
        impact:
          'Mallory exchanges the stolen code for Alice\'s tokens (or, with ' +
          'PKCE, fails on the exchange but still gets a usable one-shot in ' +
          'non-PKCE deployments). Full impersonation of Alice at every ' +
          'Resource Server the tokens are valid for.',
      },
    ],
    mitigations: [
      {
        action:
          'Register exact redirect_uri values; AS performs byte-for-byte ' +
          'match (no prefix, no wildcard, no query-string trimming).',
        mitigates: ['code-interception-loose-match'],
      },
      {
        action:
          'Eliminate open-redirect endpoints under any registered host. ' +
          'Audit `/redirect?to=…`-style helpers and lock them down to an ' +
          'allowlist.',
        mitigates: ['code-interception-loose-match'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §3.1.2 (Redirection Endpoint)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2',
      },
      {
        label: 'RFC 9700 §4.1 (Insufficient redirect_uri Validation)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.1',
      },
    ],
  },

  code: {
    purpose:
      'A short-lived, single-use credential issued at the redirect. The ' +
      'client exchanges it server-to-server for tokens. The code itself ' +
      'grants nothing without the matching client authentication (and PKCE ' +
      'verifier, if used).',
    attacks: [
      {
        id: 'code-replay',
        name: 'Authorization code replay',
        scenario:
          'A code leaks via referer header to a third-party script loaded ' +
          'on the redirect_uri page, or via a server access log shared with ' +
          'an analytics pipeline. Mallory finds it hours later. If the code ' +
          'is still valid and reusable, she exchanges it for tokens — the ' +
          'legitimate client already did the same exchange, but the AS ' +
          'happily issued a second token set.',
        impact:
          'Silent token theft with no failed-login signal at the client.',
      },
    ],
    mitigations: [
      {
        action:
          'Issue codes with single-use semantics (RFC 6749 §10.5: "MUST ' +
          'NOT be used more than once").',
        mitigates: ['code-replay'],
      },
      {
        action:
          'Bound the replay window with short TTLs (~10 minutes max).',
        mitigates: ['code-replay'],
      },
      {
        action:
          'On detected code replay, AS SHOULD revoke all tokens issued ' +
          'from that code and surface the event to monitoring.',
        mitigates: ['code-replay'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §4.1.2 (Authorization Response)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2',
      },
      {
        label: 'RFC 6749 §10.5 (Authorization Codes)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-10.5',
      },
    ],
  },

  code_verifier: {
    purpose:
      'A high-entropy random string the client generates and keeps locally. ' +
      'Sent only on the back-channel token exchange. The AS hashes it and ' +
      'compares to the `code_challenge` it received earlier — proving the ' +
      'same client instance started and finished the flow. RFC 9700 (BCP ' +
      '240, Jan 2025) makes PKCE mandatory for all clients, public and ' +
      'confidential.',
    attacks: [
      {
        id: 'mobile-intent-hijacking',
        name: 'Authorization code interception on mobile',
        scenario:
          'Alice\'s app registers a custom URL scheme (`myapp://callback`) ' +
          'for its redirect_uri. Mallory ships a malicious app on the same ' +
          'device that registers the same scheme. When the system resolves ' +
          'the redirect, Mallory\'s app receives the code first.',
        impact:
          'Without PKCE: Mallory calls /token with the stolen code and the ' +
          'public client_id, and gets Alice\'s tokens. With PKCE: she has ' +
          'the code but not the verifier — the exchange fails (DoS-only).',
      },
      {
        id: 'code-injection',
        name: 'Authorization Code Injection (confidential clients)',
        scenario:
          'Mallory captures her own valid code from the AS and injects it ' +
          'into Alice\'s legitimate session at a confidential client. ' +
          'Without PKCE, the client exchanges the injected code and links ' +
          'Mallory\'s identity into Alice\'s session. This is the reason ' +
          'RFC 9700 made PKCE universal: the attack works against ' +
          'confidential clients too, where client_secret alone is no ' +
          'defence because the secret is used at /token but is unrelated ' +
          'to who originated the code.',
        impact:
          'Account-takeover via identity confusion. With PKCE, the captured ' +
          'code is bound to a verifier the legit client holds — the attack ' +
          'reduces to denial-of-service (the code is burned without tokens ' +
          'being issued).',
      },
    ],
    mitigations: [
      {
        action:
          'Generate `code_verifier` as a cryptographically-random 43-128 ' +
          'character string from the unreserved set [A-Za-z0-9-._~] per ' +
          'authorization request.',
        mitigates: ['mobile-intent-hijacking', 'code-injection'],
      },
      {
        action:
          'Send the verifier only on the back-channel /token request — ' +
          'never on the front-channel /authorize redirect.',
        mitigates: ['mobile-intent-hijacking', 'code-injection'],
      },
      {
        action:
          'AS validates SHA-256(verifier) matches the stored ' +
          '`code_challenge` before issuing tokens.',
        mitigates: ['mobile-intent-hijacking', 'code-injection'],
      },
    ],
    references: [
      {
        label: 'RFC 7636 (PKCE)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7636',
      },
      {
        label: 'RFC 9700 §2.1.1 (PKCE mandatory)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1',
      },
      {
        label: 'RFC 9700 §4.5 (Code Injection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.5',
      },
      {
        label: 'OAuth 2.0 for Native Apps §8.1 (BCP 212)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8252#section-8.1',
      },
    ],
  },

  code_challenge: {
    purpose:
      'BASE64URL(SHA-256(code_verifier)) — sent on the front-channel ' +
      '/authorize request. The AS stores it bound to the issued code so the ' +
      'matching verifier can be checked at token exchange.',
    attacks: [
      {
        id: 'pkce-no-op',
        name: 'Unbound or unenforced challenge',
        scenario:
          'The AS does not persist the challenge bound to the issued code, ' +
          'or accepts /token requests without comparing the verifier hash ' +
          'against the stored challenge. PKCE collapses to a no-op: a ' +
          'stolen code is redeemable.',
        impact:
          'Public clients become token-theft targets (any captured code ' +
          'redeemable at /token); confidential clients become code-injection ' +
          'targets (no binding between code and originating client).',
      },
    ],
    mitigations: [
      {
        action:
          'AS MUST persist the challenge bound to the issued code and reject ' +
          '/token requests where SHA-256(verifier) does not match.',
        mitigates: ['pkce-no-op'],
      },
    ],
    references: [
      {
        label: 'RFC 7636 §4.2 (code_challenge)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7636#section-4.2',
      },
    ],
  },

  code_challenge_method: {
    purpose:
      'Tells the AS how the verifier maps to the challenge. `S256` means ' +
      'SHA-256; `plain` means the challenge IS the verifier (no hashing).',
    attacks: [
      {
        id: 'pkce-plain-downgrade',
        name: 'Plain method downgrade',
        scenario:
          'With `plain`, the front-channel redirect carries a value that ' +
          'is byte-identical to the secret needed at /token. Anyone who ' +
          'sees the redirect (browser history, referer header, network tap, ' +
          'browser extension, OS-level URL handler) trivially has the ' +
          'verifier.',
        impact:
          'Reduces PKCE to security theatre — captured front-channel value ' +
          'is replayable on /token alongside the stolen code.',
      },
    ],
    mitigations: [
      {
        action:
          'Use `S256` exclusively. RFC 7636 §4.2 specifies S256 as ' +
          'mandatory for clients that can compute SHA-256.',
        rationale:
          '`plain` exists only as a fallback for legacy environments that ' +
          'genuinely cannot compute SHA-256 — vanishingly rare in practice.',
        mitigates: ['pkce-plain-downgrade'],
      },
      {
        action: 'AS rejects clients that propose `plain` in production.',
        mitigates: ['pkce-plain-downgrade'],
      },
    ],
    references: [
      {
        label: 'RFC 7636 §4.2 (Method Selection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7636#section-4.2',
      },
    ],
  },

  scope: {
    purpose:
      'Space-delimited list of permissions the client is requesting. The ' +
      'user sees this on the consent screen; the AS enforces it on every ' +
      'token issued and every Resource Server validates it on every request. ' +
      'Scope is the principle-of-least-privilege control.',
    attacks: [
      {
        id: 'over-broad-scope-amplification',
        name: 'Over-broad scope amplification',
        scenario:
          'A client requests `admin:*` because it occasionally needs admin ' +
          'operations, even though 95% of its calls only need ' +
          '`read:profile`. A token leak (XSS, log exposure, stolen device) ' +
          'hands the attacker the full admin surface, not just the read ' +
          'permissions actually in active use at the time of compromise.',
        impact:
          'Blast radius of any token compromise is the union of all scopes ' +
          'ever granted, not the intersection of scopes currently in use.',
      },
    ],
    mitigations: [
      {
        action:
          'Request the narrowest scope that satisfies the immediate user ' +
          'action; step up to broader scopes only when needed for a ' +
          'specific operation.',
        mitigates: ['over-broad-scope-amplification'],
      },
      {
        action:
          'AS enforces the requested scope at token issuance; every RS ' +
          'validates scope on every request.',
        mitigates: ['over-broad-scope-amplification'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §3.3 (Access Token Scope)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-3.3',
      },
    ],
  },

  response_type: {
    purpose:
      'Selects which authorization grant flow to run. `code` runs the ' +
      'authorization code flow (token issued back-channel). `token` runs ' +
      'the legacy implicit flow (access token returned directly in the ' +
      'redirect URL fragment).',
    attacks: [
      {
        id: 'implicit-fragment-leak',
        name: 'Implicit-flow token leak via URL fragment',
        scenario:
          'The AS hands the access token to the browser as a URL fragment ' +
          '(`#access_token=…`). Fragments are not transmitted to servers in ' +
          'standard HTTP requests, but they ARE visible to anything that can ' +
          'read the address bar, browser history, or DOM — including ' +
          'third-party scripts on the redirect page, browser extensions, and ' +
          'any code that reads `window.location`. The client SPA loads an ' +
          'analytics or ad-tech tag on its callback page. The token sits in ' +
          '`window.location.hash` while the SPA parses it. A third-party ' +
          'script reads `location.hash` (or hooks `history.replaceState`) ' +
          'before the SPA can clear it, and exfiltrates the token. Browser ' +
          'history and Referer headers leaked to embedded images/iframes ' +
          'can also expose it. There is no back-channel exchange where the ' +
          'AS could detect or revoke this.',
        impact:
          'Direct token theft with no client authentication step to fail at.',
      },
    ],
    mitigations: [
      {
        action:
          'Always use `code` (with PKCE for public clients); never `token`.',
        mitigates: ['implicit-fragment-leak'],
      },
      {
        action:
          'OAuth 2.1 removes the implicit grant entirely; RFC 9700 §2.1.2 ' +
          'says implicit MUST NOT be used.',
        mitigates: ['implicit-fragment-leak'],
      },
    ],
    references: [
      {
        label: 'RFC 9700 §2.1.2 (Implicit Grant)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2',
      },
      {
        label: 'OAuth 2.1 §10.1 (Removal of the Implicit Grant)',
        href: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#name-removal-of-the-oauth-20-imp',
      },
    ],
  },

  client_secret: {
    purpose:
      'A long-term shared secret between a confidential client (server-' +
      'side app) and the AS. Proves the request came from the registered ' +
      'client, not just someone who knows the public client_id.',
    attacks: [
      {
        id: 'native-app-secret-extraction',
        name: 'Native-app secret extraction',
        scenario:
          'A team builds a mobile app, registers a confidential client ' +
          'because that\'s "more secure", and ships the client_secret in ' +
          'the binary. Mallory unzips the APK / IPA, runs `strings`, and ' +
          'pulls the secret in seconds. She can now mint tokens against ' +
          'any user\'s code or refresh token she observes. Same outcome ' +
          'when secrets land in JS bundles, public git repos, log files, ' +
          'or error reports.',
        impact:
          'Persistent credential leak — rotating the secret breaks every ' +
          'legitimate install of the app.',
      },
    ],
    mitigations: [
      {
        action:
          'Public clients (mobile, SPA) MUST register without a ' +
          'client_secret and use PKCE for client authentication.',
        rationale:
          'There is nowhere on a user-controlled device to store a secret ' +
          'such that the user (or an attacker on the same device) cannot ' +
          'read it — a "secret" in those contexts is not a secret.',
        mitigates: ['native-app-secret-extraction'],
      },
      {
        action:
          'Confidential `client_secret` only belongs in environments the ' +
          'end user cannot inspect: server, vault, managed service identity.',
        mitigates: ['native-app-secret-extraction'],
      },
      {
        action:
          'For confidential clients, prefer `private_key_jwt` or mTLS ' +
          'client authentication (per-request assertion, no long-term ' +
          'shared secret) where the AS supports it.',
        mitigates: ['native-app-secret-extraction'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §2.3.1 (Client Authentication)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1',
      },
      {
        label: 'OAuth 2.0 for Native Apps §8.5 (No client_secret in apps)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8252#section-8.5',
      },
    ],
  },

  refresh_token: {
    purpose:
      'Long-lived credential the client exchanges for fresh access tokens ' +
      'without re-prompting the user. Lives weeks to months; access tokens ' +
      'it mints live minutes to hours.',
    attacks: [
      {
        id: 'refresh-token-replay',
        name: 'Refresh token theft + replay',
        scenario:
          'Mallory exfiltrates Alice\'s refresh token via an XSS bug, a ' +
          'stolen backup, a malicious browser extension, or a leaked log. ' +
          'Without rotation, Mallory mints fresh access tokens on demand ' +
          'indefinitely; Alice sees nothing wrong because her own session ' +
          'also still works.',
        impact:
          'Silent persistent account takeover bounded only by the refresh ' +
          'token lifetime — outlives session revocation, password changes, ' +
          'and most "log everyone out" mechanisms.',
      },
    ],
    mitigations: [
      {
        action:
          'Refresh-token rotation: AS issues a new refresh token on each ' +
          'use and invalidates the prior one.',
        mitigates: ['refresh-token-replay'],
      },
      {
        action:
          'Reuse detection: when an already-rotated refresh token is ' +
          'presented again, AS revokes the entire token family — both ' +
          'parties get logged out and the breach surfaces immediately.',
        rationale:
          'Turns silent persistence into a noisy, self-detecting event.',
        mitigates: ['refresh-token-replay'],
      },
      {
        action:
          'Store refresh tokens server-side or in HttpOnly cookies; never ' +
          'in localStorage, front-end code, or non-HttpOnly cookies.',
        mitigates: ['refresh-token-replay'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §10.4 (Refresh Token Security)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-10.4',
      },
      {
        label: 'RFC 9700 §4.14 (Refresh Token Protection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.14',
      },
    ],
  },

  access_token: {
    purpose:
      'Bearer credential presented on every API call to a Resource Server. ' +
      '"Bearer" means whoever holds it can use it — there is no second ' +
      'factor binding it to a specific client at the RS.',
    attacks: [
      {
        id: 'referer-leakage',
        name: 'Token leakage via Referer header',
        scenario:
          'A client passes the token in a query string (`?access_token=…`) ' +
          'to "make CORS easier". The Resource Server page returns HTML ' +
          'containing third-party images. Each image fetch sends a ' +
          '`Referer: https://api.example.com/?access_token=…` header to ' +
          'the third-party host, where the token lands in CDN logs.',
        impact:
          'Third parties (analytics, ad-tech, CDN operators) end up with ' +
          'working credentials, often stored in logs reviewed months later.',
      },
      {
        id: 'localstorage-xss',
        name: 'XSS-driven token theft from localStorage',
        scenario:
          'The SPA stores the access token in `localStorage` for ' +
          'convenience. A momentary XSS — vulnerable third-party dependency, ' +
          'reflected payload in user-generated content, malicious browser ' +
          'extension — reads `localStorage.access_token` and exfiltrates it.',
        impact:
          'Full token theft. localStorage is accessible to every script ' +
          'running in the origin; XSS = token stolen.',
      },
      {
        id: 'log-capture',
        name: 'Token capture in server / proxy logs',
        scenario:
          'Tokens appear in URLs, request bodies logged at debug level, or ' +
          'error reports that include full request context. Operations ' +
          'staff or downstream log consumers (SIEM, analytics pipelines) ' +
          'have access months after the fact.',
        impact:
          'Working credentials sit in long-retention logs accessible to ' +
          'parties with no legitimate need.',
      },
      {
        id: 'cross-service-replay',
        name: 'Bearer replay across Resource Servers',
        scenario:
          'Mallory captures Alice\'s token from any leakage path. The token ' +
          'has no audience binding (or the RS doesn\'t check `aud`). ' +
          'Mallory replays it at a different Resource Server in the same ' +
          'ecosystem and gains access to a second service.',
        impact:
          'A leak from one service compromises every service the AS fronts.',
      },
    ],
    mitigations: [
      {
        action:
          'Send tokens ONLY in the `Authorization: Bearer` header (RFC ' +
          '6750 §2.1) — never in query strings, body fields, or fragments.',
        mitigates: ['referer-leakage', 'log-capture'],
      },
      {
        action:
          'Store tokens in memory or HttpOnly cookies; never in ' +
          'localStorage, sessionStorage, or non-HttpOnly cookies.',
        mitigates: ['localstorage-xss'],
      },
      {
        action:
          'Validate `aud` on every Resource Server so a token issued for ' +
          'service A is rejected at service B.',
        mitigates: ['cross-service-replay'],
      },
      {
        action:
          'Keep access-token lifetimes short (minutes, not hours).',
        rationale:
          'Bounds the window during which any leaked token is useful.',
        mitigates: [
          'referer-leakage',
          'localstorage-xss',
          'log-capture',
          'cross-service-replay',
        ],
      },
      {
        action:
          'Where the threat model warrants it, upgrade Bearer to a ' +
          'sender-constrained token: DPoP (RFC 9449) binds each token to a ' +
          'per-client key pair, so a stolen token is unusable without the ' +
          'matching private key.',
        rationale: 'Token theft becomes a non-event.',
        mitigates: [
          'referer-leakage',
          'localstorage-xss',
          'log-capture',
          'cross-service-replay',
        ],
      },
    ],
    references: [
      {
        label: 'RFC 6750 §2 (Bearer Token Usage)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6750#section-2',
      },
      {
        label: 'RFC 6750 §5 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6750#section-5',
      },
      {
        label: 'RFC 9700 §4.3 (Token Leakage)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.3',
      },
      {
        label: 'RFC 9449 (DPoP)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9449',
      },
    ],
  },

  aud: {
    purpose:
      'The "audience" claim names the Resource Server(s) a token is valid ' +
      'for. Encoded into JWT access tokens at issuance and surfaced on ' +
      'introspection. Every Resource Server MUST verify that its own ' +
      'identifier appears in `aud` before honouring the token.',
    attacks: [
      {
        id: 'confused-deputy',
        name: 'Confused deputy / cross-RS token reuse',
        scenario:
          'Mallory builds a low-privilege client (a "photo backup" tool) ' +
          'and gets users to authorise it. She receives access tokens from ' +
          'a shared AS that also fronts the "admin" API. Because no RS in ' +
          'the ecosystem checks `aud`, Mallory replays each user\'s token ' +
          'at the admin API — promoting a deliberately small permission ' +
          'set into full admin access.',
        impact:
          'Effective scope explosion: any client compromise on the AS ' +
          'becomes a compromise of every RS that trusts the AS.',
      },
      {
        id: 'audience-injection',
        name: 'Audience injection (RFC 9700 §4.10)',
        scenario:
          'In a deployment with multiple ASes, a malicious AS coerces ' +
          'clients into sending tokens with attacker-chosen audience ' +
          'values, redirecting tokens to RSes that should not have received ' +
          'them.',
        impact:
          'Tokens minted for one party arrive at unexpected RSes, where ' +
          'they may be honoured if audience policy is loose.',
      },
    ],
    mitigations: [
      {
        action:
          'AS populates `aud` from the client\'s declared `resource` (RFC ' +
          '8707) or registered audience — never from caller-supplied ' +
          'untrusted input.',
        mitigates: ['confused-deputy', 'audience-injection'],
      },
      {
        action:
          'Every Resource Server rejects tokens whose `aud` does not ' +
          'include its own identifier.',
        mitigates: ['confused-deputy', 'audience-injection'],
      },
    ],
    references: [
      {
        label: 'RFC 7519 §4.1.3 (aud claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3',
      },
      {
        label: 'RFC 8707 (Resource Indicators)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8707',
      },
      {
        label: 'RFC 9700 §4.10 (Audience Injection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.10',
      },
    ],
  },

  iss: {
    purpose:
      'The "issuer" identifier — names which Authorization Server minted ' +
      'the token (introspection response, RFC 7662) or returned the ' +
      'response (authorization response, RFC 9207). Lets the recipient ' +
      'cross-check that the response actually came from the AS it expected ' +
      'to be talking to.',
    attacks: [
      {
        id: 'as-mix-up',
        name: 'AS Mix-Up Attack',
        scenario:
          'The client trusts both `honest-as.example` and ' +
          '`evil-as.example` (perhaps because Mallory registered her AS ' +
          'under a legitimate-looking federation). Mallory starts a flow ' +
          'where Alice picks `honest-as` but Mallory swaps the discovery ' +
          'metadata so Alice\'s browser is redirected to `evil-as` instead. ' +
          'Alice authenticates at evil-as and the code comes back to the ' +
          'client. Without an issuer in the response, the client sends the ' +
          'code to honest-as\'s token endpoint together with honest-as\'s ' +
          'client_secret.',
        impact:
          'Code/token confusion across authorization servers — attacker ' +
          'captures codes or tokens minted by one AS by routing them ' +
          'through a confused client to another AS.',
      },
    ],
    mitigations: [
      {
        action:
          'AS includes `iss` in the authorization response (RFC 9207); ' +
          'client verifies it matches the expected issuer for the AS it ' +
          'intended to talk to.',
        mitigates: ['as-mix-up'],
      },
      {
        action:
          'Every RS that consumes introspection results validates `iss` ' +
          'against the trusted AS allowlist before honouring the token.',
        mitigates: ['as-mix-up'],
      },
    ],
    references: [
      {
        label: 'RFC 9207 (Authorization Server Issuer Identification)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9207',
      },
      {
        label: 'RFC 9700 §4.4 (Mix-Up Attacks)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.4',
      },
      {
        label: 'RFC 7662 §2.2 (Introspection Response)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7662#section-2.2',
      },
    ],
  },

  expires_in: {
    purpose:
      'Token lifetime in seconds, returned alongside the access token. Sets ' +
      'the window during which a stolen token is useful before the RS ' +
      'rejects it. The primary blast-radius control on token compromise.',
    attacks: [
      {
        id: 'persistent-xss-theft',
        name: 'Persistent post-leak token use',
        scenario:
          'A momentary XSS exposes Alice\'s access token to Mallory. With ' +
          'a 5-minute lifetime, Mallory has roughly one API window to do ' +
          'damage and Alice\'s next refresh issues fresh tokens. With a ' +
          '24-hour lifetime (still common in the wild), Mallory has a full ' +
          'day of access from a single capture, and revocation requires ' +
          'introspection on every RS call or a token-blocklist propagation ' +
          'most deployments don\'t have.',
        impact:
          'Blast radius of any token compromise scales linearly with ' +
          'lifetime.',
      },
    ],
    mitigations: [
      {
        action:
          'Set short access-token lifetimes (minutes, not hours); rely on ' +
          'refresh tokens for renewal. RFC 9700 §2.2.1.',
        mitigates: ['persistent-xss-theft'],
      },
      {
        action:
          'Implement a token-revocation path (introspection or token-' +
          'blocklist propagation) for incident response.',
        mitigates: ['persistent-xss-theft'],
      },
    ],
    references: [
      {
        label: 'RFC 6749 §5.1 (Token Response)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-5.1',
      },
      {
        label: 'RFC 9700 §2.2.1 (Access Token Privilege Restriction)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.2.1',
      },
    ],
  },

  token_type: {
    purpose:
      'Names the token usage profile. `Bearer` (RFC 6750) means "whoever ' +
      'presents this is treated as the holder" — no further proof required ' +
      'at the RS. `DPoP` (RFC 9449) is the sender-constrained alternative: ' +
      'each request must carry a fresh proof-of-possession signed by the ' +
      'client\'s private key.',
    attacks: [
      {
        id: 'bearer-replay-cross-context',
        name: 'Bearer replay across context',
        scenario:
          'Mallory captures Alice\'s Bearer token via any leakage path. ' +
          'She replays it from an entirely different IP, browser, country — ' +
          'the RS has no way to detect the swap because the token itself ' +
          'carries no link to the legitimate holder.',
        impact:
          'First attacker to capture the token is indistinguishable from ' +
          'the legitimate client at the RS.',
      },
    ],
    mitigations: [
      {
        action:
          'For high-value APIs (financial, healthcare, admin operations, ' +
          'FAPI 2.0), upgrade to DPoP (RFC 9449) — every API call must be ' +
          'signed with the client\'s private key.',
        rationale:
          'A stolen token is unusable without the matching private key.',
        mitigates: ['bearer-replay-cross-context'],
      },
      {
        action:
          'Or use mTLS-bound tokens (RFC 8705), where the token is bound ' +
          'to the client\'s TLS certificate.',
        mitigates: ['bearer-replay-cross-context'],
      },
      {
        action:
          'For lower-value APIs Bearer is acceptable provided lifetimes ' +
          'are short and `aud` is enforced — neither is a substitute for ' +
          'sender-constraint, but together they bound damage from a leak.',
        mitigates: ['bearer-replay-cross-context'],
      },
    ],
    references: [
      {
        label: 'RFC 6750 (Bearer)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6750',
      },
      {
        label: 'RFC 9449 (DPoP)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9449',
      },
      {
        label: 'RFC 8705 (mTLS-Bound Tokens)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8705',
      },
    ],
  },
}
