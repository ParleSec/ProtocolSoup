/**
 * OAuth 2.0 — Parameter Explainers
 *
 * Entries reused across OIDC, OID4VCI, OID4VP and other protocols that
 * build on OAuth2. Lookup is by parameter name in the central registry
 * (see `index.ts`). When a downstream protocol needs different
 * semantics for the same parameter name, add a per-protocol override
 * (e.g. `oidc:aud`) in that protocol's file.
 */

import type { ParameterExplainer } from './index'

export const OAUTH2_EXPLAINERS: Record<string, ParameterExplainer> = {
  state: {
    purpose:
      'An opaque, unguessable value the client generates per authorization request, ' +
      'persisted in the user session, and required to match on the redirect callback.',
    withoutIt:
      'The /authorize endpoint and the redirect_uri callback both still work. ' +
      'Functionally everything succeeds — the gap is that the client has no way to ' +
      'know whether *it* started the flow that produced the code it just received.',
    attack:
      'Account-linking CSRF. Mallory starts an authorization flow at the IdP under ' +
      'her own credentials and stops at the redirect, capturing a valid `code` tied ' +
      'to her IdP identity. She crafts a link or auto-submitting iframe pointing at ' +
      'the client\'s redirect_uri carrying that code, and tricks Alice (already ' +
      'signed in to the client) into loading it. The client exchanges Mallory\'s ' +
      'code, receives tokens for Mallory\'s IdP identity, and links that identity ' +
      'to Alice\'s session.',
    impact:
      'Persistent account takeover: Mallory now logs into Alice\'s account at the ' +
      'client by signing in with her own IdP credentials. Particularly dangerous ' +
      'for "add a social login" flows on accounts that already have local ' +
      'credentials — the link is silent and survives password resets. ' +
      '`state` remains the explicit CSRF check and is recommended as ' +
      'defence-in-depth even when other code-binding mitigations are in place.',
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
      'The exact URL the Authorization Server will return the user to after consent. ' +
      'Must be pre-registered with the client and matched byte-for-byte at runtime.',
    withoutIt:
      'If matching is loose (prefix match, wildcard subdomain, ignored query string, ' +
      'or "any path under the registered host"), the client still completes the flow ' +
      'normally for legitimate users — but the AS will also redirect to URLs the ' +
      'attacker controls under the same host.',
    attack:
      'Authorization code interception. The client registers ' +
      '`https://app.example.com/*` (or has an open-redirect endpoint at ' +
      '`/redirect?to=…`). Mallory crafts an authorize URL using Alice\'s client_id ' +
      'but a redirect_uri pointing at her own callback ' +
      '(`https://app.example.com/attacker-controlled/cb` or ' +
      '`https://app.example.com/redirect?to=https://mallory.example`). Alice clicks, ' +
      'authenticates, consents — and the AS hands the `code` to Mallory.',
    impact:
      'Mallory exchanges the stolen code for Alice\'s tokens (or, with PKCE, fails ' +
      'on the exchange but still gets a usable one-shot in non-PKCE deployments). ' +
      'Full impersonation of Alice at every Resource Server the tokens are valid for.',
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
      'A short-lived, single-use credential issued at the redirect. The client ' +
      'exchanges it server-to-server for tokens. The code itself grants nothing ' +
      'without the matching client authentication (and PKCE verifier, if used).',
    withoutIt:
      'If codes are long-lived or reusable, any place the code is logged or cached ' +
      'becomes a token-equivalent secret: browser history, referer headers, server ' +
      'access logs, proxy logs, error reporters that capture URLs.',
    attack:
      'Code replay. A code leaks via referer header to a third-party script loaded ' +
      'on the redirect_uri page, or via a server access log shared with an analytics ' +
      'pipeline. Mallory finds it hours later. If the code is still valid and ' +
      'reusable, she exchanges it for tokens — the legitimate client already did the ' +
      'same exchange, but the AS happily issued a second token set.',
    impact:
      'Silent token theft with no failed-login signal at the client. RFC 6749 ' +
      'mandates single-use ("MUST NOT be used more than once"); a properly ' +
      'implemented AS detects replay and revokes all tokens issued from that code.',
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
      'A high-entropy random string the client generates and keeps locally. Sent ' +
      'only on the back-channel token exchange. The AS hashes it and compares to ' +
      'the `code_challenge` it received earlier — proving the same client instance ' +
      'started and finished the flow. Per RFC 9700 (BCP 240, Jan 2025), PKCE is ' +
      'mandatory for *all* clients — public and confidential — not only the ' +
      'public-client scenario it was originally designed for.',
    withoutIt:
      'Two distinct attacks open up. First, on public clients (mobile, SPA) that ' +
      'cannot hold a client_secret: anyone who captures the code can redeem it. ' +
      'Second — and the reason RFC 9700 made PKCE universal — even confidential ' +
      'clients are vulnerable to *authorization code injection*: a code stolen ' +
      'from any victim can be injected into a legitimate session, with the ' +
      'attacker\'s identity getting linked to the victim\'s account.',
    attack:
      'Authorization code interception on mobile. Alice\'s app registers a custom ' +
      'URL scheme (`myapp://callback`) for its redirect_uri. Mallory ships a ' +
      'malicious app on the same device that registers the same scheme. When the ' +
      'system resolves the redirect, Mallory\'s app receives the code first. ' +
      'Without PKCE, she calls /token with the stolen code and the (public) ' +
      'client_id, and gets Alice\'s tokens. With PKCE, she has the code but not ' +
      'the verifier — the exchange fails. Variant on confidential clients: ' +
      'authorization code injection (Mallory injects her own captured code into ' +
      'Alice\'s session), where PKCE binds the code to the verifier the legit ' +
      'client holds and breaks the injection.',
    impact:
      'Without PKCE: full token theft on any public client where the redirect ' +
      'channel is not exclusive; account-takeover via code injection on ' +
      'confidential clients. With PKCE: both attacks reduced to a ' +
      'denial-of-service (the captured code is burned but no tokens issued).',
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
      'BASE64URL(SHA-256(code_verifier)) — sent on the front-channel /authorize ' +
      'request. The AS stores it bound to the issued code so the matching verifier ' +
      'can be checked at token exchange.',
    withoutIt:
      'Without a challenge bound to the code, the AS has nothing to compare the ' +
      'verifier against — PKCE collapses to a no-op even if the client sends a ' +
      'verifier on /token.',
    attack:
      'An attacker who intercepts the front-channel redirect can read the ' +
      'challenge but cannot reverse SHA-256 to recover the verifier — the ' +
      'point of the hash. The attack opens up only if the AS fails to bind ' +
      'the stored challenge to the issued code (so a stolen code can be ' +
      'redeemed at /token without supplying a matching verifier) or accepts ' +
      'a verifier whose hash does not match the stored challenge.',
    impact:
      'A missing or unenforced challenge eliminates PKCE\'s protection ' +
      'against code interception — public clients become token-theft ' +
      'targets, confidential clients become code-injection targets.',
    references: [
      {
        label: 'RFC 7636 §4.2 (code_challenge)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7636#section-4.2',
      },
    ],
  },

  code_challenge_method: {
    purpose:
      'Tells the AS how the verifier maps to the challenge. `S256` means SHA-256; ' +
      '`plain` means the challenge IS the verifier (no hashing).',
    withoutIt:
      'If the method is `plain`, the front-channel redirect carries a value that ' +
      'is byte-identical to the secret needed at /token. Anyone who sees the ' +
      'redirect (browser history, referer, network tap on a non-TLS hop, malicious ' +
      'browser extension, OS-level URL handler) trivially has the verifier.',
    attack:
      'Mallory observes Alice\'s front-channel redirect — say, via a referer ' +
      'header leaking to a third-party analytics script on the consent page. With ' +
      '`S256`, she has SHA-256(verifier) and cannot invert it. With `plain`, the ' +
      'value she captured IS the verifier; she replays it on /token alongside the ' +
      'stolen code and gets tokens.',
    impact:
      'Reduces PKCE to security theatre. RFC 7636 §4.2 specifies `S256` as ' +
      'mandatory for clients that can compute SHA-256 — `plain` exists only as a ' +
      'fallback for environments that genuinely cannot.',
    references: [
      {
        label: 'RFC 7636 §4.2 (Method Selection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7636#section-4.2',
      },
    ],
  },

  scope: {
    purpose:
      'Space-delimited list of permissions the client is requesting. The user ' +
      'sees this on the consent screen; the AS enforces it on every token issued ' +
      'and every Resource Server validates it on every request.',
    withoutIt:
      'Scope is the principle-of-least-privilege control. Without careful scope ' +
      'design, a single token compromise grants every permission the client was ' +
      'ever pre-authorised for.',
    attack:
      'Over-broad scope amplification. A client requests `admin:*` because it ' +
      'occasionally needs admin operations, even though 95% of its calls only ' +
      'need `read:profile`. A token leak (XSS, log exposure, stolen device) hands ' +
      'the attacker the full admin surface, not just the read permissions actually ' +
      'in active use at the time of compromise.',
    impact:
      'Blast radius of any token compromise is the union of all scopes ever ' +
      'granted, not the intersection of scopes currently in use. Rule of thumb: ' +
      'request the narrowest scope that satisfies the immediate user action; ' +
      'step up only when needed.',
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
      'authorization code flow (token issued back-channel). `token` runs the ' +
      'legacy implicit flow (access token returned directly in the redirect URL ' +
      'fragment).',
    withoutIt:
      'Choosing `token` (implicit) is the gap. The AS hands the access token to ' +
      'the browser as a URL fragment (`#access_token=…`). Fragments are not sent ' +
      'over the wire to servers, but they ARE visible to anything that can read ' +
      'the address bar, browser history, or DOM — including third-party scripts ' +
      'on the redirect page, browser extensions, and any code that reads ' +
      '`window.location`.',
    attack:
      'Implicit-flow token leak. The client SPA loads an analytics or ad-tech ' +
      'tag on its callback page. The token sits in `window.location.hash` while ' +
      'the SPA parses it. A third-party script reads `location.hash` (or hooks ' +
      '`history.replaceState`) before the SPA can clear it, and exfiltrates ' +
      'the token. Browser history and HTTP referer headers leaked to embedded ' +
      'images/iframes can also expose it. There is no back-channel exchange where ' +
      'the AS could detect or revoke this.',
    impact:
      'Direct token theft with no client authentication step to fail at. ' +
      'OAuth 2.0 Security BCP §2.1.2 says implicit MUST NOT be used; OAuth 2.1 ' +
      'removes it entirely. Always use `code` (with PKCE for public clients).',
    references: [
      {
        label: 'RFC 9700 §2.1.2 (Implicit Grant)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.2',
      },
      {
        label: 'OAuth 2.1 §2.1.2 (Removed Grant Types)',
        href: 'https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1#section-2.1.2',
      },
    ],
  },

  client_secret: {
    purpose:
      'A long-term shared secret between a confidential client (server-side ' +
      'app) and the AS. Proves the request came from the registered client, not ' +
      'just someone who knows the public client_id.',
    withoutIt:
      'For confidential clients: anyone with a stolen `code` (or refresh token) ' +
      'and the public `client_id` can redeem it at /token. The single thing ' +
      'binding the token issuance to the legitimate client is gone. For public ' +
      'clients (mobile, SPA): a client_secret cannot meaningfully exist — there ' +
      'is no place on the device to store it that the user (or an attacker on ' +
      'the same device) cannot read.',
    attack:
      'The native-app trap. A team builds a mobile app, registers a confidential ' +
      'client because that\'s "more secure", and ships the client_secret in the ' +
      'binary. Mallory unzips the APK / IPA, runs `strings`, and pulls the ' +
      'secret in seconds. She can now mint tokens against any user\'s code or ' +
      'refresh token she observes. Same outcome when secrets land in JS bundles, ' +
      'public git repos, log files, or error reports.',
    impact:
      'Persistent credential leak — rotating the secret breaks every legitimate ' +
      'install of the app. The fix is to register as a public client and use ' +
      'PKCE instead of a secret. Confidential client_secret only belongs in ' +
      'environments the end user cannot inspect: a server, a vault, a managed ' +
      'service identity.',
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
      'without re-prompting the user. Lives weeks to months; access tokens it ' +
      'mints live minutes to hours.',
    withoutIt:
      'A leaked refresh token without rotation IS persistent access. It ' +
      'outlives session revocation, password changes, and most forms of ' +
      '"log everyone out" because nothing in the access-token validation path ' +
      'sees it. The AS issues a new access token to whoever presents it, ' +
      'forever, until someone notices.',
    attack:
      'Refresh token theft + replay. Mallory exfiltrates Alice\'s refresh ' +
      'token via an XSS bug, a stolen backup, a malicious browser extension, ' +
      'or a leaked log. Without rotation: Mallory mints fresh access tokens ' +
      'on demand, indefinitely; Alice sees nothing wrong because her own ' +
      'session also still works. With rotation + reuse detection: the moment ' +
      'either party uses an already-rotated refresh token, the AS revokes the ' +
      'whole token family — both Alice and Mallory get logged out, and the ' +
      'breach surfaces immediately.',
    impact:
      'Without rotation: silent persistent account takeover bounded only by ' +
      'the refresh token lifetime. With rotation: theft becomes a noisy, ' +
      'self-detecting event. Storage rules apply at every layer — never in ' +
      'localStorage, never in front-end code, never in non-HttpOnly cookies.',
    references: [
      {
        label: 'RFC 6749 §10.4 (Refresh Token Security)',
        href: 'https://datatracker.ietf.org/doc/html/rfc6749#section-10.4',
      },
      {
        label: 'RFC 9700 §4.13 (Refresh Token Protection)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9700#section-4.13',
      },
    ],
  },

  access_token: {
    purpose:
      'Bearer credential presented on every API call to a Resource Server. ' +
      '"Bearer" means whoever holds it can use it — there is no second factor ' +
      'binding it to a specific client at the RS.',
    withoutIt:
      'The risks are not about *omitting* the token but about how it travels ' +
      'and where it rests. Any place a Bearer token lands by accident is a ' +
      'token-equivalent secret: query strings (server logs, referer headers, ' +
      'browser history, analytics), localStorage (any XSS reads it), non-HTTPS ' +
      'hops (network taps), error reporters that capture URLs.',
    attack:
      'Token leakage via referer + URL. A client passes the token in a query ' +
      'string (`?access_token=…`) to "make CORS easier". The Resource Server ' +
      'page returns HTML containing third-party images. Each image fetch sends ' +
      'a `Referer: https://api.example.com/?access_token=…` header to the ' +
      'third-party host. Their CDN logs include full URLs. A junior engineer ' +
      'on that team, six months later, opens the log archive for an unrelated ' +
      'investigation — and now has working credentials for thousands of users.',
    impact:
      'Token theft with no audit signal at the issuer. Mitigations: send ' +
      'tokens ONLY in the `Authorization` header (RFC 6750 §2.1), keep ' +
      'lifetimes short (see `expires_in`), validate `aud` on the RS so a token ' +
      'for one service is rejected at another. Where the threat model warrants ' +
      'it, upgrade Bearer to a sender-constrained token: DPoP (RFC 9449) binds ' +
      'each token to a per-client key pair, so a stolen token is unusable ' +
      'without the matching private key — token theft becomes a non-event.',
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
      'The "audience" claim names the Resource Server(s) a token is valid for. ' +
      'Encoded into JWT access tokens at issuance and surfaced on introspection. ' +
      'Every Resource Server MUST verify that its own identifier appears in `aud` ' +
      'before honouring the token.',
    withoutIt:
      'If the RS skips the `aud` check (or accepts any non-empty value), every ' +
      'token issued by that AS is interchangeable across every RS that trusts it. ' +
      'A token meant for the read-only "Photos API" works at the high-privilege ' +
      '"Documents API" too.',
    attack:
      'Confused deputy / token reuse. Mallory builds a low-privilege client (say, ' +
      'a "photo backup" tool) and gets users to authorise it. She receives ' +
      'access tokens from a shared AS that also fronts the "admin" API. Because ' +
      'no RS in the ecosystem checks `aud`, Mallory replays each user\'s token at ' +
      'the admin API — promoting a deliberately small permission set into full ' +
      'admin access. Audience injection (RFC 9700 §4.10): a malicious AS in a ' +
      'multi-AS deployment can also coerce clients into sending tokens to the ' +
      'wrong audience.',
    impact:
      'Effective scope explosion: any client compromise on the AS becomes a ' +
      'compromise of every RS that trusts the AS. The fix is two-sided — the AS ' +
      'must populate `aud` based on the client\'s declared `resource` (RFC 8707) ' +
      'or registered audience, and every RS must reject tokens whose `aud` does ' +
      'not include its own identifier.',
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
      'The "issuer" identifier — names which Authorization Server minted the ' +
      'token (introspection response, RFC 7662) or returned the response ' +
      '(authorization response, RFC 9207). Lets the recipient cross-check that ' +
      'the response actually came from the AS it expected to be talking to.',
    withoutIt:
      'A client that integrates with multiple ASes (typical for federated ' +
      'logins, B2B SaaS, multi-tenant identity) cannot tell from the redirect ' +
      'alone which AS produced a given `code`. The legacy authorization ' +
      'response carries no issuer identification at all.',
    attack:
      'AS Mix-up Attack. The client trusts both `honest-as.example` and ' +
      '`evil-as.example` (perhaps because Mallory registered her AS under a ' +
      'legitimate-looking federation). Mallory starts a flow where Alice picks ' +
      '`honest-as` but Mallory swaps the discovery metadata so Alice\'s browser ' +
      'is redirected to `evil-as` instead. Alice authenticates at evil-as ' +
      '(maybe with shared SSO) and the code comes back to the client. The ' +
      'client, with no issuer in the response, sends the code to honest-as\'s ' +
      'token endpoint together with honest-as\'s client_secret. RFC 9207\'s ' +
      '`iss` parameter on the authorization response is the explicit ' +
      'countermeasure — the client checks that the issuer it expected matches ' +
      'the issuer that responded.',
    impact:
      'In multi-AS deployments without `iss`: code/token confusion across ' +
      'authorization servers — the attacker captures codes or tokens minted by ' +
      'one AS by routing them through a confused client to another AS. Every ' +
      'RS that consumes introspection results MUST also validate `iss` so that ' +
      'tokens from a different (possibly attacker-controlled) AS in the same ' +
      'ecosystem are rejected.',
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
      'Token lifetime in seconds, returned alongside the access token. Sets the ' +
      'window during which a stolen token is useful before the RS rejects it.',
    withoutIt:
      'The risk is not omitting the field but choosing a long lifetime "for ' +
      'convenience". Hours-to-days lifetimes turn a single XSS, log leak, or ' +
      'stolen device into a long-running compromise — every minute of validity ' +
      'is a minute the attacker keeps working access while the legitimate user ' +
      'sees nothing wrong.',
    attack:
      'Persistent XSS-driven theft. A momentary XSS exposes Alice\'s access ' +
      'token to Mallory. With a 5-minute lifetime, Mallory has roughly one API ' +
      'window to do damage and Alice\'s next refresh issues fresh tokens. With ' +
      'a 24-hour lifetime (still common in the wild), Mallory has a full day ' +
      'of access from a single capture, and revocation requires either ' +
      'introspection on every RS call or a token-blocklist propagation that ' +
      'most deployments don\'t have.',
    impact:
      'Blast radius scales linearly with lifetime. RFC 9700 recommends short ' +
      '(minutes) access tokens paired with rotated refresh tokens. The ' +
      'short-lived access token is the primary blast-radius control even when ' +
      'every other defence holds.',
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
      'presents this is treated as the holder" — no further proof required at ' +
      'the RS. `DPoP` (RFC 9449) is the sender-constrained alternative: each ' +
      'request must carry a fresh proof-of-possession signed by the client\'s ' +
      'private key.',
    withoutIt:
      'Bearer tokens are the default and the easiest to integrate, but they ' +
      'have no link to the legitimate holder. The first attacker to capture ' +
      'one (XSS, log, malicious extension, MITM on a downgraded link) is ' +
      'indistinguishable from the legitimate client at the RS.',
    attack:
      'Token replay across context. Mallory captures Alice\'s Bearer token ' +
      'via any leakage path (see `access_token`). She replays it from an ' +
      'entirely different IP, browser, country — the RS has no way to detect ' +
      'the swap. With DPoP, every API call must be signed with the private ' +
      'key Alice\'s client holds; Mallory has the token but not the key, so ' +
      'replay fails on the first request.',
    impact:
      'For high-value APIs (financial, healthcare, admin operations, FAPI 2.0 ' +
      'profile), Bearer is increasingly inadequate. Move to DPoP or mTLS-bound ' +
      'tokens (RFC 8705) where the cost of a single token theft is high. For ' +
      'lower-value APIs Bearer is acceptable provided the lifetime is short ' +
      'and `aud` is enforced.',
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
