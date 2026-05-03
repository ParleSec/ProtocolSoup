/**
 * Shared Signals Framework (SSF) — Parameter Explainers
 *
 * Out-of-band security event delivery between identity systems. Built on
 * Security Event Tokens (SET, RFC 8417); profiles include CAEP
 * (Continuous Access Evaluation) and RISC (Risk and Incident Sharing).
 * Transmitters publish events; Receivers consume and act on them
 * (terminate sessions, revoke tokens, force re-auth, etc.).
 *
 * Distinct threat model from authentication protocols: SSF events
 * trigger destructive actions (logouts, revocations) — false signals
 * are denial-of-service primitives; missed signals are persistent-
 * compromise primitives.
 */

import type { ParameterExplainer } from './index'

export const SSF_EXPLAINERS: Record<string, ParameterExplainer> = {
  SET: {
    purpose:
      'Security Event Token (RFC 8417) — a signed JWT that conveys a ' +
      'security-relevant event from a Transmitter to one or more ' +
      'Receivers. Wire format: `application/secevent+jwt`. Carries ' +
      'standard JWT claims (`iss`, `aud`, `iat`, `jti`) plus the ' +
      'SET-specific `events` claim, which is what makes a JWT a SET ' +
      'rather than an ID Token, access token, or any other JWT type.',
    withoutIt:
      'The same JWT-validation pitfalls as `id_token`: alg=none, ' +
      'algorithm confusion (RS256→HS256), fail-open on unknown alg, ' +
      'skipped claim validation. SETs additionally require the ' +
      '`events` claim presence as a token-type discriminator (RFC ' +
      '8417 §2.2) — and missing that check enables token-type ' +
      'confusion attacks unique to SSF.',
    attack:
      'Token-type confusion. Mallory captures Alice\'s legitimate ID ' +
      'Token (via any JWT-leakage path — referer, log, browser ' +
      'extension). Without `events`-claim validation on the SSF ' +
      'Receiver, Mallory POSTs the captured ID Token to the receiver\'s ' +
      'push endpoint. The token is signed by the same OP/Transmitter, ' +
      '`iss`/`aud`/`iat` all valid — receiver accepts it as a SET. ' +
      'Depending on what code path runs without an `events` claim, this ' +
      'either crashes (best case) or silently triggers default ' +
      'behaviour (worst case — forced logout for the subject named in ' +
      '`sub`). Same hazard for SET-vs-ID-Token in the other direction: ' +
      'a SET replayed at an OIDC RP\'s ID Token consumer.',
    impact:
      'Cross-token-type confusion enabling either auth bypass (SET ' +
      'accepted as ID Token) or DoS-via-forced-logout (ID Token ' +
      'accepted as SET). Defences: (1) RFC 8417 §2.2 — Receiver MUST ' +
      'reject any token without an `events` claim; (2) verify the SET\'s ' +
      '`typ` header is `secevent+jwt`; (3) standard JWT validation ' +
      '(alg pinning, iss/aud check, signature) applies as for any ' +
      'JWT — and is just as easy to get wrong here as in OIDC.',
    references: [
      {
        label: 'RFC 8417 (Security Event Token)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417',
      },
      {
        label: 'RFC 8417 §2.2 (events claim — token-type discriminator)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-2.2',
      },
    ],
  },

  events: {
    purpose:
      'Mandatory claim on a SET. Object whose keys are event-type URIs ' +
      '(e.g. `https://schemas.openid.net/secevent/caep/event-type/' +
      'session-revoked`) and whose values are event-specific payloads. ' +
      'Doubles as the *token-type discriminator* — the absence of ' +
      '`events` means "this JWT is not a SET, do not process it as one".',
    withoutIt:
      'Without strict `events` validation, two failure classes: (1) ' +
      'a non-SET JWT (ID Token, access token) gets processed as a SET ' +
      'because nothing rejected the missing claim; (2) processing event ' +
      'types the receiver doesn\'t actually support — receivers that ' +
      'naively iterate `events` keys and call generic handlers may ' +
      'execute logic the implementer never intended for unrecognized ' +
      'event types.',
    attack:
      'Unknown-event-type abuse. Mallory submits a SET with ' +
      '`events: { "https://attacker.example/custom-event": {...} }`. A ' +
      'receiver implementing "process all events in the events claim" ' +
      'with a generic dispatcher may invoke per-event hooks, log the ' +
      'unknown event with sensitive context, or, in the worst case, ' +
      'allow the payload to flow into downstream processing where its ' +
      'unexpected shape causes harm (parser confusion, type-coercion ' +
      'bugs). Variant: receivers that accept events from event-type ' +
      'URIs they technically know about but for which they have no ' +
      'meaningful local action — silently no-oping is fine, ' +
      'silently logging the (potentially attacker-crafted) payload is ' +
      'an information-leak surface.',
    impact:
      'Event-type allowlist bypass + payload-driven side effects. ' +
      'Defences: (1) explicit allowlist of event-type URIs the receiver ' +
      'understands; (2) reject SETs containing any unrecognised event ' +
      'type (don\'t silently ignore — the spec allows ignoring, but ' +
      'rejecting catches misconfigurations); (3) per-event-type schema ' +
      'validation on the payload before processing.',
    references: [
      {
        label: 'RFC 8417 §2.2 (events claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-2.2',
      },
    ],
  },

  event_type: {
    purpose:
      'A URI naming a specific kind of event: ' +
      '`.../caep/event-type/session-revoked`, ' +
      '`.../caep/event-type/credential-change`, ' +
      '`.../risc/event-type/account-disabled`, ' +
      '`.../risc/event-type/credential-compromise`. Used as a key in ' +
      'the `events` claim. Drives receiver-side dispatch — different ' +
      'event types trigger different actions.',
    withoutIt:
      'The receiver\'s response to an event is *exactly* as scoped as ' +
      'its event-type allowlist. A receiver that processes ' +
      '`account-disabled` will block all access for the subject; one ' +
      'that processes `credential-compromise` will additionally force ' +
      'password reset. Mishandled or unrecognised event types either ' +
      'fail open (no response) or fail confused (wrong response).',
    attack:
      'Event-type spoofing. Mallory injects a SET (via any path that ' +
      'lets her reach the receiver — see `SET` and `events` entries) ' +
      'with `event_type=account-disabled` for an executive\'s subject ' +
      'identifier. The receiver, treating the event as authoritative, ' +
      'terminates the executive\'s sessions and revokes their tokens — ' +
      'denial of service via false signal. RISC events (`account-' +
      'disabled`, `credential-compromise`) are particularly dangerous ' +
      'because their *intended* response is destructive; misuse turns ' +
      'them into weaponised disruption.',
    impact:
      'False-signal DoS. Defences: (1) authenticate every SET against ' +
      'a known Transmitter via signature on the trust-domain JWKS; (2) ' +
      'restrict which Transmitters can publish each event type — not ' +
      'every Transmitter should be authoritative for ' +
      '`account-disabled`; (3) human-in-the-loop / staged enforcement ' +
      'for high-impact RISC events when possible (alert-then-enforce ' +
      'with a small delay window for the security team to override).',
    references: [
      {
        label: 'OpenID CAEP Spec',
        href: 'https://openid.net/specs/openid-caep-1_0-ID2.html',
      },
      {
        label: 'OpenID RISC Event Types',
        href: 'https://openid.net/specs/openid-risc-profile-1_0-ID1.html',
      },
    ],
  },

  jti: {
    purpose:
      'JWT ID claim — a Transmitter-assigned unique identifier for ' +
      'this specific SET. Receivers cache `jti` values to detect ' +
      'replay; pollers also use `jti` as the acknowledgment key.',
    withoutIt:
      'Without `jti` replay tracking, the same SET can be processed ' +
      'multiple times. For idempotent event types this is harmless; ' +
      'for events that trigger one-shot side effects it is a ' +
      'denial-of-service primitive (force a user through repeated ' +
      'forced-logouts) or a state-corruption primitive (downstream ' +
      'systems that count events).',
    attack:
      'SET replay against a receiver without `jti` caching. Mallory ' +
      'captures one of Alice\'s legitimate `session-revoked` SETs ' +
      'from a transmitter\'s push delivery (network tap on a non-TLS ' +
      'internal hop, leaked log, malicious receiver-side load balancer). ' +
      'She replays it to the same receiver some time later. Without jti ' +
      'caching, the receiver processes the event again — and because ' +
      'session-revoked is destructive, this terminates Alice\'s ' +
      '*current* session even though the original event was about a ' +
      'session she\'d already logged out of. Mallory can replay this ' +
      'on any cadence she likes to prevent Alice from ever staying ' +
      'logged in.',
    impact:
      'DoS via replay-driven destructive action. Defences: (1) cache ' +
      '`jti` for the duration of the validity window; (2) reject ' +
      'duplicate `jti` from the same Transmitter; (3) align cache TTL ' +
      'with the SET\'s implied validity (typically 5-15 minutes for ' +
      'real-time events).',
    references: [
      {
        label: 'RFC 8417 §2.2 (jti)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-2.2',
      },
      {
        label: 'RFC 7519 §4.1.7 (jti claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7',
      },
    ],
  },

  delivery: {
    purpose:
      'How SETs flow from Transmitter to Receiver. Two profiles: ' +
      '**Push** (RFC 8935) — Transmitter POSTs each SET to the ' +
      'Receiver\'s endpoint as events occur; **Poll** (RFC 8936) — ' +
      'Receiver POSTs to fetch any pending SETs, with optional ' +
      'long-polling. Choice affects which side bears the resource cost ' +
      'and which side is on the attack surface.',
    withoutIt:
      'Each delivery method has its own DoS profile: Push exposes the ' +
      'Receiver\'s endpoint to whoever can reach it (flood the receiver ' +
      'with SETs to force resource exhaustion); Poll exposes the ' +
      'Transmitter\'s endpoint to long-poll connection holding (open ' +
      'thousands of long-polls to consume Transmitter sockets and ' +
      'memory).',
    attack:
      'Push-endpoint flooding. Mallory either compromises one ' +
      'Transmitter in the trust mesh or finds a Receiver whose push ' +
      'endpoint has lax authentication. She POSTs a high volume of ' +
      'SETs (each individually valid-looking) to consume the receiver\'s ' +
      'parsing and verification capacity — every SET requires a JWS ' +
      'verification, a jti cache lookup, and event-handler dispatch. ' +
      'The receiver either crashes or starts rejecting traffic, ' +
      'including legitimate events that the receiver actually needed ' +
      '(e.g. real `account-disabled` events for compromised accounts ' +
      'now stuck in the queue). Variant for poll: hold thousands of ' +
      'long-poll connections to exhaust the Transmitter\'s socket / ' +
      'goroutine / thread pool.',
    impact:
      'DoS plus availability impact on legitimate SET delivery — and ' +
      'the events being missed are precisely the ones the receiver ' +
      'most needs to act on. Defences: (1) authenticate every push ' +
      'request — receiver MUST validate the Transmitter\'s identity ' +
      '(typically Bearer token bound to the stream); (2) rate-limit ' +
      'per-Transmitter; (3) for poll, cap concurrent long-poll ' +
      'connections per Receiver and reject excess; (4) timeouts and ' +
      'circuit breakers on push verification — don\'t let one bad ' +
      'transmitter exhaust the pool.',
    references: [
      {
        label: 'RFC 8935 (SET Push Delivery)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8935',
      },
      {
        label: 'RFC 8936 (SET Poll Delivery)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8936',
      },
    ],
  },

  stream_id: {
    purpose:
      'Identifier for an SSF stream — the relationship between one ' +
      'Transmitter and one Receiver, including its delivery method, ' +
      'subscribed event types, and authentication credentials. Created ' +
      'via POST to the configuration_endpoint; managed via stream-' +
      'control endpoints.',
    withoutIt:
      'Streams are the access-control unit for SSF — who can subscribe ' +
      'to events for which subjects, with which event types. Stream ' +
      'creation that lacks proper authorization lets attackers create ' +
      'their own streams subscribing to events for arbitrary subjects.',
    attack:
      'Unauthorized stream creation. The Transmitter\'s configuration ' +
      'endpoint accepts stream-creation requests with weak ' +
      'authentication (no token, shared bearer token leaked widely). ' +
      'Mallory POSTs a stream-creation request asking to receive ' +
      '`account-disabled` events for Alice\'s subject identifier. The ' +
      'Transmitter creates the stream; from this point on, every ' +
      '`account-disabled` event for Alice is also delivered to ' +
      'Mallory\'s receiver. Mallory now has real-time intelligence on ' +
      'when Alice\'s account is disabled — useful for timing attacks, ' +
      'social engineering ("we noticed your account was just disabled, ' +
      'click here to reactivate"), or simply confirming when ' +
      'compromise has been detected.',
    impact:
      'Information disclosure of security-event signals to attackers. ' +
      'Defences: (1) protect the stream-management endpoint with ' +
      'strong authentication (OAuth2 client credentials, mTLS); (2) ' +
      'authorize stream-creation by the Receiver\'s legitimate ' +
      'identity, not just possession of a token; (3) limit which ' +
      'subjects each Receiver may subscribe to (a Receiver representing ' +
      'AppA shouldn\'t subscribe to events for users it doesn\'t ' +
      'manage); (4) audit stream creations.',
    references: [
      {
        label: 'OpenID SSF §7 (Stream Management)',
        href: 'https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html',
      },
    ],
  },

  subject: {
    purpose:
      'Identifies the entity (user, device, session, application) the ' +
      'SET is about. Multiple Subject Identifier formats per RFC 9493: ' +
      '`email`, `iss_sub`, `opaque`, `phone_number`, `account`, ' +
      '`did`, `uri`, `aliases`. The Receiver maps the subject to its ' +
      'local user record before taking action.',
    withoutIt:
      'Subject identifier mapping is the choke point where the ' +
      'Transmitter\'s view of "who" meets the Receiver\'s view of ' +
      '"who". Mismatched mappings either fail safe (event ignored) or ' +
      'fail dangerously (event applied to the wrong user).',
    attack:
      'Subject confusion → wrong-user enforcement. The Transmitter ' +
      'identifies users by `email`. The Receiver matches incoming ' +
      'events by email too. Mallory has a colliding email — same ' +
      'address at a different IdP, or a legitimately-owned email that ' +
      'happens to match Alice\'s historical address (recycled ' +
      'corporate domain). A `credential-compromise` event for Mallory ' +
      'arrives at the Receiver, which keys on email and applies the ' +
      'compromise response to *Alice* (forced logout, password reset, ' +
      'token revocation). False-positive enforcement against the wrong ' +
      'subject. Variant: `iss_sub` (issuer + subject) format provides ' +
      'tenant scoping but only if the Receiver implements the ' +
      'composite-key match correctly.',
    impact:
      'Cross-user effect of legitimate events — the SET-delivery ' +
      'analogue of the OIDC nOAuth attack (matching users by email ' +
      'instead of stable identifier). Defences: (1) prefer `iss_sub` ' +
      '(issuer + subject pair) Subject Identifier format over mutable ' +
      'claims like email; (2) explicit mapping tables, not best-effort ' +
      'heuristics; (3) reject events whose subject doesn\'t map to a ' +
      'known local user (don\'t silently no-op — log and alert).',
    references: [
      {
        label: 'RFC 9493 (Subject Identifiers for SETs)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9493',
      },
    ],
  },

  initiating_entity: {
    purpose:
      'CAEP claim identifying who/what triggered the event: `admin`, ' +
      '`user`, `policy`, `system`. Drives receiver-side response ' +
      'differentiation — admin-initiated revocation may warrant ' +
      'different handling than policy-driven revocation.',
    withoutIt:
      'Without `initiating_entity`, the receiver treats every event ' +
      'identically — losing the ability to differentiate "user clicked ' +
      'sign-out" (benign) from "security system detected anomaly" ' +
      '(potentially attacker-driven false signal).',
    attack:
      'Audit-trail confusion. An attacker who can submit SETs may set ' +
      '`initiating_entity=user` to make malicious revocations appear ' +
      'as if the user requested them — masking attacker activity in ' +
      'the audit logs. Conversely, missing `initiating_entity` gives ' +
      'the receiver no way to weight responses (an admin-initiated ' +
      'session-revoked might warrant a security alert; a user-' +
      'initiated one is routine).',
    impact:
      'Audit and response-policy differentiation lost. Defences: (1) ' +
      'include `initiating_entity` on every CAEP event the Transmitter ' +
      'emits; (2) Receiver logs `initiating_entity` as part of every ' +
      'event-driven action; (3) consider differentiated response ' +
      'policies (rate-limit `policy`-initiated revocations more ' +
      'aggressively than `user`-initiated, since attacker-injected ' +
      'false signals will most often claim `policy`).',
    references: [
      {
        label: 'OpenID CAEP §2 (Common Event Properties)',
        href: 'https://openid.net/specs/openid-caep-1_0-ID2.html',
      },
    ],
  },

  reason: {
    purpose:
      'RISC `account-disabled` event property naming the high-level ' +
      'reason: `hijacking` (account-takeover detected) or ' +
      '`bulk-account` (mass-compromise scenario). Lets Receivers ' +
      'differentiate response intensity.',
    withoutIt:
      'Without `reason`, every account-disabled event triggers the ' +
      'same response. With `reason`, the Receiver can distinguish ' +
      '"individual account compromised, contain it" from "bulk event ' +
      'affecting many accounts, also alert SOC and check correlated ' +
      'subjects".',
    attack:
      'Reason-driven response amplification or suppression. An ' +
      'attacker submitting a forged SET can choose `reason` to either ' +
      'amplify response (claim `bulk-account` for a single account to ' +
      'trigger broader investigation overhead and alert fatigue) or ' +
      'suppress it (claim no specific reason for what is actually a ' +
      'mass event, hoping the receiver\'s default response is ' +
      'lighter).',
    impact:
      'Response-policy manipulation when `reason` is taken at face ' +
      'value. Defences: (1) authenticate the Transmitter (signature on ' +
      'JWKS) before trusting `reason` to drive policy; (2) cross-check ' +
      'reason against observed event volume — a `bulk-account` claim ' +
      'with no other corroborating events is suspicious.',
    references: [
      {
        label: 'OpenID RISC Profile §2.2 (account-disabled)',
        href: 'https://openid.net/specs/openid-risc-profile-1_0-ID1.html',
      },
    ],
  },

  reason_admin: {
    purpose:
      'Administrative log message attached to a CAEP/RISC event. ' +
      'Free-form text intended for the Receiver\'s logs and ' +
      'investigation pipelines. Sibling `reason_user` is intended for ' +
      'end-user-facing display.',
    withoutIt:
      'The "without it" risk is *including too much* in `reason_admin` ' +
      'rather than omitting it. Transmitters that embed sensitive ' +
      'detection details ("user detected on Tor exit at $IP", ' +
      '"matched breach database hit for password $hash") leak that ' +
      'information to Receivers — and through them to logs, SIEMs, ' +
      'and analytics pipelines that may not have appropriate ' +
      'sensitivity controls.',
    attack:
      'Cross-organisation information leakage via SET payloads. The ' +
      'Transmitter is an enterprise IdP. The Receiver is a SaaS the ' +
      'enterprise federates to — operationally trusted but not under ' +
      'the enterprise\'s direct administrative control. The ' +
      'Transmitter emits a `credential-compromise` event with ' +
      '`reason_admin` containing the user\'s name, the detection ' +
      'method, the suspected attacker\'s IP, and internal ticket ID. ' +
      'All of that lands in the SaaS\'s logs, accessible to the SaaS\'s ' +
      'support staff and any subprocessor of the SaaS\'s logging ' +
      'pipeline. RISC §2.1 explicitly warns: "Do NOT include actual ' +
      'compromised credential values in the SET" — but the broader ' +
      'principle (don\'t leak detection details) is often missed.',
    impact:
      'Privacy and operational-information leakage outside the ' +
      'organisation. Defences: (1) treat `reason_admin` as crossing a ' +
      'data-sharing boundary; (2) include only what the Receiver ' +
      'needs to differentiate response policies (a category code, not ' +
      'free-form details); (3) NEVER include actual credential ' +
      'values, raw IP addresses, or PII the Receiver doesn\'t already ' +
      'have a legitimate processing basis for.',
    references: [
      {
        label: 'OpenID CAEP §2 (reason_admin / reason_user)',
        href: 'https://openid.net/specs/openid-caep-1_0-ID2.html',
      },
    ],
  },

  credential_type: {
    purpose:
      'CAEP `credential-change` event property identifying which ' +
      'credential changed: `password`, `pin`, `x509`, ' +
      '`fido2-platform`, `fido2-roaming`, `fido-u2f`, ' +
      '`verifiable-credential`, `phone-voice`, `phone-sms`, `app`. ' +
      'Lets Receivers scope their response to invalidating tokens ' +
      'derived from the changed credential.',
    withoutIt:
      'Without `credential_type`, the Receiver either treats every ' +
      'credential change as full revocation (over-broad — annoying ' +
      'users when only their fingerprint enrollment changed) or as a ' +
      'soft signal (under-broad — keeps password-derived tokens valid ' +
      'after a password change).',
    attack:
      'Tokens-from-stale-credential persistence. The user changes ' +
      'their password. The Transmitter emits a `credential-change` ' +
      'event with no `credential_type`. The Receiver, lacking enough ' +
      'detail, defaults to "log the event but don\'t revoke anything". ' +
      'Tokens issued during the original-password session remain ' +
      'valid until natural expiry — defeating the user\'s intent in ' +
      'changing the password. The user *thinks* they\'re secured; they ' +
      'are not.',
    impact:
      'Persistence of tokens past credential rotation. Defences: ' +
      '(1) Transmitter MUST include `credential_type` on every ' +
      '`credential-change` event; (2) Receiver MUST scope its ' +
      'response to tokens / sessions actually derived from the ' +
      'specific credential type — and trigger full revocation when ' +
      'the credential type can\'t be determined; (3) for password / ' +
      'high-assurance changes, force re-authentication with the new ' +
      'credential before reissuing any tokens.',
    references: [
      {
        label: 'OpenID CAEP §3.2 (credential-change)',
        href: 'https://openid.net/specs/openid-caep-1_0-ID2.html',
      },
    ],
  },

  change_type: {
    purpose:
      'CAEP `credential-change` event property: `create` (new ' +
      'credential added), `revoke` (credential removed), or `update` ' +
      '(credential modified, e.g. password reset). Drives the ' +
      'Receiver\'s response — `revoke` triggers token invalidation; ' +
      '`create` may be informational; `update` requires nuanced ' +
      'response.',
    withoutIt:
      'Without `change_type`, the Receiver cannot tell "user added a ' +
      'new MFA factor" (benign) from "user removed all credentials" ' +
      '(emergency). Default-to-strict means every credential add ' +
      'forces re-auth (annoying); default-to-permissive means ' +
      'credential revocation events fail to trigger token revocation ' +
      '(dangerous).',
    attack:
      'Same persistence-of-tokens class as `credential_type` — but at ' +
      'the create/revoke/update granularity. An attacker who can ' +
      'manipulate `change_type` (forged SET, compromised Transmitter) ' +
      'sends `create` instead of `revoke` for a removed credential — ' +
      'Receiver logs the event as benign rather than triggering ' +
      'revocation. Or sends `update` instead of `revoke` to muddy the ' +
      'audit trail when removing the user\'s only remaining MFA factor.',
    impact:
      'Audit-trail manipulation and missed revocation. Defences: ' +
      '(1) authenticate every SET signature before trusting `change_' +
      'type`; (2) cross-check change_type values against IdP logs ' +
      'periodically (a stream of credential-change events with no ' +
      'corresponding IdP-side credential modifications is a forged-' +
      'SET signal); (3) if `change_type=revoke`, treat as the highest-' +
      'urgency CAEP event after RISC events.',
    references: [
      {
        label: 'OpenID CAEP §3.2 (credential-change change_type)',
        href: 'https://openid.net/specs/openid-caep-1_0-ID2.html',
      },
    ],
  },
}
