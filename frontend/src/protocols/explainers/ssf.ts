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
    attacks: [
      {
        id: 'set-token-type-confusion',
        name: 'Token-type confusion (SET vs ID Token)',
        scenario:
          'Mallory captures Alice\'s legitimate ID Token (via any ' +
          'JWT-leakage path — referer, log, browser extension). Without ' +
          '`events`-claim validation on the SSF Receiver, Mallory POSTs ' +
          'the captured ID Token to the receiver\'s push endpoint. The ' +
          'token is signed by the same OP/Transmitter, `iss`/`aud`/`iat` ' +
          'all valid — receiver accepts it as a SET. Depending on what ' +
          'code path runs without an `events` claim, this either crashes ' +
          '(best case) or silently triggers default behaviour (worst case ' +
          '— forced logout for the subject named in `sub`). Same hazard ' +
          'in the other direction: a SET replayed at an OIDC RP\'s ID ' +
          'Token consumer.',
        impact:
          'Cross-token-type confusion enabling either auth bypass (SET ' +
          'accepted as ID Token) or DoS-via-forced-logout (ID Token ' +
          'accepted as SET).',
      },
      {
        id: 'set-jwt-validation-pitfalls',
        name: 'Standard JWT validation pitfalls (alg=none, alg confusion, etc.)',
        scenario:
          'The same JWT-validation pitfalls as `id_token`: alg=none, ' +
          'algorithm confusion (RS256→HS256), fail-open on unknown alg, ' +
          'skipped claim validation. SETs are JWTs and inherit every JWT ' +
          'validation footgun.',
        impact:
          'Authentication / authorization bypass at the SET-receiver layer ' +
          '— forged events accepted, real events spoofed.',
      },
    ],
    mitigations: [
      {
        action:
          'Receiver MUST reject any token without an `events` claim (RFC ' +
          '8417 §2.2 — token-type discriminator).',
        mitigates: ['set-token-type-confusion'],
      },
      {
        action:
          'Verify the SET\'s `typ` header is `secevent+jwt` before any ' +
          'further processing.',
        mitigates: ['set-token-type-confusion'],
      },
      {
        action:
          'Apply standard JWT validation: pin allowed `alg` from ' +
          'Transmitter metadata; verify signature; validate `iss`, `aud`, ' +
          'and `iat`/exp.',
        mitigates: [
          'set-jwt-validation-pitfalls',
          'set-token-type-confusion',
        ],
      },
    ],
    references: [
      {
        label: 'RFC 8417 (Security Event Token)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417',
      },
      {
        label: 'RFC 8417 §2.2 (Core SET Claims — events token-type)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-2.2',
      },
      {
        label: 'RFC 8417 §5 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-5',
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
    attacks: [
      {
        id: 'unknown-event-type-abuse',
        name: 'Unknown-event-type abuse',
        scenario:
          'Mallory submits a SET with `events: ' +
          '{ "https://attacker.example/custom-event": {...} }`. A receiver ' +
          'implementing "process all events in the events claim" with a ' +
          'generic dispatcher may invoke per-event hooks, log the unknown ' +
          'event with sensitive context, or, in the worst case, allow the ' +
          'payload to flow into downstream processing where its unexpected ' +
          'shape causes harm (parser confusion, type-coercion bugs).',
        impact:
          'Event-type allowlist bypass + payload-driven side effects.',
      },
      {
        id: 'silent-log-info-leak',
        name: 'Silent logging of attacker-crafted payload',
        scenario:
          'Receivers that accept events from event-type URIs they ' +
          'technically know about but for which they have no meaningful ' +
          'local action — silently no-oping is fine; silently logging the ' +
          '(potentially attacker-crafted) payload is an information-leak ' +
          'surface.',
        impact:
          'Log pollution / information disclosure to log consumers.',
      },
      {
        id: 'set-vs-other-jwt-confusion-via-events',
        name: 'Non-SET JWT processed as SET',
        scenario:
          'A non-SET JWT (ID Token, access token) gets processed as a SET ' +
          'because nothing rejected the missing `events` claim — the ' +
          'token-type discriminator was not enforced.',
        impact:
          'See `SET` entry — same cross-token-type confusion class.',
      },
    ],
    mitigations: [
      {
        action:
          'Maintain an explicit allowlist of event-type URIs the receiver ' +
          'understands.',
        mitigates: ['unknown-event-type-abuse'],
      },
      {
        action:
          'Reject SETs containing any unrecognised event type. The spec ' +
          'allows ignoring, but rejecting catches misconfigurations.',
        mitigates: ['unknown-event-type-abuse'],
      },
      {
        action:
          'Per-event-type schema validation on the payload before ' +
          'processing — reject malformed payloads, do not log raw ' +
          'attacker content.',
        mitigates: ['unknown-event-type-abuse', 'silent-log-info-leak'],
      },
      {
        action:
          'Reject any token without an `events` claim before further ' +
          'processing — enforces the token-type discriminator.',
        mitigates: ['set-vs-other-jwt-confusion-via-events'],
      },
    ],
    references: [
      {
        label: 'RFC 8417 §2.2 (events claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-2.2',
      },
      {
        label: 'RFC 8417 §5 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-5',
      },
    ],
  },

  event_type: {
    purpose:
      'A URI naming a specific kind of event: ' +
      '`.../caep/event-type/session-revoked`, ' +
      '`.../caep/event-type/credential-change`, ' +
      '`.../risc/event-type/account-disabled`, ' +
      '`.../risc/event-type/credential-compromise`. Used as a key in the ' +
      '`events` claim. Drives receiver-side dispatch — different event ' +
      'types trigger different actions.',
    attacks: [
      {
        id: 'event-type-spoofing-false-signal',
        name: 'Event-type spoofing → false-signal DoS',
        scenario:
          'Mallory injects a SET (via any path that lets her reach the ' +
          'receiver) with `event_type=account-disabled` for an ' +
          'executive\'s subject identifier. The receiver, treating the ' +
          'event as authoritative, terminates the executive\'s sessions ' +
          'and revokes their tokens — denial of service via false signal. ' +
          'RISC events (`account-disabled`, `credential-compromise`) are ' +
          'particularly dangerous because their *intended* response is ' +
          'destructive; misuse turns them into weaponised disruption.',
        impact:
          'Targeted DoS by triggering destructive responses for chosen ' +
          'subjects.',
      },
    ],
    mitigations: [
      {
        action:
          'Authenticate every SET against a known Transmitter via ' +
          'signature on the trust-domain JWKS — only signed events from ' +
          'trusted Transmitters get processed.',
        mitigates: ['event-type-spoofing-false-signal'],
      },
      {
        action:
          'Restrict which Transmitters can publish each event type — not ' +
          'every Transmitter should be authoritative for `account-' +
          'disabled`.',
        mitigates: ['event-type-spoofing-false-signal'],
      },
      {
        action:
          'For high-impact RISC events, consider human-in-the-loop / ' +
          'staged enforcement (alert-then-enforce with a small delay ' +
          'window for the security team to override).',
        mitigates: ['event-type-spoofing-false-signal'],
      },
    ],
    references: [
      {
        label: 'OpenID CAEP Spec',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
      {
        label: 'OpenID RISC Event Types',
        href: 'https://openid.net/specs/openid-risc-1_0.html',
      },
      {
        label: 'RFC 8417 §5 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-5',
      },
      {
        label: 'OpenID CAEP §4 (Security Considerations)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
      {
        label: 'OpenID RISC §4 (Security Considerations)',
        href: 'https://openid.net/specs/openid-risc-1_0.html',
      },
    ],
  },

  jti: {
    purpose:
      'JWT ID claim — a Transmitter-assigned unique identifier for this ' +
      'specific SET. Receivers cache `jti` values to detect replay; ' +
      'pollers also use `jti` as the acknowledgment key.',
    attacks: [
      {
        id: 'set-replay-no-jti-cache',
        name: 'SET replay against receiver without jti caching',
        scenario:
          'Mallory captures one of Alice\'s legitimate `session-revoked` ' +
          'SETs from a transmitter\'s push delivery (network tap on a ' +
          'non-TLS internal hop, leaked log, malicious receiver-side load ' +
          'balancer). She replays it to the same receiver some time later. ' +
          'Without jti caching, the receiver processes the event again — ' +
          'and because session-revoked is destructive, this terminates ' +
          'Alice\'s *current* session even though the original event was ' +
          'about a session she\'d already logged out of. Mallory can ' +
          'replay this on any cadence she likes to prevent Alice from ' +
          'ever staying logged in.',
        impact:
          'DoS via replay-driven destructive action; for state-tracking ' +
          'systems, downstream count corruption.',
      },
    ],
    mitigations: [
      {
        action:
          'Cache `jti` for the duration of the validity window; reject ' +
          'duplicate `jti` from the same Transmitter.',
        mitigates: ['set-replay-no-jti-cache'],
      },
      {
        action:
          'Align cache TTL with the SET\'s implied validity (typically ' +
          '5-15 minutes for real-time events) — long enough to catch ' +
          'replay, short enough to bound memory.',
        mitigates: ['set-replay-no-jti-cache'],
      },
    ],
    references: [
      {
        label: 'RFC 8417 §2.2 (jti)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-2.2',
      },
      {
        label: 'RFC 7519 §4.1.7 (jti claim)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7',
      },
      {
        label: 'RFC 8417 §5 (Security Considerations — replay)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8417#section-5',
      },
    ],
  },

  delivery: {
    purpose:
      'How SETs flow from Transmitter to Receiver. Two profiles: **Push** ' +
      '(RFC 8935) — Transmitter POSTs each SET to the Receiver\'s endpoint ' +
      'as events occur; **Poll** (RFC 8936) — Receiver POSTs to fetch any ' +
      'pending SETs, with optional long-polling. Choice affects which ' +
      'side bears the resource cost and which side is on the attack ' +
      'surface.',
    attacks: [
      {
        id: 'push-endpoint-flooding',
        name: 'Push-endpoint flooding (DoS receiver)',
        scenario:
          'Mallory either compromises one Transmitter in the trust mesh or ' +
          'finds a Receiver whose push endpoint has lax authentication. ' +
          'She POSTs a high volume of SETs (each individually valid-' +
          'looking) to consume the receiver\'s parsing and verification ' +
          'capacity — every SET requires a JWS verification, a jti cache ' +
          'lookup, and event-handler dispatch. The receiver either crashes ' +
          'or starts rejecting traffic, including legitimate events that ' +
          'the receiver actually needed (e.g. real `account-disabled` ' +
          'events for compromised accounts now stuck in the queue).',
        impact:
          'DoS plus availability impact on legitimate SET delivery — and ' +
          'the events being missed are precisely the ones the receiver ' +
          'most needs to act on.',
      },
      {
        id: 'long-poll-connection-exhaustion',
        name: 'Long-poll connection exhaustion (DoS transmitter)',
        scenario:
          'Open thousands of long-poll connections against the ' +
          'Transmitter to consume Transmitter sockets, goroutines, ' +
          'thread pool — exhausting the resources legitimate Receivers ' +
          'need.',
        impact:
          'Transmitter unable to serve legitimate Receivers; events ' +
          'queue up undelivered.',
      },
    ],
    mitigations: [
      {
        action:
          'Receiver MUST authenticate every push request — validate the ' +
          'Transmitter\'s identity (typically Bearer token bound to the ' +
          'stream).',
        mitigates: ['push-endpoint-flooding'],
      },
      {
        action:
          'Rate-limit per-Transmitter on the Receiver side; one bad ' +
          'transmitter must not exhaust the pool.',
        mitigates: ['push-endpoint-flooding'],
      },
      {
        action:
          'For poll, cap concurrent long-poll connections per Receiver ' +
          'and reject excess.',
        mitigates: ['long-poll-connection-exhaustion'],
      },
      {
        action:
          'Timeouts and circuit breakers on push verification.',
        mitigates: ['push-endpoint-flooding'],
      },
    ],
    references: [
      {
        label: 'RFC 8935 (SET Push Delivery)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8935',
      },
      {
        label: 'RFC 8936 (SET Poll Delivery)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8936',
      },
      {
        label: 'RFC 8935 §5 (Push — Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8935#section-5',
      },
      {
        label: 'RFC 8936 §4 (Poll — Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc8936#section-4',
      },
    ],
  },

  stream_id: {
    purpose:
      'Identifier for an SSF stream — the relationship between one ' +
      'Transmitter and one Receiver, including its delivery method, ' +
      'subscribed event types, and authentication credentials. Created ' +
      'via POST to the configuration_endpoint; managed via stream-control ' +
      'endpoints.',
    attacks: [
      {
        id: 'unauthorized-stream-creation',
        name: 'Unauthorized stream creation',
        scenario:
          'The Transmitter\'s configuration endpoint accepts ' +
          'stream-creation requests with weak authentication (no token, ' +
          'shared bearer token leaked widely). Mallory POSTs a ' +
          'stream-creation request asking to receive `account-disabled` ' +
          'events for Alice\'s subject identifier. The Transmitter creates ' +
          'the stream; from this point on, every `account-disabled` event ' +
          'for Alice is also delivered to Mallory\'s receiver. Mallory ' +
          'now has real-time intelligence on when Alice\'s account is ' +
          'disabled — useful for timing attacks, social engineering ' +
          '("we noticed your account was just disabled, click here to ' +
          'reactivate"), or simply confirming when compromise has been ' +
          'detected.',
        impact:
          'Information disclosure of security-event signals to attackers.',
      },
    ],
    mitigations: [
      {
        action:
          'Protect the stream-management endpoint with strong ' +
          'authentication (OAuth2 client credentials, mTLS).',
        mitigates: ['unauthorized-stream-creation'],
      },
      {
        action:
          'Authorize stream-creation by the Receiver\'s legitimate ' +
          'identity, not just possession of a token.',
        mitigates: ['unauthorized-stream-creation'],
      },
      {
        action:
          'Limit which subjects each Receiver may subscribe to — a ' +
          'Receiver representing AppA shouldn\'t subscribe to events for ' +
          'users it doesn\'t manage.',
        mitigates: ['unauthorized-stream-creation'],
      },
      {
        action:
          'Audit stream creations; alert on unexpected new streams or ' +
          'subject additions.',
        mitigates: ['unauthorized-stream-creation'],
      },
    ],
    references: [
      {
        label: 'OpenID SSF §7 (Stream Management)',
        href: 'https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html',
      },
      {
        label: 'OpenID SSF §11 (Security Considerations)',
        href: 'https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html',
      },
    ],
  },

  subject: {
    purpose:
      'Identifies the entity (user, device, session, application) the SET ' +
      'is about. Multiple Subject Identifier formats per RFC 9493: ' +
      '`email`, `iss_sub`, `opaque`, `phone_number`, `account`, `did`, ' +
      '`uri`, `aliases`. The Receiver maps the subject to its local user ' +
      'record before taking action.',
    attacks: [
      {
        id: 'subject-confusion-wrong-user',
        name: 'Subject confusion → wrong-user enforcement',
        scenario:
          'The Transmitter identifies users by `email`. The Receiver ' +
          'matches incoming events by email too. Mallory has a colliding ' +
          'email — same address at a different IdP, or a legitimately-' +
          'owned email that happens to match Alice\'s historical address ' +
          '(recycled corporate domain). A `credential-compromise` event ' +
          'for Mallory arrives at the Receiver, which keys on email and ' +
          'applies the compromise response to *Alice* (forced logout, ' +
          'password reset, token revocation). False-positive enforcement ' +
          'against the wrong subject.',
        impact:
          'Legitimate events trigger destructive responses against the ' +
          'wrong user — the SET-delivery analogue of the OIDC nOAuth ' +
          'attack (matching users by email instead of stable identifier).',
      },
      {
        id: 'iss-sub-composite-key-bug',
        name: 'iss_sub composite-key match implementation bug',
        scenario:
          '`iss_sub` (issuer + subject) format provides tenant scoping ' +
          'but only if the Receiver implements the composite-key match ' +
          'correctly — a Receiver that compares only the `sub` portion ' +
          'reintroduces the cross-tenant collision class.',
        impact:
          'Same wrong-user-enforcement outcome as plain email-based ' +
          'matching, despite using the safer identifier format.',
      },
    ],
    mitigations: [
      {
        action:
          'Prefer `iss_sub` (issuer + subject pair) Subject Identifier ' +
          'format over mutable claims like email.',
        mitigates: [
          'subject-confusion-wrong-user',
          'iss-sub-composite-key-bug',
        ],
      },
      {
        action:
          'Use explicit mapping tables, not best-effort heuristics, to ' +
          'translate Subject Identifiers to local user records.',
        mitigates: ['subject-confusion-wrong-user'],
      },
      {
        action:
          'Reject events whose subject doesn\'t map to a known local user ' +
          '— don\'t silently no-op; log and alert.',
        mitigates: ['subject-confusion-wrong-user'],
      },
      {
        action:
          'When using `iss_sub`, match on the full composite key — ' +
          'never reduce to `sub` alone.',
        mitigates: ['iss-sub-composite-key-bug'],
      },
    ],
    references: [
      {
        label: 'RFC 9493 (Subject Identifiers for SETs)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9493',
      },
      {
        label: 'RFC 9493 §6 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc9493#section-6',
      },
    ],
  },

  initiating_entity: {
    purpose:
      'CAEP claim identifying who/what triggered the event: `admin`, ' +
      '`user`, `policy`, `system`. Drives receiver-side response ' +
      'differentiation — admin-initiated revocation may warrant different ' +
      'handling than policy-driven revocation.',
    attacks: [
      {
        id: 'initiating-entity-audit-trail-confusion',
        name: 'Audit-trail confusion',
        scenario:
          'An attacker who can submit SETs may set ' +
          '`initiating_entity=user` to make malicious revocations appear ' +
          'as if the user requested them — masking attacker activity in ' +
          'the audit logs. Conversely, missing `initiating_entity` gives ' +
          'the receiver no way to weight responses (an admin-initiated ' +
          'session-revoked might warrant a security alert; a user-' +
          'initiated one is routine).',
        impact:
          'Audit and response-policy differentiation lost; attacker ' +
          'activity disguised as user-initiated routine events.',
      },
    ],
    mitigations: [
      {
        action:
          'Transmitter MUST include `initiating_entity` on every CAEP ' +
          'event.',
        mitigates: ['initiating-entity-audit-trail-confusion'],
      },
      {
        action:
          'Receiver logs `initiating_entity` as part of every event-driven ' +
          'action — preserves the audit trail for post-incident analysis.',
        mitigates: ['initiating-entity-audit-trail-confusion'],
      },
      {
        action:
          'Consider differentiated response policies — rate-limit ' +
          '`policy`-initiated revocations more aggressively than ' +
          '`user`-initiated, since attacker-injected false signals will ' +
          'most often claim `policy`.',
        mitigates: ['initiating-entity-audit-trail-confusion'],
      },
    ],
    references: [
      {
        label: 'OpenID CAEP §2 (Common Event Properties)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
      {
        label: 'OpenID CAEP §4 (Security Considerations)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
    ],
  },

  reason: {
    purpose:
      'RISC `account-disabled` event property naming the high-level reason: ' +
      '`hijacking` (account-takeover detected) or `bulk-account` ' +
      '(mass-compromise scenario). Lets Receivers differentiate response ' +
      'intensity.',
    attacks: [
      {
        id: 'reason-driven-amplification',
        name: 'Response amplification via inflated reason',
        scenario:
          'An attacker submitting a forged SET claims `bulk-account` for ' +
          'a single account to trigger broader investigation overhead and ' +
          'alert fatigue across the security team.',
        impact:
          'Operational disruption — investigators spend time on a ' +
          'fabricated mass event.',
      },
      {
        id: 'reason-driven-suppression',
        name: 'Response suppression via omitted/under-stated reason',
        scenario:
          'An attacker claims no specific reason for what is actually a ' +
          'mass event, hoping the receiver\'s default response is ' +
          'lighter than what `bulk-account` would have triggered.',
        impact:
          'Real bulk-compromise events handled with under-scoped response.',
      },
    ],
    mitigations: [
      {
        action:
          'Authenticate the Transmitter (signature on JWKS) before ' +
          'trusting `reason` to drive policy.',
        mitigates: [
          'reason-driven-amplification',
          'reason-driven-suppression',
        ],
      },
      {
        action:
          'Cross-check `reason` against observed event volume — a ' +
          '`bulk-account` claim with no other corroborating events is ' +
          'suspicious.',
        mitigates: ['reason-driven-amplification'],
      },
    ],
    references: [
      {
        label: 'OpenID RISC Profile §2.3 (account-disabled)',
        href: 'https://openid.net/specs/openid-risc-1_0.html',
      },
      {
        label: 'OpenID RISC §4 (Security Considerations)',
        href: 'https://openid.net/specs/openid-risc-1_0.html',
      },
    ],
  },

  reason_admin: {
    purpose:
      'Administrative log message attached to a CAEP/RISC event. ' +
      'Free-form text intended for the Receiver\'s logs and investigation ' +
      'pipelines. Sibling `reason_user` is intended for end-user-facing ' +
      'display.',
    attacks: [
      {
        id: 'cross-org-info-leak-reason-admin',
        name: 'Cross-organisation information leakage via SET payloads',
        scenario:
          'The Transmitter is an enterprise IdP. The Receiver is a SaaS ' +
          'the enterprise federates to — operationally trusted but not ' +
          'under the enterprise\'s direct administrative control. The ' +
          'Transmitter emits a `credential-compromise` event with ' +
          '`reason_admin` containing the user\'s name, the detection ' +
          'method, the suspected attacker\'s IP, and internal ticket ID. ' +
          'All of that lands in the SaaS\'s logs, accessible to the SaaS\'s ' +
          'support staff and any subprocessor of the SaaS\'s logging ' +
          'pipeline. RISC §2.7 explicitly warns: "Do NOT include actual ' +
          'compromised credential values in the SET" — but the broader ' +
          'principle (don\'t leak detection details) is often missed.',
        impact:
          'Privacy and operational-information leakage outside the ' +
          'organisation.',
      },
    ],
    mitigations: [
      {
        action:
          'Treat `reason_admin` as crossing a data-sharing boundary — ' +
          'evaluate every field against your data-sharing policy before ' +
          'emitting.',
        mitigates: ['cross-org-info-leak-reason-admin'],
      },
      {
        action:
          'Include only what the Receiver needs to differentiate response ' +
          'policies — a category code, not free-form details.',
        mitigates: ['cross-org-info-leak-reason-admin'],
      },
      {
        action:
          'NEVER include actual credential values, raw IP addresses, or ' +
          'PII the Receiver doesn\'t already have a legitimate processing ' +
          'basis for.',
        mitigates: ['cross-org-info-leak-reason-admin'],
      },
    ],
    references: [
      {
        label: 'OpenID CAEP §2 (reason_admin / reason_user)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
      {
        label: 'OpenID CAEP §4 (Security Considerations) / RISC §2.7 Privacy Warning',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
    ],
  },

  credential_type: {
    purpose:
      'CAEP `credential-change` event property identifying which ' +
      'credential changed: `password`, `pin`, `x509`, `fido2-platform`, ' +
      '`fido2-roaming`, `fido-u2f`, `verifiable-credential`, ' +
      '`phone-voice`, `phone-sms`, `app`. Lets Receivers scope their ' +
      'response to invalidating tokens derived from the changed credential.',
    attacks: [
      {
        id: 'tokens-from-stale-credential-persistence',
        name: 'Tokens-from-stale-credential persistence',
        scenario:
          'The user changes their password. The Transmitter emits a ' +
          '`credential-change` event with no `credential_type`. The ' +
          'Receiver, lacking enough detail, defaults to "log the event ' +
          'but don\'t revoke anything". Tokens issued during the original-' +
          'password session remain valid until natural expiry — defeating ' +
          'the user\'s intent in changing the password. The user *thinks* ' +
          'they\'re secured; they are not.',
        impact:
          'Persistence of tokens past credential rotation.',
      },
    ],
    mitigations: [
      {
        action:
          'Transmitter MUST include `credential_type` on every ' +
          '`credential-change` event.',
        mitigates: ['tokens-from-stale-credential-persistence'],
      },
      {
        action:
          'Receiver MUST scope its response to tokens / sessions actually ' +
          'derived from the specific credential type — and trigger full ' +
          'revocation when the credential type can\'t be determined.',
        mitigates: ['tokens-from-stale-credential-persistence'],
      },
      {
        action:
          'For password / high-assurance changes, force re-authentication ' +
          'with the new credential before reissuing any tokens.',
        mitigates: ['tokens-from-stale-credential-persistence'],
      },
    ],
    references: [
      {
        label: 'OpenID CAEP §3.3 (credential-change)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
      {
        label: 'OpenID CAEP §4 (Security Considerations)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
    ],
  },

  change_type: {
    purpose:
      'CAEP `credential-change` event property: `create` (new credential ' +
      'added), `revoke` (credential removed), or `update` (credential ' +
      'modified, e.g. password reset). Drives the Receiver\'s response — ' +
      '`revoke` triggers token invalidation; `create` may be ' +
      'informational; `update` requires nuanced response.',
    attacks: [
      {
        id: 'change-type-revoke-as-create',
        name: 'Revoke disguised as create — missed revocation',
        scenario:
          'An attacker who can manipulate `change_type` (forged SET, ' +
          'compromised Transmitter) sends `create` instead of `revoke` ' +
          'for a removed credential. The Receiver logs the event as ' +
          'benign rather than triggering token revocation.',
        impact:
          'Tokens that should have been revoked remain valid — silent ' +
          'persistence past credential removal.',
      },
      {
        id: 'change-type-update-disguise',
        name: 'Update disguising revocation in audit trail',
        scenario:
          'Sends `update` instead of `revoke` to muddy the audit trail ' +
          'when removing the user\'s only remaining MFA factor — ' +
          'investigators looking for revocation events miss it.',
        impact:
          'Audit-trail manipulation that delays incident response.',
      },
    ],
    mitigations: [
      {
        action:
          'Authenticate every SET signature before trusting `change_type` ' +
          'to drive enforcement decisions.',
        mitigates: [
          'change-type-revoke-as-create',
          'change-type-update-disguise',
        ],
      },
      {
        action:
          'Cross-check change_type values against IdP logs periodically — ' +
          'a stream of credential-change events with no corresponding ' +
          'IdP-side credential modifications is a forged-SET signal.',
        mitigates: [
          'change-type-revoke-as-create',
          'change-type-update-disguise',
        ],
      },
      {
        action:
          'Treat `change_type=revoke` as the highest-urgency CAEP event ' +
          'after RISC events — bias toward over-revocation rather than ' +
          'under-revocation.',
        mitigates: ['change-type-revoke-as-create'],
      },
    ],
    references: [
      {
        label: 'OpenID CAEP §3.3 (credential-change change_type)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
      {
        label: 'OpenID CAEP §4 (Security Considerations)',
        href: 'https://openid.net/specs/openid-caep-1_0-final.html',
      },
    ],
  },
}
