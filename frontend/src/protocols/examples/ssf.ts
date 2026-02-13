import type { CodeExample } from './index'

export const SSF_EXAMPLES: Record<string, CodeExample> = {
  /* ------------------------------------------------------------------ */
  'ssf-stream-configuration': {
    language: 'javascript',
    label: 'JavaScript (Stream Manager)',
    code: `// SSF Stream Configuration (OpenID SSF §4)
// Configure a stream between a Transmitter (IdP) and Receiver (your app).

// Step 1: Discover SSF capabilities via the well-known endpoint
const config = await fetch('/.well-known/ssf-configuration')
  .then(r => r.json());

// Discovery response:
// {
//   "issuer": "https://idp.example.com",
//   "jwks_uri": "/ssf/jwks",
//   "configuration_endpoint": "/ssf/stream",
//   "status_endpoint": "/ssf/status",
//   "delivery_methods_supported": [
//     "urn:ietf:rfc:8935",     ← Push Delivery
//     "urn:ietf:rfc:8936"      ← Poll Delivery
//   ]
// }

// Step 2: Create a stream (SSF §4.1)
const stream = await fetch(config.configuration_endpoint, {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + MANAGEMENT_TOKEN,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    delivery_method: 'push',             // or 'poll'
    delivery_endpoint_url: PUSH_ENDPOINT, // Your receiver URL
    events_requested: [
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      'https://schemas.openid.net/secevent/caep/event-type/credential-change',
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
      'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
    ],
  }),
}).then(r => r.json());

console.log('Stream ID:', stream.stream_id);
console.log('Status:', stream.status);               // "enabled"
console.log('Events delivered:', stream.events_delivered);

// Step 3: Fetch JWKS for verifying incoming SETs
const jwks = await fetch(config.jwks_uri).then(r => r.json());
// { "keys": [{ "kty": "RSA", "kid": "...", "n": "...", "e": "AQAB", "use": "sig" }] }`,
  },

  /* ------------------------------------------------------------------ */
  'ssf-push-delivery': {
    language: 'typescript',
    label: 'TypeScript (Receiver — Express)',
    code: `// SSF Push Delivery — Receiver Implementation (RFC 8935)
// The Transmitter POSTs Security Event Tokens to your endpoint.

import * as jose from 'jose';

// JWKS cache for signature verification
let cachedJWKS: jose.FlattenedJWSInput | null = null;

async function getJWKS() {
  if (!cachedJWKS) {
    cachedJWKS = jose.createRemoteJWKSet(
      new URL(TRANSMITTER_URL + '/ssf/jwks')
    );
  }
  return cachedJWKS;
}

// Replay detection — track processed JTIs (use Redis/DB in production)
const processedJTIs = new Set<string>();

// Push endpoint — receives raw SET tokens
app.post('/ssf/push', async (req, res) => {
  // RFC 8935 §2.2: Content-Type MUST be application/secevent+jwt
  const setToken = req.body;  // Raw JWT string (not parsed JSON)

  try {
    // 1. Verify SET signature against Transmitter's JWKS
    const jwks = await getJWKS();
    const { payload } = await jose.jwtVerify(setToken, jwks, {
      issuer: TRANSMITTER_ISSUER,
      audience: MY_AUDIENCE,
    });

    // 2. Replay detection (RFC 8935 §2.3)
    if (processedJTIs.has(payload.jti as string)) {
      return res.status(400).json({
        err: 'invalid_request',
        description: 'Duplicate SET — JTI already processed',
      });
    }
    processedJTIs.add(payload.jti as string);

    // 3. Validate timing — iat should not be more than 5 minutes old
    const iat = (payload.iat as number) * 1000;
    if (Date.now() - iat > 5 * 60 * 1000) {
      return res.status(400).json({
        err: 'invalid_request',
        description: 'SET is too old',
      });
    }

    // 4. Process security events from the "events" claim
    const events = payload.events as Record<string, Record<string, unknown>>;
    const subject = payload.sub_id as { format: string; email?: string };

    for (const [eventType, eventData] of Object.entries(events)) {
      await handleSecurityEvent(eventType, subject, eventData);
    }

    // 5. Acknowledge receipt — 202 Accepted (RFC 8935 §2.2)
    res.status(202).send();

  } catch (error) {
    res.status(400).json({
      err: 'invalid_request',
      description: (error as Error).message,
    });
  }
});`,
  },

  /* ------------------------------------------------------------------ */
  'ssf-poll-delivery': {
    language: 'typescript',
    label: 'TypeScript (Receiver — Polling Client)',
    code: `// SSF Poll Delivery — Receiver Implementation (RFC 8936)
// The Receiver periodically polls the Transmitter for queued SETs.

import * as jose from 'jose';

const POLL_ENDPOINT = TRANSMITTER_URL + '/ssf/poll';
const pendingAcks: string[] = [];

async function pollForEvents() {
  // RFC 8936 §3: POST to the poll endpoint
  const response = await fetch(POLL_ENDPOINT, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + ACCESS_TOKEN,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      max_events: 10,
      ack: pendingAcks.splice(0),  // Acknowledge previously processed SETs
      // returnImmediately: false   // Long-polling (optional)
    }),
  }).then(r => r.json());

  // Response: { "sets": { "jti1": "eyJ...", "jti2": "eyJ..." }, "more_available": true }

  // Process each SET
  const jwks = jose.createRemoteJWKSet(
    new URL(TRANSMITTER_URL + '/ssf/jwks')
  );

  for (const [jti, setToken] of Object.entries(response.sets)) {
    try {
      const { payload } = await jose.jwtVerify(setToken as string, jwks, {
        issuer: TRANSMITTER_ISSUER,
        audience: MY_AUDIENCE,
      });

      const events = payload.events as Record<string, Record<string, unknown>>;
      const subject = payload.sub_id as { format: string; email?: string };

      for (const [eventType, eventData] of Object.entries(events)) {
        await handleSecurityEvent(eventType, subject, eventData);
      }

      // Queue JTI for acknowledgment on next poll
      pendingAcks.push(jti);
    } catch (error) {
      console.error('Failed to process SET ' + jti + ':', error);
      // Don't acknowledge — will be retried on next poll
    }
  }

  // Schedule next poll
  if (response.more_available) {
    setImmediate(pollForEvents);     // More events waiting — poll immediately
  } else {
    setTimeout(pollForEvents, 30000); // 30-second interval when idle
  }
}

// Start the polling loop
pollForEvents();`,
  },

  /* ------------------------------------------------------------------ */
  'caep-session-revoked': {
    language: 'typescript',
    label: 'TypeScript (Transmitter + Receiver)',
    code: `// CAEP Session Revoked Event (CAEP §3.1)
// Continuous Access Evaluation — revoke sessions in real time.
import * as jose from 'jose';

// === TRANSMITTER: Generate and deliver a Session Revoked SET ===
async function emitSessionRevokedEvent(
  subjectEmail: string,
  reason: string,
  initiator: 'admin' | 'user' | 'policy' | 'system',
) {
  const privateKey = await jose.importPKCS8(SIGNING_KEY_PEM, 'RS256');

  // Construct SET per RFC 8417 + CAEP §3.1
  const set = await new jose.SignJWT({
    iss: TRANSMITTER_ISSUER,
    aud: RECEIVER_AUDIENCES,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subjectEmail },
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiating_entity: initiator,
        reason_admin: { en: reason },
        reason_user: { en: 'Your session has been terminated for security reasons.' },
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: SIGNING_KEY_ID, typ: 'secevent+jwt' })
  .sign(privateKey);

  // Push to receiver (RFC 8935)
  await fetch(RECEIVER_PUSH_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/secevent+jwt' },
    body: set,
  });
}

// === RECEIVER: Handle Session Revoked ===
async function handleSessionRevoked(
  eventData: { initiating_entity: string; reason_admin?: { en: string } },
  subject: { email: string },
) {
  // 1. Terminate all sessions for this user
  await sessionStore.deleteAllForUser(subject.email);

  // 2. Revoke outstanding access tokens
  await tokenStore.revokeAllForUser(subject.email);

  // 3. Audit log
  console.log('Sessions revoked for', subject.email,
    '— Reason:', eventData.reason_admin?.en,
    '— Initiator:', eventData.initiating_entity);
}`,
  },

  /* ------------------------------------------------------------------ */
  'caep-credential-change': {
    language: 'typescript',
    label: 'TypeScript (Transmitter + Receiver)',
    code: `// CAEP Credential Change Event (CAEP §3.2)
// Notifies relying parties when a user's credentials are modified.
import * as jose from 'jose';

// === TRANSMITTER: Emit Credential Change SET ===
async function emitCredentialChangeEvent(
  subjectEmail: string,
  credentialType: 'password' | 'fido2-platform' | 'fido2-roaming' | 'x509',
  changeType: 'create' | 'update' | 'revoke',
) {
  const privateKey = await jose.importPKCS8(SIGNING_KEY_PEM, 'RS256');

  const set = await new jose.SignJWT({
    iss: TRANSMITTER_ISSUER,
    aud: RECEIVER_AUDIENCES,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subjectEmail },
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/credential-change': {
        event_timestamp: Math.floor(Date.now() / 1000),
        credential_type: credentialType,
        change_type: changeType,
        initiating_entity: 'user',
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: SIGNING_KEY_ID, typ: 'secevent+jwt' })
  .sign(privateKey);

  await deliverSET(set);
}

// === RECEIVER: Handle Credential Change ===
async function handleCredentialChange(
  eventData: { credential_type: string; change_type: string },
  subject: { email: string },
) {
  const { credential_type, change_type } = eventData;

  // 1. Invalidate cached tokens and identity claims
  await tokenCache.invalidateForUser(subject.email);
  await claimsCache.invalidateForUser(subject.email);

  // 2. For password changes — force re-authentication everywhere
  if (credential_type === 'password') {
    await sessionStore.deleteAllForUser(subject.email);
  }

  // 3. For MFA credential revocation — flag for re-enrollment
  if (credential_type.startsWith('fido2') && change_type === 'revoke') {
    await flagForMFAReenrollment(subject.email);
  }

  console.log('Credential change:', credential_type, change_type,
    'for', subject.email);
}`,
  },

  /* ------------------------------------------------------------------ */
  'risc-account-disabled': {
    language: 'typescript',
    label: 'TypeScript (Transmitter + Receiver)',
    code: `// RISC Account Disabled Event (RISC §2.2)
// High-severity event — immediately block all access for the subject.
import * as jose from 'jose';

// === TRANSMITTER: Emit Account Disabled SET ===
async function emitAccountDisabledEvent(
  subjectEmail: string,
  reason: string,
) {
  const privateKey = await jose.importPKCS8(SIGNING_KEY_PEM, 'RS256');

  const set = await new jose.SignJWT({
    iss: TRANSMITTER_ISSUER,
    aud: RECEIVER_AUDIENCES,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subjectEmail },
    events: {
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled': {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiating_entity: 'admin',
        reason_admin: { en: reason },
        reason_user: { en: 'Your account has been suspended. Contact support.' },
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: SIGNING_KEY_ID, typ: 'secevent+jwt' })
  .sign(privateKey);

  // RISC events are high priority — retry aggressively
  await deliverWithRetry(set, { maxRetries: 5, priority: 'high' });
}

// === RECEIVER: Handle Account Disabled (CRITICAL) ===
async function handleAccountDisabled(
  eventData: { reason_admin?: { en: string } },
  subject: { email: string },
) {
  // CRITICAL: Block all access immediately

  // 1. Terminate ALL sessions
  await sessionStore.deleteAllForUser(subject.email);

  // 2. Revoke ALL tokens
  await tokenStore.revokeAllForUser(subject.email);

  // 3. Block new authentication attempts
  await userStore.setStatus(subject.email, 'disabled');

  // 4. Block API key access
  await apiKeyStore.disableAllForUser(subject.email);

  // 5. Audit log for compliance
  await auditLog.record({
    event: 'ACCOUNT_DISABLED_VIA_SSF',
    subject: subject.email,
    reason: eventData.reason_admin?.en,
    timestamp: new Date(),
  });
}`,
  },

  /* ------------------------------------------------------------------ */
  'risc-credential-compromise': {
    language: 'typescript',
    label: 'TypeScript (Transmitter + Receiver)',
    code: `// RISC Credential Compromise Event (RISC §2.1) — CRITICAL SEVERITY
// The highest-severity RISC event. Credentials have been exposed.
import * as jose from 'jose';

// === TRANSMITTER: Emit Credential Compromise SET ===
async function emitCredentialCompromiseEvent(
  subjectEmail: string,
  detectionSource: string,
) {
  const privateKey = await jose.importPKCS8(SIGNING_KEY_PEM, 'RS256');

  const set = await new jose.SignJWT({
    iss: TRANSMITTER_ISSUER,
    aud: RECEIVER_AUDIENCES,
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subjectEmail },
    events: {
      'https://schemas.openid.net/secevent/risc/event-type/credential-compromise': {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiating_entity: 'system',
        reason_admin: {
          en: 'Credential compromise detected via ' + detectionSource,
        },
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: SIGNING_KEY_ID, typ: 'secevent+jwt' })
  .sign(privateKey);

  // EMERGENCY: Aggressive delivery with failure alerting
  await deliverWithRetry(set, {
    maxRetries: 10,
    priority: 'critical',
    alertOnFailure: true,
  });
}

// === RECEIVER: Handle Credential Compromise (EMERGENCY) ===
async function handleCredentialCompromise(
  eventData: { reason_admin?: { en: string } },
  subject: { email: string },
) {
  console.error('CREDENTIAL COMPROMISE DETECTED:', subject.email);

  // 1. IMMEDIATELY terminate ALL sessions
  await sessionStore.deleteAllForUser(subject.email);

  // 2. Revoke ALL tokens globally
  await tokenStore.revokeAllForUser(subject.email);

  // 3. Revoke all API keys and certificates
  await apiKeyStore.revokeAllForUser(subject.email);

  // 4. Force password reset on next login
  await userStore.setPasswordResetRequired(subject.email, true);

  // 5. Require MFA re-enrollment
  await userStore.setMFAReenrollmentRequired(subject.email, true);

  // 6. Block account until credential reset completes
  await userStore.setStatus(subject.email, 'pending_credential_reset');

  // 7. Alert security team
  await securityAlert.critical({
    type: 'CREDENTIAL_COMPROMISE',
    subject: subject.email,
    source: eventData.reason_admin?.en,
    timestamp: new Date(),
  });

  // 8. Create incident for forensic investigation
  await incidentResponse.createIncident({
    type: 'credential_compromise',
    subject: subject.email,
    evidence: { eventData, timestamp: new Date() },
  });
}`,
  },
}
