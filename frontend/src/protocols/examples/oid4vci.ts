import type { CodeExample } from './index'

export const OID4VCI_EXAMPLES: Record<string, CodeExample> = {
  'oid4vci-pre-authorized': {
    language: 'javascript',
    label: 'JavaScript (Wallet Flow)',
    code: `// OID4VCI Pre-Authorized Code Flow (OpenID4VCI 1.0)
// 1) Create a credential offer (issuer-side helper endpoint)
const offerResponse = await fetch('/oid4vci/offers/pre-authorized', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    credential_configuration_ids: ['UniversityDegreeCredential'],
    tx_code_required: false,
  }),
}).then(r => r.json());

// offerResponse includes:
// - credential_offer_uri
// - pre_authorized_code
// - offer_id
// - wallet_subject

// 2) Resolve credential offer by reference
const credentialOffer = await fetch(offerResponse.credential_offer_uri)
  .then(r => r.json());

// 3) Exchange pre-authorized code for access token + c_nonce
const tokenResponse = await fetch('/oid4vci/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    'pre-authorized_code': offerResponse.pre_authorized_code,
  }),
}).then(r => r.json());

// 4) Build proof JWT bound to c_nonce and issuer audience
const proofJWT = await createOID4VCIProofJWT({
  issuer: offerResponse.wallet_subject,         // wallet subject
  audience: window.location.origin + '/oid4vci',
  nonce: tokenResponse.c_nonce,
  typ: 'openid4vci-proof+jwt',
  alg: 'RS256',
});

// 5) Request credential
const credentialResponse = await fetch('/oid4vci/credential', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + tokenResponse.access_token,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    credential_configuration_id: 'UniversityDegreeCredential',
    proofs: [{ proof_type: 'jwt', jwt: proofJWT }],
  }),
}).then(r => r.json());

// Immediate issuance response:
// {
//   "format": "dc+sd-jwt",
//   "credential": "<issuer-signed-jwt~disclosure~...>",
//   "c_nonce": "...",
//   "c_nonce_expires_in": 300
// }`,
  },

  'oid4vci-pre-authorized-tx-code': {
    language: 'javascript',
    label: 'JavaScript (tx_code Variant)',
    code: `// OID4VCI Pre-Authorized + tx_code (OpenID4VCI 1.0 §6.1)
// When credential offer grant includes tx_code object, token request MUST include tx_code.

const offer = await fetch('/oid4vci/offers/pre-authorized', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    tx_code_required: true,
    credential_configuration_ids: ['UniversityDegreeCredential'],
  }),
}).then(r => r.json());

// In this implementation, tx_code is delivered OOB for demo use.
const outOfBandTxCode = offer.tx_code_oob_value; // e.g. "123456"

const token = await fetch('/oid4vci/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    'pre-authorized_code': offer.pre_authorized_code,
    tx_code: outOfBandTxCode,
  }),
}).then(r => r.json());

if (token.error) {
  // invalid_grant if tx_code missing/invalid
  throw new Error(token.error_description || token.error);
}`,
  },

  'oid4vci-deferred-issuance': {
    language: 'javascript',
    label: 'JavaScript (Deferred Issuance)',
    code: `// OID4VCI Deferred Issuance
// Credential endpoint returns transaction_id first, then wallet polls deferred endpoint.

const offer = await fetch('/oid4vci/offers/pre-authorized/deferred', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    credential_configuration_ids: ['UniversityDegreeCredential'],
  }),
}).then(r => r.json());

const token = await fetch('/oid4vci/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    'pre-authorized_code': offer.pre_authorized_code,
  }),
}).then(r => r.json());

const proofJWT = await createOID4VCIProofJWT({
  issuer: offer.wallet_subject,
  audience: window.location.origin + '/oid4vci',
  nonce: token.c_nonce,
  typ: 'openid4vci-proof+jwt',
  alg: 'RS256',
});

const initial = await fetch('/oid4vci/credential', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + token.access_token,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    credential_configuration_id: 'UniversityDegreeCredential',
    proofs: [{ proof_type: 'jwt', jwt: proofJWT }],
  }),
}).then(r => r.json());

const transactionID = initial.transaction_id;
if (!transactionID) throw new Error('Expected transaction_id for deferred flow');

while (true) {
  const poll = await fetch('/oid4vci/deferred_credential', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + token.access_token,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ transaction_id: transactionID }),
  }).then(r => r.json());

  if (!poll.error) {
    // Success: { format: "dc+sd-jwt", credential: "..." }
    break;
  }
  if (poll.error !== 'issuance_pending') {
    throw new Error(poll.error_description || poll.error);
  }
  await new Promise(resolve => setTimeout(resolve, 1000));
}`,
  },
}
