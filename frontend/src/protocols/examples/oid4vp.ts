import type { CodeExample } from './index'

export const OID4VP_EXAMPLES: Record<string, CodeExample> = {
  'oid4vp-direct-post': {
    language: 'javascript',
    label: 'JavaScript (Verifier + Wallet Callback)',
    code: `// OID4VP DCQL + direct_post (OpenID4VP 1.0)
// 1) Verifier creates authorization request with DCQL query
const createRequest = await fetch('/oid4vp/request/create', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    client_id: 'redirect_uri:https://verifier.example.com/callback',
    response_mode: 'direct_post',
    response_uri: window.location.origin + '/oid4vp/response',
    dcql_query: {
      credentials: [
        {
          id: 'university_degree',
          meta: { vct_values: ['https://protocolsoup.com/credentials/university_degree'] },
          claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
        },
      ],
    },
  }),
}).then(r => r.json());

// createRequest includes request_id, request_uri, request JWT, state, nonce

// 2) Wallet resolves request_uri
const requestObject = await fetch(createRequest.request_uri).then(r => r.json());

// 3) Wallet submits vp_token + state to response_uri
await fetch(createRequest.response_uri, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    state: createRequest.state,
    vp_token: walletGeneratedVPToken,
  }),
});

// 4) Verifier checks policy decision
const result = await fetch('/oid4vp/result/' + createRequest.request_id)
  .then(r => r.json());

// result.status: "pending" | "completed"
// result.result.policy: { allowed, code, message, reasons, reason_codes }`,
  },

  'oid4vp-direct-post-jwt': {
    language: 'typescript',
    label: 'TypeScript (direct_post.jwt)',
    code: `// OID4VP direct_post.jwt (OpenID4VP 1.0 §8.3.1)
// Wallet sends encrypted "response" containing signed inner JWT.
import * as jose from 'jose';

const createRequest = await fetch('/oid4vp/request/create', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    response_mode: 'direct_post.jwt',
    response_uri: window.location.origin + '/oid4vp/response',
    dcql_query: {
      credentials: [{ id: 'university_degree', claims: [{ path: ['degree'] }] }],
    },
  }),
}).then(r => r.json());

// Build signed inner response JWT (typ=oauth-authz-resp+jwt)
const innerResponseJWT = await new jose.SignJWT({
  iss: walletSubjectDid,
  sub: walletSubjectDid,
  aud: createRequest.response_uri,
  state: createRequest.state,
  vp_token: walletVPToken,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 120,
})
  .setProtectedHeader({ alg: 'RS256', typ: 'oauth-authz-resp+jwt', kid: walletKeyID })
  .sign(walletPrivateKey);

// Encrypt inner JWT for verifier (RSA-OAEP + A256GCM in this implementation)
const encryptedResponse = await new jose.CompactEncrypt(
  new TextEncoder().encode(innerResponseJWT),
)
  .setProtectedHeader({ alg: 'RSA-OAEP', enc: 'A256GCM' })
  .encrypt(verifierEncryptionPublicKey);

// Wallet callback payload
await fetch(createRequest.response_uri, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    state: createRequest.state,
    response: encryptedResponse,
  }),
});

// Verifier decrypts, validates inner typ/aud/sub/exp, then evaluates vp_token policy.`,
  },
}
