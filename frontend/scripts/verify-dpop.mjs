#!/usr/bin/env node
// Verifies RFC 9449 DPoP client behavior that has no other automated
// coverage: proof construction in src/utils/crypto.ts's generateDPoPProof(),
// and the Looking Glass deep-link contract in
// src/components/palette/runDispatch.ts that carries client_auth/token_mode
// selections between the palette and the Looking Glass page.
//
// Like verify-jwk-thumbprint.mjs, this imports the actual shipped
// implementations (not a reimplementation local to this script) via Node's
// native TypeScript type-stripping, so a regression in either module fails
// this check rather than only a manual walkthrough.
//
// Usage: npm run verify-dpop

import { createHash } from 'node:crypto'
import {
  generateDPoPProof,
  generateES256SigningMaterial,
  decodeJWTWithoutValidation,
  base64URLEncode,
  base64URLDecode,
} from '../src/utils/crypto.ts'
import {
  parseFlowDeepLink,
  buildLookingGlassPath,
  buildFlowExecutionPath,
  resolveFlowHandoff,
} from '../src/components/palette/runDispatch.ts'

// resolveFlowHandoff resolves result.run_url against window.location.origin.
// This script runs under plain Node, not a browser/jsdom, so it provides the
// minimal same-origin shim that call actually needs.
globalThis.window = { location: { origin: 'http://localhost:3000' } }

const failures = []
let checksRun = 0

function check(name, condition, detail) {
  checksRun += 1
  if (condition) {
    console.log(`[PASS] ${name}`)
  } else {
    failures.push(name)
    console.log(`[FAIL] ${name}`)
    if (detail !== undefined) {
      console.log(`       ${detail}`)
    }
  }
}

// Independent cross-check for the ath claim (RFC 9449 Section 4.3 step 11):
// computed here via Node's native node:crypto hash API, not the WebCrypto
// subtle.digest() call generateDPoPProof itself uses, so a regression in
// either the hashing or the base64url encoding fails this comparison.
function independentAth(accessToken) {
  const digest = createHash('sha256').update(accessToken).digest()
  return base64URLEncode(new Uint8Array(digest))
}

async function verifyDPoPProofGeneration() {
  const signingMaterial = await generateES256SigningMaterial('verify-dpop-test')
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    signingMaterial.publicJWK,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )

  async function verifySignature(jwt) {
    const [headerSeg, payloadSeg, signatureSeg] = jwt.split('.')
    const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`)
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      publicKey,
      base64URLDecode(signatureSeg),
      signingInput,
    )
  }

  // Token-endpoint proof: no access token yet, no nonce.
  const tokenProofJWT = await generateDPoPProof(signingMaterial, {
    htm: 'POST',
    htu: 'https://issuer.example/oauth2/token',
  })
  const tokenProof = decodeJWTWithoutValidation(tokenProofJWT)

  check('token-endpoint proof: typ header is dpop+jwt (RFC 9449 §4.2)', tokenProof?.header.typ === 'dpop+jwt')
  check('token-endpoint proof: alg header is ES256', tokenProof?.header.alg === 'ES256')
  check(
    'token-endpoint proof: header carries only the public JWK (x, y, crv, kty)',
    tokenProof?.header.jwk &&
      typeof tokenProof.header.jwk.x === 'string' &&
      typeof tokenProof.header.jwk.y === 'string' &&
      tokenProof.header.jwk.crv === 'P-256' &&
      tokenProof.header.jwk.kty === 'EC' &&
      tokenProof.header.jwk.d === undefined,
  )
  check('token-endpoint proof: htm claim matches the request method', tokenProof?.payload.htm === 'POST')
  check('token-endpoint proof: htu claim matches the request URI', tokenProof?.payload.htu === 'https://issuer.example/oauth2/token')
  check('token-endpoint proof: jti claim is present', typeof tokenProof?.payload.jti === 'string' && tokenProof.payload.jti.length > 0)
  check(
    'token-endpoint proof: iat claim is a recent Unix timestamp',
    typeof tokenProof?.payload.iat === 'number' && Math.abs(Date.now() / 1000 - tokenProof.payload.iat) < 10,
  )
  check('token-endpoint proof: no ath claim without an access token', tokenProof?.payload.ath === undefined)
  check('token-endpoint proof: no nonce claim unless requested', tokenProof?.payload.nonce === undefined)
  check(
    'token-endpoint proof: signature verifies against the proof\'s own public key',
    await verifySignature(tokenProofJWT),
  )

  // jti must be single-use: two proofs over the identical htm/htu must not
  // collide (RFC 9449 Section 4.3 check 10).
  const secondTokenProofJWT = await generateDPoPProof(signingMaterial, {
    htm: 'POST',
    htu: 'https://issuer.example/oauth2/token',
  })
  const secondTokenProof = decodeJWTWithoutValidation(secondTokenProofJWT)
  check(
    'two proofs over the same htm/htu still get distinct jti values',
    tokenProof.payload.jti !== secondTokenProof.payload.jti,
  )

  // Resource-endpoint proof: carries ath over a real access token, plus a
  // server-issued nonce (RFC 9449 Sections 4.3 and 8).
  const accessToken = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtYWNoaW5lLWNsaWVudCJ9.sig-placeholder'
  const resourceProofJWT = await generateDPoPProof(signingMaterial, {
    htm: 'GET',
    htu: 'https://issuer.example/oauth2/resource',
    accessToken,
    nonce: 'server-nonce-abc123',
  })
  const resourceProof = decodeJWTWithoutValidation(resourceProofJWT)

  check('resource-endpoint proof: htm claim is GET', resourceProof?.payload.htm === 'GET')
  check(
    'resource-endpoint proof: ath claim matches an independently computed SHA-256 of the access token',
    resourceProof?.payload.ath === independentAth(accessToken),
  )
  check('resource-endpoint proof: nonce claim echoes the server-provided nonce', resourceProof?.payload.nonce === 'server-nonce-abc123')
  check(
    'resource-endpoint proof: signature verifies against the same key as the token-endpoint proof',
    await verifySignature(resourceProofJWT),
  )
}

function verifyFlowDeepLinks() {
  // Round-trip: both optional selectors present.
  const fullParams = new URLSearchParams({
    protocol: 'oauth2',
    flow: 'client-credentials',
    client_auth: 'private_key_jwt',
    token_mode: 'dpop',
  })
  const fullParsed = parseFlowDeepLink(fullParams)
  check(
    'parseFlowDeepLink reads protocol, flow, client_auth, and token_mode together',
    fullParsed?.protocolId === 'oauth2' &&
      fullParsed.flowId === 'client-credentials' &&
      fullParsed.clientAuth === 'private_key_jwt' &&
      fullParsed.accessTokenMode === 'dpop',
  )
  check(
    'buildLookingGlassPath round-trips a full deep link back through parseFlowDeepLink',
    (() => {
      const path = buildLookingGlassPath(fullParsed)
      const reparsed = parseFlowDeepLink(new URL(path, 'http://localhost').searchParams)
      return reparsed?.clientAuth === 'private_key_jwt' && reparsed.accessTokenMode === 'dpop'
    })(),
  )

  // Missing required protocol/flow must yield null, not a partial object.
  check(
    'parseFlowDeepLink returns null when flow is missing',
    parseFlowDeepLink(new URLSearchParams({ protocol: 'oauth2' })) === null,
  )
  check(
    'parseFlowDeepLink returns null when protocol is missing',
    parseFlowDeepLink(new URLSearchParams({ flow: 'client-credentials' })) === null,
  )

  // An unrecognized selector value must be dropped, not passed through to
  // the executor as an unsupported configuration.
  const garbageParsed = parseFlowDeepLink(new URLSearchParams({
    protocol: 'oauth2',
    flow: 'client-credentials',
    client_auth: 'not_a_real_method',
    token_mode: 'not_a_real_mode',
  }))
  check(
    'parseFlowDeepLink ignores an unrecognized client_auth value',
    garbageParsed?.protocolId === 'oauth2' && garbageParsed.clientAuth === undefined,
  )
  check(
    'parseFlowDeepLink ignores an unrecognized token_mode value',
    garbageParsed?.accessTokenMode === undefined,
  )

  // buildLookingGlassPath omits optional params entirely when unset, rather
  // than emitting empty query parameters.
  const bareParams = buildLookingGlassPath({ protocolId: 'oauth2', flowId: 'authorization-code' })
  check(
    'buildLookingGlassPath omits client_auth/token_mode when neither selector is set',
    bareParams === '/looking-glass?protocol=oauth2&flow=authorization-code',
  )

  // buildFlowExecutionPath sends every protocol, including SSF, to Looking Glass.
  check(
    'buildFlowExecutionPath routes ssf to Looking Glass',
    buildFlowExecutionPath({ protocolId: 'ssf', flowId: 'stream-management' }) === '/looking-glass?protocol=ssf&flow=stream-management',
  )
  check(
    'buildFlowExecutionPath routes every other protocol to Looking Glass',
    buildFlowExecutionPath({ protocolId: 'oauth2', flowId: 'client-credentials' }) === '/looking-glass?protocol=oauth2&flow=client-credentials',
  )

  // resolveFlowHandoff mirrors the backend's runURLFor output end to end:
  // a runnable flow result with client_auth/token_mode on run_url produces
  // a matching FlowRunHandoff, and a non-runnable result is rejected.
  const runnableResult = {
    id: 'flows/oauth2/client-credentials',
    type: 'flow',
    name: 'Client Credentials Grant',
    axis_chips: [],
    match_reasons: [],
    runnable: true,
    href: '/protocols/oauth2/flows/client-credentials',
    run_url: '/looking-glass?protocol=oauth2&flow=client-credentials&token_mode=dpop',
    score: 1,
  }
  const handoff = resolveFlowHandoff(runnableResult)
  check(
    'resolveFlowHandoff extracts token_mode from a runnable palette result\'s run_url',
    handoff?.protocolId === 'oauth2' &&
      handoff.flowId === 'client-credentials' &&
      handoff.accessTokenMode === 'dpop' &&
      handoff.lookingGlassPath === '/looking-glass?protocol=oauth2&flow=client-credentials&token_mode=dpop',
  )
  check(
    'resolveFlowHandoff returns null for a non-runnable palette result',
    resolveFlowHandoff({ ...runnableResult, runnable: false }) === null,
  )
  check(
    'resolveFlowHandoff returns null for a concept result even if marked runnable',
    resolveFlowHandoff({ ...runnableResult, type: 'concept' }) === null,
  )
}

async function main() {
  await verifyDPoPProofGeneration()
  verifyFlowDeepLinks()

  console.log(`\n${checksRun} checks run, ${failures.length} failure(s).`)
  if (failures.length > 0) {
    console.log(`Failed: ${failures.join(', ')}`)
    process.exit(1)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(2)
})
