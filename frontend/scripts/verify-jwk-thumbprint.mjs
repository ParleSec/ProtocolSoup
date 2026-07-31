#!/usr/bin/env node
// Verifies src/utils/crypto.ts's jwkThumbprint() against RFC 7638 known-answer
// vectors and its own documented edge-case contract.
//
// This imports the actual shipped implementation (not a reimplementation
// local to this script) via Node's native TypeScript type-stripping, so a
// regression in jwkThumbprint itself -- a wrong member order, a dropped kty
// branch, a hash/encoding mistake -- fails this check. The TokenInspector
// cnf.jkt panel (backend/internal/crypto/keys.go's Go Thumbprint(), mirrored
// here) renders a match/mismatch verdict entirely on this function's output,
// so a silently-wrong thumbprint would render a false verdict rather than an
// error the PR checklist's self-attestation can't be relied on alone to catch
// for external contributions -- see CONTRIBUTING.md and the CI step that runs
// this alongside verify-refs.
//
// Vector provenance (each computed independently against the cited RFC's own
// published test key before being pinned as an expected constant below; the
// RSA vector's expected value is the RFC's own published thumbprint, which
// both confirms this script's method and pins the shipped implementation
// against it):
//   - RSA:  RFC 7638 Section 3.1 example key and its published thumbprint.
//   - EC:   RFC 7515 Appendix A.3 ES256 example public key (P-256).
//   - OKP:  RFC 8037 Appendix A.1 Ed25519 example public key.
//
// The same three vectors, with the identical expected constants, are also
// pinned in backend/internal/crypto/keys_test.go's TestThumbprintSpecVectors
// against Go's Thumbprint(). That test and this script are the cross-check:
// TypeScript and Go are asserted against the same known answers rather than
// each being merely self-consistent, so a canonicalization or encoding
// mismatch between the two implementations fails on whichever side
// regressed instead of passing silently because nothing compares them to
// each other.
//
// Usage: npm run verify-jwk-thumbprint

import { jwkThumbprint } from '../src/utils/crypto.ts'

const KNOWN_ANSWER_VECTORS = [
  {
    name: 'RSA (RFC 7638 §3.1 example key)',
    jwk: {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
    },
    // Published verbatim in RFC 7638 Section 3.1: "the value ... base64url
    // encoded ... is: NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs".
    expected: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
  },
  {
    name: 'EC P-256 (RFC 7515 Appendix A.3 public key)',
    jwk: {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    },
    expected: 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
  },
  {
    name: 'OKP Ed25519 (RFC 8037 Appendix A.1 public key)',
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    },
    expected: 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
  },
  {
    name: 'EC P-256 with extra members and scrambled field order',
    // Same key as the RFC 7515 vector above, but with alg/use/kid noise
    // mixed in and the source object's own member order scrambled (x
    // before crv, kty last). RFC 7638 Section 3.2 defines the thumbprint
    // over exactly {crv, kty, x, y} for an EC key, nothing else, in that
    // lexicographic order -- this must still produce the identical digest
    // as the clean vector above. It would not if a future change stopped
    // explicitly destructuring the required members into a fresh object
    // and instead forwarded the caller's object (e.g. via spread), which
    // would let extra members and input order leak into what gets hashed.
    jwk: {
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      alg: 'ES256',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      use: 'sig',
      crv: 'P-256',
      kid: 'test-key-1',
      kty: 'EC',
    },
    expected: 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U',
  },
]

// Edge cases from jwkThumbprint's own doc comment: an unsupported or
// malformed key must return null (a distinct "cannot compute" state), never
// throw and never guess a value that could render as a false match or
// mismatch in the TokenInspector panel.
const NULL_RESULT_CASES = [
  { name: 'unsupported kty (oct)', jwk: { kty: 'oct', k: 'GawgguFyGrWKav7AX4VKUg' } },
  { name: 'missing kty', jwk: { n: 'abc', e: 'AQAB' } },
  { name: 'RSA missing n', jwk: { kty: 'RSA', e: 'AQAB' } },
  { name: 'RSA missing e', jwk: { kty: 'RSA', n: 'abc' } },
  { name: 'EC missing y', jwk: { kty: 'EC', crv: 'P-256', x: 'abc' } },
  { name: 'OKP missing x', jwk: { kty: 'OKP', crv: 'Ed25519' } },
]

async function main() {
  const failures = []

  for (const vector of KNOWN_ANSWER_VECTORS) {
    const computed = await jwkThumbprint(vector.jwk)
    if (computed === vector.expected) {
      console.log(`[PASS] ${vector.name}`)
    } else {
      failures.push(vector.name)
      console.log(`[FAIL] ${vector.name}`)
      console.log(`       expected: ${vector.expected}`)
      console.log(`       computed: ${computed}`)
    }
  }

  for (const testCase of NULL_RESULT_CASES) {
    const computed = await jwkThumbprint(testCase.jwk)
    if (computed === null) {
      console.log(`[PASS] ${testCase.name} -> null`)
    } else {
      failures.push(testCase.name)
      console.log(`[FAIL] ${testCase.name}`)
      console.log(`       expected: null (cannot compute)`)
      console.log(`       computed: ${computed}`)
    }
  }

  console.log(`\n${KNOWN_ANSWER_VECTORS.length + NULL_RESULT_CASES.length} checks run, ${failures.length} failure(s).`)
  if (failures.length > 0) {
    console.log(`Failed: ${failures.join(', ')}`)
    process.exit(1)
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(2)
})
