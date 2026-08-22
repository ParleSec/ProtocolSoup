## Summary

The ProtocolSoup wallet harness (`backend/cmd/walletharness`, image `ghcr.io/parlesec/protocolsoup-wallet`) exposes an unauthenticated HTTP endpoint, `POST /api/resolve`, that accepts a caller-supplied `request_uri` and performs a server-side HTTP fetch to resolve an OID4VP request object (and related OID4VCI metadata). External fetches are enabled by default (`WALLET_ALLOW_EXTERNAL_VERIFIERS=true`).

The destination allow-list inspected the URL **hostname string** with Go's `net.ParseIP`, which only matches literal IP address text. DNS names were not resolved, HTTP redirects were followed by the default client (up to ten hops) without re-checking the next URL, and the TCP dial was not pinned to a validated address. Non-success HTTP responses from the fetched URL were copied into the JSON `error_description` returned to the caller.

An unauthenticated network client that can reach the wallet HTTP API can therefore cause the wallet process to issue HTTP GET or POST requests to destinations that the existing checks intended to block (loopback, private, link-local, and other non-public addresses), and can read a truncated copy of a non-success response body.

This is CWE-918 (Server-Side Request Forgery). It does not grant arbitrary remote code execution by itself.

## Impact

**Who is affected.** Any deployment of `protocolsoup-wallet` built from git tags **v2.0.0 through v4.1.0**, the Go module `github.com/ParleSec/ProtocolSoup` at those same versions, `ghcr.io/parlesec/protocolsoup-wallet` tags matching those versions, and `latest` / hosted `https://wallet.protocolsoup.com` until a patched build is deployed. Tag **v1.0.0** does not contain this code path. Other ProtocolSoup images (federation, VC, SCIM, SSF, SPIFFE, gateway, frontend) do not run this binary.

**What an attacker can do.**

- Trigger server-side HTTP requests to internal or loopback HTTP services reachable from the wallet host (link-local metadata endpoints, docker-internal listeners, private management APIs).
- Use `request_uri_method=post` to send an `application/x-www-form-urlencoded` POST (`wallet_nonce` only). The client does not send an attacker-chosen body or arbitrary methods.
- Observe **non-2xx** response bodies (newlines stripped) in `error_description`. This is a limited oracle, not a general file-read primitive.
- 2xx responses are only returned to the caller when they look like a compact JWS (`application/oauth-authz-req+jwt`). Other 2xx bodies are not reflected.

**What this is not.** It is not authentication bypass of the ProtocolSoup issuer or Looking Glass. It does not by itself mint tokens or credentials. Integrity impact is limited to the wallet process acting as an HTTP client against addresses it should have refused. Confidentiality and integrity impact are bounded by what internal services expose or accept via unauthenticated HTTP. There is no availability impact.

**Primary entry point:** `POST /api/resolve` with JSON `request_uri` (also `openid4vp` URIs that embed `request_uri`).

**Same helper, secondary surfaces:** `GET /authorize` (validates but does not fetch), OID4VCI import / token / nonce / credential / PAR / JWKS / notification URL fetches, `did:web` document GET, and untrusted OID4VP `response_uri` checks. Treat those as the same root cause, not separate CVEs.

## Root cause

1. **Hostname-only IP check.** `net.ParseIP` returns nil for DNS names, so loopback/private blocks never ran unless the host was already a literal IP.
2. **No DNS resolution or dial pinning.** The client resolved names at connect time with no second check that the connected address was public.
3. **Redirect follow.** The shared `http.Client` used Go's default redirect policy and did not re-run the URL policy on `Location`.
4. **HTTP exception for names starting with `127.`.** Untrusted `http://` was allowed when the hostname had that prefix, which is not a loopback address. RFC 9101 §5 requires `request_uri` to be an `https` URI unless the contents are pre-registered; ProtocolSoup treats only the configured target/issuer origin as pre-registered.
5. **Error-body oracle.** Failed fetches embedded the upstream body in `error_description`.

## Patches

Patched wallet builds (**v4.1.1** and later):

- Require `https` for every untrusted (non-target, non-issuer) URL.
- Resolve the hostname and refuse the request if **any** address is loopback, private, link-local, multicast, unspecified, shared address space (`100.64.0.0/10`), or otherwise non-global unicast.
- Use an HTTP client that re-validates each redirect hop and dials only an address that passed that check (no proxy).
- Return `request_uri` HTTP status on fetch failure **without** reflecting the upstream body.

The fix ships in **v4.1.1**. Self-hosted operators who track `latest` pick up the fix when `master` is rebuilt after the release. Operators pinned to `v2.0.0`–`v4.1.0` must upgrade to **v4.1.1** or later. Per `SECURITY.md`, older minors are not separately patched.

## Workarounds

These reduce exposure; they are not a substitute for the patched binary on an Internet-facing wallet.

1. Set `WALLET_ALLOW_EXTERNAL_VERIFIERS=false`. Only the configured `WALLET_TARGET_BASE_URL` / `WALLET_ISSUER_BASE_URL` hosts remain fetchable. Third-party `request_uri` and external OID4VCI import stop working.
2. Do not publish the wallet listen port to untrusted networks. Keep it on a private network or behind an authenticating proxy.
3. Restrict egress from the wallet task (no access to link-local metadata, no access to other internal listeners).

The hosted ProtocolSoup wallet cannot use workaround (1) if it must fetch third-party verifiers; it must run a patched wallet image.

## Credit

Reported by [EQSTLab](https://github.com/EQSTLab).

## References

- CWE-918: Server-Side Request Forgery (SSRF)
- RFC 9101 §5 (JWT-secured Authorization Request): `request_uri` MUST be an https URI unless the contents are pre-registered
- OpenID for Verifiable Presentations 1.0 §5.10 (request object passed by reference)
- Wallet service docs: https://docs.protocolsoup.com/deploy/services/wallet/
