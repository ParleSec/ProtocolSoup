# Use the ProtocolSoup Wallet Harness

This origin ({{ORIGIN}}) is an OID4VCI issuer client and OID4VP holder. It is not Looking Glass and not an MCP server. MCP is {{SITE}}/mcp and is read-only catalog/decode; it does not drive this wallet.

Human UI: {{ORIGIN}}/
Machine recipes: {{ORIGIN}}/llms-full.txt (this file)
Runtime contract: {{DOCS}}
Reviewed template: https://github.com/ParleSec/ProtocolSoup/blob/master/backend/cmd/walletharness/agent-skills/use-wallet-harness.md

The skills index at {{ORIGIN}}/.well-known/agent-skills/index.json publishes a `sha256` digest of the exact bytes served for this artifact (after origin substitution). Pin the git SHA of the template, or verify the served digest, before ingesting it.

## Capabilities

- Issue `mso_mdoc` and SD-JWT VC credentials from a live issuer.
- Present stored credentials to a live verifier (`direct_post` / `direct_post.jwt`, including HAIP).
- Isolate demo runs with `X-Wallet-Session` on API calls. The browser UI uses an HttpOnly cookie instead. Looking Glass runs also accept `looking_glass_session_id` in the JSON body.
- Return the current store as JSON from `GET {{ORIGIN}}/api/session`.

QR scanning and `openid4vp://` / `openid-credential-offer://` deeplinks are human handoffs. Agents use the HTTP surface below.

`GET {{ORIGIN}}/authorize` is an OID4VP protocol hop for a live `request_uri`. It is not a documentation page.

## Protocol artifacts

This file is first-party. It does not contain live offers, request objects, or credentials. Those are returned by the JSON APIs below as the wallet received and stored them.

## Health

    GET {{ORIGIN}}/health

JSON `{"status":"ok"}`. Optional `commit` is the deployed source SHA.

## Issue a credential (OID4VCI)

Bootstrap against the configured ProtocolSoup issuer:

    POST {{ORIGIN}}/api/issue
    Content-Type: application/json
    X-Wallet-Session: {opaque-id}

    {
      "credential_format": "mso_mdoc",
      "credential_configuration_id": "MobileDrivingLicenceMsoMdoc"
    }

Omitted `credential_format` uses the wallet default (`mso_mdoc`). `force_issue: true` mints a new credential when the session already has one.

Redeem an offer (Looking Glass pre-authorized path):

    POST {{ORIGIN}}/api/import
    Content-Type: application/json
    X-Wallet-Session: {opaque-id}

    {
      "offer": "openid-credential-offer://?credential_offer=...",
      "tx_code": "optional",
      "looking_glass_session_id": "optional-lg-session"
    }

Exactly one of `offer`, `credential`, `credential_issuer`, or `discovery_url`+`resource_endpoint`+`scope`.

A successful import returns the stored credential plus `_protocol_exchanges` (wallet-to-issuer HTTP hops) and `_looking_glass_events`. An `authorization_code` grant includes `authorization_url`; the issuer then redirects to `GET {{ORIGIN}}/api/oid4vci/callback`.

HAIP configurations require attester JWKs on this process. Without them import returns HTTP 400 with `error` `invalid_request` explaining that the configuration requires HAIP attestation material.

## Present a credential (OID4VP)

One-click submit (Looking Glass / automation):

    POST {{ORIGIN}}/submit
    Content-Type: application/json

    {
      "request_id": "{verifier-request-id}",
      "request": "{signed-request-jwt-or-omit-if-request_uri-already-resolved}",
      "mode": "one_click",
      "looking_glass_session_id": "optional-lg-session"
    }

`mode=one_click` bootstraps a matching credential if the store has no DCQL match, builds the presentation, and POSTs to the verifier `response_uri`. For `direct_post.jwt` the wallet encrypts the Authorization Response.

Stepwise alternative: `mode=stepwise` with `step` of `bootstrap`, `issue_credential`, `build_presentation`, or `submit_response`.

Resolve then present (wallet UI path):

    POST {{ORIGIN}}/api/resolve
    {"request_uri": "https://verifier.example/request/...", "request_uri_method": "post"}

    POST {{ORIGIN}}/api/present
    {"request_id": "...", "approve_external_trust": false}

## Errors

API errors are JSON objects with a stable `error` token and a prose `error_description`. They are not RFC 9457 Problem Details. Common tokens: `invalid_request`, `method_not_allowed`, `server_error`, `wallet_submission_failed`. This origin does not currently send `Retry-After` or advertise a published rate-limit.

## Related hosts

- Looking Glass: {{SITE}}/looking-glass
- Protocol catalog: {{SITE}}/api/protocols
- Site llms.txt: {{SITE}}/llms.txt
- Docs llms.txt: https://docs.protocolsoup.com/llms.txt
- Agent skills on the main site: {{SITE}}/.well-known/agent-skills/index.json
- This host does not serve `/mcp`.
