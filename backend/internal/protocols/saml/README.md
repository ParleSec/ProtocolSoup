# SAML 2.0 Protocol Implementation

ProtocolSoup's SAML plugin runs a SAML 2.0 identity provider and a SAML 2.0 service provider as two separate entities. They exchange signed messages over the HTTP-Redirect and HTTP-POST bindings, and each trusts the other only through the metadata the other publishes.

## Overview

| Specification | Sections exercised |
|---------------|--------------------|
| SAML 2.0 Core (`saml-core-2.0-os`, Errata 05) | §1.3 identifiers and time values, §2 assertions, §3.2-3.4 request/response and AuthnRequest, §3.7 Single Logout, §5.4 XML signatures |
| SAML 2.0 Bindings (`saml-bindings-2.0-os`) | §3.4 HTTP-Redirect (DEFLATE encoding and query signatures), §3.5 HTTP-POST |
| SAML 2.0 Profiles (`saml-profiles-2.0-os`) | §4.1 Web Browser SSO, §4.4 Single Logout |
| SAML 2.0 Metadata (`saml-metadata-2.0-os`) | §2.3-2.4 descriptors, §4.1 publication at the entityID |
| W3C XML Signature, Exclusive XML Canonicalization 1.0 | Enveloped RSA-SHA256 signatures |

XML signing and verification use [`github.com/russellhaering/goxmldsig`](https://github.com/russellhaering/goxmldsig) over [`github.com/beevik/etree`](https://github.com/beevik/etree). The test suite also verifies an assertion signed by .NET `System.Security.Cryptography.Xml.SignedXml` (`xmldsig/testdata/dotnet-signed-response.xml`). .NET in turn verifies signatures produced here, so canonicalization is checked against an independent implementation.

## Service Deployment

The plugin is part of the `server-federation` service and the `server` monolith, mounted at `/saml`. Signing keys and self-signed certificates for both roles persist under `{SHOWCASE_DATA_DIR}/saml/`:

| File | Contents |
|------|----------|
| `idp.key.pem`, `idp.cert.pem` | IdP RSA-2048 signing key and certificate |
| `sp.key.pem`, `sp.cert.pem` | SP RSA-2048 signing key and certificate |

Certificates are valid for five years and are regenerated within 30 days of expiry. Without `SHOWCASE_DATA_DIR` both pairs are generated on every start, so any external party that cached the metadata must fetch it again.

## Architecture

| Role | entityID (also its metadata URL) | Package |
|------|----------------------------------|---------|
| Identity provider | `{BASE_URL}/saml/idp/metadata` | `idp` |
| Service provider | `{BASE_URL}/saml/sp/metadata` | `sp` |

- Each entityID is the URL its metadata is published at (SAML Metadata §4.1.1).
- Each role resolves the other by dereferencing that URL over HTTP, with its own `metadata.Resolver`. The resolver checks the `application/samlmetadata+xml` media type, the entityID and `validUntil`, and caches the result for `cacheDuration`.
- The peer's signing certificate comes only from that metadata. A certificate in a message's `<ds:KeyInfo>` is accepted only if it equals one published there.
- The roles share no state. The IdP holds the sessions it issued assertions for; the SP holds the sessions it accepted.
- `idp` and `sp` never import each other. `TestRolesDoNotImportEachOther` fails the build if either does.

## Package Structure

Each package has one job and depends only on the packages listed above it:

| Package | Purpose |
|---------|---------|
| `message` | Constants, identifier and time rules, XML parse/serialize, message builders (`samlp:`/`saml:` prefixes), read-only message types |
| `xmldsig` | Enveloped XML signatures (SAML Core §5.4) over goxmldsig, HTTP-Redirect query signatures, per-entity credentials persisted under the data directory |
| `binding` | HTTP-Redirect and HTTP-POST encode/decode/send, RelayState limit, `Authenticate` (signature + Destination), validation `Report`, Looking Glass event hook |
| `metadata` | Metadata publication (`BuildIdP`, `BuildSP`) and consumption (`Parse`, `Resolver`, `Peer`) |
| `session` | Sessions, pending request IDs, replay cache, processed-logout records |
| `logout` | LogoutRequest/LogoutResponse processing used by whichever role receives the message |
| `idp` | Identity provider: AuthnRequest processing, error Responses, assertion issuance, IdP side of Single Logout, its HTTP endpoints and login page |
| `sp` | Service provider: AuthnRequest creation, Response processing rules (`acs.go`), SP side of Single Logout, its HTTP endpoints |
| `saml` (root) | `plugin.go` wiring and routes, `flows.go` flow and demo definitions, `lookingglass.go` Looking Glass and demo endpoints, end-to-end tests |

## API Endpoints

### Identity provider (`/saml/idp`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/saml/idp/metadata` | IdP `EntityDescriptor` |
| GET | `/saml/idp/sso` | SingleSignOnService, HTTP-Redirect binding |
| POST | `/saml/idp/sso` | SingleSignOnService, HTTP-POST binding |
| POST | `/saml/idp/login` | Authenticate the principal (`email`, `password`) and post the signed Response to the SP |
| GET | `/saml/idp/initiate` | Start IdP-initiated SSO (`RelayState` optional) |
| GET, POST | `/saml/idp/slo` | SingleLogoutService |

### Service provider (`/saml/sp`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/saml/sp/metadata` | SP `EntityDescriptor` |
| GET | `/saml/sp/login` | Send a signed AuthnRequest (`binding=redirect` default, or `post`; `RelayState` optional, at most 80 bytes) |
| POST | `/saml/sp/acs` | AssertionConsumerService. HTTP-POST only: "The HTTP Redirect binding MUST NOT be used" for the Response (Profiles §4.1.2) |
| GET | `/saml/sp/logout` | Send a signed LogoutRequest for `session_id` (`binding=redirect` default, or `post`) |
| GET, POST | `/saml/sp/slo` | SingleLogoutService |

The ACS answers with JSON: `success`, the `validation` report (every check with its spec reference), `relayState`, and the created `session`. A rejected Response returns HTTP 403 with the same report.

### Demo and Looking Glass

| Method | Path | Description |
|--------|------|-------------|
| GET | `/saml/demo/users` | Demo user presets |
| GET | `/saml/demo/sessions` | Sessions held by the SP (`sp`) and the IdP (`idp`) |
| GET | `/saml/looking-glass/authn-request` | SP builds and signs an AuthnRequest (`binding`, `relay_state`) |
| POST | `/saml/looking-glass/authenticate` | IdP processes `SAMLRequest`+`RelayState` or `redirect_url` (or starts IdP-initiated SSO when neither is sent), authenticates `username`/`password`, issues the signed Response; the SP processes it |
| GET | `/saml/looking-glass/logout-request` | SP (`initiator=sp`) or IdP (`initiator=idp`) builds and signs a LogoutRequest (`session_id`, `binding`, `relay_state`) |
| POST | `/saml/looking-glass/logout` | The role named in the request's `Destination` processes it; the requester processes the LogoutResponse |

The Looking Glass endpoints call the same role code as the binding endpoints, in one request, and return each side's real validation report. Looking Glass events use the `X-Looking-Glass-Session` header or `lg_session` query parameter.

## Signatures

- **Enveloped signatures** (Core §5.4.1). `<ds:Signature>` is inserted immediately after `<saml:Issuer>`. Exclusive Canonicalization is used for `SignedInfo` and as a transform (§5.4.3), with RSA-SHA256 and SHA-256 digests.
- **Single reference** (§5.4.2): exactly one `<ds:Reference>`, whose URI must be `#` plus the signed element's `ID`.
- **Transforms** (§5.4.4): verifiers reject any transform other than enveloped-signature and exclusive C14N.
- **`<ds:Object>`** is rejected (Core Errata E91).
- **Duplicate IDs**: an `ID` declared more than once in the document is rejected (§1.3.4).
- **XSW defence**: after verification, content is read only from the element goxmldsig rebuilds from the digested bytes.
- **HTTP-Redirect** (Bindings §3.4.4.1): the XML carries no signature. The signature covers `SAMLRequest|SAMLResponse=…&RelayState=…&SigAlg=…` and is verified over the URL-encoded values exactly as received. RSA-SHA256/384/512 are accepted.

## Processing Rules

### IdP, on an AuthnRequest

1. Read the unauthenticated `Issuer` only to identify the SP. It must be the registered SP, with `Format` omitted or `entity` (Profiles §4.1.4.1).
2. Resolve the SP's metadata. Verify the signature against its certificate, and check `Destination` against the SingleSignOnService URL.
3. If the signature or `Destination` fails, discard the request with HTTP 400, because the responder "MUST NOT rely on the contents" (Core §3.2.1).
4. If the request is unsigned, return a signed error Response (`Requester`/`RequestDenied`) to the SP's default ACS. The SP publishes `AuthnRequestsSigned="true"` (Metadata §2.4.4, Errata E7).
5. Check `Version`, `ProtocolBinding`, and `AssertionConsumerServiceURL`/`AssertionConsumerServiceIndex` against the SP metadata (Profiles §4.1.4.1). Also check `NameIDPolicy` and `IsPassive`; each failure gets an error Response with the matching status code.

### IdP, issuing the Response

- One assertion: `Issuer`, an email-format `NameID`, and a bearer `SubjectConfirmationData` with `Recipient`, `NotOnOrAfter` (5 minutes) and `InResponseTo` (when solicited).
- `Conditions` with `AudienceRestriction` naming the SP.
- An `AuthnStatement` with `SessionIndex`.
- An `AttributeStatement` with OID-named attributes: `uid`, `mail`, `displayName`, `givenName`, `sn`.
- The assertion is signed (the SP wants signed assertions), then the Response is signed. Both are delivered over HTTP-POST with the received RelayState echoed exactly (Bindings §3.5.3).

### SP, on a Response (Profiles §4.1.4.3, §4.1.4.5)

| Check | Reference |
|-------|-----------|
| HTTP-POST binding | Profiles §4.1.2 |
| Response signature (when present) against IdP metadata; `Destination` equals the ACS URL | Core §3.2.2, Bindings §3.5.5.2 |
| `Version` 2.0; `Issuer` is the IdP with `Format` omitted or `entity` (required when signed) | Profiles §4.1.4.2 (Errata E17) |
| `InResponseTo` matches an outstanding AuthnRequest, consumed once; `RelayState` equals the value sent | Core §3.2.2, Bindings §3.5.3 |
| Status `Success`; an error Response must carry no assertion | Core §3.2.2.2, Profiles §4.1.4.2 |
| Each assertion carries its own valid signature | Metadata §2.4.4 (Errata E7), Profiles §4.1.4.5 |
| A bearer `SubjectConfirmationData`: `Recipient` equals the ACS URL, `NotOnOrAfter` not passed, no `NotBefore`, `InResponseTo` matches (absent when unsolicited) | Profiles §4.1.4.2-4.1.4.3, §4.1.5 |
| `Conditions` time window; every `AudienceRestriction` includes the SP | Core §2.5.1.2, §2.5.1.4 |
| `AuthnStatement` present with `SessionIndex` | Profiles §4.1.4.2 |
| Assertion ID not replayed; kept until `NotOnOrAfter` | Profiles §4.1.4.5 |

Clock skew is 3 minutes (Core §1.3.3, Errata E92). Any failed check rejects the Response and no session is created. `EncryptedAssertion` is rejected, because the SP publishes no encryption key.

### Single Logout

- Both roles accept LogoutRequest and LogoutResponse on HTTP-Redirect and HTTP-POST.
- Both must be signed on these bindings (Profiles §4.4.3.1, §4.4.3.4).
- `Issuer` must be the peer with `Format` omitted or `entity` (§4.4.4.1-4.4.4.2), and `Destination` must be this SingleLogoutService.
- An expired `NotOnOrAfter` gets a `Requester`/`RequestDenied` LogoutResponse.
- The IdP requires at least one `SessionIndex` from the SP (§4.4.4.1, Errata E38).
- The LogoutResponse goes to the requester's SingleLogoutService for the same binding (`ResponseLocation` if published). Its `InResponseTo` and `RelayState` must match the outstanding request.
- The IdP has one session participant, so there is no further propagation (Core §3.7.3.2).
- The SP remembers each LogoutRequest it processed until that request's `NotOnOrAfter`. It refuses a late-arriving assertion for the same principal and `SessionIndex` (Core §3.7.3.1).

## Example Response

This Response was captured from a local SP-initiated run. `{BASE_URL}` stands for the deployment's base URL. Digest, signature and certificate values are elided (`…`). The XML is indented for reading only; on the wire it is a single line, and re-indenting it would break both signatures.

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_ab06564c5264f290ce5480c7516d286b2c28a2f6" Version="2.0" IssueInstant="2026-10-17T03:07:58Z" Destination="{BASE_URL}/saml/sp/acs" InResponseTo="_91020509702736e67eae46b6948aaf363d7c776a">
  <saml:Issuer>{BASE_URL}/saml/idp/metadata</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_ab06564c5264f290ce5480c7516d286b2c28a2f6">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>…</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>…</ds:SignatureValue>
    <ds:KeyInfo><ds:X509Data><ds:X509Certificate>…</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_7e3a76cf3d42c3d0b0695f3a470c08c6ee89c645" Version="2.0" IssueInstant="2026-10-17T03:07:58Z">
    <saml:Issuer>{BASE_URL}/saml/idp/metadata</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><!-- as above, Reference URI="#_7e3a76cf3d42c3d0b0695f3a470c08c6ee89c645" --></ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_91020509702736e67eae46b6948aaf363d7c776a" NotOnOrAfter="2026-10-17T03:12:58Z" Recipient="{BASE_URL}/saml/sp/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-10-17T03:07:58Z" NotOnOrAfter="2026-10-17T03:12:58Z">
      <saml:AudienceRestriction>
        <saml:Audience>{BASE_URL}/saml/sp/metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-10-17T03:07:58Z" SessionIndex="_509c1a4f9251b77204320e4ef269a3adbc0804f3">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid">
        <saml:AttributeValue>alice</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail">
        <saml:AttributeValue>alice@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.16.840.1.113730.3.1.241" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="displayName">
        <saml:AttributeValue>Alice Johnson</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.5.4.4" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="sn">
        <saml:AttributeValue>Johnson</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="urn:oid:2.5.4.42" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="givenName">
        <saml:AttributeValue>Alice</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

## Development

```bash
# Metadata for each role
curl -i http://localhost:8080/saml/idp/metadata
curl -i http://localhost:8080/saml/sp/metadata

# SP-initiated SSO in a browser (HTTP-Redirect AuthnRequest, HTTP-POST Response)
open "http://localhost:8080/saml/sp/login?binding=redirect"

# IdP-initiated SSO in a browser
open "http://localhost:8080/saml/idp/initiate"

# Sessions held by each role
curl http://localhost:8080/saml/demo/sessions

# Tests: end-to-end bindings over TLS, replay, XSW, tampering, foreign keys,
# unsigned requests, Destination, RelayState, SLO, .NET signature interop
cd backend && go test ./internal/protocols/saml/... -count=1
```

## Not Implemented

- HTTP-Artifact and SOAP bindings (and so back-channel Single Logout)
- `EncryptedAssertion`, `EncryptedID` and metadata signing
- An IdP authentication session: every SSO prompts for credentials, so `IsPassive` requests get `NoPassive`
- More than one SP, so logout has no other participants to propagate to

## Decisions

These are SHOULD-level deviations, recorded here as the committed decision record.

| Requirement | Decision | Reason |
|-------------|----------|--------|
| Profiles §4.1.5 (Errata E90): "Service providers SHOULD have a means of disabling the acceptance of unsolicited responses if circumstances warrant." | The SP always accepts unsolicited Responses. | IdP-initiated SSO is one of the flows this lab exists to demonstrate, and the SP trusts exactly one IdP. Unsolicited Responses still pass every other check, and replay detection is the defence the Looking Glass flow shows. |
