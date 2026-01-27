# SAML 2.0 Protocol Implementation

A standards-compliant implementation of [SAML 2.0](https://docs.oasis-open.org/security/saml/v2.0/) (Security Assertion Markup Language) for federated identity and Single Sign-On (SSO). This implementation operates as both a Service Provider (SP) and Identity Provider (IdP) for demonstration and educational purposes.

## Overview

This implementation provides:

- **Dual Role Operation**: Functions as both SP and IdP for complete protocol demonstration
- **HTTP Bindings**: HTTP-POST and HTTP-Redirect bindings per SAML 2.0 Bindings specification
- **XML Digital Signatures**: RSA-SHA256 signing and validation per XML-DSig specification
- **Single Sign-On (SSO)**: SP-initiated and IdP-initiated authentication flows
- **Single Logout (SLO)**: Federated logout across multiple session participants
- **Metadata Generation**: Standards-compliant SP and IdP metadata documents
- **Security Validation**: InResponseTo validation, replay prevention, condition checking
- **Looking Glass Integration**: Real-time flow visualization for educational purposes

## Service Deployment

The SAML implementation runs as part of the protocol gateway. It can be accessed:

- **Behind the gateway** (recommended): `/saml/*` is served through the gateway so the frontend uses a single base URL.
- **Standalone testing**: Direct HTTP requests to SAML endpoints for protocol testing.

When configuring external IdPs or SPs, set your Entity ID and endpoints using the base URL from `SHOWCASE_BASE_URL`.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SAML 2.0 Implementation                              │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  External Entities                                                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │  External IdPs  │  │  External SPs   │  │   Browsers      │              │
│  │                 │  │                 │  │                 │              │
│  │  (Okta, Azure)  │  │ (Applications)  │  │ (End Users)     │              │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘              │
│           │                    │                    │                       │
│           └────────────────────┼────────────────────┘                       │
│                                │                                            │
│                    HTTP-POST / HTTP-Redirect Bindings                       │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     SAML Plugin (plugin.go)                         │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │   SSO Service     │  │   ACS Endpoint    │  │  SLO Service    │  │    │
│  │  │   (IdP Role)      │  │   (SP Role)       │  │  (Both Roles)   │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • AuthnRequest    │  │ • Response        │  │ • LogoutRequest │  │    │
│  │  │ • User Login      │  │ • Validation      │  │ • LogoutResponse│  │    │
│  │  │ • Response Gen    │  │ • Session Create  │  │ • Propagation   │  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │  Bindings         │  │  Signature        │  │  Metadata       │  │    │
│  │  │  (bindings.go)    │  │  (signature.go)   │  │  (metadata.go)  │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • HTTP-POST       │  │ • XML-DSig        │  │ • SP Metadata   │  │    │
│  │  │ • HTTP-Redirect   │  │ • RSA-SHA256      │  │ • IdP Metadata  │  │    │
│  │  │ • DEFLATE/Base64  │  │ • Replay Cache    │  │ • Certificates  │  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐                       │    │
│  │  │  SAML Types       │  │  Logout Manager   │                       │    │
│  │  │  (saml.go)        │  │  (logout.go)      │                       │    │
│  │  │                   │  │                   │                       │    │
│  │  │ • AuthnRequest    │  │ • SLO State       │                       │    │
│  │  │ • Response        │  │ • Multi-SP Track  │                       │    │
│  │  │ • Assertion       │  │ • Completion      │                       │    │
│  │  └───────────────────┘  └───────────────────┘                       │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                |                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Session Storage                              │    │
│  │                       (In-Memory Sessions)                          │    │
│  │                                                                     │    │
│  │  ┌─────────────────┐  ┌─────────────────────────────────────────┐   │    │
│  │  │  SAML Sessions  │  │  Session Index Mapping                  │   │    │
│  │  │                 │  │                                         │   │    │
│  │  │ ID (UUID)       │  │ nameIDToSessions: NameID → SessionIDs   │   │    │
│  │  │ NameID          │  │ loginRequests: ReqID → RequestInfo      │   │    │
│  │  │ SessionIndex    │  │ assertionCache: AssertionID → Time      │   │    │
│  │  │ Attributes      │  │ requestIDCache: RequestID → Time        │   │    │
│  │  │ AuthnInstant    │  │                                         │   │    │
│  │  └─────────────────┘  └─────────────────────────────────────────┘   │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

| File | Purpose |
|------|---------|
| `plugin.go` | Main plugin implementing `ProtocolPlugin` interface, route registration, flow definitions, inspectors |
| `handlers.go` | HTTP request handlers for SSO, ACS, SLO, and Looking Glass API endpoints |
| `saml.go` | Core SAML 2.0 type definitions (AuthnRequest, Response, Assertion, etc.) and helper functions |
| `bindings.go` | HTTP-POST and HTTP-Redirect binding implementations per SAML 2.0 Bindings spec |
| `metadata.go` | SP and IdP metadata generation per SAML 2.0 Metadata specification |
| `signature.go` | XML digital signature validation, assertion replay cache, request ID tracking |
| `xmlsig.go` | XML digital signature generation (signing assertions and responses) |
| `logout.go` | Single Logout (SLO) state management and multi-SP coordination |

## API Endpoints

### Metadata & Discovery

| Method | Endpoint | Description | Spec Reference |
|--------|----------|-------------|----------------|
| GET | `/saml/metadata` | SP/IdP metadata document | SAML 2.0 Metadata |

### SSO Service Endpoints (IdP Role)

| Method | Endpoint | Description | Spec Reference |
|--------|----------|-------------|----------------|
| GET | `/saml/sso` | SSO Service (HTTP-Redirect) | SAML 2.0 Bindings §3.4 |
| POST | `/saml/sso` | SSO Service (HTTP-POST) | SAML 2.0 Bindings §3.5 |

### Assertion Consumer Service (SP Role)

| Method | Endpoint | Description | Spec Reference |
|--------|----------|-------------|----------------|
| GET | `/saml/acs` | ACS (HTTP-Redirect) | SAML 2.0 Bindings §3.4 |
| POST | `/saml/acs` | ACS (HTTP-POST) | SAML 2.0 Bindings §3.5 |

### Single Logout Service

| Method | Endpoint | Description | Spec Reference |
|--------|----------|-------------|----------------|
| GET | `/saml/slo` | SLO Service (HTTP-Redirect) | SAML 2.0 Profiles §4.4 |
| POST | `/saml/slo` | SLO Service (HTTP-POST) | SAML 2.0 Profiles §4.4 |

### SP-Initiated Login

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| GET | `/saml/login` | Start SP-initiated SSO | `binding`, `RelayState` |
| POST | `/saml/login` | Process login form submission | `username`, `password` |

### IdP-Initiated SSO

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| GET | `/saml/idp-initiated` | Start IdP-initiated SSO | `sp`, `acs`, `RelayState` |

### Demo/Utility Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/saml/demo/users` | List available demo users |
| GET | `/saml/demo/sessions` | List active SAML sessions |
| GET/POST | `/saml/demo/logout` | Simple logout for demo |

### Looking Glass API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/saml/looking-glass/authn-request` | Create AuthnRequest with full details |
| POST | `/saml/looking-glass/authenticate` | Authenticate and create SAML Response |
| GET | `/saml/looking-glass/logout-request` | Create LogoutRequest with full details |
| POST | `/saml/looking-glass/logout` | Process logout and create LogoutResponse |

## SAML Bindings

### HTTP-Redirect Binding

Per SAML 2.0 Bindings Section 3.4:

1. Serialize message to XML
2. DEFLATE compress (raw, no zlib header)
3. Base64 encode
4. URL encode
5. Append to destination URL as query parameter

**Signature (if signed):**
```
signature = RSA-SHA256(SAMLRequest=value&RelayState=value&SigAlg=value)
```

### HTTP-POST Binding

Per SAML 2.0 Bindings Section 3.5:

1. Sign message with XML digital signature (if configured)
2. Serialize to XML with declaration
3. Base64 encode (no compression)
4. Embed in auto-submitting HTML form

```html
<form method="POST" action="{destination}">
    <input type="hidden" name="SAMLResponse" value="{base64-encoded-xml}"/>
    <input type="hidden" name="RelayState" value="{relay-state}"/>
</form>
```

## Security Features

### XML Digital Signatures (SAML 2.0 Core Section 5)

| Feature | Implementation |
|---------|----------------|
| Signature Algorithm | RSA-SHA256 (SHA-1 supported for legacy) |
| Digest Algorithm | SHA-256 (SHA-1 supported for legacy) |
| Canonicalization | Exclusive XML Canonicalization (exc-c14n) |
| Key Info | X.509 Certificate in signature |

### Security Validations

| Validation | Description | Spec Reference |
|------------|-------------|----------------|
| Signature Verification | Validate XML-DSig on Response/Assertion | Core Section 5 |
| InResponseTo | Match against pending AuthnRequest IDs | Profiles Section 4.1.4.3 |
| Replay Prevention | Track consumed assertion IDs | Profiles Section 4.1.4.5 |
| Conditions | NotBefore, NotOnOrAfter, AudienceRestriction | Core Section 2.5 |
| Subject Confirmation | Recipient, NotOnOrAfter validation | Core Section 2.4.1.2 |
| Version Check | SAML version must be "2.0" | Core Section 3.2.2 |

### Signature Validation Result

```go
type SignatureValidationResult struct {
    Valid             bool     // Overall validation result
    SignatureVerified bool     // Cryptographic signature valid
    DigestVerified    bool     // Content digest matches
    CertificateValid  bool     // Certificate is trusted and not expired
    Algorithm         string   // Signature algorithm used
    DigestAlgorithm   string   // Digest algorithm used
    Errors            []string // Validation errors
    Warnings          []string // Security warnings (e.g., SHA-1 usage)
}
```

## Protocol Flows

### SP-Initiated SSO Flow

```
User          Service Provider        Identity Provider
 │                   │                       │
 │  Access Resource  │                       │
 │──────────────────>│                       │
 │                   │                       │
 │                   │  AuthnRequest         │
 │                   │──────────────────────>│
 │                   │                       │
 │                   │       Login Page      │
 │<──────────────────────────────────────────│
 │                   │                       │
 │  Credentials      │                       │
 │──────────────────────────────────────────>│
 │                   │                       │
 │                   │  SAML Response        │
 │                   │<──────────────────────│
 │                   │                       │
 │                   │  Validate & Session   │
 │                   │──────────────────────>│
 │                   │                       │
 │  Access Granted   │                       │
 │<──────────────────│                       │
```

### IdP-Initiated SSO Flow

```
User          Identity Provider       Service Provider
 │                   │                       │
 │  Login at IdP     │                       │
 │──────────────────>│                       │
 │                   │                       │
 │  Select SP        │                       │
 │──────────────────>│                       │
 │                   │                       │
 │                   │  Unsolicited Response │
 │                   │  (no InResponseTo)    │
 │                   │──────────────────────>│
 │                   │                       │
 │                   │  Validate & Session   │
 │                   │──────────────────────>│
 │                   │                       │
 │  Access Granted   │                       │
 │<──────────────────────────────────────────│
```

### Single Logout Flow

```
User     Initiating SP      Identity Provider      Other SPs
 │            │                    │                   │
 │  Logout    │                    │                   │
 │───────────>│                    │                   │
 │            │                    │                   │
 │            │  LogoutRequest     │                   │
 │            │───────────────────>│                   │
 │            │                    │                   │
 │            │                    │  LogoutRequest    │
 │            │                    │──────────────────>│
 │            │                    │                   │
 │            │                    │  LogoutResponse   │
 │            │                    │<──────────────────│
 │            │                    │                   │
 │            │  LogoutResponse    │                   │
 │            │<───────────────────│                   │
 │            │                    │                   │
 │  Logged Out│                    │                   │
 │<───────────│                    │                   │
```

## Looking Glass Flows

### Executable Flows

| Flow ID | Name | Description |
|---------|------|-------------|
| `sp_initiated_sso` | SP-Initiated SSO | Complete SP-initiated authentication flow |
| `idp_initiated_sso` | IdP-Initiated SSO | Unsolicited response authentication flow |
| `single_logout` | Single Logout (SLO) | Federated logout across session participants |

### Demo Scenarios

| Scenario ID | Name | Description |
|-------------|------|-------------|
| `sp_initiated_sso_demo` | SP-Initiated SSO Demo | Interactive SSO demonstration |
| `idp_initiated_sso_demo` | IdP-Initiated SSO Demo | Unsolicited response demonstration |
| `single_logout_demo` | Single Logout Demo | Multi-SP logout demonstration |
| `assertion_inspection` | SAML Assertion Deep Dive | Detailed assertion structure analysis |
| `metadata_exploration` | Metadata Exploration | SP/IdP metadata examination |

## SAML Message Structures

### AuthnRequest

```xml
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_abc123..."
    Version="2.0"
    IssueInstant="2024-01-15T10:30:00Z"
    Destination="https://idp.example.com/sso"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
    <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>
```

### SAML Response with Assertion

```xml
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_xyz789..."
    Version="2.0"
    IssueInstant="2024-01-15T10:30:05Z"
    Destination="https://sp.example.com/saml/acs"
    InResponseTo="_abc123...">
    <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_def456..." Version="2.0" IssueInstant="2024-01-15T10:30:05Z">
        <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                alice@example.com
            </saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData
                    NotOnOrAfter="2024-01-15T10:35:05Z"
                    Recipient="https://sp.example.com/saml/acs"
                    InResponseTo="_abc123..."/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2024-01-15T10:30:05Z" NotOnOrAfter="2024-01-15T10:35:05Z">
            <saml:AudienceRestriction>
                <saml:Audience>https://sp.example.com/saml</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2024-01-15T10:30:05Z" SessionIndex="_sess123...">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                </saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>alice@example.com</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="name">
                <saml:AttributeValue>Alice Johnson</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>
```

### LogoutRequest

```xml
<samlp:LogoutRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_logout123..."
    Version="2.0"
    IssueInstant="2024-01-15T12:00:00Z"
    Destination="https://idp.example.com/saml/slo"
    NotOnOrAfter="2024-01-15T12:05:00Z">
    <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        alice@example.com
    </saml:NameID>
    <samlp:SessionIndex>_sess123...</samlp:SessionIndex>
</samlp:LogoutRequest>
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHOWCASE_BASE_URL` | Base URL for entity ID and endpoints | (required) |
| `SAML_PRIVATE_KEY_PATH` | Path to RSA private key for signing | (optional) |
| `SAML_CERTIFICATE_PATH` | Path to X.509 certificate | (optional) |
| `SAML_ASSERTION_TTL` | Assertion validity duration | `5m` |
| `SAML_SESSION_TTL` | Session validity duration | `8h` |

### Entity Configuration

The plugin automatically configures endpoints based on the base URL:

| Setting | Value |
|---------|-------|
| Entity ID | `{BASE_URL}/saml` |
| ACS URL | `{BASE_URL}/saml/acs` |
| SLO URL | `{BASE_URL}/saml/slo` |
| SSO URL | `{BASE_URL}/saml/sso` |
| Metadata URL | `{BASE_URL}/saml/metadata` |

## NameID Formats

| Format | URI | Description |
|--------|-----|-------------|
| Email | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | Email address |
| Persistent | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | Persistent opaque identifier |
| Transient | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` | Temporary identifier |
| Unspecified | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | Provider-determined format |

## Status Codes

| Status Code | Description |
|-------------|-------------|
| `Success` | Request succeeded |
| `Requester` | Error on requester side |
| `Responder` | Error on responder side |
| `VersionMismatch` | Unsupported SAML version |
| `AuthnFailed` | Authentication failed |
| `PartialLogout` | Not all sessions terminated |
| `RequestDenied` | Request denied by IdP |

## Inspectors

| Inspector ID | Name | Type | Description |
|--------------|------|------|-------------|
| `saml-assertion` | SAML Assertion Inspector | token | Decode and analyze assertions |
| `saml-request` | SAML Request Inspector | request | Analyze AuthnRequest/LogoutRequest |
| `saml-response` | SAML Response Inspector | response | Analyze Response messages |
| `saml-metadata` | SAML Metadata Inspector | response | Analyze SP/IdP metadata |

## Development

### Running Locally

```bash
# Start with Docker Compose
cd docker
docker compose up -d

# Test metadata endpoint
curl http://localhost:8080/saml/metadata

# List demo users
curl http://localhost:8080/saml/demo/users

# Start SP-initiated SSO (opens in browser)
open http://localhost:8080/saml/login
```

### Testing SSO Flow

```bash
# 1. Get AuthnRequest details
curl "http://localhost:8080/saml/looking-glass/authn-request?binding=post"

# 2. Authenticate and get Response
curl -X POST http://localhost:8080/saml/looking-glass/authenticate \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=alice123"

# 3. List active sessions
curl http://localhost:8080/saml/demo/sessions
```

### Testing SLO Flow

```bash
# 1. Create logout request
curl "http://localhost:8080/saml/looking-glass/logout-request?name_id=alice@example.com"

# 2. Process logout
curl -X POST http://localhost:8080/saml/looking-glass/logout \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name_id=alice@example.com"
```

## Specification Compliance

| Specification | Status |
|---------------|--------|
| SAML 2.0 Core | ✅ Compliant |
| SAML 2.0 Bindings | ✅ Compliant |
| SAML 2.0 Profiles | ✅ Compliant |
| SAML 2.0 Metadata | ✅ Compliant |
| XML Digital Signature (XML-DSig) | ✅ Compliant |

### Implemented Features

- ✅ SP-initiated SSO (Web Browser SSO Profile)
- ✅ IdP-initiated SSO (Unsolicited Response)
- ✅ Single Logout Profile
- ✅ HTTP-POST Binding
- ✅ HTTP-Redirect Binding
- ✅ XML Digital Signatures (RSA-SHA256)
- ✅ Assertion conditions validation
- ✅ InResponseTo validation
- ✅ Assertion replay prevention
- ✅ SP and IdP metadata generation
- ✅ Multiple NameID formats
- ✅ Attribute statements

### Not Implemented

- ❌ Artifact Binding
- ❌ SOAP Binding
- ❌ Assertion encryption
- ❌ Attribute queries
- ❌ Enhanced Client or Proxy (ECP) Profile
- ❌ Identity Provider Discovery Profile

## Specifications Reference

- [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [SAML 2.0 Bindings](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [SAML 2.0 Metadata](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [XML Digital Signature (XML-DSig)](https://www.w3.org/TR/xmldsig-core1/)

## License

Part of the ProtocolLens project.
