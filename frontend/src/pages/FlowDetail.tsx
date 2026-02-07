import { useEffect, useState, useMemo } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  ArrowLeft, Eye, ChevronDown, ChevronRight,
  Lock, Key, AlertTriangle, Copy, Check,
  Code, ExternalLink, Loader2, ArrowRight,
  Fingerprint, Server, Globe, FileKey, Shield, Users, Radio
} from 'lucide-react'
import { TokenInspector } from '../components/lookingglass/TokenInspector'
import { FlowDiagram } from '../components/lookingglass/FlowDiagram'
import { useProtocolFlows, FlowStep } from '../protocols'
import { SEO } from '../components/common/SEO'
import { getFlowSEO } from '../config/seo'
import { generateFlowPageSchema } from '../utils/schema'
import { SITE_CONFIG } from '../config/seo'

export function FlowDetail() {
  const { protocolId, flowId } = useParams()
  const [activeStep, setActiveStep] = useState<number>(-1)
  const [token, setToken] = useState<string>('')
  const [copied, setCopied] = useState(false)
  const [showCode, setShowCode] = useState(false)

  const { flows, loading, error } = useProtocolFlows(protocolId)

  // Alias map: URL slug → backend flow ID (for cases where they don't match via simple normalization)
  const FLOW_ALIASES: Record<string, Record<string, string>> = {
    oidc: { hybrid: 'oidc_hybrid', userinfo: 'oidc_userinfo', discovery: 'oidc_discovery' },
    scim: { 'group-management': 'group-membership', 'filter-queries': 'user-discovery' },
  }

  const mappedFlowId = useMemo(() => {
    if (!flowId) return ''
    const normalized = flowId.replace(/-/g, '_')
    // Check alias map first
    const aliased = protocolId ? FLOW_ALIASES[protocolId]?.[flowId] : undefined
    const match = flows.find(f =>
      f.id === flowId ||
      f.id === normalized ||
      f.id.replace(/_/g, '-') === flowId ||
      (aliased && f.id === aliased)
    )
    return match?.id || aliased || normalized || flowId
  }, [flowId, flows, protocolId])

  const flow = useMemo(() => {
    if (!mappedFlowId) return null
    const apiFlow = flows.find(f => f.id === mappedFlowId)
    if (!apiFlow) return null
    return {
      title: apiFlow.name,
      description: apiFlow.description,
      steps: apiFlow.steps,
    }
  }, [flows, mappedFlowId])

  useEffect(() => {
    setActiveStep(-1)
  }, [flowId])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <Loader2 className="w-6 h-6 text-surface-400 animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-20">
        <h1 className="text-xl font-semibold text-white mb-3">Flow Data Unavailable</h1>
        <p className="text-sm text-surface-400 mb-6">{error.message}</p>
        <Link to={`/protocol/${protocolId}`} className="text-cyan-400 hover:underline">
          Back to {getProtocolName(protocolId)}
        </Link>
      </div>
    )
  }

  const copyCode = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const getCodeExample = () => {
    if (mappedFlowId === 'authorization_code_pkce') {
      return `// Generate PKCE parameters
const codeVerifier = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
const codeChallenge = base64URLEncode(
  await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
);

// Redirect to authorization
const authUrl = new URL('/oauth2/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('code_challenge', codeChallenge);
authUrl.searchParams.set('code_challenge_method', 'S256');
window.location.href = authUrl;

// Exchange code for tokens (in callback)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    code_verifier: codeVerifier,
  }),
}).then(r => r.json());`
    }
    
    if (mappedFlowId === 'client_credentials') {
      return `// Client Credentials (server-side only)
const tokens = await fetch('/oauth2/token', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'api:read api:write',
  }),
}).then(r => r.json());`
    }

    if (mappedFlowId === 'token_introspection') {
      return `// Token Introspection (RFC 7662)
const result = await fetch('/oauth2/introspect', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({ token: accessToken }),
}).then(r => r.json());

if (result.active) {
  console.log('Valid until:', new Date(result.exp * 1000));
}`
    }

    if (mappedFlowId === 'token_revocation') {
      return `// Token Revocation (RFC 7009)
await fetch('/oauth2/revoke', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa(clientId + ':' + clientSecret),
    'Content-Type': 'application/x-www-form-urlencoded',
  },
  body: new URLSearchParams({
    token: refreshToken,
    token_type_hint: 'refresh_token',
  }),
});`
    }

    if (mappedFlowId === 'oidc_userinfo') {
      return `// Fetch user claims
const userInfo = await fetch('/oidc/userinfo', {
  headers: { 'Authorization': 'Bearer ' + accessToken },
}).then(r => r.json());

console.log('User:', userInfo.name, userInfo.email);`
    }

    if (mappedFlowId === 'oidc_discovery') {
      return `// Auto-configure from discovery document
const config = await fetch('/.well-known/openid-configuration')
  .then(r => r.json());

const jwks = await fetch(config.jwks_uri).then(r => r.json());

// Use discovered endpoints
console.log('Authorization:', config.authorization_endpoint);
console.log('Token:', config.token_endpoint);
console.log('UserInfo:', config.userinfo_endpoint);
console.log('Supported scopes:', config.scopes_supported);`
    }

    if (mappedFlowId === 'oidc_authorization_code') {
      return `// OIDC Authorization Code Flow
// Step 1: Generate nonce for replay protection
const nonce = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
sessionStorage.setItem('oidc_nonce', nonce);

// Step 2: Redirect to authorization
const authUrl = new URL('/oidc/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', window.location.origin + '/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', crypto.randomUUID());
authUrl.searchParams.set('nonce', nonce);
window.location.href = authUrl;

// Step 3: In callback - exchange code for tokens
const tokens = await fetch('/oidc/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    redirect_uri: window.location.origin + '/callback',
  }),
}).then(r => r.json());

// Step 4: Validate ID Token (server-side recommended)
// - Verify signature against JWKS
// - Check iss matches expected issuer
// - Check aud contains client_id  
// - Check nonce matches stored value
// - Check exp is in the future`
    }

    if (mappedFlowId === 'oidc_implicit') {
      return `// OIDC Implicit Flow (Legacy - use PKCE instead)
// ⚠️ NOT RECOMMENDED for new applications

// Step 1: Generate nonce (REQUIRED for id_token)
const nonce = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
sessionStorage.setItem('oidc_nonce', nonce);

// Step 2: Redirect with response_type=id_token token
const authUrl = new URL('/oidc/authorize', origin);
authUrl.searchParams.set('response_type', 'id_token token');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', window.location.origin + '/callback');
authUrl.searchParams.set('scope', 'openid profile');
authUrl.searchParams.set('state', crypto.randomUUID());
authUrl.searchParams.set('nonce', nonce); // REQUIRED
window.location.href = authUrl;

// Step 3: Parse tokens from URL fragment
const fragment = new URLSearchParams(window.location.hash.substring(1));
const idToken = fragment.get('id_token');
const accessToken = fragment.get('access_token');

// Step 4: Validate ID Token
// - MUST verify nonce matches to prevent replay attacks
// - MUST verify at_hash matches access_token (if present)
// - Tokens in browser history = security risk`
    }

    if (mappedFlowId === 'oidc_hybrid') {
      return `// OIDC Hybrid Flow (code id_token)
// Combines immediate ID token with secure code exchange

// Step 1: Generate nonce (REQUIRED when id_token in response_type)
const nonce = base64URLEncode(crypto.getRandomValues(new Uint8Array(32)));
sessionStorage.setItem('oidc_nonce', nonce);

// Step 2: Redirect with hybrid response_type
const authUrl = new URL('/oidc/authorize', origin);
authUrl.searchParams.set('response_type', 'code id_token');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', window.location.origin + '/callback');
authUrl.searchParams.set('scope', 'openid profile email');
authUrl.searchParams.set('state', crypto.randomUUID());
authUrl.searchParams.set('nonce', nonce);
window.location.href = authUrl;

// Step 3: Parse response - code in query, id_token in fragment
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const fragment = new URLSearchParams(window.location.hash.substring(1));
const idToken = fragment.get('id_token');

// Step 4: Validate ID Token including c_hash
// c_hash = BASE64URL(left-half(SHA256(code)))
const cHash = await computeHash(code);
// Compare cHash with c_hash claim in ID Token

// Step 5: Exchange code for tokens (back-channel)
const tokens = await fetch('/oidc/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
  }),
}).then(r => r.json());`
    }

    // SAML flows
    if (mappedFlowId === 'saml_sp_initiated_sso') {
      return `// SP-Initiated SSO - Redirect to IdP
// This would typically be handled server-side

// 1. Create AuthnRequest XML
const authnRequest = \`
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_\${crypto.randomUUID()}"
  Version="2.0"
  IssueInstant="\${new Date().toISOString()}"
  AssertionConsumerServiceURL="https://sp.example.com/saml/acs">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    https://sp.example.com
  </saml:Issuer>
</samlp:AuthnRequest>\`;

// 2. Encode and redirect (HTTP-Redirect binding)
const encoded = btoa(pako.deflateRaw(authnRequest, { to: 'string' }));
const redirectUrl = \`\${idpSsoUrl}?SAMLRequest=\${encodeURIComponent(encoded)}\`;`
    }

    if (mappedFlowId === 'saml_single_logout') {
      return `// Single Logout - Create LogoutRequest
const logoutRequest = \`
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  ID="_\${crypto.randomUUID()}"
  Version="2.0"
  IssueInstant="\${new Date().toISOString()}"
  Destination="\${idpSloUrl}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    https://sp.example.com
  </saml:Issuer>
  <saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
    user@example.com
  </saml:NameID>
  <samlp:SessionIndex>\${sessionIndex}</samlp:SessionIndex>
</samlp:LogoutRequest>\`;`
    }

    if (mappedFlowId === 'saml_metadata') {
      return `// Fetch and parse SAML metadata
const metadataUrl = 'https://idp.example.com/saml/metadata';
const response = await fetch(metadataUrl);
const xml = await response.text();

// Parse the XML to extract endpoints and certificates
const parser = new DOMParser();
const doc = parser.parseFromString(xml, 'application/xml');

// Extract SSO endpoint
const ssoBinding = doc.querySelector('SingleSignOnService[Binding*="HTTP-POST"]');
const ssoUrl = ssoBinding?.getAttribute('Location');

// Extract signing certificate
const cert = doc.querySelector('KeyDescriptor[use="signing"] X509Certificate');
const certificate = cert?.textContent;`
    }

    // SPIFFE/SPIRE flows
    if (mappedFlowId === 'x509-svid-issuance') {
      return `// X.509-SVID Acquisition using go-spiffe
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Connect to SPIRE Agent Workload API
ctx := context.Background()
source, err := workloadapi.NewX509Source(ctx,
    workloadapi.WithClientOptions(
        workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
    ),
)
if err != nil {
    log.Fatal("Failed to create X509Source:", err)
}
defer source.Close()

// Get the X.509-SVID (auto-rotates)
svid, err := source.GetX509SVID()
if err != nil {
    log.Fatal("Failed to get X509-SVID:", err)
}

fmt.Printf("SPIFFE ID: %s\\n", svid.ID)
fmt.Printf("Not After: %s\\n", svid.Certificates[0].NotAfter)`
    }

    if (mappedFlowId === 'jwt-svid-issuance') {
      return `// JWT-SVID Acquisition using go-spiffe
import (
    "github.com/spiffe/go-spiffe/v2/workloadapi"
    "github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// Connect to SPIRE Agent
source, err := workloadapi.NewJWTSource(ctx,
    workloadapi.WithClientOptions(
        workloadapi.WithAddr("unix:///run/spire/sockets/agent.sock"),
    ),
)
if err != nil {
    log.Fatal("Failed to create JWTSource:", err)
}
defer source.Close()

// Fetch JWT-SVID for specific audience
svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{
    Audience: "api.example.com",
})
if err != nil {
    log.Fatal("Failed to get JWT-SVID:", err)
}

// Use token in API requests
req.Header.Set("Authorization", "Bearer " + svid.Marshal())`
    }

    if (mappedFlowId === 'mtls-handshake') {
      return `// mTLS Server using X.509-SVIDs
import (
    "github.com/spiffe/go-spiffe/v2/spiffetls"
    "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// Create mTLS listener (auto-rotates certificates)
listener, err := spiffetls.Listen(ctx, "tcp", ":8443",
    tlsconfig.AuthorizeMemberOf(trustDomain),
)
if err != nil {
    log.Fatal("Failed to create listener:", err)
}

// Handle connections with verified SPIFFE IDs
for {
    conn, _ := listener.Accept()
    tlsConn := conn.(*tls.Conn)
    peerID := tlsConn.ConnectionState().PeerCertificates[0].URIs[0]
    fmt.Printf("Authenticated peer: %s\\n", peerID)
}`
    }

    if (mappedFlowId === 'certificate-rotation') {
      return `// Automatic Certificate Rotation via Streaming API
import "github.com/spiffe/go-spiffe/v2/workloadapi"

// X509Source automatically handles rotation
source, _ := workloadapi.NewX509Source(ctx)

// Get notified of SVID updates
go func() {
    for {
        select {
        case <-ctx.Done():
            return
        case <-time.After(30 * time.Second):
            svid, _ := source.GetX509SVID()
            log.Printf("Current SVID expires: %s", 
                svid.Certificates[0].NotAfter)
        }
    }
}()

// SPIRE Agent rotates at ~50% of TTL
// Default TTL: 1 hour → Rotates at ~30 minutes
// New connections automatically use new certificate`
    }

    // SCIM 2.0 flows
    if (mappedFlowId === 'scim_user_lifecycle') {
      return `// SCIM 2.0 User Lifecycle (RFC 7644)
const SCIM_BASE = 'https://example.com/scim/v2';
const TOKEN = 'your-bearer-token';

// Check if user exists
const checkUser = await fetch(
  \`\${SCIM_BASE}/Users?filter=userName eq "john@example.com"\`,
  { headers: { 'Authorization': \`Bearer \${TOKEN}\`, 'Accept': 'application/scim+json' } }
).then(r => r.json());

// Create user if not exists
if (checkUser.totalResults === 0) {
  const newUser = await fetch(\`\${SCIM_BASE}/Users\`, {
    method: 'POST',
    headers: {
      'Authorization': \`Bearer \${TOKEN}\`,
      'Content-Type': 'application/scim+json',
    },
    body: JSON.stringify({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'john@example.com',
      name: { givenName: 'John', familyName: 'Doe' },
      emails: [{ value: 'john@example.com', type: 'work', primary: true }],
      active: true,
    }),
  }).then(r => r.json());
  console.log('Created user:', newUser.id);
}

// Deactivate user (PATCH)
await fetch(\`\${SCIM_BASE}/Users/\${userId}\`, {
  method: 'PATCH',
  headers: { 'Authorization': \`Bearer \${TOKEN}\`, 'Content-Type': 'application/scim+json' },
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{ op: 'replace', path: 'active', value: false }],
  }),
});`
    }

    if (mappedFlowId === 'scim_group_management') {
      return `// SCIM 2.0 Group Management (RFC 7644)
const SCIM_BASE = 'https://example.com/scim/v2';
const TOKEN = 'your-bearer-token';
const headers = { 'Authorization': \`Bearer \${TOKEN}\`, 'Content-Type': 'application/scim+json' };

// Create a group
const group = await fetch(\`\${SCIM_BASE}/Groups\`, {
  method: 'POST',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName: 'Engineering Team',
  }),
}).then(r => r.json());

// Add member to group (PATCH)
await fetch(\`\${SCIM_BASE}/Groups/\${group.id}\`, {
  method: 'PATCH',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{
      op: 'add',
      path: 'members',
      value: [{ value: userId }],
    }],
  }),
});

// Remove member from group
await fetch(\`\${SCIM_BASE}/Groups/\${group.id}\`, {
  method: 'PATCH',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{
      op: 'remove',
      path: \`members[value eq "\${userId}"]\`,
    }],
  }),
});`
    }

    if (mappedFlowId === 'scim_filter_queries') {
      return `// SCIM 2.0 Filter Queries (RFC 7644 Section 3.4.2)

// Simple equality filter
GET /Users?filter=userName eq "john@example.com"

// Contains filter (useful for search)
GET /Users?filter=name.familyName co "Smith"

// Complex filter with AND/OR
GET /Users?filter=active eq true and (emails.value co "@company.com")

// Nested attribute filter
GET /Users?filter=emails[type eq "work" and primary eq true]

// Presence filter (attribute exists)
GET /Users?filter=title pr

// Comparison operators
GET /Users?filter=meta.lastModified gt "2024-01-01T00:00:00Z"

// Pagination
GET /Users?startIndex=1&count=25

// Sorting
GET /Users?sortBy=name.familyName&sortOrder=ascending

// Filter operators:
// eq  - equals
// ne  - not equals
// co  - contains
// sw  - starts with
// ew  - ends with
// gt  - greater than
// lt  - less than
// ge  - greater than or equal
// le  - less than or equal
// pr  - present (attribute exists)`
    }

    if (mappedFlowId === 'scim_schema_discovery') {
      return `// SCIM 2.0 Schema Discovery (RFC 7644 Section 4)
const SCIM_BASE = 'https://example.com/scim/v2';

// 1. Discover server capabilities
const config = await fetch(\`\${SCIM_BASE}/ServiceProviderConfig\`)
  .then(r => r.json());

console.log('PATCH supported:', config.patch.supported);
console.log('Bulk max ops:', config.bulk.maxOperations);
console.log('Filter max results:', config.filter.maxResults);

// 2. Get available resource types
const resourceTypes = await fetch(\`\${SCIM_BASE}/ResourceTypes\`)
  .then(r => r.json());

resourceTypes.Resources.forEach(rt => {
  console.log(\`Resource: \${rt.name} at \${rt.endpoint}\`);
  console.log(\`  Schema: \${rt.schema}\`);
});

// 3. Get detailed schema for User
const userSchema = await fetch(
  \`\${SCIM_BASE}/Schemas/urn:ietf:params:scim:schemas:core:2.0:User\`
).then(r => r.json());

userSchema.attributes.forEach(attr => {
  console.log(\`\${attr.name}: \${attr.type} (\${attr.mutability})\`);
});`
    }

    if (mappedFlowId === 'scim_bulk_operations') {
      return `// SCIM 2.0 Bulk Operations (RFC 7644 Section 3.7)
const SCIM_BASE = 'https://example.com/scim/v2';
const TOKEN = 'your-bearer-token';

// Bulk request to create multiple users
const bulkResponse = await fetch(\`\${SCIM_BASE}/Bulk\`, {
  method: 'POST',
  headers: {
    'Authorization': \`Bearer \${TOKEN}\`,
    'Content-Type': 'application/scim+json',
  },
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
    failOnErrors: 1, // Stop after first error
    Operations: [
      {
        method: 'POST',
        path: '/Users',
        bulkId: 'user1',
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'alice@example.com',
          name: { givenName: 'Alice', familyName: 'Smith' },
        },
      },
      {
        method: 'POST',
        path: '/Users',
        bulkId: 'user2',
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'bob@example.com',
          name: { givenName: 'Bob', familyName: 'Jones' },
        },
      },
      {
        method: 'POST',
        path: '/Groups',
        bulkId: 'group1',
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
          displayName: 'New Team',
          // Reference users by bulkId
          members: [
            { value: 'bulkId:user1' },
            { value: 'bulkId:user2' },
          ],
        },
      },
    ],
  }),
}).then(r => r.json());

// Check results
bulkResponse.Operations.forEach(op => {
  console.log(\`\${op.bulkId}: \${op.status} - \${op.location || op.response?.detail}\`);
});`
    }

    // SSF (Shared Signals Framework) flows
    if (mappedFlowId === 'ssf_stream_configuration') {
      return `// SSF Stream Configuration (SSF §4)
const SSF_BASE = 'https://idp.example.com';

// 1. Discover SSF configuration
const config = await fetch(\`\${SSF_BASE}/.well-known/ssf-configuration\`)
  .then(r => r.json());

console.log('Issuer:', config.issuer);
console.log('Delivery methods:', config.delivery_methods_supported);
console.log('Configuration endpoint:', config.configuration_endpoint);

// 2. Create a stream
const stream = await fetch(config.configuration_endpoint, {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + managementToken,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    delivery: {
      method: 'urn:ietf:rfc:8935', // Push delivery
      endpoint_url: 'https://myapp.example.com/ssf/push',
    },
    events_requested: [
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
    ],
    format: 'email', // Subject identifier format
  }),
}).then(r => r.json());

console.log('Stream ID:', stream.stream_id);
console.log('Events delivered:', stream.events_delivered);

// 3. Fetch JWKS for SET verification
const jwks = await fetch(config.jwks_uri).then(r => r.json());
console.log('Verification keys:', jwks.keys.length);`
    }

    if (mappedFlowId === 'ssf_push_delivery') {
      return `// SSF Push Delivery - Receiver Implementation (RFC 8935)
import * as jose from 'jose';

// Store for replay detection
const processedJTIs = new Set();
let jwks = null;

// Fetch and cache JWKS
async function getJWKS() {
  if (!jwks) {
    const res = await fetch('https://idp.example.com/ssf/jwks');
    jwks = jose.createRemoteJWKSet(new URL('https://idp.example.com/ssf/jwks'));
  }
  return jwks;
}

// Push endpoint handler
app.post('/ssf/push', async (req, res) => {
  const setToken = req.body; // Raw JWT string
  
  try {
    // 1. Verify SET signature
    const keySet = await getJWKS();
    const { payload, protectedHeader } = await jose.jwtVerify(setToken, keySet, {
      issuer: 'https://idp.example.com',
      audience: 'https://myapp.example.com',
    });
    
    // 2. Replay detection
    if (processedJTIs.has(payload.jti)) {
      return res.status(400).json({ err: 'invalid_request', description: 'Duplicate event' });
    }
    processedJTIs.add(payload.jti);
    
    // 3. Process events
    for (const [eventType, eventData] of Object.entries(payload.events)) {
      await handleSecurityEvent(eventType, payload.sub_id, eventData);
    }
    
    // 4. Acknowledge receipt
    res.status(202).send();
    
  } catch (error) {
    console.error('SET validation failed:', error);
    res.status(400).json({ err: 'invalid_request', description: error.message });
  }
});

async function handleSecurityEvent(eventType, subject, eventData) {
  switch (eventType) {
    case 'https://schemas.openid.net/secevent/caep/event-type/session-revoked':
      await revokeUserSessions(subject.email);
      break;
    case 'https://schemas.openid.net/secevent/risc/event-type/account-disabled':
      await disableUserAccount(subject.email);
      break;
  }
}`
    }

    if (mappedFlowId === 'ssf_poll_delivery') {
      return `// SSF Poll Delivery - Receiver Implementation (RFC 8936)
import * as jose from 'jose';

const POLL_ENDPOINT = 'https://idp.example.com/ssf/poll';
const acknowledgedJTIs = [];

async function pollForEvents() {
  const response = await fetch(POLL_ENDPOINT, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      maxEvents: 10,
      returnImmediately: false, // Long-polling
      acks: acknowledgedJTIs.splice(0), // Acknowledge previously processed
    }),
  });
  
  const data = await response.json();
  
  // Process each SET
  for (const [jti, setToken] of Object.entries(data.sets)) {
    try {
      // Verify and process SET
      const payload = await verifyAndProcessSET(setToken);
      acknowledgedJTIs.push(jti);
    } catch (error) {
      console.error(\`Failed to process SET \${jti}:\`, error);
    }
  }
  
  // Continue polling if more events available
  if (data.moreAvailable) {
    setImmediate(pollForEvents);
  } else {
    setTimeout(pollForEvents, 30000); // Poll every 30 seconds
  }
}

async function verifyAndProcessSET(setToken) {
  const jwks = jose.createRemoteJWKSet(new URL('https://idp.example.com/ssf/jwks'));
  const { payload } = await jose.jwtVerify(setToken, jwks, {
    issuer: 'https://idp.example.com',
    audience: 'https://myapp.example.com',
  });
  
  // Process event
  for (const [eventType, eventData] of Object.entries(payload.events)) {
    await handleSecurityEvent(eventType, payload.sub_id, eventData);
  }
  
  return payload;
}

// Start polling
pollForEvents();`
    }

    if (mappedFlowId === 'caep_session_revoked') {
      return `// CAEP Session Revoked - Transmitter & Receiver (CAEP §3.1)
import * as jose from 'jose';

// === TRANSMITTER: Generate Session Revoked SET ===
async function emitSessionRevokedEvent(subject, reason, initiator) {
  const privateKey = await jose.importPKCS8(SIGNING_KEY, 'RS256');
  
  const set = await new jose.SignJWT({
    iss: 'https://idp.example.com',
    aud: ['https://app1.example.com', 'https://app2.example.com'],
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: {
      format: 'email',
      email: subject.email,
    },
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiating_entity: initiator, // 'admin' | 'user' | 'policy' | 'system'
        reason_admin: { en: reason },
        reason_user: { en: 'Your session has been terminated for security reasons.' },
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: 'key-2024' })
  .sign(privateKey);
  
  // Push to all subscribed receivers
  for (const receiver of getStreamReceivers(subject)) {
    await fetch(receiver.pushEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/secevent+jwt' },
      body: set,
    });
  }
}

// === RECEIVER: Handle Session Revoked Event ===
async function handleSessionRevoked(eventData, subject) {
  const email = subject.email;
  
  // 1. Terminate all user sessions
  await sessionStore.deleteAllForUser(email);
  
  // 2. Revoke access tokens
  await tokenStore.revokeAllForUser(email);
  
  // 3. Log the event
  console.log(\`Sessions revoked for \${email} - Reason: \${eventData.reason_admin?.en}\`);
  
  // 4. Optionally notify user
  if (eventData.reason_user) {
    await notifyUser(email, eventData.reason_user.en);
  }
}`
    }

    if (mappedFlowId === 'caep_credential_change') {
      return `// CAEP Credential Change Event (CAEP §3.2)
import * as jose from 'jose';

// === TRANSMITTER: Emit Credential Change Event ===
async function emitCredentialChangeEvent(subject, credentialType, changeType) {
  const set = await new jose.SignJWT({
    iss: 'https://idp.example.com',
    aud: ['https://app.example.com'],
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subject.email },
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/credential-change': {
        event_timestamp: Math.floor(Date.now() / 1000),
        credential_type: credentialType, // 'password' | 'fido2-platform' | 'x509'
        change_type: changeType, // 'create' | 'update' | 'revoke'
        initiating_entity: 'user',
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: 'key-2024' })
  .sign(privateKey);
  
  await deliverSET(set, subject);
}

// === RECEIVER: Handle Credential Change ===
async function handleCredentialChange(eventData, subject) {
  const email = subject.email;
  const { credential_type, change_type } = eventData;
  
  console.log(\`Credential change: \${credential_type} \${change_type} for \${email}\`);
  
  // 1. Invalidate cached tokens/credentials
  await tokenCache.invalidateForUser(email);
  
  // 2. Clear any cached identity claims
  await claimsCache.invalidateForUser(email);
  
  // 3. For password changes, force re-authentication
  if (credential_type === 'password') {
    await sessionStore.deleteAllForUser(email);
  }
  
  // 4. For MFA changes, consider additional verification
  if (credential_type === 'fido2-platform' && change_type === 'revoke') {
    await flagForMFAReenrollment(email);
  }
}`
    }

    if (mappedFlowId === 'risc_account_disabled') {
      return `// RISC Account Disabled Event (RISC §2.2)
import * as jose from 'jose';

// === TRANSMITTER: Emit Account Disabled Event ===
async function emitAccountDisabledEvent(subject, reason, admin) {
  const set = await new jose.SignJWT({
    iss: 'https://idp.example.com',
    aud: ['https://app.example.com'],
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subject.email },
    events: {
      'https://schemas.openid.net/secevent/risc/event-type/account-disabled': {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiating_entity: 'admin',
        reason_admin: { en: reason },
        reason_user: { en: 'Your account has been suspended. Contact support.' },
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: 'key-2024' })
  .sign(privateKey);
  
  // RISC events are high priority - ensure delivery
  await deliverWithRetry(set, subject, { maxRetries: 5, priority: 'high' });
}

// === RECEIVER: Handle Account Disabled ===
async function handleAccountDisabled(eventData, subject) {
  const email = subject.email;
  
  // CRITICAL: Block all access immediately
  
  // 1. Terminate ALL sessions
  await sessionStore.deleteAllForUser(email);
  
  // 2. Revoke ALL tokens
  await tokenStore.revokeAllForUser(email);
  
  // 3. Block new authentication attempts
  await userStore.setStatus(email, 'disabled');
  
  // 4. Block API access
  await apiKeyStore.disableAllForUser(email);
  
  // 5. Log for compliance/audit
  await auditLog.record({
    event: 'ACCOUNT_DISABLED_VIA_SSF',
    subject: email,
    reason: eventData.reason_admin?.en,
    timestamp: new Date(),
  });
  
  // 6. Consider data access restrictions
  // await dataAccessControl.restrictForUser(email);
}`
    }

    if (mappedFlowId === 'risc_credential_compromise') {
      return `// RISC Credential Compromise Event (RISC §2.1) - CRITICAL
import * as jose from 'jose';

// === TRANSMITTER: Emit Credential Compromise Event ===
async function emitCredentialCompromiseEvent(subject, detectionSource) {
  // CRITICAL: This is the highest severity RISC event
  const set = await new jose.SignJWT({
    iss: 'https://idp.example.com',
    aud: ['https://app.example.com'],
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    sub_id: { format: 'email', email: subject.email },
    events: {
      'https://schemas.openid.net/secevent/risc/event-type/credential-compromise': {
        event_timestamp: Math.floor(Date.now() / 1000),
        initiating_entity: 'system',
        reason_admin: { 
          en: \`Credential compromise detected via \${detectionSource}\` 
        },
      },
    },
  })
  .setProtectedHeader({ alg: 'RS256', kid: 'key-2024' })
  .sign(privateKey);
  
  // EMERGENCY: Aggressive delivery with monitoring
  await deliverWithRetry(set, subject, { 
    maxRetries: 10, 
    priority: 'critical',
    alertOnFailure: true,
  });
}

// === RECEIVER: Handle Credential Compromise (EMERGENCY) ===
async function handleCredentialCompromise(eventData, subject) {
  const email = subject.email;
  
  // CRITICAL: This is an emergency security event
  console.error(\`🚨 CREDENTIAL COMPROMISE DETECTED: \${email}\`);
  
  // 1. IMMEDIATELY terminate ALL sessions
  await sessionStore.deleteAllForUser(email);
  
  // 2. Revoke ALL tokens globally
  await tokenStore.revokeAllForUser(email);
  
  // 3. Revoke all API keys and certificates
  await apiKeyStore.revokeAllForUser(email);
  
  // 4. Force password reset on next login
  await userStore.setPasswordResetRequired(email, true);
  
  // 5. Consider requiring MFA re-enrollment
  await userStore.setMFAReenrollmentRequired(email, true);
  
  // 6. Block account until password reset
  await userStore.setStatus(email, 'pending_credential_reset');
  
  // 7. Alert security team
  await securityAlert.critical({
    type: 'CREDENTIAL_COMPROMISE',
    subject: email,
    source: eventData.reason_admin?.en,
    timestamp: new Date(),
  });
  
  // 8. Preserve evidence for investigation
  await incidentResponse.createIncident({
    type: 'credential_compromise',
    subject: email,
    evidence: { eventData, timestamp: new Date() },
  });
}`
    }

    return `// Authorization Code Flow
const authUrl = new URL('/oauth2/authorize', origin);
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('state', crypto.randomUUID());
window.location.href = authUrl;`
  }

  // Get flow badges
  const getBadges = () => {
    const badges = []
    if (mappedFlowId.includes('pkce')) {
      badges.push({ label: 'PKCE Protected', color: 'green', icon: Lock })
    }
    if (mappedFlowId === 'authorization_code') {
      badges.push({ label: 'Server-side', color: 'yellow', icon: Key })
    }
    if (mappedFlowId === 'client_credentials') {
      badges.push({ label: 'Machine-to-Machine', color: 'blue', icon: Server })
    }
    if (mappedFlowId.includes('oidc')) {
      badges.push({ label: 'ID Token', color: 'purple', icon: Fingerprint })
    }
    // SAML badges
    if (mappedFlowId.includes('saml')) {
      badges.push({ label: 'XML-Based', color: 'cyan', icon: FileKey })
    }
    if (mappedFlowId === 'saml_sp_initiated_sso' || mappedFlowId === 'saml_idp_initiated_sso') {
      badges.push({ label: 'SSO', color: 'green', icon: Shield })
    }
    // SPIFFE/SPIRE badges
    if (mappedFlowId === 'x509-svid-issuance') {
      badges.push({ label: 'X.509 Certificate', color: 'green', icon: Shield })
      badges.push({ label: 'Workload API', color: 'cyan', icon: Server })
    }
    if (mappedFlowId === 'jwt-svid-issuance') {
      badges.push({ label: 'JWT Token', color: 'purple', icon: Key })
      badges.push({ label: 'Short-Lived', color: 'yellow', icon: Lock })
    }
    if (mappedFlowId === 'mtls-handshake') {
      badges.push({ label: 'Mutual TLS', color: 'green', icon: Lock })
      badges.push({ label: 'Zero Trust', color: 'blue', icon: Shield })
    }
    if (mappedFlowId === 'certificate-rotation') {
      badges.push({ label: 'Auto-Rotation', color: 'cyan', icon: Shield })
      badges.push({ label: 'Zero Downtime', color: 'green', icon: Lock })
    }
    if (mappedFlowId === 'saml_single_logout') {
      badges.push({ label: 'Federated Logout', color: 'yellow', icon: Globe })
    }
    // SCIM 2.0 badges
    if (mappedFlowId.includes('scim')) {
      badges.push({ label: 'Provisioning', color: 'purple', icon: Users })
    }
    if (mappedFlowId === 'scim_user_lifecycle') {
      badges.push({ label: 'User CRUD', color: 'blue', icon: Server })
      badges.push({ label: 'IdP Integration', color: 'cyan', icon: Globe })
    }
    if (mappedFlowId === 'scim_group_management') {
      badges.push({ label: 'Group Sync', color: 'green', icon: Users })
    }
    if (mappedFlowId === 'scim_filter_queries') {
      badges.push({ label: 'RFC 7644', color: 'yellow', icon: Code })
    }
    if (mappedFlowId === 'scim_schema_discovery') {
      badges.push({ label: 'Auto-Config', color: 'cyan', icon: Server })
    }
    if (mappedFlowId === 'scim_bulk_operations') {
      badges.push({ label: 'Batch Processing', color: 'blue', icon: Server })
    }
    // SSF badges
    if (mappedFlowId.includes('ssf') || mappedFlowId.includes('caep') || mappedFlowId.includes('risc')) {
      badges.push({ label: 'Security Events', color: 'amber', icon: Radio })
    }
    if (mappedFlowId === 'ssf_stream_configuration') {
      badges.push({ label: 'Stream Setup', color: 'blue', icon: Server })
    }
    if (mappedFlowId === 'ssf_push_delivery') {
      badges.push({ label: 'Real-time Push', color: 'green', icon: Server })
      badges.push({ label: 'RFC 8935', color: 'cyan', icon: Code })
    }
    if (mappedFlowId === 'ssf_poll_delivery') {
      badges.push({ label: 'Poll-based', color: 'purple', icon: Server })
      badges.push({ label: 'RFC 8936', color: 'cyan', icon: Code })
    }
    if (mappedFlowId.includes('caep')) {
      badges.push({ label: 'CAEP', color: 'blue', icon: Shield })
      badges.push({ label: 'Continuous Eval', color: 'green', icon: Lock })
    }
    if (mappedFlowId.includes('risc')) {
      badges.push({ label: 'RISC', color: 'amber', icon: AlertTriangle })
      badges.push({ label: 'High Severity', color: 'purple', icon: Shield })
    }
    if (mappedFlowId === 'risc_credential_compromise') {
      badges.push({ label: 'CRITICAL', color: 'purple', icon: AlertTriangle })
    }
    return badges
  }

  function getProtocolName(id: string | undefined) {
    switch (id) {
      case 'oauth2': return 'OAuth 2.0'
      case 'oidc': return 'OpenID Connect'
      case 'saml': return 'SAML 2.0'
      case 'spiffe': return 'SPIFFE/SPIRE'
      case 'scim': return 'SCIM 2.0'
      case 'ssf': return 'Shared Signals (SSF)'
      default: return id || 'Protocol'
    }
  }

  if (!flow) {
    return (
      <div className="text-center py-20">
        <h1 className="text-xl font-semibold text-white mb-4">Flow Not Found</h1>
        <Link to={`/protocol/${protocolId}`} className="text-cyan-400 hover:underline">
          Back to {getProtocolName(protocolId)}
        </Link>
      </div>
    )
  }

  const badges = getBadges()

  // Generate SEO data
  const protocolName = getProtocolName(protocolId)
  const seoData = getFlowSEO(protocolId || '', flowId || '', flow.title)
  const structuredData = generateFlowPageSchema(
    protocolName,
    flow.title,
    flow.description,
    `${SITE_CONFIG.baseUrl}/protocol/${protocolId}/flow/${flowId}`,
    flow.steps.map(s => ({ name: s.name, description: s.description }))
  )

  return (
    <>
      <SEO
        title={seoData.title}
        description={seoData.description}
        canonical={`/protocol/${protocolId}/flow/${flowId}`}
        ogType="article"
        keywords={seoData.keywords}
        structuredData={structuredData}
      />
      <div className="max-w-4xl mx-auto space-y-4 sm:space-y-6 px-1 sm:px-0">
      {/* Breadcrumb & Title */}
      <header>
        {/* Mobile breadcrumb - simplified */}
        <nav className="sm:hidden text-xs text-surface-400 mb-3">
          <Link to="/protocols" className="hover:text-white transition-colors">Protocols</Link>
          <span className="mx-1.5">›</span>
          <Link to={`/protocol/${protocolId}`} className="hover:text-white transition-colors">
            {getProtocolName(protocolId)}
          </Link>
        </nav>
        
        {/* Desktop breadcrumb - full */}
        <div className="hidden sm:flex items-center gap-2 text-sm text-surface-400 mb-2">
          <Link to="/protocols" className="hover:text-white transition-colors">Protocols</Link>
          <ChevronRight className="w-4 h-4" />
          <Link to={`/protocol/${protocolId}`} className="hover:text-white transition-colors">
            {getProtocolName(protocolId)}
          </Link>
          <ChevronRight className="w-4 h-4" />
          <span className="text-surface-300">{flow.title}</span>
        </div>
        
        {/* Mobile layout - stacked */}
        <div className="flex flex-col gap-3 sm:hidden">
          <div>
            <h1 className="text-xl font-semibold text-white mb-1.5">{flow.title}</h1>
            <p className="text-sm text-surface-400">{flow.description}</p>
          </div>
          
          <Link
            to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
            className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r ${
              protocolId === 'ssf' 
                ? 'from-amber-500/20 to-orange-500/20 border-amber-500/30 text-amber-400 hover:from-amber-500/30 hover:to-orange-500/30' 
                : 'from-cyan-500/20 to-purple-500/20 border-cyan-500/30 text-cyan-400 hover:from-cyan-500/30 hover:to-purple-500/30'
            } border text-sm font-medium transition-all w-full`}
          >
            {protocolId === 'ssf' ? <Radio className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {protocolId === 'ssf' ? 'Try in SSF Sandbox' : 'Try in Looking Glass'}
          </Link>
        </div>
        
        {/* Desktop layout - side by side */}
        <div className="hidden sm:flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-white mb-2">{flow.title}</h1>
            <p className="text-surface-400">{flow.description}</p>
          </div>
          
          <Link
            to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r ${
              protocolId === 'ssf' 
                ? 'from-amber-500/20 to-orange-500/20 border-amber-500/30 text-amber-400 hover:from-amber-500/30 hover:to-orange-500/30' 
                : 'from-cyan-500/20 to-purple-500/20 border-cyan-500/30 text-cyan-400 hover:from-cyan-500/30 hover:to-purple-500/30'
            } border text-sm font-medium transition-all flex-shrink-0`}
          >
            {protocolId === 'ssf' ? <Radio className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {protocolId === 'ssf' ? 'Try in SSF Sandbox' : 'Try in Looking Glass'}
          </Link>
        </div>

        {/* Badges */}
        {badges.length > 0 && (
          <div className="flex flex-wrap gap-1.5 sm:gap-2 mt-3 sm:mt-4">
            {badges.map(badge => (
              <span 
                key={badge.label}
                className={`inline-flex items-center gap-1 sm:gap-1.5 px-2 sm:px-2.5 py-0.5 sm:py-1 rounded-full text-[10px] sm:text-xs font-medium border
                  ${badge.color === 'green' ? 'bg-green-500/10 text-green-400 border-green-500/20' : ''}
                  ${badge.color === 'yellow' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : ''}
                  ${badge.color === 'blue' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' : ''}
                  ${badge.color === 'purple' ? 'bg-purple-500/10 text-purple-400 border-purple-500/20' : ''}
                  ${badge.color === 'cyan' ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' : ''}
                  ${badge.color === 'amber' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : ''}
                `}
              >
                <badge.icon className="w-2.5 h-2.5 sm:w-3 sm:h-3" />
                {badge.label}
              </span>
            ))}
          </div>
        )}
      </header>

      {/* Sequence Diagram */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
          <h2 className="font-medium text-white text-sm sm:text-base">Sequence Diagram</h2>
          <p className="text-xs sm:text-sm text-surface-400 mt-0.5 sm:mt-1">Click any step for details</p>
        </div>
        <div className="p-3 sm:p-5">
          <FlowDiagram 
            steps={flow.steps}
            activeStep={activeStep}
            onStepClick={setActiveStep}
          />
        </div>
      </section>

      {/* Code Example */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <button
          onClick={() => setShowCode(!showCode)}
          className="w-full px-3 sm:px-5 py-3 sm:py-4 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
        >
          <h2 className="font-medium text-white flex items-center gap-2 text-sm sm:text-base">
            <Code className="w-4 h-4 text-surface-400" />
            Implementation Example
          </h2>
          <ChevronDown className={`w-4 h-4 text-surface-400 transition-transform ${showCode ? 'rotate-180' : ''}`} />
        </button>

        <AnimatePresence>
          {showCode && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="relative border-t border-white/10">
                <button
                  onClick={() => copyCode(getCodeExample())}
                  className="absolute top-2 right-2 sm:top-3 sm:right-3 flex items-center gap-1.5 px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-lg text-xs text-surface-400 hover:text-white hover:bg-white/10 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied!' : 'Copy'}
                </button>
                <pre className="p-3 sm:p-5 overflow-x-auto text-xs sm:text-sm">
                  <code className="text-surface-300 font-mono leading-relaxed">{getCodeExample()}</code>
                </pre>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </section>

      {/* Step-by-Step Breakdown */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
          <h2 className="font-medium text-white text-sm sm:text-base">Step-by-Step Breakdown</h2>
        </div>
        <div className="p-3 sm:p-5">
          <div className="space-y-2 sm:space-y-3">
            {flow.steps.map((step, index) => (
              <StepRow
                key={step.order}
                step={step}
                index={index}
                isActive={activeStep === step.order}
                isLast={index === flow.steps.length - 1}
                onClick={() => setActiveStep(activeStep === step.order ? -1 : step.order)}
              />
            ))}
          </div>
        </div>
      </section>

      {/* Token Inspector */}
      <section className="rounded-xl border border-white/10 bg-surface-900/30 overflow-hidden">
        <div className="px-3 sm:px-5 py-3 sm:py-4 border-b border-white/10">
          <h2 className="font-medium text-white flex items-center gap-2 text-sm sm:text-base">
            <Key className="w-4 h-4 text-amber-400" />
            Token Inspector
          </h2>
        </div>
        <div className="p-3 sm:p-5">
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste a JWT to decode..."
            className="w-full px-3 sm:px-4 py-2 sm:py-2.5 rounded-lg bg-surface-900 border border-white/10 text-xs sm:text-sm font-mono text-white placeholder-surface-600 focus:outline-none focus:border-cyan-500/50 mb-3 sm:mb-4"
          />
          {token && <TokenInspector token={token} />}
        </div>
      </section>

      {/* Navigation */}
      <div className="flex items-center justify-between pt-2 pb-4 sm:pb-0">
        <Link
          to={`/protocols`}
          className="flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
          <span className="hidden sm:inline">All Protocols</span>
          <span className="sm:hidden">Back</span>
        </Link>
        <Link
          to={protocolId === 'ssf' ? '/ssf-sandbox' : '/looking-glass'}
          className="flex items-center gap-1.5 sm:gap-2 text-xs sm:text-sm text-surface-400 hover:text-white transition-colors"
        >
          <span className="hidden sm:inline">{protocolId === 'ssf' ? 'Open SSF Sandbox' : 'Open Looking Glass'}</span>
          <span className="sm:hidden">{protocolId === 'ssf' ? 'SSF Sandbox' : 'Looking Glass'}</span>
          <ExternalLink className="w-3.5 h-3.5 sm:w-4 sm:h-4" />
        </Link>
      </div>
    </div>
    </>
  )
}

// Step Row Component
function StepRow({ step, index, isActive, isLast, onClick }: { 
  step: FlowStep & { security?: string[] }
  index: number
  isActive: boolean
  isLast: boolean
  onClick: () => void 
}) {
  const typeConfig: Record<string, { color: string; icon: React.ElementType }> = {
    request: { color: 'text-blue-400 bg-blue-500/10 border-blue-500/20', icon: ArrowRight },
    response: { color: 'text-green-400 bg-green-500/10 border-green-500/20', icon: ArrowLeft },
    redirect: { color: 'text-amber-400 bg-amber-500/10 border-amber-500/20', icon: Globe },
    internal: { color: 'text-surface-400 bg-surface-800 border-white/10', icon: Server },
  }
  
  const config = typeConfig[step.type] || typeConfig.request
  const TypeIcon = config.icon

  return (
    <div className="relative">
      {/* Connector line */}
      {!isLast && (
        <div className="absolute left-4 sm:left-5 top-9 sm:top-10 bottom-0 w-px bg-white/10" />
      )}
      
      <motion.div
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: index * 0.03 }}
        onClick={onClick}
        className={`relative rounded-lg border cursor-pointer transition-all ${
          isActive 
            ? 'bg-white/5 border-white/20' 
            : 'border-transparent hover:bg-white/[0.02] hover:border-white/10'
        }`}
      >
        <div className="p-2 sm:p-3 flex items-start gap-2 sm:gap-3">
          {/* Step number */}
          <div className={`w-8 h-8 sm:w-10 sm:h-10 rounded-full flex items-center justify-center text-xs sm:text-sm font-medium flex-shrink-0 border ${config.color}`}>
            {step.order}
          </div>
          
          {/* Content */}
          <div className="flex-1 min-w-0 pt-0.5 sm:pt-1">
            <div className="flex items-center gap-1.5 sm:gap-2 mb-0.5">
              <span className="font-medium text-white text-sm sm:text-base truncate">{step.name}</span>
              <TypeIcon className={`w-3 h-3 sm:w-3.5 sm:h-3.5 flex-shrink-0 ${config.color.split(' ')[0]}`} />
            </div>
            <div className="text-xs sm:text-sm text-surface-400 truncate">
              {step.from} → {step.to}
            </div>
          </div>

          {/* Expand indicator */}
          <ChevronDown className={`w-4 h-4 text-surface-400 transition-transform mt-1 sm:mt-2 flex-shrink-0 ${isActive ? 'rotate-180' : ''}`} />
        </div>

        {/* Expanded content */}
        <AnimatePresence>
          {isActive && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="px-2 sm:px-3 pb-2 sm:pb-3 pt-1 ml-10 sm:ml-[52px] space-y-2 sm:space-y-3">
                <p className="text-xs sm:text-sm text-surface-300">{step.description}</p>

                {step.parameters && Object.keys(step.parameters).length > 0 && (
                  <div className="grid gap-1 sm:gap-1.5">
                    {Object.entries(step.parameters).map(([key, value]) => (
                      <div key={key} className="flex flex-col sm:flex-row sm:gap-3 text-xs sm:text-sm">
                        <code className="text-cyan-400 font-mono break-all">{key}</code>
                        <span className="text-surface-400 break-words">{value}</span>
                      </div>
                    ))}
                  </div>
                )}

                {step.security && step.security.length > 0 && (
                  <div className="p-2 sm:p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                    <div className="flex items-center gap-1.5 text-xs font-medium text-amber-400 mb-1.5 sm:mb-2">
                      <AlertTriangle className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                      Security Note
                    </div>
                    <ul className="space-y-1">
                      {step.security.map((note, i) => (
                        <li key={i} className="text-xs sm:text-sm text-amber-200/80">• {note}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  )
}

