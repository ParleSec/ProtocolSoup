/**
 * Fallback Flow Data
 * 
 * This data is used when the API is unavailable (e.g., during development).
 * In production, all flow data should come from the backend plugins.
 * 
 * This ensures the frontend can work standalone while maintaining
 * the modular plugin architecture.
 */

import type { FlowStep } from './registry'

export interface FlowData {
  title: string
  description: string
  steps: FlowStep[]
}

export const fallbackFlows: Record<string, FlowData> = {
  authorization_code: {
    title: "Authorization Code Flow",
    description: "The most secure OAuth 2.0 flow for server-side applications.",
    steps: [
      {
        order: 1,
        name: "Authorization Request",
        description: "Your app redirects the user to the authorization server.",
        from: "Client",
        to: "Authorization Server",
        type: "redirect",
        parameters: {
          response_type: "code",
          client_id: "Your app's identifier",
          redirect_uri: "Callback URL",
          scope: "Requested permissions",
          state: "CSRF protection token",
        },
      },
      {
        order: 2,
        name: "User Login",
        description: "User authenticates and approves permissions.",
        from: "User",
        to: "Authorization Server",
        type: "internal",
      },
      {
        order: 3,
        name: "Auth Code",
        description: "Server redirects back with authorization code.",
        from: "Authorization Server",
        to: "Client",
        type: "redirect",
        parameters: {
          code: "Single-use authorization code",
          state: "Must match original",
        },
      },
      {
        order: 4,
        name: "Token Request",
        description: "Backend exchanges code for tokens (server-to-server).",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          grant_type: "authorization_code",
          code: "The authorization code",
          client_secret: "Your secret (server-side only)",
        },
      },
      {
        order: 5,
        name: "Tokens",
        description: "Receive access token and refresh token.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          access_token: "API access token",
          refresh_token: "For getting new tokens",
          expires_in: "Token lifetime",
        },
      },
    ]
  },

  authorization_code_pkce: {
    title: "Authorization Code + PKCE",
    description: "Enhanced security for SPAs and mobile apps using PKCE.",
    steps: [
      {
        order: 1,
        name: "Generate PKCE",
        description: "Generate code_verifier and derive code_challenge.",
        from: "Client",
        to: "Client",
        type: "internal",
        parameters: {
          code_verifier: "Random 43-128 char string",
          code_challenge: "SHA256(verifier), base64url encoded",
        },
      },
      {
        order: 2,
        name: "Auth Request + Challenge",
        description: "Redirect with code_challenge (not verifier).",
        from: "Client",
        to: "Authorization Server",
        type: "redirect",
        parameters: {
          response_type: "code",
          code_challenge: "The SHA256 hash",
          code_challenge_method: "S256",
          state: "CSRF protection",
        },
      },
      {
        order: 3,
        name: "User Login",
        description: "User authenticates and consents.",
        from: "User",
        to: "Authorization Server",
        type: "internal",
      },
      {
        order: 4,
        name: "Auth Code",
        description: "Redirect back with authorization code.",
        from: "Authorization Server",
        to: "Client",
        type: "redirect",
        parameters: { code: "Authorization code", state: "Original state" },
      },
      {
        order: 5,
        name: "Token + Verifier",
        description: "Exchange code with original verifier for proof.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          grant_type: "authorization_code",
          code: "Authorization code",
          code_verifier: "Original random string",
        },
      },
      {
        order: 6,
        name: "Tokens",
        description: "Receive tokens after PKCE verification.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          access_token: "Access token",
          refresh_token: "Refresh token",
        },
      },
    ]
  },

  client_credentials: {
    title: "Client Credentials",
    description: "Machine-to-machine authentication without user involvement.",
    steps: [
      {
        order: 1,
        name: "Token Request",
        description: "Service authenticates with its own credentials.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          grant_type: "client_credentials",
          client_id: "Service identifier",
          client_secret: "Service secret",
          scope: "Requested permissions",
        },
      },
      {
        order: 2,
        name: "Access Token",
        description: "Receive access token (no refresh token).",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          access_token: "Access token",
          expires_in: "Token lifetime",
        },
      },
    ]
  },

  refresh_token: {
    title: "Refresh Token",
    description: "Get new access tokens without user interaction.",
    steps: [
      {
        order: 1,
        name: "Refresh Request",
        description: "Use refresh token to get new access token.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          grant_type: "refresh_token",
          refresh_token: "Your refresh token",
        },
      },
      {
        order: 2,
        name: "New Tokens",
        description: "Receive new access token (and possibly new refresh token).",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          access_token: "New access token",
          refresh_token: "New refresh token (if rotation)",
        },
      },
    ]
  },

  token_introspection: {
    title: "Token Introspection",
    description: "Validate tokens and retrieve metadata. Allows resource servers to query the authorization server about the current state of an access token (RFC 7662).",
    steps: [
      {
        order: 1,
        name: "Introspection Request",
        description: "Resource server sends token to introspection endpoint for validation.",
        from: "Resource Server",
        to: "Authorization Server",
        type: "request",
        parameters: {
          token: "The access token to introspect",
          token_type_hint: "access_token (optional)",
          client_id: "Resource server identifier",
          client_secret: "Resource server secret",
        },
      },
      {
        order: 2,
        name: "Introspection Response",
        description: "Authorization server returns token metadata and validity status.",
        from: "Authorization Server",
        to: "Resource Server",
        type: "response",
        parameters: {
          active: "Boolean - is token valid?",
          scope: "Granted scopes",
          client_id: "Client that requested token",
          username: "Resource owner (if applicable)",
          exp: "Expiration timestamp",
          iat: "Issued-at timestamp",
          sub: "Subject identifier",
          aud: "Intended audience",
          iss: "Token issuer",
        },
      },
      {
        order: 3,
        name: "Access Decision",
        description: "Resource server uses introspection result to authorize the request.",
        from: "Resource Server",
        to: "Resource Server",
        type: "internal",
        parameters: {
          check: "active === true",
          verify: "scope includes required permissions",
          validate: "exp > current time",
        },
      },
    ]
  },

  token_revocation: {
    title: "Token Revocation",
    description: "Invalidate access or refresh tokens before their natural expiration. Essential for logout flows and security incident response (RFC 7009).",
    steps: [
      {
        order: 1,
        name: "Revocation Request",
        description: "Client sends token to revocation endpoint to invalidate it.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          token: "The token to revoke",
          token_type_hint: "refresh_token or access_token (optional)",
          client_id: "Your client identifier",
          client_secret: "Your client secret (if confidential)",
        },
      },
      {
        order: 2,
        name: "Revocation Response",
        description: "Server acknowledges revocation (200 OK even if token was already invalid).",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          status: "200 OK (always, for security)",
          note: "No body content on success",
        },
      },
      {
        order: 3,
        name: "Token Invalidated",
        description: "Token can no longer be used; introspection will return active=false.",
        from: "Authorization Server",
        to: "Authorization Server",
        type: "internal",
        parameters: {
          cascade: "Revoking refresh token may revoke associated access tokens",
          security: "Prevents token reuse after logout or compromise",
        },
      },
    ]
  },

  oidc_authorization_code: {
    title: "OIDC Authorization Code Flow",
    description: "OpenID Connect flow using authorization code for authentication. Returns ID token with user identity claims.",
    steps: [
      {
        order: 1,
        name: "Discovery",
        description: "Client fetches OpenID Provider configuration.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          endpoint: "/.well-known/openid-configuration",
        },
      },
      {
        order: 2,
        name: "JWKS Fetch",
        description: "Client fetches public keys for token validation.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          endpoint: "/.well-known/jwks.json",
        },
      },
      {
        order: 3,
        name: "Auth Request",
        description: "Redirect with 'openid' scope for identity.",
        from: "Client",
        to: "Authorization Server",
        type: "redirect",
        parameters: {
          response_type: "code",
          scope: "openid profile email",
          nonce: "Replay protection (binds ID token to session)",
          state: "CSRF protection",
        },
      },
      {
        order: 4,
        name: "User Login",
        description: "User authenticates and consents to share profile.",
        from: "User",
        to: "Authorization Server",
        type: "internal",
      },
      {
        order: 5,
        name: "Auth Code",
        description: "Redirect with authorization code.",
        from: "Authorization Server",
        to: "Client",
        type: "redirect",
        parameters: { 
          code: "Authorization code",
          state: "Must match original",
        },
      },
      {
        order: 6,
        name: "Token Request",
        description: "Exchange code for tokens.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: { 
          grant_type: "authorization_code", 
          code: "Auth code",
          redirect_uri: "Must match original",
        },
      },
      {
        order: 7,
        name: "Tokens + ID Token",
        description: "Receive access token AND ID token with user claims.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          access_token: "For API access",
          id_token: "JWT with identity claims",
          refresh_token: "For token renewal",
        },
      },
      {
        order: 8,
        name: "ID Token Validation",
        description: "Validate the ID token signature and claims.",
        from: "Client",
        to: "Client",
        type: "internal",
        parameters: {
          verify: "Signature using JWKS",
          check: "iss, aud, exp, nonce claims",
        },
      },
      {
        order: 9,
        name: "UserInfo (optional)",
        description: "Request additional user claims.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: { Authorization: "Bearer {access_token}" },
      },
      {
        order: 10,
        name: "User Profile",
        description: "Receive user profile data.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: { 
          sub: "Unique user identifier",
          name: "Full name",
          email: "Email address",
          picture: "Profile picture URL",
        },
      },
    ]
  },

  oidc_implicit: {
    title: "OIDC Implicit Flow (Legacy)",
    description: "Direct token response in redirect URL fragment. Not recommended for new applications - use Authorization Code + PKCE instead.",
    steps: [
      {
        order: 1,
        name: "Auth Request",
        description: "Request tokens directly (no code exchange).",
        from: "Client",
        to: "Authorization Server",
        type: "redirect",
        parameters: {
          response_type: "id_token token",
          scope: "openid profile",
          nonce: "Required for implicit flow",
          state: "CSRF protection",
        },
      },
      {
        order: 2,
        name: "User Login",
        description: "User authenticates and consents.",
        from: "User",
        to: "Authorization Server",
        type: "internal",
      },
      {
        order: 3,
        name: "Token Response",
        description: "Tokens returned in URL fragment (#).",
        from: "Authorization Server",
        to: "Client",
        type: "redirect",
        parameters: {
          id_token: "JWT with identity",
          access_token: "For API access",
          token_type: "Bearer",
        },
      },
      {
        order: 4,
        name: "ID Token Validation",
        description: "Validate the ID token.",
        from: "Client",
        to: "Client",
        type: "internal",
        parameters: {
          verify: "Signature and nonce",
          warning: "Tokens exposed in browser history",
        },
      },
    ]
  },

  oidc_hybrid: {
    title: "OIDC Hybrid Flow",
    description: "Combines authorization code and implicit flows. Returns some tokens from the authorization endpoint and others from the token endpoint.",
    steps: [
      {
        order: 1,
        name: "Auth Request",
        description: "Request code and tokens simultaneously.",
        from: "Client",
        to: "Authorization Server",
        type: "redirect",
        parameters: {
          response_type: "code id_token (or code token, code id_token token)",
          scope: "openid profile email",
          nonce: "Required - binds tokens to session",
          state: "CSRF protection",
        },
      },
      {
        order: 2,
        name: "User Login",
        description: "User authenticates and consents.",
        from: "User",
        to: "Authorization Server",
        type: "internal",
      },
      {
        order: 3,
        name: "Hybrid Response",
        description: "ID token in fragment, code in query (or both in fragment).",
        from: "Authorization Server",
        to: "Client",
        type: "redirect",
        parameters: {
          code: "Authorization code (for backend)",
          id_token: "Immediate identity verification",
          state: "Must match original",
        },
      },
      {
        order: 4,
        name: "Validate ID Token",
        description: "Verify ID token immediately for quick identity.",
        from: "Client",
        to: "Client",
        type: "internal",
        parameters: {
          verify: "Signature using JWKS",
          check: "nonce, iss, aud claims",
        },
      },
      {
        order: 5,
        name: "Token Exchange",
        description: "Exchange code for access token (backend).",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          grant_type: "authorization_code",
          code: "The authorization code",
        },
      },
      {
        order: 6,
        name: "Access Token",
        description: "Receive access token for API calls.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          access_token: "For API access",
          refresh_token: "For token renewal",
        },
      },
    ]
  },

  oidc_userinfo: {
    title: "UserInfo Endpoint",
    description: "Retrieve claims about the authenticated user using an access token. Returns profile information based on granted scopes.",
    steps: [
      {
        order: 1,
        name: "UserInfo Request",
        description: "Request user claims with access token.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          method: "GET or POST",
          Authorization: "Bearer {access_token}",
          endpoint: "/oidc/userinfo",
        },
      },
      {
        order: 2,
        name: "Token Validation",
        description: "Server validates the access token.",
        from: "Authorization Server",
        to: "Authorization Server",
        type: "internal",
        parameters: {
          check: "Token not expired",
          verify: "Token has 'openid' scope",
          lookup: "Associated user identity",
        },
      },
      {
        order: 3,
        name: "UserInfo Response",
        description: "Return user claims based on token scopes.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          sub: "Subject identifier (always present)",
          name: "Full name (profile scope)",
          email: "Email address (email scope)",
          email_verified: "Email verification status",
          picture: "Profile picture URL",
          updated_at: "Last profile update timestamp",
        },
      },
    ]
  },

  oidc_discovery: {
    title: "OpenID Connect Discovery",
    description: "Auto-configuration mechanism that allows clients to discover the OpenID Provider's endpoints and capabilities.",
    steps: [
      {
        order: 1,
        name: "Discovery Request",
        description: "Fetch the OpenID Provider configuration document.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          endpoint: "/.well-known/openid-configuration",
          method: "GET",
        },
      },
      {
        order: 2,
        name: "Configuration Response",
        description: "Receive metadata about the OpenID Provider.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          issuer: "Provider identifier URL",
          authorization_endpoint: "URL for authorization",
          token_endpoint: "URL for token exchange",
          userinfo_endpoint: "URL for user claims",
          jwks_uri: "URL for signing keys",
          scopes_supported: "Available scopes",
          response_types_supported: "Supported response types",
          claims_supported: "Available user claims",
        },
      },
      {
        order: 3,
        name: "JWKS Request",
        description: "Fetch the JSON Web Key Set for signature validation.",
        from: "Client",
        to: "Authorization Server",
        type: "request",
        parameters: {
          endpoint: "Value from jwks_uri",
          method: "GET",
        },
      },
      {
        order: 4,
        name: "JWKS Response",
        description: "Receive public keys for token validation.",
        from: "Authorization Server",
        to: "Client",
        type: "response",
        parameters: {
          keys: "Array of JWK objects",
          kty: "Key type (RSA, EC)",
          use: "Key usage (sig)",
          kid: "Key ID for matching",
          n: "RSA modulus (if RSA)",
          e: "RSA exponent (if RSA)",
        },
      },
    ]
  },

  // SAML 2.0 Flows
  saml_sp_initiated_sso: {
    title: "SP-Initiated SSO",
    description: "Service Provider initiates Single Sign-On by redirecting the user to the Identity Provider with an AuthnRequest.",
    steps: [
      {
        order: 1,
        name: "Access Protected Resource",
        description: "User attempts to access a protected resource at the Service Provider.",
        from: "User",
        to: "Service Provider",
        type: "request",
      },
      {
        order: 2,
        name: "Generate AuthnRequest",
        description: "SP creates a SAML AuthnRequest message to request authentication.",
        from: "Service Provider",
        to: "Service Provider",
        type: "internal",
        parameters: {
          ID: "Unique request identifier",
          IssueInstant: "Timestamp of request creation",
          Issuer: "SP Entity ID",
          AssertionConsumerServiceURL: "Where to send the response",
          ProtocolBinding: "HTTP-POST or HTTP-Redirect",
        },
      },
      {
        order: 3,
        name: "Redirect to IdP",
        description: "SP redirects user to IdP SSO Service with the AuthnRequest.",
        from: "Service Provider",
        to: "Identity Provider",
        type: "redirect",
        parameters: {
          SAMLRequest: "Base64-encoded (and deflated for redirect) AuthnRequest",
          RelayState: "Opaque state to be echoed back",
          SigAlg: "Signature algorithm (if signed)",
          Signature: "Request signature (if signed)",
        },
      },
      {
        order: 4,
        name: "User Authentication",
        description: "User authenticates at the Identity Provider.",
        from: "User",
        to: "Identity Provider",
        type: "internal",
      },
      {
        order: 5,
        name: "Generate SAML Response",
        description: "IdP creates a SAML Response containing the Assertion with user identity.",
        from: "Identity Provider",
        to: "Identity Provider",
        type: "internal",
        parameters: {
          Status: "Success or error code",
          Assertion: "Signed assertion with user identity",
          NameID: "User identifier",
          Attributes: "User attributes (optional)",
          Conditions: "Validity constraints",
          AuthnStatement: "Authentication context",
        },
      },
      {
        order: 6,
        name: "POST Response to ACS",
        description: "IdP sends SAML Response to SP's Assertion Consumer Service.",
        from: "Identity Provider",
        to: "Service Provider",
        type: "response",
        parameters: {
          SAMLResponse: "Base64-encoded SAML Response",
          RelayState: "Echoed from request",
        },
      },
      {
        order: 7,
        name: "Validate Assertion",
        description: "SP validates the signature, conditions, and extracts identity.",
        from: "Service Provider",
        to: "Service Provider",
        type: "internal",
        parameters: {
          verify_signature: "Check Response/Assertion signature",
          check_inresponseto: "Must match original request ID",
          validate_conditions: "NotBefore/NotOnOrAfter timestamps",
          verify_audience: "SP Entity ID must be in audience",
          check_replay: "Assertion ID not previously used",
        },
      },
      {
        order: 8,
        name: "Create Session",
        description: "SP creates a local session and grants access to the resource.",
        from: "Service Provider",
        to: "User",
        type: "response",
      },
    ]
  },

  saml_idp_initiated_sso: {
    title: "IdP-Initiated SSO",
    description: "Identity Provider initiates Single Sign-On without a prior AuthnRequest. User starts at IdP and is sent to SP with an unsolicited SAML Response.",
    steps: [
      {
        order: 1,
        name: "User at IdP Portal",
        description: "User is authenticated at the IdP and selects an SP to access.",
        from: "User",
        to: "Identity Provider",
        type: "request",
      },
      {
        order: 2,
        name: "Generate Unsolicited Response",
        description: "IdP creates a SAML Response without a prior AuthnRequest.",
        from: "Identity Provider",
        to: "Identity Provider",
        type: "internal",
        parameters: {
          InResponseTo: "Empty (no request to respond to)",
          Destination: "SP's ACS URL from metadata",
          note: "No InResponseTo to validate - increased replay risk",
        },
      },
      {
        order: 3,
        name: "POST Response to SP",
        description: "IdP POSTs the SAML Response to SP's Assertion Consumer Service.",
        from: "Identity Provider",
        to: "Service Provider",
        type: "response",
        parameters: {
          SAMLResponse: "Base64-encoded SAML Response with Assertion",
          RelayState: "Optional - target URL at SP",
        },
      },
      {
        order: 4,
        name: "Validate Assertion",
        description: "SP validates the response and extracts identity.",
        from: "Service Provider",
        to: "Service Provider",
        type: "internal",
        parameters: {
          verify_signature: "Check Assertion signature",
          validate_conditions: "Check time constraints",
          check_audience: "Verify SP is intended recipient",
          security_note: "Cannot verify InResponseTo - use other replay prevention",
        },
      },
      {
        order: 5,
        name: "Create Session",
        description: "SP creates a local session and grants access.",
        from: "Service Provider",
        to: "User",
        type: "response",
      },
    ]
  },

  saml_single_logout: {
    title: "Single Logout (SLO)",
    description: "Terminates all sessions established via SSO across all participating Service Providers and the Identity Provider.",
    steps: [
      {
        order: 1,
        name: "Initiate Logout",
        description: "User initiates logout at one participant (SP or IdP).",
        from: "User",
        to: "Service Provider",
        type: "request",
      },
      {
        order: 2,
        name: "Create LogoutRequest",
        description: "Initiating party creates a SAML LogoutRequest.",
        from: "Service Provider",
        to: "Service Provider",
        type: "internal",
        parameters: {
          NameID: "Identifier of user being logged out",
          SessionIndex: "Specific session to terminate (optional)",
          Reason: "Logout reason (optional)",
        },
      },
      {
        order: 3,
        name: "Send LogoutRequest to IdP",
        description: "SP sends LogoutRequest to IdP's SLO endpoint.",
        from: "Service Provider",
        to: "Identity Provider",
        type: "request",
        parameters: {
          SAMLRequest: "Base64-encoded LogoutRequest",
          RelayState: "State to maintain through logout",
        },
      },
      {
        order: 4,
        name: "Propagate to Other SPs",
        description: "IdP sends LogoutRequest to all other SPs with active sessions.",
        from: "Identity Provider",
        to: "Other Service Providers",
        type: "request",
        parameters: {
          note: "Each SP must validate and terminate their session",
        },
      },
      {
        order: 5,
        name: "SPs Respond",
        description: "Each SP terminates its session and sends LogoutResponse.",
        from: "Service Providers",
        to: "Identity Provider",
        type: "response",
        parameters: {
          Status: "Success or failure",
        },
      },
      {
        order: 6,
        name: "IdP Terminates Session",
        description: "IdP terminates its own session for the user.",
        from: "Identity Provider",
        to: "Identity Provider",
        type: "internal",
      },
      {
        order: 7,
        name: "Final LogoutResponse",
        description: "IdP sends LogoutResponse to the initiating SP.",
        from: "Identity Provider",
        to: "Service Provider",
        type: "response",
        parameters: {
          Status: "Success or PartialLogout",
          InResponseTo: "Original LogoutRequest ID",
        },
      },
      {
        order: 8,
        name: "Logout Complete",
        description: "User is logged out of all participants.",
        from: "Service Provider",
        to: "User",
        type: "response",
      },
    ]
  },

  saml_metadata: {
    title: "Metadata Exchange",
    description: "Exchange of SAML metadata documents describing entity configurations, endpoints, certificates, and capabilities.",
    steps: [
      {
        order: 1,
        name: "Request SP Metadata",
        description: "Retrieve the Service Provider's metadata document.",
        from: "Identity Provider",
        to: "Service Provider",
        type: "request",
        parameters: {
          endpoint: "/saml/metadata",
          method: "GET",
        },
      },
      {
        order: 2,
        name: "SP Metadata Response",
        description: "SP returns its metadata XML document.",
        from: "Service Provider",
        to: "Identity Provider",
        type: "response",
        parameters: {
          entityID: "SP's unique identifier",
          AssertionConsumerService: "ACS URL and binding",
          SingleLogoutService: "SLO URL and binding",
          KeyDescriptor: "X.509 certificates for signing/encryption",
          NameIDFormat: "Supported name identifier formats",
        },
      },
      {
        order: 3,
        name: "Request IdP Metadata",
        description: "Retrieve the Identity Provider's metadata document.",
        from: "Service Provider",
        to: "Identity Provider",
        type: "request",
        parameters: {
          endpoint: "/saml/metadata",
          method: "GET",
        },
      },
      {
        order: 4,
        name: "IdP Metadata Response",
        description: "IdP returns its metadata XML document.",
        from: "Identity Provider",
        to: "Service Provider",
        type: "response",
        parameters: {
          entityID: "IdP's unique identifier",
          SingleSignOnService: "SSO URL and binding",
          SingleLogoutService: "SLO URL and binding",
          KeyDescriptor: "X.509 certificates for signing",
          NameIDFormat: "Supported name identifier formats",
        },
      },
      {
        order: 5,
        name: "Configure Trust",
        description: "Both parties import and configure the other's metadata.",
        from: "Both Parties",
        to: "Both Parties",
        type: "internal",
        parameters: {
          verify_signature: "Validate metadata signature if signed",
          store_certificates: "Cache certificates for validation",
          configure_endpoints: "Set up SSO/SLO URLs",
        },
      },
    ]
  },

  // ============================================================================
  // SPIFFE/SPIRE Flows
  // ============================================================================

  'x509-svid-issuance': {
    title: "X.509-SVID Acquisition",
    description: "Acquire an X.509 certificate containing a SPIFFE ID via the Workload API.",
    steps: [
      {
        order: 1,
        name: "Connect to Workload API",
        description: "Workload connects to SPIRE Agent via Unix Domain Socket.",
        from: "Workload",
        to: "SPIRE Agent",
        type: "request",
        parameters: {
          socket_path: "unix:///run/spire/sockets/agent.sock",
          protocol: "gRPC",
          api_method: "FetchX509SVID (streaming)",
        },
      },
      {
        order: 2,
        name: "Workload Attestation",
        description: "Agent verifies the calling workload's identity using selectors.",
        from: "SPIRE Agent",
        to: "Workload Attestor",
        type: "internal",
        parameters: {
          unix_selectors: "uid, gid, binary path",
          docker_selectors: "container labels, image ID",
          k8s_selectors: "namespace, service account, pod labels",
        },
      },
      {
        order: 3,
        name: "SVID Request",
        description: "Agent requests SVID from SPIRE Server on workload's behalf.",
        from: "SPIRE Agent",
        to: "SPIRE Server",
        type: "request",
        parameters: {
          spiffe_id: "From registration entry",
          csr: "Certificate Signing Request",
          ttl_hint: "Requested TTL",
        },
      },
      {
        order: 4,
        name: "Certificate Signing",
        description: "Server signs the certificate with the trust domain CA.",
        from: "SPIRE Server",
        to: "CA",
        type: "internal",
        parameters: {
          issuer: "Trust domain CA",
          san_uri: "spiffe://trust-domain/workload/path",
          validity: "Short-lived (typically 1 hour)",
        },
      },
      {
        order: 5,
        name: "SVID Delivery",
        description: "X.509-SVID delivered to workload with private key.",
        from: "SPIRE Agent",
        to: "Workload",
        type: "response",
        parameters: {
          x509_svid: "Signed X.509 certificate",
          private_key: "Corresponding private key",
          trust_bundle: "CA certificates for verification",
        },
      },
    ]
  },

  'jwt-svid-issuance': {
    title: "JWT-SVID Acquisition",
    description: "Acquire a JWT token containing SPIFFE claims for API authentication.",
    steps: [
      {
        order: 1,
        name: "Request JWT-SVID",
        description: "Workload requests JWT-SVID with target audience.",
        from: "Workload",
        to: "SPIRE Agent",
        type: "request",
        parameters: {
          api_method: "FetchJWTSVID",
          audience: "Intended recipient (e.g., api.example.com)",
        },
      },
      {
        order: 2,
        name: "Identity Verification",
        description: "Agent verifies workload is authorized for this SPIFFE ID.",
        from: "SPIRE Agent",
        to: "Registration Cache",
        type: "internal",
        parameters: {
          selector_match: "Verify workload selectors match entry",
          spiffe_id: "Assigned from matching entry",
        },
      },
      {
        order: 3,
        name: "JWT Generation",
        description: "Server generates and signs JWT with SPIFFE claims.",
        from: "SPIRE Server",
        to: "JWT Signer",
        type: "internal",
        parameters: {
          alg: "ES256 or RS256",
          sub: "SPIFFE ID (spiffe://trust-domain/path)",
          aud: "Target audience(s)",
          exp: "Short expiration (typically 5 minutes)",
          iat: "Issued at timestamp",
        },
      },
      {
        order: 4,
        name: "Token Delivery",
        description: "JWT-SVID returned to workload for API authentication.",
        from: "SPIRE Agent",
        to: "Workload",
        type: "response",
        parameters: {
          token: "Signed JWT-SVID",
          expiry: "Token expiration time",
        },
      },
    ]
  },

  'mtls-handshake': {
    title: "mTLS with X.509-SVIDs",
    description: "Establish mutual TLS authentication between services using SPIFFE identities.",
    steps: [
      {
        order: 1,
        name: "Client Fetches SVID",
        description: "Client service obtains its X.509-SVID from Workload API.",
        from: "Client",
        to: "SPIRE Agent",
        type: "request",
        parameters: {
          x509_svid: "Client's certificate",
          private_key: "Client's private key",
          trust_bundle: "CA certificates",
        },
      },
      {
        order: 2,
        name: "TLS Client Hello",
        description: "Client initiates TLS connection to server.",
        from: "Client",
        to: "Server",
        type: "request",
        parameters: {
          tls_version: "TLS 1.2 or 1.3",
          cipher_suites: "Supported algorithms",
        },
      },
      {
        order: 3,
        name: "Server Certificate",
        description: "Server presents its X.509-SVID certificate.",
        from: "Server",
        to: "Client",
        type: "response",
        parameters: {
          certificate: "Server's X.509-SVID",
          san_uri: "spiffe://trust-domain/server",
        },
      },
      {
        order: 4,
        name: "Client Certificate",
        description: "Client presents its X.509-SVID certificate.",
        from: "Client",
        to: "Server",
        type: "response",
        parameters: {
          certificate: "Client's X.509-SVID",
          san_uri: "spiffe://trust-domain/client",
        },
      },
      {
        order: 5,
        name: "Mutual Verification",
        description: "Both sides verify certificates against SPIFFE trust bundle.",
        from: "Both",
        to: "Trust Bundle",
        type: "internal",
        parameters: {
          chain_validation: "Verify to trusted root",
          spiffe_id_check: "Extract and authorize SPIFFE ID",
        },
      },
      {
        order: 6,
        name: "Secure Channel",
        description: "Encrypted channel established with verified identities.",
        from: "Client",
        to: "Server",
        type: "internal",
        parameters: {
          client_id: "spiffe://trust-domain/client",
          server_id: "spiffe://trust-domain/server",
          encryption: "TLS 1.3 with forward secrecy",
        },
      },
    ]
  },

  'certificate-rotation': {
    title: "Certificate Rotation",
    description: "Automatic X.509-SVID rotation without service disruption.",
    steps: [
      {
        order: 1,
        name: "Monitor Expiration",
        description: "SPIRE Agent monitors certificate lifetime.",
        from: "SPIRE Agent",
        to: "SVID Cache",
        type: "internal",
        parameters: {
          check_interval: "Periodic (e.g., every 30s)",
          rotation_threshold: "Typically 50% of TTL",
        },
      },
      {
        order: 2,
        name: "Pre-Rotation Request",
        description: "Agent requests new SVID before expiration.",
        from: "SPIRE Agent",
        to: "SPIRE Server",
        type: "request",
        parameters: {
          reason: "Approaching rotation threshold",
          current_serial: "For tracking",
        },
      },
      {
        order: 3,
        name: "New SVID Issued",
        description: "Server issues fresh certificate with new validity period.",
        from: "SPIRE Server",
        to: "SPIRE Agent",
        type: "response",
        parameters: {
          new_x509_svid: "Fresh certificate",
          new_serial: "New serial number",
          validity: "Fresh TTL period",
        },
      },
      {
        order: 4,
        name: "Workload Notification",
        description: "Workload receives new SVID via streaming API.",
        from: "SPIRE Agent",
        to: "Workload",
        type: "response",
        parameters: {
          streaming_update: "FetchX509SVID stream delivers new SVID",
          trust_bundle: "Updated if changed",
        },
      },
      {
        order: 5,
        name: "Graceful Transition",
        description: "Workload uses new certificate for new connections.",
        from: "Workload",
        to: "TLS Stack",
        type: "internal",
        parameters: {
          new_connections: "Use new certificate",
          existing_connections: "Continue with old cert until closed",
          zero_downtime: "No service interruption",
        },
      },
    ]
  },
}

/**
 * Map URL slugs to flow IDs
 */
export const flowIdMap: Record<string, string> = {
  // OAuth 2.0 flows
  'authorization-code': 'authorization_code',
  'authorization-code-pkce': 'authorization_code_pkce',
  'client-credentials': 'client_credentials',
  'refresh-token': 'refresh_token',
  'token-introspection': 'token_introspection',
  'token-revocation': 'token_revocation',
  // OIDC flows
  'oidc-code': 'oidc_authorization_code',
  'oidc-authorization-code': 'oidc_authorization_code',
  'oidc-implicit': 'oidc_implicit',
  'oidc_implicit': 'oidc_implicit',
  'hybrid': 'oidc_hybrid',
  'userinfo': 'oidc_userinfo',
  'discovery': 'oidc_discovery',
  // SAML 2.0 flows
  'sp-initiated-sso': 'saml_sp_initiated_sso',
  'idp-initiated-sso': 'saml_idp_initiated_sso',
  'single-logout': 'saml_single_logout',
  'metadata': 'saml_metadata',
  // SPIFFE/SPIRE flows (use consistent hyphenated format)
  'x509-svid-issuance': 'x509-svid-issuance',
  'jwt-svid-issuance': 'jwt-svid-issuance',
  'mtls-handshake': 'mtls-handshake',
  'certificate-rotation': 'certificate-rotation',
}

/**
 * Get flow data with fallback to local data
 */
export function getFlowWithFallback(flowId: string): FlowData | undefined {
  const mappedId = flowIdMap[flowId] || flowId
  return fallbackFlows[mappedId]
}

