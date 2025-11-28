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
  // OIDC flows
  'oidc-code': 'oidc_authorization_code',
  'oidc-authorization-code': 'oidc_authorization_code',
  'oidc-implicit': 'oidc_implicit',
}

/**
 * Get flow data with fallback to local data
 */
export function getFlowWithFallback(flowId: string): FlowData | undefined {
  const mappedId = flowIdMap[flowId] || flowId
  return fallbackFlows[mappedId]
}

