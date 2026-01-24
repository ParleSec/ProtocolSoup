/**
 * OIDC Discovery Flow Executor
 * 
 * Implements OpenID Connect Discovery 1.0
 * 
 * Makes live requests to the discovery and JWKS endpoints, capturing responses.
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export class OIDCDiscoveryExecutor extends FlowExecutorBase {
  readonly flowType = 'oidc_discovery'
  readonly flowName = 'OIDC Discovery'
  readonly rfcReference = 'OIDC Discovery 1.0'

  constructor(config: FlowExecutorConfig) {
    super(config)
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating OIDC Discovery',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting OIDC Discovery',
      description: `GET ${this.config.baseUrl}/.well-known/openid-configuration`,
      rfcReference: this.rfcReference,
    })

    try {
      const discovery = await this.fetchDiscoveryDocument()
      
      if (discovery.jwks_uri && typeof discovery.jwks_uri === 'string') {
        await this.fetchJWKS(discovery.jwks_uri)
      }

      this.updateState({
        status: 'completed',
        currentStep: 'Discovery completed',
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Discovery failed',
        error: {
          code: 'discovery_error',
          description: message,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Request Failed',
        description: message,
      })
    }
  }

  private async fetchDiscoveryDocument(): Promise<Record<string, unknown>> {
    this.updateState({
      currentStep: 'Fetching discovery document',
    })

    // Make the request
    const { response, data } = await this.makeRequest(
      'GET',
      `${this.config.baseUrl}/.well-known/openid-configuration`,
      {
        headers: {
          'Accept': 'application/json',
        },
        step: 'Discovery Document Request',
        rfcReference: 'OIDC Discovery 1.0 Section 4',
      }
    )

    if (!response.ok) {
      throw new Error(`Discovery document fetch failed with status ${response.status}`)
    }

    const discovery = data as Record<string, unknown>

    // Log the ACTUAL endpoints discovered
    this.addEvent({
      type: 'info',
      title: 'Discovery Document Retrieved',
      description: `Issuer: ${discovery.issuer}`,
      data: {
        issuer: discovery.issuer,
        authorization_endpoint: discovery.authorization_endpoint,
        token_endpoint: discovery.token_endpoint,
        userinfo_endpoint: discovery.userinfo_endpoint,
        jwks_uri: discovery.jwks_uri,
        introspection_endpoint: discovery.introspection_endpoint,
        revocation_endpoint: discovery.revocation_endpoint,
      },
    })

    // Log actual supported capabilities
    this.addEvent({
      type: 'info',
      title: 'Provider Capabilities',
      description: `Response types: ${(discovery.response_types_supported as string[])?.join(', ') || 'N/A'}`,
      data: {
        scopes_supported: discovery.scopes_supported,
        response_types_supported: discovery.response_types_supported,
        grant_types_supported: discovery.grant_types_supported,
        code_challenge_methods_supported: discovery.code_challenge_methods_supported,
        token_endpoint_auth_methods_supported: discovery.token_endpoint_auth_methods_supported,
      },
    })

    return discovery
  }

  private async fetchJWKS(jwksUri: string): Promise<void> {
    this.updateState({
      currentStep: 'Fetching JWKS',
    })

    // Make the request
    const { response, data } = await this.makeRequest(
      'GET',
      jwksUri,
      {
        headers: {
          'Accept': 'application/json',
        },
        step: 'JWKS Request',
        rfcReference: 'RFC 7517',
      }
    )

    if (!response.ok) {
      throw new Error(`JWKS fetch failed with status ${response.status}`)
    }

    const jwks = data as { keys: Array<Record<string, unknown>> }

    // Log the ACTUAL keys retrieved
    this.addEvent({
      type: 'crypto',
      title: 'JWKS Retrieved',
      description: `${jwks.keys?.length || 0} public key(s) available`,
      data: {
        keyCount: jwks.keys?.length || 0,
        keys: jwks.keys?.map(key => ({
          kid: key.kid,
          kty: key.kty,
          alg: key.alg,
          use: key.use,
        })),
      },
    })
  }
}
