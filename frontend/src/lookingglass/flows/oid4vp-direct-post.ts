/**
 * OID4VP Direct Post Flow Executor
 *
 * Executes verifier-side OID4VP flow:
 * - Create DCQL request object
 * - Hand off request to an external wallet
 * - Fetch verifier result and policy decision
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'
import { decodeJWTWithoutValidation } from '../../utils/crypto'

export interface OID4VPDirectPostConfig extends FlowExecutorConfig {
  responseMode?: 'direct_post' | 'direct_post.jwt'
  dcqlQueryJSON?: string
  scopeAlias?: string
}

export class OID4VPDirectPostExecutor extends FlowExecutorBase {
  readonly flowType = 'oid4vp_direct_post'
  readonly flowName = 'OID4VP Direct Post'
  readonly rfcReference = 'OpenID4VP 1.0'

  private flowConfig: OID4VPDirectPostConfig

  constructor(config: OID4VPDirectPostConfig) {
    super(config)
    this.flowConfig = config
  }

  async execute(): Promise<void> {
    if (this.state.status === 'executing') {
      return
    }

    if (this.state.status === 'awaiting_user') {
      const requestID = String(this.state.securityParams.requestId || '').trim()
      if (!requestID) {
        this.updateState({
          status: 'error',
          currentStep: 'OID4VP flow failed',
          error: {
            code: 'oid4vp_flow_failed',
            description: 'Missing request_id for result lookup',
          },
        })
        return
      }

      this.abortController?.abort()
      this.abortController = new AbortController()
      this.updateState({
        status: 'executing',
        currentStep: 'Checking verifier result',
      })

      try {
        const resultData = await this.fetchVerificationResult(requestID)
        if (!resultData) {
          this.updateState({
            status: 'awaiting_user',
            currentStep: 'Waiting for wallet response callback',
          })
          this.addEvent({
            type: 'info',
            title: 'Still Waiting for Wallet Callback',
            description: `No completed verifier result for request_id=${requestID} yet. Complete wallet handoff, then check again.`,
          })
          return
        }

        this.applyVerificationResult(requestID, resultData)
        this.updateState({
          status: 'completed',
          currentStep: 'OID4VP flow completed',
        })
      } catch (error) {
        const description = error instanceof Error ? error.message : 'Unknown OID4VP flow error'
        this.updateState({
          status: 'error',
          currentStep: 'OID4VP flow failed',
          error: {
            code: 'oid4vp_flow_failed',
            description,
          },
        })
        this.addEvent({
          type: 'error',
          title: 'OID4VP Result Check Failed',
          description,
        })
      }
      return
    }

    this.abortController?.abort()
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Starting OID4VP verifier flow',
    })

    try {
      const request = await this.createAuthorizationRequest()
      const requestID = String(request.request_id || '')
      if (!requestID) {
        throw new Error('OID4VP request response missing request_id')
      }
      this.updateState({
        status: 'awaiting_user',
        currentStep: 'Waiting for wallet response callback',
      })
    } catch (error) {
      const description = error instanceof Error ? error.message : 'Unknown OID4VP flow error'
      this.updateState({
        status: 'error',
        currentStep: 'OID4VP flow failed',
        error: {
          code: 'oid4vp_flow_failed',
          description,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'OID4VP Execution Failed',
        description,
      })
    }
  }

  private async createAuthorizationRequest(): Promise<Record<string, unknown>> {
    this.updateState({ currentStep: 'Creating verifier authorization request' })

    const responseMode = this.flowConfig.responseMode || 'direct_post'
    const defaultDCQLQuery = {
      credentials: [
        {
          id: 'university_degree',
          meta: {
            vct_values: ['https://protocolsoup.com/credentials/university_degree'],
          },
          claims: [{ path: ['degree'] }, { path: ['graduation_year'] }],
        },
      ],
    }
    const configuredScopeAlias = String(this.flowConfig.scopeAlias || '').trim()
    const configuredDCQLRaw = String(this.flowConfig.dcqlQueryJSON || '').trim()
    let dcqlQuery: Record<string, unknown> | null = null
    if (configuredDCQLRaw) {
      try {
        dcqlQuery = JSON.parse(configuredDCQLRaw) as Record<string, unknown>
      } catch {
        throw new Error('Configured dcql_query is not valid JSON')
      }
    }
    if (!dcqlQuery && !configuredScopeAlias) {
      dcqlQuery = defaultDCQLQuery
    }

    const requestPayload: Record<string, unknown> = {
      response_mode: responseMode,
      response_uri: `${window.location.origin}${this.config.baseUrl}/response`,
    }
    if (configuredScopeAlias) {
      requestPayload.scope = configuredScopeAlias
    }
    if (dcqlQuery) {
      requestPayload.dcql_query = dcqlQuery
    }

    const { response, data } = await this.makeRequest('POST', `${this.config.baseUrl}/request/create`, {
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestPayload),
      step: 'Create OID4VP request object',
      rfcReference: 'OpenID4VP 1.0 Section 5',
    })

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(String(errorData.error_description || errorData.error || `Request creation failed (${response.status})`))
    }

    const requestData = data as Record<string, unknown>
    const requestID = String(requestData.request_id || '')
    if (!requestID) {
      throw new Error('OID4VP request response missing request_id')
    }
    const requestURI = String(requestData.request_uri || '')
    const requestJWT = String(requestData.request || '')
    const decodedRequestJWT = requestJWT ? decodeJWTWithoutValidation(requestJWT) : null
    const trustMode = String(requestData.trust_mode || '').trim()
    const didWebAllowedHosts = Array.isArray(requestData.did_web_allowed_hosts)
      ? requestData.did_web_allowed_hosts.map(host => String(host).trim()).filter(Boolean)
      : []
    const deepLink = requestURI
      ? `openid4vp://authorize?request_uri=${encodeURIComponent(requestURI)}`
      : ''

    if (requestJWT) {
      this.addVCArtifact({
        type: 'request_object',
        title: 'OID4VP Request Object',
        format: 'oauth-authz-req+jwt',
        rfcReference: 'OpenID4VP 1.0 Section 5',
        raw: requestJWT,
        json: decodedRequestJWT
          ? { header: decodedRequestJWT.header, payload: decodedRequestJWT.payload }
          : {},
        metadata: {
          responseMode,
          requestURI,
          trustMode,
          didWebAllowedHosts,
          scopeAlias: configuredScopeAlias || undefined,
          dcqlQueryConfigured: Boolean(dcqlQuery),
        },
      })
    }
    if (deepLink || requestURI) {
      this.addVCArtifact({
        type: 'wallet_handoff',
        title: 'Wallet Handoff Payload',
        format: 'openid4vp-deeplink',
        rfcReference: 'OpenID4VP 1.0 Section 5',
        raw: deepLink || requestURI,
        metadata: {
          deepLink,
          qrPayload: deepLink || requestURI,
          requestURI,
          responseMode,
          trustMode,
          didWebAllowedHosts,
        },
      })
    }
    this.addEvent({
      type: 'user_action',
      title: 'Wallet Handoff Ready',
      description: 'Share deep link or QR payload with a real wallet and wait for direct_post callback',
      rfcReference: 'OpenID4VP 1.0 Section 5',
      data: {
        request_id: requestID,
        request_uri: requestURI,
        deep_link: deepLink,
        qr_payload: deepLink || requestURI,
        trust_mode: trustMode || undefined,
        did_web_allowed_hosts: didWebAllowedHosts,
      },
    })
    this.updateState({
      status: 'awaiting_user',
      currentStep: 'Wallet handoff prepared (deep-link/QR)',
      securityParams: {
        ...this.state.securityParams,
        requestId: requestID,
        state: String(requestData.state || ''),
        nonce: String(requestData.nonce || ''),
      },
    })

    this.addEvent({
      type: 'info',
      title: 'Request Object Created',
      description: `request_id=${requestID} mode=${responseMode}`,
      data: {
        requestUri: requestURI,
        responseMode,
        state: requestData.state,
        nonce: requestData.nonce,
        trustMode: trustMode || undefined,
        didWebAllowedHosts,
      },
    })

    return requestData
  }

  private async fetchVerificationResult(requestID: string): Promise<Record<string, unknown> | null> {
    const { response, data } = await this.makeRequest('GET', `${this.config.baseUrl}/result/${requestID}`, {
      headers: { Accept: 'application/json' },
      step: 'Fetch verifier result',
      rfcReference: 'OpenID4VP 1.0',
    })
    if (!response.ok) {
      throw new Error(`Result lookup failed (${response.status})`)
    }

    const payload = data as Record<string, unknown>
    const status = String(payload.status || '')
    if (status !== 'completed') {
      return null
    }
    return payload
  }

  private applyVerificationResult(requestID: string, resultData: Record<string, unknown>): void {
    const result = (resultData.result || {}) as Record<string, unknown>
    const policy = (result.policy || {}) as Record<string, unknown>
    const allowed = Boolean(policy.allowed)
    const reasons = Array.isArray(policy.reasons) ? policy.reasons : []
    const reasonCodes = Array.isArray(policy.reason_codes) ? policy.reason_codes : []
    const credentialEvidence = (result.credential_evidence || {}) as Record<string, unknown>
    const checks = {
      nonceValidated: Boolean(result.nonce_validated),
      audienceValidated: Boolean(result.audience_validated),
      expiryValidated: Boolean(result.expiry_validated),
      holderBindingVerified: Boolean(result.holder_binding_verified),
    }

    this.addVCArtifact({
      type: 'verification_result',
      title: 'Verifier Policy Decision',
      format: 'oid4vp-policy',
      rfcReference: 'OpenID4VP 1.0 Section 8.2',
      json: {
        request_id: requestID,
        result,
      },
      metadata: {
        allowed,
        policyCode: String(policy.code || ''),
        reasons,
        reasonCodes,
        checks,
        credentialEvidence,
      },
    })

    this.addEvent({
      type: allowed ? 'security' : 'error',
      title: allowed ? 'Verifier Policy: Allowed' : 'Verifier Policy: Denied',
      description: String(policy.message || (allowed ? 'Presentation accepted' : 'Presentation denied')),
      data: {
        requestId: requestID,
        policyCode: policy.code,
        reasons,
        reasonCodes,
        nonceValidated: checks.nonceValidated,
        audienceValidated: checks.audienceValidated,
        expiryValidated: checks.expiryValidated,
        holderBindingVerified: checks.holderBindingVerified,
      },
    })

    if (!allowed) {
      throw new Error(`Verifier policy denied request ${requestID}`)
    }
  }

}
