/**
 * SPIFFE SVID Flow Executors
 * 
 * Implements SPIFFE Workload API flows per specification:
 * - X.509-SVID acquisition via Workload API
 * - JWT-SVID acquisition and validation
 * - mTLS configuration with X.509-SVIDs
 * - Certificate rotation analysis
 * 
 * Requires SPIRE infrastructure (Server + Agent) for live execution.
 * Without SPIRE, flows will fail with clear infrastructure requirements.
 */

import {
  FlowExecutorBase,
  type FlowExecutorConfig,
} from './base'

// ============================================================================
// Types
// ============================================================================

export interface SPIFFESVIDConfig extends FlowExecutorConfig {
  /** Trust domain for SPIFFE IDs */
  trustDomain: string
  /** Target audience for JWT-SVIDs */
  audience?: string
}

export interface X509SVIDInfo {
  spiffe_id: string
  certificate: string
  chain: string[]
  not_before: string
  not_after: string
  serial_number: string
  issuer: string
  subject: string
  dns_names: string[]
  uris: string[]
  public_key: {
    algorithm: string
    size?: number
    curve?: string
  }
  signature: {
    algorithm: string
    value: string
  }
  extensions: Array<{
    oid: string
    critical: boolean
    name?: string
  }>
}

export interface JWTSVIDInfo {
  token: string
  spiffe_id: string
  audience: string[]
  expires_at: string
  issued_at: string
  header: Record<string, unknown>
  claims: Record<string, unknown>
}

export interface TrustBundleInfo {
  trust_domain: string
  num_roots: number
  roots: Array<{
    subject: string
    issuer: string
    not_before: string
    not_after: string
    serial_number: string
    is_ca: boolean
  }>
}

export interface WorkloadInfo {
  spiffe_id: string
  trust_domain: string
  svid_expiry: string
  enabled: boolean
  socket_path: string
  capabilities: string[]
  metadata?: Record<string, unknown>
}

// ============================================================================
// X.509-SVID Flow Executor
// ============================================================================

export class X509SVIDExecutor extends FlowExecutorBase {
  readonly flowType = 'x509_svid'
  readonly flowName = 'X.509-SVID Acquisition'
  readonly rfcReference = 'SPIFFE X.509-SVID Specification'

  protected config: SPIFFESVIDConfig

  constructor(config: SPIFFESVIDConfig) {
    super(config)
    this.config = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Starting X.509-SVID acquisition' })

    try {
      // Step 1: Check SPIFFE status
      this.addEvent({
        type: 'info',
        title: 'Checking SPIFFE Status',
        description: 'Verifying connection to SPIRE Workload API',
        rfcReference: 'SPIFFE Workload API',
      })

      const statusResponse = await this.makeRequest('GET', `${this.config.baseUrl}/status`, {
        step: 'Check SPIFFE status',
        rfcReference: 'SPIFFE Workload API',
      })

      const status = statusResponse.data as { enabled: boolean; trust_domain: string; spiffe_id?: string; message?: string }
      
      if (status.enabled) {
        this.addEvent({
          type: 'security',
          title: 'Workload API Connected',
          description: `Connected to SPIRE Agent. Trust Domain: ${status.trust_domain}`,
          rfcReference: 'SPIFFE Workload API Specification',
          data: { 
            spiffeId: status.spiffe_id,
            trustDomain: status.trust_domain,
            workloadApiStatus: 'connected'
          },
        })
      } else {
        // SPIRE not available - cannot proceed with real SVID acquisition
        this.addEvent({
          type: 'error',
          title: 'Workload API Unavailable',
          description: 'SPIRE Agent not connected. SVID acquisition requires a running SPIRE infrastructure.',
          rfcReference: 'SPIFFE Workload API Specification',
          data: { 
            trustDomain: status.trust_domain,
            workloadApiStatus: 'unavailable',
            requirement: 'SPIRE Server and Agent must be deployed and running'
          },
        })
        
        this.updateState({
          status: 'error',
          currentStep: 'SPIRE infrastructure required',
          error: {
            code: 'WORKLOAD_API_UNAVAILABLE',
            description: 'Cannot acquire SVIDs without SPIRE infrastructure. Deploy SPIRE Server and Agent to enable real workload identity.',
          },
        })
        return
      }

      // Step 2: Get workload information
      this.addEvent({
        type: 'info',
        title: 'Fetching Workload Information',
        description: 'Getting workload identity details from SPIRE Agent',
        rfcReference: 'SPIFFE Workload API',
      })

      const workloadResponse = await this.makeRequest('GET', `${this.config.baseUrl}/workload`, {
        step: 'Get workload information',
        rfcReference: 'SPIFFE Workload API',
      })

      const workloadInfo = workloadResponse.data as WorkloadInfo
      
      this.addEvent({
        type: 'info',
        title: 'Workload Info Retrieved',
        description: `SPIFFE ID: ${workloadInfo.spiffe_id || 'N/A'}`,
        data: { ...workloadInfo } as Record<string, unknown>,
      })

      // Step 3: Fetch X.509-SVID
      this.addEvent({
        type: 'crypto',
        title: 'Requesting X.509-SVID',
        description: 'Fetching X.509 certificate with SPIFFE ID from Workload API',
        rfcReference: 'X.509-SVID Specification Section 3',
      })

      const svidResponse = await this.makeRequest('GET', `${this.config.baseUrl}/svid/x509`, {
        step: 'Fetch X.509-SVID',
        rfcReference: 'X.509-SVID Specification',
      })

      const x509SVID = svidResponse.data as X509SVIDInfo

      this.addEvent({
        type: 'security',
        title: 'X.509-SVID Received',
        description: `SPIFFE ID: ${x509SVID.spiffe_id}`,
        rfcReference: 'X.509-SVID Specification Section 4',
        data: {
          spiffeId: x509SVID.spiffe_id,
          notBefore: x509SVID.not_before,
          notAfter: x509SVID.not_after,
          issuer: x509SVID.issuer,
        },
      })

      // Step 4: Fetch Trust Bundle
      this.addEvent({
        type: 'info',
        title: 'Fetching Trust Bundle',
        description: 'Getting root CA certificates for peer verification',
        rfcReference: 'SPIFFE Trust Bundle Specification',
      })

      const bundleResponse = await this.makeRequest('GET', `${this.config.baseUrl}/trust-bundle`, {
        step: 'Fetch trust bundle',
        rfcReference: 'SPIFFE Trust Bundle',
      })

      const trustBundle = bundleResponse.data as TrustBundleInfo

      this.addEvent({
        type: 'security',
        title: 'Trust Bundle Received',
        description: `${trustBundle.num_roots} root certificate(s) for ${trustBundle.trust_domain}`,
        rfcReference: 'SPIFFE Trust Bundle Specification',
      })

      // Complete
      this.updateState({
        status: 'completed',
        currentStep: 'X.509-SVID acquisition complete',
      })

      this.addEvent({
        type: 'info',
        title: 'Flow Complete',
        description: 'X.509-SVID and trust bundle successfully acquired',
      })

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Error',
        error: {
          code: 'svid_error',
          description: errorMessage,
        },
      })

      this.addEvent({
        type: 'error',
        title: 'Flow Failed',
        description: errorMessage,
      })
    }
  }
}

// ============================================================================
// JWT-SVID Flow Executor
// ============================================================================

export class JWTSVIDExecutor extends FlowExecutorBase {
  readonly flowType = 'jwt_svid'
  readonly flowName = 'JWT-SVID Acquisition'
  readonly rfcReference = 'SPIFFE JWT-SVID Specification'

  protected config: SPIFFESVIDConfig

  constructor(config: SPIFFESVIDConfig) {
    super(config)
    this.config = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    const audience = this.config.audience || 'protocolsoup'
    
    this.updateState({ 
      status: 'executing', 
      currentStep: 'Verifying SPIFFE Workload API' 
    })

    try {
      // Step 1: Verify Workload API is available
      this.addEvent({
        type: 'info',
        title: 'Verifying SPIFFE Infrastructure',
        description: 'Checking Workload API connection for JWT-SVID issuance',
        rfcReference: 'SPIFFE Workload API Specification',
      })

      const statusResponse = await this.makeRequest('GET', `${this.config.baseUrl}/status`, {
        step: 'Check SPIFFE Workload API status',
        rfcReference: 'SPIFFE Workload API',
      })

      const status = statusResponse.data as { enabled: boolean; trust_domain: string; spiffe_id?: string }

      if (!status.enabled) {
        this.addEvent({
          type: 'error',
          title: 'Workload API Unavailable',
          description: 'Cannot acquire JWT-SVIDs without SPIRE infrastructure.',
          rfcReference: 'SPIFFE JWT-SVID Specification',
          data: {
            requirement: 'SPIRE Server and Agent must be deployed',
            trustDomain: status.trust_domain
          },
        })
        this.updateState({
          status: 'error',
          currentStep: 'SPIRE infrastructure required',
          error: {
            code: 'WORKLOAD_API_UNAVAILABLE',
            description: 'JWT-SVID acquisition requires SPIRE Workload API. Deploy SPIRE infrastructure to enable this flow.',
          },
        })
        return
      }

      this.addEvent({
        type: 'security',
        title: 'Workload API Connected',
        description: `SPIFFE ID: ${status.spiffe_id}`,
        rfcReference: 'SPIFFE Workload API Specification',
        data: { trustDomain: status.trust_domain, spiffeId: status.spiffe_id },
      })

      // Step 2: Request JWT-SVID
      this.addEvent({
        type: 'info',
        title: 'Requesting JWT-SVID',
        description: `Requesting JWT token for audience: ${audience}`,
        rfcReference: 'JWT-SVID Specification Section 3',
      })

      const jwtResponse = await this.makeRequest(
        'GET',
        `${this.config.baseUrl}/svid/jwt?audience=${encodeURIComponent(audience)}`,
        {
          step: 'Fetch JWT-SVID',
          rfcReference: 'JWT-SVID Specification',
        }
      )

      const jwtSVID = jwtResponse.data as JWTSVIDInfo

      // Decode the JWT for display
      const decoded = this.decodeJwt(jwtSVID.token, 'access_token')
      this.updateState({
        decodedTokens: [...this.state.decodedTokens, decoded],
      })

      this.addEvent({
        type: 'token',
        title: 'JWT-SVID Received',
        description: `SPIFFE ID in sub claim: ${jwtSVID.spiffe_id}`,
        rfcReference: 'JWT-SVID Specification Section 4',
        data: {
          spiffeId: jwtSVID.spiffe_id,
          audience: jwtSVID.audience,
          expiresAt: jwtSVID.expires_at,
        },
      })

      this.addEvent({
        type: 'security',
        title: 'JWT-SVID Claims',
        description: 'Token contains SPIFFE-specific claims per specification',
        rfcReference: 'JWT-SVID Specification Section 4.1',
        data: {
          header: jwtSVID.header,
          claims: Object.keys(jwtSVID.claims),
        },
      })

      // Step 2: Validate the JWT-SVID
      this.addEvent({
        type: 'info',
        title: 'Validating JWT-SVID',
        description: 'Verifying signature against trust bundle',
        rfcReference: 'JWT-SVID Specification Section 5',
      })

      const validationResponse = await this.makeRequest(
        'POST',
        `${this.config.baseUrl}/validate/jwt`,
        {
          step: 'Validate JWT-SVID',
          rfcReference: 'JWT-SVID Specification Section 5',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            token: jwtSVID.token,
            audience: [audience],
          }),
        }
      )

      const validation = validationResponse.data as { valid: boolean; spiffe_id: string; error?: string }
      
      this.addEvent({
        type: validation.valid ? 'security' : 'error',
        title: validation.valid ? 'JWT-SVID Valid' : 'JWT-SVID Invalid',
        description: validation.valid 
          ? 'Signature verified against trust bundle' 
          : validation.error || 'Validation failed',
        rfcReference: 'JWT-SVID Specification Section 5',
      })

      // Complete
      this.updateState({
        status: 'completed',
        currentStep: 'JWT-SVID acquisition complete',
      })

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Error',
        error: {
          code: 'jwt_svid_error',
          description: errorMessage,
        },
      })

      this.addEvent({
        type: 'error',
        title: 'Flow Failed',
        description: errorMessage,
      })
    }
  }
}

// ============================================================================
// mTLS Flow Executor
// ============================================================================

export class MTLSExecutor extends FlowExecutorBase {
  readonly flowType = 'mtls_call'
  readonly flowName = 'mTLS Service-to-Service Call'
  readonly rfcReference = 'SPIFFE X.509-SVID + TLS 1.3'

  protected config: SPIFFESVIDConfig

  constructor(config: SPIFFESVIDConfig) {
    super(config)
    this.config = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ 
      status: 'executing', 
      currentStep: 'Checking SPIFFE Workload API' 
    })

    try {
      // Step 1: Verify SPIFFE Workload API is available
      this.addEvent({
        type: 'info',
        title: 'Verifying SPIFFE Infrastructure',
        description: 'Checking Workload API connection for X.509-SVID availability',
        rfcReference: 'SPIFFE Workload API Specification',
      })

      const statusResponse = await this.makeRequest('GET', `${this.config.baseUrl}/status`, {
        step: 'Check SPIFFE Workload API status',
        rfcReference: 'SPIFFE Workload API',
      })

      const status = statusResponse.data as { enabled: boolean; trust_domain: string; spiffe_id?: string }

      if (!status.enabled) {
        this.addEvent({
          type: 'error',
          title: 'Workload API Unavailable',
          description: 'Cannot perform mTLS without SPIRE infrastructure. X.509-SVIDs are required for mutual TLS.',
          rfcReference: 'SPIFFE X.509-SVID Specification',
          data: {
            requirement: 'SPIRE Server and Agent must be deployed',
            trustDomain: status.trust_domain
          },
        })
        this.updateState({
          status: 'error',
          currentStep: 'SPIRE infrastructure required',
          error: {
            code: 'WORKLOAD_API_UNAVAILABLE',
            description: 'mTLS requires X.509-SVIDs from SPIRE Workload API. Deploy SPIRE infrastructure to enable this flow.',
          },
        })
        return
      }

      this.addEvent({
        type: 'security',
        title: 'Workload API Connected',
        description: `SPIFFE ID: ${status.spiffe_id}`,
        rfcReference: 'SPIFFE Workload API Specification',
        data: { trustDomain: status.trust_domain, spiffeId: status.spiffe_id },
      })

      // Step 2: Fetch X.509-SVID for mTLS client authentication
      this.addEvent({
        type: 'crypto',
        title: 'Fetching X.509-SVID',
        description: 'Retrieving X.509 certificate with embedded SPIFFE ID for TLS client authentication',
        rfcReference: 'SPIFFE X.509-SVID Specification Section 3',
      })

      const svidResponse = await this.makeRequest('GET', `${this.config.baseUrl}/svid/x509`, {
        step: 'Fetch X.509-SVID for mTLS',
        rfcReference: 'X.509-SVID Specification',
      })

      const svid = svidResponse.data as { 
        spiffe_id: string
        not_before: string
        not_after: string
        serial_number?: string
        issuer?: string
      }

      this.addEvent({
        type: 'security',
        title: 'X.509-SVID Retrieved',
        description: 'Certificate obtained for TLS client authentication',
        rfcReference: 'SPIFFE X.509-SVID Specification',
        data: {
          spiffeId: svid.spiffe_id,
          validFrom: svid.not_before,
          validUntil: svid.not_after,
          serialNumber: svid.serial_number,
        },
      })

      // Step 3: Fetch trust bundle for server certificate validation
      this.addEvent({
        type: 'info',
        title: 'Fetching Trust Bundle',
        description: 'Retrieving trust bundle to validate peer certificates',
        rfcReference: 'SPIFFE Trust Domain and Bundle Specification',
      })

      const bundleResponse = await this.makeRequest('GET', `${this.config.baseUrl}/trust-bundle`, {
        step: 'Fetch trust bundle for peer validation',
        rfcReference: 'SPIFFE Trust Domain Specification',
      })

      const bundle = bundleResponse.data as { trust_domain: string; ca_count?: number }

      this.addEvent({
        type: 'security',
        title: 'Trust Bundle Retrieved',
        description: `Trust bundle for ${bundle.trust_domain} obtained`,
        rfcReference: 'SPIFFE Trust Domain and Bundle',
        data: bundle,
      })

      // Step 4: mTLS handshake explanation (per RFC 8446)
      this.addEvent({
        type: 'crypto',
        title: 'TLS 1.3 Handshake (mTLS)',
        description: 'In mTLS, both client and server present X.509-SVIDs during the TLS handshake',
        rfcReference: 'RFC 8446 Section 4.4.2',
        data: {
          step1: 'ClientHello with supported cipher suites',
          step2: 'ServerHello + Server Certificate (X.509-SVID)',
          step3: 'Client Certificate (X.509-SVID) + CertificateVerify',
          step4: 'Finished - Mutual authentication complete',
        },
      })

      this.addEvent({
        type: 'info',
        title: 'Certificate Verification',
        description: 'Both parties validate peer certificate against trust bundle and extract SPIFFE ID from SAN URI',
        rfcReference: 'SPIFFE X.509-SVID Section 4.1',
        data: {
          validation: 'Certificate chain validated against trust bundle CA certificates',
          spiffeIdExtraction: 'SPIFFE ID extracted from Subject Alternative Name (SAN) URI extension',
          authorization: 'Application performs authorization based on SPIFFE ID',
        },
      })

      this.addEvent({
        type: 'security',
        title: 'mTLS Configuration Ready',
        description: 'X.509-SVID and trust bundle available for mTLS connections',
        data: {
          clientSpiffeId: svid.spiffe_id,
          trustDomain: status.trust_domain,
          tlsVersion: 'TLS 1.3',
          cipherSuites: 'TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256',
        },
      })

      this.updateState({
        status: 'completed',
        currentStep: 'mTLS configuration ready',
      })

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        error: {
          code: 'mtls_error',
          description: errorMessage,
        },
      })
    }
  }
}

// ============================================================================
// Certificate Rotation Flow Executor
// ============================================================================

export class CertRotationExecutor extends FlowExecutorBase {
  readonly flowType = 'cert_rotation'
  readonly flowName = 'Certificate Rotation'
  readonly rfcReference = 'SPIFFE Workload API'

  protected config: SPIFFESVIDConfig

  constructor(config: SPIFFESVIDConfig) {
    super(config)
    this.config = config
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ 
      status: 'executing', 
      currentStep: 'Checking SPIFFE Workload API' 
    })

    try {
      // Step 1: Verify Workload API is available
      this.addEvent({
        type: 'info',
        title: 'Verifying SPIFFE Infrastructure',
        description: 'Checking Workload API connection for SVID rotation capabilities',
        rfcReference: 'SPIFFE Workload API Specification',
      })

      const statusResponse = await this.makeRequest('GET', `${this.config.baseUrl}/status`, {
        step: 'Check SPIFFE Workload API status',
        rfcReference: 'SPIFFE Workload API',
      })

      const status = statusResponse.data as { enabled: boolean; trust_domain: string; spiffe_id?: string }

      if (!status.enabled) {
        this.addEvent({
          type: 'error',
          title: 'Workload API Unavailable',
          description: 'Cannot analyze certificate rotation without SPIRE infrastructure.',
          rfcReference: 'SPIFFE Workload API Specification',
          data: {
            requirement: 'SPIRE Server and Agent must be deployed',
            trustDomain: status.trust_domain
          },
        })
        this.updateState({
          status: 'error',
          currentStep: 'SPIRE infrastructure required',
          error: {
            code: 'WORKLOAD_API_UNAVAILABLE',
            description: 'Certificate rotation requires SPIRE Workload API. Deploy SPIRE infrastructure to enable this flow.',
          },
        })
        return
      }

      this.addEvent({
        type: 'security',
        title: 'Workload API Connected',
        description: `SPIFFE ID: ${status.spiffe_id}`,
        rfcReference: 'SPIFFE Workload API Specification',
        data: { trustDomain: status.trust_domain, spiffeId: status.spiffe_id },
      })

      // Step 2: Get current X.509-SVID
      this.addEvent({
        type: 'crypto',
        title: 'Fetching Current X.509-SVID',
        description: 'Retrieving current certificate to analyze validity period',
        rfcReference: 'SPIFFE X.509-SVID Specification',
      })

      const currentSVID = await this.makeRequest('GET', `${this.config.baseUrl}/svid/x509`, {
        step: 'Get current X.509-SVID',
        rfcReference: 'X.509-SVID Specification',
      })

      const svid = currentSVID.data as X509SVIDInfo
      
      // Calculate time until expiry
      const notAfter = new Date(svid.not_after)
      const notBefore = new Date(svid.not_before)
      const now = new Date()
      const totalLifetime = notAfter.getTime() - notBefore.getTime()
      const timeRemaining = notAfter.getTime() - now.getTime()
      const percentRemaining = Math.round((timeRemaining / totalLifetime) * 100)

      this.addEvent({
        type: 'security',
        title: 'Current Certificate Details',
        description: `Certificate valid until ${svid.not_after}`,
        rfcReference: 'SPIFFE X.509-SVID Specification',
        data: {
          spiffeId: svid.spiffe_id,
          notBefore: svid.not_before,
          notAfter: svid.not_after,
          serialNumber: svid.serial_number?.slice(0, 32) + '...',
          lifetimeRemaining: `${percentRemaining}%`,
        },
      })

      // Step 3: Explain SPIRE's automatic rotation mechanism
      this.addEvent({
        type: 'info',
        title: 'SPIRE Automatic Rotation',
        description: 'SPIRE Agent automatically rotates SVIDs before expiry (typically at 50% lifetime)',
        rfcReference: 'SPIFFE Workload API Specification Section 5',
        data: {
          mechanism: 'X509Source stream watches for SVID updates',
          trigger: 'Agent requests new SVID when current reaches rotation threshold',
          threshold: 'Typically 50% of certificate lifetime',
          process: 'New SVID is fetched and old connections gracefully drained',
        },
      })

      this.addEvent({
        type: 'crypto',
        title: 'Zero-Downtime Rotation Process',
        description: 'Workload API provides streaming updates for seamless certificate rotation',
        rfcReference: 'SPIFFE Workload API Specification',
        data: {
          step1: 'Agent monitors SVID expiration time',
          step2: 'At rotation threshold, Agent requests new SVID from Server',
          step3: 'Server issues new X.509-SVID with same SPIFFE ID',
          step4: 'Agent updates X509Source, workload receives new certificate',
          step5: 'Existing connections continue with old cert until closed',
          step6: 'New connections use updated certificate',
        },
      })

      this.addEvent({
        type: 'security',
        title: 'Rotation Benefits',
        description: 'Short-lived certificates minimize compromise window',
        rfcReference: 'SPIFFE Security Considerations',
        data: {
          shortLived: 'Typical SVID lifetime: 1 hour (configurable)',
          automaticRenewal: 'No manual intervention required',
          noDowntime: 'Streaming API enables seamless rotation',
          compromiseWindow: 'Shorter lifetime = smaller attack surface',
        },
      })

      this.updateState({
        status: 'completed',
        currentStep: 'Certificate rotation analysis complete',
      })

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        error: {
          code: 'rotation_error',
          description: errorMessage,
        },
      })
    }
  }
}

// ============================================================================
// Factory Function
// ============================================================================

export type SPIFFEFlowType = 'x509_svid' | 'jwt_svid' | 'mtls_call' | 'cert_rotation'

export function createSPIFFEExecutor(
  flowType: SPIFFEFlowType,
  config: SPIFFESVIDConfig
): FlowExecutorBase {
  switch (flowType) {
    case 'x509_svid':
      return new X509SVIDExecutor(config)
    case 'jwt_svid':
      return new JWTSVIDExecutor(config)
    case 'mtls_call':
      return new MTLSExecutor(config)
    case 'cert_rotation':
      return new CertRotationExecutor(config)
    default:
      throw new Error(`Unknown SPIFFE flow type: ${flowType}`)
  }
}

export const SPIFFE_FLOWS = {
  x509_svid: {
    name: 'X.509-SVID Acquisition',
    description: 'Acquire X.509 certificate with SPIFFE ID via Workload API',
    specification: 'SPIFFE X.509-SVID',
  },
  jwt_svid: {
    name: 'JWT-SVID Acquisition',
    description: 'Acquire JWT token with SPIFFE claims via Workload API',
    specification: 'SPIFFE JWT-SVID',
  },
  mtls_call: {
    name: 'mTLS Configuration',
    description: 'Prepare X.509-SVID and trust bundle for mutual TLS',
    specification: 'SPIFFE mTLS',
  },
  cert_rotation: {
    name: 'Certificate Rotation Analysis',
    description: 'Analyze SVID lifecycle and SPIRE automatic rotation mechanism',
    specification: 'SPIFFE Workload API',
  },
}
