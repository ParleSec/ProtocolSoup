/**
 * Device Authorization Flow Executor
 * 
 * Implements RFC 8628 - OAuth 2.0 Device Authorization Grant
 * 
 * Used for devices with limited input capabilities (TVs, CLI tools, IoT)
 * where the user authorizes on a separate device with a browser.
 * 
 * Flow:
 * 1. Device requests device_code and user_code from authorization server
 * 2. User visits verification_uri on another device and enters user_code
 * 3. Device polls token endpoint until user completes authorization
 * 4. Token endpoint returns access token once authorized
 */

import { FlowExecutorBase, type FlowExecutorConfig } from './base'

export interface DeviceCodeConfig extends FlowExecutorConfig {
  /** Polling interval in seconds (default from server or 5s) */
  pollInterval?: number
  /** Maximum polling duration in seconds */
  maxPollDuration?: number
}

export class DeviceCodeExecutor extends FlowExecutorBase {
  readonly flowType = 'device_code'
  readonly flowName = 'Device Authorization Grant'
  readonly rfcReference = 'RFC 8628'

  private flowConfig: DeviceCodeConfig
  private pollTimer: ReturnType<typeof setInterval> | null = null

  constructor(config: DeviceCodeConfig) {
    super(config)
    this.flowConfig = {
      ...config,
      pollInterval: config.pollInterval || 5,
      maxPollDuration: config.maxPollDuration || 300, // 5 minutes default
    }
  }

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({
      ...this.createInitialState(),
      status: 'executing',
      currentStep: 'Initiating Device Authorization Flow',
    })

    this.addEvent({
      type: 'info',
      title: 'Starting Device Authorization Flow',
      description: 'For devices with limited input capabilities',
      rfcReference: this.rfcReference,
      data: {
        clientId: this.config.clientId,
        scopes: this.config.scopes,
        useCase: 'Smart TVs, CLI tools, IoT devices, gaming consoles',
      },
    })

    try {
      // Step 1: Request device and user codes
      const deviceAuth = await this.requestDeviceAuthorization()

      this.addEvent({
        type: 'user_action',
        title: 'User Action Required',
        description: `Visit ${deviceAuth.verification_uri} and enter code: ${deviceAuth.user_code}`,
        rfcReference: 'RFC 8628 Section 3.3',
        data: {
          verification_uri: deviceAuth.verification_uri,
          verification_uri_complete: deviceAuth.verification_uri_complete,
          user_code: deviceAuth.user_code,
          expires_in: deviceAuth.expires_in,
        },
      })

      // Store device code
      this.updateState({
        status: 'awaiting_user',
        currentStep: `Enter code ${deviceAuth.user_code} at ${deviceAuth.verification_uri}`,
        securityParams: {
          ...this.state.securityParams,
          deviceCode: deviceAuth.device_code,
        },
      })

      // Step 2: Poll for token
      await this.pollForToken(deviceAuth)

      this.updateState({
        status: 'completed',
        currentStep: 'Flow completed successfully',
      })

      this.addEvent({
        type: 'info',
        title: 'Device Authorization Flow Complete',
        description: 'User authorized the device',
        rfcReference: this.rfcReference,
      })

    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error'
      this.updateState({
        status: 'error',
        currentStep: 'Flow failed',
        error: {
          code: 'execution_error',
          description: message,
        },
      })
      this.addEvent({
        type: 'error',
        title: 'Flow Execution Failed',
        description: message,
      })
    } finally {
      if (this.pollTimer) {
        clearInterval(this.pollTimer)
        this.pollTimer = null
      }
    }
  }

  private async requestDeviceAuthorization(): Promise<{
    device_code: string
    user_code: string
    verification_uri: string
    verification_uri_complete?: string
    expires_in: number
    interval?: number
  }> {
    this.addEvent({
      type: 'rfc',
      title: 'RFC 8628 Section 3.1',
      description: 'Device Authorization Request - Requesting device and user codes',
      rfcReference: 'RFC 8628 Section 3.1',
    })

    const body: Record<string, string> = {
      client_id: this.config.clientId,
    }

    if (this.config.scopes.length > 0) {
      body.scope = this.config.scopes.join(' ')
    }

    const { response, data } = await this.makeRequest(
      'POST',
      `${this.config.baseUrl}/device/authorize`,
      {
        body,
        step: 'Device Authorization Request',
        rfcReference: 'RFC 8628 Section 3.1',
      }
    )

    if (!response.ok) {
      const errorData = data as Record<string, unknown>
      throw new Error(
        (errorData.error_description as string) || 
        (errorData.error as string) || 
        'Device authorization request failed'
      )
    }

    const deviceAuth = data as {
      device_code: string
      user_code: string
      verification_uri: string
      verification_uri_complete?: string
      expires_in: number
      interval?: number
    }

    this.addEvent({
      type: 'rfc',
      title: 'RFC 8628 Section 3.2',
      description: 'Device Authorization Response received',
      rfcReference: 'RFC 8628 Section 3.2',
      data: {
        user_code: deviceAuth.user_code,
        verification_uri: deviceAuth.verification_uri,
        expires_in: deviceAuth.expires_in,
        interval: deviceAuth.interval || this.flowConfig.pollInterval,
      },
    })

    return deviceAuth
  }

  private async pollForToken(deviceAuth: {
    device_code: string
    interval?: number
    expires_in: number
  }): Promise<void> {
    const interval = (deviceAuth.interval || this.flowConfig.pollInterval!) * 1000
    const maxDuration = Math.min(
      deviceAuth.expires_in * 1000,
      this.flowConfig.maxPollDuration! * 1000
    )
    const startTime = Date.now()

    this.addEvent({
      type: 'rfc',
      title: 'RFC 8628 Section 3.4',
      description: 'Starting to poll token endpoint',
      rfcReference: 'RFC 8628 Section 3.4',
      data: {
        interval: interval / 1000,
        maxDuration: maxDuration / 1000,
        note: 'Must respect slow_down errors by increasing interval',
      },
    })

    return new Promise((resolve, reject) => {
      let currentInterval = interval
      let pollCount = 0

      const poll = async () => {
        pollCount++

        if (Date.now() - startTime > maxDuration) {
          clearInterval(this.pollTimer!)
          reject(new Error('Device authorization timeout'))
          return
        }

        if (this.abortController?.signal.aborted) {
          clearInterval(this.pollTimer!)
          reject(new Error('Polling aborted'))
          return
        }

        this.updateState({
          currentStep: `Polling for authorization (attempt ${pollCount})...`,
        })

        try {
          const { response, data } = await this.makeRequest(
            'POST',
            `${this.config.baseUrl}/token`,
            {
              body: {
                grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
                device_code: deviceAuth.device_code,
                client_id: this.config.clientId,
              },
              step: `Token Poll Request #${pollCount}`,
              rfcReference: 'RFC 8628 Section 3.4',
            }
          )

          if (response.ok) {
            clearInterval(this.pollTimer!)
            
            this.addEvent({
              type: 'rfc',
              title: 'RFC 8628 Section 3.5',
              description: 'Device Access Token Response - User authorized the device',
              rfcReference: 'RFC 8628 Section 3.5',
              data: { pollAttempts: pollCount },
            })

            this.processTokenResponse(data as Record<string, unknown>)
            resolve()
            return
          }

          const errorData = data as Record<string, unknown>
          const error = errorData.error as string

          switch (error) {
            case 'authorization_pending':
              // User hasn't completed authorization yet - continue polling
              this.addEvent({
                type: 'info',
                title: 'Authorization Pending',
                description: 'User has not yet authorized - continuing to poll',
                rfcReference: 'RFC 8628 Section 3.5',
              })
              break

            case 'slow_down':
              // Increase polling interval by 5 seconds
              currentInterval += 5000
              clearInterval(this.pollTimer!)
              this.pollTimer = setInterval(poll, currentInterval)
              
              this.addEvent({
                type: 'rfc',
                title: 'Slow Down Received',
                description: `Increasing poll interval to ${currentInterval / 1000}s`,
                rfcReference: 'RFC 8628 Section 3.5',
              })
              break

            case 'access_denied':
              clearInterval(this.pollTimer!)
              this.addEvent({
                type: 'error',
                title: 'Access Denied',
                description: 'User denied the authorization request',
                rfcReference: 'RFC 8628 Section 3.5',
              })
              reject(new Error('User denied authorization'))
              return

            case 'expired_token':
              clearInterval(this.pollTimer!)
              this.addEvent({
                type: 'error',
                title: 'Device Code Expired',
                description: 'The device code has expired - restart the flow',
                rfcReference: 'RFC 8628 Section 3.5',
              })
              reject(new Error('Device code expired'))
              return

            default:
              clearInterval(this.pollTimer!)
              reject(new Error(errorData.error_description as string || error))
              return
          }
        } catch (err) {
          // Network error - continue polling
          console.error('Poll error:', err)
        }
      }

      // Start polling
      this.pollTimer = setInterval(poll, currentInterval)
      poll() // First poll immediately
    })
  }

  abort(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer)
      this.pollTimer = null
    }
    super.abort()
  }
}

