/**
 * SCIM 2.0 Flow Executors
 * 
 * Implements real SCIM protocol flows per RFC 7642, 7643, 7644.
 * These are not simulations - they make actual SCIM API calls.
 */

import { FlowExecutorBase, FlowExecutorConfig, generateSecureRandom } from './base'

// ============================================================================
// Types
// ============================================================================

export interface SCIMProvisioningConfig extends FlowExecutorConfig {
  /** SCIM server base URL (default: /scim/v2) */
  scimBaseUrl?: string
  /** Bearer token for authentication */
  bearerToken?: string
}

export interface SCIMUser {
  schemas: string[]
  id?: string
  externalId?: string
  userName: string
  name?: {
    formatted?: string
    familyName?: string
    givenName?: string
    middleName?: string
    honorificPrefix?: string
    honorificSuffix?: string
  }
  displayName?: string
  nickName?: string
  profileUrl?: string
  title?: string
  userType?: string
  preferredLanguage?: string
  locale?: string
  timezone?: string
  active?: boolean
  emails?: Array<{
    value: string
    type?: string
    primary?: boolean
  }>
  phoneNumbers?: Array<{
    value: string
    type?: string
    primary?: boolean
  }>
  addresses?: Array<{
    formatted?: string
    streetAddress?: string
    locality?: string
    region?: string
    postalCode?: string
    country?: string
    type?: string
    primary?: boolean
  }>
  groups?: Array<{
    value: string
    $ref?: string
    display?: string
  }>
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'?: {
    employeeNumber?: string
    costCenter?: string
    organization?: string
    division?: string
    department?: string
    manager?: {
      value?: string
      $ref?: string
      displayName?: string
    }
  }
  meta?: {
    resourceType?: string
    created?: string
    lastModified?: string
    location?: string
    version?: string
  }
}

export interface SCIMGroup {
  schemas: string[]
  id?: string
  displayName: string
  members?: Array<{
    value: string
    $ref?: string
    display?: string
    type?: string
  }>
  meta?: {
    resourceType?: string
    created?: string
    lastModified?: string
    location?: string
    version?: string
  }
}

export interface SCIMListResponse<T> {
  schemas: string[]
  totalResults: number
  startIndex?: number
  itemsPerPage?: number
  Resources?: T[]
}

export interface SCIMPatchOperation {
  op: 'add' | 'remove' | 'replace'
  path?: string
  value?: unknown
}

export interface SCIMPatchRequest {
  schemas: string[]
  Operations: SCIMPatchOperation[]
}

// Schema URNs
const SCHEMA_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
const SCHEMA_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group'
const SCHEMA_ENTERPRISE_USER = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'
const SCHEMA_PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'

// ============================================================================
// SCIM Base Executor
// ============================================================================

abstract class SCIMExecutorBase extends FlowExecutorBase {
  protected scimBaseUrl: string
  protected bearerToken: string

  constructor(config: SCIMProvisioningConfig) {
    super(config)
    this.scimBaseUrl = config.scimBaseUrl || '/scim/v2'
    this.bearerToken = config.bearerToken || ''
  }

  protected async makeSCIMRequest<T>(
    method: string,
    path: string,
    options: {
      body?: unknown
      step: string
      rfcReference?: string
    }
  ): Promise<{ response: Response; data: T }> {
    const url = `${this.scimBaseUrl}${path}`
    const headers: Record<string, string> = {
      'Accept': 'application/scim+json',
    }

    // Bearer token authentication is required for SCIM operations
    if (this.bearerToken) {
      headers['Authorization'] = `Bearer ${this.bearerToken}`
    }

    let bodyStr: string | undefined
    if (options.body) {
      headers['Content-Type'] = 'application/scim+json'
      bodyStr = JSON.stringify(options.body)
    }

    // Create exchange record
    const exchange = this.addExchange({
      step: options.step,
      rfcReference: options.rfcReference,
      request: {
        method,
        url,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
      },
    })

    this.addEvent({
      type: 'request',
      title: `${method} ${path}`,
      description: options.step,
      rfcReference: options.rfcReference,
      data: {
        method,
        path,
        hasBody: !!options.body,
      },
    })

    const startTime = Date.now()

    const response = await fetch(url, {
      method,
      headers,
      body: bodyStr,
      signal: this.abortController?.signal,
    })

    const duration = Date.now() - startTime
    const contentType = response.headers.get('content-type') || ''
    let data: T

    if (contentType.includes('json')) {
      data = await response.json()
    } else if (response.status === 204) {
      data = {} as T
    } else {
      data = await response.text() as unknown as T
    }

    // Update exchange with response
    exchange.response = {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: data,
      duration,
    }

    this.updateState({
      exchanges: this.state.exchanges.map(e => 
        e.id === exchange.id ? exchange : e
      ),
    })

    const eventType = response.ok ? 'response' : 'error'
    this.addEvent({
      type: eventType,
      title: `${response.status} ${response.statusText}`,
      description: `Response received in ${duration}ms`,
      data: {
        status: response.status,
        duration,
      },
    })

    return { response, data }
  }
}

// ============================================================================
// User Lifecycle Flow Executor
// ============================================================================

export class UserLifecycleExecutor extends SCIMExecutorBase {
  readonly flowType = 'scim-user-lifecycle'
  readonly flowName = 'SCIM User Lifecycle'
  readonly rfcReference = 'RFC 7644'

  private createdUserId?: string

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Starting user lifecycle flow' })

    try {
      // Step 1: Create User
      await this.createUser()

      // Step 2: Get User
      await this.getUser()

      // Step 3: Update User (PATCH)
      await this.patchUser()

      // Step 4: Deactivate User
      await this.deactivateUser()

      // Step 5: Delete User
      await this.deleteUser()

      this.updateState({ status: 'completed', currentStep: 'User lifecycle complete' })
    } catch (error) {
      this.updateState({
        status: 'error',
        error: {
          code: 'execution_error',
          description: error instanceof Error ? error.message : 'Unknown error',
        },
      })
    }
  }

  private async createUser(): Promise<void> {
    this.updateState({ currentStep: 'Creating user via POST /Users' })

    const user: SCIMUser = {
      schemas: [SCHEMA_USER, SCHEMA_ENTERPRISE_USER],
      userName: `demo.user.${generateSecureRandom(4)}@example.com`,
      name: {
        givenName: 'Demo',
        familyName: 'User',
        formatted: 'Demo User',
      },
      displayName: 'Demo User',
      active: true,
      emails: [
        {
          value: `demo.user.${generateSecureRandom(4)}@example.com`,
          type: 'work',
          primary: true,
        },
      ],
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': {
        department: 'Engineering',
        organization: 'Protocol Labs',
      },
    }

    const { response, data } = await this.makeSCIMRequest<SCIMUser>(
      'POST',
      '/Users',
      {
        body: user,
        step: 'Create new user via POST /Users',
        rfcReference: 'RFC 7644 Section 3.3',
      }
    )

    if (response.status === 201) {
      this.createdUserId = data.id
      this.addEvent({
        type: 'info',
        title: 'User Created Successfully',
        description: `User ID: ${data.id}`,
        data: { userId: data.id, userName: data.userName },
      })
    } else {
      throw new Error(`Failed to create user: ${response.status}`)
    }
  }

  private async getUser(): Promise<void> {
    if (!this.createdUserId) throw new Error('No user ID available')

    this.updateState({ currentStep: `Getting user via GET /Users/${this.createdUserId}` })

    const { response, data } = await this.makeSCIMRequest<SCIMUser>(
      'GET',
      `/Users/${this.createdUserId}`,
      {
        step: 'Retrieve created user',
        rfcReference: 'RFC 7644 Section 3.4.1',
      }
    )

    if (response.ok) {
      this.addEvent({
        type: 'info',
        title: 'User Retrieved',
        description: `ETag: ${response.headers.get('etag') || 'N/A'}`,
        data: { user: data },
      })
    }
  }

  private async patchUser(): Promise<void> {
    if (!this.createdUserId) throw new Error('No user ID available')

    this.updateState({ currentStep: 'Updating user via PATCH' })

    const patchRequest: SCIMPatchRequest = {
      schemas: [SCHEMA_PATCH_OP],
      Operations: [
        {
          op: 'replace',
          path: 'displayName',
          value: 'Updated Demo User',
        },
        {
          op: 'add',
          path: 'phoneNumbers',
          value: [{ value: '+1-555-0123', type: 'work' }],
        },
      ],
    }

    const { response } = await this.makeSCIMRequest<SCIMUser>(
      'PATCH',
      `/Users/${this.createdUserId}`,
      {
        body: patchRequest,
        step: 'Update user attributes via PATCH',
        rfcReference: 'RFC 7644 Section 3.5.2',
      }
    )

    if (response.ok) {
      this.addEvent({
        type: 'info',
        title: 'User Updated',
        description: 'PATCH operations applied successfully',
        data: { operations: patchRequest.Operations },
      })
    }
  }

  private async deactivateUser(): Promise<void> {
    if (!this.createdUserId) throw new Error('No user ID available')

    this.updateState({ currentStep: 'Deactivating user' })

    const patchRequest: SCIMPatchRequest = {
      schemas: [SCHEMA_PATCH_OP],
      Operations: [
        {
          op: 'replace',
          path: 'active',
          value: false,
        },
      ],
    }

    const { response } = await this.makeSCIMRequest<SCIMUser>(
      'PATCH',
      `/Users/${this.createdUserId}`,
      {
        body: patchRequest,
        step: 'Deactivate user by setting active=false',
        rfcReference: 'RFC 7644 Section 3.5.2',
      }
    )

    if (response.ok) {
      this.addEvent({
        type: 'security',
        title: 'User Deactivated',
        description: 'User account is now inactive but still exists',
      })
    }
  }

  private async deleteUser(): Promise<void> {
    if (!this.createdUserId) throw new Error('No user ID available')

    this.updateState({ currentStep: 'Deleting user' })

    const { response } = await this.makeSCIMRequest<void>(
      'DELETE',
      `/Users/${this.createdUserId}`,
      {
        step: 'Permanently delete user',
        rfcReference: 'RFC 7644 Section 3.6',
      }
    )

    if (response.status === 204) {
      this.addEvent({
        type: 'info',
        title: 'User Deleted',
        description: 'User permanently removed from the system',
      })
    }
  }
}

// ============================================================================
// Group Management Flow Executor
// ============================================================================

export class GroupManagementExecutor extends SCIMExecutorBase {
  readonly flowType = 'scim-group-management'
  readonly flowName = 'SCIM Group Management'
  readonly rfcReference = 'RFC 7644'

  private createdGroupId?: string
  private testUserId?: string

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Starting group management flow' })

    try {
      // Get an existing user to add to group
      await this.getExistingUser()

      // Step 1: Create Group
      await this.createGroup()

      // Step 2: Add Member
      await this.addMember()

      // Step 3: Get Group with Members
      await this.getGroup()

      // Step 4: Remove Member
      await this.removeMember()

      // Step 5: Delete Group
      await this.deleteGroup()

      this.updateState({ status: 'completed', currentStep: 'Group management complete' })
    } catch (error) {
      this.updateState({
        status: 'error',
        error: {
          code: 'execution_error',
          description: error instanceof Error ? error.message : 'Unknown error',
        },
      })
    }
  }

  private async getExistingUser(): Promise<void> {
    this.updateState({ currentStep: 'Finding existing user' })

    const { response, data } = await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      '/Users?count=1',
      {
        step: 'Get existing user for group membership',
        rfcReference: 'RFC 7644 Section 3.4.2',
      }
    )

    if (response.ok && data.Resources && data.Resources.length > 0) {
      this.testUserId = data.Resources[0].id
      this.addEvent({
        type: 'info',
        title: 'User Found',
        description: `Using user ${data.Resources[0].userName} for membership tests`,
      })
    }
  }

  private async createGroup(): Promise<void> {
    this.updateState({ currentStep: 'Creating group' })

    const group: SCIMGroup = {
      schemas: [SCHEMA_GROUP],
      displayName: `Demo Group ${generateSecureRandom(4)}`,
    }

    const { response, data } = await this.makeSCIMRequest<SCIMGroup>(
      'POST',
      '/Groups',
      {
        body: group,
        step: 'Create new group via POST /Groups',
        rfcReference: 'RFC 7644 Section 3.3',
      }
    )

    if (response.status === 201) {
      this.createdGroupId = data.id
      this.addEvent({
        type: 'info',
        title: 'Group Created',
        description: `Group ID: ${data.id}`,
      })
    }
  }

  private async addMember(): Promise<void> {
    if (!this.createdGroupId || !this.testUserId) return

    this.updateState({ currentStep: 'Adding member to group' })

    const patchRequest: SCIMPatchRequest = {
      schemas: [SCHEMA_PATCH_OP],
      Operations: [
        {
          op: 'add',
          path: 'members',
          value: [{ value: this.testUserId }],
        },
      ],
    }

    const { response } = await this.makeSCIMRequest<SCIMGroup>(
      'PATCH',
      `/Groups/${this.createdGroupId}`,
      {
        body: patchRequest,
        step: 'Add member to group via PATCH',
        rfcReference: 'RFC 7644 Section 3.5.2',
      }
    )

    if (response.ok) {
      this.addEvent({
        type: 'info',
        title: 'Member Added',
        description: `User ${this.testUserId} added to group`,
      })
    }
  }

  private async getGroup(): Promise<void> {
    if (!this.createdGroupId) return

    this.updateState({ currentStep: 'Getting group with members' })

    const { response, data } = await this.makeSCIMRequest<SCIMGroup>(
      'GET',
      `/Groups/${this.createdGroupId}`,
      {
        step: 'Retrieve group with members',
        rfcReference: 'RFC 7644 Section 3.4.1',
      }
    )

    if (response.ok) {
      this.addEvent({
        type: 'info',
        title: 'Group Retrieved',
        description: `Group has ${data.members?.length || 0} members`,
        data: { members: data.members },
      })
    }
  }

  private async removeMember(): Promise<void> {
    if (!this.createdGroupId || !this.testUserId) return

    this.updateState({ currentStep: 'Removing member from group' })

    const patchRequest: SCIMPatchRequest = {
      schemas: [SCHEMA_PATCH_OP],
      Operations: [
        {
          op: 'remove',
          path: `members[value eq "${this.testUserId}"]`,
        },
      ],
    }

    const { response } = await this.makeSCIMRequest<SCIMGroup>(
      'PATCH',
      `/Groups/${this.createdGroupId}`,
      {
        body: patchRequest,
        step: 'Remove member from group via PATCH with filter',
        rfcReference: 'RFC 7644 Section 3.5.2',
      }
    )

    if (response.ok) {
      this.addEvent({
        type: 'info',
        title: 'Member Removed',
        description: 'User removed from group using value filter',
      })
    }
  }

  private async deleteGroup(): Promise<void> {
    if (!this.createdGroupId) return

    this.updateState({ currentStep: 'Deleting group' })

    const { response } = await this.makeSCIMRequest<void>(
      'DELETE',
      `/Groups/${this.createdGroupId}`,
      {
        step: 'Delete group',
        rfcReference: 'RFC 7644 Section 3.6',
      }
    )

    if (response.status === 204) {
      this.addEvent({
        type: 'info',
        title: 'Group Deleted',
        description: 'Group permanently removed',
      })
    }
  }
}

// ============================================================================
// Filter Query Flow Executor
// ============================================================================

export class FilterQueryExecutor extends SCIMExecutorBase {
  readonly flowType = 'scim-filter-queries'
  readonly flowName = 'SCIM Filter Queries'
  readonly rfcReference = 'RFC 7644 Section 3.4.2.2'

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Starting filter query demos' })

    try {
      // Demo various filter expressions
      await this.listAllUsers()
      await this.filterByUsername()
      await this.filterByActive()
      await this.filterWithContains()
      await this.filterWithLogicalAnd()
      await this.filterWithPagination()

      this.updateState({ status: 'completed', currentStep: 'Filter demos complete' })
    } catch (error) {
      this.updateState({
        status: 'error',
        error: {
          code: 'execution_error',
          description: error instanceof Error ? error.message : 'Unknown error',
        },
      })
    }
  }

  private async listAllUsers(): Promise<void> {
    this.updateState({ currentStep: 'Listing all users' })

    const { data } = await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      '/Users',
      {
        step: 'List all users (no filter)',
        rfcReference: 'RFC 7644 Section 3.4.2',
      }
    )

    this.addEvent({
      type: 'info',
      title: 'Users Listed',
      description: `Total: ${data.totalResults} users`,
    })
  }

  private async filterByUsername(): Promise<void> {
    this.updateState({ currentStep: 'Filter by userName' })

    const filter = 'userName sw "alice"'
    await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      `/Users?filter=${encodeURIComponent(filter)}`,
      {
        step: `Filter: ${filter}`,
        rfcReference: 'RFC 7644 Section 3.4.2.2',
      }
    )

    this.addEvent({
      type: 'rfc',
      title: 'String Filter: sw (starts with)',
      description: 'The "sw" operator matches if the attribute starts with the specified value',
      rfcReference: 'RFC 7644 Section 3.4.2.2',
    })
  }

  private async filterByActive(): Promise<void> {
    this.updateState({ currentStep: 'Filter by active status' })

    const filter = 'active eq true'
    await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      `/Users?filter=${encodeURIComponent(filter)}`,
      {
        step: `Filter: ${filter}`,
        rfcReference: 'RFC 7644 Section 3.4.2.2',
      }
    )

    this.addEvent({
      type: 'rfc',
      title: 'Boolean Filter: eq (equals)',
      description: 'The "eq" operator performs exact matching',
      rfcReference: 'RFC 7644 Section 3.4.2.2',
    })
  }

  private async filterWithContains(): Promise<void> {
    this.updateState({ currentStep: 'Filter with contains' })

    const filter = 'emails.value co "@example.com"'
    await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      `/Users?filter=${encodeURIComponent(filter)}`,
      {
        step: `Filter: ${filter}`,
        rfcReference: 'RFC 7644 Section 3.4.2.2',
      }
    )

    this.addEvent({
      type: 'rfc',
      title: 'Sub-attribute Filter with co (contains)',
      description: 'Filters on multi-valued attribute sub-attributes using dot notation',
      rfcReference: 'RFC 7644 Section 3.4.2.2',
    })
  }

  private async filterWithLogicalAnd(): Promise<void> {
    this.updateState({ currentStep: 'Filter with logical AND' })

    const filter = 'active eq true and userType eq "Employee"'
    await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      `/Users?filter=${encodeURIComponent(filter)}`,
      {
        step: `Filter: ${filter}`,
        rfcReference: 'RFC 7644 Section 3.4.2.2',
      }
    )

    this.addEvent({
      type: 'rfc',
      title: 'Logical Operators',
      description: 'SCIM supports "and", "or", and "not" logical operators',
      rfcReference: 'RFC 7644 Section 3.4.2.2',
    })
  }

  private async filterWithPagination(): Promise<void> {
    this.updateState({ currentStep: 'Paginated query' })

    await this.makeSCIMRequest<SCIMListResponse<SCIMUser>>(
      'GET',
      '/Users?startIndex=1&count=5',
      {
        step: 'Paginated list with startIndex and count',
        rfcReference: 'RFC 7644 Section 3.4.2.4',
      }
    )

    this.addEvent({
      type: 'rfc',
      title: 'Pagination',
      description: 'Use startIndex (1-based) and count parameters for pagination',
      rfcReference: 'RFC 7644 Section 3.4.2.4',
    })
  }
}

// ============================================================================
// Schema Discovery Flow Executor
// ============================================================================

export class SchemaDiscoveryExecutor extends SCIMExecutorBase {
  readonly flowType = 'scim-schema-discovery'
  readonly flowName = 'SCIM Schema Discovery'
  readonly rfcReference = 'RFC 7643, RFC 7644'

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Starting schema discovery' })

    try {
      await this.getServiceProviderConfig()
      await this.getResourceTypes()
      await this.getSchemas()
      await this.getUserSchema()

      this.updateState({ status: 'completed', currentStep: 'Schema discovery complete' })
    } catch (error) {
      this.updateState({
        status: 'error',
        error: {
          code: 'execution_error',
          description: error instanceof Error ? error.message : 'Unknown error',
        },
      })
    }
  }

  private async getServiceProviderConfig(): Promise<void> {
    this.updateState({ currentStep: 'Getting ServiceProviderConfig' })

    const { data } = await this.makeSCIMRequest<Record<string, unknown>>(
      'GET',
      '/ServiceProviderConfig',
      {
        step: 'Discover server capabilities',
        rfcReference: 'RFC 7643 Section 5',
      }
    )

    this.addEvent({
      type: 'info',
      title: 'Server Capabilities',
      description: 'ServiceProviderConfig describes what features the server supports',
      data: {
        patch: (data.patch as Record<string, boolean>)?.supported,
        bulk: (data.bulk as Record<string, boolean>)?.supported,
        filter: (data.filter as Record<string, boolean>)?.supported,
        etag: (data.etag as Record<string, boolean>)?.supported,
      },
    })
  }

  private async getResourceTypes(): Promise<void> {
    this.updateState({ currentStep: 'Getting ResourceTypes' })

    const { data } = await this.makeSCIMRequest<SCIMListResponse<Record<string, unknown>>>(
      'GET',
      '/ResourceTypes',
      {
        step: 'List available resource types',
        rfcReference: 'RFC 7643 Section 6',
      }
    )

    this.addEvent({
      type: 'info',
      title: 'Resource Types',
      description: `Server supports ${data.totalResults} resource types`,
      data: {
        types: data.Resources?.map(r => r.name),
      },
    })
  }

  private async getSchemas(): Promise<void> {
    this.updateState({ currentStep: 'Getting Schemas' })

    const { data } = await this.makeSCIMRequest<SCIMListResponse<Record<string, unknown>>>(
      'GET',
      '/Schemas',
      {
        step: 'List all schemas',
        rfcReference: 'RFC 7643 Section 7',
      }
    )

    this.addEvent({
      type: 'info',
      title: 'Schemas',
      description: `Server provides ${data.totalResults} schema definitions`,
      data: {
        schemas: data.Resources?.map(s => s.id),
      },
    })
  }

  private async getUserSchema(): Promise<void> {
    this.updateState({ currentStep: 'Getting User Schema details' })

    const { data } = await this.makeSCIMRequest<Record<string, unknown>>(
      'GET',
      `/Schemas/${encodeURIComponent(SCHEMA_USER)}`,
      {
        step: 'Get User schema definition',
        rfcReference: 'RFC 7643 Section 7',
      }
    )

    const attributes = data.attributes as Array<{ name: string; type: string; required: boolean }>
    this.addEvent({
      type: 'rfc',
      title: 'User Schema',
      description: `User schema has ${attributes?.length || 0} attributes`,
      rfcReference: 'RFC 7643 Section 4.1',
      data: {
        requiredAttributes: attributes?.filter(a => a.required).map(a => a.name),
      },
    })
  }
}

// ============================================================================
// Bulk Operations Flow Executor
// ============================================================================

export class BulkOperationsExecutor extends SCIMExecutorBase {
  readonly flowType = 'scim-bulk-operations'
  readonly flowName = 'SCIM Bulk Operations'
  readonly rfcReference = 'RFC 7644 Section 3.7'

  async execute(): Promise<void> {
    this.abortController = new AbortController()
    this.updateState({ status: 'executing', currentStep: 'Starting bulk operations demo' })

    try {
      await this.executeBulkCreate()

      this.updateState({ status: 'completed', currentStep: 'Bulk operations complete' })
    } catch (error) {
      this.updateState({
        status: 'error',
        error: {
          code: 'execution_error',
          description: error instanceof Error ? error.message : 'Unknown error',
        },
      })
    }
  }

  private async executeBulkCreate(): Promise<void> {
    this.updateState({ currentStep: 'Creating multiple users in bulk' })

    const bulkRequest = {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
      Operations: [
        {
          method: 'POST',
          path: '/Users',
          bulkId: 'user1',
          data: {
            schemas: [SCHEMA_USER],
            userName: `bulk.user.1.${generateSecureRandom(4)}@example.com`,
            displayName: 'Bulk User 1',
            active: true,
          },
        },
        {
          method: 'POST',
          path: '/Users',
          bulkId: 'user2',
          data: {
            schemas: [SCHEMA_USER],
            userName: `bulk.user.2.${generateSecureRandom(4)}@example.com`,
            displayName: 'Bulk User 2',
            active: true,
          },
        },
        {
          method: 'POST',
          path: '/Users',
          bulkId: 'user3',
          data: {
            schemas: [SCHEMA_USER],
            userName: `bulk.user.3.${generateSecureRandom(4)}@example.com`,
            displayName: 'Bulk User 3',
            active: true,
          },
        },
      ],
    }

    const { response, data } = await this.makeSCIMRequest<{
      Operations: Array<{ status: string; bulkId: string; location?: string }>
    }>(
      'POST',
      '/Bulk',
      {
        body: bulkRequest,
        step: 'Execute bulk operations',
        rfcReference: 'RFC 7644 Section 3.7',
      }
    )

    if (response.ok) {
      const successful = data.Operations.filter(op => op.status === '201').length
      this.addEvent({
        type: 'info',
        title: 'Bulk Operations Complete',
        description: `${successful}/${data.Operations.length} operations succeeded`,
        data: { results: data.Operations },
      })
    }
  }
}

// ============================================================================
// Factory Function
// ============================================================================

export type SCIMFlowType = 
  | 'user-lifecycle'
  | 'group-management'
  | 'filter-queries'
  | 'schema-discovery'
  | 'bulk-operations'

export function createSCIMExecutor(
  flowType: SCIMFlowType,
  config: SCIMProvisioningConfig
): SCIMExecutorBase {
  switch (flowType) {
    case 'user-lifecycle':
      return new UserLifecycleExecutor(config)
    case 'group-management':
      return new GroupManagementExecutor(config)
    case 'filter-queries':
      return new FilterQueryExecutor(config)
    case 'schema-discovery':
      return new SchemaDiscoveryExecutor(config)
    case 'bulk-operations':
      return new BulkOperationsExecutor(config)
    default:
      throw new Error(`Unknown SCIM flow type: ${flowType}`)
  }
}

export const SCIM_FLOWS = {
  'user-lifecycle': {
    name: 'User Lifecycle',
    description: 'Complete user provisioning: Create → Update → Deactivate → Delete',
    rfcReference: 'RFC 7644',
  },
  'group-management': {
    name: 'Group Membership',
    description: 'Create groups and manage user membership',
    rfcReference: 'RFC 7644',
  },
  'filter-queries': {
    name: 'Filter Queries',
    description: 'Explore SCIM filter syntax with live examples',
    rfcReference: 'RFC 7644 Section 3.4.2.2',
  },
  'schema-discovery': {
    name: 'Schema Discovery',
    description: 'Discover server capabilities and schema definitions',
    rfcReference: 'RFC 7643, RFC 7644',
  },
  'bulk-operations': {
    name: 'Bulk Operations',
    description: 'Execute multiple operations in a single request',
    rfcReference: 'RFC 7644 Section 3.7',
  },
}

