import 'server-only'

import type { FlowDefinition, Protocol } from '@/protocols/registry'
import {
  getCatalogProtocol,
  isAgentSurfaceProtocol,
} from '@/protocols/presentation/protocol-catalog-data'

const BACKEND_ORIGIN = process.env.BACKEND_ORIGIN || 'http://localhost:8080'

class BackendRequestError extends Error {
  status: number
  pathname: string

  constructor(pathname: string, status: number) {
    super(`Backend request failed: ${pathname} (${status})`)
    this.name = 'BackendRequestError'
    this.pathname = pathname
    this.status = status
  }
}

function isBackendRequestError(error: unknown): error is BackendRequestError {
  return error instanceof BackendRequestError
}

export function isBackendNotFoundError(error: unknown): boolean {
  return isBackendRequestError(error) && error.status === 404
}

function catalogFallback(protocolId: string): { protocol: Protocol; flows: FlowDefinition[] } | null {
  const catalog = getCatalogProtocol(protocolId)
  if (!catalog) {
    return null
  }

  const executable = !isAgentSurfaceProtocol(protocolId)
  return {
    protocol: {
      id: catalog.id,
      name: catalog.name,
      version: catalog.spec,
      description: catalog.description,
      tags: [],
    },
    flows: catalog.flows.map((flow) => ({
      id: flow.backendId || flow.id,
      name: flow.name,
      description: flow.rfc,
      steps: [],
      executable: executable && flow.lookingGlass !== false,
    })),
  }
}

async function fetchBackendJSON<T>(
  pathname: string,
  revalidateSeconds: number,
) {
  const endpoint = `${BACKEND_ORIGIN}${pathname}`
  let response: Response

  try {
    response = await fetch(endpoint, {
      next: { revalidate: revalidateSeconds },
    })
  } catch {
    throw new Error(`Backend request failed: ${pathname} (network error)`)
  }

  if (!response.ok) {
    throw new BackendRequestError(pathname, response.status)
  }

  return (await response.json()) as T
}

export async function getProtocolPageData(protocolId: string): Promise<{
  protocol: Protocol
  flows: FlowDefinition[]
}> {
  try {
    const [protocol, flowResponse] = await Promise.all([
      fetchBackendJSON<Protocol>(`/api/protocols/${protocolId}`, 3600),
      fetchBackendJSON<{ flows: FlowDefinition[] }>(`/api/protocols/${protocolId}/flows`, 3600),
    ])

    return {
      protocol,
      flows: flowResponse.flows,
    }
  } catch (error) {
    const fallback = catalogFallback(protocolId)
    if (fallback) {
      return fallback
    }
    throw error
  }
}

export async function getFlowPageData(
  protocolId: string,
): Promise<{
  flows: FlowDefinition[]
}> {
  try {
    const flowResponse = await fetchBackendJSON<{ flows: FlowDefinition[] }>(
      `/api/protocols/${protocolId}/flows`,
      86400,
    )
    return { flows: flowResponse.flows }
  } catch (error) {
    const fallback = catalogFallback(protocolId)
    if (fallback) {
      return { flows: fallback.flows }
    }
    throw error
  }
}
