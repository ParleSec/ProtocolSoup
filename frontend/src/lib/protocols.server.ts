import 'server-only'

import type { FlowDefinition, Protocol } from '@/protocols/registry'

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
  const [protocol, flowResponse] = await Promise.all([
    fetchBackendJSON<Protocol>(`/api/protocols/${protocolId}`, 3600),
    fetchBackendJSON<{ flows: FlowDefinition[] }>(`/api/protocols/${protocolId}/flows`, 3600),
  ])

  return {
    protocol,
    flows: flowResponse.flows,
  }
}

export async function getFlowPageData(
  protocolId: string,
): Promise<{
  flows: FlowDefinition[]
}> {
  const flowResponse = await fetchBackendJSON<{ flows: FlowDefinition[] }>(`/api/protocols/${protocolId}/flows`, 86400)
  return { flows: flowResponse.flows }
}
