'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { api } from '@/utils/api'

/**
 * Exposes the site's key actions to browser-resident AI agents through the
 * WebMCP API (https://webmachinelearning.github.io/webmcp/).
 *
 * Every tool calls the same live endpoints the UI uses, so an agent driving the
 * page sees exactly what a person would.
 */

interface ToolResultContent {
  type: 'text'
  text: string
}

interface ToolResult {
  content: ToolResultContent[]
  isError?: boolean
}

interface ToolDescriptor {
  name: string
  description: string
  inputSchema: Record<string, unknown>
  execute: (args: Record<string, unknown>) => Promise<ToolResult>
}

interface ModelContext {
  registerTool?: (
    descriptor: ToolDescriptor,
    options?: { signal?: AbortSignal },
  ) => { unregister?: () => void } | void
  provideContext?: (context: { tools: ToolDescriptor[] }) => void
}

declare global {
  interface Navigator {
    modelContext?: ModelContext
  }
}

function ok(value: unknown): ToolResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] }
}

function failed(error: unknown): ToolResult {
  const message = error instanceof Error ? error.message : String(error)
  return { content: [{ type: 'text', text: message }], isError: true }
}

function requireString(args: Record<string, unknown>, key: string): string {
  const value = args[key]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`"${key}" is required and must be a non-empty string`)
  }
  return value.trim()
}

export function WebMcpTools() {
  const router = useRouter()

  useEffect(() => {
    const modelContext = navigator.modelContext
    if (!modelContext) {
      return
    }

    const tools: ToolDescriptor[] = [
      {
        name: 'search_protocols',
        description:
          'List the authentication and identity protocols ProtocolSoup implements, optionally filtered by a search term matched against protocol name, description, and tags.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Optional search term, for example "oauth" or "credentials".',
            },
          },
          additionalProperties: false,
        },
        async execute(args) {
          try {
            const { protocols } = await api.getProtocols()
            const query = typeof args.query === 'string' ? args.query.trim().toLowerCase() : ''
            const matches = query
              ? protocols.filter((protocol) =>
                  [protocol.id, protocol.name, protocol.description, ...(protocol.tags ?? [])]
                    .join(' ')
                    .toLowerCase()
                    .includes(query),
                )
              : protocols
            return ok(matches)
          } catch (error) {
            return failed(error)
          }
        },
      },
      {
        name: 'list_protocol_flows',
        description:
          'List the flows a protocol can execute, including which are runnable and the ordered steps each one performs.',
        inputSchema: {
          type: 'object',
          properties: {
            protocolId: {
              type: 'string',
              description: 'Protocol id from search_protocols, for example "oauth2" or "oid4vci".',
            },
          },
          required: ['protocolId'],
          additionalProperties: false,
        },
        async execute(args) {
          try {
            const protocolId = requireString(args, 'protocolId')
            const { flows } = await api.getProtocolFlows(protocolId)
            return ok(
              flows.map((flow) => ({
                id: flow.id,
                name: flow.name,
                description: flow.description,
                executable: flow.executable,
                steps: flow.steps?.length ?? 0,
              })),
            )
          } catch (error) {
            return failed(error)
          }
        },
      },
      {
        name: 'decode_token',
        description:
          'Decode a JWT and report its header, payload, and whether its signature verifies against the sandbox key set.',
        inputSchema: {
          type: 'object',
          properties: {
            token: {
              type: 'string',
              description: 'The encoded JWT to decode.',
            },
          },
          required: ['token'],
          additionalProperties: false,
        },
        async execute(args) {
          try {
            const decoded = await api.decodeToken(requireString(args, 'token'))
            return ok(decoded)
          } catch (error) {
            return failed(error)
          }
        },
      },
      {
        name: 'open_protocol_page',
        description:
          'Navigate this browser tab to a protocol page, where its flows can be run interactively.',
        inputSchema: {
          type: 'object',
          properties: {
            protocolId: {
              type: 'string',
              description: 'Protocol id from search_protocols, for example "saml".',
            },
          },
          required: ['protocolId'],
          additionalProperties: false,
        },
        async execute(args) {
          try {
            const protocolId = requireString(args, 'protocolId')
            const path = `/protocol/${encodeURIComponent(protocolId)}`
            router.push(path)
            return ok({ navigatedTo: path })
          } catch (error) {
            return failed(error)
          }
        },
      },
    ]

    const controller = new AbortController()

    if (typeof modelContext.registerTool === 'function') {
      const registrations = tools.map((tool) =>
        modelContext.registerTool?.(tool, { signal: controller.signal }),
      )
      return () => {
        controller.abort()
        for (const registration of registrations) {
          registration?.unregister?.()
        }
      }
    }

    if (typeof modelContext.provideContext === 'function') {
      modelContext.provideContext({ tools })
      return () => {
        modelContext.provideContext?.({ tools: [] })
      }
    }
  }, [router])

  return null
}
