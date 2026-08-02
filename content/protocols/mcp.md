---
id: mcp
name: Model Context Protocol
use_cases:
  - agent-tooling
  - discovery
actors:
  - mcp-client
  - mcp-server
patterns:
  - back-channel
  - metadata-discovery
  - json-rpc
problem_domains:
  - agent-tooling
  - discovery
normative_anchors:
  - rfc: MCP 2026-07-28
    sections: ["basic/transports/streamable-http", "server/discover", "basic/versioning"]
  - rfc: SEP-2127
    sections: ["1"]
status: live
href: /protocol/mcp
summary: Remote MCP server over Streamable HTTP with catalog and JWT tools.
---

The Model Context Protocol (MCP) exposes tools to agents over a Streamable HTTP
transport. Revision 2026-07-28 is stateless: there is no initialize handshake
and no session header. Agents discover this server via the AI Catalog and
Server Card, then call read-only tools for the protocol catalog, flow
definitions, and JWT decoding.
