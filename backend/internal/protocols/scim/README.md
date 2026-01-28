# SCIM 2.0 Protocol Implementation

A standards-compliant implementation of [SCIM 2.0](https://scim.cloud/) (System for Cross-domain Identity Management) per RFC 7642, 7643, and 7644. This implementation operates as a real SCIM server integrated with enterprise Identity Providers like Okta and Azure AD.

## Overview

This implementation provides:

- **Real SCIM Server**: Full RFC 7644 compliant REST API for user and group provisioning
- **IdP Integration**: Bearer token authentication for Okta, Azure AD, and other SCIM clients
- **SQLite Persistence**: Durable storage with automatic schema migrations
- **RFC 7644 Filtering**: Complete filter expression parser with SQL translation
- **PATCH Operations**: RFC-compliant add, remove, and replace operations with path expressions
- **Bulk Operations**: Multi-operation requests per RFC 7644 Section 3.7
- **Schema Discovery**: ServiceProviderConfig, ResourceTypes, and Schemas endpoints
- **ETag Support**: Optimistic concurrency control with version tracking
- **Looking Glass Integration**: Real-time flow visualization for educational purposes

## Service Deployment

The SCIM implementation runs as its own service in the split backend architecture. It can be used:

- **Behind the gateway** (recommended): `/scim/*` is proxied through the gateway so the frontend and clients use a single base URL.
- **Standalone**: run the SCIM service by itself and point your IdP directly at it.

When running standalone, set `SHOWCASE_BASE_URL` to the public URL you want SCIM to advertise in links and metadata.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SCIM 2.0 Implementation                              │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  External Identity Providers                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │      Okta       │  │    Azure AD     │  │   Other IdPs    │              │
│  │                 │  │                 │  │                 │              │
│  │ SCIM Connector  │  │ SCIM Connector  │  │ SCIM Connector  │              │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘              │
│           │                    │                    │                       │
│           └────────────────────┼────────────────────┘                       │
│                                │                                            │
│                      HTTPS + Bearer Token Auth                              │
│                                │                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     SCIM Plugin (plugin.go)                         │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │  Auth Middleware  │  │  HTTP Handlers    │  │  Storage Layer  │  │    │
│  │  │   (auth.go)       │  │  (handlers.go)    │  │  (storage.go)   │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • Bearer Token    │  │ • /Users CRUD     │  │ • SQLite DB     │  │    │
│  │  │ • IdP Detection   │  │ • /Groups CRUD    │  │ • Migrations    │  │    │
│  │  │ • Audit Logging   │  │ • /Bulk           │  │ • Filtering     │  │    │
│  │  └───────────────────┘  │ • /.search        │  │ • Pagination    │  │    │
│  │                         └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐  ┌─────────────────┐  │    │
│  │  │  Discovery        │  │  Filter Parser    │  │  PATCH Engine   │  │    │
│  │  │  (discovery.go)   │  │  (filter.go)      │  │  (patch.go)     │  │    │
│  │  │                   │  │                   │  │                 │  │    │
│  │  │ • /ServiceProv... │  │ • Lexer           │  │ • Path Parsing  │  │    │
│  │  │ • /ResourceTypes  │  │ • Parser          │  │ • Op Execution  │  │    │
│  │  │ • /Schemas        │  │ • SQL Generation  │  │ • Value Filters │  │    │
│  │  └───────────────────┘  └───────────────────┘  └─────────────────┘  │    │
│  │                                                                     │    │
│  │  ┌───────────────────┐  ┌───────────────────┐                       │    │
│  │  │  Resources        │  │  Error Handling   │                       │    │
│  │  │  (resources.go)   │  │  (errors.go)      │                       │    │
│  │  │                   │  │                   │                       │    │
│  │  │ • User Schema     │  │ • SCIMError type  │                       │    │
│  │  │ • Group Schema    │  │ • RFC 7644 codes  │                       │    │
│  │  │ • Enterprise Ext  │  │ • HTTP mapping    │                       │    │
│  │  └───────────────────┘  └───────────────────┘                       │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                |                                            │
│                                ▼                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         SQLite Database                             │    │
│  │                        /data/scim/scim.db                           │    │
│  │                                                                     │    │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐  │    │
│  │  │   scim_users    │  │   scim_groups   │  │ scim_group_members  │  │    │
│  │  │                 │  │                 │  │                     │  │    │
│  │  │ id (UUID)       │  │ id (UUID)       │  │ group_id            │  │    │
│  │  │ external_id     │  │ external_id     │  │ user_id             │  │    │
│  │  │ user_name       │  │ display_name    │  │ type                │  │    │
│  │  │ data (JSON)     │  │ data (JSON)     │  │ display             │  │    │
│  │  │ version         │  │ version         │  └─────────────────────┘  │    │
│  │  │ created_at      │  │ created_at      │                           │    │
│  │  │ updated_at      │  │ updated_at      │                           │    │
│  │  └─────────────────┘  └─────────────────┘                           │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

| File | Purpose |
|------|---------|
| `plugin.go` | Main plugin implementing `ProtocolPlugin` interface, route registration, flow definitions |
| `handlers.go` | HTTP request handlers for all SCIM endpoints (Users, Groups, Bulk, Search) |
| `storage.go` | SQLite storage layer with migrations, CRUD operations, and query building |
| `resources.go` | SCIM resource type definitions (User, Group, EnterpriseUser extension) |
| `discovery.go` | Schema discovery endpoints (ServiceProviderConfig, ResourceTypes, Schemas) |
| `filter.go` | RFC 7644 filter expression lexer, parser, and SQL translator |
| `patch.go` | PATCH operation engine with path expression parsing and execution |
| `auth.go` | Bearer token authentication middleware and IdP detection |
| `errors.go` | SCIM-specific error types per RFC 7644 Section 3.12 |
| `client.go` | Outbound SCIM client for provisioning to external servers |

## API Endpoints

### Discovery Endpoints (Public)

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| GET | `/scim/v2/ServiceProviderConfig` | Server capabilities | RFC 7643 §5 |
| GET | `/scim/v2/ResourceTypes` | Supported resource types | RFC 7643 §6 |
| GET | `/scim/v2/ResourceTypes/{id}` | Specific resource type | RFC 7643 §6 |
| GET | `/scim/v2/Schemas` | All schemas | RFC 7643 §7 |
| GET | `/scim/v2/Schemas/{id}` | Specific schema by URN | RFC 7643 §7 |

### User Endpoints (Authenticated)

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| GET | `/scim/v2/Users` | List users with filtering/pagination | RFC 7644 §3.4.2 |
| POST | `/scim/v2/Users` | Create user | RFC 7644 §3.3 |
| GET | `/scim/v2/Users/{id}` | Get user by ID | RFC 7644 §3.4.1 |
| PUT | `/scim/v2/Users/{id}` | Replace user | RFC 7644 §3.5.1 |
| PATCH | `/scim/v2/Users/{id}` | Modify user | RFC 7644 §3.5.2 |
| DELETE | `/scim/v2/Users/{id}` | Delete user | RFC 7644 §3.6 |

### Group Endpoints (Authenticated)

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| GET | `/scim/v2/Groups` | List groups with filtering | RFC 7644 §3.4.2 |
| POST | `/scim/v2/Groups` | Create group | RFC 7644 §3.3 |
| GET | `/scim/v2/Groups/{id}` | Get group by ID | RFC 7644 §3.4.1 |
| PUT | `/scim/v2/Groups/{id}` | Replace group | RFC 7644 §3.5.1 |
| PATCH | `/scim/v2/Groups/{id}` | Modify group/members | RFC 7644 §3.5.2 |
| DELETE | `/scim/v2/Groups/{id}` | Delete group | RFC 7644 §3.6 |

### Bulk & Search (Authenticated)

| Method | Endpoint | Description | RFC Reference |
|--------|----------|-------------|---------------|
| POST | `/scim/v2/Bulk` | Bulk operations | RFC 7644 §3.7 |
| POST | `/scim/v2/.search` | Server-side search | RFC 7644 §3.4.3 |

## Authentication

### Bearer Token Authentication

All endpoints under `/scim/v2/*` (except discovery) require Bearer token authentication:

```http
Authorization: Bearer {SCIM_API_TOKEN}
```

Configure the token via environment variable:

```bash
# Set on Fly.io
fly secrets set SCIM_API_TOKEN=your-secure-token-here

# Or in docker-compose.yml
environment:
  - SCIM_API_TOKEN=your-secure-token-here
```

### IdP Detection

The system automatically detects the source Identity Provider from request headers:

| IdP | Detection Method |
|-----|------------------|
| Okta | User-Agent contains "Okta" |
| Azure AD | User-Agent contains "Azure" or "Microsoft" |
| OneLogin | User-Agent contains "OneLogin" |
| Ping Identity | User-Agent contains "Ping" |
| Generic | Default fallback |

This information is logged for audit purposes and displayed in the Looking Glass.

> Note: If `SCIM_API_TOKEN` is not set, authentication is disabled for demo and local testing.
> For production deployments, configure `SCIM_API_TOKEN` and require it on your IdP connector.

## Filter Expressions

The implementation supports the full RFC 7644 filter grammar:

### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equal | `userName eq "alice"` |
| `ne` | Not equal | `active ne false` |
| `co` | Contains | `emails.value co "@example.com"` |
| `sw` | Starts with | `name.familyName sw "J"` |
| `ew` | Ends with | `userName ew "@example.com"` |
| `gt` | Greater than | `meta.created gt "2024-01-01"` |
| `ge` | Greater or equal | `meta.lastModified ge "2024-01-01"` |
| `lt` | Less than | `meta.created lt "2024-12-31"` |
| `le` | Less or equal | `meta.lastModified le "2024-12-31"` |
| `pr` | Present (has value) | `emails pr` |

### Logical Operators

```
userName eq "alice" and active eq true
emails.type eq "work" or emails.type eq "home"  
not(active eq false)
```

### Value Path Expressions

```
emails[type eq "work"].value
addresses[type eq "work" and primary eq true]
```

### Example Queries

```http
# Find user by email
GET /scim/v2/Users?filter=userName eq "alice@example.com"

# Find active users in engineering
GET /scim/v2/Users?filter=active eq true and urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Engineering"

# Paginate results
GET /scim/v2/Users?startIndex=1&count=25

# Sort by family name descending  
GET /scim/v2/Users?sortBy=name.familyName&sortOrder=descending
```

## PATCH Operations

### Supported Operations

| Operation | Description | Example |
|-----------|-------------|---------|
| `add` | Add value(s) | Add new email address |
| `remove` | Remove value(s) | Remove phone number |
| `replace` | Replace value(s) | Update display name |

### Path Expressions

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "replace",
      "path": "name.givenName",
      "value": "Robert"
    },
    {
      "op": "add", 
      "path": "emails",
      "value": [{"value": "bob.work@example.com", "type": "work"}]
    },
    {
      "op": "remove",
      "path": "phoneNumbers[type eq \"fax\"]"
    }
  ]
}
```

### Group Membership via PATCH

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {
      "op": "add",
      "path": "members",
      "value": [{"value": "user-uuid-here"}]
    },
    {
      "op": "remove",
      "path": "members[value eq \"user-uuid-to-remove\"]"
    }
  ]
}
```

## Resource Schemas

### User Resource

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
  ],
  "id": "2819c223-7f76-453a-919d-413861904646",
  "externalId": "okta-user-id",
  "userName": "alice@example.com",
  "name": {
    "formatted": "Alice Johnson",
    "familyName": "Johnson",
    "givenName": "Alice"
  },
  "displayName": "Alice Johnson",
  "active": true,
  "emails": [
    {"value": "alice@example.com", "type": "work", "primary": true}
  ],
  "phoneNumbers": [
    {"value": "+1-555-1234", "type": "work"}
  ],
  "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
    "employeeNumber": "E12345",
    "department": "Engineering",
    "manager": {"value": "manager-uuid", "displayName": "Bob Smith"}
  },
  "meta": {
    "resourceType": "User",
    "created": "2024-01-15T10:30:00Z",
    "lastModified": "2024-01-15T10:30:00Z",
    "location": "https://protocolsoup.fly.dev/scim/v2/Users/2819c223-7f76-453a-919d-413861904646",
    "version": "W/\"1\""
  }
}
```

### Group Resource

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
  "id": "e9e30dba-f08f-4109-8486-d5c6a331660a",
  "displayName": "Engineering",
  "members": [
    {"value": "2819c223-7f76-453a-919d-413861904646", "display": "Alice Johnson", "type": "User"}
  ],
  "meta": {
    "resourceType": "Group",
    "created": "2024-01-15T10:30:00Z",
    "lastModified": "2024-01-15T10:30:00Z",
    "location": "https://protocolsoup.fly.dev/scim/v2/Groups/e9e30dba-f08f-4109-8486-d5c6a331660a",
    "version": "W/\"1\""
  }
}
```

## Looking Glass Flows

The following flows are available in the Looking Glass for educational visualization:

### Executable Flows

| Flow ID | Name | Description |
|---------|------|-------------|
| `user-lifecycle` | User Lifecycle | Create → Update → Deactivate → Delete (with cleanup) |
| `group-membership` | Group Management | Create group → Add/Remove members → Delete (with cleanup) |
| `user-discovery` | Filter Queries | Query users with various filter expressions (read-only) |
| `schema-discovery` | Schema Discovery | Explore ServiceProviderConfig, ResourceTypes, Schemas (read-only) |

### Reference-Only Flows

| Flow ID | Name | Why Not Executable |
|---------|------|-------------------|
| `bulk-operations` | Bulk Operations | Creates multiple users without cleanup |
| `outbound-provisioning` | Outbound Provisioning | Requires external SCIM server |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCIM_API_TOKEN` | Bearer token for authentication | (none - auth disabled if not set) |
| `SCIM_DATA_DIR` | Directory for SQLite database | `./data` or `/data/scim` on Fly.io |
| `SCIM_LOOKING_GLASS` | Enable Looking Glass capture | `true` |

### Fly.io Deployment

```toml
# fly.toml
[env]
  SCIM_DATA_DIR = "/data/scim"

[[mounts]]
  source = "protocolsoup_data"
  destination = "/data"
```

### Docker Compose

```yaml
services:
  scim-service:
    environment:
      - SCIM_API_TOKEN=${SCIM_API_TOKEN}
      - SCIM_DATA_DIR=/app/data
    volumes:
      - scim-data:/app/data
```

## Okta Integration

### Setup Steps

1. **Create SCIM App in Okta**
   - Applications → Create App Integration → SCIM 2.0 Test App

2. **Configure SCIM Connection**
   - Base URL: `{GATEWAY_BASE_URL}/scim/v2` (or the standalone SCIM service URL)
   - Authentication: HTTP Header
   - Header Name: `Authorization`
   - Header Value: `Bearer {your-token}`

3. **Enable Provisioning Features**
   - Create Users ✓
   - Update User Attributes ✓
   - Deactivate Users ✓
   - Push Groups ✓

4. **Assign Users/Groups**
   - Assignments tab → Assign users or groups to push

### Testing Connection

Okta provides a "Test Connector Configuration" button that verifies:
- Authentication works
- User schema is compatible
- Create/Update/Delete operations function

## Error Responses

All errors follow RFC 7644 Section 3.12:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "400",
  "scimType": "invalidValue",
  "detail": "userName is required"
}
```

### Error Types

| scimType | HTTP Status | Description |
|----------|-------------|-------------|
| `invalidFilter` | 400 | Malformed filter expression |
| `invalidPath` | 400 | Invalid PATCH path |
| `invalidValue` | 400 | Invalid attribute value |
| `invalidSyntax` | 400 | Request body parse error |
| `noTarget` | 400 | No target for operation |
| `invalidVers` | 400 | ETag version mismatch |
| `mutability` | 400 | Immutable attribute modification |
| `uniqueness` | 409 | Duplicate unique value |
| `tooMany` | 400 | Too many operations |

## Development

### Running Locally

```bash
# Start with Docker Compose
cd docker
docker compose up -d

# Test endpoints via gateway
curl http://localhost:8080/scim/v2/ServiceProviderConfig

# Create a user
curl -X POST http://localhost:8080/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"test@example.com"}'
```

### Database Location

- **Local/Docker**: `./data/scim.db`
- **Fly.io**: `/data/scim/scim.db` (persistent volume)

### Viewing Logs

```bash
# Fly.io logs
fly logs -a protocolsoup | grep -i scim

# Docker logs
docker compose logs scim-service | grep -i scim
```

## RFC Compliance

| RFC | Title | Status |
|-----|-------|--------|
| RFC 7642 | SCIM Definitions, Overview, Concepts | ✅ Compliant |
| RFC 7643 | SCIM Core Schema | ✅ Compliant |
| RFC 7644 | SCIM Protocol | ✅ Compliant |

### Implemented Features

- ✅ User and Group CRUD operations
- ✅ Enterprise User extension schema
- ✅ Filter expressions (all operators)
- ✅ PATCH operations with path expressions
- ✅ Bulk operations
- ✅ Pagination (startIndex, count)
- ✅ Sorting (sortBy, sortOrder)
- ✅ ETag/versioning for optimistic concurrency
- ✅ Schema discovery endpoints
- ✅ SCIM error response format

### Not Implemented

- ❌ Custom schemas (only core User/Group)
- ❌ Password management
- ❌ Multi-tenancy
- ❌ Rate limiting (handled at infrastructure level)
