import type { CodeExample } from './index'

export const SCIM_EXAMPLES: Record<string, CodeExample> = {
  /* ------------------------------------------------------------------ */
  'user-lifecycle': {
    language: 'javascript',
    label: 'JavaScript (IdP / Provisioning Client)',
    code: `// SCIM 2.0 User Lifecycle (RFC 7644 §3.3, §3.5.1, §3.5.2)
// Demonstrates the full create → read → update → deactivate → delete cycle.

const SCIM_BASE = '/scim/v2';
const headers = {
  'Authorization': 'Bearer ' + SCIM_API_TOKEN,
  'Content-Type': 'application/scim+json',
};

// 1. Check if user already exists via filter query (RFC 7644 §3.4.2)
const existing = await fetch(
  SCIM_BASE + '/Users?filter=userName eq "j.doe@corp.example"',
  { headers }
).then(r => r.json());

let userId;
if (existing.totalResults === 0) {
  // 2. Create the user (RFC 7644 §3.3)
  const created = await fetch(SCIM_BASE + '/Users', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'j.doe@corp.example',
      name: { givenName: 'Jane', familyName: 'Doe' },
      emails: [
        { value: 'j.doe@corp.example', type: 'work', primary: true },
      ],
      active: true,
    }),
  }).then(r => r.json());
  // Response: 201 Created with Location header + meta.version (ETag)
  userId = created.id;
}

// 3. Update via PATCH (RFC 7644 §3.5.2 — PatchOp)
// Supports path expressions for nested attributes
await fetch(SCIM_BASE + '/Users/' + userId, {
  method: 'PATCH',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [
      { op: 'replace', path: 'name.familyName', value: 'Smith' },
      { op: 'add', path: 'phoneNumbers', value: [
        { value: '+1-555-0123', type: 'work' },
      ]},
    ],
  }),
});

// 4. Deactivate the user (soft-delete via PATCH)
await fetch(SCIM_BASE + '/Users/' + userId, {
  method: 'PATCH',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [
      { op: 'replace', path: 'active', value: false },
    ],
  }),
});

// 5. Hard delete (RFC 7644 §3.6) — returns 204 No Content
await fetch(SCIM_BASE + '/Users/' + userId, {
  method: 'DELETE',
  headers: { 'Authorization': 'Bearer ' + SCIM_API_TOKEN },
});`,
  },

  /* ------------------------------------------------------------------ */
  'group-membership': {
    language: 'javascript',
    label: 'JavaScript (IdP / Provisioning Client)',
    code: `// SCIM 2.0 Group Membership Management (RFC 7644 §3.3, §3.5.2)
const SCIM_BASE = '/scim/v2';
const headers = {
  'Authorization': 'Bearer ' + SCIM_API_TOKEN,
  'Content-Type': 'application/scim+json',
};

// 1. Create a group (RFC 7644 §3.3)
const group = await fetch(SCIM_BASE + '/Groups', {
  method: 'POST',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName: 'Engineering Team',
  }),
}).then(r => r.json());

// 2. Add members to the group via PATCH (RFC 7644 §3.5.2)
await fetch(SCIM_BASE + '/Groups/' + group.id, {
  method: 'PATCH',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{
      op: 'add',
      path: 'members',
      value: [
        { value: userId1 },
        { value: userId2 },
      ],
    }],
  }),
});

// 3. Remove a specific member using a value filter path expression
// This uses SCIM path expressions: members[value eq "..."]
await fetch(SCIM_BASE + '/Groups/' + group.id, {
  method: 'PATCH',
  headers,
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    Operations: [{
      op: 'remove',
      path: 'members[value eq "' + userId1 + '"]',
    }],
  }),
});

// 4. Replace entire membership (atomic update)
await fetch(SCIM_BASE + '/Groups/' + group.id, {
  method: 'PUT',
  headers: { ...headers, 'If-Match': group.meta.version },  // Optimistic locking
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    displayName: 'Engineering Team',
    members: [
      { value: userId2 },
      { value: userId3 },
    ],
  }),
});`,
  },

  /* ------------------------------------------------------------------ */
  'user-discovery': {
    language: 'http',
    label: 'HTTP (Filter Queries)',
    code: `# SCIM 2.0 Filter Queries (RFC 7644 §3.4.2)
# The filter grammar supports complex expressions with logical operators.

# Equality filter — exact match
GET /scim/v2/Users?filter=userName eq "j.doe@corp.example"

# Contains filter — substring match (useful for search)
GET /scim/v2/Users?filter=name.familyName co "Doe"

# Starts-with filter
GET /scim/v2/Users?filter=userName sw "j."

# Complex filter with AND / OR
GET /scim/v2/Users?filter=active eq true and (emails.value co "@corp.example")

# Nested attribute filter using value path expression
# Matches users whose "work" email is primary
GET /scim/v2/Users?filter=emails[type eq "work" and primary eq true]

# Presence filter — attribute exists (has a value)
GET /scim/v2/Users?filter=title pr

# Date comparison
GET /scim/v2/Users?filter=meta.lastModified gt "2025-01-01T00:00:00Z"

# Pagination (RFC 7644 §3.4.2.4) — 1-indexed
GET /scim/v2/Users?startIndex=1&count=25

# Sorting (RFC 7644 §3.4.2.3)
GET /scim/v2/Users?sortBy=name.familyName&sortOrder=ascending

# Supported filter operators:
#   eq  — equals              ne  — not equals
#   co  — contains            sw  — starts with
#   ew  — ends with           pr  — present (exists)
#   gt  — greater than        ge  — greater than or equal
#   lt  — less than           le  — less than or equal
#   and / or / not            — logical combinators
#
# Response envelope:
# {
#   "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
#   "totalResults": 142,
#   "startIndex": 1,
#   "itemsPerPage": 25,
#   "Resources": [ ... ]
# }`,
  },

  /* ------------------------------------------------------------------ */
  'schema-discovery': {
    language: 'javascript',
    label: 'JavaScript (Client)',
    code: `// SCIM 2.0 Schema Discovery (RFC 7644 §4)
// Discover server capabilities before starting provisioning.

const SCIM_BASE = '/scim/v2';

// 1. ServiceProviderConfig — server capabilities (RFC 7644 §4)
const config = await fetch(SCIM_BASE + '/ServiceProviderConfig')
  .then(r => r.json());

console.log('PATCH supported:',      config.patch.supported);
console.log('Bulk supported:',       config.bulk.supported);
console.log('Bulk max operations:',  config.bulk.maxOperations);
console.log('Bulk max payload:',     config.bulk.maxPayloadSize);
console.log('Filter supported:',     config.filter.supported);
console.log('Filter max results:',   config.filter.maxResults);
console.log('Change password:',      config.changePassword.supported);
console.log('Sort supported:',       config.sort.supported);
console.log('ETag supported:',       config.etag.supported);
console.log('Auth schemes:',         config.authenticationSchemes.map(s => s.type));

// 2. ResourceTypes — what resources this server manages (RFC 7644 §4)
const resourceTypes = await fetch(SCIM_BASE + '/ResourceTypes')
  .then(r => r.json());

for (const rt of resourceTypes.Resources) {
  console.log('Resource:', rt.name, 'at', rt.endpoint);
  console.log('  Schema:', rt.schema);
  if (rt.schemaExtensions) {
    for (const ext of rt.schemaExtensions) {
      console.log('  Extension:', ext.schema, ext.required ? '(required)' : '(optional)');
    }
  }
}

// 3. Schemas — detailed attribute definitions (RFC 7643 §7)
const userSchema = await fetch(
  SCIM_BASE + '/Schemas/urn:ietf:params:scim:schemas:core:2.0:User'
).then(r => r.json());

for (const attr of userSchema.attributes) {
  console.log(attr.name + ':', attr.type,
    '(' + attr.mutability + ')',
    attr.required ? 'REQUIRED' : 'optional');
}
// userName: string (readWrite) REQUIRED
// name: complex (readWrite) optional
// emails: complex (readWrite) optional  [multiValued]
// active: boolean (readWrite) optional`,
  },

  /* ------------------------------------------------------------------ */
  'bulk-operations': {
    language: 'javascript',
    label: 'JavaScript (IdP / Provisioning Client)',
    code: `// SCIM 2.0 Bulk Operations (RFC 7644 §3.7)
// Create multiple resources in a single HTTP request.
// Supports cross-references via bulkId for dependent resources.

const SCIM_BASE = '/scim/v2';

const bulkResponse = await fetch(SCIM_BASE + '/Bulk', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + SCIM_API_TOKEN,
    'Content-Type': 'application/scim+json',
  },
  body: JSON.stringify({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
    failOnErrors: 1,  // Stop processing after the first error
    Operations: [
      {
        method: 'POST',
        path: '/Users',
        bulkId: 'user-alice',
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'alice@corp.example',
          name: { givenName: 'Alice', familyName: 'Smith' },
          active: true,
        },
      },
      {
        method: 'POST',
        path: '/Users',
        bulkId: 'user-bob',
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'bob@corp.example',
          name: { givenName: 'Bob', familyName: 'Jones' },
          active: true,
        },
      },
      {
        // Cross-reference: use bulkId to refer to resources created above
        method: 'POST',
        path: '/Groups',
        bulkId: 'group-team',
        data: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
          displayName: 'New Team',
          members: [
            { value: 'bulkId:user-alice' },  // Resolved to alice's ID
            { value: 'bulkId:user-bob' },    // Resolved to bob's ID
          ],
        },
      },
    ],
  }),
}).then(r => r.json());

// Response: BulkResponse with per-operation results
// {
//   "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
//   "Operations": [
//     { "bulkId": "user-alice", "method": "POST", "status": "201",
//       "location": "/scim/v2/Users/uuid-1", "version": "W/\\"1\\"" },
//     { "bulkId": "user-bob",   "method": "POST", "status": "201",
//       "location": "/scim/v2/Users/uuid-2", "version": "W/\\"1\\"" },
//     { "bulkId": "group-team", "method": "POST", "status": "201",
//       "location": "/scim/v2/Groups/uuid-3", "version": "W/\\"1\\"" }
//   ]
// }

for (const op of bulkResponse.Operations) {
  console.log(op.bulkId + ':', op.status, op.location || op.response?.detail);
}`,
  },
}
