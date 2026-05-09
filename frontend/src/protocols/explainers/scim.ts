/**
 * SCIM 2.0 — Parameter Explainers
 *
 * REST/JSON identity-provisioning protocol. Different category from
 * authentication protocols: SCIM is a CRUD API for User and Group
 * resources, with PATCH semantics, filter queries, and bulk operations.
 * Attack surface revolves around identifier confusion (CVE-2025-41115
 * Grafana externalId, CVSS 10.0), PATCH path traversal, filter
 * injection, and over-privileged long-lived bearer tokens.
 */

import type { ParameterExplainer } from './index'

export const SCIM_EXPLAINERS: Record<string, ParameterExplainer> = {
  userName: {
    purpose:
      'The SCIM standard human-readable identifier for a User resource. ' +
      'Required, unique within the tenant, often used for sign-in. ' +
      'Comparable to a username — *mutable*, set by the SCIM client at ' +
      'create time, may be updated.',
    attacks: [
      {
        id: 'username-recycling',
        name: 'Account-takeover via username recycling',
        scenario:
          'Alice\'s account is deleted (perhaps after she leaves the ' +
          'company). Months later, the SCIM client provisions a new user ' +
          '`bob` and later renames them to `alice` (now-free username). ' +
          'The SP, keying by userName, links Bob to Alice\'s historical ' +
          'account state — which may include retained data, stale group ' +
          'memberships, or session artifacts.',
        impact:
          'Bob inherits Alice\'s account residue. Especially severe if ' +
          'Alice was a privileged user.',
      },
      {
        id: 'username-unicode-confusion',
        name: 'Case / Unicode normalization mismatch',
        scenario:
          'Case/Unicode normalization mismatch between SCIM client and SP ' +
          '(`Alice` vs `alice` vs `Аlice` with Cyrillic А) lets an attacker ' +
          'provision a visually-identical second account.',
        impact:
          'Two account records that look identical to the user but are ' +
          'distinct internally — confusion, account-merge bugs, ' +
          'authentication targeting wrong record.',
      },
    ],
    mitigations: [
      {
        action:
          'Use the server-assigned `id` (immutable) as the account primary ' +
          'key, never `userName`. RFC 7643 §4.1.1 explicitly says userName ' +
          'MAY be changed; account-record stability requires binding to ' +
          '`id`.',
        mitigates: ['username-recycling'],
      },
      {
        action:
          'Apply Unicode normalization (NFKC) and case-folding consistently ' +
          'when comparing userName values; reject confusable scripts at ' +
          'create time.',
        mitigates: ['username-unicode-confusion'],
      },
    ],
    references: [
      {
        label: 'RFC 7643 §4.1.1 (userName)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.1',
      },
      {
        label: 'RFC 7643 §9 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-9',
      },
    ],
  },

  externalId: {
    purpose:
      'A *client-assigned* identifier the SCIM client (typically the IdP) ' +
      'uses to correlate its own user record with the SCIM server\'s. The ' +
      'SCIM server stores it but treats it as opaque. Caller-controlled, ' +
      'free-form, optional.',
    attacks: [
      {
        id: 'cve-2025-41115-grafana-externalid',
        name: 'CVE-2025-41115 (Grafana Enterprise externalId, CVSS 10.0)',
        scenario:
          'Grafana\'s SCIM provisioning code mapped the caller-supplied ' +
          '`externalId` directly to the internal `user.uid`. An attacker ' +
          'with access to a SCIM client crafts a provisioning request with ' +
          '`externalId: "1"` — which is the UID of Grafana\'s built-in ' +
          'admin account. The provisioned user is silently linked to ' +
          'admin; the attacker now logs in as administrator without ever ' +
          'authenticating through the standard login flow. Affected ' +
          'versions 12.0.0–12.2.1; patched 2025-11. The pattern is broader ' +
          'than Grafana: any SCIM server that uses externalId for internal ' +
          'mapping has the same shape.',
        impact:
          'Maximum-severity (CVSS 10.0) full remote impersonation, no ' +
          'authentication required beyond SCIM client access.',
      },
    ],
    mitigations: [
      {
        action:
          'Treat externalId as opaque — never use it as an authoritative ' +
          'identifier internally.',
        mitigates: ['cve-2025-41115-grafana-externalid'],
      },
      {
        action:
          'Reject externalId values that are syntactically internal IDs ' +
          '(numeric where IDs are numeric, UUID-formatted where IDs are ' +
          'UUIDs).',
        mitigates: ['cve-2025-41115-grafana-externalid'],
      },
      {
        action:
          'Audit how externalId flows through your provisioning code path ' +
          '— anywhere it ends up in a database column other than a ' +
          'dedicated `external_id` field is a finding.',
        mitigates: ['cve-2025-41115-grafana-externalid'],
      },
    ],
    references: [
      {
        label: 'CVE-2025-41115 (Grafana Enterprise SCIM, CVSS 10.0)',
        href: 'https://thehackernews.com/2025/11/grafana-patches-cvss-100-scim-flaw.html',
      },
      {
        label: 'SOC Prime — CVE-2025-41115 deep dive',
        href: 'https://socprime.com/blog/cve-2025-41115-vulnerability/',
      },
      {
        label: 'RFC 7643 §3.1 (Common Attributes — externalId)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-3.1',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  id: {
    purpose:
      'Server-assigned, immutable, globally-unique identifier for a SCIM ' +
      'resource. Returned in the `Location` header on create. The ' +
      'authoritative key for a resource — every subsequent operation ' +
      'targets the resource via `/Users/{id}` URL path.',
    attacks: [
      {
        id: 'scim-body-vs-url-id-idor',
        name: 'Body-vs-URL ID override (Keycloak SCIM PUT IDOR)',
        scenario:
          'Keycloak issue #46658. The handler reads `/Users/{id-A}` from ' +
          'the URL to check authorization ("can the caller modify ' +
          'resource A?") but then reads the `id` field from the request ' +
          'body and updates resource B. Mallory has permission for her ' +
          'own user A but crafts a PUT with `id: "<admin-id>"` in the body ' +
          '— server authorizes against A, modifies admin. SCIM\'s ' +
          'structure (id appears in both URL and body) makes this mistake ' +
          'easy to miss in code review.',
        impact:
          'Cross-resource modification with bypassed authorization.',
      },
    ],
    mitigations: [
      {
        action:
          'Authorize against the URL-path id; treat the request body as ' +
          'the operation payload only.',
        mitigates: ['scim-body-vs-url-id-idor'],
      },
      {
        action:
          'Ignore body `id` fields entirely on PUT/PATCH (RFC 7643 §3.1: ' +
          'id is read-only).',
        mitigates: ['scim-body-vs-url-id-idor'],
      },
      {
        action:
          'Reject requests where body `id` differs from URL-path id with ' +
          '400 Bad Request — defence-in-depth signal that the caller is ' +
          'doing something wrong.',
        mitigates: ['scim-body-vs-url-id-idor'],
      },
    ],
    references: [
      {
        label: 'Keycloak Issue #46658 (SCIM PUT IDOR)',
        href: 'https://github.com/keycloak/keycloak/issues/46658',
      },
      {
        label: 'RFC 7643 §3.1 (Common Attributes — id immutable)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-3.1',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  op: {
    purpose:
      'PATCH operation type: `add` (insert/append), `replace` (overwrite), ' +
      '`remove` (delete). One of three operations applied at a JSON ' +
      'Pointer `path` on a target resource. SCIM PATCH wraps these in a ' +
      'PatchOp document with multiple operations applied in sequence per ' +
      'RFC 7644 §3.5.2 (servers stop on the first error; whether prior ' +
      'successful operations roll back is implementation-defined).',
    attacks: [
      {
        id: 'op-attribute-escalation',
        name: 'PATCH op-specific privilege escalation',
        scenario:
          'Mallory has SCIM client access scoped to "manage user profile ' +
          'fields" (intended: name, email). She crafts a PATCH with ' +
          '`op=add, path=groups, value=[{value: "admins"}]` — adding ' +
          'herself to a privileged group. The SCIM server authorizes the ' +
          'PATCH as a profile update because the *resource* is a user ' +
          'profile, missing that the *attribute path* `groups` is ' +
          'privilege-relevant. Variant: `op=replace, path=active, ' +
          'value=true` to reactivate a disabled account.',
        impact:
          'Privilege escalation via attribute-path-aware authorization gap.',
      },
    ],
    mitigations: [
      {
        action:
          'Authorization MUST be per-attribute, not per-resource — having ' +
          '"can PATCH this user" is not the same as "can PATCH groups on ' +
          'this user".',
        mitigates: ['op-attribute-escalation'],
      },
      {
        action:
          'Maintain an allowlist of paths each caller may modify; reject ' +
          'PATCH ops touching paths outside the allowlist.',
        mitigates: ['op-attribute-escalation'],
      },
      {
        action:
          'Treat `groups`, `active`, `roles`, `entitlements`, anything ' +
          'role-relevant as security-critical paths requiring elevated ' +
          'permission.',
        mitigates: ['op-attribute-escalation'],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.5.2 (PatchOp)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  path: {
    purpose:
      'JSON Pointer-like path identifying which attribute the PATCH ' +
      'operation targets. May include filters: ' +
      '`emails[type eq "work"].value`, `members[value eq "abc"]`. Drives ' +
      'most of SCIM PATCH\'s expressive power — and most of its attack ' +
      'surface.',
    attacks: [
      {
        id: 'path-traversal-admin-attributes',
        name: 'PATCH path traversal to admin-relevant attributes',
        scenario:
          'Mallory\'s authorization is "edit own profile". She crafts ' +
          'PATCH paths targeting attributes outside her permitted set: ' +
          '`groups[display eq "Administrators"]`, `meta.resourceType`, ' +
          'extension-schema attributes that map to backend role ' +
          'assignments. Sloppy SCIM servers parse the path and execute ' +
          'the operation without checking whether the *attribute* is in ' +
          'the caller\'s permitted set.',
        impact:
          'Attribute-level privilege escalation.',
      },
      {
        id: 'empty-path-full-resource-replace',
        name: 'Empty/null path replaces entire resource',
        scenario:
          '`{op: "replace", value: <whole resource>}` (no path) replaces ' +
          'the entire resource. Used in some SCIM implementations as a ' +
          'backdoor for full-resource updates that bypass per-attribute ' +
          'checks.',
        impact:
          'Authorization bypass on every attribute via single full-resource ' +
          'PATCH.',
      },
    ],
    mitigations: [
      {
        action:
          'Parse and normalize paths into structured form before ' +
          'authorization; authorize against the resolved attribute, not ' +
          'the raw path string.',
        mitigates: ['path-traversal-admin-attributes'],
      },
      {
        action:
          'Reject empty/null paths in PATCH operations unless the caller ' +
          'has full-resource write permission.',
        mitigates: ['empty-path-full-resource-replace'],
      },
      {
        action:
          'Validate against the resource schema — paths to undefined ' +
          'attributes should 400.',
        mitigates: ['path-traversal-admin-attributes'],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.5.2 (path attribute)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  value: {
    purpose:
      'The data carried by the PATCH operation: scalar for simple ' +
      'attributes, object/array for complex/multi-valued attributes, ' +
      'omitted for `remove`. Type-checked against the schema definition ' +
      'of the attribute named by `path`.',
    attacks: [
      {
        id: 'stored-xss-via-scim-value',
        name: 'Stored XSS via SCIM value',
        scenario:
          'The SCIM client provisions a user with ' +
          '`displayName: "<script>...</script>"`. The SP stores it and ' +
          'later renders the displayName unsanitised in an admin UI — ' +
          'every admin viewing the user list executes the attacker\'s ' +
          'script.',
        impact:
          'XSS scaled across every admin who views the user list.',
      },
      {
        id: 'log-injection-via-scim-value',
        name: 'Log-injection via newline-bearing values',
        scenario:
          'A SCIM `value` containing newline characters and forged log ' +
          'fields gets written to logs that downstream tools parse — ' +
          'spoofing log entries that appear to come from the system.',
        impact:
          'Audit-trail forgery; misdirection during incident response.',
      },
      {
        id: 'sql-nosql-injection-via-scim-value',
        name: 'SQL/NoSQL injection via SCIM value',
        scenario:
          'If `value` is concatenated into a query for downstream storage ' +
          '(rather than parameterized), a crafted value injects SQL or ' +
          'NoSQL operators.',
        impact:
          'Database compromise via injection during provisioning.',
      },
    ],
    mitigations: [
      {
        action:
          'Enforce SCIM schema constraints on every attribute (string ' +
          'length, pattern, enum) at write time.',
        mitigates: [
          'stored-xss-via-scim-value',
          'log-injection-via-scim-value',
          'sql-nosql-injection-via-scim-value',
        ],
      },
      {
        action:
          'Sanitise/escape on render — never trust SCIM-stored data as ' +
          'safe HTML.',
        mitigates: ['stored-xss-via-scim-value'],
      },
      {
        action:
          'Never use SCIM data directly in shell, SQL, LDAP, or template ' +
          'expressions without context-appropriate escaping or ' +
          'parameterization.',
        mitigates: [
          'log-injection-via-scim-value',
          'sql-nosql-injection-via-scim-value',
        ],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.5.2 (value attribute)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  filter: {
    purpose:
      'SCIM\'s SQL-like query language for resource search: ' +
      '`userName eq "alice"`, ' +
      '`emails.type eq "work" and active eq true`, ' +
      '`name.familyName sw "Smi"`. Operators include `eq`, `ne`, `co`, ' +
      '`sw`, `ew`, `pr`, `gt`, `ge`, `lt`, `le`, plus logical `and`, ' +
      '`or`, `not`. Carried in URL query string on GET, embedded in PATCH ' +
      'paths, and used in bulk operations.',
    attacks: [
      {
        id: 'scim-filter-sql-injection',
        name: 'SQL injection via filter concatenation',
        scenario:
          'Hand-rolled SCIM implementations sometimes string-concatenate ' +
          'the filter into SQL: `SELECT * FROM users WHERE userName = ' +
          '"alice"`. Mallory submits ' +
          '`?filter=userName eq "alice" or 1=1 --"` and the resulting SQL ' +
          'becomes `WHERE userName = "alice" or 1=1 --"`, returning every ' +
          'user.',
        impact:
          'Mass user enumeration → potential bulk modification if the ' +
          'injection works on PATCH-via-filter operations.',
      },
      {
        id: 'scim-filter-nosql-injection',
        name: 'NoSQL injection via filter JSON decoding',
        scenario:
          '`?filter=userName eq {"$ne":""}` if the SCIM layer JSON-decodes ' +
          'filter fragments into MongoDB operator objects.',
        impact:
          'Authentication / authorization bypass in NoSQL-backed SCIM ' +
          'servers.',
      },
      {
        id: 'scim-filter-ldap-injection',
        name: 'LDAP injection via filter values',
        scenario:
          'Filter values containing `*)(uid=*` confuse LDAP query parsers ' +
          'that translate SCIM filters directly into LDAP search filters.',
        impact:
          'LDAP query manipulation enabling enumeration or auth bypass.',
      },
    ],
    mitigations: [
      {
        action:
          'Parse the SCIM filter into a typed AST; translate the AST to ' +
          'parameterized backend queries — never string-concatenate filter ' +
          'text into SQL/LDAP/Mongo.',
        mitigates: [
          'scim-filter-sql-injection',
          'scim-filter-nosql-injection',
          'scim-filter-ldap-injection',
        ],
      },
      {
        action:
          'Impose hard rate limits on filtered GETs to bound enumeration ' +
          'damage even if injection succeeds.',
        mitigates: [
          'scim-filter-sql-injection',
          'scim-filter-nosql-injection',
          'scim-filter-ldap-injection',
        ],
      },
      {
        action:
          'When filters embed in PATCH paths, apply the same parsing and ' +
          'validation — the injection surface is the same.',
        mitigates: [
          'scim-filter-sql-injection',
          'scim-filter-nosql-injection',
          'scim-filter-ldap-injection',
        ],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.4.2.2 (Filtering)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.2',
      },
      {
        label: 'OWASP — LDAP Injection Prevention',
        href: 'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  'scim:active': {
    purpose:
      'Boolean attribute on a User resource indicating whether the account ' +
      'is enabled. The IdP\'s SCIM client typically toggles `active=false` ' +
      'to deactivate users on offboarding, and the SP is expected to ' +
      'enforce that flag at sign-in / API access time.',
    attacks: [
      {
        id: 'deactivation-session-lag',
        name: 'IdP-de-provisioning bypass via SP session lag',
        scenario:
          'Alice is fired. IdP issues SCIM PATCH `active=false` to the SP ' +
          'at 09:00. SP updates its user record at 09:00:01 but does NOT ' +
          'invalidate Alice\'s active sessions, refresh tokens, or API ' +
          'keys. Alice (or someone with her credentials) continues using ' +
          'the SP for hours or days until the existing tokens naturally ' +
          'expire. Variant: SP caches the `active` flag in a denormalised ' +
          'join table updated asynchronously; the cached value lags behind ' +
          'the SCIM update.',
        impact:
          'Persistent access despite de-provisioning.',
      },
      {
        id: 'unauthorized-reactivation',
        name: 'Unauthorized reactivation via PATCH',
        scenario:
          'A caller with profile-edit permission crafts ' +
          '`op=replace, path=active, value=true` to reactivate a disabled ' +
          'account. Same auth-relevant-attribute gap as `op` warned about.',
        impact:
          'Disabled accounts re-enabled outside admin oversight.',
      },
    ],
    mitigations: [
      {
        action:
          'Treat SCIM `active=false` as a trigger for full session/token ' +
          'revocation across every credential surface — not just a ' +
          'database flag flip. Refresh tokens, API keys, downstream ' +
          'service sessions all need invalidation. SCIM is a provisioning ' +
          'protocol; session revocation is the SP\'s responsibility outside ' +
          'the SCIM RFCs, so this is operational hardening rather than a ' +
          'spec-normative MUST.',
        mitigates: ['deactivation-session-lag'],
      },
      {
        action:
          'Restrict PATCH access to `active` to admin-class SCIM clients ' +
          '(treat as security-critical attribute per `op` mitigations).',
        mitigates: ['unauthorized-reactivation'],
      },
      {
        action:
          'Alert on PATCH ops modifying `active` for unexpected escalation ' +
          'patterns (reactivation of recently-deactivated users).',
        mitigates: ['unauthorized-reactivation'],
      },
    ],
    references: [
      {
        label: 'RFC 7643 §4.1.1 (active attribute)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.1',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  bulkId: {
    purpose:
      'Caller-supplied placeholder identifier within a Bulk request. Lets ' +
      'a single bulk operation reference resources created by *earlier* ' +
      'operations in the same bulk: operation 1 creates a group with ' +
      '`bulkId="g1"`, operation 2 adds a member referring to `bulkId:g1` ' +
      '— the server resolves it to the actual id once operation 1 ' +
      'completes.',
    attacks: [
      {
        id: 'bulkid-circular-reference',
        name: 'Circular bulkId references',
        scenario:
          'Operation A references bulkId B, operation B references bulkId ' +
          'A. Servers without cycle detection enter infinite-resolve loops.',
        impact:
          'Denial of service via cycle exhaustion.',
      },
      {
        id: 'bulkid-forgery',
        name: 'bulkId forgery / undefined reference probing',
        scenario:
          'Caller submits a bulkId-style reference that wasn\'t actually ' +
          'defined in the bulk. Server tries to resolve and either fails ' +
          'or, depending on implementation, leaks information about which ' +
          'IDs exist via differential responses. Mallory submits a bulk ' +
          'request that creates a user with `bulkId="probe"` then attempts ' +
          'to read user `bulkId:<guess-of-internal-id-format>`.',
        impact:
          'Information disclosure (predictable internal ID patterns) → ' +
          'enumeration.',
      },
      {
        id: 'bulkid-self-reference',
        name: 'Self-reference attack',
        scenario:
          'Operation references its own bulkId — without explicit rejection ' +
          '(per SCIM-SDK\'s "invalidValue" response), the server may end ' +
          'up creating a resource that references itself with consequences ' +
          'the schema didn\'t anticipate.',
        impact:
          'State corruption — depends on schema, ranges from minor ' +
          'inconsistency to authorization bypass.',
      },
    ],
    mitigations: [
      {
        action:
          'Strictly validate every bulkId reference is defined within the ' +
          'same bulk request before resolution.',
        mitigates: ['bulkid-forgery'],
      },
      {
        action: 'Reject circular references with HTTP 409 Conflict.',
        mitigates: ['bulkid-circular-reference'],
      },
      {
        action:
          'Reject self-references with HTTP 400 invalidValue (per SCIM-SDK ' +
          'pattern).',
        mitigates: ['bulkid-self-reference'],
      },
      {
        action:
          'Cap bulk request size (`failOnErrors` and overall operation ' +
          'count limits) to bound resource consumption.',
        mitigates: ['bulkid-circular-reference', 'bulkid-forgery'],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.7.2 (Bulk Operation Request and Response Structure)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.7.2',
      },
      {
        label: 'SCIM-SDK BulkId Reference Resolving (cycle detection)',
        href: 'https://github.com/Captain-P-Goldfish/SCIM-SDK/wiki/BulkId-reference-resolving',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  members: {
    purpose:
      'Multi-valued attribute on a Group resource listing User IDs (or ' +
      'nested Group IDs) belonging to the group. Typically updated via ' +
      'PATCH operations on the path `members` (add/remove). Group ' +
      'membership is the standard SCIM mechanism for role assignment — so ' +
      '`members` is the privilege-bearing attribute on Groups.',
    attacks: [
      {
        id: 'group-membership-privilege-escalation',
        name: 'Group-membership privilege escalation',
        scenario:
          'Keycloak SCIM-class vulnerability per 2025 SOC Prime advisory. ' +
          'Mallory has SCIM client permission to create or modify Group ' +
          'resources for some legitimate purpose (managing project teams). ' +
          'She PATCHes the `Administrators` group with ' +
          '`op=add, path=members, value=[{value: "<own-user-id>"}]` — ' +
          'adding herself. The SCIM server authorizes the PATCH because ' +
          'the *resource* (Group Administrators) is in her writable set; ' +
          'it doesn\'t check that modifying *that specific group\'s ' +
          'members* requires elevated authority.',
        impact:
          'Admin role acquisition through group membership manipulation.',
      },
    ],
    mitigations: [
      {
        action:
          'Treat privileged groups (admin, root, owner, etc.) as ' +
          'restricted resources requiring elevated SCIM client authority ' +
          'to modify.',
        mitigates: ['group-membership-privilege-escalation'],
      },
      {
        action:
          'Authorize on the *combination* of resource, attribute, AND ' +
          'specific value — adding to Administrators is not the same ' +
          'authorization as adding to ProjectTeamA.',
        mitigates: ['group-membership-privilege-escalation'],
      },
      {
        action:
          'Audit every `members` PATCH that touches privileged groups; ' +
          'alert on unexpected membership changes.',
        mitigates: ['group-membership-privilege-escalation'],
      },
    ],
    references: [
      {
        label: 'RFC 7643 §4.2 (Group Schema)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.2',
      },
      {
        label: 'RFC 7644 §3.5.2 (Modifying with PATCH)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  attributes: {
    purpose:
      'Query parameter on GET requests selecting which attributes to ' +
      'return in the response (projection). Sibling `excludedAttributes` ' +
      'inverts the selection. Lets clients reduce payload size and limit ' +
      'data exposure.',
    attacks: [
      {
        id: 'attributes-projection-auth-bypass',
        name: 'Authorization bypass via attribute exclusion',
        scenario:
          'Server logic: "return user record, but only check `groups` ACL ' +
          'if `groups` is in the requested `attributes`". Mallory requests ' +
          '`GET /Users/{id}?attributes=name,email` — no `groups` ' +
          'requested, so no `groups` ACL check, and the response also ' +
          'returns the lighter projection. But the ACL was the gating ' +
          'control; without it, even non-privileged callers receive ' +
          'responses on resources they shouldn\'t see at all. Variant: ' +
          '`excludedAttributes=groups` with the same effect.',
        impact:
          'Authorization-control bypass via projection abuse.',
      },
      {
        id: 'attributes-projection-ignored',
        name: 'Projection ignored — over-disclosure',
        scenario:
          'Server returns full resources regardless of `attributes`, ' +
          'leaking attributes the caller didn\'t need (and may not have ' +
          'been authorized for).',
        impact:
          'Information disclosure beyond caller\'s intent or authorization.',
      },
    ],
    mitigations: [
      {
        action:
          'Enforce resource-level authorization independent of projection ' +
          '— "does the caller have GET permission on this user at all?" ' +
          'is checked before projection is considered.',
        mitigates: ['attributes-projection-auth-bypass'],
      },
      {
        action:
          'Treat `attributes` strictly as a response-shaping hint, never ' +
          'as input to authorization decisions.',
        mitigates: ['attributes-projection-auth-bypass'],
      },
      {
        action:
          'Attribute-level authorization filters the response *after* the ' +
          'resource-level check passes — and respects the projection ' +
          'parameter for shaping, not for gating.',
        mitigates: [
          'attributes-projection-auth-bypass',
          'attributes-projection-ignored',
        ],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.4.2.5 (attributes and excludedAttributes)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.5',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },

  ETag: {
    purpose:
      'Resource version identifier returned in the ETag response header ' +
      'and stored in `meta.version`. Clients send it back via `If-Match` / ' +
      '`If-None-Match` request headers to detect concurrent modifications. ' +
      'SCIM\'s optimistic-concurrency-control mechanism.',
    attacks: [
      {
        id: 'concurrent-patch-race-active',
        name: 'Concurrent-PATCH race on `active` toggle',
        scenario:
          'Admin Bob initiates PATCH `active=false` to lock Mallory\'s ' +
          'account at 12:00:00.000. Mallory, knowing she\'s about to be ' +
          'locked out, simultaneously initiates PATCH `active=true` ' +
          '(perhaps via stolen SCIM client credentials with self-management ' +
          'scope). Without ETag/If-Match, the second operation to land ' +
          'wins regardless of which started first.',
        impact:
          'Lost-update on security-relevant attribute — Bob\'s lockout ' +
          'silently loses to Mallory\'s reactivation.',
      },
      {
        id: 'partial-state-from-concurrent-writes',
        name: 'Partial state from concurrent writes',
        scenario:
          'An inconsistent set of concurrent writes leaves the resource ' +
          'in a partial state: Bob\'s deactivation completes but Mallory\'s ' +
          'group-membership-add to `Administrators` lands after — ' +
          'inactive admin account that gets reactivated on next legitimate ' +
          'PATCH.',
        impact:
          'Inconsistent persisted state that bypasses intended security ' +
          'invariants.',
      },
    ],
    mitigations: [
      {
        action:
          'Require `If-Match` on PATCH/PUT for security-critical ' +
          'attributes (`active`, `groups`, `entitlements`).',
        mitigates: [
          'concurrent-patch-race-active',
          'partial-state-from-concurrent-writes',
        ],
      },
      {
        action:
          'Reject 412 Precondition Failed on ETag mismatch — caller must ' +
          'refresh and retry.',
        mitigates: ['concurrent-patch-race-active'],
      },
      {
        action:
          'When the SCIM client retries on 412, the application logic ' +
          'must re-evaluate the desired state against the new server ' +
          'state — naive retry-with-same-payload re-introduces the race.',
        mitigates: ['concurrent-patch-race-active'],
      },
    ],
    references: [
      {
        label: 'RFC 7644 §3.14 (ETag / If-Match)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.14',
      },
      {
        label: 'RFC 7644 §7 (Security Considerations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-7',
      },
    ],
  },
}
