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
    withoutIt:
      'The trap is using `userName` as the SP-side primary key for the ' +
      'user record. `userName` is mutable: an IdP-driven rename through ' +
      'PATCH changes it. If the SP keys account records on userName, a ' +
      'rename either silently creates a new account (orphaning the old ' +
      'one with its data) or collides with another user\'s old userName ' +
      'still cached somewhere.',
    attack:
      'Account-takeover via username recycling. Alice\'s account is ' +
      'deleted (perhaps after she leaves the company). Months later, ' +
      'the SCIM client provisions a new user `bob` and later renames ' +
      'them to `alice` (now-free username). The SP, keying by ' +
      'userName, links Bob to Alice\'s historical account state — ' +
      'which may include retained data, stale group memberships, or ' +
      'session artifacts. Variant: case/Unicode normalization mismatch ' +
      'between SCIM client and SP (`Alice` vs `alice` vs `Аlice` with ' +
      'Cyrillic А) lets an attacker provision a visually-identical ' +
      'second account.',
    impact:
      'Use the server-assigned `id` (immutable) as the account primary ' +
      'key, never `userName`. SCIM RFC 7643 §4.1.1 explicitly says ' +
      'userName MAY be changed; account-record stability requires ' +
      'binding to `id`. Apply Unicode normalization (NFKC) and ' +
      'case-folding consistently when comparing.',
    references: [
      {
        label: 'RFC 7643 §4.1.1 (userName)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.1',
      },
    ],
  },

  externalId: {
    purpose:
      'A *client-assigned* identifier the SCIM client (typically the ' +
      'IdP) uses to correlate its own user record with the SCIM ' +
      'server\'s. The SCIM server stores it but treats it as opaque. ' +
      'Caller-controlled, free-form, optional.',
    withoutIt:
      'The trap is *trusting* `externalId` as anything more than an ' +
      'opaque correlation token. SCIM servers that map externalId ' +
      'into authorization-relevant identifiers (internal user IDs, ' +
      'role names, group memberships) hand the SCIM client a privilege-' +
      'escalation primitive.',
    attack:
      'CVE-2025-41115 (Grafana Enterprise, CVSS 10.0, Nov 2025). ' +
      'Grafana\'s SCIM provisioning code mapped the caller-supplied ' +
      '`externalId` directly to the internal `user.uid`. An attacker ' +
      'with access to a SCIM client crafts a provisioning request with ' +
      '`externalId: "1"` — which is the UID of Grafana\'s built-in ' +
      'admin account. The provisioned user is silently linked to admin; ' +
      'the attacker now logs in as administrator without ever ' +
      'authenticating through the standard login flow. CVSS 10.0 — full ' +
      'remote impersonation, no authentication required beyond SCIM ' +
      'client access. Affected versions 12.0.0–12.2.1; patched ' +
      '2025-11. Pattern is broader than Grafana: any SCIM server that ' +
      'uses externalId for internal mapping has the same shape.',
    impact:
      'Maximum-severity privilege escalation when externalId is ' +
      'naively trusted. Defences: (1) treat externalId as opaque — ' +
      'never use it as an authoritative identifier internally; (2) ' +
      'reject externalId values that are syntactically internal IDs ' +
      '(numeric where IDs are numeric, UUID-formatted where IDs are ' +
      'UUIDs); (3) audit how externalId flows through your provisioning ' +
      'code path — anywhere it ends up in a database column other than ' +
      'a dedicated `external_id` field is a finding.',
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
        label: 'RFC 7643 §3.1 (externalId)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-3.1',
      },
    ],
  },

  id: {
    purpose:
      'Server-assigned, immutable, globally-unique identifier for a ' +
      'SCIM resource. Returned in the `Location` header on create. The ' +
      'authoritative key for a resource — every subsequent operation ' +
      'targets the resource via `/Users/{id}` URL path.',
    withoutIt:
      'IDOR (Insecure Direct Object Reference) is the canonical risk: ' +
      'allowing the caller to influence which `id` is operated on by ' +
      'reading the `id` from request *body* rather than the URL path.',
    attack:
      'Body-vs-URL ID override (Keycloak SCIM PUT IDOR, GitHub issue ' +
      '#46658). The handler reads `/Users/{id-A}` from the URL to check ' +
      'authorization ("can the caller modify resource A?") but then ' +
      'reads the `id` field from the request body and updates resource ' +
      'B. Mallory has permission for her own user A but crafts a PUT ' +
      'with `id: "<admin-id>"` in the body — server authorizes against ' +
      'A, modifies admin. SCIM\'s structure (id appears in both URL and ' +
      'body) makes this mistake easy to miss in code review.',
    impact:
      'Cross-resource modification with bypassed authorization. ' +
      'Defences: (1) authorize against the URL-path id; (2) ignore body ' +
      '`id` fields entirely on PUT/PATCH (RFC 7643 §3.1: id is ' +
      'read-only); (3) reject requests where body `id` differs from ' +
      'URL-path id with 400 Bad Request.',
    references: [
      {
        label: 'Keycloak Issue #46658 (SCIM PUT IDOR)',
        href: 'https://github.com/keycloak/keycloak/issues/46658',
      },
      {
        label: 'RFC 7643 §3.1 (id is server-assigned and immutable)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-3.1',
      },
    ],
  },

  op: {
    purpose:
      'PATCH operation type: `add` (insert/append), `replace` (overwrite), ' +
      '`remove` (delete). One of three operations applied at a JSON ' +
      'Pointer `path` on a target resource. SCIM PATCH wraps these in a ' +
      'PatchOp document with multiple operations applied transactionally.',
    withoutIt:
      'Each `op` value has different authorization requirements. SCIM ' +
      'servers that authorize at "can the caller PATCH this resource at ' +
      'all?" granularity but not at "can they replace `groups`?" level ' +
      'allow privilege escalation through legitimate-looking PATCHes.',
    attack:
      'PATCH op-specific privilege escalation. Mallory has SCIM client ' +
      'access scoped to "manage user profile fields" (intended: name, ' +
      'email). She crafts a PATCH with ' +
      '`op=add, path=groups, value=[{value: "admins"}]` — adding herself ' +
      'to a privileged group. The SCIM server authorizes the PATCH as a ' +
      'profile update because the *resource* is a user profile, missing ' +
      'that the *attribute path* `groups` is privilege-relevant. ' +
      'Variant: `op=replace, path=active, value=true` to reactivate a ' +
      'disabled account.',
    impact:
      'Privilege escalation via attribute-path-aware authorization gap. ' +
      'Defences: (1) authorization MUST be per-attribute, not per-' +
      'resource; (2) maintain an allowlist of paths each caller may ' +
      'modify; (3) treat `groups`, `active`, `roles`, ' +
      '`entitlements`, anything role-relevant as security-critical paths ' +
      'requiring elevated permission.',
    references: [
      {
        label: 'RFC 7644 §3.5.2 (PatchOp)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
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
    withoutIt:
      'Without strict path validation, attackers craft paths that reach ' +
      'attributes the caller has no business modifying. SCIM\'s nested-' +
      'attribute syntax (filters within paths) lets a single PATCH ' +
      'operation surgically modify deeply-nested resource state.',
    attack:
      'PATCH path traversal to admin-relevant attributes. Mallory\'s ' +
      'authorization is "edit own profile". She crafts PATCH paths ' +
      'targeting attributes outside her permitted set: ' +
      '`groups[display eq "Administrators"]`, `meta.resourceType`, ' +
      'extension-schema attributes that map to backend role assignments. ' +
      'Sloppy SCIM servers parse the path and execute the operation ' +
      'without checking whether the *attribute* is in the caller\'s ' +
      'permitted set. Variant: empty / null path (`{op: "replace", ' +
      'value: <whole resource>}`) replaces the entire resource — used ' +
      'in some SCIM implementations as a backdoor for full-resource ' +
      'updates that bypass per-attribute checks.',
    impact:
      'Attribute-level privilege escalation. Defences: (1) parse and ' +
      'normalize paths into structured form before authorization; ' +
      '(2) authorize against the resolved attribute, not the raw path ' +
      'string; (3) reject empty/null paths in PATCH operations unless ' +
      'the caller has full-resource write permission; (4) validate ' +
      'against the resource schema — paths to undefined attributes ' +
      'should 400.',
    references: [
      {
        label: 'RFC 7644 §3.5.2 (path attribute)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
      },
    ],
  },

  value: {
    purpose:
      'The data carried by the PATCH operation: scalar for simple ' +
      'attributes, object/array for complex/multi-valued attributes, ' +
      'omitted for `remove`. Type-checked against the schema definition ' +
      'of the attribute named by `path`.',
    withoutIt:
      'Without strict schema-bound type validation, callers can submit ' +
      '`value` content that exploits the SP\'s downstream processing — ' +
      'classic injection territory whenever SCIM data flows into ' +
      'queries, log entries, email templates, or rendered HTML.',
    attack:
      'Stored-XSS or template injection via SCIM `value`. The SCIM ' +
      'client provisions a user with `displayName: "<script>...</' +
      'script>"`. The SP stores it and later renders the displayName ' +
      'unsanitised in an admin UI — every admin viewing the user list ' +
      'executes the attacker\'s script. Variant: log-injection via ' +
      'newline-bearing values that forge log entries; SQL/NoSQL ' +
      'injection if `value` is concatenated into a query for downstream ' +
      'storage.',
    impact:
      'Standard injection-class attacks scaled across the user base ' +
      '(every provisioned user can carry a payload). Defences: enforce ' +
      'SCIM schema constraints on every attribute (string length, ' +
      'pattern, enum) at write time; sanitise/escape on render; never ' +
      'use SCIM data directly in shell, SQL, LDAP, or template ' +
      'expressions without context-appropriate escaping.',
    references: [
      {
        label: 'RFC 7644 §3.5.2 (value attribute)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2',
      },
    ],
  },

  filter: {
    purpose:
      'SCIM\'s SQL-like query language for resource search: ' +
      '`userName eq "alice"`, `emails.type eq "work" and active eq true`, ' +
      '`name.familyName sw "Smi"`. Operators include `eq`, `ne`, `co`, ' +
      '`sw`, `ew`, `pr`, `gt`, `ge`, `lt`, `le`, plus logical `and`, ' +
      '`or`, `not`. Carried in URL query string on GET, embedded in ' +
      'PATCH paths, and used in bulk operations.',
    withoutIt:
      'SCIM filters are user input that translates to backend storage ' +
      'queries. Without proper translation, the filter language becomes ' +
      'an injection vehicle into the underlying database — SQL injection ' +
      'if the SCIM layer concatenates filter text into SQL, NoSQL ' +
      'injection if into MongoDB query objects, LDAP injection if into ' +
      'LDAP search filters.',
    attack:
      'SCIM filter → backend query injection. Filter text ' +
      '`userName eq "alice"` should compile to a parameterized backend ' +
      'query. Hand-rolled SCIM implementations sometimes string-' +
      'concatenate the filter into SQL: `SELECT * FROM users WHERE ' +
      'userName = "alice"`. Mallory submits ' +
      '`?filter=userName eq "alice" or 1=1 --"` and the resulting SQL ' +
      'becomes `WHERE userName = "alice" or 1=1 --"`, returning every ' +
      'user. Variant for NoSQL: `?filter=userName eq {"$ne":""}` if ' +
      'the SCIM layer JSON-decodes filter fragments. Variant for LDAP: ' +
      'filter values containing `*)(uid=*` confuse LDAP query parsers.',
    impact:
      'Mass user enumeration → potential bulk modification if the ' +
      'injection works on PATCH-via-filter operations. Defences: (1) ' +
      'parse the SCIM filter into a typed AST; (2) translate the AST to ' +
      'parameterized backend queries — never string-concatenate filter ' +
      'text into SQL/LDAP/Mongo; (3) impose hard rate limits on filtered ' +
      'GETs; (4) when filters embed in PATCH paths, apply the same ' +
      'parsing and validation.',
    references: [
      {
        label: 'RFC 7644 §3.4.2.2 (Filtering)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.2.2',
      },
      {
        label: 'OWASP — LDAP Injection Prevention',
        href: 'https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html',
      },
    ],
  },

  active: {
    purpose:
      'Boolean attribute on a User resource indicating whether the ' +
      'account is enabled. The IdP\'s SCIM client typically toggles ' +
      '`active=false` to deactivate users on offboarding, and the SP ' +
      'is expected to enforce that flag at sign-in / API access time.',
    withoutIt:
      'Two failure modes: (1) **Deactivation race** — the SCIM PATCH ' +
      'completes (returns 200) but propagation to the auth-enforcement ' +
      'layer (session store, cached permissions) is delayed; the user ' +
      'has a window to authenticate even after de-provisioning; (2) ' +
      '**Re-activation via PATCH** — same auth-relevant attribute the ' +
      '`op` entry warned about, used to bypass admin de-provisioning.',
    attack:
      'IdP-de-provisioning bypass via SP session lag. Alice is fired. ' +
      'IdP issues SCIM PATCH `active=false` to the SP at 09:00. SP ' +
      'updates its user record at 09:00:01 but does NOT invalidate ' +
      'Alice\'s active sessions, refresh tokens, or API keys. Alice (or ' +
      'someone with her credentials) continues using the SP for hours ' +
      'or days until the existing tokens naturally expire. Variant: SP ' +
      'caches the `active` flag in a denormalised join table updated ' +
      'asynchronously; the cached value lags behind the SCIM update.',
    impact:
      'Persistent access despite de-provisioning. Defences: SCIM ' +
      '`active=false` MUST trigger session/token revocation — not just ' +
      'a database flag flip. Refresh tokens, API keys, downstream ' +
      'service sessions all need invalidation. Alert on PATCH ops ' +
      'modifying `active` for unexpected escalation patterns ' +
      '(reactivation of recently-deactivated users).',
    references: [
      {
        label: 'RFC 7643 §4.1.1 (active attribute)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.1',
      },
    ],
  },

  bulkId: {
    purpose:
      'Caller-supplied placeholder identifier within a Bulk request. ' +
      'Lets a single bulk operation reference resources created by ' +
      '*earlier* operations in the same bulk: operation 1 creates a ' +
      'group with `bulkId="g1"`, operation 2 adds a member referring to ' +
      '`bulkId:g1` — the server resolves it to the actual id once ' +
      'operation 1 completes.',
    withoutIt:
      'Two specific failure modes around bulkId resolution: (1) ' +
      '**Circular references** — operation A references bulkId B, ' +
      'operation B references bulkId A; servers without cycle detection ' +
      'enter infinite-resolve loops. (2) **bulkId forgery** — caller ' +
      'submits a bulkId-style reference that wasn\'t actually defined ' +
      'in the bulk; server tries to resolve and either fails or, ' +
      'depending on implementation, leaks information about which IDs ' +
      'exist.',
    attack:
      'Bulk-ID-driven information disclosure / resource creation race. ' +
      'Mallory submits a bulk request that creates a user with ' +
      '`bulkId="probe"` then attempts to read user ' +
      '`bulkId:<guess-of-internal-id-format>`. Servers that don\'t ' +
      'strictly validate bulkId references (per the SCIM-SDK pattern of ' +
      'returning 409 on circular and 400 on self-reference) may leak ' +
      'whether internal IDs follow predictable patterns, enabling ' +
      'enumeration. Self-reference attack: operation references its own ' +
      'bulkId — without explicit rejection (per SCIM-SDK\'s "invalidValue" ' +
      'response), the server may end up creating a resource that ' +
      'references itself with consequences the schema didn\'t anticipate.',
    impact:
      'Mostly information disclosure and DoS via cycle detection ' +
      'failures. Defences: (1) strictly validate every bulkId reference ' +
      'is defined within the same bulk request; (2) reject circular ' +
      'references with 409; (3) reject self-references with 400 ' +
      'invalidValue; (4) cap bulk request size (`failOnErrors` and ' +
      'overall operation count limits).',
    references: [
      {
        label: 'RFC 7644 §3.7 (Bulk Operations)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.7',
      },
      {
        label: 'SCIM-SDK BulkId Reference Resolving (cycle detection)',
        href: 'https://github.com/Captain-P-Goldfish/SCIM-SDK/wiki/BulkId-reference-resolving',
      },
    ],
  },

  members: {
    purpose:
      'Multi-valued attribute on a Group resource listing User IDs (or ' +
      'nested Group IDs) belonging to the group. Typically updated via ' +
      'PATCH operations on the path `members` (add/remove). Group ' +
      'membership is the standard SCIM mechanism for role assignment.',
    withoutIt:
      '`members` is the privilege-bearing attribute on Groups. Every ' +
      'PATCH that touches `members` is potentially a role assignment ' +
      'change — and SCIM authorization that doesn\'t treat `members` ' +
      'specially lets group manipulation slip through generic ' +
      '"can-modify-Groups" checks.',
    attack:
      'Group-membership privilege escalation (Keycloak SCIM-class ' +
      'vulnerability per 2025 SOC Prime advisory). Mallory has SCIM ' +
      'client permission to create or modify Group resources for some ' +
      'legitimate purpose (managing project teams). She PATCHes the ' +
      '`Administrators` group with `op=add, path=members, ' +
      'value=[{value: "<own-user-id>"}]` — adding herself. The SCIM ' +
      'server authorizes the PATCH because the *resource* (Group ' +
      'Administrators) is in her writable set; it doesn\'t check that ' +
      'modifying *that specific group\'s members* requires elevated ' +
      'authority. She now has admin role through group membership.',
    impact:
      'Privilege escalation through group manipulation. Defences: (1) ' +
      'treat privileged groups (admin, root, owner, etc.) as restricted ' +
      'resources requiring elevated SCIM client authority to modify; ' +
      '(2) authorize on the *combination* of resource, attribute, AND ' +
      'specific value — adding to Administrators is not the same ' +
      'authorization as adding to ProjectTeamA; (3) audit every ' +
      '`members` PATCH that touches privileged groups.',
    references: [
      {
        label: 'RFC 7643 §4.2 (Group Schema)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7643#section-4.2',
      },
      {
        label: 'SOC Prime — SCIM PATCH escalation (related class)',
        href: 'https://socprime.com/blog/cve-2025-41115-vulnerability/',
      },
    ],
  },

  attributes: {
    purpose:
      'Query parameter on GET requests selecting which attributes to ' +
      'return in the response (projection). Sibling `excludedAttributes` ' +
      'inverts the selection. Lets clients reduce payload size and ' +
      'limit data exposure.',
    withoutIt:
      'Two opposing failure modes: (1) **Projection ignored** — server ' +
      'returns full resources regardless of `attributes`, leaking ' +
      'attributes the caller didn\'t need (and may not have been ' +
      'authorized for); (2) **Projection trusted for authorization** — ' +
      'server uses `attributes` to decide what to *check authorization ' +
      'on* rather than what to return, so excluding sensitive attributes ' +
      'from the projection bypasses the check entirely.',
    attack:
      'Authorization bypass via attribute exclusion. Server logic: ' +
      '"return user record, but only check `groups` ACL if `groups` is ' +
      'in the requested `attributes`". Mallory requests ' +
      '`GET /Users/{id}?attributes=name,email` — no `groups` requested, ' +
      'so no `groups` ACL check, and the response also returns the ' +
      'lighter projection. But the ACL was the gating control; without ' +
      'it, even non-privileged callers receive responses on resources ' +
      'they shouldn\'t see at all. Variant: `excludedAttributes=groups` ' +
      'with the same effect.',
    impact:
      'Authorization-control bypass via projection abuse. Defences: ' +
      '(1) enforce resource-level authorization independent of ' +
      'projection (does the caller have GET permission on this user ' +
      'at all?); (2) treat `attributes` strictly as a response-shaping ' +
      'hint, never as input to authorization decisions; (3) attribute-' +
      'level authorization filters the response *after* the resource-' +
      'level check passes.',
    references: [
      {
        label: 'RFC 7644 §3.9 (attributes / excludedAttributes)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.9',
      },
    ],
  },

  ETag: {
    purpose:
      'Resource version identifier returned in the ETag response header ' +
      'and stored in `meta.version`. Clients send it back via ' +
      '`If-Match` / `If-None-Match` request headers to detect concurrent ' +
      'modifications. SCIM\'s optimistic-concurrency-control mechanism.',
    withoutIt:
      'Without ETag enforcement, two concurrent PATCH operations on ' +
      'the same resource race: the second write silently overwrites ' +
      'the first. For security-relevant attributes (`active`, ' +
      '`groups`), this is a real attack window when the operations ' +
      'have opposing intent.',
    attack:
      'Concurrent-PATCH race on `active` toggle. Admin Bob initiates ' +
      'PATCH `active=false` to lock Mallory\'s account at 12:00:00.000. ' +
      'Mallory, knowing she\'s about to be locked out, simultaneously ' +
      'initiates PATCH `active=true` (perhaps via stolen SCIM client ' +
      'credentials with self-management scope). Without ETag/If-Match, ' +
      'the second operation to land wins regardless of which started ' +
      'first. Variant: an inconsistent set of concurrent writes leaves ' +
      'the resource in a partial state (Bob\'s deactivation completes ' +
      'but Mallory\'s group-membership-add to `Administrators` lands ' +
      'after — inactive admin account that gets reactivated on ' +
      'next legitimate PATCH).',
    impact:
      'Lost-update class of race conditions on security-relevant ' +
      'state. Defences: (1) require `If-Match` on PATCH/PUT for ' +
      'security-critical attributes (`active`, `groups`, ' +
      '`entitlements`); (2) reject 412 Precondition Failed on ETag ' +
      'mismatch; (3) when the SCIM client retries on 412, the ' +
      'application logic must re-evaluate the desired state against ' +
      'the new server state — naive retry-with-same-payload re-' +
      'introduces the race.',
    references: [
      {
        label: 'RFC 7644 §3.14 (ETag / If-Match)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7644#section-3.14',
      },
    ],
  },
}
