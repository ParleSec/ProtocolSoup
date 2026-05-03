/**
 * SPIFFE / SPIRE — Parameter Explainers
 *
 * Workload identity. Different threat model from human-auth protocols:
 * the user is a process, the credentials are X.509 certificates or JWTs
 * (SVIDs), trust is anchored in trust domains rooted at signing CAs,
 * and attestation (proving "what process this is") is the central
 * primitive — not human authentication.
 */

import type { ParameterExplainer } from './index'

export const SPIFFE_EXPLAINERS: Record<string, ParameterExplainer> = {
  spiffe_id: {
    purpose:
      'A SPIFFE Verifiable Identity Document (SVID) names a workload via ' +
      'a URI: `spiffe://trust-domain/path`. The trust domain (authority) ' +
      'identifies the issuing SPIRE deployment; the path identifies the ' +
      'specific workload within it. Carried in the URI SAN of an X.509-' +
      'SVID or in the `sub` claim of a JWT-SVID.',
    withoutIt:
      'Two failure classes around SPIFFE ID parsing and authorization: ' +
      '(1) **URI SAN ambiguity** — a certificate may technically have ' +
      'multiple URI SANs; SPIFFE spec says exactly one MUST be a SPIFFE ' +
      'ID, but lax parsers accept the first match anywhere. (2) ' +
      '**Authorization-by-prefix** — checking only `spiffe://prod-domain/` ' +
      'as a prefix lets `spiffe://prod-domain/anyone` pass when policy ' +
      'meant `spiffe://prod-domain/specific-service`.',
    attack:
      'Multi-URI-SAN smuggling. Mallory obtains a legitimate certificate ' +
      'for some innocuous workload, but at issuance she gets the CA to ' +
      'include both her real SPIFFE ID and a higher-privilege one she ' +
      'wants to impersonate (CA hardening prevents this in SPIRE itself, ' +
      'but bridge implementations and home-grown CAs are looser). The ' +
      'verifier reads "the first URI SAN" and gets her chosen target. ' +
      'Defence: SPIFFE spec MANDATES exactly one URI SAN must be a SPIFFE ' +
      'ID and that\'s the one to use; reject certs with multiple URI ' +
      'SANs that match `spiffe://*`.',
    impact:
      'Identity confusion → unauthorized service-to-service access. ' +
      'Authorization MUST match by full SPIFFE ID, not by trust-domain ' +
      'prefix unless trust-domain-wide access is genuinely intended. ' +
      'Use `(trust_domain, path)` as the composite key — never the path ' +
      'alone.',
    references: [
      {
        label: 'SPIFFE ID specification',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md',
      },
      {
        label: 'SPIFFE X.509-SVID §2 (URI SAN)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md',
      },
    ],
  },

  trust_domain: {
    purpose:
      'The authority component of a SPIFFE ID — names the SPIRE ' +
      'deployment (one per organisational unit, environment, or security ' +
      'boundary). All SVIDs in a trust domain are signed by CAs rooted in ' +
      'that domain\'s trust bundle. The trust domain IS the cryptographic ' +
      'security boundary in SPIFFE.',
    withoutIt:
      'If a verifier accepts SVIDs from any trust domain it has bundles ' +
      'for (without checking *which* trust domain the SVID is from), an ' +
      'SVID minted in one trust domain can authorize actions intended ' +
      'only for another. This is the workload-identity counterpart of ' +
      'cross-tenant attacks in human-identity protocols: the ' +
      'cryptography is fine; the failure is loose authorization scope.',
    attack:
      'Trust domain spoofing in federations. The verifier has both ' +
      '`spiffe://prod.example` and `spiffe://test.example` trust bundles ' +
      'configured for federation. A workload in `test.example` (where ' +
      'admin access is broad and registration loose) gets an SVID for ' +
      '`spiffe://test.example/superuser`. Without strict trust-domain ' +
      'binding in the verifier\'s policy, the test-domain SVID is ' +
      'accepted as if it had come from prod. Authorization rules MUST ' +
      'name the expected trust domain, not just the path.',
    impact:
      'Cross-trust-domain authorization bleed. Defence: every authz ' +
      'check matches the full SPIFFE ID (including trust domain); ' +
      'federation should be limited to the minimum cross-domain trust ' +
      'actually required. Treat each trust domain as a separate security ' +
      'principal even when federating — they are not equivalent.',
    references: [
      {
        label: 'SPIFFE Trust Domain and Bundle spec',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md',
      },
    ],
  },

  selectors: {
    purpose:
      'Workload attributes the SPIRE Agent collects via OS introspection ' +
      'to identify a calling process: `unix:uid:1000`, `unix:path:/usr/' +
      'bin/myapp`, `docker:label:app:myapp`, `k8s:ns:default`, ' +
      '`k8s:sa:default`, `k8s:pod-name:myapp-7d8c`. Registration entries ' +
      'are matched by selector subset — entry selectors must all be ' +
      'present in the workload\'s collected selectors.',
    withoutIt:
      'Selectors are *only as trustworthy as the OS/container runtime ' +
      'reporting them*. Two failure classes: (1) **Spoofable selectors** ' +
      '— Kubernetes node-name is easy to spoof if the agent SVID is ' +
      'stolen; pod label selectors trust whoever can write to the pod ' +
      'spec; (2) **Over-broad selectors** — `unix:uid:0` matches every ' +
      'root process on the node, including any that the attacker can ' +
      'spawn.',
    attack:
      'Selector spoofing via container compromise. Mallory compromises ' +
      'one container on a Kubernetes node — say, via a vulnerable ' +
      'sidecar. She launches a process inside that container matching ' +
      'the high-privilege workload\'s selectors (same `unix:path`, ' +
      'forged `docker:label`s by manipulating the container labels). ' +
      'The SPIRE Agent\'s introspection reports the spoofed values to ' +
      'the workload-attestation step; the registration entry matches; ' +
      'and Mallory\'s process is issued an SVID for the legitimate ' +
      'workload. Variant: rogue agent registration via compromised ' +
      'Kubernetes API server → fake service-account tokens → bogus ' +
      'agent → arbitrary workload SVIDs on that "node".',
    impact:
      'Workload identity spoofing within a node. Defences: (1) use ' +
      'attestor-specific selectors that the runtime cannot forge from ' +
      'within a container (cgroup paths verified by the kernel; SHA-256 ' +
      'binary checksums; TPM-backed measurements where available); (2) ' +
      'enforce selector specificity — `unix:uid:1000` alone is too ' +
      'broad; combine with `unix:path:/usr/bin/myapp` AND ' +
      '`unix:sha256:abc…`; (3) protect the SPIRE Agent\'s identity ' +
      'aggressively — node compromise = all-workloads-on-that-node ' +
      'compromise.',
    references: [
      {
        label: 'SPIRE Concepts — Workload Attestation',
        href: 'https://spiffe.io/docs/latest/spire-about/spire-concepts/',
      },
      {
        label: 'SPIRE Agent attestor plugins',
        href: 'https://github.com/spiffe/spire/tree/main/pkg/agent/plugin/workloadattestor',
      },
    ],
  },

  parent_id: {
    purpose:
      'On a registration entry, names the SPIRE Agent (or an upstream ' +
      'workload, in nested deployments) authorized to issue this SVID. ' +
      'Restricts the entry: only the named parent\'s agent can produce ' +
      'matching SVIDs. Pivotal for the agent-as-trusted-attestor model.',
    withoutIt:
      'Without `parent_id` constraints, every agent in the trust domain ' +
      'can issue every SVID — collapsing the per-node isolation that ' +
      'limits blast radius after agent compromise.',
    attack:
      'Lateral movement after agent compromise. Mallory roots one node ' +
      'in the cluster and obtains its SPIRE Agent\'s SVID. With ' +
      '`parent_id` properly scoped, that agent can only issue SVIDs for ' +
      'workloads registered with `parent_id` matching that specific ' +
      'agent — typically just the workloads scheduled to that one node. ' +
      'Without `parent_id` scoping (e.g. registrations using a wildcard ' +
      'parent), Mallory\'s compromised agent can issue SVIDs for *any* ' +
      'workload anywhere in the trust domain.',
    impact:
      'Agent compromise = full trust-domain compromise without parent_id ' +
      'scoping; agent compromise = single-node compromise with proper ' +
      'scoping. Always set `parent_id` to a specific agent or specific ' +
      'pre-registered ancestor; do not use wildcard or trust-domain-wide ' +
      'parent IDs in production.',
    references: [
      {
        label: 'SPIRE Registering Workloads — parent_id',
        href: 'https://spiffe.io/docs/latest/deploying/registering/',
      },
    ],
  },

  csr: {
    purpose:
      'Certificate Signing Request submitted by the agent (on behalf of ' +
      'a workload) to the SPIRE Server. Contains the workload\'s public ' +
      'key. The CSR\'s Subject and SAN fields are *advisory* — the ' +
      'server sets the actual SPIFFE ID from the registration entry, ' +
      'NOT from the CSR.',
    withoutIt:
      'The defining property of SPIFFE\'s CSR handling is that the *CSR ' +
      'cannot influence the issued identity*. The server discards Subject/' +
      'SAN fields the workload tries to put in the CSR and uses the ' +
      'registration entry\'s SPIFFE ID instead. Implementations that ' +
      'honour CSR-supplied SANs become identity-forgery primitives.',
    attack:
      'CSR-driven identity forgery (against weak implementations only). ' +
      'A non-conformant SPIRE-clone or bridge CA reads the URI SAN from ' +
      'the workload\'s CSR and includes it in the issued cert. Mallory\'s ' +
      'compromised workload submits a CSR claiming `spiffe://domain/' +
      'admin` and gets a cert with that identity, bypassing the ' +
      'registration entry mechanism entirely. SPIRE itself does not have ' +
      'this bug; downstream CAs and integrations sometimes do.',
    impact:
      'Identity forgery via CSR field trust. Defences: SPIRE Server ' +
      '(and any CA acting in this role) MUST ignore Subject/SAN fields ' +
      'in the CSR and synthesize them from the registration entry. ' +
      'Audit: run a workload that submits a CSR with bogus URI SAN and ' +
      'verify the issued cert has the *registered* identity, not the ' +
      'requested one.',
    references: [
      {
        label: 'SPIFFE X.509-SVID §3 (Issuance)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md',
      },
    ],
  },

  uri_san: {
    purpose:
      'The URI Subject Alternative Name in an X.509-SVID where the SPIFFE ' +
      'ID is encoded. SPIFFE spec: exactly ONE URI SAN MUST be a valid ' +
      'SPIFFE ID; certs MAY have other (non-SPIFFE) URI SANs but the ' +
      'verifier MUST identify the SPIFFE one as the authoritative identity.',
    withoutIt:
      'Multi-URI-SAN parsing is the gap. A naive verifier that takes ' +
      '"the first URI SAN" or "any URI SAN starting with spiffe://" can ' +
      'be fooled by certs with multiple SPIFFE-shaped URI SANs.',
    attack:
      'Multi-URI-SAN attack. A misbehaving CA (or a SPIRE clone bridging ' +
      'to legacy PKI) issues a cert with two URI SANs: ' +
      '`spiffe://domain/innocent-service` (the legitimate one Mallory ' +
      'is registered for) and `spiffe://domain/admin-service` (her ' +
      'target). A naive verifier that iterates URI SANs and stops at the ' +
      'first SPIFFE-shaped match returns whichever comes first — and ' +
      'Mallory crafts the cert order to put the privileged ID first.',
    impact:
      'Identity confusion. Defences: count SPIFFE-shaped URI SANs; ' +
      'reject certs with more than one. Use SPIFFE\'s reference parsing ' +
      'libraries (go-spiffe, spiffe-rs) which enforce this rule. Do NOT ' +
      'hand-roll certificate-to-SPIFFE-ID parsing.',
    references: [
      {
        label: 'SPIFFE X.509-SVID §2 (URI SAN constraints)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md',
      },
    ],
  },

  trust_bundle: {
    purpose:
      'The set of root CA certificates for a trust domain. Verifiers ' +
      'use it to validate the certificate chain on incoming SVIDs. ' +
      'Distributed by the SPIRE Server to all agents (which deliver to ' +
      'workloads via the Workload API) — and to any external verifier ' +
      'that needs to authenticate workloads in this trust domain.',
    withoutIt:
      'Two failure modes: (1) **Stale bundle** — CA rotation happened ' +
      'but the verifier\'s cache has not refreshed; new SVIDs fail to ' +
      'verify, breaking service-to-service auth (availability impact). ' +
      '(2) **Tampered bundle** — verifier loaded a bundle that includes ' +
      'attacker-controlled CA roots; SVIDs the attacker minted now ' +
      'verify as legitimate.',
    attack:
      'Bundle tampering at distribution time. Mallory has compromised ' +
      'the storage backing a verifier\'s trust bundle cache (a Kubernetes ' +
      'ConfigMap, a file on disk, an environment variable supplying a ' +
      'PEM bundle). She adds her own self-signed CA to the bundle. The ' +
      'verifier now trusts SVIDs Mallory mints with that CA — full ' +
      'identity forgery within the trust domain (from the verifier\'s ' +
      'perspective).',
    impact:
      'Trust subversion at the trust-bundle layer. Defences: deliver ' +
      'bundles via the Workload API (not file-system distribution); ' +
      'protect the storage path / ConfigMap with appropriate RBAC; ' +
      'verify bundle freshness against the SPIRE Server periodically; ' +
      'consider using bundle endpoints with mTLS authentication for ' +
      'external verifiers.',
    references: [
      {
        label: 'SPIFFE Trust Domain and Bundle §4',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md',
      },
    ],
  },

  federated_bundles: {
    purpose:
      'Trust bundles for *foreign* trust domains, fetched via federation ' +
      'and used to validate SVIDs from those domains. Each entry maps ' +
      '`trust_domain → root_cas`. Distributed alongside the local trust ' +
      'bundle to workloads that participate in cross-domain ' +
      'communication.',
    withoutIt:
      'Federation extends trust beyond the local domain — every additional ' +
      'federated bundle is an additional set of CAs that can mint SVIDs ' +
      'the local verifier will accept. A single compromised foreign ' +
      'bundle endpoint compromises every workload that consumes its ' +
      'output.',
    attack:
      'Federation chain compromise. Trust domain A federates with B; B ' +
      'federates with C. Mallory compromises C\'s bundle endpoint and ' +
      'starts publishing her own CA in C\'s bundle. B fetches it (B ' +
      'trusts C\'s endpoint), then B redistributes the federated bundle. ' +
      'A fetches B\'s redistributed view (A trusts B), and now A\'s ' +
      'workloads trust SVIDs that Mallory minted from C\'s "compromised" ' +
      'CA — even though A and C have no direct relationship. Per the ' +
      'SPIFFE Federation spec: "compromise of a trust domain or bundle ' +
      'endpoint server in the chain would result in the compromise of ' +
      'the next trust domain."',
    impact:
      'Cascading trust compromise across federation chains. Defences: ' +
      'minimise federation depth (avoid B-trusts-C-trusts-D chains; ' +
      'establish direct relationships); use `https_spiffe` profile for ' +
      'bundle endpoints (mTLS, not Web PKI); monitor federated bundle ' +
      'changes and alert on unexpected CA additions; treat federated ' +
      'trust domains with the same scrutiny as direct ones.',
    references: [
      {
        label: 'SPIFFE Federation spec',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md',
      },
    ],
  },

  bundle_endpoint_url: {
    purpose:
      'URL the local SPIRE Server fetches to obtain a foreign trust ' +
      'domain\'s bundle. Standard path is `/.well-known/spiffe-bundle` ' +
      'on the foreign SPIRE Server but custom URLs are supported. The ' +
      'choice of `endpoint_profile` (`https_spiffe` vs `https_web`) ' +
      'determines how this URL\'s authenticity is verified.',
    withoutIt:
      'The bundle endpoint URL itself is sensitive configuration. Per ' +
      'SPIFFE Federation spec: "Compromise of the configuration of a ' +
      'federation relationship can weaken or completely break security ' +
      'guarantees." URL tampering with `https_web` profile lets an ' +
      'attacker issue fraudulent keys and impersonate any identity in ' +
      'the corresponding trust domain.',
    attack:
      'Endpoint URL substitution. Mallory has write access to the SPIRE ' +
      'Server\'s federation configuration (via compromised Kubernetes ' +
      'ConfigMap, leaked admin credentials, etc.). She changes ' +
      '`bundle_endpoint_url` for `partner.example.com` from ' +
      '`https://spire.partner.example.com:8443/bundle` to ' +
      '`https://attacker.example.com/fake-bundle`. With `https_web` ' +
      'profile, the SPIRE Server fetches the fake bundle (TLS valid for ' +
      'attacker domain), trusts the attacker\'s CA, and from this point ' +
      'forward every SVID minted by the attacker is accepted as if it ' +
      'were a legitimate `partner.example.com` workload.',
    impact:
      'Total federation compromise via configuration tampering. ' +
      'Defences: (1) use `https_spiffe` endpoint_profile — the bundle ' +
      'endpoint server must present a SPIFFE SVID matching ' +
      '`endpoint_spiffe_id`, which the attacker cannot forge without ' +
      'compromising the foreign trust domain; (2) protect federation ' +
      'configuration storage with strict RBAC; (3) audit federation ' +
      'config changes; (4) pin endpoint URLs against tampering at the ' +
      'configuration layer.',
    references: [
      {
        label: 'SPIFFE Federation §5 (Bundle Endpoint Distribution)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md',
      },
    ],
  },

  endpoint_profile: {
    purpose:
      'Authentication profile for the bundle endpoint: `https_spiffe` ' +
      '(the foreign SPIRE Server presents a SPIFFE SVID; mTLS) or ' +
      '`https_web` (Web PKI TLS — the foreign endpoint presents a cert ' +
      'from a public CA chain). `https_spiffe` is the secure choice; ' +
      '`https_web` is provided for bootstrapping / cross-organization ' +
      'cases where SPIFFE identities are not yet exchanged.',
    withoutIt:
      '`https_web` is the gap. It anchors federation trust in Web PKI — ' +
      'meaning anyone able to obtain a TLS cert for the bundle endpoint ' +
      'domain (DNS hijack, BGP attack, lax CA, abused ACME challenge) ' +
      'can serve a fake bundle and the local SPIRE Server will accept ' +
      'it.',
    attack:
      'Bundle endpoint TLS hijack. Mallory performs a BGP hijack against ' +
      '`partner.example.com`\'s IP space, obtains a Let\'s Encrypt cert ' +
      'for it via HTTP-01 challenge during the hijack, and serves a ' +
      'fake bundle from her infrastructure. The local SPIRE Server, ' +
      'configured with `endpoint_profile=https_web`, sees a TLS ' +
      'connection that validates against Web PKI roots — accepts it. ' +
      'With `https_spiffe`, the connection would have failed because ' +
      'Mallory cannot mint a partner-domain SPIFFE SVID without ' +
      'compromising partner\'s SPIRE Server.',
    impact:
      'Federation trust subversion via Web PKI weaknesses. Defences: ' +
      'use `https_spiffe` for any production federation; reserve ' +
      '`https_web` for the *initial* bundle exchange only, then switch ' +
      'to `https_spiffe` once both sides have each other\'s bundles. ' +
      'Treat any federation still on `https_web` as a configuration ' +
      'finding to remediate.',
    references: [
      {
        label: 'SPIFFE Federation §5.2 (Endpoint Profiles)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md',
      },
    ],
  },

  attestor_type: {
    purpose:
      'Plugin identifier for the node attestor: `join_token` (one-time ' +
      'bootstrap secret), `aws_iid` (AWS Instance Identity Document), ' +
      '`gcp_iit` (GCP Instance Identity Token), `azure_msi`, `k8s_psat` ' +
      '/ `k8s_sat` (Kubernetes service account token), `x509pop` (X.509 ' +
      'proof of possession), `tpm_devid` (TPM-backed). Determines what ' +
      'evidence the agent presents to prove its node identity to the ' +
      'SPIRE Server.',
    withoutIt:
      'Each attestor has a different threat model. `join_token` is the ' +
      'simplest but the weakest — it\'s a bearer secret. `aws_iid` and ' +
      'similar cloud attestors trust the cloud platform\'s identity ' +
      'document signing. `tpm_devid` is the strongest — hardware-rooted ' +
      'attestation. Picking the wrong attestor for the threat model ' +
      'produces a deployment that *looks* secure but isn\'t.',
    attack:
      'Attestor mismatch attacks: (1) **join_token in production** — ' +
      'tokens leak via terraform state files, CI logs, configuration ' +
      'management. Mallory finds an unused token and registers a rogue ' +
      'agent in the trust domain. (2) **k8s_psat on a compromised cluster** ' +
      '— if the Kubernetes API server is compromised, attacker mints ' +
      'arbitrary projected service account tokens for any namespace, ' +
      'registering rogue agents. (3) **aws_iid metadata-service hijack** ' +
      '— SSRF in a workload that lets the attacker query the AWS metadata ' +
      'service of a different EC2 instance, then submitting that IID as ' +
      'their own.',
    impact:
      'Rogue agent registration → ability to mint workload SVIDs in the ' +
      'trust domain. Defences: (1) use the strongest attestor the ' +
      'platform supports — TPM-backed where available, cloud-platform ' +
      'attestors otherwise, `join_token` only for ephemeral / bootstrap ' +
      'cases; (2) constrain attestor results — `aws_iid` agents should ' +
      'be scoped to specific account IDs and instance roles, not ' +
      'open-ended; (3) for `join_token`, use very short TTLs and ' +
      'consume-on-first-use semantics (SPIRE default).',
    references: [
      {
        label: 'SPIRE Node Attestation',
        href: 'https://spiffe.io/docs/latest/deploying/configuring/',
      },
    ],
  },

  join_token: {
    purpose:
      'Single-use bearer token the SPIRE Server administrator generates ' +
      'and provisions out-of-band onto a node. The agent presents it on ' +
      'first run; the server consumes the token and issues an agent SVID. ' +
      'Simplest node-attestation method, useful for development and ' +
      'small static deployments.',
    withoutIt:
      'A bearer secret with the same threat model as any other shared ' +
      'token: visible to anyone who can read the provisioning channel ' +
      'before consumption. Production deployments should prefer ' +
      'platform attestors (cloud or TPM) precisely because join_tokens ' +
      'are operationally fragile.',
    attack:
      'Join token theft from provisioning channels. Mallory has read ' +
      'access to a Terraform state file, a CI build log, a Slack ' +
      'channel, an email thread — anywhere the join token might appear ' +
      'before reaching the target node. She submits the token to the ' +
      'SPIRE Server before the legitimate node does. Server consumes ' +
      'the token, issues an agent SVID to Mallory\'s rogue agent. The ' +
      'legitimate node then fails to attest (token already used) — the ' +
      'failure is the only signal.',
    impact:
      'Rogue agent in the trust domain → arbitrary workload SVID issuance ' +
      'on Mallory\'s infrastructure. Defences: (1) use platform attestors ' +
      'in production, not join_token; (2) for join_token, keep TTLs ' +
      'short (minutes, not days); (3) treat token leakage as detected ' +
      'breach — rotate trust domain credentials, audit which workloads ' +
      'were issued SVIDs by the rogue agent.',
    references: [
      {
        label: 'SPIRE Server — Join Token attestor',
        href: 'https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_jointoken.md',
      },
    ],
  },

  audience: {
    purpose:
      'On a JWT-SVID issuance request, names the intended recipient of ' +
      'the token (a SPIFFE ID, URI, or arbitrary string the receiving ' +
      'service identifies as). The SPIRE Server binds this value into ' +
      'the JWT\'s `aud` claim. Verifiers MUST check that the value they ' +
      'identify as appears in `aud` before trusting the token.',
    withoutIt:
      'Two attack classes. (1) **No audience binding** — token issued ' +
      'without specific audience can be replayed at any service that ' +
      'consumes JWT-SVIDs from this trust domain. (2) **Multi-audience ' +
      'tokens** — JWT-SVIDs with multiple `aud` values can be replayed ' +
      'across audiences: a token sent to one of the listed audiences is ' +
      'reusable by that audience to impersonate the original sender at ' +
      'the other listed audiences.',
    attack:
      'Cross-audience replay (per the JWT-SVID spec\'s explicit warning). ' +
      'Alice mints a JWT-SVID with `aud=[Bob, Chuck]` and sends it to ' +
      'Chuck. Chuck now has a token that *Bob* will accept as proof of ' +
      'Alice\'s identity. Chuck replays the token to Bob; Bob sees a ' +
      'valid JWT-SVID with `aud` containing his identifier, signed by ' +
      'the trust domain CA — accepts it. Chuck has now successfully ' +
      'impersonated Alice at Bob.',
    impact:
      'Identity confusion across services. Defences: (1) request ' +
      'JWT-SVIDs with EXACTLY ONE audience, identifying the specific ' +
      'recipient; (2) verifiers MUST reject tokens missing `aud` or ' +
      'with `aud` not matching their identifier; (3) avoid the ' +
      'multi-audience pattern entirely — issue separate tokens for ' +
      'separate recipients.',
    references: [
      {
        label: 'SPIFFE JWT-SVID §3 (audience claim)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md',
      },
    ],
  },

  agent_svid: {
    purpose:
      'The X.509-SVID issued to the SPIRE Agent itself after successful ' +
      'node attestation. The agent uses it for mTLS to the SPIRE Server ' +
      'when fetching workload SVIDs and trust bundle updates. Forms the ' +
      'agent\'s identity as a "trusted attestor" for workloads on its ' +
      'node.',
    withoutIt:
      'An attacker who steals the agent SVID *and* the corresponding ' +
      'private key gets the agent\'s authority — can ask the SPIRE ' +
      'Server for any workload SVID that lists this agent as ' +
      '`parent_id`. Agent compromise = full workload-SVID issuance ' +
      'authority for that agent\'s scope.',
    attack:
      'Agent identity theft → workload SVID issuance. Mallory roots a ' +
      'node and reads the SPIRE Agent\'s on-disk SVID and private key ' +
      '(typically stored in a Kubernetes Secret or local file). She ' +
      'connects to the SPIRE Server from her own infrastructure ' +
      'presenting the stolen agent SVID, requests workload SVIDs for ' +
      'the registration entries scoped to that agent — and gets them. ' +
      'She can now run "those workloads" anywhere with full trust-' +
      'domain identity.',
    impact:
      'Lateral movement bounded by `parent_id` scoping (which is why ' +
      '`parent_id` matters — see that entry). Defences: (1) store agent ' +
      'private keys in HSM / TPM where available, not on disk; (2) ' +
      'enable agent SVID rotation with short TTLs so stolen credentials ' +
      'expire quickly; (3) monitor for agent SVID use from unexpected ' +
      'IPs (the SPIRE Server can log the source of agent connections); ' +
      '(4) minimise `parent_id` scope — never use trust-domain-wide ' +
      'parents.',
    references: [
      {
        label: 'SPIRE Concepts — Agent SVID lifecycle',
        href: 'https://spiffe.io/docs/latest/spire-about/spire-concepts/',
      },
    ],
  },

  peer_creds: {
    purpose:
      'OS-kernel-verified PID, UID, GID of the process connecting to ' +
      'the SPIRE Agent\'s Workload API socket. Obtained via SO_PEERCRED ' +
      '(Linux) or equivalent. Distinct from anything the workload could ' +
      'tell the agent — these come from the kernel.',
    withoutIt:
      'Kernel-verified PID/UID/GID is the ground truth that workload ' +
      'attestation is anchored to. *But* — PID is a small integer that ' +
      'the kernel reuses. If a process exits and its PID is recycled, ' +
      'a later process with the same PID is a different program; an ' +
      'agent that caches PID-based attestation results without ' +
      'detecting this race issues SVIDs to the wrong process.',
    attack:
      'PID-reuse race against attestation cache. Process A (legitimate, ' +
      'attested) exits. Process B (Mallory\'s, malicious) starts on the ' +
      'same node and the kernel happens to assign it Process A\'s old ' +
      'PID. A naive agent that looks up "what SPIFFE ID did PID 12345 ' +
      'attest to last time" returns Process A\'s identity to Process B. ' +
      'SPIRE\'s real defence: when the agent re-reads `/proc/{pid}/exe` ' +
      'and other process attributes, the kernel returns the *new* ' +
      'process\'s attributes (or fails if the FD became stale), so ' +
      'attestation re-runs and matches the new process\'s actual ' +
      'selectors — not the old ones.',
    impact:
      'Wrong-workload-identity issuance under PID reuse. Defences: ' +
      'agent MUST re-attest on every Workload API call (do not cache ' +
      'the attestation across calls); use process-start-time alongside ' +
      'PID for cache keying; verify the executable hasn\'t changed ' +
      'between attestation and SVID handover.',
    references: [
      {
        label: 'SPIFFE Workload API §3 (Process Identity Verification)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md',
      },
    ],
  },
}
