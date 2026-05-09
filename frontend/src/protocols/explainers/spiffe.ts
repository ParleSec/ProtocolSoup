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
      'A SPIFFE Verifiable Identity Document (SVID) names a workload via a ' +
      'URI: `spiffe://trust-domain/path`. The trust domain (authority) ' +
      'identifies the issuing SPIRE deployment; the path identifies the ' +
      'specific workload within it. Carried in the URI SAN of an X.509-SVID ' +
      'or in the `sub` claim of a JWT-SVID.',
    attacks: [
      {
        id: 'multi-uri-san-smuggling',
        name: 'Multi-URI-SAN smuggling',
        scenario:
          'X.509-SVID §2 says an SVID MUST contain exactly one URI SAN, ' +
          'and §5.2 mandates verifiers reject any cert with more than one. ' +
          'Lax verifiers — typically bridge implementations or home-grown ' +
          'CAs that treat URI SAN as just another SAN — read the first ' +
          'URI SAN they find. Mallory persuades such a CA to issue a cert ' +
          'with both her own SPIFFE ID and a higher-privilege impersonation ' +
          'target. A verifier that reads "the first URI SAN" picks ' +
          'whichever the CA emitted first.',
        impact:
          'Identity confusion → unauthorized service-to-service access.',
      },
      {
        id: 'authorization-by-prefix',
        name: 'Authorization-by-prefix',
        scenario:
          'Checking only `spiffe://prod-domain/` as a prefix lets ' +
          '`spiffe://prod-domain/anyone` pass when policy meant ' +
          '`spiffe://prod-domain/specific-service`.',
        impact:
          'Privilege escalation across workloads in the same trust domain.',
      },
    ],
    mitigations: [
      {
        action:
          'Reject any certificate with more than one URI SAN, period. ' +
          'X.509-SVID §5.2 (Leaf Validation) is explicit: an SVID MUST ' +
          'contain exactly one URI SAN; verifiers MUST reject if more ' +
          'than one is present.',
        mitigates: ['multi-uri-san-smuggling'],
      },
      {
        action:
          'Authorization MUST match by full SPIFFE ID, not by trust-domain ' +
          'prefix unless trust-domain-wide access is genuinely intended.',
        mitigates: ['authorization-by-prefix'],
      },
      {
        action:
          'Use `(trust_domain, path)` as the composite key — never the ' +
          'path alone.',
        mitigates: ['authorization-by-prefix'],
      },
    ],
    references: [
      {
        label: 'SPIFFE ID specification',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md',
      },
      {
        label: 'SPIFFE X.509-SVID §2 (SPIFFE ID)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#2-spiffe-id',
      },
      {
        label: 'SPIFFE X.509-SVID §5.2 (Leaf Validation)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#52-leaf-validation',
      },
    ],
  },

  trust_domain: {
    purpose:
      'The authority component of a SPIFFE ID — names the SPIRE deployment ' +
      '(one per organisational unit, environment, or security boundary). ' +
      'All SVIDs in a trust domain are signed by CAs rooted in that ' +
      'domain\'s trust bundle. The trust domain IS the cryptographic ' +
      'security boundary in SPIFFE.',
    attacks: [
      {
        id: 'trust-domain-spoofing',
        name: 'Trust domain spoofing in federations',
        scenario:
          'The verifier has both `spiffe://prod.example` and ' +
          '`spiffe://test.example` trust bundles configured for federation. ' +
          'A workload in `test.example` (where admin access is broad and ' +
          'registration loose) gets an SVID for ' +
          '`spiffe://test.example/superuser`. Without strict trust-domain ' +
          'binding in the verifier\'s policy, the test-domain SVID is ' +
          'accepted as if it had come from prod. The cryptography is fine; ' +
          'the failure is loose authorization scope — the workload-' +
          'identity counterpart of cross-tenant attacks in human-identity ' +
          'protocols.',
        impact:
          'Cross-trust-domain authorization bleed.',
      },
    ],
    mitigations: [
      {
        action:
          'Every authz check matches the full SPIFFE ID (including trust ' +
          'domain) — not the path alone. Authorization rules MUST name the ' +
          'expected trust domain.',
        mitigates: ['trust-domain-spoofing'],
      },
      {
        action:
          'Federation should be limited to the minimum cross-domain trust ' +
          'actually required. Treat each trust domain as a separate ' +
          'security principal even when federating — they are not ' +
          'equivalent.',
        mitigates: ['trust-domain-spoofing'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Trust Domain and Bundle spec',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md',
      },
      {
        label: 'SPIFFE Trust Domain and Bundle §6 (Security Considerations)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#6-security-considerations',
      },
    ],
  },

  selectors: {
    purpose:
      'Workload attributes the SPIRE Agent collects via OS introspection ' +
      'to identify a calling process: `unix:uid:1000`, ' +
      '`unix:path:/usr/bin/myapp`, `docker:label:app:myapp`, ' +
      '`k8s:ns:default`, `k8s:sa:default`, `k8s:pod-name:myapp-7d8c`. ' +
      'Registration entries are matched by selector subset — entry ' +
      'selectors must all be present in the workload\'s collected ' +
      'selectors. Selectors are *only as trustworthy as the OS/container ' +
      'runtime reporting them*.',
    attacks: [
      {
        id: 'selector-spoofing-container-compromise',
        name: 'Selector spoofing via container compromise',
        scenario:
          'Mallory compromises one container on a Kubernetes node — say, ' +
          'via a vulnerable sidecar. She launches a process inside that ' +
          'container matching the high-privilege workload\'s selectors ' +
          '(same `unix:path`, forged `docker:label`s by manipulating the ' +
          'container labels). The SPIRE Agent\'s introspection reports the ' +
          'spoofed values to the workload-attestation step; the ' +
          'registration entry matches; and Mallory\'s process is issued ' +
          'an SVID for the legitimate workload.',
        impact:
          'Workload identity spoofing within a node.',
      },
      {
        id: 'over-broad-selector',
        name: 'Over-broad selector matches everyone',
        scenario:
          '`unix:uid:0` matches every root process on the node, including ' +
          'any that the attacker can spawn. K8s node-name selectors are ' +
          'easy to spoof if the agent SVID is stolen; pod label selectors ' +
          'trust whoever can write to the pod spec.',
        impact:
          'Identity match too permissive — wrong workload gets the SVID.',
      },
      {
        id: 'rogue-agent-via-k8s-api',
        name: 'Rogue agent registration via compromised Kubernetes API',
        scenario:
          'The Kubernetes API server is compromised. Attacker mints fake ' +
          'service-account tokens for any namespace, registers a bogus ' +
          'agent claiming to attest some "node", and now the bogus agent ' +
          'can issue arbitrary workload SVIDs claiming to be "on that node".',
        impact:
          'Trust-domain compromise via control-plane compromise.',
      },
    ],
    mitigations: [
      {
        action:
          'Use attestor-specific selectors that the runtime cannot forge ' +
          'from within a container: cgroup paths verified by the kernel, ' +
          'SHA-256 binary checksums, TPM-backed measurements where ' +
          'available.',
        mitigates: ['selector-spoofing-container-compromise'],
      },
      {
        action:
          'Enforce selector specificity — `unix:uid:1000` alone is too ' +
          'broad. Combine with `unix:path:/usr/bin/myapp` AND ' +
          '`unix:sha256:abc…`.',
        mitigates: [
          'over-broad-selector',
          'selector-spoofing-container-compromise',
        ],
      },
      {
        action:
          'Protect the SPIRE Agent\'s identity aggressively — node ' +
          'compromise = all-workloads-on-that-node compromise.',
        mitigates: ['selector-spoofing-container-compromise'],
      },
      {
        action:
          'Restrict who can mint Kubernetes service-account tokens; ' +
          'monitor for unexpected agent registrations.',
        mitigates: ['rogue-agent-via-k8s-api'],
      },
    ],
    references: [
      {
        label: 'SPIRE Concepts — Workload Attestation',
        href: 'https://spiffe.io/docs/latest/spire-about/spire-concepts/',
      },
      {
        label: 'SPIRE Agent attestor plugins',
        href: 'https://github.com/spiffe/spire/tree/main/pkg/agent/plugin/workloadattestor',
      },
      {
        label: 'SPIFFE Workload API §4.1 (Identifying the Caller)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md#41-identifying-the-caller',
      },
    ],
  },

  parent_id: {
    purpose:
      'On a registration entry, names the SPIRE Agent (or an upstream ' +
      'workload, in nested deployments) authorized to issue this SVID. ' +
      'Restricts the entry: only the named parent\'s agent can produce ' +
      'matching SVIDs. Pivotal for the agent-as-trusted-attestor model.',
    attacks: [
      {
        id: 'lateral-movement-after-agent-compromise',
        name: 'Lateral movement after agent compromise',
        scenario:
          'Mallory roots one node in the cluster and obtains its SPIRE ' +
          'Agent\'s SVID. With `parent_id` properly scoped, that agent ' +
          'can only issue SVIDs for workloads registered with `parent_id` ' +
          'matching that specific agent — typically just the workloads ' +
          'scheduled to that one node. Without `parent_id` scoping (e.g. ' +
          'registrations using a wildcard parent), Mallory\'s compromised ' +
          'agent can issue SVIDs for *any* workload anywhere in the trust ' +
          'domain.',
        impact:
          'Without `parent_id` scoping: agent compromise = full ' +
          'trust-domain compromise. With proper scoping: agent compromise ' +
          '= single-node compromise.',
      },
    ],
    mitigations: [
      {
        action:
          'Always set `parent_id` to a specific agent or specific ' +
          'pre-registered ancestor.',
        mitigates: ['lateral-movement-after-agent-compromise'],
      },
      {
        action:
          'Do not use wildcard or trust-domain-wide parent IDs in ' +
          'production registration entries.',
        mitigates: ['lateral-movement-after-agent-compromise'],
      },
    ],
    references: [
      {
        label: 'SPIRE Registering Workloads — parent_id',
        href: 'https://spiffe.io/docs/latest/deploying/registering/',
      },
    ],
  },

  csr: {
    purpose:
      'Certificate Signing Request submitted by the agent (on behalf of a ' +
      'workload) to the SPIRE Server. Contains the workload\'s public key. ' +
      'The CSR\'s Subject and SAN fields are *advisory* — the server sets ' +
      'the actual SPIFFE ID from the registration entry, NOT from the CSR. ' +
      'The defining property of SPIFFE\'s CSR handling: the CSR cannot ' +
      'influence the issued identity.',
    attacks: [
      {
        id: 'csr-driven-identity-forgery',
        name: 'CSR-driven identity forgery (against weak implementations)',
        scenario:
          'A non-conformant SPIRE-clone or bridge CA reads the URI SAN ' +
          'from the workload\'s CSR and includes it in the issued cert. ' +
          'Mallory\'s compromised workload submits a CSR claiming ' +
          '`spiffe://domain/admin` and gets a cert with that identity, ' +
          'bypassing the registration entry mechanism entirely. SPIRE ' +
          'itself does not have this bug; downstream CAs and integrations ' +
          'sometimes do.',
        impact:
          'Identity forgery — workload claims arbitrary SPIFFE ID by ' +
          'submitting a crafted CSR.',
      },
    ],
    mitigations: [
      {
        action:
          'SPIRE Server (and any CA acting in this role) MUST ignore ' +
          'Subject/SAN fields in the CSR and synthesize them from the ' +
          'registration entry.',
        mitigates: ['csr-driven-identity-forgery'],
      },
      {
        action:
          'Audit: run a workload that submits a CSR with bogus URI SAN ' +
          'and verify the issued cert has the *registered* identity, not ' +
          'the requested one.',
        mitigates: ['csr-driven-identity-forgery'],
      },
    ],
    references: [
      {
        label: 'SPIFFE X.509-SVID §3 (Hierarchy)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#3-hierarchy',
      },
      {
        label: 'SPIFFE X.509-SVID §5 (Validation)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#5-validation',
      },
    ],
  },

  uri_san: {
    purpose:
      'The URI Subject Alternative Name in an X.509-SVID where the SPIFFE ' +
      'ID is encoded. X.509-SVID §2 mandates that an SVID MUST contain ' +
      'exactly one URI SAN, and that URI SAN MUST be the SPIFFE ID. ' +
      '§5.2 (Leaf Validation) requires verifiers to reject any cert with ' +
      'more than one URI SAN.',
    attacks: [
      {
        id: 'multi-uri-san-attack',
        name: 'Multi-URI-SAN attack',
        scenario:
          'A misbehaving CA (or a SPIRE clone bridging to legacy PKI) ' +
          'issues a cert with two URI SANs in violation of X.509-SVID §2: ' +
          '`spiffe://domain/innocent-service` (the legitimate one Mallory ' +
          'is registered for) and `spiffe://domain/admin-service` (her ' +
          'target). A non-conforming verifier that iterates URI SANs and ' +
          'returns the first one — instead of rejecting the cert outright ' +
          'as §5.2 requires — picks whichever the CA emitted first, and ' +
          'Mallory crafts the cert order to put the privileged ID first.',
        impact:
          'Identity confusion in the verifier.',
      },
    ],
    mitigations: [
      {
        action:
          'Reject any cert with more than one URI SAN, per X.509-SVID §5.2 ' +
          'Leaf Validation. Do not "pick the first SPIFFE-shaped one" — ' +
          'the spec forbids that path entirely.',
        mitigates: ['multi-uri-san-attack'],
      },
      {
        action:
          'Use SPIFFE\'s reference parsing libraries (go-spiffe, ' +
          'spiffe-rs) which enforce the §5.2 rule. Do NOT hand-roll ' +
          'certificate-to-SPIFFE-ID parsing.',
        mitigates: ['multi-uri-san-attack'],
      },
    ],
    references: [
      {
        label: 'SPIFFE X.509-SVID §2 (SPIFFE ID)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#2-spiffe-id',
      },
      {
        label: 'SPIFFE X.509-SVID §5.2 (Leaf Validation)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#52-leaf-validation',
      },
    ],
  },

  trust_bundle: {
    purpose:
      'The set of root CA certificates for a trust domain. Verifiers use it ' +
      'to validate the certificate chain on incoming SVIDs. Distributed by ' +
      'the SPIRE Server to all agents (which deliver to workloads via the ' +
      'Workload API) — and to any external verifier that needs to ' +
      'authenticate workloads in this trust domain.',
    attacks: [
      {
        id: 'stale-trust-bundle',
        name: 'Stale bundle after CA rotation',
        scenario:
          'CA rotation happened but the verifier\'s cache has not refreshed; ' +
          'new SVIDs fail to verify, breaking service-to-service auth.',
        impact:
          'Availability impact — failed auth, support tickets — until ' +
          'cache refreshes.',
      },
      {
        id: 'tampered-trust-bundle',
        name: 'Tampered bundle (attacker CA injected)',
        scenario:
          'Mallory has compromised the storage backing a verifier\'s trust ' +
          'bundle cache (a Kubernetes ConfigMap, a file on disk, an ' +
          'environment variable supplying a PEM bundle). She adds her own ' +
          'self-signed CA to the bundle. The verifier now trusts SVIDs ' +
          'Mallory mints with that CA — full identity forgery within the ' +
          'trust domain (from the verifier\'s perspective).',
        impact:
          'Trust subversion at the trust-bundle layer.',
      },
    ],
    mitigations: [
      {
        action:
          'Deliver bundles via the Workload API rather than file-system ' +
          'distribution where possible.',
        mitigates: ['tampered-trust-bundle'],
      },
      {
        action:
          'Protect the storage path / ConfigMap with appropriate RBAC so ' +
          'only the SPIRE Server can write.',
        mitigates: ['tampered-trust-bundle'],
      },
      {
        action:
          'Verify bundle freshness against the SPIRE Server periodically.',
        mitigates: ['stale-trust-bundle', 'tampered-trust-bundle'],
      },
      {
        action:
          'For external verifiers, use bundle endpoints with mTLS ' +
          'authentication.',
        mitigates: ['tampered-trust-bundle'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Trust Domain and Bundle §4 (Bundle Format)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format',
      },
      {
        label: 'SPIFFE Trust Domain and Bundle §6 (Security Considerations)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#6-security-considerations',
      },
    ],
  },

  federated_bundles: {
    purpose:
      'Trust bundles for *foreign* trust domains, fetched via federation ' +
      'and used to validate SVIDs from those domains. Each entry maps ' +
      '`trust_domain → root_cas`. Distributed alongside the local trust ' +
      'bundle to workloads that participate in cross-domain communication. ' +
      'Federation extends trust beyond the local domain — every additional ' +
      'federated bundle is an additional set of CAs that can mint SVIDs ' +
      'the local verifier will accept.',
    attacks: [
      {
        id: 'federation-chain-compromise',
        name: 'Cascading federation chain compromise',
        scenario:
          'Trust domain A federates with B; B federates with C. Mallory ' +
          'compromises C\'s bundle endpoint and starts publishing her own ' +
          'CA in C\'s bundle. B fetches it (B trusts C\'s endpoint), then ' +
          'B redistributes the federated bundle. A fetches B\'s ' +
          'redistributed view (A trusts B), and now A\'s workloads trust ' +
          'SVIDs that Mallory minted from C\'s "compromised" CA — even ' +
          'though A and C have no direct relationship. Per the SPIFFE ' +
          'Federation spec: "compromise of a trust domain or bundle ' +
          'endpoint server in the chain would result in the compromise of ' +
          'the next trust domain."',
        impact:
          'Cascading trust compromise across federation chains.',
      },
    ],
    mitigations: [
      {
        action:
          'Minimise federation depth — avoid B-trusts-C-trusts-D chains; ' +
          'establish direct relationships where possible.',
        mitigates: ['federation-chain-compromise'],
      },
      {
        action:
          'Use `https_spiffe` profile for bundle endpoints (mTLS, not ' +
          'Web PKI).',
        mitigates: ['federation-chain-compromise'],
      },
      {
        action:
          'Monitor federated bundle changes and alert on unexpected CA ' +
          'additions.',
        mitigates: ['federation-chain-compromise'],
      },
      {
        action:
          'Treat federated trust domains with the same scrutiny as direct ' +
          'ones — each is an additional source of SVIDs your verifier will ' +
          'accept.',
        mitigates: ['federation-chain-compromise'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Federation spec',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md',
      },
      {
        label: 'SPIFFE Federation §7 (Security Considerations)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md#7-security-considerations',
      },
    ],
  },

  bundle_endpoint_url: {
    purpose:
      'URL the local SPIRE Server fetches to obtain a foreign trust ' +
      'domain\'s bundle. Standard path is `/.well-known/spiffe-bundle` on ' +
      'the foreign SPIRE Server but custom URLs are supported. The choice ' +
      'of `endpoint_profile` (`https_spiffe` vs `https_web`) determines ' +
      'how this URL\'s authenticity is verified.',
    attacks: [
      {
        id: 'endpoint-url-substitution',
        name: 'Endpoint URL substitution',
        scenario:
          'Mallory has write access to the SPIRE Server\'s federation ' +
          'configuration (via compromised Kubernetes ConfigMap, leaked ' +
          'admin credentials, etc.). She changes `bundle_endpoint_url` ' +
          'for `partner.example.com` from ' +
          '`https://spire.partner.example.com:8443/bundle` to ' +
          '`https://attacker.example.com/fake-bundle`. With `https_web` ' +
          'profile, the SPIRE Server fetches the fake bundle (TLS valid ' +
          'for attacker domain), trusts the attacker\'s CA, and from this ' +
          'point forward every SVID minted by the attacker is accepted as ' +
          'if it were a legitimate `partner.example.com` workload. Per ' +
          'SPIFFE Federation spec: "Compromise of the configuration of a ' +
          'federation relationship can weaken or completely break security ' +
          'guarantees."',
        impact:
          'Total federation compromise via configuration tampering.',
      },
    ],
    mitigations: [
      {
        action:
          'Use `https_spiffe` endpoint_profile — the bundle endpoint ' +
          'server must present a SPIFFE SVID matching ' +
          '`endpoint_spiffe_id`, which the attacker cannot forge without ' +
          'compromising the foreign trust domain.',
        mitigates: ['endpoint-url-substitution'],
      },
      {
        action:
          'Protect federation configuration storage with strict RBAC ' +
          '(only platform admins can edit; audit every change).',
        mitigates: ['endpoint-url-substitution'],
      },
      {
        action:
          'Audit federation config changes; alert on bundle_endpoint_url ' +
          'modifications.',
        mitigates: ['endpoint-url-substitution'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Federation §5 (Serving and Consuming a SPIFFE Bundle Endpoint)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md#5-serving-and-consuming-a-spiffe-bundle-endpoint',
      },
      {
        label: 'SPIFFE Federation §7 (Security Considerations)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md#7-security-considerations',
      },
    ],
  },

  endpoint_profile: {
    purpose:
      'Authentication profile for the bundle endpoint: `https_spiffe` (the ' +
      'foreign SPIRE Server presents a SPIFFE SVID; mTLS) or `https_web` ' +
      '(Web PKI TLS — the foreign endpoint presents a cert from a public ' +
      'CA chain). `https_spiffe` is the secure choice; `https_web` is ' +
      'provided for bootstrapping / cross-organization cases where SPIFFE ' +
      'identities are not yet exchanged.',
    attacks: [
      {
        id: 'bundle-endpoint-tls-hijack',
        name: 'Bundle endpoint TLS hijack (https_web profile)',
        scenario:
          'Mallory performs a BGP hijack against `partner.example.com`\'s ' +
          'IP space, obtains a Let\'s Encrypt cert for it via HTTP-01 ' +
          'challenge during the hijack, and serves a fake bundle from her ' +
          'infrastructure. The local SPIRE Server, configured with ' +
          '`endpoint_profile=https_web`, sees a TLS connection that ' +
          'validates against Web PKI roots — accepts it. With ' +
          '`https_spiffe`, the connection would have failed because ' +
          'Mallory cannot mint a partner-domain SPIFFE SVID without ' +
          'compromising partner\'s SPIRE Server.',
        impact:
          'Federation trust subversion via Web PKI weaknesses (DNS hijack, ' +
          'BGP attack, lax CA, abused ACME challenge).',
      },
    ],
    mitigations: [
      {
        action:
          'Use `https_spiffe` for any production federation.',
        mitigates: ['bundle-endpoint-tls-hijack'],
      },
      {
        action:
          'Reserve `https_web` for the *initial* bundle exchange only, ' +
          'then switch to `https_spiffe` once both sides have each other\'s ' +
          'bundles.',
        mitigates: ['bundle-endpoint-tls-hijack'],
      },
      {
        action:
          'Treat any federation still on `https_web` as a configuration ' +
          'finding to remediate.',
        mitigates: ['bundle-endpoint-tls-hijack'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Federation §5.2 (Endpoint Profiles)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md#52-endpoint-profiles',
      },
      {
        label: 'SPIFFE Federation §7 (Security Considerations)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md#7-security-considerations',
      },
    ],
  },

  attestor_type: {
    purpose:
      'Plugin identifier for the node attestor: `join_token` (one-time ' +
      'bootstrap secret), `aws_iid` (AWS Instance Identity Document), ' +
      '`gcp_iit` (GCP Instance Identity Token), `azure_msi`, `k8s_psat` / ' +
      '`k8s_sat` (Kubernetes service account token), `x509pop` (X.509 ' +
      'proof of possession), `tpm_devid` (TPM-backed). Determines what ' +
      'evidence the agent presents to prove its node identity to the SPIRE ' +
      'Server. Each attestor has a different threat model.',
    attacks: [
      {
        id: 'join-token-in-production',
        name: 'join_token in production',
        scenario:
          'Tokens leak via terraform state files, CI logs, configuration ' +
          'management. Mallory finds an unused token and registers a ' +
          'rogue agent in the trust domain.',
        impact:
          'Rogue agent registration → ability to mint workload SVIDs in ' +
          'the trust domain.',
      },
      {
        id: 'k8s-psat-compromised-cluster',
        name: 'k8s_psat on a compromised cluster',
        scenario:
          'If the Kubernetes API server is compromised, attacker mints ' +
          'arbitrary projected service account tokens for any namespace, ' +
          'registering rogue agents.',
        impact:
          'Trust-domain compromise via control-plane compromise.',
      },
      {
        id: 'aws-iid-metadata-hijack',
        name: 'aws_iid metadata-service hijack',
        scenario:
          'SSRF in a workload lets the attacker query the AWS metadata ' +
          'service of a different EC2 instance, then submitting that IID ' +
          'as their own to register a rogue agent.',
        impact:
          'Attacker registers an agent claiming to be a specific EC2 ' +
          'instance they don\'t actually control.',
      },
    ],
    mitigations: [
      {
        action:
          'Use the strongest attestor the platform supports — TPM-backed ' +
          'where available, cloud-platform attestors otherwise, ' +
          '`join_token` only for ephemeral / bootstrap cases.',
        mitigates: [
          'join-token-in-production',
          'k8s-psat-compromised-cluster',
        ],
      },
      {
        action:
          'Constrain attestor results — `aws_iid` agents should be scoped ' +
          'to specific account IDs and instance roles, not open-ended.',
        mitigates: ['aws-iid-metadata-hijack'],
      },
      {
        action:
          'For `join_token`, use very short TTLs and consume-on-first-use ' +
          'semantics (SPIRE default).',
        mitigates: ['join-token-in-production'],
      },
      {
        action:
          'Audit Kubernetes RBAC restricting who can mint service-account ' +
          'tokens; defence-in-depth against control-plane compromise.',
        mitigates: ['k8s-psat-compromised-cluster'],
      },
    ],
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
      'Simplest node-attestation method, useful for development and small ' +
      'static deployments. A bearer secret with the same threat model as ' +
      'any other shared token.',
    attacks: [
      {
        id: 'join-token-channel-theft',
        name: 'Token theft from provisioning channels',
        scenario:
          'Mallory has read access to a Terraform state file, a CI build ' +
          'log, a Slack channel, an email thread — anywhere the join ' +
          'token might appear before reaching the target node. She submits ' +
          'the token to the SPIRE Server before the legitimate node does. ' +
          'Server consumes the token, issues an agent SVID to Mallory\'s ' +
          'rogue agent. The legitimate node then fails to attest (token ' +
          'already used) — the failure is the only signal.',
        impact:
          'Rogue agent in the trust domain → arbitrary workload SVID ' +
          'issuance on Mallory\'s infrastructure.',
      },
    ],
    mitigations: [
      {
        action:
          'Use platform attestors (cloud or TPM) in production rather than ' +
          'join_token.',
        mitigates: ['join-token-channel-theft'],
      },
      {
        action:
          'For join_token, keep TTLs short (minutes, not days).',
        mitigates: ['join-token-channel-theft'],
      },
      {
        action:
          'Treat token leakage as detected breach — rotate trust domain ' +
          'credentials, audit which workloads were issued SVIDs by the ' +
          'rogue agent.',
        mitigates: ['join-token-channel-theft'],
      },
    ],
    references: [
      {
        label: 'SPIRE Server — Join Token attestor',
        href: 'https://github.com/spiffe/spire/blob/main/doc/plugin_server_nodeattestor_jointoken.md',
      },
    ],
  },

  audience: {
    purpose:
      'On a JWT-SVID issuance request, names the intended recipient of the ' +
      'token (a SPIFFE ID, URI, or arbitrary string the receiving service ' +
      'identifies as). The SPIRE Server binds this value into the JWT\'s ' +
      '`aud` claim. Verifiers MUST check that the value they identify as ' +
      'appears in `aud` before trusting the token.',
    attacks: [
      {
        id: 'jwt-svid-cross-audience-replay',
        name: 'Cross-audience replay (multi-audience tokens)',
        scenario:
          'Per the JWT-SVID spec\'s explicit warning: Alice mints a ' +
          'JWT-SVID with `aud=[Bob, Chuck]` and sends it to Chuck. Chuck ' +
          'now has a token that *Bob* will accept as proof of Alice\'s ' +
          'identity. Chuck replays the token to Bob; Bob sees a valid ' +
          'JWT-SVID with `aud` containing his identifier, signed by the ' +
          'trust domain CA — accepts it. Chuck has now successfully ' +
          'impersonated Alice at Bob.',
        impact:
          'Identity confusion across services in multi-audience ' +
          'configurations.',
      },
      {
        id: 'jwt-svid-no-audience-binding',
        name: 'No audience binding',
        scenario:
          'Token issued without specific audience can be replayed at any ' +
          'service that consumes JWT-SVIDs from this trust domain.',
        impact:
          'Single-token-stolen → any-service-compromised within the trust ' +
          'domain.',
      },
    ],
    mitigations: [
      {
        action:
          'Request JWT-SVIDs with EXACTLY ONE audience, identifying the ' +
          'specific recipient — avoid the multi-audience pattern entirely.',
        mitigates: [
          'jwt-svid-cross-audience-replay',
          'jwt-svid-no-audience-binding',
        ],
      },
      {
        action:
          'Verifiers MUST reject tokens missing `aud` or with `aud` not ' +
          'matching their identifier.',
        mitigates: ['jwt-svid-no-audience-binding'],
      },
      {
        action:
          'Issue separate tokens for separate recipients rather than ' +
          'reusing one across services.',
        mitigates: ['jwt-svid-cross-audience-replay'],
      },
    ],
    references: [
      {
        label: 'SPIFFE JWT-SVID §3.2 (Audience)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md#32-audience',
      },
      {
        label: 'SPIFFE JWT-SVID §7.2 (Audience — replay protection)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md#72-audience',
      },
    ],
  },

  agent_svid: {
    purpose:
      'The X.509-SVID issued to the SPIRE Agent itself after successful ' +
      'node attestation. The agent uses it for mTLS to the SPIRE Server ' +
      'when fetching workload SVIDs and trust bundle updates. Forms the ' +
      'agent\'s identity as a "trusted attestor" for workloads on its node.',
    attacks: [
      {
        id: 'agent-identity-theft',
        name: 'Agent identity theft → workload SVID issuance',
        scenario:
          'Mallory roots a node and reads the SPIRE Agent\'s on-disk SVID ' +
          'and private key (typically stored in a Kubernetes Secret or ' +
          'local file). She connects to the SPIRE Server from her own ' +
          'infrastructure presenting the stolen agent SVID, requests ' +
          'workload SVIDs for the registration entries scoped to that ' +
          'agent — and gets them. She can now run "those workloads" ' +
          'anywhere with full trust-domain identity.',
        impact:
          'Lateral movement bounded by `parent_id` scoping (which is why ' +
          '`parent_id` matters).',
      },
    ],
    mitigations: [
      {
        action:
          'Store agent private keys in HSM / TPM where available, not on ' +
          'disk.',
        mitigates: ['agent-identity-theft'],
      },
      {
        action:
          'Enable agent SVID rotation with short TTLs so stolen ' +
          'credentials expire quickly.',
        mitigates: ['agent-identity-theft'],
      },
      {
        action:
          'Monitor for agent SVID use from unexpected IPs (the SPIRE ' +
          'Server can log the source of agent connections).',
        mitigates: ['agent-identity-theft'],
      },
      {
        action:
          'Minimise `parent_id` scope — never use trust-domain-wide ' +
          'parents.',
        mitigates: ['agent-identity-theft'],
      },
    ],
    references: [
      {
        label: 'SPIRE Concepts — Agent SVID lifecycle',
        href: 'https://spiffe.io/docs/latest/spire-about/spire-concepts/',
      },
    ],
  },

  peer_creds: {
    purpose:
      'OS-kernel-verified PID, UID, GID of the process connecting to the ' +
      'SPIRE Agent\'s Workload API socket. Obtained via SO_PEERCRED (Linux) ' +
      'or equivalent — distinct from anything the workload could tell the ' +
      'agent. Kernel-verified PID/UID/GID is the ground truth that ' +
      'workload attestation is anchored to. *But* — PID is a small integer ' +
      'that the kernel reuses.',
    attacks: [
      {
        id: 'pid-reuse-race',
        name: 'PID-reuse race against attestation cache',
        scenario:
          'Process A (legitimate, attested) exits. Process B (Mallory\'s, ' +
          'malicious) starts on the same node and the kernel happens to ' +
          'assign it Process A\'s old PID. A naive agent that looks up ' +
          '"what SPIFFE ID did PID 12345 attest to last time" returns ' +
          'Process A\'s identity to Process B. SPIRE\'s real defence: when ' +
          'the agent re-reads `/proc/{pid}/exe` and other process ' +
          'attributes, the kernel returns the *new* process\'s attributes ' +
          '(or fails if the FD became stale), so attestation re-runs and ' +
          'matches the new process\'s actual selectors — not the old ones.',
        impact:
          'Wrong-workload-identity issuance under PID reuse.',
      },
    ],
    mitigations: [
      {
        action:
          'Re-attest on every Workload API call — do not cache attestation ' +
          'across calls. SPIRE Agent does this by default; the spec ' +
          'delegates attestation specifics to implementations, so this is ' +
          'an implementation requirement rather than a spec MUST.',
        mitigates: ['pid-reuse-race'],
      },
      {
        action:
          'Use process-start-time alongside PID for cache keying so a new ' +
          'process with a recycled PID gets a fresh attestation.',
        mitigates: ['pid-reuse-race'],
      },
      {
        action:
          'Verify the executable hasn\'t changed between attestation and ' +
          'SVID handover.',
        mitigates: ['pid-reuse-race'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Workload API §3 (Service Definition)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md#3-service-definition',
      },
      {
        label: 'SPIFFE Workload API §4.1 (Identifying the Caller)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md#41-identifying-the-caller',
      },
    ],
  },

  'spiffe:format': {
    purpose:
      'Wire format of a federated trust-bundle endpoint response — a JWKS ' +
      '(RFC 7517) document where each entry with `use=x509-svid` carries ' +
      'an `x5c` parameter holding exactly one base64-DER CA certificate ' +
      '(SHOULD be self-signed, per X.509-SVID §6.1). The local SPIRE ' +
      'Server unions these certificates to form the foreign trust ' +
      'domain\'s X.509 CA bundle.',
    attacks: [
      {
        id: 'rogue-x5c-injection',
        name: 'Rogue CA injection via attacker-controlled `x5c`',
        scenario:
          'The bundle endpoint is reached without proper TLS validation ' +
          '(missing `endpoint_spiffe_id` check on `https_spiffe`, or wrong ' +
          'CA pinning on `https_web`). Mallory MITMs the response and ' +
          'replaces the `x5c` chain with her own CA. The local SPIRE Server ' +
          'imports the rogue CA into the federated bundle, after which any ' +
          'workload presenting an SVID signed by Mallory\'s CA is treated ' +
          'as a legitimate member of the foreign trust domain.',
        impact:
          'Attacker mints arbitrary identities in any federated trust ' +
          'domain — full cross-domain workload impersonation.',
      },
      {
        id: 'jwks-format-drift',
        name: 'Format-drift attacks (non-conformant JWKS body)',
        scenario:
          'X.509-SVID §6.2 requires consumers to ignore any `use=x509-svid` ' +
          'JWK entry whose `x5c` is missing or empty, and to take only the ' +
          'first value when multiple are present. A misconfigured (or ' +
          'compromised) endpoint can serve `use=x509-svid` entries with no ' +
          '`x5c`, or PEM, or an empty `keys: []`. A consumer that skips ' +
          'this filtering and just takes whatever it parsed either fails ' +
          'open (clears the X509-SVID trust bundle, then accepts ' +
          'anything) or silently retains the previous bundle indefinitely ' +
          'past `spiffe_refresh_hint`.',
        impact:
          'Either no trust enforcement (fail-open) or stale trust ' +
          'anchors that survive intentional revocation.',
      },
    ],
    mitigations: [
      {
        action:
          'Validate the bundle endpoint TLS chain *before* parsing the ' +
          'body. For `https_spiffe`, require the endpoint\'s SPIFFE ID to ' +
          'match the configured `endpoint_spiffe_id`. For `https_web`, pin ' +
          'the Web-PKI CA used to authenticate the bundle URL.',
        mitigates: ['rogue-x5c-injection'],
      },
      {
        action:
          'Strictly parse JWKS: require `Content-Type: application/json`, ' +
          'reject responses without a non-empty `keys[]` containing ' +
          '`x5c` chains, and validate each chain up to a known root before ' +
          'trusting it.',
        mitigates: ['rogue-x5c-injection', 'jwks-format-drift'],
      },
      {
        action:
          'On bundle-fetch failure or schema mismatch, retain the last-' +
          'known-good bundle and alert — do not clear trust anchors. The ' +
          'spec recommends caching and retrying at the next interval. ' +
          'Honour `spiffe_refresh_hint` (Trust Domain §4.1.2) for cache ' +
          'lifetime, and cap maximum age locally so stale bundles cannot ' +
          'persist forever — the cap is operational hardening, not a ' +
          'spec requirement.',
        mitigates: ['jwks-format-drift'],
      },
    ],
    references: [
      {
        label: 'SPIFFE Trust Domain and Bundle §4 (Bundle Format)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format',
      },
      {
        label: 'SPIFFE Federation §5.2 (Endpoint Profiles)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md#52-endpoint-profiles',
      },
      {
        label: 'SPIFFE X.509-SVID §6.1 (Publishing SPIFFE Bundle Elements)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#61-publishing-spiffe-bundle-elements',
      },
      {
        label: 'SPIFFE X.509-SVID §6.2 (Consuming a SPIFFE Bundle)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#62-consuming-a-spiffe-bundle',
      },
      {
        label: 'RFC 7517 (JSON Web Key)',
        href: 'https://datatracker.ietf.org/doc/html/rfc7517',
      },
    ],
  },

  'spiffe:issuer': {
    purpose:
      'The signing CA that issued an X.509-SVID — typically SPIRE\'s ' +
      'intermediate CA chained under the trust-domain root. The verifier ' +
      'uses this together with the trust bundle to decide whether the ' +
      'presented SVID is a legitimate member of the trust domain.',
    attacks: [
      {
        id: 'intermediate-ca-compromise',
        name: 'Signing-CA compromise mints arbitrary SVIDs',
        scenario:
          'SPIRE Server is configured with the `disk` KeyManager (one of ' +
          'the default options) so the intermediate CA\'s private key sits ' +
          'in a file on the host, and the operator has overridden the ' +
          'default 24h CA TTL to a longer period for "stability." A host ' +
          'compromise (admin credential leak, container escape, backup ' +
          'exfiltration) hands Mallory the signing key. She mints SVIDs ' +
          'for `spiffe://trust-domain/admin/anything` offline, and any ' +
          'verifier validating chain-to-trust-bundle accepts them as ' +
          'legitimate.',
        impact:
          'Trust-domain-wide impersonation. Until the intermediate is ' +
          'rotated and the old key removed from the trust bundle, every ' +
          'workload in the domain is impersonable.',
      },
      {
        id: 'chain-validation-skipped',
        name: 'Verifier accepts SVID without validating issuer chain',
        scenario:
          'Verifier code extracts the SPIFFE ID from the SVID\'s URI SAN ' +
          'and authorises on that, but does not validate the X.509 chain ' +
          'up to a CA in the trust bundle. Attacker presents a self-signed ' +
          'cert, or a cert signed by an unrelated CA, with a URI SAN of ' +
          'the target SPIFFE ID. Verifier honours the identity.',
        impact:
          'No cryptographic binding between identity claim and trust ' +
          'domain — anyone can claim any SPIFFE ID.',
      },
    ],
    mitigations: [
      {
        action:
          'Hold the signing key in a managed key store via SPIRE\'s ' +
          'KeyManager plugin: `aws_kms`, `gcp_kms`, or `azure_key_vault` ' +
          '(rather than the `disk` or `memory` defaults). Separately, ' +
          'consider chaining SPIRE\'s CA under an external root via the ' +
          'UpstreamAuthority plugin (`vault`, `awspca`, `cert-manager`). ' +
          'Keep CA TTL at or below SPIRE\'s 24h default and monitor for ' +
          'SVID-issuance anomalies (unexpected SPIFFE IDs, off-hours ' +
          'minting).',
        rationale:
          'KeyManager controls *where the private key lives*; ' +
          'UpstreamAuthority controls *what root signs SPIRE\'s ' +
          'intermediate*. Conflating them is a common configuration error.',
        mitigates: ['intermediate-ca-compromise'],
      },
      {
        action:
          'Verifiers MUST validate the full X.509 chain from the SVID up ' +
          'to a CA present in the local or federated trust bundle BEFORE ' +
          'authorising on the URI SAN. Reject any SVID whose chain does ' +
          'not terminate at a trusted root.',
        mitigates: ['chain-validation-skipped', 'intermediate-ca-compromise'],
      },
      {
        action:
          'Keep SVID lifetimes short (default `default_x509_svid_ttl=1h` ' +
          'in SPIRE) so a compromised intermediate has a bounded blast ' +
          'radius after rotation — old SVIDs naturally expire.',
        mitigates: ['intermediate-ca-compromise'],
      },
    ],
    references: [
      {
        label: 'SPIFFE X.509-SVID §5 (Validation)',
        href: 'https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md#5-validation',
      },
      {
        label: 'SPIRE KeyManager — AWS KMS plugin',
        href: 'https://github.com/spiffe/spire/blob/main/doc/plugin_server_keymanager_aws_kms.md',
      },
      {
        label: 'SPIRE UpstreamAuthority configuration',
        href: 'https://spiffe.io/docs/latest/deploying/configuring/#configuring-which-trust-root--upstream-authority-your-application-will-use',
      },
      {
        label: 'RFC 5280 §6 (Certification Path Validation)',
        href: 'https://datatracker.ietf.org/doc/html/rfc5280#section-6',
      },
    ],
  },
}
