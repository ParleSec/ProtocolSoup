package spiffe

import "github.com/ParleSec/ProtocolSoup/internal/plugin"

// getFlowDefinitions returns all SPIFFE protocol flow definitions
func getFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		getWorkloadRegistrationFlow(),
		getNodeAttestationFlow(),
		getWorkloadAttestationFlow(),
		getX509SVIDIssuanceFlow(),
		getJWTSVIDIssuanceFlow(),
		getMTLSHandshakeFlow(),
		getCertificateRotationFlow(),
		getTrustBundleFederationFlow(),
	}
}

// getWorkloadRegistrationFlow defines the workload registration process
// This is an administrative process that requires SPIRE Server API access
func getWorkloadRegistrationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "workload-registration",
		Name:        "Workload Registration",
		Description: "Administrative process of creating a registration entry in SPIRE Server that maps workload selectors to a SPIFFE ID (SPIFFE spec §3). Registration entries define the policy for which workloads receive which identities. Each entry specifies a SPIFFE ID, a parent (the agent node), and one or more selectors that the workload must match during attestation. This is the foundation of SPIFFE's identity model - no SVID can be issued without a matching registration entry.",
		Executable:  false, // Admin process - not accessible via Workload API
		Category:    "admin",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Create Registration Entry",
				Description: "Administrator creates a registration entry via the SPIRE Server Registration API (spire-api-sdk). The entry maps a set of selectors (platform-specific workload identifiers) to a SPIFFE ID. The parent_id links this entry to a specific SPIRE Agent node, meaning only that agent can issue SVIDs for this entry. The SPIFFE ID MUST conform to the spiffe:// URI scheme (SPIFFE spec §2).",
				From:        "Admin",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"spiffe_id":  "spiffe://trust-domain/workload/path - identity to assign (REQUIRED, SPIFFE spec §2)",
					"parent_id":  "spiffe://trust-domain/agent/node - agent authorized to issue this SVID (REQUIRED)",
					"selectors":  "Workload selectors: docker:label:app:myapp, k8s:ns:default, unix:uid:1000 (REQUIRED, at least one)",
					"ttl":        "SVID TTL in seconds (OPTIONAL, default from server config, max enforced by server)",
					"dns_names":  "DNS SANs to include in X.509-SVID (OPTIONAL, e.g., myapp.svc.cluster.local)",
					"downstream": "false - true only for nested SPIRE servers in multi-tier deployments",
					"admin":      "false - true grants workload admin access to SPIRE Server APIs",
				},
				Security: []string{
					"Only authorized administrators should create registration entries - use SPIRE admin APIs with mTLS",
					"SPIFFE IDs MUST follow the spiffe://trust-domain/path format (SPIFFE spec §2)",
					"Use the most specific selectors possible to prevent workload impersonation",
					"TTL should be as short as practical - shorter TTLs limit compromise blast radius",
					"Avoid granting 'admin' flag unless the workload genuinely needs SPIRE Server API access",
				},
			},
			{
				Order:       2,
				Name:        "Entry Persisted to Datastore",
				Description: "SPIRE Server persists the registration entry to its configured datastore (SQL database or in-memory). The entry is assigned a unique entry ID and timestamped. The datastore is the source of truth for all identity policies - entries survive server restarts. SPIRE supports SQLite (development) and PostgreSQL/MySQL (production) datastores.",
				From:        "SPIRE Server",
				To:          "Datastore",
				Type:        "internal",
				Parameters: map[string]string{
					"entry_id":    "Auto-generated UUID for this registration entry",
					"created_at":  "UTC timestamp of entry creation",
					"admin_id":    "SPIFFE ID of the administrator who created the entry (audit trail)",
					"entry_state": "active - entry is immediately available for attestation matching",
					"revision":    "Entry revision number for optimistic concurrency control",
				},
				Security: []string{
					"Registration entries are persisted durably - they survive SPIRE Server restarts",
					"All entry creation/modification events should be audited with the admin identity",
					"Entries can be revoked by deletion via the Registration API",
					"Datastore SHOULD be encrypted at rest (database-level encryption)",
				},
			},
			{
				Order:       3,
				Name:        "Agent Cache Sync",
				Description: "SPIRE Agents receive updated registration entries from the Server via the Node API (a streaming gRPC connection authenticated with the agent's own SVID). Agents cache relevant entries locally so they can perform workload attestation without contacting the Server for every SVID request. Only entries whose parent_id matches the agent's SPIFFE ID are synced.",
				From:        "SPIRE Server",
				To:          "SPIRE Agent",
				Type:        "response",
				Parameters: map[string]string{
					"sync_type":       "Streaming gRPC (long-lived connection) or periodic polling",
					"entries":         "Registration entries where parent_id matches this agent",
					"sync_interval":   "Configurable polling interval (default varies by SPIRE version)",
					"selective_sync":  "Only entries relevant to this specific agent node are transmitted",
				},
				Security: []string{
					"Agent-to-Server sync uses mTLS with the agent's SVID - mutually authenticated",
					"Agents only receive entries for their own node (parent_id filtering on server side)",
					"Cached entries are refreshed periodically to pick up new registrations and deletions",
					"Network partition: agent continues serving cached entries until reconnection",
				},
			},
		},
	}
}

// getNodeAttestationFlow defines the node attestation process
// This is an infrastructure process that occurs during SPIRE Agent bootstrap
func getNodeAttestationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "node-attestation",
		Name:        "Node Attestation",
		Description: "Process by which a SPIRE Agent proves the identity of its host node to the SPIRE Server during bootstrap (SPIFFE spec §4). Node attestation is the trust anchor for the entire SPIFFE identity system - the agent must cryptographically prove it is running on an authorized node before it can receive registration entries or issue SVIDs to workloads. SPIRE supports multiple attestation plugins for different infrastructure: join tokens, AWS IID, GCP IIT, Azure MSI, and Kubernetes PSAT.",
		Executable:  false, // Infrastructure process - happens during agent bootstrap
		Category:    "infrastructure",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Agent Startup and Attestor Selection",
				Description: "SPIRE Agent starts and loads its configured Node Attestor plugin. The attestor type is determined by the agent's configuration file and must match a corresponding server-side attestor. The agent invokes the attestor's FetchAttestationData RPC to collect platform-specific proof of node identity.",
				From:        "SPIRE Agent",
				To:          "Node Attestor Plugin",
				Type:        "internal",
				Parameters: map[string]string{
					"attestor_type": "join_token | aws_iid | gcp_iit | azure_msi | k8s_psat | k8s_sat | x509pop | tpm_devid",
					"join_token":    "One-time bootstrap token (simplest, good for development)",
					"aws_iid":       "AWS Instance Identity Document signed by AWS (production AWS)",
					"gcp_iit":       "GCP Identity Token from metadata server (production GCP)",
					"k8s_psat":      "Kubernetes Projected Service Account Token (production Kubernetes)",
					"x509pop":       "Pre-existing X.509 certificate for proof of possession",
				},
				Security: []string{
					"Attestor choice determines the security properties of the entire SPIFFE deployment",
					"join_token is single-use but weakest - suitable only for development or bootstrap",
					"Cloud attestors (aws_iid, gcp_iit) leverage platform-level cryptographic identity",
					"k8s_psat is preferred over k8s_sat as it uses audience-bound, time-limited tokens",
				},
			},
			{
				Order:       2,
				Name:        "Attestation Evidence Collection",
				Description: "The Node Attestor plugin collects cryptographic proof of the node's identity from the underlying platform. For cloud environments, this typically involves requesting a signed identity document from the cloud provider's metadata service. The evidence is platform-specific and unforgeable by the workload layer - it can only be produced by the actual infrastructure.",
				From:        "Node Attestor Plugin",
				To:          "SPIRE Agent",
				Type:        "internal",
				Parameters: map[string]string{
					"join_token":         "One-time token provisioned out-of-band (consumed on first use)",
					"aws_instance_doc":   "PKCS#7-signed Instance Identity Document from AWS metadata (169.254.169.254)",
					"gcp_identity_token": "OIDC token from GCP metadata server with audience=spire-server",
					"k8s_psat":           "Projected ServiceAccount JWT token with configurable audience and expiry",
					"x509_certificate":   "Pre-provisioned X.509 certificate and private key for proof of possession",
				},
				Security: []string{
					"Join tokens MUST be single-use and securely provisioned (e.g., via secrets manager)",
					"Cloud identity documents are cryptographically signed by the cloud provider",
					"k8s_psat tokens are time-limited and audience-bound (more secure than k8s_sat)",
					"Evidence collection is local to the node - no network calls except to metadata services",
				},
			},
			{
				Order:       3,
				Name:        "Attestation Request to Server",
				Description: "Agent sends an AttestAgent RPC to the SPIRE Server over gRPC/TLS (SPIRE Server API). The request contains the attestation evidence from the platform and a Certificate Signing Request (CSR) for the agent's own SVID. The initial TLS connection uses either a bootstrap bundle or an insecure bootstrap (for join_token in trusted networks).",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"attestation_data": "Platform-specific proof from the Node Attestor plugin",
					"attestor_type":    "Plugin type identifier (e.g., 'join_token', 'aws_iid')",
					"csr":              "X.509 Certificate Signing Request containing agent's public key",
					"bootstrap_method": "Bootstrap bundle (pre-provisioned CA cert) or insecure bootstrap",
				},
				Security: []string{
					"Initial TLS should use a bootstrap trust bundle when possible (not insecure bootstrap)",
					"CSR contains only the agent's public key - private key never leaves the agent",
					"The gRPC connection is authenticated server-side via the bootstrap bundle",
					"Attestation data is transmitted once and consumed - not replayable for join_token",
				},
			},
			{
				Order:       4,
				Name:        "Server Verifies Attestation Evidence",
				Description: "SPIRE Server loads the matching server-side Node Attestor plugin and verifies the attestation evidence. For join_token, the server checks its stored token list; for aws_iid, it verifies the AWS signature and optionally calls AWS APIs to confirm the instance; for k8s_psat, it validates the JWT against the Kubernetes API server's OIDC keys.",
				From:        "SPIRE Server",
				To:          "Server Node Attestor",
				Type:        "internal",
				Parameters: map[string]string{
					"join_token_verify":  "Lookup token in server's token store, consume on match (single-use)",
					"aws_iid_verify":     "Verify PKCS#7 signature using AWS public certificate, optionally call DescribeInstances",
					"gcp_iit_verify":     "Validate OIDC token signature using Google's public keys, check audience and claims",
					"k8s_psat_verify":    "Validate JWT against Kubernetes API server's OIDC discovery endpoint",
					"agent_id_assignment": "Server assigns agent SPIFFE ID based on verified platform identity (e.g., spiffe://domain/agent/aws_iid/i-1234567890abcdef0)",
				},
				Security: []string{
					"Server MUST verify attestation evidence cryptographically - never trust self-reported identity",
					"Failed attestation MUST result in RPC rejection - no SVID is issued",
					"join_token is consumed (deleted) after successful use - prevents replay",
					"Cloud attestors should enable re-attestation checks to detect terminated instances",
				},
			},
			{
				Order:       5,
				Name:        "Agent SVID Issuance and Trust Bundle Delivery",
				Description: "After successful attestation, the SPIRE Server signs the agent's CSR to produce an X.509-SVID certificate with the assigned agent SPIFFE ID in the URI SAN. The server returns the signed SVID, the trust bundle (root CA certificates for the trust domain), and the agent's assigned SPIFFE ID. The agent uses this SVID for all subsequent mTLS communication with the server.",
				From:        "SPIRE Server",
				To:          "SPIRE Agent",
				Type:        "response",
				Parameters: map[string]string{
					"agent_svid":   "Signed X.509 certificate with agent SPIFFE ID in URI SAN (SPIFFE X.509-SVID spec §2)",
					"agent_id":     "spiffe://trust-domain/agent/{attestor_type}/{node-id} - agent's SPIFFE ID",
					"trust_bundle": "Root CA certificates for the trust domain (SPIFFE Trust Domain and Bundle spec §4)",
					"svid_ttl":     "Agent SVID lifetime (typically 1 hour, auto-rotated)",
				},
				Security: []string{
					"Agent SVID is short-lived and automatically rotated before expiry",
					"The trust bundle enables the agent to verify SVIDs from other entities in the trust domain",
					"Agent's private key never leaves the agent process - only the CSR's public key was sent",
					"All subsequent agent-to-server communication uses mTLS with this SVID",
				},
			},
		},
	}
}

// getWorkloadAttestationFlow defines workload attestation
// This happens automatically when a workload requests an SVID via the Workload API
func getWorkloadAttestationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "workload-attestation",
		Name:        "Workload Attestation",
		Description: "Process by which the SPIRE Agent identifies a calling workload and determines which SPIFFE ID(s) to assign (SPIFFE Workload API spec §5). When a workload connects to the Workload API, the agent introspects the calling process using OS-level mechanisms (SO_PEERCRED on Linux), collects platform-specific selectors via Workload Attestor plugins, and matches them against cached registration entries. This is SPIFFE's zero-trust identity assignment - workloads cannot self-assert their identity.",
		Executable:  false, // Happens automatically - demonstrated via X.509-SVID flow
		Category:    "infrastructure",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Workload API Connection",
				Description: "Workload connects to the SPIRE Agent via the SPIFFE Workload API, a gRPC service exposed on a Unix Domain Socket (SPIFFE Workload API spec §3). The Unix socket provides two critical properties: local-only access (no network exposure) and automatic caller identification via the kernel's SO_PEERCRED mechanism, which reports the PID, UID, and GID of the connecting process without the process being able to forge these values.",
				From:        "Workload",
				To:          "SPIRE Agent",
				Type:        "request",
				Parameters: map[string]string{
					"socket_path":  "/run/spire/sockets/agent.sock (configurable, SPIFFE Workload API spec §3)",
					"protocol":     "gRPC over Unix Domain Socket",
					"peer_creds":   "Kernel provides PID, UID, GID of connecting process via SO_PEERCRED",
					"api_method":   "FetchX509SVID, FetchJWTSVID, or FetchX509Bundles",
				},
				Security: []string{
					"Unix Domain Socket is local-only - cannot be accessed from remote hosts",
					"SO_PEERCRED is a kernel facility - caller cannot forge PID/UID/GID information",
					"Socket file permissions (e.g., 0770) provide an additional access control layer",
					"No authentication is required from the workload - identity is determined by attestation",
				},
			},
			{
				Order:       2,
				Name:        "Process Introspection",
				Description: "The SPIRE Agent uses the PID from SO_PEERCRED to introspect the calling process. The agent reads process metadata from /proc/{pid} on Linux (or equivalent on other OSes) to determine the binary path, user, group, and other process attributes. These raw attributes are then passed to configured Workload Attestor plugins for platform-specific selector generation.",
				From:        "SPIRE Agent",
				To:          "Workload Attestor Plugins",
				Type:        "internal",
				Parameters: map[string]string{
					"pid":       "Process ID from SO_PEERCRED (kernel-verified, unforgeable)",
					"uid":       "User ID of the calling process",
					"gid":       "Group ID of the calling process",
					"exe_path":  "Executable binary path from /proc/{pid}/exe",
					"cmdline":   "Command line arguments from /proc/{pid}/cmdline",
					"cgroups":   "Control group membership from /proc/{pid}/cgroup (used by Docker/K8s attestors)",
				},
				Security: []string{
					"Agent MUST run with sufficient privileges to read /proc/{pid} of calling processes",
					"Multiple Workload Attestor plugins can run simultaneously for defense-in-depth",
					"PID reuse attacks are mitigated by atomic attestation within the gRPC request lifecycle",
				},
			},
			{
				Order:       3,
				Name:        "Selector Collection",
				Description: "Each configured Workload Attestor plugin examines the workload process and generates typed selectors - key:value pairs that describe the workload's identity from the platform's perspective. The unix attestor generates filesystem-level selectors, the Docker attestor queries the Docker daemon for container metadata, and the Kubernetes attestor resolves the pod identity from the kubelet. All selectors from all attestors are combined.",
				From:        "Workload Attestor Plugins",
				To:          "SPIRE Agent",
				Type:        "internal",
				Parameters: map[string]string{
					"unix_selectors":   "unix:uid:1000, unix:gid:1000, unix:path:/usr/bin/myapp (basic process identity)",
					"docker_selectors": "docker:label:app:myapp, docker:image_id:sha256:abc123, docker:env:ENV=production",
					"k8s_selectors":    "k8s:ns:default, k8s:sa:myapp-sa, k8s:pod-label:app:myapp, k8s:container-name:main",
					"combined":         "Union of all selectors from all active attestor plugins",
				},
				Security: []string{
					"Selectors are the basis of workload identity - more specific selectors mean stronger identity guarantees",
					"Docker selectors query the Docker daemon API - requires agent access to Docker socket",
					"Kubernetes selectors query the kubelet API - requires agent access to kubelet read-only port or API",
					"Combining unix + container selectors provides multi-layer identity verification",
				},
			},
			{
				Order:       4,
				Name:        "Registration Entry Matching",
				Description: "The agent matches the collected workload selectors against its cached registration entries. A registration entry matches when ALL of the entry's selectors are present in the workload's collected selectors (subset matching). If multiple registration entries match, the workload receives an SVID for each matching entry. If no entries match, the request is denied - this is SPIFFE's deny-by-default security model.",
				From:        "SPIRE Agent",
				To:          "Registration Cache",
				Type:        "internal",
				Parameters: map[string]string{
					"matching_algorithm": "Entry matches if entry.selectors ⊆ workload.selectors (all entry selectors present)",
					"multi_match":       "Multiple matching entries = multiple SVIDs returned to workload",
					"no_match":          "Zero matching entries = request denied (deny by default)",
					"parent_filter":     "Only entries where parent_id matches this agent's SPIFFE ID are considered",
				},
				Security: []string{
					"Deny by default: no registration entry match = no SVID issued",
					"Subset matching means broader selectors match more workloads - be specific",
					"Multiple SVIDs for one workload enable multi-identity patterns (e.g., service + database role)",
					"Agent's local registration cache is synced from server - consistent with global policy",
				},
			},
			{
				Order:       5,
				Name:        "Identity Assignment",
				Description: "The agent assigns the SPIFFE ID(s) from matching registration entries to the workload. The assigned identity is used to generate the requested credential type (X.509-SVID or JWT-SVID). The workload has no ability to choose or influence its identity - identity is entirely determined by the platform-verified selectors and administrator-defined registration entries. This is the core of SPIFFE's zero-trust model.",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"spiffe_id":  "spiffe://trust-domain/workload/path - from matching registration entry",
					"ttl":        "SVID lifetime from registration entry TTL (or server default)",
					"dns_names":  "DNS SANs from registration entry (for X.509-SVIDs)",
					"hint":       "Suggested name for workload to use when selecting among multiple SVIDs",
				},
				Security: []string{
					"Workloads CANNOT choose their own identity - it is assigned by the infrastructure",
					"Identity is bound to the workload process for the SVID lifetime only",
					"Re-attestation occurs on every SVID renewal - identity is continuously re-verified",
					"If a workload's selectors change (e.g., container restart with different labels), identity may change",
				},
			},
		},
	}
}

// getX509SVIDIssuanceFlow defines X.509-SVID issuance
// This flow is executable - it fetches a real X.509-SVID via the Workload API
func getX509SVIDIssuanceFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "x509-svid-issuance",
		Name:        "X.509-SVID Issuance",
		Description: "Acquire an X.509 certificate encoding a SPIFFE ID as a URI SAN via the Workload API (SPIFFE X.509-SVID spec §2). X.509-SVIDs are the primary credential type in SPIFFE, used for mTLS authentication between workloads. The SPIRE Agent generates the key pair, obtains a signed certificate from the SPIRE Server's CA, and delivers the complete credential set (certificate, private key, trust bundle) to the workload via the local Unix socket.",
		Executable:  true, // Uses real Workload API
		Category:    "workload-api",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "FetchX509SVID Request",
				Description: "Workload calls the FetchX509SVID RPC on the SPIFFE Workload API (SPIFFE Workload API spec §6.1). This is a server-streaming RPC - the initial response delivers the SVID immediately, and subsequent updates are pushed automatically when the certificate is rotated or the trust bundle changes. The workload's identity is determined by workload attestation, not by any parameter in the request.",
				From:        "Workload",
				To:          "SPIRE Agent",
				Type:        "request",
				Parameters: map[string]string{
					"api_method":    "SpiffeWorkloadAPI.FetchX509SVID (server-streaming gRPC, SPIFFE Workload API spec §6.1)",
					"connection":    "Unix Domain Socket (no TLS - local only, SPIFFE Workload API spec §3)",
					"security_header": "No authentication required - identity determined by workload attestation",
				},
				Security: []string{
					"Workload attestation (selector matching) determines which SVIDs are returned",
					"Streaming RPC means the workload receives automatic updates on rotation - no polling needed",
					"Request contains no identity claims - the workload cannot request a specific SPIFFE ID",
					"Multiple SVIDs may be returned if multiple registration entries match the workload",
				},
			},
			{
				Order:       2,
				Name:        "Key Pair Generation",
				Description: "SPIRE Agent generates a fresh asymmetric key pair for the workload's SVID using the configured Key Manager plugin. SPIRE supports EC P-256 (recommended for performance), EC P-384, and RSA 2048/4096 key types. The private key is generated and held by the agent - the workload's process never generates or handles raw key material during this step.",
				From:        "SPIRE Agent",
				To:          "Key Manager",
				Type:        "internal",
				Parameters: map[string]string{
					"algorithm":    "EC P-256 (RECOMMENDED by SPIFFE spec), EC P-384, RSA 2048, or RSA 4096",
					"key_id":       "Unique identifier for key lifecycle tracking",
					"key_storage":  "Memory (default, keys lost on restart) or Disk (persisted, encrypted)",
					"rotation":     "New key pair generated on each SVID renewal - forward secrecy",
				},
				Security: []string{
					"Private key is generated by the agent, not the workload - centralized key management",
					"EC P-256 is recommended for TLS performance and security balance",
					"Memory-backed keys are destroyed on agent restart - disk-backed keys survive restarts",
					"New key pair on every rotation provides forward secrecy - old keys cannot decrypt new traffic",
				},
			},
			{
				Order:       3,
				Name:        "CSR Submission to SPIRE Server",
				Description: "Agent creates a Certificate Signing Request (CSR) containing the workload's public key and submits it to the SPIRE Server via the Node API (BatchNewX509SVID RPC). The SPIFFE ID and DNS SANs are determined by the matching registration entry, not by the CSR - the server sets these values authoritatively. The agent authenticates to the server using its own agent SVID (mTLS).",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"csr":           "X.509 Certificate Signing Request with workload's public key",
					"spiffe_id":     "Set by server from registration entry (not in CSR, SPIFFE X.509-SVID spec §2)",
					"dns_names":     "DNS SANs from registration entry dns_names field (OPTIONAL)",
					"ttl_hint":      "Requested TTL from registration entry (server enforces maximum)",
					"entry_id":      "Registration entry ID that authorized this SVID",
				},
				Security: []string{
					"CSR contains ONLY the public key - SPIFFE ID is set server-side to prevent spoofing",
					"Agent-to-server communication uses mTLS with the agent's own SVID",
					"Server enforces maximum TTL per its configuration - agent hints may be reduced",
					"Batch API allows multiple SVIDs to be requested in a single RPC for efficiency",
				},
			},
			{
				Order:       4,
				Name:        "Certificate Signing by SPIRE CA",
				Description: "SPIRE Server's upstream Certificate Authority signs the certificate, embedding the SPIFFE ID as a URI SAN (Subject Alternative Name) in the format spiffe://trust-domain/workload/path (SPIFFE X.509-SVID spec §2). The certificate also includes key usage extensions (digitalSignature, keyEncipherment) and extended key usage (serverAuth, clientAuth) for mTLS. SPIRE supports built-in CA, upstream CA (e.g., Vault, AWS PCA), or disk-based CA.",
				From:        "SPIRE Server",
				To:          "Certificate Authority",
				Type:        "internal",
				Parameters: map[string]string{
					"issuer":         "SPIRE's signing CA (intermediate CA under the trust domain root)",
					"uri_san":        "spiffe://trust-domain/workload/path (REQUIRED, exactly one, SPIFFE X.509-SVID spec §2)",
					"dns_sans":       "Optional DNS names from registration entry",
					"serial_number":  "Unique serial number (cryptographically random, per RFC 5280 §4.1.2.2)",
					"not_before":     "Current time (with small backdate for clock skew)",
					"not_after":      "Current time + TTL (typically 1 hour, SPIFFE recommendation: short-lived)",
					"key_usage":      "digitalSignature, keyEncipherment (SPIFFE X.509-SVID spec §4.3)",
					"ext_key_usage":  "serverAuth, clientAuth (SPIFFE X.509-SVID spec §4.4)",
				},
				Security: []string{
					"X.509-SVID MUST contain exactly one URI SAN with the SPIFFE ID (spec §2)",
					"CA private key protection is critical - use HSM or upstream CA for production",
					"Short-lived certificates (1 hour default) reduce the impact of key compromise",
					"Certificate chain: workload SVID → SPIRE intermediate CA → trust domain root",
				},
			},
			{
				Order:       5,
				Name:        "SVID and Trust Bundle Delivery",
				Description: "Agent delivers the complete X.509-SVID credential set to the workload via the streaming gRPC response (SPIFFE Workload API spec §6.1). The response includes the signed certificate chain, the corresponding private key, and the trust bundle (root CAs for the trust domain, plus any federated trust domain bundles). The workload uses these to configure TLS listeners and clients.",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"x509_svid":       "Signed X.509 certificate chain (leaf + intermediate CA certificates)",
					"private_key":     "Private key corresponding to the SVID certificate (PEM-encoded)",
					"trust_bundle":    "Trust domain root CA certificates for verifying peer SVIDs",
					"federated_bundles": "Root CAs for federated trust domains (if federation is configured)",
					"spiffe_id":       "The SPIFFE ID encoded in the certificate's URI SAN",
					"hint":            "Suggested use label for workloads receiving multiple SVIDs",
				},
				Security: []string{
					"Private key is transmitted over the Unix socket (local only) - never over network",
					"Workload MUST use the trust bundle (not system CAs) for peer SVID verification",
					"Trust bundle updates are pushed automatically via the streaming RPC",
					"Workload should keep the streaming connection open for automatic rotation and bundle updates",
				},
			},
		},
	}
}

// getJWTSVIDIssuanceFlow defines JWT-SVID issuance
// This flow is executable - it fetches a real JWT-SVID via the Workload API
func getJWTSVIDIssuanceFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "jwt-svid-issuance",
		Name:        "JWT-SVID Issuance",
		Description: "Acquire a signed JWT token encoding a SPIFFE ID via the Workload API (SPIFFE JWT-SVID spec §2). JWT-SVIDs are an alternative to X.509-SVIDs designed for HTTP/gRPC-based authentication where presenting a client certificate is impractical (e.g., L7 proxies, API gateways). The workload specifies the intended audience, and SPIRE Server mints a signed JWT with the workload's SPIFFE ID as the subject. JWT-SVIDs are short-lived (typically 5 minutes) and audience-bound.",
		Executable:  true, // Uses real Workload API
		Category:    "workload-api",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "FetchJWTSVID Request",
				Description: "Workload calls the FetchJWTSVID RPC on the SPIFFE Workload API (SPIFFE Workload API spec §6.3). Unlike FetchX509SVID, this is a unary (non-streaming) RPC because JWT-SVIDs are short-lived and should be fetched fresh for each use. The workload MUST specify at least one audience to bind the token to the intended recipient service.",
				From:        "Workload",
				To:          "SPIRE Agent",
				Type:        "request",
				Parameters: map[string]string{
					"api_method":  "SpiffeWorkloadAPI.FetchJWTSVID (unary gRPC, SPIFFE Workload API spec §6.3)",
					"audience":    "REQUIRED - intended recipient service (e.g., spiffe://domain/backend or https://api.example.com)",
					"spiffe_id":   "OPTIONAL - requested SPIFFE ID (if workload has multiple, selects which to use)",
					"connection":  "Unix Domain Socket (local only, no TLS)",
				},
				Security: []string{
					"Audience parameter is REQUIRED - prevents token reuse at unintended services (JWT-SVID spec §3)",
					"Workload identity determined by attestation, same as X.509-SVID flow",
					"JWT-SVIDs should be fetched fresh per-request, not cached (they are intentionally short-lived)",
					"If the workload has multiple SVIDs, the spiffe_id parameter selects which identity to use",
				},
			},
			{
				Order:       2,
				Name:        "Agent Forwards to SPIRE Server",
				Description: "The SPIRE Agent forwards the JWT-SVID request to the SPIRE Server via the Node API (MintJWTSVID RPC), authenticating with its own agent SVID over mTLS. The agent includes the attested workload's SPIFFE ID (from registration entry matching) and the requested audience. JWT signing must be done server-side because the signing keys are held exclusively by the server.",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"spiffe_id":  "Workload's SPIFFE ID from registration entry matching (set by agent, not workload)",
					"audience":   "Forwarded from workload request - bound into the JWT 'aud' claim",
					"ttl":        "Requested TTL from registration entry configuration (server enforces maximum)",
					"entry_id":   "Registration entry that authorized this JWT-SVID",
				},
				Security: []string{
					"Agent-to-server mTLS ensures the request is from an authorized agent",
					"Server verifies the agent is authorized to request SVIDs for this SPIFFE ID",
					"JWT signing keys are held only by the SPIRE Server - never distributed to agents",
					"Server enforces maximum TTL regardless of what the agent requests",
				},
			},
			{
				Order:       3,
				Name:        "JWT-SVID Generation and Signing",
				Description: "SPIRE Server generates and signs the JWT according to the SPIFFE JWT-SVID specification (JWT-SVID spec §3). The JWT contains the workload's SPIFFE ID as the 'sub' claim, the requested audience(s) as the 'aud' claim, and a short expiration. The 'kid' header identifies the signing key for verifier key rotation. The signing key's public counterpart is available via the JWKS endpoint for verifiers.",
				From:        "SPIRE Server",
				To:          "JWT Signer",
				Type:        "internal",
				Parameters: map[string]string{
					"header.alg":  "ES256 (RECOMMENDED), ES384, ES512 (ECDSA) or RS256, RS384, RS512 (RSA) per JWT-SVID spec §3",
					"header.kid":  "Key identifier matching a key in the trust domain's JWKS (REQUIRED for key rotation)",
					"header.typ":  "JWT (REQUIRED, JWT-SVID spec §3)",
					"payload.sub": "SPIFFE ID: spiffe://trust-domain/workload/path (REQUIRED, JWT-SVID spec §3)",
					"payload.aud": "Intended recipient service identifier(s) (REQUIRED, may be array)",
					"payload.exp": "Expiration time as Unix timestamp (REQUIRED, typically now + 5 minutes)",
					"payload.iat": "Issued-at time as Unix timestamp (RECOMMENDED)",
					"payload.iss": "ABSENT - JWT-SVIDs do NOT use iss claim; trust is via JWKS bundle (JWT-SVID spec §3)",
				},
				Security: []string{
					"JWT-SVIDs intentionally omit the 'iss' claim - trust is established via JWKS bundles, not issuer identity",
					"ES256 (P-256 ECDSA) is recommended for compact tokens and strong security",
					"Expiration SHOULD be very short (5 minutes) - JWT-SVIDs are not meant to be long-lived",
					"kid header is essential for key rotation - verifiers use it to select the correct public key from JWKS",
				},
			},
			{
				Order:       4,
				Name:        "JWT-SVID Delivery to Workload",
				Description: "The signed JWT-SVID is returned to the workload through the agent via the Workload API response. The workload uses this token in HTTP Authorization headers (Bearer scheme) or gRPC metadata when calling the target service. The verifying service validates the JWT signature using the trust domain's JWKS bundle (available via the FetchJWTBundles Workload API RPC or SPIFFE Bundle Endpoint).",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"jwt_svid":   "Signed JWT token (compact serialization: header.payload.signature)",
					"spiffe_id":  "SPIFFE ID encoded in the 'sub' claim",
					"expiry":     "Token expiration time (from 'exp' claim)",
					"usage":      "Authorization: Bearer {jwt_svid} in HTTP headers or gRPC metadata",
				},
				Security: []string{
					"JWT-SVIDs should be used immediately and fetched fresh for each request (not cached long-term)",
					"Do NOT log JWT-SVIDs - they are bearer tokens that grant access to the audience service",
					"Verifiers MUST check: signature (via JWKS), sub (SPIFFE ID), aud (matches self), exp (not expired)",
					"Verifiers obtain JWKS bundles via FetchJWTBundles API or SPIFFE Bundle Endpoint (Trust Domain and Bundle spec §4.1)",
				},
			},
		},
	}
}

// getMTLSHandshakeFlow defines mTLS handshake with SPIFFE
// This flow is executable - it fetches real certificates and explains the mTLS process
func getMTLSHandshakeFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "mtls-handshake",
		Name:        "mTLS Handshake with X.509-SVIDs",
		Description: "Mutual TLS authentication between two workloads using X.509-SVIDs as client and server certificates (SPIFFE X.509-SVID spec §5). Both services present their SPIFFE-issued certificates and verify the peer's certificate against the SPIFFE trust bundle (not system CAs). After cryptographic verification, each side extracts the peer's SPIFFE ID from the URI SAN and performs authorization based on the identity. This provides authentication, encryption, and integrity in a single handshake.",
		Executable:  true, // Fetches real certs via Workload API
		Category:    "workload-api",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Client Hello",
				Description: "The client service initiates a TLS handshake by sending a ClientHello message to the server (RFC 8446 §4.1.2 for TLS 1.3). The ClientHello contains supported TLS versions, cipher suites, and extensions. For SPIFFE mTLS, TLS 1.3 is strongly recommended as it provides mandatory forward secrecy and a simplified handshake. The client's SVID is not sent yet - only after the server requests it.",
				From:        "Client Service",
				To:          "Server Service",
				Type:        "request",
				Parameters: map[string]string{
					"tls_version":    "TLS 1.3 (RECOMMENDED) or TLS 1.2 (RFC 8446 / RFC 5246)",
					"cipher_suites":  "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)",
					"supported_groups": "x25519, secp256r1, secp384r1 (for key exchange)",
					"extensions":     "supported_versions, signature_algorithms, server_name (SNI)",
				},
				Security: []string{
					"TLS 1.3 is strongly recommended - mandatory forward secrecy and faster handshake",
					"TLS 1.2 MUST use ECDHE cipher suites for forward secrecy (avoid RSA key exchange)",
					"SNI extension may reveal the target service name in cleartext (encrypted in TLS 1.3 ECH)",
				},
			},
			{
				Order:       2,
				Name:        "Server Presents X.509-SVID",
				Description: "Server responds with its X.509-SVID certificate chain in the Certificate message (RFC 8446 §4.4.2). The server's SVID contains its SPIFFE ID as a URI SAN (e.g., spiffe://trust-domain/server). The certificate chain includes the leaf SVID and any intermediate CA certificates leading to the trust domain root. In TLS 1.3, this is followed by CertificateVerify proving possession of the private key.",
				From:        "Server Service",
				To:          "Client Service",
				Type:        "response",
				Parameters: map[string]string{
					"certificate":       "Server's X.509-SVID leaf certificate",
					"certificate_chain": "Intermediate CA certificates (SPIRE intermediate CA → root)",
					"uri_san":           "spiffe://trust-domain/server/path (SPIFFE ID in SAN, X.509-SVID spec §2)",
					"certificate_verify": "Signature proving server holds the private key (TLS 1.3, RFC 8446 §4.4.3)",
				},
				Security: []string{
					"SPIFFE ID is encoded as a URI SAN - this is the server's identity claim",
					"Certificate chain must be verifiable against the SPIFFE trust bundle",
					"CertificateVerify (TLS 1.3) proves the server possesses the private key matching the certificate",
				},
			},
			{
				Order:       3,
				Name:        "Server Requests Client Certificate",
				Description: "Server sends a CertificateRequest message requiring the client to present its own X.509-SVID (RFC 8446 §4.3.2). This is what makes the handshake 'mutual' - both sides authenticate. The server includes its trust bundle CAs in the certificate_authorities extension to indicate which CAs it trusts. Only SVIDs signed by these CAs will be accepted.",
				From:        "Server Service",
				To:          "Client Service",
				Type:        "request",
				Parameters: map[string]string{
					"certificate_request":   "TLS CertificateRequest message (RFC 8446 §4.3.2)",
					"certificate_authorities": "Trust bundle root CAs the server accepts (SPIFFE trust bundle CAs)",
					"signature_algorithms":  "Acceptable signature algorithms for client certificate",
				},
				Security: []string{
					"Mutual TLS requires BOTH sides to present certificates - not just the server",
					"Server advertises its trust bundle CAs - client must present an SVID signed by one of these",
					"In SPIFFE, the trust bundle replaces traditional CA trust stores for peer verification",
				},
			},
			{
				Order:       4,
				Name:        "Client Presents X.509-SVID",
				Description: "Client responds with its own X.509-SVID certificate chain, proving its workload identity to the server (RFC 8446 §4.4.2). The client's SVID contains its SPIFFE ID as a URI SAN (e.g., spiffe://trust-domain/client). The client also sends CertificateVerify to prove possession of the private key. Both services now have each other's SPIFFE identity claims.",
				From:        "Client Service",
				To:          "Server Service",
				Type:        "response",
				Parameters: map[string]string{
					"certificate":       "Client's X.509-SVID leaf certificate",
					"certificate_chain": "Intermediate CA certificates to trust domain root",
					"uri_san":           "spiffe://trust-domain/client/path (client's SPIFFE ID)",
					"certificate_verify": "Signature proving client holds the private key",
				},
				Security: []string{
					"Client's SPIFFE ID proves the workload's identity as attested by SPIRE",
					"Private key proof prevents certificate replay (someone presenting a stolen cert without the key)",
					"Both sides now have cryptographic proof of each other's SPIFFE identity",
				},
			},
			{
				Order:       5,
				Name:        "Mutual Certificate Verification",
				Description: "Both services verify the peer's X.509-SVID against the SPIFFE trust bundle (X.509-SVID spec §5). Verification MUST use the SPIFFE trust bundle, NOT the system CA store - SPIFFE operates its own PKI independent of public CAs. Each side validates: certificate chain to a trusted root, certificate not expired, the URI SAN contains a valid SPIFFE ID in the expected trust domain. Federated trust bundles enable cross-domain verification.",
				From:        "Both Services",
				To:          "Trust Bundle",
				Type:        "internal",
				Parameters: map[string]string{
					"chain_validation":   "Verify certificate chain from leaf → intermediate CA → trust bundle root (RFC 5280 §6)",
					"expiry_check":       "Verify NotBefore ≤ now ≤ NotAfter on all certificates in chain",
					"uri_san_validation": "Extract URI SAN, verify it starts with spiffe:// and matches expected trust domain",
					"trust_domain_check": "SPIFFE ID trust domain MUST match one of: local trust domain or federated trust domains",
					"revocation_check":   "Optional CRL/OCSP checking (SPIFFE recommendation: use short-lived certs instead)",
				},
				Security: []string{
					"CRITICAL: Use SPIFFE trust bundle, NOT system CAs - SPIFFE has its own PKI",
					"Verify the trust domain in the SPIFFE ID matches your configuration (prevents cross-domain attacks)",
					"Short-lived SVIDs (1 hour) make traditional revocation (CRL/OCSP) less necessary",
					"Federated trust bundles enable verification of SVIDs from different SPIFFE trust domains",
				},
			},
			{
				Order:       6,
				Name:        "SPIFFE ID Authorization",
				Description: "After cryptographic verification, each side extracts the peer's SPIFFE ID from the URI SAN and applies authorization policy (X.509-SVID spec §5). Authentication (TLS handshake) answers 'who is this?' while authorization answers 'are they allowed to do this?'. Authorization policies can match exact SPIFFE IDs, trust domain membership, or path patterns. This is application-level logic, not part of TLS.",
				From:        "Server Service",
				To:          "Authorization Policy",
				Type:        "internal",
				Parameters: map[string]string{
					"peer_spiffe_id":  "Extracted from peer certificate URI SAN (e.g., spiffe://domain/frontend)",
					"allowed_ids":     "Exact SPIFFE ID match (e.g., spiffe://domain/frontend)",
					"allowed_patterns": "Path-based patterns (e.g., spiffe://domain/team-a/*)",
					"allowed_domains": "Trust domain membership (e.g., any ID in spiffe://partner-domain/...)",
					"action":          "Allow or deny the request based on policy evaluation",
				},
				Security: []string{
					"Authentication (TLS) and authorization (policy) are separate concerns - both are required",
					"Deny by default: if no authorization policy matches, reject the connection",
					"Log all authorization decisions (allow and deny) for security audit",
					"Authorization policies should follow least-privilege: allow only specific needed identities",
				},
			},
			{
				Order:       7,
				Name:        "Encrypted Channel Established",
				Description: "The TLS handshake completes successfully with mutual authentication. Both services have verified each other's SPIFFE identity and the TLS session keys are derived. All subsequent communication over this connection is encrypted, integrity-protected, and authenticated. TLS 1.3 provides forward secrecy via ephemeral key exchange - compromising a long-term key does not compromise past sessions.",
				From:        "Client Service",
				To:          "Server Service",
				Type:        "internal",
				Parameters: map[string]string{
					"session_keys":    "Symmetric keys derived from handshake key exchange (unique per session)",
					"cipher":          "Negotiated AEAD cipher (e.g., AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)",
					"forward_secrecy": "Ephemeral ECDHE keys ensure past sessions remain secure if long-term keys are compromised",
					"mutual_auth":     "Both peer SPIFFE IDs verified - connection is mutually authenticated",
				},
				Security: []string{
					"All subsequent traffic is encrypted and integrity-protected by TLS",
					"Forward secrecy (TLS 1.3 mandatory, TLS 1.2 with ECDHE) protects past communications",
					"Session keys are unique per connection - no key reuse across connections",
					"When SVIDs are rotated, new connections use the new certificate while existing connections continue",
				},
			},
		},
	}
}

// getCertificateRotationFlow defines automatic certificate rotation
// This flow is executable - it analyzes the current SVID and explains rotation
func getCertificateRotationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "certificate-rotation",
		Name:        "Automatic Certificate Rotation",
		Description: "SPIRE's automatic X.509-SVID rotation mechanism that continuously renews workload certificates before they expire, ensuring zero-downtime cryptographic identity refresh (SPIFFE X.509-SVID spec §4.1). The SPIRE Agent proactively monitors SVID lifetimes and triggers renewal at a configurable threshold (typically 50% of lifetime). New SVIDs are delivered to workloads via the streaming Workload API, enabling graceful transition without service interruption. This eliminates the manual certificate management that plagues traditional PKI deployments.",
		Executable:  true, // Fetches real SVID to analyze
		Category:    "workload-api",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "SVID Lifetime Monitoring",
				Description: "The SPIRE Agent continuously monitors the remaining lifetime of all cached X.509-SVIDs. When an SVID reaches the rotation threshold (configurable, default 50% of total lifetime), the agent initiates proactive renewal. For a 1-hour SVID, rotation begins at the 30-minute mark - well before expiration. The agent also monitors the trust bundle for CA key rotation events from the SPIRE Server.",
				From:        "SPIRE Agent",
				To:          "SVID Cache",
				Type:        "internal",
				Parameters: map[string]string{
					"check_interval":      "Periodic check (configurable, typically every 5-30 seconds)",
					"rotation_threshold":  "Percentage of SVID lifetime at which to begin renewal (default: 50%)",
					"svid_ttl":            "Total SVID lifetime (e.g., 1 hour = renewal at 30 minutes remaining)",
					"backoff_on_failure":  "Exponential backoff if server is unreachable during rotation",
				},
				Security: []string{
					"Early rotation ensures SVIDs are renewed well before expiration - no gap in identity",
					"Rotation threshold should leave enough time for retry on failure (50% is conservative)",
					"Agent handles clock skew between agent and server gracefully",
					"If the server is unreachable, agent retries with backoff while continuing to serve cached SVIDs",
				},
			},
			{
				Order:       2,
				Name:        "Fresh Key Pair and CSR",
				Description: "When rotation is triggered, the SPIRE Agent generates a completely new asymmetric key pair and creates a fresh CSR. The new key pair provides forward secrecy - even if the old private key was somehow compromised, the new SVID uses independent key material. The old SVID remains in use for existing connections while the new one is being obtained.",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"new_csr":          "Fresh Certificate Signing Request with new public key",
					"new_key_pair":     "Freshly generated EC P-256 or RSA key pair (not reused from previous SVID)",
					"entry_id":         "Registration entry ID for this workload identity",
					"agent_auth":       "Agent authenticates to server using its own (still valid) agent SVID via mTLS",
				},
				Security: []string{
					"New key pair on every rotation provides forward secrecy - old keys are discarded",
					"The old SVID continues serving existing connections until the new one is ready",
					"Agent uses its own SVID (separately rotated) for mTLS authentication to the server",
					"If key generation fails, the agent retries - the old SVID remains valid during retries",
				},
			},
			{
				Order:       3,
				Name:        "New SVID Issuance",
				Description: "The SPIRE Server signs the new CSR to produce a fresh X.509-SVID with the same SPIFFE ID but a new serial number, new validity period, and new public key. If the trust bundle has changed (e.g., CA key rotation), the updated bundle is included in the response. The server may also re-verify that the registration entry is still active before signing.",
				From:        "SPIRE Server",
				To:          "SPIRE Agent",
				Type:        "response",
				Parameters: map[string]string{
					"new_x509_svid":    "Freshly signed X.509-SVID certificate with new validity period",
					"new_serial":       "New unique serial number (different from previous SVID)",
					"new_not_before":   "Current time (with backdate for clock skew)",
					"new_not_after":    "Current time + TTL (fresh full lifetime)",
					"updated_bundle":   "Trust bundle if CA keys have rotated (empty if unchanged)",
				},
				Security: []string{
					"New SVID has a fresh full lifetime - no accumulated clock drift from previous SVID",
					"Serial number changes ensure old and new SVIDs are distinguishable",
					"Trust bundle updates are critical for CA key rotation - workloads must receive updated CAs",
					"Server may reject renewal if the registration entry was deleted (identity revocation)",
				},
			},
			{
				Order:       4,
				Name:        "Workload SVID Update via Streaming API",
				Description: "The SPIRE Agent delivers the new SVID, new private key, and any trust bundle updates to the workload via the existing FetchX509SVID streaming gRPC connection (SPIFFE Workload API spec §6.1). Because the workload keeps the streaming connection open, updates are pushed immediately - the workload does not need to poll. Libraries like go-spiffe and java-spiffe handle this transparently.",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"new_svid":          "New X.509-SVID certificate chain",
					"new_private_key":   "New private key matching the new certificate",
					"updated_bundle":    "Updated trust bundle (if CA rotation occurred)",
					"delivery_method":   "Push via streaming gRPC (no polling, no restart required)",
				},
				Security: []string{
					"Streaming delivery is immediate - no delay between agent receiving new SVID and workload receiving it",
					"New private key is transmitted via Unix socket only (local, not over network)",
					"Workload libraries (go-spiffe, java-spiffe) handle certificate updates automatically",
					"If the streaming connection drops, the workload must reconnect to receive future updates",
				},
			},
			{
				Order:       5,
				Name:        "Graceful TLS Transition",
				Description: "The workload atomically updates its TLS configuration to use the new SVID and private key. New TLS connections (both inbound and outbound) use the new certificate, while existing in-flight connections continue using the old certificate until they naturally close. Both old and new SVIDs are valid simultaneously during this overlap period, ensuring zero service disruption.",
				From:        "Workload",
				To:          "TLS Stack",
				Type:        "internal",
				Parameters: map[string]string{
					"new_connections":    "Use new SVID certificate and private key",
					"existing_connections": "Continue with old certificate until natural close (no disruption)",
					"overlap_period":     "Old and new SVIDs are both valid during transition (old has remaining lifetime)",
					"atomic_update":      "TLS config update is atomic - no window where neither cert is configured",
					"old_key_cleanup":    "Old private key is securely zeroed from memory after transition",
				},
				Security: []string{
					"Zero-downtime rotation: no service disruption, no dropped connections",
					"Overlap period where both certs are valid ensures smooth transition for long-lived connections",
					"Old private key material SHOULD be securely erased from memory after successful rotation",
					"SPIFFE libraries handle atomic TLS config swap - application code does not manage certificates",
				},
			},
		},
	}
}

// getTrustBundleFederationFlow defines federation between trust domains
// This is an administrative process that requires SPIRE Server configuration
func getTrustBundleFederationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "trust-bundle-federation",
		Name:        "Trust Domain Federation",
		Description: "Establish mutual trust between independent SPIFFE trust domains by exchanging trust bundles (SPIFFE Trust Domain and Bundle spec §5). Federation enables workloads in different organizations or environments to authenticate each other using mTLS, without sharing a common CA. Each domain publishes its trust bundle (root CA certificates) via a Bundle Endpoint, and peer domains fetch and cache these bundles. This enables zero-trust cross-domain service mesh communication.",
		Executable:  false, // Admin process - requires SPIRE Server API access
		Category:    "admin",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Configure Federation Relationship",
				Description: "Administrator configures a federation relationship on the local SPIRE Server, specifying the foreign trust domain and how to fetch its trust bundle (SPIFFE Trust Domain and Bundle spec §5). SPIRE supports two endpoint profiles: 'https_spiffe' (mutual SPIFFE authentication of the bundle endpoint itself) and 'https_web' (standard Web PKI TLS for initial bootstrap). The https_web profile is typically used for initial federation setup.",
				From:        "Admin",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"trust_domain":         "Foreign trust domain name (e.g., partner.example.com)",
					"bundle_endpoint_url":  "URL to fetch the foreign bundle (e.g., https://spire.partner.example.com:8443/bundle)",
					"endpoint_profile":     "https_spiffe (mTLS with SPIFFE) or https_web (Web PKI TLS for bootstrap)",
					"endpoint_spiffe_id":   "Expected SPIFFE ID of the bundle endpoint server (for https_spiffe profile)",
					"bundle_refresh_hint":  "How often to re-fetch the foreign bundle (e.g., 300s)",
				},
				Security: []string{
					"Federation is an explicit trust decision - only federate with verified partner domains",
					"https_spiffe profile provides strongest security (mutual SPIFFE auth) but requires bootstrap",
					"https_web profile uses Web PKI for initial trust establishment (suitable for first-time setup)",
					"Bundle endpoint URL MUST use HTTPS - never fetch trust bundles over unencrypted HTTP",
				},
			},
			{
				Order:       2,
				Name:        "Fetch Foreign Trust Bundle",
				Description: "The local SPIRE Server fetches the foreign trust domain's bundle from the configured Bundle Endpoint (SPIFFE Trust Domain and Bundle spec §4.1). The bundle is a JWKS (JSON Web Key Set) document containing the foreign domain's root CA public keys with x5c (X.509 certificate chain) parameters. For the https_spiffe profile, the bundle endpoint itself is authenticated using SPIFFE mTLS. For https_web, standard Web PKI TLS is used.",
				From:        "SPIRE Server",
				To:          "Foreign SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"endpoint":     "GET https://foreign-server:8443/.well-known/spiffe-bundle (standard path) or custom URL",
					"format":       "JWKS (JSON Web Key Set) with x5c parameter containing X.509 CA certificates",
					"content_type": "application/json (SPIFFE Trust Domain and Bundle spec §4.1)",
					"authentication": "https_spiffe: mTLS with SPIFFE SVIDs | https_web: Web PKI TLS certificates",
				},
				Security: []string{
					"Verify TLS certificate of the bundle endpoint to prevent man-in-the-middle attacks",
					"For https_spiffe, verify the endpoint's SPIFFE ID matches the configured endpoint_spiffe_id",
					"Bundle content is the foreign domain's root CA public keys - these define what SVIDs you'll trust",
					"Parse and validate the JWKS structure before trusting the contained certificates",
				},
			},
			{
				Order:       3,
				Name:        "Store Foreign Bundle in Datastore",
				Description: "The local SPIRE Server persists the foreign trust bundle in its datastore, separate from the local trust domain's bundle. The foreign bundle is tagged with the trust domain name and a refresh hint indicating when to re-fetch. On subsequent refreshes, the server detects CA key rotations in the foreign domain and updates the stored bundle accordingly.",
				From:        "SPIRE Server",
				To:          "Datastore",
				Type:        "internal",
				Parameters: map[string]string{
					"bundle_type":    "foreign (distinct from local trust domain bundle)",
					"trust_domain":   "Foreign trust domain name (e.g., partner.example.com)",
					"refresh_hint":   "Seconds until next fetch (from bundle endpoint or admin config)",
					"ca_certificates": "Foreign domain's root CA X.509 certificates (from JWKS x5c)",
					"last_fetched":   "UTC timestamp of last successful bundle fetch",
				},
				Security: []string{
					"Foreign bundles are stored separately from the local trust domain bundle",
					"Periodic refresh ensures CA key rotations in the foreign domain are picked up promptly",
					"Stale bundles (failed refresh) should trigger alerts - they may miss CA rotations",
					"Removing a federation relationship deletes the foreign bundle and revokes cross-domain trust",
				},
			},
			{
				Order:       4,
				Name:        "Distribute Federated Bundles to Agents",
				Description: "The local SPIRE Server distributes the foreign trust bundle to all SPIRE Agents via the Node API cache sync. Agents include federated bundles alongside the local trust bundle when delivering credentials to workloads via the FetchX509SVID and FetchX509Bundles Workload API RPCs. Workloads receive the federated bundles automatically via their streaming connection.",
				From:        "SPIRE Server",
				To:          "SPIRE Agents",
				Type:        "response",
				Parameters: map[string]string{
					"local_bundle":      "Local trust domain root CA certificates",
					"federated_bundles": "Map of {trust_domain → root CA certificates} for each federated domain",
					"delivery_method":   "Streamed via Node API cache sync (same mechanism as registration entries)",
				},
				Security: []string{
					"Agents and workloads receive federated bundles automatically - no manual configuration needed",
					"Workloads use federated bundles to verify X.509-SVIDs from foreign trust domains during mTLS",
					"Bundle updates (CA rotation) propagate from server → agents → workloads via streaming APIs",
					"Only registration entries marked for federation will receive federated bundles (if configured)",
				},
			},
			{
				Order:       5,
				Name:        "Cross-Domain mTLS Authentication",
				Description: "With federated trust bundles in place, workloads from different SPIFFE trust domains can now authenticate each other using mTLS. Each side presents its own X.509-SVID and verifies the peer's SVID against the appropriate federated trust bundle. The local workload verifies the foreign SVID's certificate chain against the foreign trust bundle, and vice versa. Authorization policies can then be applied based on the peer's SPIFFE ID and trust domain.",
				From:        "Local Workload",
				To:          "Foreign Workload",
				Type:        "request",
				Parameters: map[string]string{
					"local_svid":          "spiffe://local-domain/service-a (presented to foreign workload)",
					"foreign_svid":        "spiffe://foreign-domain/service-b (received from foreign workload)",
					"local_verification":  "Verify foreign SVID against federated bundle for foreign-domain",
					"foreign_verification": "Foreign workload verifies local SVID against their copy of local-domain's bundle",
				},
				Security: []string{
					"Trust is explicit and bilateral - both domains must configure federation with each other",
					"Each domain maintains its own independent CA - no shared key material",
					"Cross-domain authorization should be more restrictive than intra-domain (zero trust)",
					"Removing federation on either side immediately breaks cross-domain authentication",
				},
			},
		},
	}
}

