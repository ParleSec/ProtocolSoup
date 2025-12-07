package spiffe

import "github.com/security-showcase/protocol-showcase/internal/plugin"

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
func getWorkloadRegistrationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "workload-registration",
		Name:        "Workload Registration",
		Description: "Process of registering a workload identity with SPIRE Server",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Create Registration Entry",
				Description: "Administrator creates a registration entry mapping selectors to SPIFFE ID",
				From:        "Admin",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"spiffe_id":  "spiffe://trust-domain/workload/path",
					"parent_id":  "spiffe://trust-domain/agent/node",
					"selectors":  "docker:label:app:myapp",
					"ttl":        "3600",
					"dns_names":  "myapp.svc.cluster.local",
					"downstream": "false",
				},
				Security: []string{
					"Only authorized administrators should create registration entries",
					"Use least-privilege when assigning SPIFFE IDs",
					"Selectors should be specific enough to prevent impersonation",
				},
			},
			{
				Order:       2,
				Name:        "Entry Storage",
				Description: "SPIRE Server stores registration entry in datastore",
				From:        "SPIRE Server",
				To:          "Datastore",
				Type:        "internal",
				Parameters: map[string]string{
					"entry_id":    "auto-generated UUID",
					"created_at":  "timestamp",
					"admin_id":    "creator identity",
					"entry_state": "active",
				},
				Security: []string{
					"Registration entries are persisted to prevent loss",
					"Entries can be audited and revoked",
				},
			},
			{
				Order:       3,
				Name:        "Agent Sync",
				Description: "SPIRE Agents receive updated registration entries",
				From:        "SPIRE Server",
				To:          "SPIRE Agent",
				Type:        "response",
				Parameters: map[string]string{
					"sync_type": "streaming or polling",
					"entries":   "relevant registration entries",
				},
				Security: []string{
					"Agents only receive entries for their node",
					"Sync is authenticated and encrypted",
				},
			},
		},
	}
}

// getNodeAttestationFlow defines the node attestation process
func getNodeAttestationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "node-attestation",
		Name:        "Node Attestation",
		Description: "Process by which SPIRE Agent proves its identity to SPIRE Server",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Agent Startup",
				Description: "SPIRE Agent starts and initiates attestation",
				From:        "SPIRE Agent",
				To:          "Node Attestor Plugin",
				Type:        "internal",
				Parameters: map[string]string{
					"attestor_type": "join_token, aws_iid, gcp_iit, k8s_psat, x509pop",
				},
				Security: []string{
					"Agent should use secure attestation method appropriate for environment",
				},
			},
			{
				Order:       2,
				Name:        "Attestation Data Collection",
				Description: "Attestor plugin collects node-specific proof of identity",
				From:        "Node Attestor Plugin",
				To:          "SPIRE Agent",
				Type:        "internal",
				Parameters: map[string]string{
					"join_token":        "one-time token (if using join_token)",
					"aws_instance_doc":  "signed instance identity document (if using aws_iid)",
					"gcp_identity_token": "GCP identity token (if using gcp_iit)",
					"k8s_service_token": "Kubernetes projected service account token (if using k8s_psat)",
				},
				Security: []string{
					"Join tokens are single-use and should be securely provisioned",
					"Cloud attestation relies on platform security",
				},
			},
			{
				Order:       3,
				Name:        "Attestation Request",
				Description: "Agent sends attestation request to SPIRE Server",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"attestation_data": "proof from attestor plugin",
					"csr":              "certificate signing request for agent SVID",
				},
				Security: []string{
					"Request is made over TLS (bootstrap or previously established trust)",
					"CSR contains agent's public key",
				},
			},
			{
				Order:       4,
				Name:        "Server Verification",
				Description: "SPIRE Server verifies attestation data",
				From:        "SPIRE Server",
				To:          "Server Node Attestor",
				Type:        "internal",
				Parameters: map[string]string{
					"verification_method": "token lookup, signature verification, API call",
				},
				Security: []string{
					"Server validates attestation data cryptographically or via trusted API",
					"Failed attestation results in rejection",
				},
			},
			{
				Order:       5,
				Name:        "Agent SVID Issuance",
				Description: "Server issues agent SVID and returns trust bundle",
				From:        "SPIRE Server",
				To:          "SPIRE Agent",
				Type:        "response",
				Parameters: map[string]string{
					"agent_svid":   "X.509 certificate with agent SPIFFE ID",
					"trust_bundle": "root CA certificates for trust domain",
					"agent_id":     "spiffe://trust-domain/agent/node-id",
				},
				Security: []string{
					"Agent SVID is short-lived and automatically rotated",
					"Trust bundle enables verification of other SVIDs",
				},
			},
		},
	}
}

// getWorkloadAttestationFlow defines workload attestation
func getWorkloadAttestationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "workload-attestation",
		Name:        "Workload Attestation",
		Description: "Process by which SPIRE Agent identifies workloads and assigns SPIFFE IDs",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Workload API Connection",
				Description: "Workload connects to SPIRE Agent via Unix Domain Socket",
				From:        "Workload",
				To:          "SPIRE Agent",
				Type:        "request",
				Parameters: map[string]string{
					"socket_path": "/run/spire/sockets/agent.sock",
					"protocol":    "gRPC",
				},
				Security: []string{
					"Socket file permissions restrict access",
					"Connection provides process information via SO_PEERCRED",
				},
			},
			{
				Order:       2,
				Name:        "Process Introspection",
				Description: "Agent inspects the calling process",
				From:        "SPIRE Agent",
				To:          "Workload Attestor Plugins",
				Type:        "internal",
				Parameters: map[string]string{
					"pid":      "process ID from socket",
					"uid":      "user ID",
					"gid":      "group ID",
					"exe_path": "executable path",
				},
				Security: []string{
					"Agent runs with privileges to inspect processes",
					"Multiple attestors can be combined",
				},
			},
			{
				Order:       3,
				Name:        "Selector Collection",
				Description: "Attestor plugins collect selectors about the workload",
				From:        "Workload Attestor Plugins",
				To:          "SPIRE Agent",
				Type:        "internal",
				Parameters: map[string]string{
					"unix_selectors":   "uid:1000, gid:1000, path:/usr/bin/app",
					"docker_selectors": "docker:label:app:myapp, docker:image_id:sha256:...",
					"k8s_selectors":    "k8s:ns:default, k8s:sa:myapp, k8s:pod-label:app:myapp",
				},
				Security: []string{
					"Selectors provide defense-in-depth for identity",
					"More specific selectors reduce impersonation risk",
				},
			},
			{
				Order:       4,
				Name:        "Registration Entry Matching",
				Description: "Agent matches selectors against registration entries",
				From:        "SPIRE Agent",
				To:          "Registration Cache",
				Type:        "internal",
				Parameters: map[string]string{
					"matching_algorithm": "all selectors must match entry selectors",
					"result":             "matched SPIFFE ID or rejection",
				},
				Security: []string{
					"No match means no SVID - deny by default",
					"Multiple matches may result in multiple SVIDs",
				},
			},
			{
				Order:       5,
				Name:        "Identity Assignment",
				Description: "Workload is assigned SPIFFE ID from matching entry",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"spiffe_id": "spiffe://trust-domain/workload/path",
					"ttl":       "from registration entry",
				},
				Security: []string{
					"Identity is bound to workload for the SVID lifetime",
					"Workload cannot choose its own identity",
				},
			},
		},
	}
}

// getX509SVIDIssuanceFlow defines X.509-SVID issuance
func getX509SVIDIssuanceFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "x509-svid-issuance",
		Name:        "X.509-SVID Issuance",
		Description: "Process of issuing an X.509 certificate containing a SPIFFE ID",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "FetchX509SVID Request",
				Description: "Workload requests X.509-SVID from agent via Workload API",
				From:        "Workload",
				To:          "SPIRE Agent",
				Type:        "request",
				Parameters: map[string]string{
					"api_method": "FetchX509SVID (streaming)",
				},
				Security: []string{
					"Request is local via Unix socket",
					"Workload attestation determines eligibility",
				},
			},
			{
				Order:       2,
				Name:        "Key Generation",
				Description: "Agent generates key pair for workload",
				From:        "SPIRE Agent",
				To:          "Key Manager",
				Type:        "internal",
				Parameters: map[string]string{
					"algorithm":  "EC P-256 or RSA 2048",
					"key_id":     "unique identifier",
					"storage":    "memory or disk",
				},
				Security: []string{
					"Private key never leaves the agent",
					"Key material is protected in memory",
				},
			},
			{
				Order:       3,
				Name:        "CSR Creation",
				Description: "Agent creates Certificate Signing Request",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"spiffe_id":    "from registration entry",
					"public_key":   "from generated key pair",
					"dns_names":    "optional DNS SANs",
					"ttl_hint":     "requested TTL",
				},
				Security: []string{
					"CSR contains only public key",
					"SPIFFE ID is set by server, not requested",
				},
			},
			{
				Order:       4,
				Name:        "Certificate Signing",
				Description: "SPIRE Server signs the certificate",
				From:        "SPIRE Server",
				To:          "Certificate Authority",
				Type:        "internal",
				Parameters: map[string]string{
					"issuer":      "SPIRE intermediate or root CA",
					"validity":    "per server configuration",
					"serial":      "unique serial number",
					"extensions":  "SPIFFE URI SAN, key usage",
				},
				Security: []string{
					"CA private key is protected",
					"Short-lived certificates reduce compromise impact",
				},
			},
			{
				Order:       5,
				Name:        "Certificate Delivery",
				Description: "Signed certificate returned to workload",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"x509_svid":    "signed X.509 certificate",
					"private_key":  "corresponding private key",
					"trust_bundle": "CA certificates for verification",
					"hint":         "suggested renewal time",
				},
				Security: []string{
					"Private key transmitted securely to workload",
					"Trust bundle enables peer verification",
				},
			},
		},
	}
}

// getJWTSVIDIssuanceFlow defines JWT-SVID issuance
func getJWTSVIDIssuanceFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "jwt-svid-issuance",
		Name:        "JWT-SVID Issuance",
		Description: "Process of issuing a JWT token containing a SPIFFE ID",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "FetchJWTSVID Request",
				Description: "Workload requests JWT-SVID with target audience",
				From:        "Workload",
				To:          "SPIRE Agent",
				Type:        "request",
				Parameters: map[string]string{
					"api_method": "FetchJWTSVID",
					"audience":   "intended recipient identifier",
				},
				Security: []string{
					"Audience prevents token reuse at unintended services",
					"Workload must be attested first",
				},
			},
			{
				Order:       2,
				Name:        "JWT Request to Server",
				Description: "Agent requests JWT-SVID from SPIRE Server",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"spiffe_id": "from registration entry",
					"audience":  "from workload request",
					"ttl":       "from configuration",
				},
				Security: []string{
					"Request authenticated with agent SVID",
					"Server enforces authorization",
				},
			},
			{
				Order:       3,
				Name:        "JWT Generation",
				Description: "Server generates and signs JWT",
				From:        "SPIRE Server",
				To:          "JWT Signer",
				Type:        "internal",
				Parameters: map[string]string{
					"header_alg": "RS256 or ES256",
					"header_kid": "key identifier for rotation",
					"header_typ": "JWT",
					"claim_sub":  "SPIFFE ID",
					"claim_aud":  "audience(s)",
					"claim_exp":  "expiration time",
					"claim_iat":  "issued at time",
				},
				Security: []string{
					"Short expiration (typically 5 minutes)",
					"Key ID enables key rotation",
				},
			},
			{
				Order:       4,
				Name:        "JWT Delivery",
				Description: "Signed JWT-SVID returned to workload",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"jwt_svid": "signed JWT token",
					"spiffe_id": "SPIFFE ID in token",
					"expiry":   "token expiration time",
				},
				Security: []string{
					"Token should be used immediately",
					"Do not log or persist JWT-SVIDs",
				},
			},
		},
	}
}

// getMTLSHandshakeFlow defines mTLS handshake with SPIFFE
func getMTLSHandshakeFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "mtls-handshake",
		Name:        "mTLS Handshake with X.509-SVIDs",
		Description: "Mutual TLS authentication between services using SPIFFE identities",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Client Hello",
				Description: "Client initiates TLS connection",
				From:        "Client Service",
				To:          "Server Service",
				Type:        "request",
				Parameters: map[string]string{
					"tls_version":   "TLS 1.2 or 1.3",
					"cipher_suites": "supported ciphers",
					"extensions":    "SNI, ALPN",
				},
				Security: []string{
					"Use TLS 1.3 when possible",
					"Strong cipher suites only",
				},
			},
			{
				Order:       2,
				Name:        "Server Certificate",
				Description: "Server presents X.509-SVID certificate",
				From:        "Server Service",
				To:          "Client Service",
				Type:        "response",
				Parameters: map[string]string{
					"certificate":   "server X.509-SVID",
					"chain":         "intermediate CA certificates",
					"spiffe_id_san": "spiffe://domain/server in SAN URI",
				},
				Security: []string{
					"SPIFFE ID in SAN URI extension",
					"Certificate chain to trusted root",
				},
			},
			{
				Order:       3,
				Name:        "Client Certificate Request",
				Description: "Server requests client certificate",
				From:        "Server Service",
				To:          "Client Service",
				Type:        "request",
				Parameters: map[string]string{
					"certificate_request": "CertificateRequest message",
					"acceptable_cas":      "trust bundle CAs",
				},
				Security: []string{
					"Server requires mutual authentication",
				},
			},
			{
				Order:       4,
				Name:        "Client Certificate",
				Description: "Client presents X.509-SVID certificate",
				From:        "Client Service",
				To:          "Server Service",
				Type:        "response",
				Parameters: map[string]string{
					"certificate":   "client X.509-SVID",
					"chain":         "intermediate CA certificates",
					"spiffe_id_san": "spiffe://domain/client in SAN URI",
				},
				Security: []string{
					"Client proves its SPIFFE identity",
				},
			},
			{
				Order:       5,
				Name:        "Certificate Verification",
				Description: "Both sides verify peer certificates",
				From:        "Both Services",
				To:          "Trust Bundle",
				Type:        "internal",
				Parameters: map[string]string{
					"chain_validation":  "verify to trusted root",
					"expiry_check":      "certificate not expired",
					"revocation_check":  "optional CRL/OCSP",
					"spiffe_id_extract": "extract URI from SAN",
				},
				Security: []string{
					"Verify against trust bundle, not system CAs",
					"Check SPIFFE ID is in expected trust domain",
				},
			},
			{
				Order:       6,
				Name:        "Authorization",
				Description: "Authorize peer SPIFFE ID",
				From:        "Server Service",
				To:          "Authorization Policy",
				Type:        "internal",
				Parameters: map[string]string{
					"peer_spiffe_id": "extracted from certificate",
					"policy":         "allowed SPIFFE ID patterns",
				},
				Security: []string{
					"Verify peer is authorized for requested resource",
					"Log authentication events for audit",
				},
			},
			{
				Order:       7,
				Name:        "Encrypted Channel",
				Description: "TLS handshake completes, secure channel established",
				From:        "Client Service",
				To:          "Server Service",
				Type:        "internal",
				Parameters: map[string]string{
					"session_keys": "derived from handshake",
					"cipher":       "negotiated cipher suite",
				},
				Security: []string{
					"All subsequent traffic encrypted",
					"Forward secrecy with ephemeral keys",
				},
			},
		},
	}
}

// getCertificateRotationFlow defines automatic certificate rotation
func getCertificateRotationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "certificate-rotation",
		Name:        "Automatic Certificate Rotation",
		Description: "Seamless X.509-SVID rotation without service disruption",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Rotation Check",
				Description: "Agent monitors certificate expiration",
				From:        "SPIRE Agent",
				To:          "SVID Cache",
				Type:        "internal",
				Parameters: map[string]string{
					"check_interval":    "periodic (e.g., every 30s)",
					"rotation_threshold": "typically at 50% lifetime",
				},
				Security: []string{
					"Rotate well before expiration",
					"Handle clock skew gracefully",
				},
			},
			{
				Order:       2,
				Name:        "New SVID Request",
				Description: "Agent requests fresh SVID from server",
				From:        "SPIRE Agent",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"csr":         "new certificate signing request",
					"current_svid": "for identification",
				},
				Security: []string{
					"New key pair generated",
					"Old SVID used until rotation complete",
				},
			},
			{
				Order:       3,
				Name:        "New SVID Issuance",
				Description: "Server issues new certificate",
				From:        "SPIRE Server",
				To:          "SPIRE Agent",
				Type:        "response",
				Parameters: map[string]string{
					"new_x509_svid": "fresh certificate",
					"new_bundle":    "updated trust bundle if changed",
				},
				Security: []string{
					"New certificate has fresh validity period",
					"Serial number changes",
				},
			},
			{
				Order:       4,
				Name:        "Workload Notification",
				Description: "Workload receives new SVID via streaming API",
				From:        "SPIRE Agent",
				To:          "Workload",
				Type:        "response",
				Parameters: map[string]string{
					"new_svid":      "fresh X.509-SVID",
					"new_key":       "new private key",
					"updated_bundle": "if trust bundle changed",
				},
				Security: []string{
					"Workload should update TLS config atomically",
					"In-flight connections continue with old cert",
				},
			},
			{
				Order:       5,
				Name:        "Graceful Transition",
				Description: "Workload transitions to new certificate",
				From:        "Workload",
				To:          "TLS Stack",
				Type:        "internal",
				Parameters: map[string]string{
					"strategy": "new connections use new cert",
					"existing": "existing connections continue",
				},
				Security: []string{
					"No service disruption during rotation",
					"Both old and new certs valid briefly",
				},
			},
		},
	}
}

// getTrustBundleFederationFlow defines federation between trust domains
func getTrustBundleFederationFlow() plugin.FlowDefinition {
	return plugin.FlowDefinition{
		ID:          "trust-bundle-federation",
		Name:        "Trust Domain Federation",
		Description: "Establishing trust between different SPIFFE trust domains",
		Steps: []plugin.FlowStep{
			{
				Order:       1,
				Name:        "Federation Configuration",
				Description: "Configure federation relationship between domains",
				From:        "Admin",
				To:          "SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"federation_type":     "web or profile",
					"trust_domain":        "foreign trust domain",
					"bundle_endpoint_url": "https://foreign-server:8443/bundle",
					"endpoint_profile":    "https_spiffe or https_web",
				},
				Security: []string{
					"Verify foreign domain ownership",
					"Use HTTPS for bundle endpoint",
				},
			},
			{
				Order:       2,
				Name:        "Bundle Fetch",
				Description: "Server fetches foreign trust bundle",
				From:        "SPIRE Server",
				To:          "Foreign SPIRE Server",
				Type:        "request",
				Parameters: map[string]string{
					"endpoint": "/.well-known/spiffe-bundle or custom",
					"format":   "JWKS with x5c",
				},
				Security: []string{
					"Authenticate bundle endpoint",
					"Verify bundle signature if available",
				},
			},
			{
				Order:       3,
				Name:        "Bundle Storage",
				Description: "Foreign bundle stored in datastore",
				From:        "SPIRE Server",
				To:          "Datastore",
				Type:        "internal",
				Parameters: map[string]string{
					"bundle_type":   "foreign",
					"trust_domain":  "foreign domain",
					"refresh_hint":  "how often to refresh",
				},
				Security: []string{
					"Foreign bundles are separate from local",
					"Periodic refresh keeps bundle current",
				},
			},
			{
				Order:       4,
				Name:        "Bundle Distribution",
				Description: "Foreign bundle distributed to agents and workloads",
				From:        "SPIRE Server",
				To:          "SPIRE Agents",
				Type:        "response",
				Parameters: map[string]string{
					"bundles": "local and federated bundles",
				},
				Security: []string{
					"Workloads can now verify foreign SVIDs",
				},
			},
			{
				Order:       5,
				Name:        "Cross-Domain Authentication",
				Description: "Services from different domains can authenticate",
				From:        "Local Workload",
				To:          "Foreign Workload",
				Type:        "request",
				Parameters: map[string]string{
					"local_svid":    "spiffe://local-domain/service",
					"foreign_svid":  "spiffe://foreign-domain/service",
					"verification":  "each side verifies against federated bundle",
				},
				Security: []string{
					"Trust is explicit and configured",
					"Each domain maintains its own CA",
				},
			},
		},
	}
}

