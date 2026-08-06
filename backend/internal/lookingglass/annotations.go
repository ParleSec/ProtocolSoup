package lookingglass

// AnnotationLibrary provides pre-defined security annotations for common scenarios
type AnnotationLibrary struct{}

// NewAnnotationLibrary creates a new annotation library
func NewAnnotationLibrary() *AnnotationLibrary {
	return &AnnotationLibrary{}
}

// OAuth2Annotations returns annotations for OAuth 2.0 protocol elements
func (l *AnnotationLibrary) OAuth2Annotations() map[string][]Annotation {
	return map[string][]Annotation{
		"authorization_code": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Authorization Code Flow",
				Description: "The most secure OAuth 2.0 flow for server-side applications. The authorization code is exchanged for tokens via a back-channel request.",
				Reference:   "RFC 6749 Section 4.1",
			},
		},
		"pkce": {
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "PKCE (Proof Key for Code Exchange)",
				Description: "PKCE protects the authorization code flow from interception attacks, especially important for public clients and mobile apps.",
				Reference:   "RFC 7636",
			},
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Code Verifier Requirements",
				Description: "The code_verifier must be a high-entropy cryptographic random string using unreserved characters [A-Z] / [a-z] / [0-9] / '-' / '.' / '_' / '~', with a minimum length of 43 characters.",
				Severity:    "info",
			},
		},
		"access_token": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Access Token",
				Description: "A credential used to access protected resources. Should be short-lived and scoped to minimum necessary permissions.",
				Reference:   "RFC 6749 Section 1.4",
			},
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "Token Lifetime",
				Description: "Access tokens should have short lifetimes (minutes to hours) to limit exposure if compromised.",
				Severity:    "info",
			},
		},
		"refresh_token": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Refresh Token",
				Description: "A credential used to obtain new access tokens without user interaction. Should be stored securely and rotated on use.",
				Reference:   "RFC 6749 Section 1.5",
			},
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "Refresh Token Rotation",
				Description: "Implement refresh token rotation - issue a new refresh token with each access token refresh and invalidate the old one.",
				Severity:    "info",
			},
		},
		"state_parameter": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "CSRF Protection",
				Description: "The state parameter prevents CSRF attacks. It should be a cryptographically random value bound to the user's session.",
				Reference:   "RFC 6749 Section 10.12",
				Severity:    "warning",
			},
		},
		"redirect_uri": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Redirect URI Validation",
				Description: "Redirect URIs must be validated exactly - no wildcards, no open redirects. Use HTTPS in production.",
				Reference:   "RFC 6749 Section 10.6",
				Severity:    "warning",
			},
		},
		"client_credentials": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Client Credentials Flow",
				Description: "Used for machine-to-machine authentication where no user context is needed. The client authenticates with its own credentials.",
				Reference:   "RFC 6749 Section 4.4",
			},
		},
		"token_introspection": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Token Introspection",
				Description: "Allows resource servers to query the authorization server about the state and metadata of an access token.",
				Reference:   "RFC 7662",
			},
		},
		"token_revocation": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Token Revocation",
				Description: "Mechanism for clients to notify the authorization server that a token is no longer needed.",
				Reference:   "RFC 7009",
			},
		},
		"dpop_proof": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "DPoP Proof (Demonstrating Proof of Possession)",
				Description: "A signed JWT the client mints per-request, carrying the HTTP method (htm), target URI (htu), a fresh issued-at time (iat), a single-use identifier (jti), and its own public key (jwk) in the header. Possession of the matching private key is what the proof demonstrates -- the server never sees that key.",
				Reference:   "RFC 9449 Section 4.2",
			},
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Proof Freshness and Replay",
				Description: "A proof's iat must fall within a narrow window of the server's clock, and its jti may only be accepted once. Both checks bound how long a captured proof (not the underlying key) remains useful to an attacker.",
				Reference:   "RFC 9449 Section 11.1",
				Severity:    "warning",
			},
		},
		"dpop_cnf_jkt": {
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "Sender-Constrained Access Token (cnf.jkt)",
				Description: "An access token issued against a valid DPoP proof carries a cnf.jkt claim: the RFC 7638 thumbprint of the client's public key. The resource server must then reject that token unless it is accompanied by a fresh proof from the same key -- the token alone, without the key, is not sufficient.",
				Reference:   "RFC 9449 Section 4.1 & Section 7.1",
			},
			{
				Type:        AnnotationTypeExplanation,
				Title:       "DPoP vs Bearer token_type",
				Description: "A DPoP-bound token response uses token_type=DPoP rather than Bearer (RFC 6750), signalling to the client that every future presentation of this token must be accompanied by a matching proof.",
				Reference:   "RFC 9449 Section 5",
			},
		},
		"dpop_nonce": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Server-Provided DPoP Nonce",
				Description: "When enabled at an endpoint, the server rejects a proof that lacks its current nonce with error=use_dpop_nonce and a DPoP-Nonce response header. The client mints a fresh proof echoing that value in its nonce claim and retries -- this is a defined recovery path, not a hard failure.",
				Reference:   "RFC 9449 Section 8",
			},
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Independent AS/RS Nonce Spaces",
				Description: "A nonce issued by an authorization server's token endpoint is not valid at a resource server's protected endpoint, and vice versa -- even when, as with this issuer's own credential endpoints, the two roles are served by the same process.",
				Reference:   "RFC 9449 Section 8.2",
				Severity:    "info",
			},
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "Opt-In Hardening, Not a Baseline Requirement",
				Description: "Nonces are disabled by default and enabled per endpoint by deployment configuration. Requiring one unconditionally would break every DPoP client that has not yet implemented the challenge/retry flow, so RFC 9449 treats it as optional additional protection.",
				Reference:   "RFC 9449 Section 8",
			},
		},
	}
}

// OIDCAnnotations returns annotations for OIDC protocol elements
func (l *AnnotationLibrary) OIDCAnnotations() map[string][]Annotation {
	return map[string][]Annotation{
		"id_token": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "ID Token",
				Description: "A JWT containing claims about the authentication event and the authenticated user. Should be validated before use.",
				Reference:   "OpenID Connect Core 1.0 Section 2",
			},
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "ID Token Validation",
				Description: "Always validate: signature, issuer (iss), audience (aud), expiration (exp), and nonce if present.",
				Severity:    "info",
			},
		},
		"discovery": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "OpenID Connect Discovery",
				Description: "The discovery document (.well-known/openid-configuration) provides metadata about the OpenID Provider's configuration.",
				Reference:   "OpenID Connect Discovery 1.0",
			},
		},
		"userinfo": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "UserInfo Endpoint",
				Description: "Returns claims about the authenticated user. Requires a valid access token with appropriate scopes.",
				Reference:   "OpenID Connect Core 1.0 Section 5.3",
			},
		},
		"nonce": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Nonce for Replay Prevention",
				Description: "The nonce binds the ID token to the client session, preventing replay attacks. Should be a cryptographic random value.",
				Reference:   "OpenID Connect Core 1.0 Section 3.1.2.1",
				Severity:    "info",
			},
		},
		"claims": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "OIDC Standard Claims",
				Description: "OpenID Connect defines standard claims for user information: sub, name, email, picture, etc.",
				Reference:   "OpenID Connect Core 1.0 Section 5.1",
			},
		},
		"scopes": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "OIDC Scopes",
				Description: "Standard scopes: openid (required), profile, email, address, phone. Each scope requests specific claims.",
				Reference:   "OpenID Connect Core 1.0 Section 5.4",
			},
		},
	}
}

// OID4VCIAnnotations returns annotations for OpenID4VCI protocol elements.
func (l *AnnotationLibrary) OID4VCIAnnotations() map[string][]Annotation {
	return map[string][]Annotation{
		"metadata_discovery": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Credential Issuer Metadata Discovery",
				Description: "Wallets retrieve credential issuer metadata from the openid-credential-issuer well-known endpoint derived from the issuer identifier.",
				Reference:   "OpenID4VCI 1.0 Section 12.2.2",
			},
		},
		"credential_endpoint": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Credential Endpoint Requirement",
				Description: "Credential endpoint support is mandatory and must process access token and proof validation over TLS.",
				Reference:   "OpenID4VCI 1.0 Section 8",
				Severity:    "warning",
			},
		},
		"proof_validation": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Proof Requirement",
				Description: "When proof_types_supported is declared for a credential configuration, the credential request must include proofs.",
				Reference:   "OpenID4VCI 1.0 Section 8.2",
				Severity:    "warning",
			},
		},
		"c_nonce": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "c_nonce Freshness",
				Description: "Proof inputs must bind to a fresh c_nonce challenge when nonce-based freshness checks are enforced.",
				Reference:   "OpenID4VCI 1.0 Sections 7 and 8.2",
				Severity:    "warning",
			},
		},
		"client_attestation": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Attestation-Based Client Authentication",
				Description: "OAuth-Client-Attestation and OAuth-Client-Attestation-PoP headers authenticate the client instance at the token endpoint. A failed or partially-presented attestation is refused outright, never downgraded to client_secret authentication.",
				Reference:   "draft-ietf-oauth-attestation-based-client-auth",
				Severity:    "warning",
			},
		},
	}
}

// OID4VPAnnotations returns annotations for OpenID4VP protocol elements.
func (l *AnnotationLibrary) OID4VPAnnotations() map[string][]Annotation {
	return map[string][]Annotation{
		"dcql_contract": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "DCQL Request Contract",
				Description: "Authorization requests must include either dcql_query or a scope alias representing DCQL, but never both.",
				Reference:   "OpenID4VP 1.0 Section 5.1",
			},
		},
		"direct_post": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "direct_post Response Constraints",
				Description: "For direct_post and direct_post.jwt, response_uri is required and redirect_uri must not be present.",
				Reference:   "OpenID4VP 1.0 Section 8.2",
				Severity:    "warning",
			},
		},
		"request_object_typ": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Request Object Type Validation",
				Description: "Wallets must reject request objects that do not use typ=oauth-authz-req+jwt.",
				Reference:   "OpenID4VP 1.0 Section 5",
				Severity:    "warning",
			},
		},
		"client_id_scheme": {
			{
				Type:        AnnotationTypeBestPractice,
				Title:       "Client ID Scheme Matrix",
				Description: "Supports redirect_uri, decentralized_identifier, verifier_attestation, and x509_san_dns client_id schemes. x509_san_dns binds verifier identity to a DNS name via X.509 certificate SAN, with the leaf certificate and chain transmitted in the request object x5c JOSE header.",
				Reference:   "OpenID4VP 1.0 Section 5.9",
				Severity:    "info",
			},
		},
		"nonce_binding": {
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Nonce Binding",
				Description: "Nonce values must be fresh per transaction and bound to verifier session state for replay resistance.",
				Reference:   "OpenID4VP 1.0 Section 5.2",
				Severity:    "warning",
			},
		},
	}
}

// VulnerabilityAnnotations returns annotations for common security vulnerabilities
func (l *AnnotationLibrary) VulnerabilityAnnotations() map[string]Annotation {
	return map[string]Annotation{
		"algorithm_none": {
			Type:        AnnotationTypeVulnerability,
			Title:       "Algorithm None Attack",
			Description: "Accepting 'none' algorithm allows attackers to forge tokens without a signature. Always validate the algorithm against an allowlist.",
			Severity:    "error",
		},
		"algorithm_confusion": {
			Type:        AnnotationTypeVulnerability,
			Title:       "Algorithm Confusion Attack",
			Description: "Using asymmetric public key as HMAC secret. Always specify expected algorithms and use appropriate keys.",
			Severity:    "error",
		},
		"open_redirect": {
			Type:        AnnotationTypeVulnerability,
			Title:       "Open Redirect Vulnerability",
			Description: "Allowing arbitrary redirect URIs can lead to token theft. Validate redirect URIs against a pre-registered allowlist.",
			Severity:    "error",
		},
		"csrf": {
			Type:        AnnotationTypeVulnerability,
			Title:       "Cross-Site Request Forgery",
			Description: "Missing or predictable state parameter enables CSRF attacks. Use cryptographically random state bound to user session.",
			Severity:    "error",
		},
		"token_leakage": {
			Type:        AnnotationTypeVulnerability,
			Title:       "Token Leakage",
			Description: "Tokens in URL fragments or query parameters may be logged or leaked via referrer headers. Use POST requests and secure storage.",
			Severity:    "warning",
		},
		"insufficient_entropy": {
			Type:        AnnotationTypeVulnerability,
			Title:       "Insufficient Entropy",
			Description: "Weak random values for codes, tokens, or state parameters can be predicted. Use cryptographically secure random number generators.",
			Severity:    "error",
		},
	}
}

// GetAnnotationsForClaim returns annotations for a specific JWT claim
func (l *AnnotationLibrary) GetAnnotationsForClaim(claim string) []Annotation {
	claimAnnotations := map[string][]Annotation{
		"iss": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Issuer Claim",
				Description: "Identifies who issued the token. Must be validated against expected issuer to prevent token substitution attacks.",
				Reference:   "RFC 7519 Section 4.1.1",
			},
		},
		"sub": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Subject Claim",
				Description: "Unique identifier for the entity (user) the token represents. Should be locally unique to the issuer.",
				Reference:   "RFC 7519 Section 4.1.2",
			},
		},
		"aud": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Audience Claim",
				Description: "Identifies intended recipients. Token should be rejected if the recipient is not in the audience.",
				Reference:   "RFC 7519 Section 4.1.3",
			},
			{
				Type:        AnnotationTypeSecurityHint,
				Title:       "Audience Validation",
				Description: "Always validate that your client/resource is in the audience to prevent token misuse.",
				Severity:    "warning",
			},
		},
		"exp": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Expiration Time",
				Description: "Unix timestamp after which the token must be rejected. Provides replay attack protection.",
				Reference:   "RFC 7519 Section 4.1.4",
			},
		},
		"nbf": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Not Before",
				Description: "Unix timestamp before which the token must not be accepted. Useful for tokens issued for future use.",
				Reference:   "RFC 7519 Section 4.1.5",
			},
		},
		"iat": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Issued At",
				Description: "Unix timestamp when the token was issued. Can be used to determine token age.",
				Reference:   "RFC 7519 Section 4.1.6",
			},
		},
		"jti": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "JWT ID",
				Description: "Unique identifier for the token. Can be used to prevent token replay by tracking used tokens.",
				Reference:   "RFC 7519 Section 4.1.7",
			},
		},
		"scope": {
			{
				Type:        AnnotationTypeExplanation,
				Title:       "Scope Claim",
				Description: "Space-delimited list of scopes/permissions granted. Should follow principle of least privilege.",
				Reference:   "RFC 8693 Section 4.2",
			},
		},
	}

	if annotations, ok := claimAnnotations[claim]; ok {
		return annotations
	}
	return nil
}
