package agentauth

import (
	"encoding/json"
	"net/http"
)

// handleAuthorizationServerMetadata serves RFC 8414 Authorization Server
// Metadata for the agentic registration server, extended with the auth.md
// agent_auth block that tells an agent where to register.
func (p *Plugin) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	writeJSONCacheable(w, http.StatusOK, p.AuthorizationServerMetadata())
}

// AuthorizationServerMetadata builds this server's RFC 8414 document. It is
// exported so the origin-level authorization server can embed the same
// agent_auth block instead of maintaining a second copy of the endpoint list.
func (p *Plugin) AuthorizationServerMetadata() map[string]interface{} {
	issuer := p.issuer()

	return map[string]interface{}{
		"issuer":         issuer,
		"token_endpoint": issuer + "/token",
		// RFC 7009 Section 2 revocation for identity assertions.
		"revocation_endpoint": issuer + "/revoke",
		"jwks_uri":            p.origin() + "/api/.well-known/jwks.json",

		"grant_types_supported": []string{grantTypeJWTBearer, grantTypeClaim},
		// RFC 8414 Section 2 marks response_types_supported REQUIRED. This
		// server has no authorization endpoint — an agent registers over a
		// back channel and never redirects a browser — so the honest value is
		// the empty list rather than a response type nothing here implements.
		"response_types_supported": []string{},
		"scopes_supported":         []string{"agent:read", "agent:write"},
		// The assertion is signed by the server that consumes it, so there is
		// no separate client authentication step at the token endpoint.
		"token_endpoint_auth_methods_supported":            []string{"none"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
		"service_documentation":                            p.origin() + "/auth.md",

		"agent_auth": p.AgentAuthMetadata(),
	}
}

// AgentAuthMetadata is the auth.md profile extension. Every URL in it is a
// route this plugin actually serves.
func (p *Plugin) AgentAuthMetadata() map[string]interface{} {
	issuer := p.issuer()

	return map[string]interface{}{
		// Where an agent reads the procedure in prose.
		"skill": p.origin() + "/auth.md",

		// register_uri and identity_endpoint name the same route. The auth.md
		// reference implementation calls it identity_endpoint; the published
		// discovery skill looks for register_uri. Both are given so an agent
		// following either one arrives at the endpoint that exists.
		"register_uri":          issuer + "/identity",
		"identity_endpoint":     issuer + "/identity",
		"claim_endpoint":        issuer + "/identity/claim",
		"claim_uri":             issuer + "/identity/claim",
		"revocation_uri":        issuer + "/revoke",
		"token_endpoint":        issuer + "/token",
		"verification_uri":      issuer + "/claim",
		"grant_types_supported": []string{grantTypeJWTBearer, grantTypeClaim},

		// Only anonymous registration is implemented. ID-JAG is omitted
		// deliberately: verifying one requires an agent provider's key set,
		// and this deployment federates with none, so claiming support would
		// tell an agent its assertion had been checked when it had not.
		"identity_types_supported": []string{identityTypeAnonymous},
		"anonymous": map[string]interface{}{
			"credential_types_supported": []string{credentialTypeJWT},
			"claim_uri":                  issuer + "/identity/claim",
			"scopes_before_claim":        []string{scopePreClaim},
			"scopes_after_claim":         []string{"agent:read", "agent:write"},
		},

		"events_supported": []string{eventAssertionRevoked},
	}
}

// writeJSONCacheable writes JSON without the no-store header that credential
// responses carry, since metadata is public and worth caching.
func writeJSONCacheable(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
