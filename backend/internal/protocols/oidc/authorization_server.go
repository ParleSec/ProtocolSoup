package oidc

import (
	"encoding/json"
	"net/http"
	"strings"
)

// authorizationServerWellKnown is the RFC 8414 Section 3 well-known suffix. The
// OP issuer is the pathless site origin, so its metadata document lives at the
// bare suffix with no path component appended.
const authorizationServerWellKnown = "/.well-known/oauth-authorization-server"

// AgentAuthMetadataProvider supplies the auth.md agent_auth block. The agentic
// registration plugin implements it. Keeping this an interface lets the OP
// advertise where agents register without importing that plugin.
type AgentAuthMetadataProvider interface {
	AgentAuthMetadata() map[string]interface{}
}

// SetAgentAuthProvider attaches the agentic registration server whose
// endpoints this OP should advertise.
func (p *Plugin) SetAgentAuthProvider(provider AgentAuthMetadataProvider) {
	p.agentAuth = provider
}

// handleAuthorizationServerMetadata serves OAuth 2.0 Authorization Server
// Metadata (RFC 8414) for the origin issuer.
//
// The OP already publishes an OpenID Provider configuration at
// /.well-known/openid-configuration, but RFC 8414 Section 5 keeps the two
// documents distinct: a plain OAuth 2.0 client resolving this issuer looks
// under oauth-authorization-server and has no reason to try the OpenID
// Connect location. Protected Resource Metadata names this issuer as an
// authorization server, so RFC 9728 Section 3 sends clients here and the
// document has to exist.
func (p *Plugin) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if p.mockIdP == nil {
		http.Error(w, "authorization server metadata unavailable", http.StatusServiceUnavailable)
		return
	}

	issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
	if issuer == "" {
		http.Error(w, "authorization server metadata unavailable", http.StatusServiceUnavailable)
		return
	}

	// Every value here mirrors what the OpenID Provider configuration reports
	// for the same issuer, because it describes the same server.
	metadata := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oidc/authorize",
		"token_endpoint":                        issuer + "/oidc/token",
		"userinfo_endpoint":                     issuer + "/oidc/userinfo",
		"jwks_uri":                              issuer + "/oidc/.well-known/jwks.json",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"scopes_supported":                      scopesSupported,
		"response_types_supported":              []string{"code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "implicit", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		// RFC 9207 Section 3 / FAPI 2.0 SP §5.3.2.2
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          issuer + "/auth.md",
	}
	if p.registrationEnabled() {
		metadata["registration_endpoint"] = issuer + "/oidc/register"
	}

	// auth.md profile extension. RFC 8414 Section 2 allows additional
	// metadata, and this is how an agent discovers that registration exists
	// and where it happens. The block carries its own token_endpoint because
	// the agent grants are served by the agentic registration server, not by
	// the OP token endpoint named above.
	if p.agentAuth != nil {
		metadata["agent_auth"] = p.agentAuth.AgentAuthMetadata()
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(metadata)
}
