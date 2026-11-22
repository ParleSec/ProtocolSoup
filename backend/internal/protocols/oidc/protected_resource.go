package oidc

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// UserInfo is the only Bearer-protected resource this deployment exposes
// (OpenID Connect Core 1.0 Section 5.3, RFC 6750). Everything else on the
// origin — the protocol catalog, the Looking Glass API and the marketing
// pages — is readable without an access token.
const userInfoResourcePath = "/oidc/userinfo"

// protectedResourceWellKnown is the RFC 9728 Section 3 well-known suffix. For a
// resource identifier that has a path component, Section 3.1 inserts the suffix
// between the host and that path, so the UserInfo document lives at
// /.well-known/oauth-protected-resource/oidc/userinfo while the origin-level
// document lives at the bare suffix.
const protectedResourceWellKnown = "/.well-known/oauth-protected-resource"

const userInfoResourceMetadataPath = protectedResourceWellKnown + userInfoResourcePath

// userInfoResource is the resource identifier of the UserInfo endpoint, the
// "resource" value of its RFC 9728 metadata. Every access token the OP issues
// carries it in "aud", and UserInfo accepts only a token that does (RFC 9068
// Section 4).
func (p *Plugin) userInfoResource() string {
	return strings.TrimRight(p.mockIdP.GetIssuer(), "/") + userInfoResourcePath
}

// resourceIndicatorError checks the "resource" parameter values of a request
// to the OP (RFC 8707 Section 2). The OP issues access tokens for one
// protected resource, UserInfo, so that is the only value it accepts. It
// returns the invalid_target description, or "" when the request is
// acceptable.
func (p *Plugin) resourceIndicatorError(resources []string) string {
	for _, value := range resources {
		// RFC 8707 Section 2: "Its value MUST be an absolute URI, as
		// specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a
		// fragment component."
		parsed, err := url.Parse(value)
		if err != nil || !parsed.IsAbs() || parsed.Fragment != "" || strings.Contains(value, "#") {
			return "resource must be an absolute URI with no fragment component (RFC 8707 Section 2)"
		}
		if value != p.userInfoResource() {
			return "resource does not name a protected resource this OpenID Provider issues access tokens for"
		}
	}
	return ""
}

// emitTargetRejected records a refused resource indicator in Looking Glass.
func (p *Plugin) emitTargetRejected(sessionID, endpoint string, resources []string, description string) {
	p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Resource Indicator Rejected", map[string]interface{}{
		"endpoint":          endpoint,
		"error":             "invalid_target",
		"error_description": description,
		"resource":          resources,
		"accepted_resource": p.userInfoResource(),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Access Tokens Are For UserInfo",
		Description: "The OpenID Provider audience-restricts every access token to its UserInfo endpoint and refuses a request for any other resource.",
		Severity:    "warning",
		Reference:   "RFC 8707 Section 2",
	})
}

// handleProtectedResourceMetadata serves OAuth 2.0 Protected Resource Metadata
// (RFC 9728). Two documents are published: an origin-level document that points
// agents at the authorization servers able to issue tokens for this deployment,
// and the resource-specific document for the UserInfo endpoint.
func (p *Plugin) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if p.mockIdP == nil {
		http.Error(w, "protected resource metadata unavailable", http.StatusServiceUnavailable)
		return
	}

	// The OP issuer is the pathless site origin, so it doubles as the
	// origin-level resource identifier.
	issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
	if issuer == "" {
		http.Error(w, "protected resource metadata unavailable", http.StatusServiceUnavailable)
		return
	}

	var metadata map[string]interface{}
	switch r.URL.Path {
	case userInfoResourceMetadataPath:
		metadata = userInfoResourceMetadata(issuer)
	case protectedResourceWellKnown, "/oidc" + protectedResourceWellKnown:
		metadata = originResourceMetadata(issuer)
	default:
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(metadata)
}

// userInfoResourceMetadata describes the UserInfo endpoint itself.
func userInfoResourceMetadata(issuer string) map[string]interface{} {
	return map[string]interface{}{
		"resource":              issuer + userInfoResourcePath,
		"resource_name":         "ProtocolSoup UserInfo Endpoint",
		"authorization_servers": []string{issuer},
		"scopes_supported":      scopesSupported,
		// RFC 6750 Section 2.1 (Authorization header) and Section 2.2
		// (form-encoded access_token parameter) are both accepted by
		// handleUserInfo. The URI query parameter of Section 2.3 is not.
		"bearer_methods_supported": []string{"header", "body"},
		"resource_documentation":   issuer + "/auth.md",
	}
}

// originResourceMetadata is the document an agent finds when it resolves the
// bare well-known path for this origin. It advertises both authorization
// servers that can mint tokens here and defers the per-endpoint detail to
// auth.md, because most of the origin is readable without a token.
func originResourceMetadata(issuer string) map[string]interface{} {
	return map[string]interface{}{
		"resource":      issuer,
		"resource_name": "ProtocolSoup",
		// The OpenID Provider issuer is the site origin; the OAuth 2.0
		// authorization server uses the /oauth2 path issuer and the agentic
		// registration server the /agentauth path issuer (RFC 8414
		// Section 3.1). Each one publishes metadata at the well-known URL
		// derived from its own issuer.
		"authorization_servers":    []string{issuer, issuer + "/oauth2", issuer + "/agentauth"},
		"scopes_supported":         scopesSupported,
		"bearer_methods_supported": []string{"header", "body"},
		"resource_documentation":   issuer + "/auth.md",
	}
}

// writeUserInfoError writes a Bearer-protected resource error (RFC 6750
// Section 3). RFC 9728 Section 5.1 has the resource server point clients at its
// metadata document through the resource_metadata challenge parameter, so an
// agent that gets rejected can discover which authorization server issues
// tokens for UserInfo instead of having to guess.
func (p *Plugin) writeUserInfoError(w http.ResponseWriter, status int, errorCode, description string) {
	issuer := ""
	if p.mockIdP != nil {
		issuer = p.mockIdP.GetIssuer()
	}
	errorURI := oidcErrorURIs[errorCode]

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", protectedResourceChallenge(issuer, errorCode, description, errorURI))
	w.WriteHeader(status)

	response := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}
	if errorURI != "" {
		response["error_uri"] = errorURI
	}
	json.NewEncoder(w).Encode(response)
}

func protectedResourceChallenge(issuer, errorCode, description, errorURI string) string {
	challenge := `Bearer error="` + errorCode + `", error_description="` + description + `"`
	if errorURI != "" {
		challenge += `, error_uri="` + errorURI + `"`
	}
	if issuer != "" {
		challenge += `, resource_metadata="` + strings.TrimRight(issuer, "/") + userInfoResourceMetadataPath + `"`
	}
	return challenge
}
