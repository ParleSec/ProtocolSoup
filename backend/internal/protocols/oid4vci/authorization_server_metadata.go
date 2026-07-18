package oid4vci

import (
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// handleAuthorizationServerMetadata serves RFC 8414 OAuth 2.0 Authorization
// Server Metadata for the issuer identifier the credential issuer metadata
// advertises in authorization_servers (issuerID()). Without this document a
// spec-following wallet cannot discover authorization_endpoint and the
// authorization_code grant is unreachable.
//
// The authorization endpoint is the existing mockidp-backed OIDC authorize
// endpoint (/oidc/authorize): codes it issues are already accepted by
// handleAuthorizationCodeTokenGrant via the shared MockIdP.ValidateAuthorizationCode,
// so this handler adds discovery only, not new authorization behavior.
func (p *Plugin) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if !p.isAllowedASMetadataRequestPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	sessionID := p.getSessionFromRequest(r)
	issuerID := p.issuerID()

	tokenEndpointAuthMethods := []string{"none", "client_secret_basic", "client_secret_post"}
	if p.clientAttestationTrustAnchors != nil {
		// draft-ietf-oauth-attestation-based-client-auth-09 §9: advertise
		// attest_jwt_client_auth only once a trust anchor is actually
		// configured to validate it (client_attestation.go), so metadata never
		// claims support the issuer cannot back.
		tokenEndpointAuthMethods = append(tokenEndpointAuthMethods, "attest_jwt_client_auth")
	}

	metadata := map[string]interface{}{
		"issuer":                   issuerID,
		"authorization_endpoint":   p.baseURL + "/oidc/authorize",
		"token_endpoint":           issuerID + "/token",
		"response_types_supported": []string{"code"},
		"grant_types_supported": []string{
			"authorization_code",
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
		},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": tokenEndpointAuthMethods,
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Authorization Server Metadata Retrieved",
		map[string]interface{}{
			"issuer":            issuerID,
			"metadata_endpoint": p.authorizationServerMetadataWellKnownPath(),
			"request_path":      r.URL.Path,
		},
		p.vcAnnotation("metadata_discovery")...,
	)

	writeJSON(w, http.StatusOK, metadata)
}

func (p *Plugin) isAllowedASMetadataRequestPath(requestPath string) bool {
	normalized := normalizePathForMatch(requestPath)
	canonical := normalizePathForMatch(p.authorizationServerMetadataWellKnownPath())
	pluginLocal := normalizePathForMatch("/oid4vci/.well-known/oauth-authorization-server")
	return normalized == canonical || normalized == pluginLocal
}
