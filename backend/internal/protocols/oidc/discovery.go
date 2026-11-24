package oidc

import (
	"encoding/json"
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// scopesSupported are the scope values the OP honours. UserInfo derives the
// claims it returns from the scopes granted to the presented access token, so
// the protected resource metadata (RFC 9728) advertises the same list.
var scopesSupported = []string{"openid", "profile", "email", "address", "phone", "roles", "offline_access"}

// Client authentication metadata that the OpenID Provider configuration and
// the RFC 8414 authorization server metadata both publish for this issuer.
var (
	// clientAssertionSigningAlgs are the algorithms a private_key_jwt client
	// assertion may be signed with, at the token endpoint and at the
	// revocation endpoint. RFC 8414 Section 2 on each
	// *_endpoint_auth_signing_alg_values_supported entry: "This metadata
	// entry MUST be present if either of these authentication methods are
	// specified in the" matching *_endpoint_auth_methods_supported entry.
	clientAssertionSigningAlgs = []string{"RS256", "ES256", "EdDSA"}
	// revocationEndpointAuthMethods: RFC 8414 Section 2, "If omitted, the
	// default is "client_secret_basic"". /oauth2/revoke also takes a client
	// password in the body and a private_key_jwt assertion, and a public
	// client names itself with client_id (RFC 7009 Section 2.1).
	revocationEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"}
	// introspectionEndpointAuthMethods: /oauth2/introspect authenticates a
	// client password only, and "none" is absent because a public client is
	// not authorized to call it (RFC 7662 Section 2.1).
	introspectionEndpointAuthMethods = []string{"client_secret_basic", "client_secret_post"}
)

// handleDiscovery returns the OpenID Connect discovery document
func (p *Plugin) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := p.mockIdP.GetIssuer()

	discovery := models.DiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/oidc/authorize",
		TokenEndpoint:         issuer + "/oidc/token",
		UserinfoEndpoint:      issuer + "/oidc/userinfo",
		JwksURI:               issuer + "/oidc/.well-known/jwks.json",
		RevocationEndpoint:    issuer + "/oauth2/revoke",
		IntrospectionEndpoint: issuer + "/oauth2/introspect",
		ScopesSupported:       scopesSupported,
		// Canonical response_type sets actually handled by the authorization
		// endpoint (OIDC Core 1.0 Section 3). response_type is an unordered
		// space-delimited set, so canonical response_type orderings are advertised.
		ResponseTypesSupported: []string{"code", "token", "id_token", "id_token token", "code id_token", "code token", "code id_token token"},
		// query and fragment are the OAuth 2.0 defaults; form_post is supported
		// for every response type and delivers the response in an HTTP POST body
		// (OAuth 2.0 Form Post Response Mode), enabling the Form Post OP profiles.
		ResponseModesSupported: []string{"query", "fragment", "form_post"},
		// Only grant types the OIDC token endpoint actually accepts. The
		// client_credentials grant lives on the OAuth 2.0 token endpoint, not
		// here, so advertising it would be false metadata (OIDC Discovery 1.0
		// Section 3 requires metadata to reflect the OP's real behaviour).
		GrantTypesSupported:   []string{"authorization_code", "implicit", "refresh_token"},
		SubjectTypesSupported: []string{"public", "pairwise"},
		// ID Tokens are signed with RS256 only (crypto/jwt.go). ES256 keys are
		// published in JWKS but never used to sign ID Tokens, so RS256 is the
		// only honest advertisement here (OIDC Core 1.0 Section 3.1.3.7).
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		// Signed UserInfo is available when a client registers
		// userinfo_signed_response_alg=RS256 (OIDC Core 1.0 Section 5.3.2).
		UserinfoSigningAlgValuesSupported: []string{"RS256"},
		// Dynamic OPs MUST support Request Objects by reference (OIDC Core §15.2).
		RequestObjectSigningAlgValuesSupported: []string{"RS256"},
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		// Every claim listed here is genuinely returned in an ID Token or from
		// UserInfo for some granted scope. at_hash and c_hash are emitted from
		// the authorization endpoint for implicit and hybrid flows.
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash",
			"acr", "amr",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website", "gender",
			"birthdate", "zoneinfo", "locale", "updated_at",
			"email", "email_verified", "address", "phone_number", "phone_number_verified", "roles",
		},
		// The OP performs a single, genuine authentication context (single-factor
		// password). It is advertised so a client can request it via acr_values and
		// receive it back truthfully (OIDC Core 1.0 Section 2). No higher assurance
		// level is advertised because none is performed.
		ACRValuesSupported:            []string{acrSingleFactorLogin},
		CodeChallengeMethodsSupported: []string{"S256", "plain"},
		// By-value request objects remain unsupported. request_uri is supported for
		// Dynamic OP certification (OIDC Core 1.0 Section 15.2) and is advertised
		// true only when Dynamic Registration is enabled, matching live behaviour.
		RequestParameterSupported:    false,
		RequestURIParameterSupported: p.registrationEnabled(),
		// The OP honours the claims request parameter (OIDC Core 1.0 Section 5.5):
		// individually requested claims are returned from UserInfo (or the ID
		// Token for the id_token response type). claims_parameter_supported
		// defaults to false, so it is advertised true explicitly.
		ClaimsParameterSupported: true,
		// RFC 9207 Section 3 / FAPI 2.0 SP §5.3.2.2: authorization responses
		// always include iss; advertise support so clients validate it.
		AuthorizationResponseIssParameterSupported: true,
	}
	if p.registrationEnabled() {
		discovery.RegistrationEndpoint = issuer + "/oidc/register"
	}
	// The same entries, with the same values, as the RFC 8414 document for
	// this issuer (handleAuthorizationServerMetadata).
	discovery.TokenEndpointAuthSigningAlgValuesSupported = clientAssertionSigningAlgs
	discovery.RevocationEndpointAuthMethodsSupported = revocationEndpointAuthMethods
	discovery.RevocationEndpointAuthSigningAlgValuesSupported = clientAssertionSigningAlgs
	discovery.IntrospectionEndpointAuthMethodsSupported = introspectionEndpointAuthMethods

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(discovery)
}

// handleJWKS returns the JSON Web Key Set used to verify OP-issued JWTs.
// Only RSA and EC keys are published here: OIDC discovery advertises RS256 for
// ID Tokens, and many JWKS validators do not accept OKP/Ed25519 keys
// (unknown key type 'OKP'). Ed25519 material remains available in the KeySet
// for other ProtocolSoup surfaces.
func (p *Plugin) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := p.keySet.PublicJWKS()
	filtered := make([]crypto.JWK, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.Kty == "OKP" {
			continue
		}
		filtered = append(filtered, key)
	}
	jwks.Keys = filtered

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwks)
}

// DiscoveryAnnotations returns annotations explaining the discovery document fields
func DiscoveryAnnotations() map[string]string {
	return map[string]string{
		"issuer":                                "URL that the OP asserts as its Issuer Identifier. Must exactly match the iss claim in ID Tokens.",
		"authorization_endpoint":                "URL of the OP's OAuth 2.0 Authorization Endpoint.",
		"token_endpoint":                        "URL of the OP's OAuth 2.0 Token Endpoint.",
		"userinfo_endpoint":                     "URL of the OP's UserInfo Endpoint. Returns claims about the authenticated user.",
		"jwks_uri":                              "URL of the OP's JSON Web Key Set document containing public keys for token validation.",
		"registration_endpoint":                 "URL of the OP's Dynamic Client Registration Endpoint (if supported).",
		"scopes_supported":                      "List of OAuth 2.0 scope values supported. Must include 'openid'.",
		"response_types_supported":              "List of OAuth 2.0 response_type values supported.",
		"grant_types_supported":                 "List of OAuth 2.0 Grant Type values supported.",
		"subject_types_supported":               "List of Subject Identifier types supported (public or pairwise).",
		"id_token_signing_alg_values_supported": "List of JWS signing algorithms supported for ID Tokens.",
		"claims_supported":                      "List of Claim Names that may be returned in ID Tokens or UserInfo responses.",
		"acr_values_supported":                  "List of Authentication Context Class References supported. This OP performs single-factor password authentication and reports it via acr.",
		"code_challenge_methods_supported":      "PKCE code challenge methods supported. S256 is recommended.",
		"claims_parameter_supported":            "Whether the OP supports the claims request parameter. This OP honours it: individually requested claims are returned from UserInfo, or the ID Token for the id_token response type (OpenID Connect Core 1.0 Section 5.5).",
	}
}

// DiscoveryEndpointInfo provides detailed information about each endpoint
type DiscoveryEndpointInfo struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Description string `json:"description"`
	RFCSection  string `json:"rfc_section"`
}

// GetEndpointInfo returns detailed information about OIDC endpoints
func (p *Plugin) GetEndpointInfo() []DiscoveryEndpointInfo {
	issuer := p.mockIdP.GetIssuer()

	return []DiscoveryEndpointInfo{
		{
			Name:        "Authorization Endpoint",
			URL:         issuer + "/oidc/authorize",
			Method:      "GET",
			Description: "Initiates the authentication process. User is redirected here to authenticate.",
			RFCSection:  "OpenID Connect Core 1.0 Section 3.1.2",
		},
		{
			Name:        "Token Endpoint",
			URL:         issuer + "/oidc/token",
			Method:      "POST",
			Description: "Exchanges authorization code for tokens. Returns access_token, refresh_token, and id_token.",
			RFCSection:  "OpenID Connect Core 1.0 Section 3.1.3",
		},
		{
			Name:        "UserInfo Endpoint",
			URL:         issuer + "/oidc/userinfo",
			Method:      "GET/POST",
			Description: "Returns claims about the authenticated user. Requires valid access token.",
			RFCSection:  "OpenID Connect Core 1.0 Section 5.3",
		},
		{
			Name:        "JWKS Endpoint",
			URL:         issuer + "/oidc/.well-known/jwks.json",
			Method:      "GET",
			Description: "Returns the public keys used to sign tokens. Used for signature verification.",
			RFCSection:  "RFC 7517",
		},
		{
			Name:        "Discovery Endpoint",
			URL:         issuer + "/oidc/.well-known/openid-configuration",
			Method:      "GET",
			Description: "Returns OpenID Provider metadata. Starting point for OIDC client configuration.",
			RFCSection:  "OpenID Connect Discovery 1.0",
		},
		{
			Name:        "Revocation Endpoint",
			URL:         issuer + "/oauth2/revoke",
			Method:      "POST",
			Description: "Revokes an access or refresh token.",
			RFCSection:  "RFC 7009",
		},
		{
			Name:        "Introspection Endpoint",
			URL:         issuer + "/oauth2/introspect",
			Method:      "POST",
			Description: "Returns metadata about a token (active status, claims, etc.).",
			RFCSection:  "RFC 7662",
		},
	}
}
