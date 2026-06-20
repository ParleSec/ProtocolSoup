package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestDiscoveryMetadataIsAccurate pins OpenID Connect Discovery 1.0 Section 3:
// advertised metadata MUST reflect actual behaviour. Every advertised value
// here must be one the OP genuinely delivers, and nothing the OP cannot do may
// be advertised.
func TestDiscoveryMetadataIsAccurate(t *testing.T) {
	p := newTestPlugin(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	p.handleDiscovery(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, want 200", rr.Code)
	}

	var doc models.DiscoveryDocument
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}

	// Issuer-prefixed endpoints (OIDC Discovery 1.0 Section 4.3).
	issuer := p.mockIdP.GetIssuer()
	if doc.Issuer != issuer {
		t.Errorf("issuer = %q, want %q", doc.Issuer, issuer)
	}
	if !strings.HasPrefix(doc.AuthorizationEndpoint, issuer) {
		t.Errorf("authorization_endpoint %q not prefixed by issuer %q", doc.AuthorizationEndpoint, issuer)
	}
	if !strings.HasPrefix(doc.TokenEndpoint, issuer) {
		t.Errorf("token_endpoint %q not prefixed by issuer %q", doc.TokenEndpoint, issuer)
	}

	// ID Token signing: RS256 only (crypto/jwt.go always signs RS256). ES256 is
	// published in JWKS but never used to sign ID Tokens, so it must not be
	// advertised here (OIDC Core 1.0 Section 3.1.3.7).
	if !contains(doc.IDTokenSigningAlgValuesSupported, "RS256") {
		t.Errorf("id_token_signing_alg_values_supported must include RS256, got %v", doc.IDTokenSigningAlgValuesSupported)
	}
	if contains(doc.IDTokenSigningAlgValuesSupported, "ES256") {
		t.Errorf("ES256 must not be advertised: ID Tokens are RS256-signed, got %v", doc.IDTokenSigningAlgValuesSupported)
	}

	// Grant types: the OIDC token endpoint accepts authorization_code and
	// refresh_token only; client_credentials lives on the OAuth 2.0 endpoint.
	if !contains(doc.GrantTypesSupported, "authorization_code") || !contains(doc.GrantTypesSupported, "refresh_token") {
		t.Errorf("grant_types_supported missing required grants, got %v", doc.GrantTypesSupported)
	}
	if contains(doc.GrantTypesSupported, "client_credentials") {
		t.Errorf("client_credentials must not be advertised on the OIDC token endpoint, got %v", doc.GrantTypesSupported)
	}

	// Claims: at_hash and c_hash are emitted; the full profile-scope set is now
	// populated on the demo users, so each may be advertised (OIDC Core 1.0
	// Section 5.4). Anything advertised here must be genuinely returnable.
	for _, claim := range []string{
		"sub", "iss", "aud", "exp", "iat", "auth_time", "at_hash", "c_hash",
		"acr", "amr",
		"name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
		"email", "email_verified", "address", "phone_number", "phone_number_verified",
	} {
		if !contains(doc.ClaimsSupported, claim) {
			t.Errorf("claims_supported missing %q, got %v", claim, doc.ClaimsSupported)
		}
	}

	// Scopes: every advertised scope must return genuine claims. The demo users
	// populate address and phone, so those scopes are advertised alongside the
	// core set (OIDC Core 1.0 Section 5.4).
	for _, scope := range []string{"openid", "profile", "email", "address", "phone"} {
		if !contains(doc.ScopesSupported, scope) {
			t.Errorf("scopes_supported missing %q, got %v", scope, doc.ScopesSupported)
		}
	}

	// The OP performs a single genuine authentication context (single-factor
	// password) and advertises it so acr_values requests can be satisfied
	// truthfully (OIDC Core 1.0 Section 2). No higher assurance level is claimed.
	if !contains(doc.ACRValuesSupported, "urn:protocolsoup:ac:password") {
		t.Errorf("acr_values_supported must advertise the password context, got %v", doc.ACRValuesSupported)
	}

	// Response modes the OP actually implements.
	if !contains(doc.ResponseModesSupported, "query") || !contains(doc.ResponseModesSupported, "fragment") {
		t.Errorf("response_modes_supported must include query and fragment, got %v", doc.ResponseModesSupported)
	}

	// The OP supports neither request nor request_uri, so both must be advertised
	// false. request_uri_parameter_supported defaults to true, so emitting it as
	// false is required for accuracy (OIDC Discovery 1.0 Section 3).
	if doc.RequestParameterSupported {
		t.Errorf("request_parameter_supported must be false: the OP rejects the request parameter")
	}
	if doc.RequestURIParameterSupported {
		t.Errorf("request_uri_parameter_supported must be false: the OP rejects the request_uri parameter")
	}
	// request_uri_parameter_supported defaults to true, so the false value must
	// be present in the emitted document, not merely absent.
	if !strings.Contains(rr.Body.String(), `"request_uri_parameter_supported":false`) {
		t.Errorf("discovery document must emit request_uri_parameter_supported:false explicitly; body=%s", rr.Body.String())
	}

	// The OP honours the claims request parameter (OIDC Core 1.0 Section 5.5).
	// claims_parameter_supported defaults to false, so true must be emitted
	// explicitly to be accurate (OIDC Discovery 1.0 Section 3).
	if !doc.ClaimsParameterSupported {
		t.Errorf("claims_parameter_supported must be true: the OP honours the claims parameter")
	}
	if !strings.Contains(rr.Body.String(), `"claims_parameter_supported":true`) {
		t.Errorf("discovery document must emit claims_parameter_supported:true explicitly; body=%s", rr.Body.String())
	}
}
