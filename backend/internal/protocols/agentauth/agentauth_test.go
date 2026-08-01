package agentauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://as.example"

func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()

	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := mockidp.NewMockIdP(keySet)
	idp.SetIssuer(testIssuer)

	p := NewPlugin()
	p.mockIdP = idp
	p.keySet = keySet
	p.baseURL = testIssuer
	return p
}

// postJSON invokes a handler with a JSON body and returns the decoded response.
func postJSON(t *testing.T, handler http.HandlerFunc, path, body string) (int, map[string]interface{}) {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, testIssuer+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler(response, request)

	return response.Code, decodeBody(t, response)
}

// postForm invokes a handler with a form-encoded body, the encoding RFC 6749
// Section 4.1.3 requires at the token endpoint.
func postForm(t *testing.T, handler http.HandlerFunc, path string, values url.Values) (int, map[string]interface{}) {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, testIssuer+path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler(response, request)

	return response.Code, decodeBody(t, response)
}

func decodeBody(t *testing.T, response *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()

	if response.Body.Len() == 0 {
		return map[string]interface{}{}
	}
	var document map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("response body was not JSON: %v (%s)", err, response.Body.String())
	}
	return document
}

// registerAnonymously runs the registration step and returns the assertion and
// claim token the agent is expected to hold afterwards.
func registerAnonymously(t *testing.T, p *Plugin) (assertion, claimToken string) {
	t.Helper()

	status, body := postJSON(t, p.handleIdentity, "/agentauth/identity", `{"type":"anonymous"}`)
	if status != http.StatusOK {
		t.Fatalf("registration status = %d, body = %v", status, body)
	}

	assertion, _ = body["identity_assertion"].(string)
	claimToken, _ = body["claim_token"].(string)
	if assertion == "" || claimToken == "" {
		t.Fatalf("registration returned assertion=%q claim_token=%q", assertion, claimToken)
	}
	return assertion, claimToken
}

// RFC 7523 Section 3 fixes the claim set an authorization server must find in a
// JWT used as an authorization grant.
func TestIdentityAssertionCarriesRequiredClaims(t *testing.T) {
	p := newTestPlugin(t)
	assertion, _ := registerAnonymously(t, p)

	parsed, _, err := jwt.NewParser().ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("assertion did not parse: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	if got := claims["iss"]; got != p.issuer() {
		t.Errorf("iss = %#v, want %q", got, p.issuer())
	}
	if got := claims["aud"]; got != p.issuer() {
		t.Errorf("aud = %#v, want %q", got, p.issuer())
	}
	for _, claim := range []string{"sub", "exp", "iat", "nbf", "jti"} {
		if _, present := claims[claim]; !present {
			t.Errorf("assertion is missing the %s claim", claim)
		}
	}
	if claims["claimed"] != false {
		t.Errorf("claimed = %#v, want false for a fresh anonymous registration", claims["claimed"])
	}
	if parsed.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		t.Errorf("alg = %q, want RS256", parsed.Method.Alg())
	}
}

// RFC 7523 Section 2.1: the assertion is exchanged for an access token under
// the jwt-bearer grant type.
func TestJWTBearerGrantIssuesPreClaimToken(t *testing.T) {
	p := newTestPlugin(t)
	assertion, _ := registerAnonymously(t, p)

	status, body := postForm(t, p.handleToken, "/agentauth/token", url.Values{
		"grant_type": {grantTypeJWTBearer},
		"assertion":  {assertion},
	})
	if status != http.StatusOK {
		t.Fatalf("token status = %d, body = %v", status, body)
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %#v, want Bearer", body["token_type"])
	}
	if body["scope"] != scopePreClaim {
		t.Errorf("scope = %#v, want %q for an unclaimed agent", body["scope"], scopePreClaim)
	}
	if accessToken, _ := body["access_token"].(string); accessToken == "" {
		t.Error("no access_token was issued")
	}
}

// RFC 7523 Section 3 lets the authorization server refuse a repeated jti, which
// is what stops a captured bearer assertion being redeemed twice.
func TestIdentityAssertionCannotBeReplayed(t *testing.T) {
	p := newTestPlugin(t)
	assertion, _ := registerAnonymously(t, p)

	values := url.Values{"grant_type": {grantTypeJWTBearer}, "assertion": {assertion}}

	if status, body := postForm(t, p.handleToken, "/agentauth/token", values); status != http.StatusOK {
		t.Fatalf("first redemption status = %d, body = %v", status, body)
	}

	status, body := postForm(t, p.handleToken, "/agentauth/token", values)
	if status != http.StatusBadRequest {
		t.Fatalf("replayed redemption status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %#v, want invalid_grant", body["error"])
	}
}

// RFC 7523 Section 3: the authorization server MUST reject an assertion whose
// audience does not identify it, and MUST reject one that has expired or whose
// signature does not verify.
func TestTokenEndpointRejectsMalformedAssertions(t *testing.T) {
	p := newTestPlugin(t)

	// A live registration so the subject resolves; only the assertion varies.
	_, claimToken := registerAnonymously(t, p)
	p.mu.RLock()
	agentID := p.identities[claimToken].AgentID
	p.mu.RUnlock()

	sign := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = p.keySet.RSAKeyID()
		signed, err := token.SignedString(p.keySet.RSAPrivateKey())
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	now := time.Now()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": p.issuer(),
			"sub": agentID,
			"aud": p.issuer(),
			"exp": now.Add(time.Minute).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
			"jti": randomToken(),
		}
	}

	wrongAudience := base()
	wrongAudience["aud"] = "https://somewhere.else"

	expired := base()
	expired["exp"] = now.Add(-time.Minute).Unix()

	notYetValid := base()
	notYetValid["nbf"] = now.Add(time.Hour).Unix()

	unknownSubject := base()
	unknownSubject["sub"] = "agent-does-not-exist"

	noJTI := base()
	delete(noJTI, "jti")

	testCases := []struct {
		name      string
		assertion string
	}{
		{"audience does not identify this server", sign(wrongAudience)},
		{"assertion has expired", sign(expired)},
		{"assertion is not yet valid", sign(notYetValid)},
		{"subject is not a registered agent", sign(unknownSubject)},
		{"assertion has no jti", sign(noJTI)},
		{"signature does not verify", sign(base()) + "tampered"},
		{"assertion is not a JWT", "not-a-jwt"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			status, body := postForm(t, p.handleToken, "/agentauth/token", url.Values{
				"grant_type": {grantTypeJWTBearer},
				"assertion":  {testCase.assertion},
			})
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %v)", status, body)
			}
			if body["error"] != "invalid_grant" {
				t.Errorf("error = %#v, want invalid_grant", body["error"])
			}
		})
	}
}

// RFC 6749 Section 5.2: an unrecognised grant is unsupported_grant_type.
func TestTokenEndpointRejectsUnsupportedGrant(t *testing.T) {
	p := newTestPlugin(t)

	status, body := postForm(t, p.handleToken, "/agentauth/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"irrelevant"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %#v, want unsupported_grant_type", body["error"])
	}
}

// Advertising an identity type the server cannot verify would tell an agent its
// assertion had been checked when it had not, so anything but anonymous is
// refused.
func TestIdentityEndpointRejectsUnsupportedIdentityType(t *testing.T) {
	p := newTestPlugin(t)

	status, body := postJSON(t, p.handleIdentity, "/agentauth/identity",
		`{"type":"identity_assertion","assertion":"eyJhbGciOiJSUzI1NiJ9.e30.x"}`)

	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
	if body["error"] != "unsupported_identity_type" {
		t.Errorf("error = %#v, want unsupported_identity_type", body["error"])
	}
}

// The claim ceremony follows the RFC 8628 polling model end to end: pending
// while the person has not acted, then a wider scope and a fresh assertion once
// they have.
func TestClaimCeremonyPromotesAgent(t *testing.T) {
	p := newTestPlugin(t)
	_, claimToken := registerAnonymously(t, p)

	status, start := postJSON(t, p.handleClaimStart, "/agentauth/identity/claim",
		`{"claim_token":"`+claimToken+`","email":"owner@example.com"}`)
	if status != http.StatusOK {
		t.Fatalf("claim start status = %d, body = %v", status, start)
	}

	userCode, _ := start["user_code"].(string)
	if userCode == "" {
		t.Fatal("claim start returned no user_code")
	}
	if start["verification_uri"] != p.issuer()+"/claim" {
		t.Errorf("verification_uri = %#v", start["verification_uri"])
	}
	if start["interval"] != float64(int(pollInterval.Seconds())) {
		t.Errorf("interval = %#v, want %v", start["interval"], pollInterval.Seconds())
	}

	poll := url.Values{"grant_type": {grantTypeClaim}, "claim_token": {claimToken}}

	// RFC 8628 Section 3.5: authorization_pending until the person approves.
	status, body := postForm(t, p.handleToken, "/agentauth/token", poll)
	if status != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d %#v, want 400 authorization_pending", status, body["error"])
	}

	// Polling again immediately is faster than the advertised interval.
	status, body = postForm(t, p.handleToken, "/agentauth/token", poll)
	if status != http.StatusBadRequest || body["error"] != "slow_down" {
		t.Fatalf("immediate re-poll = %d %#v, want 400 slow_down", status, body["error"])
	}

	// The person approves in the browser.
	status, completed := postJSON(t, p.handleClaimComplete, "/agentauth/identity/claim/complete",
		`{"user_code":"`+userCode+`"}`)
	if status != http.StatusOK {
		t.Fatalf("claim completion status = %d, body = %v", status, completed)
	}

	// Let the poll interval lapse so the next poll is not rate limited.
	p.mu.Lock()
	for _, attempt := range p.attempts {
		attempt.LastPolledAt = time.Now().Add(-2 * pollInterval)
	}
	p.mu.Unlock()

	status, granted := postForm(t, p.handleToken, "/agentauth/token", poll)
	if status != http.StatusOK {
		t.Fatalf("post-approval poll status = %d, body = %v", status, granted)
	}
	if granted["scope"] != scopePostClaim {
		t.Errorf("scope = %#v, want %q", granted["scope"], scopePostClaim)
	}
	if granted["owner_email"] != "owner@example.com" {
		t.Errorf("owner_email = %#v", granted["owner_email"])
	}

	newAssertion, _ := granted["identity_assertion"].(string)
	if newAssertion == "" {
		t.Fatal("no replacement identity assertion was issued")
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(newAssertion, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("replacement assertion did not parse: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["claimed"] != true {
		t.Errorf("claimed = %#v, want true", claims["claimed"])
	}
	if claims["assertion_version"] != float64(2) {
		t.Errorf("assertion_version = %#v, want 2", claims["assertion_version"])
	}
}

// RFC 8628 Section 3.3 treats the user_code as single use. Once redeemed the
// attempt is gone, so a second approval has nothing to act on.
func TestUserCodeIsRetiredAfterSuccessfulClaim(t *testing.T) {
	p := newTestPlugin(t)
	_, claimToken := registerAnonymously(t, p)

	_, start := postJSON(t, p.handleClaimStart, "/agentauth/identity/claim",
		`{"claim_token":"`+claimToken+`","email":"owner@example.com"}`)
	userCode, _ := start["user_code"].(string)

	postJSON(t, p.handleClaimComplete, "/agentauth/identity/claim/complete",
		`{"user_code":"`+userCode+`"}`)

	if status, _ := postForm(t, p.handleToken, "/agentauth/token", url.Values{
		"grant_type":  {grantTypeClaim},
		"claim_token": {claimToken},
	}); status != http.StatusOK {
		t.Fatalf("claim redemption status = %d, want 200", status)
	}

	status, body := postJSON(t, p.handleClaimComplete, "/agentauth/identity/claim/complete",
		`{"user_code":"`+userCode+`"}`)
	if status != http.StatusBadRequest {
		t.Fatalf("second approval status = %d, want 400", status)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error = %#v, want invalid_grant", body["error"])
	}
}

// RFC 8628 Section 6.1: the user_code alphabet omits characters a person can
// confuse when reading a code aloud or retyping it.
func TestUserCodeUsesUnambiguousAlphabet(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		code := newUserCode()
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("user_code %q does not have the XXXX-XXXX shape", code)
		}
		for _, char := range strings.ReplaceAll(code, "-", "") {
			if !strings.ContainsRune(userCodeAlphabet, char) {
				t.Fatalf("user_code %q contains %q, which is outside the alphabet", code, char)
			}
		}
	}
}

// RFC 7009 Section 2.2: revocation always answers 200, and a revoked
// registration can no longer be redeemed.
func TestRevocationPreventsFurtherRedemption(t *testing.T) {
	p := newTestPlugin(t)
	_, claimToken := registerAnonymously(t, p)

	request := httptest.NewRequest(http.MethodPost, testIssuer+"/agentauth/revoke",
		strings.NewReader(url.Values{"token": {claimToken}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	p.handleRevoke(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("revocation status = %d, want 200", response.Code)
	}

	// A fresh assertion for the revoked agent must not be redeemable.
	p.mu.RLock()
	identity := *p.identities[claimToken]
	p.mu.RUnlock()
	assertion, _, err := p.mintIdentityAssertion(&identity)
	if err != nil {
		t.Fatal(err)
	}

	status, body := postForm(t, p.handleToken, "/agentauth/token", url.Values{
		"grant_type": {grantTypeJWTBearer},
		"assertion":  {assertion},
	})
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("redemption after revocation = %d %#v, want 400 invalid_grant", status, body["error"])
	}
}

// Unknown tokens must not be distinguishable from known ones at the revocation
// endpoint (RFC 7009 Section 2.2).
func TestRevocationOfUnknownTokenSucceeds(t *testing.T) {
	p := newTestPlugin(t)

	request := httptest.NewRequest(http.MethodPost, testIssuer+"/agentauth/revoke",
		strings.NewReader(url.Values{"token": {"never-issued"}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	p.handleRevoke(response, request)

	if response.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for an unknown token", response.Code)
	}
}

// Every URL the agent_auth block advertises must be one this plugin serves,
// because an agent follows them without asking anything else.
func TestAgentAuthMetadataPointsAtRealRoutes(t *testing.T) {
	p := newTestPlugin(t)
	block := p.AgentAuthMetadata()

	wantPrefix := p.issuer()
	for _, field := range []string{"register_uri", "identity_endpoint", "claim_endpoint", "claim_uri", "token_endpoint", "revocation_uri", "verification_uri"} {
		value, _ := block[field].(string)
		if !strings.HasPrefix(value, wantPrefix) {
			t.Errorf("agent_auth.%s = %q, want it under %q", field, value, wantPrefix)
		}
	}

	if block["skill"] != testIssuer+"/auth.md" {
		t.Errorf("agent_auth.skill = %#v, want the auth.md document", block["skill"])
	}

	// ID-JAG is not implemented, so it must not be advertised.
	for _, identityType := range block["identity_types_supported"].([]string) {
		if identityType == identityTypeAssertion {
			t.Error("identity_types_supported advertises identity_assertion, which this server cannot verify")
		}
	}
}

// The metadata document has to satisfy RFC 8414 Section 2 on its own terms.
func TestAuthorizationServerMetadataIsWellFormed(t *testing.T) {
	p := newTestPlugin(t)
	metadata := p.AuthorizationServerMetadata()

	if metadata["issuer"] != testIssuer+"/agentauth" {
		t.Errorf("issuer = %#v", metadata["issuer"])
	}
	if metadata["token_endpoint"] != testIssuer+"/agentauth/token" {
		t.Errorf("token_endpoint = %#v", metadata["token_endpoint"])
	}

	grants, _ := metadata["grant_types_supported"].([]string)
	for _, want := range []string{grantTypeJWTBearer, grantTypeClaim} {
		found := false
		for _, grant := range grants {
			if grant == want {
				found = true
			}
		}
		if !found {
			t.Errorf("grant_types_supported = %v, want it to contain %q", grants, want)
		}
	}

	// RFC 8414 Section 2 marks this REQUIRED even for a server with no
	// authorization endpoint.
	if _, present := metadata["response_types_supported"]; !present {
		t.Error("response_types_supported is missing")
	}
}
