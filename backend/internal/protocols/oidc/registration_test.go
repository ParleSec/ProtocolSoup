package oidc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

func newRegistrationPlugin(t *testing.T) *Plugin {
	t.Helper()
	p := newTestPlugin(t)
	p.dynamicRegistrationEnabled = true
	p.dynamicRegistrationTTL = time.Hour
	p.maxDynamicClients = 50
	p.registrationLimiter = newRegistrationRateLimiter(100, time.Minute)
	return p
}

func newOIDCTestMux(p *Plugin) http.Handler {
	r := chi.NewRouter()
	r.Route("/oidc", func(oidcRouter chi.Router) {
		p.RegisterRoutes(oidcRouter)
	})
	return r
}

func TestPairwiseRegistrationRequiresSectorDocumentForMultipleHosts(t *testing.T) {
	req := &registrationRequest{
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://one.example/callback", "https://two.example/callback"},
	}
	if err := validateRegistrationRequest(req); err == nil {
		t.Fatal("multiple pairwise redirect URI hosts were accepted without sector_identifier_uri")
	}

	req.SectorIdentifierURI = "https://sector.example/redirect-uris.json"
	if err := validateRegistrationRequest(req); err != nil {
		t.Fatalf("pairwise registration with HTTPS sector_identifier_uri rejected: %v", err)
	}
}

func TestDynamicRegistrationCreatesClientAndConfigRead(t *testing.T) {
	p := newRegistrationPlugin(t)
	mux := newOIDCTestMux(p)

	body := map[string]interface{}{
		"redirect_uris":                []string{"https://rp.example.com/callback"},
		"client_name":                  "OIDF Dynamic RP",
		"token_endpoint_auth_method":   "client_secret_basic",
		"logo_uri":                     "https://rp.example.com/logo.png",
		"policy_uri":                   "https://rp.example.com/policy",
		"tos_uri":                      "https://rp.example.com/tos",
		"initiate_login_uri":           "https://rp.example.com/initiate",
		"userinfo_signed_response_alg": "RS256",
		"unknown_extension":            "ignored",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s, want 201", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rr.Header().Get("Cache-Control"))
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}
	clientID, _ := resp["client_id"].(string)
	secret, _ := resp["client_secret"].(string)
	rat, _ := resp["registration_access_token"].(string)
	rcu, _ := resp["registration_client_uri"].(string)
	if clientID == "" || secret == "" || rat == "" || rcu == "" {
		t.Fatalf("missing credentials in response: %#v", resp)
	}
	if _, ok := resp["unknown_extension"]; ok {
		t.Fatalf("unknown metadata must be ignored, not echoed")
	}
	if resp["initiate_login_uri"] != "https://rp.example.com/initiate" {
		t.Fatalf("initiate_login_uri = %v", resp["initiate_login_uri"])
	}
	if resp["userinfo_signed_response_alg"] != "RS256" {
		t.Fatalf("userinfo_signed_response_alg = %v", resp["userinfo_signed_response_alg"])
	}

	cfgReq := httptest.NewRequest(http.MethodGet, "/oidc/register/"+clientID, nil)
	cfgReq.Header.Set("Authorization", "Bearer "+rat)
	cfgRR := httptest.NewRecorder()
	mux.ServeHTTP(cfgRR, cfgReq)

	if cfgRR.Code != http.StatusOK {
		t.Fatalf("config GET status = %d body=%s, want 200", cfgRR.Code, cfgRR.Body.String())
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(cfgRR.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfg["client_id"] != clientID {
		t.Fatalf("config client_id = %v, want %s", cfg["client_id"], clientID)
	}
	if cfg["initiate_login_uri"] != "https://rp.example.com/initiate" {
		t.Fatalf("config initiate_login_uri = %v", cfg["initiate_login_uri"])
	}
	if _, ok := cfg["registration_access_token"]; ok {
		t.Fatalf("configuration read must not re-issue registration_access_token")
	}
}

func TestDynamicRegistrationRejectsNonHTTPSInitiateLoginURI(t *testing.T) {
	p := newRegistrationPlugin(t)
	body := map[string]interface{}{
		"redirect_uris":      []string{"https://rp.example.com/callback"},
		"initiate_login_uri": "http://rp.example.com/initiate",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	p.handleRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var errBody map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &errBody)
	if errBody["error"] != "invalid_client_metadata" {
		t.Fatalf("error = %q, want invalid_client_metadata", errBody["error"])
	}
}

func TestDynamicRegistrationRejectsFragmentRedirectURI(t *testing.T) {
	p := newRegistrationPlugin(t)
	body := map[string]interface{}{
		"redirect_uris": []string{"https://rp.example.com/callback#frag"},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	p.handleRegister(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	var errBody map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &errBody)
	if errBody["error"] != "invalid_redirect_uri" {
		t.Fatalf("error = %q, want invalid_redirect_uri", errBody["error"])
	}
}

func TestDiscoveryAdvertisesRegistrationWhenEnabled(t *testing.T) {
	p := newRegistrationPlugin(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()
	p.handleDiscovery(rr, req)

	var doc map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, _ := doc["registration_endpoint"].(string)
	if !strings.HasSuffix(reg, "/oidc/register") {
		t.Fatalf("registration_endpoint = %q", reg)
	}
	if doc["request_uri_parameter_supported"] != true {
		t.Fatalf("request_uri_parameter_supported = %v, want true", doc["request_uri_parameter_supported"])
	}
	if !containsStringSlice(doc["grant_types_supported"], "implicit") {
		t.Fatalf("grant_types_supported missing implicit: %v", doc["grant_types_supported"])
	}
	if !containsStringSlice(doc["token_endpoint_auth_methods_supported"], "private_key_jwt") {
		t.Fatalf("missing private_key_jwt: %v", doc["token_endpoint_auth_methods_supported"])
	}
}

func TestThirdPartyInitiateRedirectsToRegisteredURI(t *testing.T) {
	p := newRegistrationPlugin(t)
	body := map[string]interface{}{
		"redirect_uris":      []string{"https://rp.example.com/callback"},
		"initiate_login_uri": "https://rp.example.com/start",
		"client_name":        "3P RP",
	}
	raw, _ := json.Marshal(body)
	regReq := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(raw))
	regReq.Header.Set("Content-Type", "application/json")
	regRR := httptest.NewRecorder()
	p.handleRegister(regRR, regReq)
	var resp map[string]interface{}
	_ = json.Unmarshal(regRR.Body.Bytes(), &resp)
	clientID, _ := resp["client_id"].(string)

	form := strings.NewReader("client_id=" + clientID + "&login_hint=alice%40example.com&target_link_uri=https%3A%2F%2Frp.example.com%2Fapp")
	req := httptest.NewRequest(http.MethodPost, "/oidc/third-party/initiate", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	p.handleThirdPartyInitiate(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d body=%s, want 302", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://rp.example.com/start?") {
		t.Fatalf("Location = %q", loc)
	}
	if !strings.Contains(loc, "iss=") {
		t.Fatalf("Location missing iss: %q", loc)
	}
	if !strings.Contains(loc, "login_hint=") {
		t.Fatalf("Location missing login_hint: %q", loc)
	}
	if !strings.Contains(loc, "target_link_uri=") {
		t.Fatalf("Location missing target_link_uri: %q", loc)
	}
}

func TestSignedUserInfoReturnsJWT(t *testing.T) {
	p := newRegistrationPlugin(t)
	body := map[string]interface{}{
		"redirect_uris":                []string{"https://rp.example.com/callback"},
		"userinfo_signed_response_alg": "RS256",
		"token_endpoint_auth_method":   "client_secret_post",
	}
	raw, _ := json.Marshal(body)
	regReq := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(raw))
	regReq.Header.Set("Content-Type", "application/json")
	regRR := httptest.NewRecorder()
	p.handleRegister(regRR, regReq)
	var resp map[string]interface{}
	_ = json.Unmarshal(regRR.Body.Bytes(), &resp)
	clientID, _ := resp["client_id"].(string)

	accessToken, err := p.mockIdP.JWTService().CreateAccessToken("alice", clientID, "openid profile email", time.Hour, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	p.handleUserInfo(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Fatalf("Content-Type = %q, want application/jwt", ct)
	}
	parts := strings.Split(rr.Body.String(), ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", rr.Body.String())
	}
	parsed, err := jwt.Parse(rr.Body.String(), func(token *jwt.Token) (interface{}, error) {
		return p.keySet.RSAPublicKey(), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("signed UserInfo JWT is invalid: %v", err)
	}
	signedClaims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("signed UserInfo claims type = %T", parsed.Claims)
	}
	if signedClaims["iss"] != p.mockIdP.GetIssuer() {
		t.Fatalf("signed UserInfo iss = %v, want %s", signedClaims["iss"], p.mockIdP.GetIssuer())
	}
	if signedClaims["aud"] != clientID {
		t.Fatalf("signed UserInfo aud = %v, want %s", signedClaims["aud"], clientID)
	}
}

func TestDynamicRegistrationManagementUpdateAndDelete(t *testing.T) {
	p := newRegistrationPlugin(t)
	mux := newOIDCTestMux(p)

	createBody, _ := json.Marshal(map[string]interface{}{
		"redirect_uris":              []string{"https://rp.example.com/old-callback"},
		"client_name":                "Original client",
		"logo_uri":                   "https://rp.example.com/logo.png",
		"token_endpoint_auth_method": "client_secret_basic",
	})
	createReq := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	mux.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("register status = %d body=%s", createRR.Code, createRR.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(createRR.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	clientID := created["client_id"].(string)
	clientSecret := created["client_secret"].(string)
	registrationToken := created["registration_access_token"].(string)

	updateBody, _ := json.Marshal(map[string]interface{}{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"redirect_uris":              []string{"https://rp.example.com/new-callback"},
		"client_name":                "Replacement client",
		"token_endpoint_auth_method": "client_secret_post",
	})
	updateReq := httptest.NewRequest(http.MethodPut, "/oidc/register/"+clientID, bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+registrationToken)
	updateRR := httptest.NewRecorder()
	mux.ServeHTTP(updateRR, updateReq)
	if updateRR.Code != http.StatusOK {
		t.Fatalf("update status = %d body=%s", updateRR.Code, updateRR.Body.String())
	}
	var updated map[string]interface{}
	if err := json.Unmarshal(updateRR.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	updatedToken, _ := updated["registration_access_token"].(string)
	if updatedToken == "" || updatedToken == registrationToken {
		t.Fatalf("update must rotate registration_access_token, got %q", updatedToken)
	}
	if updated["client_id"] != clientID || updated["client_name"] != "Replacement client" {
		t.Fatalf("unexpected update response: %#v", updated)
	}
	if _, ok := updated["logo_uri"]; ok {
		t.Fatalf("PUT must replace omitted metadata, response=%#v", updated)
	}

	oldTokenReadReq := httptest.NewRequest(http.MethodGet, "/oidc/register/"+clientID, nil)
	oldTokenReadReq.Header.Set("Authorization", "Bearer "+registrationToken)
	oldTokenReadRR := httptest.NewRecorder()
	mux.ServeHTTP(oldTokenReadRR, oldTokenReadReq)
	if oldTokenReadRR.Code != http.StatusUnauthorized {
		t.Fatalf("old registration token status = %d, want 401", oldTokenReadRR.Code)
	}

	readReq := httptest.NewRequest(http.MethodGet, "/oidc/register/"+clientID, nil)
	readReq.Header.Set("Authorization", "Bearer "+updatedToken)
	readRR := httptest.NewRecorder()
	mux.ServeHTTP(readRR, readReq)
	if readRR.Code != http.StatusOK {
		t.Fatalf("updated config GET status = %d body=%s", readRR.Code, readRR.Body.String())
	}
	var current map[string]interface{}
	if err := json.Unmarshal(readRR.Body.Bytes(), &current); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if current["client_name"] != "Replacement client" {
		t.Fatalf("client_name = %v, want replacement", current["client_name"])
	}
	redirectURIs, ok := current["redirect_uris"].([]interface{})
	if !ok || len(redirectURIs) != 1 || redirectURIs[0] != "https://rp.example.com/new-callback" {
		t.Fatalf("redirect_uris = %#v", current["redirect_uris"])
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/oidc/register/"+clientID, nil)
	deleteReq.Header.Set("Authorization", "Bearer "+updatedToken)
	deleteRR := httptest.NewRecorder()
	mux.ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s, want 204", deleteRR.Code, deleteRR.Body.String())
	}
	if deleteRR.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("delete Cache-Control = %q, want no-store", deleteRR.Header().Get("Cache-Control"))
	}
	if _, exists := p.mockIdP.GetClient(clientID); exists {
		t.Fatal("deleted client is still registered")
	}

	deletedReadReq := httptest.NewRequest(http.MethodGet, "/oidc/register/"+clientID, nil)
	deletedReadReq.Header.Set("Authorization", "Bearer "+updatedToken)
	deletedReadRR := httptest.NewRecorder()
	mux.ServeHTTP(deletedReadRR, deletedReadReq)
	if deletedReadRR.Code != http.StatusUnauthorized {
		t.Fatalf("deleted config GET status = %d, want 401", deletedReadRR.Code)
	}
	if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err == nil {
		t.Fatal("deleted client remained valid at the token endpoint")
	}
	deletedAuthorizeRR := doAuthorize(t, p, url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {"https://rp.example.com/new-callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	})
	if deletedAuthorizeRR.Code != http.StatusBadRequest {
		t.Fatalf("deleted authorization client status = %d, want 400", deletedAuthorizeRR.Code)
	}
}

func TestDynamicRegistrationManagementRejectsInvalidUpdateMetadata(t *testing.T) {
	p := newRegistrationPlugin(t)
	mux := newOIDCTestMux(p)

	createBody, _ := json.Marshal(map[string]interface{}{
		"redirect_uris":              []string{"https://rp.example.com/callback"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	createReq := httptest.NewRequest(http.MethodPost, "/oidc/register", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	mux.ServeHTTP(createRR, createReq)
	var created map[string]interface{}
	_ = json.Unmarshal(createRR.Body.Bytes(), &created)
	clientID := created["client_id"].(string)
	registrationToken := created["registration_access_token"].(string)

	cases := []struct {
		name string
		body map[string]interface{}
	}{
		{
			name: "missing client id",
			body: map[string]interface{}{
				"redirect_uris": []string{"https://rp.example.com/callback"},
			},
		},
		{
			name: "mismatched client id",
			body: map[string]interface{}{
				"client_id":     "different-client",
				"redirect_uris": []string{"https://rp.example.com/callback"},
			},
		},
		{
			name: "response only field",
			body: map[string]interface{}{
				"client_id":               clientID,
				"registration_client_uri": "https://attacker.example/register",
				"redirect_uris":           []string{"https://rp.example.com/callback"},
			},
		},
		{
			name: "wrong client secret",
			body: map[string]interface{}{
				"client_id":     clientID,
				"client_secret": "wrong-secret",
				"redirect_uris": []string{"https://rp.example.com/callback"},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPut, "/oidc/register/"+clientID, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+registrationToken)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s, want 400", rr.Code, rr.Body.String())
			}
		})
	}

	invalidTokenReq := httptest.NewRequest(http.MethodDelete, "/oidc/register/"+clientID, nil)
	invalidTokenReq.Header.Set("Authorization", "Bearer invalid")
	invalidTokenRR := httptest.NewRecorder()
	mux.ServeHTTP(invalidTokenRR, invalidTokenReq)
	if invalidTokenRR.Code != http.StatusUnauthorized {
		t.Fatalf("invalid registration token status = %d, want 401", invalidTokenRR.Code)
	}
}

func containsStringSlice(raw interface{}, want string) bool {
	list, ok := raw.([]interface{})
	if !ok {
		return false
	}
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
