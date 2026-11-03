package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func get(t *testing.T, target string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func postForm(t *testing.T, target string, form url.Values, header http.Header) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, values := range header {
		req.Header[key] = values
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func decodeJSON(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var decoded map[string]interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return decoded
}

// verifyRequestObject checks a request object against the key the
// scenario's DID Document publishes, as a wallet resolving did:web would.
func verifyRequestObject(t *testing.T, serverURL, scenario, compact string) (jwt.MapClaims, error) {
	t.Helper()
	_, body := get(t, serverURL+"/scenarios/"+scenario+"/did.json")
	var document struct {
		VerificationMethod []struct {
			ID           string          `json:"id"`
			PublicKeyJwk json.RawMessage `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	if err := json.Unmarshal(body, &document); err != nil || len(document.VerificationMethod) != 1 {
		t.Fatalf("did.json for %s: %v %s", scenario, err, body)
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(document.VerificationMethod[0].PublicKeyJwk); err != nil {
		t.Fatalf("publicKeyJwk: %v", err)
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(compact, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Header["typ"] != "oauth-authz-req+jwt" || token.Header["kid"] != document.VerificationMethod[0].ID {
			t.Fatalf("%s header = %v", scenario, token.Header)
		}
		return key.Key, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return claims, err
	}
	return token.Claims.(jwt.MapClaims), nil
}

func TestRequestObjectsBreakOneRuleEach(t *testing.T) {
	server := newTestServer(t)

	for scenario, check := range map[string]func(jwt.MapClaims) bool{
		"vp-001": func(c jwt.MapClaims) bool {
			return strings.HasPrefix(c["client_id"].(string), "entity_id:") && c["client_id_scheme"] == "pre-registered"
		},
		"vp-002": func(c jwt.MapClaims) bool { return strings.HasPrefix(c["client_id"].(string), "unregistered_prefix:") },
		"vp-003": func(c jwt.MapClaims) bool {
			return c["x_protocolsoup_extension"] != nil && strings.HasPrefix(c["client_id"].(string), "decentralized_identifier:did:web:")
		},
		"vp-011": func(c jwt.MapClaims) bool {
			entries, _ := c["transaction_data"].([]interface{})
			if len(entries) != 1 {
				return false
			}
			decoded, err := base64.RawURLEncoding.DecodeString(entries[0].(string))
			return err == nil && strings.Contains(string(decoded), "/scenarios/vp-011/transaction-type")
		},
	} {
		resp, body := get(t, server.URL+"/scenarios/"+scenario+"/request")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/oauth-authz-req+jwt" {
			t.Fatalf("%s: %d %s", scenario, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		claims, err := verifyRequestObject(t, server.URL, scenario, string(body))
		if err != nil {
			t.Fatalf("%s: request object does not verify: %v", scenario, err)
		}
		if !check(claims) {
			t.Fatalf("%s: claims do not break the scenario's rule: %v", scenario, claims)
		}
	}

	resp, body := postForm(t, server.URL+"/scenarios/vp-012/request", url.Values{"wallet_nonce": {"the-wallets-nonce"}}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vp-012: %d %s", resp.StatusCode, body)
	}
	claims, err := verifyRequestObject(t, server.URL, "vp-012", string(body))
	if err != nil || claims["wallet_nonce"] == "the-wallets-nonce" || claims["wallet_nonce"] == nil {
		t.Fatalf("vp-012 must answer with a different wallet_nonce: %v %v", claims["wallet_nonce"], err)
	}

	resp, body = get(t, server.URL+"/scenarios/vp-004/request")
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || decodeJSON(t, body)["request"] == nil {
		t.Fatalf("vp-004 must wrap the request object in JSON: %s %s", resp.Header.Get("Content-Type"), body)
	}

	_, body = get(t, server.URL+"/scenarios/cw-h017/request")
	if _, err := verifyRequestObject(t, server.URL, "cw-h017", string(body)); err == nil {
		t.Fatal("cw-h017's request object must not verify")
	}
}

func TestVP003ResponseAcceptsOnlyAServedState(t *testing.T) {
	server := newTestServer(t)
	_, body := get(t, server.URL+"/scenarios/vp-003/request")
	claims, err := verifyRequestObject(t, server.URL, "vp-003", string(body))
	if err != nil {
		t.Fatalf("vp-003 request: %v", err)
	}
	state := claims["state"].(string)
	if resp, body := postForm(t, server.URL+"/scenarios/vp-003/response", url.Values{"state": {"unknown"}, "vp_token": {"x"}}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown state: %d %s", resp.StatusCode, body)
	}
	if resp, body := postForm(t, server.URL+"/scenarios/vp-003/response", url.Values{"state": {state}, "vp_token": {"x"}}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("served state: %d %s", resp.StatusCode, body)
	}
	if resp, _ := postForm(t, server.URL+"/scenarios/vp-003/response", url.Values{"state": {state}, "vp_token": {"x"}}, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("a state must be answered once")
	}
}

func TestIssuerMetadataBreaksOneRuleEach(t *testing.T) {
	server := newTestServer(t)
	metadata := func(scenario string) map[string]interface{} {
		resp, body := get(t, server.URL+"/.well-known/openid-credential-issuer/scenarios/"+scenario)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s metadata: %d", scenario, resp.StatusCode)
		}
		return decodeJSON(t, body)
	}
	base := "http://counterparty.test/scenarios/"
	if got := metadata("ci-010")["credential_issuer"]; got != base+"ci-010" {
		t.Fatalf("ci-010 credential_issuer = %v", got)
	}
	if got := metadata("cw-024")["credential_issuer"]; got != base+"cw-024/" {
		t.Fatalf("cw-024 credential_issuer = %v, want a trailing slash", got)
	}
	if got := metadata("cw-010")["authorization_servers"]; len(got.([]interface{})) != 1 {
		t.Fatalf("cw-010 authorization_servers = %v", got)
	}
	configuration := metadata("cw-h014")["credential_configurations_supported"].(map[string]interface{})[counterpartyConfigurationID].(map[string]interface{})
	required := configuration["proof_types_supported"].(map[string]interface{})["jwt"].(map[string]interface{})["key_attestations_required"].(map[string]interface{})
	if required["key_storage"] == nil || required["user_authentication"] == nil {
		t.Fatalf("cw-h014 key_attestations_required = %v", required)
	}

	resp, body := get(t, server.URL+"/.well-known/oauth-authorization-server/scenarios/cw-h003")
	as := decodeJSON(t, body)
	if resp.StatusCode != http.StatusOK || as["require_pushed_authorization_requests"] != true ||
		len(as["code_challenge_methods_supported"].([]interface{})) != 1 || as["code_challenge_methods_supported"].([]interface{})[0] != "plain" {
		t.Fatalf("cw-h003 authorization server metadata = %v", as)
	}

	offer := func(scenario string) map[string]interface{} {
		_, body := get(t, server.URL+"/scenarios/"+scenario+"/credential-offer")
		return decodeJSON(t, body)["grants"].(map[string]interface{})["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})
	}
	if txCode, ok := offer("cw-006")["tx_code"].(map[string]interface{}); !ok || len(txCode) != 0 {
		t.Fatalf("cw-006 offer must carry an empty tx_code object: %v", txCode)
	}
	if hint := offer("cw-010")["authorization_server"]; hint != base+"cw-010/as-unlisted" {
		t.Fatalf("cw-010 offer authorization_server = %v", hint)
	}
}

// redeemOffer runs a scenario's offer and token request, returning the
// access token.
func redeemOffer(t *testing.T, serverURL, scenario string) string {
	t.Helper()
	_, body := get(t, serverURL+"/scenarios/"+scenario+"/credential-offer")
	code := decodeJSON(t, body)["grants"].(map[string]interface{})["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})["pre-authorized_code"].(string)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}, "pre-authorized_code": {code}}
	resp, body := postForm(t, serverURL+"/scenarios/"+scenario+"/token", form, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s token: %d %s", scenario, resp.StatusCode, body)
	}
	if resp, _ := postForm(t, serverURL+"/scenarios/"+scenario+"/token", form, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s: a pre-authorized code must redeem once", scenario)
	}
	return decodeJSON(t, body)["access_token"].(string)
}

func TestCI010CredentialEndpointAnswersAnEmptyCredentialsArray(t *testing.T) {
	server := newTestServer(t)
	accessToken := redeemOffer(t, server.URL, "ci-010")
	if resp, _ := postForm(t, server.URL+"/scenarios/ci-010/credential", nil, http.Header{"Authorization": {"Bearer wrong"}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unknown access token must be refused, got %d", resp.StatusCode)
	}
	resp, body := postForm(t, server.URL+"/scenarios/ci-010/credential", nil, http.Header{"Authorization": {"Bearer " + accessToken}})
	credentials, ok := decodeJSON(t, body)["credentials"].([]interface{})
	if resp.StatusCode != http.StatusOK || !ok || len(credentials) != 0 {
		t.Fatalf("ci-010 credential response: %d %s", resp.StatusCode, body)
	}
}

// TestCW072EncryptsTheResponseWithAnUnnegotiatedAlgorithm sends the
// encrypted Credential Request a wallet would and checks the response is a
// JWE under ECDH-ES+A256KW to the wallet's key, not the negotiated ECDH-ES.
func TestCW072EncryptsTheResponseWithAnUnnegotiatedAlgorithm(t *testing.T) {
	server := newTestServer(t)
	accessToken := redeemOffer(t, server.URL, "cw-072")

	_, body := get(t, server.URL+"/.well-known/openid-credential-issuer/scenarios/cw-072")
	var metadata struct {
		RequestEncryption struct {
			JWKS jose.JSONWebKeySet `json:"jwks"`
		} `json:"credential_request_encryption"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil || len(metadata.RequestEncryption.JWKS.Keys) != 1 {
		t.Fatalf("cw-072 credential_request_encryption: %v %s", err, body)
	}
	walletKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	walletJWK := jose.JSONWebKey{Key: &walletKey.PublicKey, Algorithm: "ECDH-ES", Use: "enc", KeyID: "wallet-response"}
	plaintext, _ := json.Marshal(map[string]interface{}{
		"credential_configuration_id":    counterpartyConfigurationID,
		"credential_response_encryption": map[string]interface{}{"jwk": walletJWK, "enc": "A256GCM"},
	})
	issuerKey := metadata.RequestEncryption.JWKS.Keys[0]
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: issuerKey.Key, KeyID: issuerKey.KeyID}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	object, _ := encrypter.Encrypt(plaintext)
	compact, _ := object.CompactSerialize()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/scenarios/cw-072/credential", strings.NewReader(compact))
	req.Header.Set("Content-Type", "application/jwt")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST credential: %v", err)
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/jwt" {
		t.Fatalf("cw-072 credential response: %d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), responseBody)
	}
	if _, err := jose.ParseEncrypted(string(responseBody), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM}); err == nil {
		t.Fatal("a wallet that negotiated ECDH-ES must not be able to parse the response as ECDH-ES")
	}
	response, err := jose.ParseEncrypted(string(responseBody), []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("parse as ECDH-ES+A256KW: %v", err)
	}
	if decrypted, err := response.Decrypt(walletKey); err != nil || !strings.Contains(string(decrypted), "carries no Credential") {
		t.Fatalf("decrypt with the wallet key: %v %s", err, decrypted)
	}
}
