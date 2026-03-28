package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func TestWellKnownMetadataURLCandidatesWithIssuerPath(t *testing.T) {
	candidates, err := wellKnownMetadataURLCandidates("https://issuer.example/oid4vci", "openid-credential-issuer")
	if err != nil {
		t.Fatalf("wellKnownMetadataURLCandidates: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatalf("expected at least one metadata candidate")
	}
	if candidates[0] != "https://issuer.example/.well-known/openid-credential-issuer/oid4vci" {
		t.Fatalf("unexpected canonical candidate %q", candidates[0])
	}
}

func TestParseExternalCredentialOfferInputSupportsOpenIDCredentialOffer(t *testing.T) {
	resolved, err := parseExternalCredentialOfferInput("openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fcredential-offer%2Fabc")
	if err != nil {
		t.Fatalf("parseExternalCredentialOfferInput: %v", err)
	}
	if resolved.OfferURI != "https://issuer.example/credential-offer/abc" {
		t.Fatalf("unexpected credential_offer_uri %q", resolved.OfferURI)
	}
	if resolved.TransportMode != "by_reference" {
		t.Fatalf("unexpected transport mode %q", resolved.TransportMode)
	}
}

func TestIssueFromExternalIssuerRequiresTxCode(t *testing.T) {
	server := &walletHarnessServer{
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	wallet, err := server.getOrCreateWallet("req:tx-code", "did:example:wallet:holder", "")
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}

	_, err = server.issueFromExternalIssuer(context.Background(), wallet, externalIssuerImportRequest{
		OfferInput: `{
			"credential_issuer":"https://issuer.example/oid4vci",
			"credential_configuration_ids":["ExternalUniversityDegree"],
			"grants":{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code":{
					"pre-authorized_code":"pre-auth-code",
					"tx_code":{"description":"Enter the code from email","length":6,"input_mode":"numeric"}
				}
			}
		}`,
	})
	if err == nil {
		t.Fatalf("expected missing tx_code to fail")
	}
	apiErr, ok := err.(*walletAPIError)
	if !ok {
		t.Fatalf("expected walletAPIError, got %T", err)
	}
	if apiErr.Status != http.StatusBadRequest {
		t.Fatalf("unexpected status %d", apiErr.Status)
	}
	if apiErr.Fields["tx_code_required"] != true {
		t.Fatalf("expected tx_code_required field in error")
	}
}

func TestIssueFromExternalIssuerImportsCredential(t *testing.T) {
	const (
		preAuthorizedCode = "pre-auth-code"
		accessToken       = "access-token"
		cNonce            = "nonce-123"
	)

	issuerPath := "/external-issuer"
	credentialConfigurationID := "ExternalUniversityDegree"

	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()
	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	credentialIssuer := testServer.URL + issuerPath
	offerURI := testServer.URL + "/credential-offer/test"

	mux.HandleFunc("/.well-known/openid-credential-issuer/external-issuer", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer": credentialIssuer,
			"authorization_servers": []string{
				credentialIssuer,
			},
			"credential_endpoint": credentialIssuer + "/credential",
			"jwks_uri":            testServer.URL + "/.well-known/jwks.json",
			"credential_configurations_supported": map[string]interface{}{
				credentialConfigurationID: map[string]interface{}{
					"format": "jwt_vc_json",
					"proof_types_supported": map[string]interface{}{
						"jwt": map[string]interface{}{
							"proof_signing_alg_values_supported": []string{"ES256", "RS256", "EdDSA"},
						},
					},
				},
			},
		})
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server/external-issuer", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":         credentialIssuer,
			"token_endpoint": credentialIssuer + "/token",
			"jwks_uri":       testServer.URL + "/.well-known/jwks.json",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(issuerKeySet.PublicJWKS())
	})

	mux.HandleFunc("/credential-offer/test", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":            credentialIssuer,
			"credential_configuration_ids": []string{credentialConfigurationID},
			"grants": map[string]interface{}{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
					"pre-authorized_code": preAuthorizedCode,
				},
			},
		})
	})

	mux.HandleFunc(issuerPath+"/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := r.FormValue("grant_type"); got != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
			http.Error(w, "unexpected grant_type "+got, http.StatusBadRequest)
			return
		}
		if got := r.FormValue("pre-authorized_code"); got != preAuthorizedCode {
			http.Error(w, "unexpected pre-authorized_code "+got, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"c_nonce":      cNonce,
		})
	})

	mux.HandleFunc(issuerPath+"/credential", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+accessToken {
			http.Error(w, "unexpected Authorization header", http.StatusUnauthorized)
			return
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := strings.TrimSpace(asString(payload["credential_configuration_id"])); got != credentialConfigurationID {
			http.Error(w, "unexpected credential_configuration_id", http.StatusBadRequest)
			return
		}
		if got := strings.TrimSpace(asString(payload["format"])); got != "jwt_vc_json" {
			http.Error(w, "unexpected credential format", http.StatusBadRequest)
			return
		}

		proof, ok := payload["proof"].(map[string]interface{})
		if !ok {
			http.Error(w, "missing proof object", http.StatusBadRequest)
			return
		}
		proofJWT := strings.TrimSpace(asString(proof["jwt"]))
		if proofJWT == "" {
			http.Error(w, "missing proof jwt", http.StatusBadRequest)
			return
		}
		decodedProof, err := intcrypto.DecodeTokenWithoutValidation(proofJWT)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := strings.TrimSpace(asString(decodedProof.Payload["aud"])); got != credentialIssuer {
			http.Error(w, "unexpected proof audience", http.StatusBadRequest)
			return
		}
		holderSubject := strings.TrimSpace(asString(decodedProof.Payload["sub"]))
		if holderSubject == "" {
			http.Error(w, "missing proof subject", http.StatusBadRequest)
			return
		}

		credential := signedCredentialJWT(t, credentialIssuer, jwt.SigningMethodRS256, issuerKeySet.RSAPrivateKey(), issuerKeySet.RSAKeyID(), holderSubject)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"format":     "jwt_vc_json",
			"credential": credential,
		})
	})

	server := &walletHarnessServer{
		httpClient:       testServer.Client(),
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	wallet, err := server.getOrCreateWallet("req:external", "did:example:wallet:holder", "")
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}

	result, err := server.issueFromExternalIssuer(context.Background(), wallet, externalIssuerImportRequest{
		OfferInput: "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURI),
	})
	if err != nil {
		t.Fatalf("issueFromExternalIssuer: %v", err)
	}
	if result == nil || result.IssuedCredential == nil {
		t.Fatalf("expected issued credential result")
	}
	if result.CredentialIssuer != credentialIssuer {
		t.Fatalf("unexpected credential issuer %q", result.CredentialIssuer)
	}
	if result.TokenEndpoint != credentialIssuer+"/token" {
		t.Fatalf("unexpected token endpoint %q", result.TokenEndpoint)
	}
	if result.IssuedCredential.CredentialFormat != "jwt_vc_json" {
		t.Fatalf("unexpected credential format %q", result.IssuedCredential.CredentialFormat)
	}
	if err := server.bindCredential(wallet, result.IssuedCredential.CredentialJWT, result.IssuedCredential.CredentialConfigID, result.IssuedCredential.CredentialFormat); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" {
		t.Fatalf("expected bound credential in wallet")
	}
	if wallet.CredentialConfigurationID != credentialConfigurationID {
		t.Fatalf("unexpected wallet credential configuration %q", wallet.CredentialConfigurationID)
	}
}

func TestImportDirectCredentialValidatesIssuerJWKS(t *testing.T) {
	t.Parallel()

	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	credentialIssuer := testServer.URL + "/issuer"
	mux.HandleFunc("/.well-known/openid-credential-issuer/issuer", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   credentialIssuer,
			"credential_endpoint": credentialIssuer + "/credential",
			"jwks_uri":            testServer.URL + "/.well-known/jwks.json",
			"credential_configurations_supported": map[string]interface{}{
				"UniversityDegreeCredential": map[string]interface{}{
					"format": "jwt_vc_json",
				},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":         credentialIssuer,
			"jwks_uri":       testServer.URL + "/.well-known/jwks.json",
			"token_endpoint": credentialIssuer + "/token",
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(issuerKeySet.PublicJWKS())
	})

	server := &walletHarnessServer{
		httpClient:       testServer.Client(),
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	credential := signedCredentialJWT(
		t,
		credentialIssuer,
		jwt.SigningMethodRS256,
		issuerKeySet.RSAPrivateKey(),
		issuerKeySet.RSAKeyID(),
		"did:key:zExampleHolder",
	)

	result, err := server.importDirectCredential(context.Background(), externalIssuerImportRequest{}, credential)
	if err != nil {
		t.Fatalf("importDirectCredential: %v", err)
	}
	if result == nil || result.IssuedCredential == nil {
		t.Fatalf("expected imported credential result")
	}
	if result.Source != "direct_import" {
		t.Fatalf("unexpected result source %q", result.Source)
	}
	if result.IssuedCredential.CredentialFormat != "jwt_vc_json" {
		t.Fatalf("unexpected credential format %q", result.IssuedCredential.CredentialFormat)
	}
	if result.CredentialIssuer != credentialIssuer {
		t.Fatalf("unexpected credential issuer %q", result.CredentialIssuer)
	}
}

func TestAuthorizationCodeImportRedirectAndCallback(t *testing.T) {
	t.Parallel()

	const credentialConfigurationID = "UniversityDegreeCredential"
	const walletBaseURL = "https://wallet.example"

	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	credentialIssuer := testServer.URL + "/issuer"
	mux.HandleFunc("/.well-known/openid-credential-issuer/issuer", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer": credentialIssuer,
			"authorization_servers": []string{
				credentialIssuer,
			},
			"credential_endpoint": credentialIssuer + "/credential",
			"jwks_uri":            testServer.URL + "/.well-known/jwks.json",
			"credential_configurations_supported": map[string]interface{}{
				credentialConfigurationID: map[string]interface{}{
					"format": "jwt_vc_json",
					"proof_types_supported": map[string]interface{}{
						"jwt": map[string]interface{}{
							"proof_signing_alg_values_supported": []string{"ES256", "RS256", "EdDSA"},
						},
					},
				},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/issuer", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                           credentialIssuer,
			"authorization_endpoint":           credentialIssuer + "/authorize",
			"token_endpoint":                   credentialIssuer + "/token",
			"jwks_uri":                         testServer.URL + "/.well-known/jwks.json",
			"code_challenge_methods_supported": []string{"S256"},
			"scopes_supported":                 []string{"openid"},
		})
	})
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(issuerKeySet.PublicJWKS())
	})
	mux.HandleFunc("/issuer/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := r.FormValue("grant_type"); got != "authorization_code" {
			http.Error(w, "unexpected grant_type "+got, http.StatusBadRequest)
			return
		}
		if got := r.FormValue("client_id"); got != "public-app" {
			http.Error(w, "unexpected client_id "+got, http.StatusBadRequest)
			return
		}
		if got := r.FormValue("redirect_uri"); got != walletBaseURL+"/api/oid4vci/callback" {
			http.Error(w, "unexpected redirect_uri "+got, http.StatusBadRequest)
			return
		}
		if got := r.FormValue("code"); got != "auth-code" {
			http.Error(w, "unexpected code "+got, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(r.FormValue("code_verifier")) == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "auth-access-token",
			"c_nonce":      "auth-c-nonce",
		})
	})
	mux.HandleFunc("/issuer/credential", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer auth-access-token" {
			http.Error(w, "unexpected Authorization header", http.StatusUnauthorized)
			return
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		proof, ok := payload["proof"].(map[string]interface{})
		if !ok {
			http.Error(w, "missing proof object", http.StatusBadRequest)
			return
		}
		proofJWT := strings.TrimSpace(asString(proof["jwt"]))
		if proofJWT == "" {
			http.Error(w, "missing proof jwt", http.StatusBadRequest)
			return
		}
		decodedProof, err := intcrypto.DecodeTokenWithoutValidation(proofJWT)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := strings.TrimSpace(asString(decodedProof.Payload["aud"])); got != credentialIssuer {
			http.Error(w, "unexpected proof audience", http.StatusBadRequest)
			return
		}
		holderSubject := strings.TrimSpace(asString(decodedProof.Payload["sub"]))
		if holderSubject == "" {
			http.Error(w, "missing proof subject", http.StatusBadRequest)
			return
		}
		credential := signedCredentialJWT(t, credentialIssuer, jwt.SigningMethodRS256, issuerKeySet.RSAPrivateKey(), issuerKeySet.RSAKeyID(), holderSubject)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"format":     "jwt_vc_json",
			"credential": credential,
		})
	})

	server := &walletHarnessServer{
		httpClient:        testServer.Client(),
		oid4vciClientID:   "public-app",
		walletSessionTTL:  10 * time.Minute,
		wallets:           make(map[string]*walletMaterial),
		oid4vciAuthStates: make(map[string]*pendingOID4VCIAuthState),
	}
	wallet, err := server.getOrCreateWallet("req:auth", "did:example:wallet:holder", walletBaseURL)
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}

	authOffer := `{"credential_issuer":"` + credentialIssuer + `","credential_configuration_ids":["` + credentialConfigurationID + `"],"grants":{"authorization_code":{"issuer_state":"issuer-state","authorization_server":"` + credentialIssuer + `"}}}`
	result, err := server.issueFromExternalIssuer(context.Background(), wallet, externalIssuerImportRequest{
		OfferInput:       authOffer,
		WalletBaseURL:    walletBaseURL,
		CredentialFormat: "jwt_vc_json",
	})
	if err != nil {
		t.Fatalf("issueFromExternalIssuer(auth code): %v", err)
	}
	if result == nil || !result.AuthorizationRequired {
		t.Fatalf("expected authorization redirect result")
	}
	if !strings.Contains(result.AuthorizationURL, "/issuer/authorize?") {
		t.Fatalf("unexpected authorization URL %q", result.AuthorizationURL)
	}

	server.mu.Lock()
	if len(server.oid4vciAuthStates) != 1 {
		server.mu.Unlock()
		t.Fatalf("expected one pending authorization state, got %d", len(server.oid4vciAuthStates))
	}
	var state string
	for pendingState := range server.oid4vciAuthStates {
		state = pendingState
	}
	server.mu.Unlock()

	callbackRequest := httptest.NewRequest(http.MethodGet, walletBaseURL+"/api/oid4vci/callback?code=auth-code&state="+url.QueryEscape(state), nil)
	callbackRequest.Host = "wallet.example"
	callbackRecorder := httptest.NewRecorder()

	server.handleAPIOID4VCICallback(callbackRecorder, callbackRequest)

	if callbackRecorder.Code != http.StatusFound {
		t.Fatalf("unexpected callback status %d: %s", callbackRecorder.Code, callbackRecorder.Body.String())
	}
	location, err := url.Parse(callbackRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("url.Parse(callback location): %v", err)
	}
	if location.IsAbs() {
		t.Fatalf("expected relative callback redirect, got %q", location.String())
	}
	if location.Path != "/" {
		t.Fatalf("unexpected callback redirect path %q", location.Path)
	}
	if got := location.Query().Get("oid4vci_status"); got != "success" {
		t.Fatalf("unexpected callback redirect status %q", got)
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" {
		t.Fatalf("expected wallet credential after callback")
	}
}

func TestOID4VCICallbackRedirectStaysSameOriginWhenStateMissing(t *testing.T) {
	t.Parallel()

	server := &walletHarnessServer{
		walletSessionTTL:  10 * time.Minute,
		oid4vciAuthStates: make(map[string]*pendingOID4VCIAuthState),
	}
	request := httptest.NewRequest(http.MethodGet, "https://wallet.example/api/oid4vci/callback?state=missing", nil)
	request.Host = "wallet.example"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "attacker.example")

	recorder := httptest.NewRecorder()
	server.handleAPIOID4VCICallback(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("unexpected callback status %d: %s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("url.Parse(callback location): %v", err)
	}
	if location.IsAbs() {
		t.Fatalf("expected relative redirect, got %q", location.String())
	}
	if location.Path != "/" {
		t.Fatalf("unexpected callback redirect path %q", location.Path)
	}
	if got := location.Query().Get("oid4vci_status"); got != "error" {
		t.Fatalf("unexpected callback redirect status %q", got)
	}
	if got := location.Query().Get("oid4vci_message"); got != "authorization state is missing or expired" {
		t.Fatalf("unexpected callback redirect message %q", got)
	}
}

func signedCredentialJWT(t *testing.T, issuer string, method jwt.SigningMethod, key interface{}, kid string, subject string) string {
	t.Helper()
	token := jwt.NewWithClaims(method, jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"vc": map[string]interface{}{
			"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"credentialSubject": map[string]interface{}{
				"id": subject,
			},
		},
	})
	token.Header["typ"] = "vc+jwt"
	if strings.TrimSpace(kid) != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString(credential): %v", err)
	}
	return signed
}
