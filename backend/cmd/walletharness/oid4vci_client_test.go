package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	oid4vciprotocol "github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func TestCredentialOfferEnvelopeRejectsBothTransports(t *testing.T) {
	t.Parallel()
	if err := oid4vciprotocol.ValidateCredentialOfferEnvelope(true, true); err == nil {
		t.Fatal("expected CW-001 rejection when both credential_offer and credential_offer_uri are present")
	}
	if err := oid4vciprotocol.ValidateCredentialOfferEnvelope(false, false); err == nil {
		t.Fatal("expected rejection when neither offer transport is present")
	}
	if err := oid4vciprotocol.ValidateCredentialOfferEnvelope(true, false); err != nil {
		t.Fatalf("by-value offer should be accepted: %v", err)
	}
}

func TestMetadataCredentialIssuerMismatchRejection(t *testing.T) {
	t.Parallel()
	if sameURLIdentifier("https://issuer.example/oid4vci", "https://other.example/oid4vci") {
		t.Fatal("expected CW-024 mismatch for different credential_issuer identifiers")
	}
	if !sameURLIdentifier("https://issuer.example/oid4vci/", "https://issuer.example/oid4vci") {
		t.Fatal("trailing slash should not break issuer identity match")
	}
}

func TestPKCES256ChallengeGeneration(t *testing.T) {
	t.Parallel()
	verifier, challenge, method, err := buildPKCES256Pair([]string{"S256"}, true)
	if err != nil {
		t.Fatalf("buildPKCES256Pair: %v", err)
	}
	if method != "S256" {
		t.Fatalf("method = %q, want S256", method)
	}
	if got := generatePKCES256Challenge(verifier); got != challenge {
		t.Fatalf("challenge mismatch: got %q want %q", got, challenge)
	}
	_, _, _, err = buildPKCES256Pair([]string{"plain"}, true)
	if err == nil {
		t.Fatal("expected S256 requirement to fail when only plain is advertised")
	}
}

func TestCredentialRequestBuilderIdentifierExclusivity(t *testing.T) {
	t.Parallel()
	if err := validateCredentialRequestSelectorExclusivity("cfg", "id-1"); err == nil {
		t.Fatal("expected exclusivity error when both selectors are set")
	}
	built, err := buildCredentialRequestBody(credentialRequestBuildInput{
		CredentialConfigurationID: "cfg",
		CredentialIdentifiers:     []string{"id-1"},
		ProofJWT:                  "proof",
	})
	if err != nil {
		t.Fatalf("buildCredentialRequestBody: %v", err)
	}
	if _, ok := built.Body["credential_configuration_id"]; ok {
		t.Fatal("credential_identifiers must win over credential_configuration_id")
	}
	if got := asString(built.Body["credential_identifier"]); got != "id-1" {
		t.Fatalf("credential_identifier = %q", got)
	}
}

func TestBatchCredentialProofCountRespectsMetadataAndFormat(t *testing.T) {
	t.Parallel()
	if got := batchCredentialProofCount(10, true, "dc+sd-jwt"); got != 2 {
		t.Fatalf("sd-jwt batch count = %d, want 2", got)
	}
	if got := batchCredentialProofCount(10, true, "mso_mdoc"); got != 2 {
		t.Fatalf("mdoc batch count = %d, want 2", got)
	}
	if got := batchCredentialProofCount(10, false, "dc+sd-jwt"); got != 1 {
		t.Fatalf("unadvertised batch count = %d, want 1", got)
	}
	if got := batchCredentialProofCount(0, true, "dc+sd-jwt"); got != 2 {
		t.Fatalf("advertised with missing batch_size count = %d, want 2", got)
	}
	size, advertised := parseBatchCredentialIssuance(map[string]interface{}{"batch_size": "10"})
	if !advertised || size != 10 {
		t.Fatalf("parse string batch_size = (%d, %v)", size, advertised)
	}
}

func TestBuildCredentialRequestBodyIncludesMultipleProofs(t *testing.T) {
	t.Parallel()
	built, err := buildCredentialRequestBody(credentialRequestBuildInput{
		CredentialConfigurationID: "UniversityDegreeCredential",
		ProofJWTs:                 []string{"proof-a", "proof-b"},
	})
	if err != nil {
		t.Fatalf("buildCredentialRequestBody: %v", err)
	}
	proofs, ok := built.Body["proofs"].(map[string]interface{})
	if !ok {
		t.Fatalf("proofs missing: %#v", built.Body)
	}
	jwtProofs, ok := proofs["jwt"].([]string)
	if !ok || len(jwtProofs) != 2 {
		t.Fatalf("proofs.jwt = %#v", proofs["jwt"])
	}
	if jwtProofs[0] != "proof-a" || jwtProofs[1] != "proof-b" {
		t.Fatalf("proofs.jwt = %#v", jwtProofs)
	}
}

func TestHolderKeyThumbprintFromCredentialUsesCnfJWK(t *testing.T) {
	t.Parallel()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubJWK := intcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "holder")
	want := strings.TrimSpace(pubJWK.Thumbprint())
	claims := jwt.MapClaims{
		"iss": "https://issuer.example",
		"cnf": map[string]interface{}{"jwk": pubJWK},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := holderKeyThumbprintFromCredential(signed); got != want {
		t.Fatalf("thumbprint = %q, want %q", got, want)
	}
}

func TestPARFormIncludesCodeChallengeMethodS256(t *testing.T) {
	t.Parallel()
	form := map[string]string{
		"code_challenge_method": "S256",
		"code_challenge":        "abc",
		"response_type":         "code",
	}
	if form["code_challenge_method"] != "S256" {
		t.Fatalf("PAR form must include code_challenge_method=S256")
	}
	_, challenge, method, err := buildPKCES256Pair(nil, true)
	if err != nil {
		t.Fatalf("buildPKCES256Pair: %v", err)
	}
	if method != "S256" || challenge == "" {
		t.Fatalf("expected S256 challenge for PAR")
	}
}

func TestCredentialRequestEncryptionJWERoundTrip(t *testing.T) {
	t.Parallel()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwk := intcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "issuer-req-enc")
	jwk.Alg = string(jose.ECDH_ES)
	jwk.Use = "enc"
	support := &credentialRequestEncryptionSupport{
		EncValuesSupported: []string{string(jose.A128GCM), string(jose.A256GCM)},
		EncryptionRequired: false,
		Keys:               []intcrypto.JWK{jwk},
	}
	if shouldEncryptCredentialRequest(support, false) {
		t.Fatal("advertised request-encryption jwks with encryption_required=false must not force encryption")
	}
	if !shouldEncryptCredentialRequest(support, true) {
		t.Fatal("expected request encryption when the wallet also requests an encrypted credential response")
	}
	plaintext, _ := json.Marshal(map[string]interface{}{
		"credential_configuration_id": "org.iso.18013.5.1.mDL",
		"proofs":                      map[string]interface{}{"jwt": []string{"proof"}},
	})
	compact, err := encryptCredentialRequestBody(plaintext, support)
	if err != nil {
		t.Fatalf("encryptCredentialRequestBody: %v", err)
	}
	object, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM, jose.A256GCM})
	if err != nil {
		t.Fatalf("ParseEncrypted: %v", err)
	}
	decoded, err := object.Decrypt(privateKey)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("plaintext mismatch: %s", decoded)
	}

	parsed := parseCredentialRequestEncryptionSupport(map[string]interface{}{
		"enc_values_supported": []interface{}{"A128GCM"},
		"encryption_required":  false,
		"jwks": []interface{}{
			map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"use": "enc",
				"alg": "ECDH-ES",
				"kid": "suite-array-form",
				"x":   jwk.X,
				"y":   jwk.Y,
			},
		},
	})
	if !parsed.advertised() || parsed.Keys[0].Kid != "suite-array-form" {
		t.Fatalf("expected suite-style jwks array parse, got %#v", parsed)
	}
}

func TestCredentialResponseEncryptionJWERoundTrip(t *testing.T) {
	t.Parallel()
	support := &credentialResponseEncryptionSupport{
		AlgValuesSupported: []string{"ECDH-ES"},
		EncValuesSupported: []string{"A256GCM"},
		EncryptionRequired: true,
	}
	encObject, privateKey, err := buildCredentialResponseEncryptionObject(support, true)
	if err != nil {
		t.Fatalf("buildCredentialResponseEncryptionObject: %v", err)
	}
	jwkMap, _ := json.Marshal(encObject["jwk"])
	var jwk intcrypto.JWK
	if err := json.Unmarshal(jwkMap, &jwk); err != nil {
		t.Fatalf("decode jwk: %v", err)
	}
	pub, err := intcrypto.ParseECPublicKeyFromJWK(jwk)
	if err != nil {
		t.Fatalf("ParseECPublicKeyFromJWK: %v", err)
	}
	plaintext, _ := json.Marshal(map[string]interface{}{
		"credentials": []map[string]interface{}{
			{"credential": "vc-token"},
		},
	})
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, (&jose.EncrypterOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	decoded, err := decryptCredentialResponseJWT(compact, privateKey)
	if err != nil {
		t.Fatalf("decryptCredentialResponseJWT: %v", err)
	}
	credentials, _ := decoded["credentials"].([]interface{})
	if len(credentials) == 0 {
		t.Fatal("expected decrypted credentials")
	}
}

func TestIso18045ModerateNotClaimedWhenEnvUnset(t *testing.T) {
	t.Setenv("WALLET_KEY_ATTESTATION_KEY_STORAGE", "")
	t.Setenv("WALLET_KEY_ATTESTATION_USER_AUTHENTICATION", "")
	keyStorage, userAuth := keyAttestationClaimsFromEnv()
	if len(keyStorage) != 0 || len(userAuth) != 0 {
		t.Fatalf("expected empty attestation claims when env unset, got %v / %v", keyStorage, userAuth)
	}
	_ = os.Setenv("WALLET_KEY_ATTESTATION_KEY_STORAGE", "iso_18045_moderate")
	_ = os.Setenv("WALLET_KEY_ATTESTATION_USER_AUTHENTICATION", "iso_18045_moderate")
	t.Cleanup(func() {
		_ = os.Unsetenv("WALLET_KEY_ATTESTATION_KEY_STORAGE")
		_ = os.Unsetenv("WALLET_KEY_ATTESTATION_USER_AUTHENTICATION")
	})
	keyStorage, userAuth = keyAttestationClaimsFromEnv()
	if len(keyStorage) != 1 || keyStorage[0] != "iso_18045_moderate" {
		t.Fatalf("unexpected key_storage %v", keyStorage)
	}
	if len(userAuth) != 1 || userAuth[0] != "iso_18045_moderate" {
		t.Fatalf("unexpected user_authentication %v", userAuth)
	}
}

func TestRFC9207IssMismatchRejection(t *testing.T) {
	t.Parallel()
	if err := validateAuthorizationResponseIss("https://as.example/oid4vci", "https://evil.example", true); err == nil {
		t.Fatal("expected iss mismatch rejection")
	}
	if err := validateAuthorizationResponseIss("https://as.example/oid4vci", "", true); err == nil {
		t.Fatal("expected missing iss rejection when required")
	}
	if err := validateAuthorizationResponseIss("https://as.example/oid4vci", "https://as.example/oid4vci", true); err != nil {
		t.Fatalf("matching iss should pass: %v", err)
	}
}

func TestStateSingleUseHelper(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	states := map[string]*pendingOID4VCIAuthState{
		"abc": {
			State:     "abc",
			ExpiresAt: now.Add(5 * time.Minute),
		},
	}
	pending, err := consumePendingOID4VCIAuthState(states, "abc", now)
	if err != nil || pending == nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	if _, err := consumePendingOID4VCIAuthState(states, "abc", now); err == nil {
		t.Fatal("second consume must fail (single-use)")
	}
}

func TestConfigurationRequiresKeyAttestationFromMetadata(t *testing.T) {
	t.Parallel()
	if configurationRequiresKeyAttestation(map[string]interface{}{
		"proof_types_supported": map[string]interface{}{
			"jwt": map[string]interface{}{
				"key_attestations_required": map[string]interface{}{},
			},
		},
	}) != true {
		t.Fatal("expected key_attestations_required metadata to enable HAIP path")
	}
	if configurationRequiresKeyAttestation(map[string]interface{}{
		"proof_types_supported": map[string]interface{}{
			"jwt": map[string]interface{}{
				"proof_signing_alg_values_supported": []string{"ES256"},
			},
		},
	}) {
		t.Fatal("did not expect key attestation without key_attestations_required")
	}
}

func TestClientAttestationIssuerEnvOverride(t *testing.T) {
	t.Setenv("WALLET_CLIENT_ATTESTATION_ISSUER", "https://custom.attester.example")
	if got := clientAttestationIssuer(); got != "https://custom.attester.example" {
		t.Fatalf("clientAttestationIssuer = %q", got)
	}
	t.Setenv("WALLET_CLIENT_ATTESTATION_ISSUER", "")
	if got := clientAttestationIssuer(); got != "https://wallet.protocolsoup.com/attester" {
		t.Fatalf("default clientAttestationIssuer = %q", got)
	}
}

func TestBuildAuthorizationURLFromPAR(t *testing.T) {
	t.Parallel()
	got, err := buildAuthorizationURLFromPAR("https://as.example/authorize", "wallet-client", "urn:ietf:params:oauth:request_uri:abc")
	if err != nil {
		t.Fatalf("buildAuthorizationURLFromPAR: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != "wallet-client" {
		t.Fatalf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("request_uri") != "urn:ietf:params:oauth:request_uri:abc" {
		t.Fatalf("request_uri = %q", query.Get("request_uri"))
	}
	// FAPI2 SP Final §5.3.3.2 / PAR-4: only client_id and request_uri.
	if len(query) != 2 {
		t.Fatalf("authorization query has unexpected params: %v", query)
	}
	if query.Get("request_uri_method") != "" {
		t.Fatal("request_uri_method must not be present on PAR authorization redirects")
	}
}

func TestShouldUseHAIPIssuancePathForExternalAttestedAS(t *testing.T) {
	t.Parallel()
	server := &walletHarnessServer{}
	asMetadata := &resolvedAuthorizationServerMetadata{
		TokenEndpointAuthMethodsSupported:   []string{"attest_jwt_client_auth"},
		RequirePushedAuthorizationRequests:  true,
		DPoPSigningAlgValuesSupported:       []string{"ES256"},
	}
	if !server.shouldUseHAIPIssuancePath("org.iso.18013.5.1.mDL", nil, asMetadata) {
		t.Fatal("expected HAIP path for attested PAR AS regardless of configuration id naming")
	}
	if server.shouldUseHAIPIssuancePath("org.iso.18013.5.1.mDL", nil, &resolvedAuthorizationServerMetadata{
		TokenEndpointAuthMethodsSupported: []string{"none"},
	}) {
		t.Fatal("did not expect HAIP path without attestation advertisement or HAIP configuration id")
	}
}

func TestGenerateEphemeralEncryptionKeyIsP256(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("expected P-256 ephemeral key")
	}
}

func TestExchangeRefreshTokenRequiresInputs(t *testing.T) {
	t.Parallel()
	server := &walletHarnessServer{httpClient: http.DefaultClient}
	if _, err := server.exchangeRefreshToken(context.Background(), "", "rt", nil, "", ""); err == nil {
		t.Fatal("expected missing token endpoint error")
	}
	if _, err := server.exchangeRefreshToken(context.Background(), "https://as.example/token", "", nil, "", ""); err == nil {
		t.Fatal("expected missing refresh_token error")
	}
}

func TestExchangeRefreshTokenRedeemsGrant(t *testing.T) {
	t.Parallel()
	var sawGrant string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sawGrant = r.Form.Get("grant_type")
		if r.Form.Get("refresh_token") != "refresh-abc" {
			http.Error(w, "bad refresh", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-xyz","token_type":"Bearer","expires_in":3600}`))
	}))
	defer upstream.Close()

	server := &walletHarnessServer{httpClient: upstream.Client()}
	payload, err := server.exchangeRefreshToken(context.Background(), upstream.URL, "refresh-abc", nil, "", "")
	if err != nil {
		t.Fatalf("exchangeRefreshToken: %v", err)
	}
	if sawGrant != "refresh_token" {
		t.Fatalf("grant_type = %q", sawGrant)
	}
	if asString(payload["access_token"]) != "access-xyz" {
		t.Fatalf("access_token = %#v", payload["access_token"])
	}
}

func TestDoDPoPJSONRequestRefreshesClientAttestationPoPOnNonceRetry(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		status     int
		writeBody  bool
		setWWWAuth bool
	}{
		{name: "as_400_json", status: http.StatusBadRequest, writeBody: true},
		{name: "rs_401_www_authenticate", status: http.StatusUnauthorized, setWWWAuth: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
			if err != nil {
				t.Fatalf("newHAIPIssuanceSession: %v", err)
			}
			const (
				clientID     = "protocolsoup-wallet"
				attestation  = "client-attestation-jwt"
				popAudience  = "https://issuer.example/oid4vci"
				initialPopJT = "wallet-attestation-pop-initial"
			)
			initialPoP, err := buildClientAttestationPoPJWT(
				session.clientInstanceKey,
				clientID,
				popAudience,
				initialPopJT,
				time.Now().UTC(),
				"",
			)
			if err != nil {
				t.Fatalf("buildClientAttestationPoPJWT: %v", err)
			}

			var popJTIs []string
			var attempt int
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempt++
				if got := r.Header.Get(headerOAuthClientAttestation); got != attestation {
					http.Error(w, "missing attestation", http.StatusBadRequest)
					return
				}
				popHeader := strings.TrimSpace(r.Header.Get(headerOAuthClientAttestationPoP))
				if popHeader == "" {
					http.Error(w, "missing pop", http.StatusBadRequest)
					return
				}
				decoded, decodeErr := intcrypto.DecodeTokenWithoutValidation(popHeader)
				if decodeErr != nil {
					http.Error(w, "bad pop", http.StatusBadRequest)
					return
				}
				popJTIs = append(popJTIs, asString(decoded.Payload["jti"]))
				if attempt == 1 {
					w.Header().Set("DPoP-Nonce", "suite-nonce-1")
					if tc.setWWWAuth {
						w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
					}
					if tc.writeBody {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(tc.status)
						_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
						return
					}
					w.WriteHeader(tc.status)
					return
				}
				if strings.TrimSpace(r.Header.Get("DPoP")) == "" {
					http.Error(w, "missing dpop", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:ok","expires_in":60}`))
			}))
			defer upstream.Close()

			server := &walletHarnessServer{
				httpClient:           upstream.Client(),
				haipAttestedClientID: clientID,
			}
			payload, err := server.doDPoPJSONRequest(context.Background(), dpopAuthenticatedRequestInput{
				Method:         http.MethodPost,
				URL:            upstream.URL,
				BodyBytes:      []byte("response_type=code"),
				ContentType:    "application/x-www-form-urlencoded",
				Accept:         "application/json",
				Session:        session,
				AttestationJWT: attestation,
				PoPJWT:         initialPoP,
				PopAudience:    popAudience,
				IncludeDPoP:    true,
			})
			if err != nil {
				t.Fatalf("doDPoPJSONRequest: %v", err)
			}
			if asString(payload["request_uri"]) != "urn:ietf:params:oauth:request_uri:ok" {
				t.Fatalf("unexpected payload: %#v", payload)
			}
			if attempt != 2 {
				t.Fatalf("attempt = %d, want 2", attempt)
			}
			if len(popJTIs) != 2 || popJTIs[0] != initialPopJT || popJTIs[1] == "" || popJTIs[1] == initialPopJT {
				t.Fatalf("pop jtis = %#v", popJTIs)
			}
		})
	}
}

func TestDoDPoPJSONRequestAcceptsDeferred202AfterNonceRetry(t *testing.T) {
	t.Parallel()
	session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}
	var attempt int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			w.Header().Set("DPoP-Nonce", "suite-nonce-deferred")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.TrimSpace(r.Header.Get("DPoP")) == "" {
			http.Error(w, "missing dpop", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"transaction_id":"tx-deferred-1","interval":5}`))
	}))
	defer upstream.Close()

	server := &walletHarnessServer{httpClient: upstream.Client()}
	payload, err := server.doDPoPJSONRequest(context.Background(), dpopAuthenticatedRequestInput{
		Method:      http.MethodPost,
		URL:         upstream.URL,
		BodyBytes:   []byte(`{"proofs":{"jwt":["x"]}}`),
		ContentType: "application/json",
		Accept:      "application/json",
		AccessToken: "access-token",
		TokenType:   "DPoP",
		Session:     session,
		IncludeDPoP: true,
		Ath:         true,
	})
	if err != nil {
		t.Fatalf("doDPoPJSONRequest: %v", err)
	}
	if asString(payload["transaction_id"]) != "tx-deferred-1" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if positiveIntFromAny(payload["interval"]) != 5 {
		t.Fatalf("interval = %v, want 5", payload["interval"])
	}
	if attempt != 2 {
		t.Fatalf("attempt = %d, want 2", attempt)
	}
}

func TestIsSuccessfulOID4VCIJSONStatus(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted} {
		if !isSuccessfulOID4VCIJSONStatus(status) {
			t.Fatalf("expected status %d to be successful", status)
		}
	}
	if isSuccessfulOID4VCIJSONStatus(http.StatusBadRequest) {
		t.Fatal("did not expect 400 to be successful")
	}
}

func TestPollDeferredCredentialRetriesDPoPNonce(t *testing.T) {
	t.Parallel()
	session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}
	var attempt int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "DPoP ") {
			http.Error(w, "missing dpop authz", http.StatusUnauthorized)
			return
		}
		if attempt == 1 {
			w.Header().Set("DPoP-Nonce", "deferred-nonce-1")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.TrimSpace(r.Header.Get("DPoP")) == "" {
			http.Error(w, "missing dpop", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credentials":[{"credential":"mdoc-deferred-1"}]}`))
	}))
	defer upstream.Close()

	server := &walletHarnessServer{
		httpClient:    upstream.Client(),
		issuerBaseURL: upstream.URL,
	}
	payload, err := server.pollDeferredCredentialAt(
		context.Background(),
		upstream.URL+"/deferred_credential",
		"access-token",
		"DPoP",
		"tx-1",
		"",
		session,
		nil,
		nil,
		false,
	)
	if err != nil {
		t.Fatalf("pollDeferredCredentialAt: %v", err)
	}
	values, err := credentialResponseValues(payload)
	if err != nil {
		t.Fatalf("credentialResponseValues: %v", err)
	}
	if asString(values[0]) != "mdoc-deferred-1" {
		t.Fatalf("unexpected credential: %#v", values[0])
	}
	if attempt != 2 {
		t.Fatalf("attempt = %d, want 2", attempt)
	}
}

func TestIsUseDPoPNonceChallenge(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", algs="ES256"`)
	if !isUseDPoPNonceChallenge(http.StatusUnauthorized, nil, headers, nil) {
		t.Fatal("expected 401 WWW-Authenticate use_dpop_nonce challenge")
	}
	if !isUseDPoPNonceChallenge(http.StatusBadRequest, map[string]interface{}{"error": "use_dpop_nonce"}, http.Header{}, nil) {
		t.Fatal("expected 400 JSON use_dpop_nonce challenge")
	}
	if isUseDPoPNonceChallenge(http.StatusUnauthorized, map[string]interface{}{"error": "invalid_token"}, http.Header{}, nil) {
		t.Fatal("did not expect plain invalid_token to look like a nonce challenge")
	}
	nonceOnly := http.Header{}
	nonceOnly.Set("DPoP-Nonce", "resource-nonce-1")
	if !isUseDPoPNonceChallenge(http.StatusUnauthorized, nil, nonceOnly, nil) {
		t.Fatal("expected 401 DPoP-Nonce header to count as a nonce challenge")
	}
}

func TestPushAuthorizationRequestFetchesChallengeEndpoint(t *testing.T) {
	t.Parallel()
	const (
		clientID            = "protocolsoup-wallet"
		expectedChallenge   = "suite-attestation-challenge-1"
		attestationAudience = "https://as.example/oid4vci"
	)

	var challengeFetches int
	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		challengeFetches++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"attestation_challenge":"` + expectedChallenge + `"}`))
	})
	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		popHeader := strings.TrimSpace(r.Header.Get(headerOAuthClientAttestationPoP))
		if popHeader == "" {
			http.Error(w, "missing pop", http.StatusBadRequest)
			return
		}
		decoded, err := intcrypto.DecodeTokenWithoutValidation(popHeader)
		if err != nil {
			http.Error(w, "bad pop", http.StatusBadRequest)
			return
		}
		if asString(decoded.Payload["challenge"]) != expectedChallenge {
			http.Error(w, "missing challenge claim", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:ok","expires_in":60}`))
	})
	upstream := httptest.NewServer(mux)
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	server := &walletHarnessServer{
		httpClient:           upstream.Client(),
		targetHost:           upstreamURL.Host,
		haipAttestedClientID: clientID,
		haipClientAttestation: &attestationJWKMaterial{
			PrivateKey: attesterKey,
			X5C:        []string{"unused-in-test"},
		},
		haipKeyAttestation: &attestationJWKMaterial{
			PrivateKey: attesterKey,
			X5C:        []string{"unused-in-test"},
		},
	}

	requestURI, err := server.pushAuthorizationRequest(context.Background(), pushAuthorizationRequestInput{
		PAREndpoint:       upstream.URL + "/par",
		ClientID:          clientID,
		RedirectURI:       "https://wallet.example/api/oid4vci/callback",
		State:             "state-1",
		CodeChallenge:     "challenge",
		Session:           session,
		PopAudience:       attestationAudience,
		ChallengeEndpoint: upstream.URL + "/challenge",
	})
	if err != nil {
		t.Fatalf("pushAuthorizationRequest: %v", err)
	}
	if requestURI != "urn:ietf:params:oauth:request_uri:ok" {
		t.Fatalf("request_uri = %q", requestURI)
	}
	if challengeFetches != 1 {
		t.Fatalf("challengeFetches = %d, want 1", challengeFetches)
	}
}

func TestBuildClientAttestationPoPJWTIncludesChallengeClaim(t *testing.T) {
	t.Parallel()
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	popJWT, err := buildClientAttestationPoPJWT(
		instanceKey,
		"protocolsoup-wallet",
		"https://as.example/oid4vci",
		"pop-jti",
		time.Now().UTC(),
		"server-challenge",
	)
	if err != nil {
		t.Fatalf("buildClientAttestationPoPJWT: %v", err)
	}
	decoded, err := intcrypto.DecodeTokenWithoutValidation(popJWT)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if asString(decoded.Payload["challenge"]) != "server-challenge" {
		t.Fatalf("challenge claim = %#v", decoded.Payload["challenge"])
	}
}
