package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/golang-jwt/jwt/v5"
)

func TestHealthReportsDeployedCommit(t *testing.T) {
	t.Setenv("BUILD_COMMIT", "0123456789abcdef")
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	(&walletHarnessServer{}).handleHealth(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", response.Code)
	}
	var payload map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if payload["commit"] != "0123456789abcdef" {
		t.Fatalf("health commit = %q", payload["commit"])
	}
}

func TestResolveWalletScopeKeyPrecedence(t *testing.T) {
	server := &walletHarnessServer{strictIsolation: true}

	scope, err := server.resolveWalletScopeKey(walletSubmitRequest{
		LookingGlassSessionID: "lg-123",
		RequestID:             "req-ignored",
	})
	if err != nil {
		t.Fatalf("resolveWalletScopeKey with looking glass session: %v", err)
	}
	if scope != "lg:lg-123" {
		t.Fatalf("unexpected scope %q", scope)
	}

	scope, err = server.resolveWalletScopeKey(walletSubmitRequest{
		RequestID: "req-123",
	})
	if err != nil {
		t.Fatalf("resolveWalletScopeKey with request id: %v", err)
	}
	if scope != "req:req-123" {
		t.Fatalf("unexpected scope %q", scope)
	}
}

func TestCredentialResponseValueRequiresFinalCredentialsArray(t *testing.T) {
	value, err := credentialResponseValue(map[string]interface{}{
		"credentials": []interface{}{
			map[string]interface{}{"credential": "signed-credential"},
		},
	})
	if err != nil {
		t.Fatalf("credentialResponseValue returned error: %v", err)
	}
	if value != "signed-credential" {
		t.Fatalf("credentialResponseValue = %v, want signed-credential", value)
	}
	if _, err := credentialResponseValue(map[string]interface{}{
		"credential": "removed-draft-shape",
	}); err == nil {
		t.Fatal("expected singular credential response shape to be rejected")
	}
}

func TestNotifyCredentialAcceptedUsesNotificationBinding(t *testing.T) {
	var gotAuthorization string
	var gotPayload map[string]string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode notification: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer issuer.Close()

	server := &walletHarnessServer{httpClient: issuer.Client(), issuerBaseURL: issuer.URL}
	err := server.notifyCredentialAccepted(context.Background(), &issuedWalletCredential{
		NotificationID:  "notification-1",
		NotificationURL: issuer.URL,
		AccessToken:     "access-1",
		TokenType:       "Bearer",
	}, "session-1")
	if err != nil {
		t.Fatalf("notifyCredentialAccepted returned error: %v", err)
	}
	if gotAuthorization != "Bearer access-1" {
		t.Fatalf("Authorization = %q, want Bearer access-1", gotAuthorization)
	}
	if gotPayload["notification_id"] != "notification-1" ||
		gotPayload["event"] != "credential_accepted" {
		t.Fatalf("unexpected notification payload: %#v", gotPayload)
	}
}

func TestNotifyCredentialAcceptedUsesDPoPWhenTokenBound(t *testing.T) {
	session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}
	accessToken := "dpop-access-token"
	var gotAuthorization string
	var gotDPoP string
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthorization = r.Header.Get("Authorization")
		gotDPoP = r.Header.Get("DPoP")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer issuer.Close()

	server := &walletHarnessServer{httpClient: issuer.Client(), issuerBaseURL: issuer.URL}
	err = server.notifyCredentialAccepted(context.Background(), &issuedWalletCredential{
		NotificationID:  "notification-1",
		NotificationURL: issuer.URL,
		AccessToken:     accessToken,
		TokenType:       "DPoP",
		HAIPDPoPSession: session,
	}, "session-1")
	if err != nil {
		t.Fatalf("notifyCredentialAccepted returned error: %v", err)
	}
	if gotAuthorization != "DPoP "+accessToken {
		t.Fatalf("Authorization = %q, want DPoP %s", gotAuthorization, accessToken)
	}
	if strings.TrimSpace(gotDPoP) == "" {
		t.Fatal("expected DPoP proof header")
	}
	decoded, err := intcrypto.DecodeTokenWithoutValidation(gotDPoP)
	if err != nil {
		t.Fatalf("decode dpop proof: %v", err)
	}
	if asString(decoded.Payload["htm"]) != "POST" {
		t.Fatalf("dpop htm = %q", decoded.Payload["htm"])
	}
	if asString(decoded.Payload["htu"]) != issuer.URL {
		t.Fatalf("dpop htu = %q, want %s", decoded.Payload["htu"], issuer.URL)
	}
	expectedATH := computeAccessTokenHash(accessToken)
	if asString(decoded.Payload["ath"]) != expectedATH {
		t.Fatalf("dpop ath = %q, want %s", decoded.Payload["ath"], expectedATH)
	}
}

func TestResolveWalletScopeKeyStrictIsolation(t *testing.T) {
	strictServer := &walletHarnessServer{strictIsolation: true}
	if _, err := strictServer.resolveWalletScopeKey(walletSubmitRequest{}); err == nil {
		t.Fatalf("expected strict isolation to reject empty scope key")
	}

	legacyServer := &walletHarnessServer{strictIsolation: false}
	scope, err := legacyServer.resolveWalletScopeKey(walletSubmitRequest{})
	if err != nil {
		t.Fatalf("expected legacy fallback scope without error, got %v", err)
	}
	if scope != "legacy:shared" {
		t.Fatalf("unexpected legacy scope %q", scope)
	}
}

func TestScopedWalletSubjectUsesScopeFingerprint(t *testing.T) {
	base := "did:example:wallet:alice"
	scopeA := scopedWalletSubject(base, "req:a")
	scopeB := scopedWalletSubject(base, "req:b")
	if scopeA == base || scopeB == base {
		t.Fatalf("scoped subject must not equal base subject")
	}
	if scopeA == scopeB {
		t.Fatalf("scoped subject must differ across scope keys")
	}
}

func TestBuildOID4VCIOfferRequestDoesNotDeriveUserIDFromHolderDID(t *testing.T) {
	body := buildOID4VCIOfferRequest(" UniversityDegreeCredential ")
	if _, exists := body["wallet_user_id"]; exists {
		t.Fatal("offer request must not treat the holder DID as an identity-provider user ID")
	}
	configurationIDs, ok := body["credential_configuration_ids"].([]string)
	if !ok || len(configurationIDs) != 1 || configurationIDs[0] != "UniversityDegreeCredential" {
		t.Fatalf("credential_configuration_ids = %#v", body["credential_configuration_ids"])
	}
}

func TestCreateCredentialProofJWTUsesFinalAnonymousProofShape(t *testing.T) {
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("create wallet keyset: %v", err)
	}
	wallet := &walletMaterial{
		Subject:          "did:key:z6MkrandomHolderKey",
		KeySet:           keySet,
		SigningAlgorithm: "ES256",
	}
	server := &walletHarnessServer{issuerBaseURL: "https://issuer.example"}
	const authorizedSubject = "did:example:wallet:alice"

	proof, err := server.createCredentialProofJWT(
		wallet,
		authorizedSubject,
		"test-c-nonce",
		"https://issuer.example/oid4vci",
	)
	if err != nil {
		t.Fatalf("createCredentialProofJWT: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse proof JWT: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("proof claims type = %T", parsed.Claims)
	}
	if _, exists := claims["iss"]; exists {
		t.Fatal("anonymous pre-authorized proof must omit iss")
	}
	if _, exists := claims["sub"]; exists {
		t.Fatal("OID4VCI Final proof must not use a sub claim for key binding")
	}
	if _, exists := parsed.Header["jwk"]; !exists {
		t.Fatal("proof JOSE header must carry jwk")
	}
	if _, exists := parsed.Header["kid"]; exists {
		t.Fatal("proof JOSE header must not carry kid when it carries jwk")
	}
	if _, exists := claims["cnf"]; exists {
		t.Fatal("proof key must not be carried in payload cnf")
	}
}

func TestSignWalletJWTOmitsKidForKeyBindingJWT(t *testing.T) {
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("create wallet keyset: %v", err)
	}
	wallet := &walletMaterial{
		KeySet:           keySet,
		SigningAlgorithm: "ES256",
	}
	signed, err := walletSignToken(wallet, jwt.MapClaims{
		"aud":   "https://verifier.example",
		"nonce": "n",
		"iat":   time.Now().UTC().Unix(),
	}, map[string]interface{}{"typ": "kb+jwt"})
	if err != nil {
		t.Fatalf("walletSignToken: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse kb-jwt: %v", err)
	}
	if parsed.Header["typ"] != "kb+jwt" {
		t.Fatalf("typ = %#v, want kb+jwt", parsed.Header["typ"])
	}
	if _, exists := parsed.Header["kid"]; exists {
		t.Fatal("kb+jwt JOSE header must not carry kid (SD-JWT §4.3)")
	}
}

func TestSelectWalletSigningAlgorithmUsesCredentialMetadataAlgorithm(t *testing.T) {
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("create wallet keyset: %v", err)
	}
	wallet := &walletMaterial{KeySet: keySet, SigningAlgorithm: "ES256"}
	configuration := map[string]interface{}{
		"proof_types_supported": map[string]interface{}{
			"jwt": map[string]interface{}{
				"proof_signing_alg_values_supported": []interface{}{"RS256"},
			},
		},
	}

	algorithm := preferredCredentialProofSigningAlgorithm(configuration)
	if algorithm != "RS256" {
		t.Fatalf("preferredCredentialProofSigningAlgorithm() = %q, want RS256", algorithm)
	}
	if err := selectWalletSigningAlgorithm(wallet, algorithm); err != nil {
		t.Fatalf("selectWalletSigningAlgorithm: %v", err)
	}
	if wallet.SigningAlgorithm != "RS256" {
		t.Fatalf("wallet SigningAlgorithm = %q, want RS256", wallet.SigningAlgorithm)
	}
}

func TestGetOrCreateWalletIsolatesByScope(t *testing.T) {
	server := &walletHarnessServer{
		strictIsolation:  true,
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	subject := "did:example:wallet:alice"

	walletA1, err := server.getOrCreateWallet("req:a", subject, "")
	if err != nil {
		t.Fatalf("getOrCreateWallet A1: %v", err)
	}
	walletA2, err := server.getOrCreateWallet("req:a", subject, "")
	if err != nil {
		t.Fatalf("getOrCreateWallet A2: %v", err)
	}
	if walletA1 != walletA2 {
		t.Fatalf("expected same wallet for same scope and subject")
	}

	walletB, err := server.getOrCreateWallet("req:b", subject, "")
	if err != nil {
		t.Fatalf("getOrCreateWallet B: %v", err)
	}
	if walletB == walletA1 {
		t.Fatalf("expected different wallet for different scope")
	}
}

func TestGetOrCreateWalletPrunesExpiredEntries(t *testing.T) {
	server := &walletHarnessServer{
		strictIsolation:  true,
		walletSessionTTL: 1 * time.Second,
		wallets:          make(map[string]*walletMaterial),
	}

	wallet, err := server.getOrCreateWallet("req:old", "did:example:wallet:old", "")
	if err != nil {
		t.Fatalf("getOrCreateWallet old: %v", err)
	}
	wallet.LastAccess = time.Now().UTC().Add(-2 * time.Second)

	if _, err := server.getOrCreateWallet("req:new", "did:example:wallet:new", ""); err != nil {
		t.Fatalf("getOrCreateWallet new: %v", err)
	}

	server.mu.Lock()
	_, stillExists := server.wallets["req:old|did:example:wallet:old"]
	server.mu.Unlock()
	if stillExists {
		t.Fatalf("expected expired wallet entry to be pruned")
	}
}

func TestGetOrCreateWalletSupportsEdDSA(t *testing.T) {
	t.Setenv("WALLET_DEFAULT_SIGNING_ALG", "EdDSA")

	server := &walletHarnessServer{
		strictIsolation:  true,
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}

	wallet, err := server.getOrCreateWallet("req:eddsa", "did:example:wallet:alice", "")
	if err != nil {
		t.Fatalf("getOrCreateWallet EdDSA: %v", err)
	}
	if wallet.SigningAlgorithm != "EdDSA" {
		t.Fatalf("unexpected signing algorithm %q", wallet.SigningAlgorithm)
	}
	if !strings.HasPrefix(wallet.Subject, "did:key:z") {
		t.Fatalf("expected did:key subject, got %q", wallet.Subject)
	}

	publicJWK, thumbprint, err := walletActiveJWK(wallet)
	if err != nil {
		t.Fatalf("walletActiveJWK: %v", err)
	}
	if publicJWK.Kty != "OKP" || publicJWK.Crv != "Ed25519" || publicJWK.Alg != "EdDSA" {
		t.Fatalf("unexpected active JWK %+v", publicJWK)
	}
	if thumbprint == "" {
		t.Fatalf("expected Ed25519 thumbprint")
	}

	signed, err := walletSignToken(wallet, jwt.MapClaims{
		"sub": wallet.Subject,
		"iat": time.Now().Unix(),
	}, map[string]interface{}{"typ": "test+jwt"})
	if err != nil {
		t.Fatalf("walletSignToken EdDSA: %v", err)
	}

	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		return wallet.KeySet.Ed25519PublicKey(), nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse EdDSA: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected EdDSA signed token to validate")
	}
}

func TestGetOrCreateWalletSupportsDIDJWK(t *testing.T) {
	server := &walletHarnessServer{
		walletDIDMethod:  "jwk",
		strictIsolation:  true,
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}

	wallet, err := server.getOrCreateWallet("req:jwk", "did:example:wallet:alice", "https://wallet.example")
	if err != nil {
		t.Fatalf("getOrCreateWallet did:jwk: %v", err)
	}
	if wallet.DIDMethod != "jwk" {
		t.Fatalf("unexpected did method %q", wallet.DIDMethod)
	}
	if !strings.HasPrefix(wallet.Subject, "did:jwk:") {
		t.Fatalf("expected did:jwk subject, got %q", wallet.Subject)
	}
}

func TestHandleWalletDIDDocumentServesDIDWeb(t *testing.T) {
	server := &walletHarnessServer{
		walletDIDMethod:  "web",
		strictIsolation:  true,
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}

	wallet, err := server.getOrCreateWallet("req:web", "did:example:wallet:alice", "https://wallet.example")
	if err != nil {
		t.Fatalf("getOrCreateWallet did:web: %v", err)
	}
	if wallet.DIDMethod != "web" {
		t.Fatalf("unexpected did method %q", wallet.DIDMethod)
	}
	path := "/wallet/" + scopeKeyFingerprint("req:web") + "/did.json"
	req := httptest.NewRequest(http.MethodGet, "https://wallet.example"+path, nil)
	req.Host = "wallet.example"
	recorder := httptest.NewRecorder()

	server.handleWalletDIDDocument(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "application/did+json") {
		t.Fatalf("unexpected content type %q", got)
	}
	var document map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("unmarshal did document: %v", err)
	}
	if got := strings.TrimSpace(asString(document["id"])); got != wallet.Subject {
		t.Fatalf("unexpected did document id %q want %q", got, wallet.Subject)
	}
}

func TestEnsureWalletMatchesPresentationRequestActivatesMatchingCredential(t *testing.T) {
	wallet := &walletMaterial{
		ScopeKey:                  "req:test",
		Subject:                   "did:key:zExampleHolder",
		CredentialID:              "cred-ldp",
		CredentialFormat:          "ldp_vc",
		CredentialConfigurationID: "UniversityDegreeCredentialLDP",
		Credentials: map[string]walletCredentialMaterial{
			"cred-ldp": {
				CredentialID:              "cred-ldp",
				CredentialJWT:             signedCredentialJWT(t, "https://issuer.example", jwt.SigningMethodHS256, []byte("issuer-secret"), "", "did:key:zExampleHolder"),
				Format:                    "ldp_vc",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				UpdatedAt:                 time.Now().UTC().Add(-1 * time.Minute),
			},
			"cred-jwt": {
				CredentialID:              "cred-jwt",
				CredentialJWT:             signedCredentialJWT(t, "https://issuer.example", jwt.SigningMethodHS256, []byte("issuer-secret"), "", "did:key:zExampleHolder"),
				Format:                    "jwt_vc_json",
				CredentialConfigurationID: "UniversityDegreeCredential",
				UpdatedAt:                 time.Now().UTC(),
			},
		},
	}
	envelope := &resolvedRequestEnvelope{
		DecodedPayload: map[string]interface{}{
			"dcql_query": map[string]interface{}{
				"credentials": []interface{}{
					map[string]interface{}{
						"id":     "degree",
						"format": "jwt_vc_json",
					},
				},
			},
		},
	}

	matchSummary, matchedActiveCredential := ensureWalletMatchesPresentationRequest(wallet, envelope, nil)
	if !matchSummary.Matched {
		t.Fatalf("expected request matching to find a wallet credential")
	}
	if !matchedActiveCredential {
		t.Fatalf("expected matching credential to become active")
	}
	if wallet.CredentialID != "cred-jwt" {
		t.Fatalf("expected matching credential to be activated, got %q", wallet.CredentialID)
	}
	if matchSummary.RecommendedCredentialID != "cred-jwt" {
		t.Fatalf("unexpected recommended credential %q", matchSummary.RecommendedCredentialID)
	}
}

func TestSummarizeCredentialNormalizesNestedClaimsForJWTAndLDPFormats(t *testing.T) {
	subject := "did:key:zExampleHolder"
	testCases := []struct {
		name   string
		raw    string
		format string
	}{
		{
			name:   "jwt_vc_json",
			raw:    signedCredentialJWTWithClaims(t, subject, false),
			format: "jwt_vc_json",
		},
		{
			name:   "jwt_vc_json-ld",
			raw:    signedCredentialJWTWithClaims(t, subject, true),
			format: "jwt_vc_json-ld",
		},
		{
			name:   "ldp_vc",
			raw:    rawLDPCredentialWithClaims(t, subject),
			format: "ldp_vc",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			summary := summarizeCredential(testCase.raw)
			if summary == nil {
				t.Fatalf("summarizeCredential() returned nil")
				return
			}
			if summary.Format != testCase.format {
				t.Fatalf("unexpected format %q", summary.Format)
			}
			if got := strings.TrimSpace(asString(summary.Claims["degree"])); got != "General Credential" {
				t.Fatalf("expected normalized degree claim, got %q", got)
			}
			if got := strings.TrimSpace(asString(summary.Claims["department"])); got != "General" {
				t.Fatalf("expected normalized department claim, got %q", got)
			}
			if !containsString(summary.CredentialTypes, "UniversityDegreeCredential") {
				t.Fatalf("expected credential types to include UniversityDegreeCredential, got %v", summary.CredentialTypes)
			}
		})
	}
}

func TestMatchWalletCredentialsToDCQLSupportsNormalizedJWTAndLDPFormats(t *testing.T) {
	subject := "did:key:zExampleHolder"
	const universityDegreeVCT = "https://protocolsoup.com/credentials/university_degree"

	testCases := []struct {
		name   string
		raw    string
		format string
	}{
		{
			name:   "jwt_vc_json",
			raw:    signedCredentialJWTWithClaims(t, subject, false),
			format: "jwt_vc_json",
		},
		{
			name:   "jwt_vc_json-ld",
			raw:    signedCredentialJWTWithClaims(t, subject, true),
			format: "jwt_vc_json-ld",
		},
		{
			name:   "ldp_vc",
			raw:    rawLDPCredentialWithClaims(t, subject),
			format: "ldp_vc",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			matched, reasons := matchWalletCredentialsToDCQL(map[string]walletCredentialMaterial{
				"cred-1": {
					CredentialID:              "cred-1",
					CredentialJWT:             testCase.raw,
					Format:                    testCase.format,
					CredentialConfigurationID: "UniversityDegreeCredential",
					VCT:                       universityDegreeVCT,
					UpdatedAt:                 time.Now().UTC(),
				},
			}, `{
				"credentials": [
					{
						"id": "degree_requirement",
						"format": "`+testCase.format+`",
						"meta": {
							"vct_values": ["`+universityDegreeVCT+`"],
							"type_values": ["UniversityDegreeCredential"]
						},
						"claims": [
							{"path": ["degree"]}
						]
					}
				]
			}`)
			if len(matched) != 1 {
				t.Fatalf("expected one matched credential, got %d (reasons=%v)", len(matched), reasons)
			}
			if matched[0].CredentialID != "cred-1" {
				t.Fatalf("unexpected matched credential id %q", matched[0].CredentialID)
			}
		})
	}
}

// walletCredentialSetsFixture returns a single stored jwt_vc_json credential
// plus a DCQL query builder with two Credential Queries -- "degree_requirement"
// (satisfiable by that credential) and "unused_requirement" (a vct the
// fixture credential never carries) -- so tests can attach different
// top-level credential_sets arrays (OID4VP 1.0 Section 6.2) and exercise
// matchWalletCredentialsToDCQL's single-credential-aware credential_sets
// handling.
func walletCredentialSetsFixture(t *testing.T) (map[string]walletCredentialMaterial, func(credentialSets string) string) {
	t.Helper()
	subject := "did:key:zExampleHolder"
	const universityDegreeVCT = "https://protocolsoup.com/credentials/university_degree"
	credentials := map[string]walletCredentialMaterial{
		"cred-1": {
			CredentialID:              "cred-1",
			CredentialJWT:             signedCredentialJWTWithClaims(t, subject, false),
			Format:                    "jwt_vc_json",
			CredentialConfigurationID: "UniversityDegreeCredential",
			VCT:                       universityDegreeVCT,
			UpdatedAt:                 time.Now().UTC(),
		},
	}
	buildQuery := func(credentialSets string) string {
		return `{
			"credentials": [
				{
					"id": "degree_requirement",
					"format": "jwt_vc_json",
					"meta": {"vct_values": ["` + universityDegreeVCT + `"], "type_values": ["UniversityDegreeCredential"]},
					"claims": [{"path": ["degree"]}]
				},
				{
					"id": "unused_requirement",
					"format": "jwt_vc_json",
					"meta": {"vct_values": ["https://protocolsoup.com/credentials/never_issued"]}
				}
			],
			"credential_sets": [` + credentialSets + `]
		}`
	}
	return credentials, buildQuery
}

// TestMatchWalletCredentialsToDCQLCredentialSetSatisfiedByOneAlternative
// proves the stored credential is still recommended when a required
// credential_sets option references it, even though a second Credential
// Query ("unused_requirement") in the same query is never satisfied -- the
// pre-credential_sets behaviour of requiring every entry in `credentials`
// does not apply once credential_sets is present (OID4VP 1.0 Section 6.4.2).
func TestMatchWalletCredentialsToDCQLCredentialSetSatisfiedByOneAlternative(t *testing.T) {
	credentials, buildQuery := walletCredentialSetsFixture(t)
	dcql := buildQuery(`{"options": [["unused_requirement"], ["degree_requirement"]], "required": true}`)

	matched, reasons := matchWalletCredentialsToDCQL(credentials, dcql)
	if len(matched) != 1 {
		t.Fatalf("expected the credential to be recommended via the degree_requirement option, got %d matched (reasons=%v)", len(matched), reasons)
	}
}

// TestMatchWalletCredentialsToDCQLDeniesUnsatisfiedRequiredCredentialSet
// proves the credential is NOT recommended when a required credential_sets
// entry's only option needs a Credential Query the credential cannot satisfy
// -- this wallet harness presents exactly one credential per request
// (createVPToken), so it can never single-handedly satisfy both
// "degree_requirement" and "unused_requirement" together.
func TestMatchWalletCredentialsToDCQLDeniesUnsatisfiedRequiredCredentialSet(t *testing.T) {
	credentials, _ := walletCredentialSetsFixture(t)
	// The fixture's buildQuery helper only supports a single credential_sets
	// entry per call; this test needs two, so it's built directly here.
	dcql := `{
		"credentials": [
			{
				"id": "degree_requirement",
				"format": "jwt_vc_json",
				"meta": {"vct_values": ["https://protocolsoup.com/credentials/university_degree"], "type_values": ["UniversityDegreeCredential"]},
				"claims": [{"path": ["degree"]}]
			},
			{
				"id": "unused_requirement",
				"format": "jwt_vc_json",
				"meta": {"vct_values": ["https://protocolsoup.com/credentials/never_issued"]}
			}
		],
		"credential_sets": [
			{"options": [["degree_requirement"]], "required": true},
			{"options": [["unused_requirement"]], "required": true}
		]
	}`

	matched, reasons := matchWalletCredentialsToDCQL(credentials, dcql)
	if len(matched) != 0 {
		t.Fatalf("expected no match since the credential cannot alone satisfy every required credential_sets entry, got %d matched", len(matched))
	}
	if len(reasons) == 0 {
		t.Fatal("expected a reason explaining why the credential was not recommended")
	}
}

// TestMatchWalletCredentialsToDCQLAllowsUnsatisfiedOptionalCredentialSet
// proves a credential_sets entry marked required:false does not prevent the
// credential from being recommended even though that entry's only option is
// unsatisfiable.
func TestMatchWalletCredentialsToDCQLAllowsUnsatisfiedOptionalCredentialSet(t *testing.T) {
	credentials, _ := walletCredentialSetsFixture(t)
	dcql := `{
		"credentials": [
			{
				"id": "degree_requirement",
				"format": "jwt_vc_json",
				"meta": {"vct_values": ["https://protocolsoup.com/credentials/university_degree"], "type_values": ["UniversityDegreeCredential"]},
				"claims": [{"path": ["degree"]}]
			},
			{
				"id": "unused_requirement",
				"format": "jwt_vc_json",
				"meta": {"vct_values": ["https://protocolsoup.com/credentials/never_issued"]}
			}
		],
		"credential_sets": [
			{"options": [["degree_requirement"]], "required": true},
			{"options": [["unused_requirement"]], "required": false}
		]
	}`

	matched, reasons := matchWalletCredentialsToDCQL(credentials, dcql)
	if len(matched) != 1 {
		t.Fatalf("expected the credential to still be recommended, got %d matched (reasons=%v)", len(matched), reasons)
	}
}

func TestExtractPublicKeyFromMethodSupportsOKP(t *testing.T) {
	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	publicJWK := intcrypto.JWKFromEd25519PublicKey(keySet.Ed25519PublicKey(), keySet.Ed25519KeyID())
	key := extractPublicKeyFromMethod(map[string]interface{}{
		"publicKeyJwk": publicJWK,
	})
	if _, ok := key.(ed25519.PublicKey); !ok {
		t.Fatalf("publicKeyJwk returned %T, want ed25519.PublicKey", key)
	}

	did, err := vc.DIDKeyFromEd25519PublicKey(keySet.Ed25519PublicKey())
	if err != nil {
		t.Fatalf("DIDKeyFromEd25519PublicKey: %v", err)
	}
	key = extractPublicKeyFromMethod(map[string]interface{}{
		"publicKeyMultibase": strings.TrimPrefix(did, "did:key:"),
	})
	if _, ok := key.(ed25519.PublicKey); !ok {
		t.Fatalf("publicKeyMultibase returned %T, want ed25519.PublicKey", key)
	}
}

func TestParseOpenID4VPURIExtractsRequestURI(t *testing.T) {
	requestURI, requestJWT, _, method, err := parseOpenID4VPURI("openid4vp://authorize?request_uri=https%3A%2F%2Fprotocolsoup.com%2Foid4vp%2Frequest%2Fabc123")
	if err != nil {
		t.Fatalf("parseOpenID4VPURI: %v", err)
	}
	if requestJWT != "" {
		t.Fatalf("expected empty request JWT, got %q", requestJWT)
	}
	if requestURI != "https://protocolsoup.com/oid4vp/request/abc123" {
		t.Fatalf("unexpected requestURI %q", requestURI)
	}
	if method != "get" {
		t.Fatalf("unexpected request_uri_method %q", method)
	}
}

func TestParseOpenID4VPURIAcceptsRequestURIMethodPost(t *testing.T) {
	_, _, _, method, err := parseOpenID4VPURI("openid4vp://authorize?request_uri=https%3A%2F%2Fprotocolsoup.com%2Foid4vp%2Frequest%2Fabc123&request_uri_method=post")
	if err != nil {
		t.Fatalf("parseOpenID4VPURI(post): %v", err)
	}
	if method != "post" {
		t.Fatalf("unexpected request_uri_method %q", method)
	}
}

func TestFetchRequestObjectConsumesFinalCompactJWTBody(t *testing.T) {
	requestJWT := buildTestRequestJWT(t, "https://protocolsoup.com/oid4vp/response")
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected request method %s", r.Method)
		}
		if got := r.Header.Get("Accept"); got != "application/oauth-authz-req+jwt" {
			t.Fatalf("unexpected Accept header %q", got)
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(requestJWT))
	}))
	defer requestServer.Close()

	server := &walletHarnessServer{httpClient: requestServer.Client()}
	gotJWT, requestID, err := server.fetchRequestObject(context.Background(), requestServer.URL, "get")
	if err != nil {
		t.Fatalf("fetchRequestObject: %v", err)
	}
	if gotJWT != requestJWT || requestID != "" {
		t.Fatalf("unexpected request object result jwt=%q requestID=%q", gotJWT, requestID)
	}
}

func TestResolveRequestContextWithOptionsRejectsExternalByDefault(t *testing.T) {
	server := &walletHarnessServer{
		targetHost:        "protocolsoup.com",
		targetResponseURI: "https://protocolsoup.com/oid4vp/response",
		allowExternal:     false,
	}
	requestJWT := buildTestRequestJWT(t, "https://wallet.example.org/oid4vp/response")
	if _, err := server.resolveRequestContextWithOptions("req-123", requestJWT, false); err == nil {
		t.Fatalf("expected external response_uri to be rejected when allowExternal=false")
	}
}

func TestResolveRequestContextWithOptionsAllowsExternalWhenEnabled(t *testing.T) {
	server := &walletHarnessServer{
		targetHost:        "protocolsoup.com",
		targetResponseURI: "https://protocolsoup.com/oid4vp/response",
		allowExternal:     true,
	}
	requestJWT := buildTestRequestJWT(t, "https://wallet.example.org/oid4vp/response")
	context, err := server.resolveRequestContextWithOptions("req-123", requestJWT, true)
	if err != nil {
		t.Fatalf("resolveRequestContextWithOptions external: %v", err)
	}
	if context.Trusted {
		t.Fatalf("expected external context to be untrusted")
	}
	if context.ResponseURI != "https://wallet.example.org/oid4vp/response" {
		t.Fatalf("unexpected response URI %q", context.ResponseURI)
	}
}

func TestResolveRequestContextRequiresFinalRequestContract(t *testing.T) {
	responseURI := "https://protocolsoup.com/oid4vp/response"
	server := &walletHarnessServer{
		targetResponseURI: responseURI,
	}
	validClaims := jwt.MapClaims{
		"jti":           "req-123",
		"state":         "state-123",
		"nonce":         "nonce-123",
		"client_id":     "redirect_uri:" + responseURI,
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  responseURI,
		"dcql_query": map[string]interface{}{
			"credentials": []interface{}{map[string]interface{}{"id": "credential-query"}},
		},
	}
	testCases := []struct {
		name   string
		mutate func(jwt.MapClaims)
	}{
		{
			name: "missing response_type",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "response_type")
			},
		},
		{
			name: "unsupported response_mode",
			mutate: func(claims jwt.MapClaims) {
				claims["response_mode"] = "fragment"
			},
		},
		{
			name: "both dcql_query and scope",
			mutate: func(claims jwt.MapClaims) {
				claims["scope"] = "mdl"
			},
		},
		{
			name: "neither dcql_query nor scope",
			mutate: func(claims jwt.MapClaims) {
				delete(claims, "dcql_query")
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			for key, value := range validClaims {
				claims[key] = value
			}
			testCase.mutate(claims)
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			token.Header["typ"] = "oauth-authz-req+jwt"
			requestJWT, err := token.SignedString([]byte("wallet-harness-test-secret"))
			if err != nil {
				t.Fatalf("sign request jwt: %v", err)
			}
			if _, err := server.resolveRequestContextWithOptions("req-123", requestJWT, false); err == nil {
				t.Fatal("expected invalid Final request contract to be rejected")
			}
		})
	}
}

func TestWalletCredentialSelectionMismatch(t *testing.T) {
	testCases := []struct {
		name        string
		wallet      *walletMaterial
		configID    string
		format      string
		hasMismatch bool
	}{
		{
			name: "no_selection_constraints",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredential",
				CredentialFormat:          "dc+sd-jwt",
			},
			configID:    "",
			format:      "",
			hasMismatch: false,
		},
		{
			name: "empty_wallet_requires_issue",
			wallet: &walletMaterial{
				CredentialJWT: "",
			},
			configID:    "UniversityDegreeCredential",
			format:      "dc+sd-jwt",
			hasMismatch: true,
		},
		{
			name: "matching_active_selection",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredential",
				CredentialFormat:          "dc+sd-jwt",
			},
			configID:    "UniversityDegreeCredential",
			format:      "dc+sd-jwt",
			hasMismatch: false,
		},
		{
			name: "format_mismatch",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				CredentialFormat:          "ldp_vc",
			},
			configID:    "UniversityDegreeCredentialLDP",
			format:      "dc+sd-jwt",
			hasMismatch: true,
		},
		{
			name: "config_mismatch",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				CredentialFormat:          "ldp_vc",
			},
			configID:    "UniversityDegreeCredential",
			format:      "ldp_vc",
			hasMismatch: true,
		},
		{
			name: "empty_active_format_with_constraints_is_mismatch",
			wallet: &walletMaterial{
				CredentialJWT:             "placeholder",
				CredentialConfigurationID: "UniversityDegreeCredentialLDP",
				CredentialFormat:          "",
			},
			configID:    "UniversityDegreeCredentialLDP",
			format:      "ldp_vc",
			hasMismatch: true,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			hasMismatch := walletCredentialSelectionMismatch(testCase.wallet, testCase.configID, testCase.format)
			if hasMismatch != testCase.hasMismatch {
				t.Fatalf("walletCredentialSelectionMismatch() = %v, want %v", hasMismatch, testCase.hasMismatch)
			}
		})
	}
}

func buildTestRequestJWT(t *testing.T, responseURI string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti":           "req-123",
		"state":         "state-123",
		"nonce":         "nonce-123",
		"client_id":     "did:example:verifier",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  responseURI,
		"dcql_query": map[string]interface{}{
			"credentials": []interface{}{map[string]interface{}{"id": "credential-query"}},
		},
	})
	token.Header["typ"] = "oauth-authz-req+jwt"
	signed, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("sign request jwt: %v", err)
	}
	return signed
}

func TestPresentationAPIsRejectUnsupportedTransactionData(t *testing.T) {
	unknownType := base64.RawURLEncoding.EncodeToString([]byte(
		`{"type":"https://example.com/transaction","credential_ids":["degree"]}`,
	))
	testCases := []struct {
		name            string
		transactionData interface{}
		wantDescription string
	}{
		{
			name:            "unknown type",
			transactionData: []string{unknownType},
			wantDescription: `transaction data type "https://example.com/transaction" is not supported`,
		},
		{
			name:            "malformed content",
			transactionData: []string{"%%%"},
			wantDescription: "is not valid base64url",
		},
	}
	apiPaths := []struct {
		name    string
		handler http.HandlerFunc
		body    func(string) string
	}{
		{
			name:    "resolve",
			handler: nil,
			body:    func(requestJWT string) string { return fmt.Sprintf(`{"request":%q}`, requestJWT) },
		},
		{
			name:    "preview",
			handler: nil,
			body:    func(requestJWT string) string { return fmt.Sprintf(`{"request":%q}`, requestJWT) },
		},
		{
			name:    "present",
			handler: nil,
			body:    func(requestJWT string) string { return fmt.Sprintf(`{"request":%q}`, requestJWT) },
		},
		{
			name:    "submit",
			handler: nil,
			body: func(requestJWT string) string {
				return fmt.Sprintf(`{"mode":"one_click","request_id":"req-123","request":%q}`, requestJWT)
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			requestJWT := buildTestRequestJWTWithTransactionData(t, testCase.transactionData)
			server := &walletHarnessServer{
				targetHost:           "verifier.example",
				targetResponseURI:    "https://verifier.example/oid4vp/response",
				defaultWalletSubject: "did:key:z6Mktest",
				walletSessionTTL:     10 * time.Minute,
				wallets:              make(map[string]*walletMaterial),
			}
			apiPaths[0].handler = server.handleAPIResolve
			apiPaths[1].handler = server.handleAPIPreview
			apiPaths[2].handler = server.handleAPIPresent
			apiPaths[3].handler = server.handleSubmit

			for _, apiPath := range apiPaths {
				t.Run(apiPath.name, func(t *testing.T) {
					request := httptest.NewRequest(
						http.MethodPost,
						"https://wallet.example/"+apiPath.name,
						strings.NewReader(apiPath.body(requestJWT)),
					)
					recorder := httptest.NewRecorder()
					apiPath.handler(recorder, request)

					if recorder.Code != http.StatusBadRequest {
						t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
					}
					var response map[string]interface{}
					if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
						t.Fatalf("decode error response: %v", err)
					}
					if response["error"] != "invalid_transaction_data" {
						t.Fatalf("error = %q, want invalid_transaction_data", response["error"])
					}
					if description := fmt.Sprint(response["error_description"]); !strings.Contains(description, testCase.wantDescription) {
						t.Fatalf("error_description = %q, want substring %q", description, testCase.wantDescription)
					}
				})
			}
		})
	}
}

func buildTestRequestJWTWithTransactionData(t *testing.T, transactionData interface{}) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti":              "req-123",
		"nonce":            "nonce-123",
		"client_id":        "redirect_uri:https://verifier.example/oid4vp/response",
		"response_type":    "vp_token",
		"response_mode":    "direct_post",
		"response_uri":     "https://verifier.example/oid4vp/response",
		"dcql_query":       map[string]interface{}{"credentials": []interface{}{map[string]interface{}{"id": "credential-query"}}},
		"transaction_data": transactionData,
	})
	token.Header["typ"] = "oauth-authz-req+jwt"
	signed, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("sign request jwt: %v", err)
	}
	return signed
}

func TestInferClientIDSchemeUsesClientIDPrefixOnly(t *testing.T) {
	testCases := []struct {
		clientID string
		payload  map[string]interface{}
		want     string
	}{
		{clientID: "x509_san_dns:verifier.example", want: "x509_san_dns"},
		{clientID: "verifier_attestation:verifier.example", want: "verifier_attestation"},
		{
			clientID: "x509_hash:thumbprint",
			payload:  map[string]interface{}{"client_id_scheme": "redirect_uri"},
			want:     "x509_hash",
		},
		{
			clientID: "https://verifier.example/callback",
			payload:  map[string]interface{}{"client_id_scheme": "verifier_attestation"},
			want:     "pre_registered",
		},
		{
			clientID: "did:web:verifier.example",
			payload:  map[string]interface{}{"client_id_scheme": "decentralized_identifier"},
			want:     "pre_registered",
		},
		{clientID: "example-client", want: "pre_registered"},
		{clientID: "invalid_scheme:attacker", want: "unknown"},
	}

	for _, testCase := range testCases {
		if got := inferClientIDScheme(testCase.clientID, testCase.payload); got != testCase.want {
			t.Fatalf("inferClientIDScheme(%q) = %q, want %q", testCase.clientID, got, testCase.want)
		}
	}
}

func TestEnsurePresentationRequestTrustRequiresVerifiedRequestObject(t *testing.T) {
	server := &walletHarnessServer{allowExternal: true}

	err := server.ensurePresentationRequestTrust(trustEvaluation{
		ClientIDScheme:         "verifier_attestation",
		TrustedTarget:          false,
		RequiresExternalAccept: true,
		RequestObjectVerification: &requestObjectVerificationResult{
			Verified: false,
			Error:    "signature mismatch",
		},
	}, true, true)
	if err == nil || !strings.Contains(err.Error(), "request object verification failed") {
		t.Fatalf("expected request object verification error, got %v", err)
	}
}

func TestEnsurePresentationRequestTrustRequiresExternalApproval(t *testing.T) {
	server := &walletHarnessServer{allowExternal: true}

	err := server.ensurePresentationRequestTrust(trustEvaluation{
		ClientIDScheme:         "redirect_uri",
		TrustedTarget:          false,
		RequiresExternalAccept: true,
	}, true, false)
	if err == nil || !strings.Contains(err.Error(), "trust approval") {
		t.Fatalf("expected external trust approval error, got %v", err)
	}
}

func TestVerifyRequestObjectSignatureRejectsUnsupportedScheme(t *testing.T) {
	server := &walletHarnessServer{}

	_, err := server.verifyRequestObjectSignature(
		context.Background(),
		&resolvedRequestEnvelope{},
		&resolvedRequestContext{},
		trustEvaluation{ClientIDScheme: "openid_federation"},
	)
	if err == nil || !strings.Contains(err.Error(), "not yet supported") {
		t.Fatalf("expected unsupported scheme error, got %v", err)
	}
}

func TestVerifyRequestObjectSignatureX509SANDNS(t *testing.T) {
	verifierKey, certificateChain := createECDSACertificateChain(t, []string{"verifier.example"}, "Verifier Certificate")
	requestJWT := signECDSAJWT(t, verifierKey, jwt.MapClaims{
		"jti":           "req-x509",
		"client_id":     "x509_san_dns:verifier.example",
		"nonce":         "nonce-123",
		"response_mode": "direct_post",
		"response_uri":  "https://verifier.example/callback",
	}, map[string]interface{}{
		"typ": "oauth-authz-req+jwt",
		"x5c": encodeCertificateChain(certificateChain),
	})
	decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}

	server := &walletHarnessServer{
		verifierX509Roots: certificateRootsFromDERChain(t, certificateChain),
	}
	keyType, err := server.verifyRequestObjectSignature(
		context.Background(),
		&resolvedRequestEnvelope{
			RequestJWT:    requestJWT,
			DecodedHeader: decodedRequest.Header,
		},
		&resolvedRequestContext{
			ClientID:    "x509_san_dns:verifier.example",
			ResponseURI: "https://verifier.example/callback",
		},
		trustEvaluation{ClientIDScheme: "x509_san_dns"},
	)
	if err != nil {
		t.Fatalf("verifyRequestObjectSignature(x509_san_dns): %v", err)
	}
	if keyType != "EC" {
		t.Fatalf("unexpected key type %q", keyType)
	}
}

func TestVerifyRequestObjectSignatureVerifierAttestation(t *testing.T) {
	attestationKey, attestationCertificateChain := createECDSACertificateChain(t, []string{"attestation.example"}, "Attestation Authority")
	verifierKey := generateECDSAKey(t)

	verifierJWK := intcrypto.JWKFromECPublicKey(&verifierKey.PublicKey, "verifier-key")
	attestationJWT := signECDSAJWT(t, attestationKey, jwt.MapClaims{
		"iss": "https://attestation.example",
		"sub": "verifier.example",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"cnf": map[string]interface{}{
			"jwk": verifierJWK,
		},
		"redirect_uris": []string{"https://verifier.example/callback"},
	}, map[string]interface{}{
		"typ": "verifier-attestation+jwt",
		"x5c": encodeCertificateChain(attestationCertificateChain),
	})
	requestJWT := signECDSAJWT(t, verifierKey, jwt.MapClaims{
		"jti":           "req-attestation",
		"client_id":     "verifier_attestation:verifier.example",
		"nonce":         "nonce-456",
		"response_mode": "direct_post",
		"response_uri":  "https://verifier.example/callback",
	}, map[string]interface{}{
		"typ": "oauth-authz-req+jwt",
		"jwt": attestationJWT,
		"kid": verifierJWK.Kid,
	})
	decodedRequest, err := intcrypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}

	server := &walletHarnessServer{
		trustedVerifierAttestationIssuers: map[string]struct{}{
			"https://attestation.example": {},
		},
		verifierX509Roots: certificateRootsFromDERChain(t, attestationCertificateChain),
	}
	keyType, err := server.verifyRequestObjectSignature(
		context.Background(),
		&resolvedRequestEnvelope{
			RequestJWT:    requestJWT,
			DecodedHeader: decodedRequest.Header,
		},
		&resolvedRequestContext{
			ClientID:    "verifier_attestation:verifier.example",
			ResponseURI: "https://verifier.example/callback",
		},
		trustEvaluation{ClientIDScheme: "verifier_attestation"},
	)
	if err != nil {
		t.Fatalf("verifyRequestObjectSignature(verifier_attestation): %v", err)
	}
	if keyType != "EC" {
		t.Fatalf("unexpected key type %q", keyType)
	}
}

func createECDSACertificateChain(t *testing.T, dnsNames []string, commonName string) (*ecdsa.PrivateKey, [][]byte) {
	t.Helper()
	caKey := generateECDSAKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName + " Root",
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * time.Minute),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
	}
	caCertificateDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(ca): %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caCertificateDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(ca): %v", err)
	}

	leafKey := generateECDSAKey(t)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(10 * time.Minute),
		DNSNames:              append([]string{}, dnsNames...),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	leafCertificateDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(leaf): %v", err)
	}
	return leafKey, [][]byte{leafCertificateDER, caCertificateDER}
}

func certificateRootsFromDERChain(t *testing.T, chain [][]byte) *x509.CertPool {
	t.Helper()
	if len(chain) == 0 {
		t.Fatal("certificate chain is empty")
	}
	root, err := x509.ParseCertificate(chain[len(chain)-1])
	if err != nil {
		t.Fatalf("parse certificate root: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return roots
}

func generateECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return privateKey
}

func encodeCertificateChain(certificates [][]byte) []string {
	encoded := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate))
	}
	return encoded
}

func signECDSAJWT(t *testing.T, privateKey *ecdsa.PrivateKey, claims jwt.MapClaims, headers map[string]interface{}) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	for key, value := range headers {
		token.Header[key] = value
	}
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

func signedCredentialJWTWithClaims(t *testing.T, subject string, includeContext bool) string {
	t.Helper()
	vcClaim := map[string]interface{}{
		"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
		"credentialSubject": map[string]interface{}{
			"id":              subject,
			"degree":          "General Credential",
			"department":      "General",
			"family_name":     "Holder",
			"given_name":      "Credential",
			"graduation_year": 2021,
		},
	}
	if includeContext {
		vcClaim["@context"] = []string{"https://www.w3.org/2018/credentials/v1"}
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"sub": subject,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"vct": "https://protocolsoup.com/credentials/university_degree",
		"vc":  vcClaim,
	})
	token.Header["typ"] = "vc+jwt"
	signed, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("SignedString(credential with claims): %v", err)
	}
	return signed
}

func rawLDPCredentialWithClaims(t *testing.T, subject string) string {
	t.Helper()
	payload := map[string]interface{}{
		"@context":       []string{"https://www.w3.org/2018/credentials/v1"},
		"id":             "https://issuer.example/credentials/ldp-1",
		"type":           []string{"VerifiableCredential", "UniversityDegreeCredential"},
		"issuer":         "did:jwk:issuer",
		"issuanceDate":   time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339),
		"expirationDate": time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
		"vct":            "https://protocolsoup.com/credentials/university_degree",
		"credentialSubject": map[string]interface{}{
			"id":              subject,
			"degree":          "General Credential",
			"department":      "General",
			"family_name":     "Holder",
			"given_name":      "Credential",
			"graduation_year": 2021,
		},
		"proof": map[string]interface{}{
			"type":               "Ed25519Signature2020",
			"proofPurpose":       "assertionMethod",
			"verificationMethod": "did:jwk:issuer#key-1",
			"created":            time.Now().UTC().Format(time.RFC3339),
			"proofValue":         "zExampleProofValue",
		},
	}
	serialized, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal(ldp credential): %v", err)
	}
	return string(serialized)
}

func TestInferCredentialFormatFromVPRequestDCQLFormat(t *testing.T) {
	testCases := []struct {
		name             string
		format           string
		expectedConfigID string
	}{
		{"dc+sd-jwt", "dc+sd-jwt", "UniversityDegreeCredential"},
		{"jwt_vc_json", "jwt_vc_json", "UniversityDegreeCredentialJWT"},
		{"jwt_vc_json-ld", "jwt_vc_json-ld", "UniversityDegreeCredentialJWTLD"},
		{"ldp_vc", "ldp_vc", "UniversityDegreeCredentialLDP"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			envelope := &resolvedRequestEnvelope{
				DecodedPayload: map[string]interface{}{
					"dcql_query": map[string]interface{}{
						"credentials": []interface{}{
							map[string]interface{}{
								"id":     "test_cred",
								"format": tc.format,
							},
						},
					},
				},
			}
			format, configID := inferCredentialFormatFromVPRequest(envelope, false)
			if format != tc.format {
				t.Fatalf("expected format %q, got %q", tc.format, format)
			}
			if configID != tc.expectedConfigID {
				t.Fatalf("expected config ID %q, got %q", tc.expectedConfigID, configID)
			}
		})
	}
}

func TestInferCredentialFormatFromVPRequestNoFormat(t *testing.T) {
	envelope := &resolvedRequestEnvelope{
		DecodedPayload: map[string]interface{}{
			"dcql_query": map[string]interface{}{
				"credentials": []interface{}{
					map[string]interface{}{
						"id": "test_cred",
					},
				},
			},
		},
	}
	format, configID := inferCredentialFormatFromVPRequest(envelope, false)
	if format != "" {
		t.Fatalf("expected empty format, got %q", format)
	}
	if configID != "" {
		t.Fatalf("expected empty config ID, got %q", configID)
	}
}

func TestInferCredentialFormatFromVPRequestNilEnvelope(t *testing.T) {
	format, configID := inferCredentialFormatFromVPRequest(nil, false)
	if format != "" || configID != "" {
		t.Fatalf("expected empty results for nil envelope, got format=%q configID=%q", format, configID)
	}
}

func TestHandleAuthorizeRedirectsToConsentFlow(t *testing.T) {
	server := &walletHarnessServer{
		targetHost:    "protocolsoup.com",
		allowExternal: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", server.handleAuthorize)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	requestURI := "https://suite.example/request/abc"
	resp, err := client.Get(ts.URL + "/authorize?" + url.Values{
		"client_id":          {"x509_hash:abc"},
		"request_uri":        {requestURI},
		"request_uri_method": {"post"},
	}.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	query := parsed.Query()
	if query.Get("request_uri") != requestURI {
		t.Fatalf("request_uri = %q", query.Get("request_uri"))
	}
	if query.Get("request_uri_method") != "post" {
		t.Fatalf("request_uri_method = %q", query.Get("request_uri_method"))
	}
	if !strings.Contains(query.Get("uri"), "openid4vp://authorize?") {
		t.Fatalf("uri = %q", query.Get("uri"))
	}
}

func TestFetchRequestObjectPOSTSendsWalletNonce(t *testing.T) {
	requestJWT := buildTestRequestJWT(t, "https://protocolsoup.com/oid4vp/response")
	var sawNonce string
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		sawNonce = strings.TrimSpace(r.Form.Get("wallet_nonce"))
		if sawNonce == "" {
			t.Fatal("expected wallet_nonce")
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(requestJWT))
	}))
	defer requestServer.Close()

	server := &walletHarnessServer{httpClient: requestServer.Client()}
	gotJWT, _, err := server.fetchRequestObject(context.Background(), requestServer.URL, "post")
	if err != nil {
		t.Fatalf("fetchRequestObject(post): %v", err)
	}
	if gotJWT != requestJWT {
		t.Fatalf("unexpected JWT %q", gotJWT)
	}
	if sawNonce == "" {
		t.Fatal("wallet_nonce was not captured")
	}
}

func TestResolveRequestContextRejectsRedirectURIWithResponseURI(t *testing.T) {
	responseURI := "https://protocolsoup.com/oid4vp/response"
	server := &walletHarnessServer{
		targetHost:        "protocolsoup.com",
		targetResponseURI: responseURI,
	}
	claims := jwt.MapClaims{
		"jti":           "req-123",
		"nonce":         "nonce-123",
		"client_id":     "redirect_uri:" + responseURI,
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  responseURI,
		"redirect_uri":  "https://protocolsoup.com/oid4vp/result/req-123",
		"dcql_query": map[string]interface{}{
			"credentials": []interface{}{map[string]interface{}{"id": "credential-query"}},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = "oauth-authz-req+jwt"
	requestJWT, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	_, err = server.resolveRequestContextWithOptions("req-123", requestJWT, true)
	if err == nil || !strings.Contains(err.Error(), "must not include redirect_uri") {
		t.Fatalf("expected redirect_uri rejection, got %v", err)
	}
}

func TestResolveRequestContextRejectsUnknownClientIDScheme(t *testing.T) {
	responseURI := "https://protocolsoup.com/oid4vp/response"
	server := &walletHarnessServer{
		targetHost:        "protocolsoup.com",
		targetResponseURI: responseURI,
	}
	claims := jwt.MapClaims{
		"jti":           "req-123",
		"nonce":         "nonce-123",
		"client_id":     "invalid_scheme:attacker",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  responseURI,
		"dcql_query": map[string]interface{}{
			"credentials": []interface{}{map[string]interface{}{"id": "credential-query"}},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = "oauth-authz-req+jwt"
	requestJWT, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("sign request: %v", err)
	}
	_, err = server.resolveRequestContextWithOptions("req-123", requestJWT, true)
	if err == nil || !strings.Contains(err.Error(), "unsupported client_id scheme") {
		t.Fatalf("expected unknown scheme rejection, got %v", err)
	}
}

func TestDisclosureClaimsFromDCQLExactEmptyMeansNone(t *testing.T) {
	claims := disclosureClaimsFromDCQL(`{"credentials":[{"id":"credential","format":"dc+sd-jwt"}]}`)
	if len(claims) != 0 {
		t.Fatalf("expected no claims for empty DCQL claims, got %v", claims)
	}
	claims = disclosureClaimsFromDCQL(`{"credentials":[{"id":"credential","format":"dc+sd-jwt","claims":[{"path":["family_name"]},{"path":["address","street"]}]}]}`)
	if !containsString(claims, "family_name") || !containsString(claims, "street") {
		t.Fatalf("unexpected claims %v", claims)
	}
	resolved, exact := resolvePresentationDisclosureClaims(nil, `{"credentials":[{"id":"credential","format":"dc+sd-jwt"}]}`)
	if !exact || len(resolved) != 0 {
		t.Fatalf("expected exact empty selection, got exact=%v claims=%v", exact, resolved)
	}
}

func TestWrapDCQLKeyedVPToken(t *testing.T) {
	wrapped, err := wrapDCQLKeyedVPToken(
		`{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}`,
		"eyJhbGciOiJFUzI1NiJ9.e30.sig~disclosure~",
		"dc+sd-jwt",
		map[string]bool{"pid": true},
	)
	if err != nil {
		t.Fatalf("wrapDCQLKeyedVPToken: %v", err)
	}
	var keyed map[string][]string
	if err := json.Unmarshal([]byte(wrapped), &keyed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(keyed["pid"]) != 1 {
		t.Fatalf("unexpected keyed token %v", keyed)
	}
}

// TestWrapDCQLKeyedVPTokenOmitsUnmatchedOptionalCredential proves OID4VP
// optional credential_sets behaviour: only the matched Credential Query id is
// present in vp_token even when another same-format query is in the DCQL.
func TestWrapDCQLKeyedVPTokenOmitsUnmatchedOptionalCredential(t *testing.T) {
	dcql := `{
		"credentials": [
			{"id":"real","format":"dc+sd-jwt","meta":{"vct_values":["https://protocolsoup.com/oid4vci/credential-types/university-degree"]}},
			{"id":"optional_other","format":"dc+sd-jwt","meta":{"vct_values":["urn:example:never"]}}
		],
		"credential_sets": [
			{"options":[["real"]]},
			{"options":[["optional_other"]],"required":false}
		]
	}`
	wrapped, err := wrapDCQLKeyedVPToken(
		dcql,
		"eyJhbGciOiJFUzI1NiJ9.e30.sig~disclosure~",
		"dc+sd-jwt",
		map[string]bool{"real": true},
	)
	if err != nil {
		t.Fatalf("wrapDCQLKeyedVPToken: %v", err)
	}
	var keyed map[string][]string
	if err := json.Unmarshal([]byte(wrapped), &keyed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(keyed) != 1 || len(keyed["real"]) != 1 {
		t.Fatalf("expected only real credential key, got %v", keyed)
	}
	if _, ok := keyed["optional_other"]; ok {
		t.Fatalf("optional unmatched credential must not appear in vp_token: %v", keyed)
	}
}

func TestValidateBrowserRedirectURI(t *testing.T) {
	got, err := validateBrowserRedirectURI("https://suite.example/continue")
	if err != nil || got != "https://suite.example/continue" {
		t.Fatalf("validateBrowserRedirectURI https: %v %q", err, got)
	}
	if _, err := validateBrowserRedirectURI("http://suite.example/continue"); err == nil {
		t.Fatal("expected http rejection")
	}
	if _, err := validateBrowserRedirectURI("https://127.0.0.1/continue"); err == nil {
		t.Fatal("expected loopback rejection")
	}
	got, err = validateBrowserRedirectURI("https://suite.example/callback#code_verifier")
	if err != nil || got != "https://suite.example/callback#code_verifier" {
		t.Fatalf("validateBrowserRedirectURI fragment: %v %q", err, got)
	}
	got, err = validateBrowserRedirectURI("https://suite.example/callback%23code_verifier")
	if err != nil || got != "https://suite.example/callback#code_verifier" {
		t.Fatalf("validateBrowserRedirectURI encoded fragment: %v %q", err, got)
	}
}

func TestHAIPAttestationJWTBuildersUseExpectedHeaders(t *testing.T) {
	attesterKey, attesterChain := createECDSACertificateChain(t, []string{"attester.example"}, "HAIP Attester")
	keyAttesterKey, keyAttesterChain := createECDSACertificateChain(t, []string{"key-attestation.example"}, "Key Attester")
	holderKey := generateECDSAKey(t)
	holderJWK := intcrypto.JWKFromECPublicKey(&holderKey.PublicKey, "holder-key")
	instanceKey := generateECDSAKey(t)
	const clientID = "protocolsoup-wallet"

	attestationJWT, err := buildClientAttestationJWT(
		attesterKey,
		encodeCertificateChain(attesterChain),
		clientID,
		intcrypto.JWKFromECPublicKey(&instanceKey.PublicKey, "client-instance"),
		time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("buildClientAttestationJWT: %v", err)
	}
	decodedAttestation, err := intcrypto.DecodeTokenWithoutValidation(attestationJWT)
	if err != nil {
		t.Fatalf("decode client attestation jwt: %v", err)
	}
	if got := strings.TrimSpace(asString(decodedAttestation.Header["typ"])); got != typOAuthClientAttestationJWT {
		t.Fatalf("client attestation typ = %q", got)
	}
	if asString(decodedAttestation.Payload["sub"]) != clientID {
		t.Fatalf("client attestation sub = %q", decodedAttestation.Payload["sub"])
	}

	popJWT, err := buildClientAttestationPoPJWT(instanceKey, "https://issuer.example/oid4vci", "pop-jti-1", time.Now().UTC())
	if err != nil {
		t.Fatalf("buildClientAttestationPoPJWT: %v", err)
	}
	decodedPoP, err := intcrypto.DecodeTokenWithoutValidation(popJWT)
	if err != nil {
		t.Fatalf("decode client attestation pop jwt: %v", err)
	}
	if got := strings.TrimSpace(asString(decodedPoP.Header["typ"])); got != typOAuthClientAttestationPoPJWT {
		t.Fatalf("client attestation pop typ = %q", got)
	}

	keyAttestationJWT, err := buildKeyAttestationJWT(
		keyAttesterKey,
		encodeCertificateChain(keyAttesterChain),
		[]intcrypto.JWK{holderJWK},
		[]string{"iso_18045_moderate"},
		[]string{"iso_18045_moderate"},
		"test-c-nonce",
	)
	if err != nil {
		t.Fatalf("buildKeyAttestationJWT: %v", err)
	}
	decodedKeyAttestation, err := intcrypto.DecodeTokenWithoutValidation(keyAttestationJWT)
	if err != nil {
		t.Fatalf("decode key attestation jwt: %v", err)
	}
	if got := strings.TrimSpace(asString(decodedKeyAttestation.Header["typ"])); got != typKeyAttestationJWT {
		t.Fatalf("key attestation typ = %q", got)
	}
	if asString(decodedKeyAttestation.Payload["nonce"]) != "test-c-nonce" {
		t.Fatalf("key attestation nonce = %q", decodedKeyAttestation.Payload["nonce"])
	}

	proofJWT, err := createCredentialProofJWTWithKeyAttestation(
		holderKey,
		holderJWK,
		"test-c-nonce",
		"did:example:wallet:alice",
		"https://issuer.example/oid4vci",
		keyAttestationJWT,
	)
	if err != nil {
		t.Fatalf("createCredentialProofJWTWithKeyAttestation: %v", err)
	}
	decodedProof, err := intcrypto.DecodeTokenWithoutValidation(proofJWT)
	if err != nil {
		t.Fatalf("decode proof jwt: %v", err)
	}
	if got := strings.TrimSpace(asString(decodedProof.Header["typ"])); got != "openid4vci-proof+jwt" {
		t.Fatalf("proof typ = %q", got)
	}
	if _, ok := decodedProof.Header["key_attestation"]; !ok {
		t.Fatal("proof must carry key_attestation header")
	}
	if asString(decodedProof.Payload["nonce"]) != "test-c-nonce" {
		t.Fatalf("proof nonce = %q", decodedProof.Payload["nonce"])
	}
}

func TestPreferHAIPBootstrapConfigurationID(t *testing.T) {
	if got := preferHAIPBootstrapConfigurationID("UniversityDegreeCredential", true); got != "UniversityDegreeCredentialSDJWTHAIP" {
		t.Fatalf("unexpected haip bootstrap config id %q", got)
	}
	if got := preferHAIPBootstrapConfigurationID("UniversityDegreeCredential", false); got != "UniversityDegreeCredential" {
		t.Fatalf("unexpected non-haip bootstrap config id %q", got)
	}
}

func TestIsHAIPCredentialConfigurationID(t *testing.T) {
	if !isHAIPCredentialConfigurationID("UniversityDegreeCredentialSDJWTHAIP") {
		t.Fatal("expected SD-JWT HAIP configuration to be detected")
	}
	if !isHAIPCredentialConfigurationID("MobileDrivingLicenceMsoMdocHAIP") {
		t.Fatal("expected mdoc HAIP configuration to be detected")
	}
	if isHAIPCredentialConfigurationID("UniversityDegreeCredential") {
		t.Fatal("did not expect non-HAIP configuration to match")
	}
}

func TestHAIPDPoPProofBuilderIncludesHTMHTU(t *testing.T) {
	session, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}
	proof, err := session.buildDPoPProof(http.MethodPost, "https://issuer.example/oid4vci/token", jwt.MapClaims{"nonce": "server-nonce"})
	if err != nil {
		t.Fatalf("buildDPoPProof: %v", err)
	}
	decoded, err := intcrypto.DecodeTokenWithoutValidation(proof)
	if err != nil {
		t.Fatalf("decode dpop proof: %v", err)
	}
	if asString(decoded.Payload["htm"]) != "POST" {
		t.Fatalf("dpop htm = %q", decoded.Payload["htm"])
	}
	if asString(decoded.Payload["htu"]) != "https://issuer.example/oid4vci/token" {
		t.Fatalf("dpop htu = %q", decoded.Payload["htu"])
	}
	if asString(decoded.Payload["nonce"]) != "server-nonce" {
		t.Fatalf("dpop nonce = %q", decoded.Payload["nonce"])
	}
}

func TestAuthorizationHeaderForAccessTokenUsesDPoPScheme(t *testing.T) {
	got := authorizationHeaderForAccessToken("DPoP", "access-token")
	if got != "DPoP access-token" {
		t.Fatalf("authorization header = %q", got)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(target) {
			return true
		}
	}
	return false
}

func TestParseAttestationJWKInputPreservesX5C(t *testing.T) {
	raw := `{"keys":[{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x5c":["MIIB"]}]}`
	_, x5c, err := parseAttestationJWKInput(raw)
	if err != nil {
		t.Fatalf("parseAttestationJWKInput: %v", err)
	}
	if len(x5c) != 1 || x5c[0] != "MIIB" {
		t.Fatalf("x5c = %#v", x5c)
	}
}

