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
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/golang-jwt/jwt/v5"
)

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
	requestURI, requestJWT, _, err := parseOpenID4VPURI("openid4vp://authorize?request_uri=https%3A%2F%2Fprotocolsoup.com%2Foid4vp%2Frequest%2Fabc123")
	if err != nil {
		t.Fatalf("parseOpenID4VPURI: %v", err)
	}
	if requestJWT != "" {
		t.Fatalf("expected empty request JWT, got %q", requestJWT)
	}
	if requestURI != "https://protocolsoup.com/oid4vp/request/abc123" {
		t.Fatalf("unexpected requestURI %q", requestURI)
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
		"response_mode": "direct_post",
		"response_uri":  responseURI,
	})
	token.Header["typ"] = "oauth-authz-req+jwt"
	signed, err := token.SignedString([]byte("wallet-harness-test-secret"))
	if err != nil {
		t.Fatalf("sign request jwt: %v", err)
	}
	return signed
}

func TestInferClientIDSchemeRecognizesPhase3Prefixes(t *testing.T) {
	testCases := []struct {
		clientID string
		want     string
	}{
		{clientID: "x509_san_dns:verifier.example", want: "x509_san_dns"},
		{clientID: "verifier_attestation:verifier.example", want: "verifier_attestation"},
	}

	for _, testCase := range testCases {
		if got := inferClientIDScheme(testCase.clientID, nil); got != testCase.want {
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

	server := &walletHarnessServer{}
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
			format, configID := inferCredentialFormatFromVPRequest(envelope)
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
	format, configID := inferCredentialFormatFromVPRequest(envelope)
	if format != "" {
		t.Fatalf("expected empty format, got %q", format)
	}
	if configID != "" {
		t.Fatalf("expected empty config ID, got %q", configID)
	}
}

func TestInferCredentialFormatFromVPRequestNilEnvelope(t *testing.T) {
	format, configID := inferCredentialFormatFromVPRequest(nil)
	if format != "" || configID != "" {
		t.Fatalf("expected empty results for nil envelope, got format=%q configID=%q", format, configID)
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
