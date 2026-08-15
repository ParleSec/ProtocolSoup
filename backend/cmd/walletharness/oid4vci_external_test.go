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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
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

func TestWellKnownMetadataURLCandidatesPreserveCredentialIssuerTrailingSlash(t *testing.T) {
	candidates, err := wellKnownMetadataURLCandidates(
		"https://issuer.example/test/a/example-alias/",
		"openid-credential-issuer",
	)
	if err != nil {
		t.Fatalf("wellKnownMetadataURLCandidates: %v", err)
	}
	want := "https://issuer.example/.well-known/openid-credential-issuer/test/a/example-alias/"
	if candidates[0] != want {
		t.Fatalf("canonical candidate = %q, want %q", candidates[0], want)
	}
	if len(candidates) != 1 {
		t.Fatalf("credential issuer discovery must not add OIDC-style fallback, got %#v", candidates)
	}
}

func TestWellKnownMetadataURLCandidatesStripOAuthASTrailingSlash(t *testing.T) {
	candidates, err := wellKnownMetadataURLCandidates(
		"https://issuer.example/test/a/example-alias/",
		"oauth-authorization-server",
	)
	if err != nil {
		t.Fatalf("wellKnownMetadataURLCandidates: %v", err)
	}
	want := "https://issuer.example/.well-known/oauth-authorization-server/test/a/example-alias"
	if candidates[0] != want {
		t.Fatalf("canonical candidate = %q, want %q", candidates[0], want)
	}
	if len(candidates) != 1 {
		t.Fatalf("oauth-authorization-server discovery must not add OIDC-style fallback, got %#v", candidates)
	}
}

func TestNormalizeCredentialIssuerIdentifierReversesWellKnownInsertion(t *testing.T) {
	got, err := normalizeCredentialIssuerIdentifier(
		"https://issuer.example/.well-known/openid-credential-issuer/test/a/example-alias/",
	)
	if err != nil {
		t.Fatalf("normalizeCredentialIssuerIdentifier: %v", err)
	}
	want := "https://issuer.example/test/a/example-alias/"
	if got != want {
		t.Fatalf("issuer = %q, want %q", got, want)
	}
}

func TestNormalizeCredentialIssuerIdentifierRejectsASDiscoveryURL(t *testing.T) {
	_, err := normalizeCredentialIssuerIdentifier(
		"https://issuer.example/.well-known/oauth-authorization-server/test/a/example/",
	)
	if err == nil {
		t.Fatal("expected AS discovery URL to be rejected")
	}
	if !strings.Contains(err.Error(), "Authorization Server discovery") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDiscoverWalletInitiatedIssuerReturnsConfigurationsWithoutPAR(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	credentialIssuer := testServer.URL + "/test/a/wallet-initiated/"
	var parHits atomic.Int32
	mux.HandleFunc("/.well-known/openid-credential-issuer/test/a/wallet-initiated/", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credential_issuer":   credentialIssuer,
			"credential_endpoint": credentialIssuer + "credential",
			"authorization_servers": []string{
				credentialIssuer,
			},
			"credential_configurations_supported": map[string]interface{}{
				"eu.europa.ec.eudi.pid.1": map[string]interface{}{
					"format": "dc+sd-jwt",
					"vct":    "urn:eu.europa.ec.eudi:pid:1",
					"cryptographic_binding_methods_supported": []string{"jwk"},
					"proof_types_supported": map[string]interface{}{
						"jwt": map[string]interface{}{
							"proof_signing_alg_values_supported": []string{"ES256"},
						},
					},
				},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/test/a/wallet-initiated", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                credentialIssuer,
			"authorization_endpoint":                credentialIssuer + "authorize",
			"token_endpoint":                        credentialIssuer + "token",
			"pushed_authorization_request_endpoint": credentialIssuer + "par",
			"require_pushed_authorization_requests": true,
			"dpop_signing_alg_values_supported":     []string{"ES256"},
			"token_endpoint_auth_methods_supported": []string{"attest_jwt_client_auth"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/test/a/wallet-initiated/par", func(w http.ResponseWriter, r *http.Request) {
		parHits.Add(1)
		http.Error(w, "par should not run during discovery", http.StatusInternalServerError)
	})

	server := &walletHarnessServer{httpClient: testServer.Client(), issuerBaseURL: testServer.URL}
	result, err := server.discoverWalletInitiatedIssuer(context.Background(), credentialIssuer, "")
	if err != nil {
		t.Fatalf("discoverWalletInitiatedIssuer: %v", err)
	}
	if result == nil || !result.ConfigurationSelectionRequired {
		t.Fatalf("expected configuration selection, got %+v", result)
	}
	if result.CredentialIssuer != credentialIssuer {
		t.Fatalf("credential_issuer = %q", result.CredentialIssuer)
	}
	if len(result.CredentialConfigurations) != 1 {
		t.Fatalf("configurations = %#v", result.CredentialConfigurations)
	}
	if got := asString(result.CredentialConfigurations[0]["id"]); got != "eu.europa.ec.eudi.pid.1" {
		t.Fatalf("configuration id = %q", got)
	}
	if parHits.Load() != 0 {
		t.Fatalf("discovery probed PAR %d times", parHits.Load())
	}
	if reqs := result.IssuanceRequirements; reqs == nil || reqs["par"] != true || reqs["dpop"] != true || reqs["client_attestation"] != true {
		t.Fatalf("issuance requirements = %#v", result.IssuanceRequirements)
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

// TestValidateImportedCredentialRefusesNotEvaluatedMdoc pins the A3c item 4
// trust boundary: validateImportedCredential accepts arbitrary pasted or
// externally-fetched credentials, and before mso_mdoc registration an mdoc
// import failed at parse. After registration it parses successfully, and
// this wallet supplies no IssuerTrustAnchors for an arbitrary external
// issuer's mdoc -- so ValidateIssuerSignature reports IssuerTrustNotEvaluated.
// That must refuse the import exactly like a checked failure, never fall
// through as an accepted-but-unverified credential.
func TestValidateImportedCredentialRefusesNotEvaluatedMdoc(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	server := &walletHarnessServer{deviceKey: deviceKey, httpClient: http.DefaultClient}
	credential := issueMdocBoundTo(t, server, &deviceKey.PublicKey)
	// issueMdocBoundTo installs the matching IACA for bindCredential tests;
	// clear it so this path models an arbitrary external issuer with no
	// configured trust anchor.
	server.mdocIssuerRoots = nil

	// issuerMetadata and authorizationServerMetadata are both nil, and the
	// parsed mdoc carries no Issuer claim (mdoc has no JWT-style iss), so
	// this exercises exactly the "arbitrary external issuer, no trust
	// anchor available" path A3c item 4 describes -- not a resolvable-but-
	// unresolved JWKS lookup.
	parsed, err := server.validateImportedCredential(context.Background(), credential, "mso_mdoc", nil, nil, "")
	if err == nil {
		t.Fatalf("validateImportedCredential accepted an mdoc credential with no issuer trust anchor; parsed=%+v", parsed)
	}
	if parsed != nil {
		t.Fatalf("validateImportedCredential returned a non-nil parsed credential alongside a refusal error")
	}
	if !strings.Contains(err.Error(), "issuer_trust=not_evaluated") {
		t.Fatalf("expected refusal to name issuer_trust=not_evaluated, got: %v", err)
	}
}

func TestValidateImportedCredentialAcceptsMdocWithIACA(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	server := &walletHarnessServer{deviceKey: deviceKey, httpClient: http.DefaultClient}
	credential := issueMdocBoundTo(t, server, &deviceKey.PublicKey)

	parsed, err := server.validateImportedCredential(context.Background(), credential, "mso_mdoc", nil, nil, "")
	if err != nil {
		t.Fatalf("validateImportedCredential with IACA: %v", err)
	}
	if parsed == nil || normalizeCredentialFormat(parsed.Format) != "mso_mdoc" {
		t.Fatalf("unexpected parsed credential: %+v", parsed)
	}
}

func TestDefaultJWKSURLCandidatesIncludesSharedShowcasePaths(t *testing.T) {
	candidates := defaultJWKSURLCandidates("https://protocolsoup.com/oid4vci")
	want := []string{
		"https://protocolsoup.com/.well-known/jwks.json",
		"https://protocolsoup.com/api/.well-known/jwks.json",
		"https://protocolsoup.com/oidc/.well-known/jwks.json",
	}
	for _, candidate := range want {
		if !containsStringFold(candidates, candidate) {
			t.Fatalf("missing candidate %q in %#v", candidate, candidates)
		}
	}
	for _, candidate := range candidates {
		if strings.Contains(candidate, "jwt-vc-issuer") {
			t.Fatalf("unexpected jwt-vc-issuer candidate %q", candidate)
		}
	}
}

func TestResolveExternalIssuerKeysDoesNotProbeJwtVCIssuer(t *testing.T) {
	t.Parallel()

	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}

	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()

	var jwtVCIssuerHits atomic.Int32
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(issuerKeySet.PublicJWKS())
	})
	mux.HandleFunc("/.well-known/jwt-vc-issuer/", func(w http.ResponseWriter, r *http.Request) {
		jwtVCIssuerHits.Add(1)
		http.NotFound(w, r)
	})
	mux.HandleFunc("/.well-known/jwt-vc-issuer", func(w http.ResponseWriter, r *http.Request) {
		jwtVCIssuerHits.Add(1)
		http.NotFound(w, r)
	})

	credentialIssuer := testServer.URL + "/test/a/example-alias/"
	server := &walletHarnessServer{httpClient: testServer.Client()}
	keys, err := server.resolveExternalIssuerKeys(
		context.Background(),
		&vc.ParsedCredential{Issuer: strings.TrimRight(credentialIssuer, "/"), Format: "dc+sd-jwt"},
		&resolvedExternalIssuerMetadata{
			CredentialIssuer: credentialIssuer,
			JWKSURI:          testServer.URL + "/.well-known/jwks.json",
		},
		nil,
		"",
	)
	if err != nil {
		t.Fatalf("resolveExternalIssuerKeys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected advertised jwks_uri keys")
	}
	if hits := jwtVCIssuerHits.Load(); hits != 0 {
		t.Fatalf("probed /.well-known/jwt-vc-issuer %d times", hits)
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
			"nonce_endpoint":      credentialIssuer + "/nonce",
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
		})
	})
	mux.HandleFunc(issuerPath+"/nonce", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			http.Error(w, "nonce endpoint must not receive an Authorization header", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"c_nonce": cNonce})
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
		var proofJWT string
		if proofs, ok := payload["proofs"].(map[string]interface{}); ok {
			if jwtProofs, ok := proofs["jwt"].([]interface{}); ok && len(jwtProofs) > 0 {
				proofJWT = strings.TrimSpace(asString(jwtProofs[0]))
			}
		}
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
		credential := signedCredentialJWT(t, credentialIssuer, jwt.SigningMethodRS256, issuerKeySet.RSAPrivateKey(), issuerKeySet.RSAKeyID(), "did:example:wallet:holder")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credentials": []map[string]interface{}{
				{"credential": credential},
			},
		})
	})

	server := &walletHarnessServer{
		httpClient:       testServer.Client(),
		issuerBaseURL:    testServer.URL,
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
		issuerBaseURL:    testServer.URL,
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
			"nonce_endpoint":      credentialIssuer + "/nonce",
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
		})
	})
	mux.HandleFunc("/issuer/nonce", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			http.Error(w, "nonce endpoint must not receive an Authorization header", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"c_nonce": "auth-c-nonce"})
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
		var proofJWT string
		if proofs, ok := payload["proofs"].(map[string]interface{}); ok {
			if jwtProofs, ok := proofs["jwt"].([]interface{}); ok && len(jwtProofs) > 0 {
				proofJWT = strings.TrimSpace(asString(jwtProofs[0]))
			}
		}
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
		credential := signedCredentialJWT(t, credentialIssuer, jwt.SigningMethodRS256, issuerKeySet.RSAPrivateKey(), issuerKeySet.RSAKeyID(), "did:example:wallet:holder")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credentials": []map[string]interface{}{
				{"credential": credential},
			},
		})
	})

	server := &walletHarnessServer{
		httpClient:        testServer.Client(),
		issuerBaseURL:     testServer.URL,
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

func TestOID4VCICallbackPassesPendingHAIPSession(t *testing.T) {
	t.Parallel()

	const (
		credentialConfigurationID = "pid_sd_jwt"
		walletBaseURL             = "https://wallet.example"
		attestedClientID          = "protocolsoup-wallet"
	)

	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	clientAttesterKey, clientAttesterChain := createECDSACertificateChain(t, []string{"attester.example"}, "Client Attester")
	keyAttesterKey, keyAttesterChain := createECDSACertificateChain(t, []string{"key-attester.example"}, "Key Attester")
	deviceKey := generateECDSAKey(t)
	haipSession, err := (&walletHarnessServer{}).newHAIPIssuanceSession()
	if err != nil {
		t.Fatalf("newHAIPIssuanceSession: %v", err)
	}

	mux := http.NewServeMux()
	testServer := httptest.NewServer(mux)
	defer testServer.Close()
	credentialIssuer := testServer.URL + "/issuer"

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(issuerKeySet.PublicJWKS())
	})
	mux.HandleFunc("/issuer/token", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(headerOAuthClientAttestation); got == "" {
			http.Error(w, "missing client attestation", http.StatusUnauthorized)
			return
		}
		if got := r.Header.Get(headerOAuthClientAttestationPoP); got == "" {
			http.Error(w, "missing client attestation pop", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "haip-access-token",
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/issuer/nonce", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"c_nonce": "haip-c-nonce"})
	})
	mux.HandleFunc("/issuer/credential", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer haip-access-token" {
			http.Error(w, "unexpected Authorization header", http.StatusUnauthorized)
			return
		}
		credential := signedCredentialJWT(t, credentialIssuer, jwt.SigningMethodRS256, issuerKeySet.RSAPrivateKey(), issuerKeySet.RSAKeyID(), "did:example:wallet:holder")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"credentials": []map[string]interface{}{
				{"credential": credential},
			},
		})
	})

	server := &walletHarnessServer{
		httpClient:           testServer.Client(),
		issuerBaseURL:        testServer.URL,
		haipAttestedClientID: attestedClientID,
		haipClientAttestation: &attestationJWKMaterial{
			PrivateKey: clientAttesterKey,
			X5C:        encodeCertificateChain(clientAttesterChain),
		},
		haipKeyAttestation: &attestationJWKMaterial{
			PrivateKey: keyAttesterKey,
			X5C:        encodeCertificateChain(keyAttesterChain),
		},
		deviceKey:         deviceKey,
		deviceKeyID:       "wallet-device",
		walletSessionTTL:  10 * time.Minute,
		wallets:           make(map[string]*walletMaterial),
		oid4vciAuthStates: make(map[string]*pendingOID4VCIAuthState),
	}
	wallet, err := server.getOrCreateWallet("req:haip-auth", "did:example:wallet:holder", walletBaseURL)
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}

	state := "haip-state-1"
	server.oid4vciAuthStates[state] = &pendingOID4VCIAuthState{
		State:                     state,
		ScopeKey:                  wallet.ScopeKey,
		WalletSubject:             wallet.Subject,
		WalletBaseURL:             walletBaseURL,
		ClientID:                  attestedClientID,
		RedirectURI:               walletBaseURL + "/api/oid4vci/callback",
		CodeVerifier:              "verifier",
		CredentialConfigurationID: credentialConfigurationID,
		CredentialFormat:          "jwt_vc_json",
		JWTProofRequired:          true,
		IssuerMetadata: &resolvedExternalIssuerMetadata{
			CredentialIssuer:   credentialIssuer,
			CredentialEndpoint: credentialIssuer + "/credential",
			NonceEndpoint:      credentialIssuer + "/nonce",
			JWKSURI:            testServer.URL + "/.well-known/jwks.json",
			CredentialConfigurationsSupported: map[string]map[string]interface{}{
				credentialConfigurationID: {
					"format": "jwt_vc_json",
					"proof_types_supported": map[string]interface{}{
						"jwt": map[string]interface{}{
							"proof_signing_alg_values_supported": []string{"ES256"},
						},
					},
				},
			},
		},
		AuthorizationServerMetadata: &resolvedAuthorizationServerMetadata{
			Issuer:                             credentialIssuer,
			TokenEndpoint:                      credentialIssuer + "/token",
			TokenEndpointAuthMethodsSupported:  []string{"attest_jwt_client_auth"},
			RequirePushedAuthorizationRequests: true,
			DPoPSigningAlgValuesSupported:      []string{"ES256"},
		},
		HAIPSession: haipSession,
		ExpectedIss: credentialIssuer,
		PopAudience: credentialIssuer,
		UseHAIP:     true,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
	}

	callbackRequest := httptest.NewRequest(http.MethodGet, walletBaseURL+"/api/oid4vci/callback?code=auth-code&state="+url.QueryEscape(state)+"&iss="+url.QueryEscape(credentialIssuer), nil)
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
	if got := location.Query().Get("oid4vci_status"); got != "success" {
		t.Fatalf("callback status = %q message = %q", got, location.Query().Get("oid4vci_message"))
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" {
		t.Fatal("expected wallet credential after HAIP callback")
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

func TestBindCredentialAcceptsSDJWTCNFWithoutSub(t *testing.T) {
	t.Parallel()

	server := &walletHarnessServer{
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	wallet, err := server.getOrCreateWallet("req:sdjwt-cnf", "did:example:wallet:holder", "")
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}
	holderJWK, _, err := walletActiveJWK(wallet)
	if err != nil {
		t.Fatalf("walletActiveJWK: %v", err)
	}
	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example/sdjwt",
		"vct": "urn:eu.europa.ec.eudi:pid:1",
		"cnf": map[string]interface{}{"jwk": holderJWK},
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	token.Header["typ"] = "dc+sd-jwt"
	token.Header["kid"] = issuerKeySet.RSAKeyID()
	signed, err := token.SignedString(issuerKeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	credential := vc.BuildSDJWTSerialization(signed, nil, "")
	if err := server.bindCredential(wallet, credential, "pid", "dc+sd-jwt"); err != nil {
		t.Fatalf("bindCredential: %v", err)
	}
	if strings.TrimSpace(wallet.CredentialJWT) == "" {
		t.Fatal("expected stored credential")
	}
}

func TestBindCredentialRejectsJWTWithoutSubOrCNF(t *testing.T) {
	t.Parallel()

	server := &walletHarnessServer{
		walletSessionTTL: 10 * time.Minute,
		wallets:          make(map[string]*walletMaterial),
	}
	wallet, err := server.getOrCreateWallet("req:unbound", "did:example:wallet:holder", "")
	if err != nil {
		t.Fatalf("getOrCreateWallet: %v", err)
	}
	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	credential := signedCredentialJWT(t, "https://issuer.example", jwt.SigningMethodRS256, issuerKeySet.RSAPrivateKey(), issuerKeySet.RSAKeyID(), "")
	if err := server.bindCredential(wallet, credential, "UniversityDegreeCredential", "jwt_vc_json"); err == nil {
		t.Fatal("expected missing subject binding")
	} else if !strings.Contains(err.Error(), "missing subject binding") {
		t.Fatalf("unexpected bind error: %v", err)
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
