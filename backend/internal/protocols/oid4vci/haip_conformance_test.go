package oid4vci

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// --- RFC 8414 Authorization Server metadata (B1) -------------------------

func TestAuthorizationServerMetadataDiscoverable(t *testing.T) {
	server, testPlugin, _ := newAttestationTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)

	if asString(t, payload["issuer"]) != testPlugin.issuerID() {
		t.Fatalf("expected issuer %q, got %v", testPlugin.issuerID(), payload["issuer"])
	}
	if asString(t, payload["authorization_endpoint"]) == "" {
		t.Fatalf("expected authorization_endpoint in AS metadata")
	}
	if asString(t, payload["token_endpoint"]) != testPlugin.issuerID()+"/token" {
		t.Fatalf("expected token_endpoint to match issuer /token, got %v", payload["token_endpoint"])
	}
	authMethods, ok := payload["token_endpoint_auth_methods_supported"].([]interface{})
	if !ok {
		t.Fatalf("expected token_endpoint_auth_methods_supported array")
	}
	for _, method := range authMethods {
		if method == "attest_jwt_client_auth" {
			t.Fatalf("attest_jwt_client_auth must not be advertised without a configured trust anchor")
		}
	}
}

func TestAuthorizationServerMetadataAdvertisesAttestationWhenConfigured(t *testing.T) {
	_, _, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)

	authMethods, ok := payload["token_endpoint_auth_methods_supported"].([]interface{})
	if !ok {
		t.Fatalf("expected token_endpoint_auth_methods_supported array")
	}
	found := false
	for _, method := range authMethods {
		if method == "attest_jwt_client_auth" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected attest_jwt_client_auth to be advertised once a trust anchor is configured, got %v", authMethods)
	}
}

func TestAuthorizationServerMetadataRejectsUnexpectedPathSuffix(t *testing.T) {
	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/oauth-authorization-server/unexpected")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// --- OAuth 2.0 Attestation-Based Client Authentication (B2) ---------------

func TestAuthorizationCodeGrantWithClientAttestationSucceeds(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()

	const clientID = "attested-wallet-client"
	const redirectURI = "https://wallet.example/callback"
	registerOID4VCITestClient(idp, clientID, redirectURI)
	authCode := createOID4VCITestAuthorizationCode(t, idp, clientID, redirectURI)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")

	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	cnfJWK := crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key")

	attestationJWT := buildClientAttestationJWT(t, attesterKey, attesterLeafDER, caCertDER, clientID, cnfJWK, time.Now().Add(5*time.Minute))
	popJWT := buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "pop-jti-1", time.Now())

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: popJWT,
	})
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["access_token"]) == "" {
		t.Fatalf("expected access_token in token response")
	}
	if asString(t, payload["c_nonce"]) == "" {
		t.Fatalf("expected c_nonce in token response")
	}
}

func TestAuthorizationCodeGrantRejectsClientIDMismatchWithAttestation(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()

	const clientID = "attested-wallet-client"
	const redirectURI = "https://wallet.example/callback"
	registerOID4VCITestClient(idp, clientID, redirectURI)
	authCode := createOID4VCITestAuthorizationCode(t, idp, clientID, redirectURI)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")

	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	cnfJWK := crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key")

	attestationJWT := buildClientAttestationJWT(t, attesterKey, attesterLeafDER, caCertDER, clientID, cnfJWK, time.Now().Add(5*time.Minute))
	popJWT := buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "pop-jti-mismatch", time.Now())

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {"some-other-client"},
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: popJWT,
	})
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["error"]) != "invalid_client" {
		t.Fatalf("expected invalid_client, got %v", payload["error"])
	}
}

func TestTokenEndpointRejectsClientAttestationWithoutTrustAnchor(t *testing.T) {
	// No OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM configured: a client
	// attestation must never be accepted on good faith.
	server, _, idp := newAttestationTestServer(t)
	defer server.Close()

	const clientID = "attested-wallet-client"
	const redirectURI = "https://wallet.example/callback"
	registerOID4VCITestClient(idp, clientID, redirectURI)
	authCode := createOID4VCITestAuthorizationCode(t, idp, clientID, redirectURI)

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
	}, map[string]string{
		headerClientAttestation:    "not-a-real-jwt",
		headerClientAttestationPoP: "not-a-real-jwt",
	})
	assertStatus(t, resp, http.StatusUnauthorized)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["error"]) != "invalid_client" {
		t.Fatalf("expected invalid_client, got %v", payload["error"])
	}
}

func TestTokenEndpointRejectsPartialClientAttestationHeaders(t *testing.T) {
	_, _, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, _, idp := newAttestationTestServer(t)
	defer server.Close()

	const clientID = "attested-wallet-client"
	const redirectURI = "https://wallet.example/callback"
	registerOID4VCITestClient(idp, clientID, redirectURI)
	authCode := createOID4VCITestAuthorizationCode(t, idp, clientID, redirectURI)

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
	}, map[string]string{
		headerClientAttestation: "only-the-attestation-header",
	})
	assertStatus(t, resp, http.StatusUnauthorized)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["error"]) != "invalid_client" {
		t.Fatalf("expected invalid_client, got %v", payload["error"])
	}
}

func TestTokenEndpointRejectsReplayedClientAttestationPoP(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()

	const clientID = "attested-wallet-client"
	const redirectURI = "https://wallet.example/callback"
	registerOID4VCITestClient(idp, clientID, redirectURI)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")

	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	cnfJWK := crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key")
	attestationJWT := buildClientAttestationJWT(t, attesterKey, attesterLeafDER, caCertDER, clientID, cnfJWK, time.Now().Add(5*time.Minute))
	popJWT := buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "reused-jti", time.Now())

	firstCode := createOID4VCITestAuthorizationCode(t, idp, clientID, redirectURI)
	firstResp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {firstCode.Code},
		"redirect_uri": {redirectURI},
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: popJWT,
	})
	assertStatus(t, firstResp, http.StatusOK)
	_ = firstResp.Body.Close()

	secondCode := createOID4VCITestAuthorizationCode(t, idp, clientID, redirectURI)
	secondResp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {secondCode.Code},
		"redirect_uri": {redirectURI},
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: popJWT,
	})
	assertStatus(t, secondResp, http.StatusUnauthorized)
	payload := decodeJSONMap(t, secondResp)
	if asString(t, payload["error"]) != "invalid_client" {
		t.Fatalf("expected invalid_client on jti replay, got %v", payload["error"])
	}
}

// --- OID4VCI 1.0 Appendix D Key Attestation (B3) --------------------------

func TestCredentialRequestRequiresKeyAttestationForHAIPConfiguration(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Key Attestation Test CA")
	t.Setenv("OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	holderJWK := crypto.JWKFromECPublicKey(&holderKey.PublicKey, "holder-key")

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key attestation leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Key Attestation Leaf")
	keyAttestationJWT := buildKeyAttestationJWT(t, attesterKey, attesterLeafDER, caCertDER, []crypto.JWK{holderJWK}, []string{"iso_18045_moderate"}, []string{"iso_18045_moderate"}, cNonce)

	proofJWT := createECProofJWTWithKeyAttestation(t, holderKey, holderJWK, cNonce, walletSubject, testIssuerAudience, keyAttestationJWT)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "MobileDrivingLicenceMsoMdocHAIP",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	if asString(t, credentialPayload["credential"]) == "" {
		t.Fatalf("expected mso_mdoc credential in response")
	}
}

func TestCredentialRequestRejectsMissingKeyAttestationForHAIPConfiguration(t *testing.T) {
	_, _, caCertDER := generateTestCA(t, "Key Attestation Test CA")
	t.Setenv("OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])

	// Standard RSA proof with no key_attestation header at all.
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "MobileDrivingLicenceMsoMdocHAIP",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof, got %v", payload["error"])
	}
}

func TestCredentialRequestRejectsKeyAttestationBelowRequiredLevel(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Key Attestation Test CA")
	t.Setenv("OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	holderJWK := crypto.JWKFromECPublicKey(&holderKey.PublicKey, "holder-key")

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key attestation leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Key Attestation Leaf")
	// key_storage is below the "iso_18045_moderate" the HAIP configuration requires.
	keyAttestationJWT := buildKeyAttestationJWT(t, attesterKey, attesterLeafDER, caCertDER, []crypto.JWK{holderJWK}, []string{"iso_18045_basic"}, []string{"iso_18045_moderate"}, cNonce)

	proofJWT := createECProofJWTWithKeyAttestation(t, holderKey, holderJWK, cNonce, walletSubject, testIssuerAudience, keyAttestationJWT)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "MobileDrivingLicenceMsoMdocHAIP",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof, got %v", payload["error"])
	}
	if !strings.Contains(asString(t, payload["error_description"]), "key_storage") {
		t.Fatalf("expected key_storage requirement failure, got %v", payload["error_description"])
	}
}

// --- OID4VCI 1.0 encrypted Credential Response (B5) -----------------------

func TestCredentialResponseEncryptionRoundTrip(t *testing.T) {
	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	responseKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate response encryption key: %v", err)
	}
	responseJWK := crypto.JWKFromECPublicKey(&responseKey.PublicKey, "response-key")
	responseJWK.Alg = "ECDH-ES"

	req, err := http.NewRequest(http.MethodPost, server.URL+"/oid4vci/credential", strings.NewReader(mustMarshalJSON(t, map[string]interface{}{
		"credential_configuration_id": "UniversityDegreeCredential",
		"proofs": []map[string]interface{}{
			{"proof_type": "jwt", "jwt": proofJWT},
		},
		"credential_response_encryption": map[string]interface{}{
			"jwk": responseJWK,
			"enc": "A128GCM",
		},
	})))
	if err != nil {
		t.Fatalf("build credential request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute credential request: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/jwt" {
		t.Fatalf("expected application/jwt content type for encrypted response, got %q", contentType)
	}
	defer resp.Body.Close()
	compactBuf := make([]byte, 0, 4096)
	readBuf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(readBuf)
		compactBuf = append(compactBuf, readBuf[:n]...)
		if readErr != nil {
			break
		}
	}

	jwe, err := jose.ParseEncrypted(string(compactBuf), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM, jose.A256GCM})
	if err != nil {
		t.Fatalf("parse JWE response: %v", err)
	}
	plaintext, err := jwe.Decrypt(responseKey)
	if err != nil {
		t.Fatalf("decrypt JWE response: %v", err)
	}
	var decrypted map[string]interface{}
	if err := json.Unmarshal(plaintext, &decrypted); err != nil {
		t.Fatalf("unmarshal decrypted credential response: %v", err)
	}
	if asString(t, decrypted["credential"]) == "" {
		t.Fatalf("expected credential in decrypted JWE payload")
	}
}

func TestCredentialResponseEncryptionRejectsUnsupportedEnc(t *testing.T) {
	server, _, _ := newAttestationTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	responseKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate response encryption key: %v", err)
	}
	responseJWK := crypto.JWKFromECPublicKey(&responseKey.PublicKey, "response-key")
	responseJWK.Alg = "ECDH-ES"

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": proofJWT},
			},
			"credential_response_encryption": map[string]interface{}{
				"jwk": responseJWK,
				"enc": "A192GCM",
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_encryption_parameters" {
		t.Fatalf("expected invalid_encryption_parameters, got %v", payload["error"])
	}
}

// --- test infrastructure ---------------------------------------------------

func newAttestationTestServer(t *testing.T) (*httptest.Server, *Plugin, *mockidp.MockIdP) {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new key set: %v", err)
	}
	idp := mockidp.NewMockIdP(keySet)
	testPlugin := NewPlugin()
	if err := testPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL: "http://localhost:8080",
		KeySet:  keySet,
		MockIdP: idp,
	}); err != nil {
		t.Fatalf("initialize plugin: %v", err)
	}

	router := chi.NewRouter()
	router.Route("/oid4vci", func(r chi.Router) {
		testPlugin.RegisterRoutes(r)
	})
	return httptest.NewServer(router), testPlugin, idp
}

func registerOID4VCITestClient(idp *mockidp.MockIdP, clientID string, redirectURI string) {
	idp.RegisterClient(&models.Client{
		ID:           clientID,
		Public:       true,
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"vc:issue"},
	})
}

func createOID4VCITestAuthorizationCode(t *testing.T, idp *mockidp.MockIdP, clientID string, redirectURI string) *models.AuthorizationCode {
	t.Helper()
	authCode, err := idp.CreateAuthorizationCode(clientID, "alice", redirectURI, "vc:issue", "", "", "", "", "", time.Now())
	if err != nil {
		t.Fatalf("create authorization code: %v", err)
	}
	return authCode
}

func generateTestCA(t *testing.T, commonName string) (*ecdsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}
	return caKey, cert, der
}

func issueLeafCertificate(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, leafKey *ecdsa.PrivateKey, commonName string) []byte {
	t.Helper()
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return der
}

func pemEncodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func x5cHeader(ders ...[]byte) []string {
	out := make([]string, 0, len(ders))
	for _, der := range ders {
		out = append(out, base64.StdEncoding.EncodeToString(der))
	}
	return out
}

func buildClientAttestationJWT(t *testing.T, leafKey *ecdsa.PrivateKey, leafDER []byte, caDER []byte, clientID string, cnfJWK crypto.JWK, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "https://attester.example",
		"sub": clientID,
		"exp": exp.Unix(),
		"cnf": map[string]interface{}{"jwk": cnfJWK},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = typClientAttestationJWT
	token.Header["x5c"] = x5cHeader(leafDER, caDER)
	signed, err := token.SignedString(leafKey)
	if err != nil {
		t.Fatalf("sign client attestation jwt: %v", err)
	}
	return signed
}

func buildClientAttestationPoPJWT(t *testing.T, instanceKey *ecdsa.PrivateKey, aud string, jti string, iat time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"aud": aud,
		"jti": jti,
		"iat": iat.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = typClientAttestationPoPJWT
	signed, err := token.SignedString(instanceKey)
	if err != nil {
		t.Fatalf("sign client attestation pop jwt: %v", err)
	}
	return signed
}

func buildKeyAttestationJWT(t *testing.T, leafKey *ecdsa.PrivateKey, leafDER []byte, caDER []byte, attestedKeys []crypto.JWK, keyStorage []string, userAuth []string, nonce string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iat":           time.Now().UTC().Unix(),
		"attested_keys": attestedKeys,
	}
	if len(keyStorage) > 0 {
		claims["key_storage"] = keyStorage
	}
	if len(userAuth) > 0 {
		claims["user_authentication"] = userAuth
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = typKeyAttestationJWT
	token.Header["x5c"] = x5cHeader(leafDER, caDER)
	signed, err := token.SignedString(leafKey)
	if err != nil {
		t.Fatalf("sign key attestation jwt: %v", err)
	}
	return signed
}

// createECProofJWTWithKeyAttestation builds an OID4VCI 1.0 §7 proof JWT bound
// to an EC holder key (cnf.jwk), carrying the given raw Key Attestation JWT in
// the key_attestation JOSE header (Appendix F.1).
func createECProofJWTWithKeyAttestation(t *testing.T, holderKey *ecdsa.PrivateKey, holderJWK crypto.JWK, nonce string, subject string, audience string, keyAttestationJWT string) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   subject,
		"sub":   subject,
		"aud":   audience,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   "proof-" + subject,
		"cnf": map[string]interface{}{
			"jwk": holderJWK,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["kid"] = holderJWK.Kid
	token.Header["key_attestation"] = keyAttestationJWT
	signed, err := token.SignedString(holderKey)
	if err != nil {
		t.Fatalf("sign proof jwt: %v", err)
	}
	return signed
}

func postFormWithHeaders(t *testing.T, endpoint string, values url.Values, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("build form request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute form request: %v", err)
	}
	return resp
}

func mustMarshalJSON(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return string(data)
}
