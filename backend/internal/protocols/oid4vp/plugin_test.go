package oid4vp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type combinedServer struct {
	Server *httptest.Server
	KeySet *crypto.KeySet
}

type combinedServerOptions struct {
	DataDir string
	KeySet  *crypto.KeySet
}

type walletFixture struct {
	Subject       string
	KeySet        *crypto.KeySet
	CredentialJWT string
}

const testIssuerAudience = "http://localhost:8080/oid4vci"
const testCredentialVCT = "https://protocolsoup.com/credentials/university_degree"

func TestDirectPostFlowEndToEnd(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestDirectPostJWTFlowEndToEnd(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post.jwt")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestDirectPostJWTFlowAcceptsRawJSONLDPresentation(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	holderKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new holder key set: %v", err)
	}
	holderJWK, found := holderKeySet.GetJWKByID(holderKeySet.ECKeyID())
	if !found {
		t.Fatalf("holder ec jwk is unavailable")
	}
	holderDID, err := vc.DIDJWKFromJSON(holderJWK)
	if err != nil {
		t.Fatalf("derive holder did:jwk: %v", err)
	}

	issuerKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new issuer key set: %v", err)
	}
	issuerJWK, found := issuerKeySet.GetJWKByID(issuerKeySet.ECKeyID())
	if !found {
		t.Fatalf("issuer ec jwk is unavailable")
	}
	issuerDID, err := vc.DIDJWKFromJSON(issuerJWK)
	if err != nil {
		t.Fatalf("derive issuer did:jwk: %v", err)
	}

	rawCredential := createRawLDPCredential(t, issuerKeySet, issuerJWK, issuerDID, holderDID)
	if !vc.DefaultWalletCredentialStore().Put(vc.WalletCredentialRecord{
		Subject:                   holderDID,
		Format:                    "ldp_vc",
		CredentialConfigurationID: "UniversityDegreeCredentialLDP",
		VCT:                       testCredentialVCT,
		CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
		CredentialJWT:             rawCredential,
		IssuerSignedJWT:           rawCredential,
		CredentialID:              "cred-ldp-raw",
		Issuer:                    issuerDID,
		IssuerJWK:                 issuerJWK,
		IssuedAt:                  time.Now().UTC(),
	}) {
		t.Fatalf("persist raw ldp_vc lineage failed")
	}

	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post.jwt", map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "credential_requirement",
				"format": "ldp_vc",
				"meta": map[string]interface{}{
					"type_values": []string{"UniversityDegreeCredential"},
				},
				"claims": []map[string]interface{}{
					{
						"path": []string{"degree"},
					},
				},
			},
		},
	})
	vpToken := createRawLDPPresentationToken(t, createPayload, holderKeySet, holderDID, rawCredential)
	form := url.Values{}
	form.Set("state", asVPString(createPayload["state"]))
	form.Set("response", createEncryptedResponseJWTWithEC(t, env.KeySet, createPayload, holderKeySet, holderDID, vpToken))

	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", form)
	if err != nil {
		t.Fatalf("post raw json-ld wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusOK)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestCreateAuthorizationRequestRejectsDCQLAndScopeTogether(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createResp := postVPJSON(t, env.Server.URL+"/oid4vp/request/create", map[string]interface{}{
		"response_mode": "direct_post",
		"response_uri":  env.Server.URL + "/oid4vp/response",
		"scope":         "openid",
		"dcql_query": map[string]interface{}{
			"credentials": []map[string]interface{}{
				{
					"id": "credential_query",
				},
			},
		},
	})
	assertVPStatus(t, createResp, http.StatusBadRequest)
	errorPayload := decodeVPJSONMap(t, createResp)
	if asVPString(errorPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request error")
	}
}

func TestCreateAuthorizationRequestBuildsVerifierAttestationRequestObject(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequestPayload(t, env.Server.URL, map[string]interface{}{
		"client_id_scheme": "verifier_attestation",
		"response_mode":    "direct_post",
		"response_uri":     env.Server.URL + "/oid4vp/response",
	})
	if asVPString(createPayload["client_id_scheme"]) != "verifier_attestation" {
		t.Fatalf("expected verifier_attestation client_id_scheme, got %q", asVPString(createPayload["client_id_scheme"]))
	}

	requestJWT := asVPString(createPayload["request"])
	decodedRequest, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}
	attestationJWT := asVPString(decodedRequest.Header["jwt"])
	if attestationJWT == "" {
		t.Fatalf("expected verifier attestation jwt in request JOSE header")
	}

	decodedAttestation, err := crypto.DecodeTokenWithoutValidation(attestationJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(attestation): %v", err)
	}
	if asVPString(decodedAttestation.Header["typ"]) != "verifier-attestation+jwt" {
		t.Fatalf("unexpected verifier attestation typ %q", asVPString(decodedAttestation.Header["typ"]))
	}
	expectedIssuer := env.Server.URL + "/oid4vp/verifier-attestation"
	if asVPString(decodedAttestation.Payload["iss"]) != expectedIssuer {
		t.Fatalf("unexpected verifier attestation issuer %q", asVPString(decodedAttestation.Payload["iss"]))
	}
	expectedClientSubject := stripClientIDSchemePrefixValue(asVPString(createPayload["client_id"]), ClientIDSchemeVerifierAttestation)
	if asVPString(decodedAttestation.Payload["sub"]) != expectedClientSubject {
		t.Fatalf("unexpected verifier attestation sub %q", asVPString(decodedAttestation.Payload["sub"]))
	}
	redirectURIs, ok := decodedAttestation.Payload["redirect_uris"].([]interface{})
	if !ok || len(redirectURIs) != 1 || asVPString(redirectURIs[0]) != env.Server.URL+"/oid4vp/response" {
		t.Fatalf("unexpected redirect_uris claim %v", decodedAttestation.Payload["redirect_uris"])
	}

	metadataResp, err := http.Get(expectedIssuer + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("fetch verifier attestation metadata: %v", err)
	}
	assertVPStatus(t, metadataResp, http.StatusOK)
	metadataPayload := decodeVPJSONMap(t, metadataResp)

	jwksResp, err := http.Get(asVPString(metadataPayload["jwks_uri"]))
	if err != nil {
		t.Fatalf("fetch verifier attestation jwks: %v", err)
	}
	assertVPStatus(t, jwksResp, http.StatusOK)
	defer jwksResp.Body.Close()

	var issuerJWKS crypto.JWKS
	if err := json.NewDecoder(jwksResp.Body).Decode(&issuerJWKS); err != nil {
		t.Fatalf("decode verifier attestation jwks: %v", err)
	}
	issuerJWK, err := issuerJWKS.GetKeyByID(asVPString(decodedAttestation.Header["kid"]))
	if err != nil {
		t.Fatalf("GetKeyByID(attestation kid): %v", err)
	}
	issuerPublicKey, err := issuerJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey(attestation jwk): %v", err)
	}
	if verified, err := crypto.VerifySignatureWithKey(attestationJWT, issuerPublicKey); err != nil || !verified {
		t.Fatalf("VerifySignatureWithKey(attestation): verified=%v err=%v", verified, err)
	}

	cnf, ok := decodedAttestation.Payload["cnf"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected cnf claim")
	}
	requestSignerJWK := jwkFromVPValue(t, cnf["jwk"])
	requestSignerPublicKey, err := requestSignerJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey(request signer jwk): %v", err)
	}
	if verified, err := crypto.VerifySignatureWithKey(requestJWT, requestSignerPublicKey); err != nil || !verified {
		t.Fatalf("VerifySignatureWithKey(request): verified=%v err=%v", verified, err)
	}
}

func TestCreateAuthorizationRequestBuildsVerifierAttestationRequestObjectWithConfiguredIssuerKey(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	t.Setenv(verifierAttestationPrivateKeyEnv, encodeECDSAPrivateKeyPEM(t, issuerKey))

	expectedIssuerJWK := crypto.JWKFromECPublicKey(&issuerKey.PublicKey, "")
	expectedIssuerJWK.Kid = expectedIssuerJWK.Thumbprint()

	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequestPayload(t, env.Server.URL, map[string]interface{}{
		"client_id_scheme": "verifier_attestation",
		"response_mode":    "direct_post",
		"response_uri":     env.Server.URL + "/oid4vp/response",
	})

	requestJWT := asVPString(createPayload["request"])
	decodedRequest, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}
	attestationJWT := asVPString(decodedRequest.Header["jwt"])
	if attestationJWT == "" {
		t.Fatalf("expected verifier attestation jwt in request JOSE header")
	}
	decodedAttestation, err := crypto.DecodeTokenWithoutValidation(attestationJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(attestation): %v", err)
	}
	if asVPString(decodedAttestation.Header["kid"]) != expectedIssuerJWK.Kid {
		t.Fatalf("unexpected verifier attestation kid %q", asVPString(decodedAttestation.Header["kid"]))
	}

	metadataResp, err := http.Get(env.Server.URL + "/oid4vp/verifier-attestation/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("fetch verifier attestation metadata: %v", err)
	}
	assertVPStatus(t, metadataResp, http.StatusOK)
	metadataPayload := decodeVPJSONMap(t, metadataResp)

	jwksResp, err := http.Get(asVPString(metadataPayload["jwks_uri"]))
	if err != nil {
		t.Fatalf("fetch verifier attestation jwks: %v", err)
	}
	assertVPStatus(t, jwksResp, http.StatusOK)
	defer jwksResp.Body.Close()

	var issuerJWKS crypto.JWKS
	if err := json.NewDecoder(jwksResp.Body).Decode(&issuerJWKS); err != nil {
		t.Fatalf("decode verifier attestation jwks: %v", err)
	}
	issuerJWK, err := issuerJWKS.GetKeyByID(expectedIssuerJWK.Kid)
	if err != nil {
		t.Fatalf("GetKeyByID(expected kid): %v", err)
	}
	if issuerJWK.Thumbprint() != expectedIssuerJWK.Thumbprint() {
		t.Fatalf("unexpected configured verifier attestation jwk thumbprint %q", issuerJWK.Thumbprint())
	}
	issuerPublicKey, err := issuerJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey(configured issuer jwk): %v", err)
	}
	if verified, err := crypto.VerifySignatureWithKey(attestationJWT, issuerPublicKey); err != nil || !verified {
		t.Fatalf("VerifySignatureWithKey(attestation): verified=%v err=%v", verified, err)
	}
}

func TestCreateAuthorizationRequestBuildsX509SANDNSRequestObject(t *testing.T) {
	verifierKey, certificateChain := createECDSACertificateChain(t, []string{"verifier.example"}, "Verifier Certificate")
	t.Setenv(x509SANDNSClientIDEnv, "x509_san_dns:verifier.example")
	t.Setenv(x509SANDNSCertificateChainPEMEnv, encodeCertificateChainPEM(certificateChain))
	t.Setenv(x509SANDNSPrivateKeyPEMEnv, encodeECDSAPrivateKeyPEM(t, verifierKey))

	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequestPayload(t, env.Server.URL, map[string]interface{}{
		"client_id_scheme": "x509_san_dns",
		"response_mode":    "direct_post",
		"response_uri":     "https://verifier.example/oid4vp/response",
	})
	if asVPString(createPayload["client_id"]) != "x509_san_dns:verifier.example" {
		t.Fatalf("unexpected x509_san_dns client_id %q", asVPString(createPayload["client_id"]))
	}

	requestJWT := asVPString(createPayload["request"])
	decodedRequest, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}
	if _, ok := decodedRequest.Header["x5c"].([]interface{}); !ok {
		t.Fatalf("expected x5c header, got %T", decodedRequest.Header["x5c"])
	}
	certificates, err := crypto.ParseX5CCertificateChain(decodedRequest.Header["x5c"])
	if err != nil {
		t.Fatalf("ParseX5CCertificateChain: %v", err)
	}
	leaf, err := crypto.ValidateCertificateChain(certificates, time.Now().UTC())
	if err != nil {
		t.Fatalf("ValidateCertificateChain: %v", err)
	}
	if err := leaf.VerifyHostname("verifier.example"); err != nil {
		t.Fatalf("VerifyHostname(verifier.example): %v", err)
	}
	if verified, err := crypto.VerifySignatureWithKey(requestJWT, verifierKey.Public()); err != nil || !verified {
		t.Fatalf("VerifySignatureWithKey(request): verified=%v err=%v", verified, err)
	}
}

func TestGenerateEphemeralX509Chain(t *testing.T) {
	certificates, leafKey, err := generateEphemeralX509Chain("verifier.example")
	if err != nil {
		t.Fatalf("generateEphemeralX509Chain: %v", err)
	}
	if len(certificates) != 2 {
		t.Fatalf("expected 2-cert chain (leaf + CA), got %d", len(certificates))
	}

	leaf := certificates[0]
	if leaf.Subject.CommonName != "verifier.example" {
		t.Fatalf("expected leaf CN=verifier.example, got %q", leaf.Subject.CommonName)
	}
	if err := leaf.VerifyHostname("verifier.example"); err != nil {
		t.Fatalf("VerifyHostname(verifier.example): %v", err)
	}
	if leaf.IsCA {
		t.Fatalf("leaf certificate must not be a CA")
	}

	caCert := certificates[1]
	if caCert.Subject.CommonName != "ProtocolSoup Ephemeral CA" {
		t.Fatalf("expected CA CN=ProtocolSoup Ephemeral CA, got %q", caCert.Subject.CommonName)
	}
	if !caCert.IsCA {
		t.Fatalf("root certificate must be a CA")
	}
	if caCert.CheckSignatureFrom(caCert) != nil {
		t.Fatalf("expected self-signed CA certificate")
	}

	validatedLeaf, err := crypto.ValidateCertificateChain(certificates, time.Now().UTC())
	if err != nil {
		t.Fatalf("ValidateCertificateChain: %v", err)
	}
	if validatedLeaf.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatalf("validated leaf serial mismatch")
	}

	if err := verifyPrivateKeyMatchesCertificate(leaf, leafKey); err != nil {
		t.Fatalf("private key does not match leaf: %v", err)
	}
}

func TestCreateAuthorizationRequestBuildsX509SANDNSEphemeralChain(t *testing.T) {
	certificates, leafKey, err := generateEphemeralX509Chain("verifier.example")
	if err != nil {
		t.Fatalf("generateEphemeralX509Chain: %v", err)
	}
	t.Setenv(x509SANDNSClientIDEnv, "x509_san_dns:verifier.example")
	t.Setenv(x509SANDNSCertificateChainPEMEnv, encodeCertificateChainPEM(marshalCertificateChainDER(certificates)))
	t.Setenv(x509SANDNSPrivateKeyPEMEnv, encodeECDSAPrivateKeyPEM(t, leafKey))

	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequestPayload(t, env.Server.URL, map[string]interface{}{
		"client_id_scheme": "x509_san_dns",
		"response_mode":    "direct_post",
		"response_uri":     "https://verifier.example/oid4vp/response",
	})
	clientID := asVPString(createPayload["client_id"])
	if clientID != "x509_san_dns:verifier.example" {
		t.Fatalf("unexpected x509_san_dns client_id %q", clientID)
	}

	requestJWT := asVPString(createPayload["request"])
	decodedRequest, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}
	rawX5C, ok := decodedRequest.Header["x5c"].([]interface{})
	if !ok || len(rawX5C) != 2 {
		t.Fatalf("expected x5c header with 2 certificates, got %v", decodedRequest.Header["x5c"])
	}

	parsedCerts, err := crypto.ParseX5CCertificateChain(decodedRequest.Header["x5c"])
	if err != nil {
		t.Fatalf("ParseX5CCertificateChain: %v", err)
	}
	leaf, err := crypto.ValidateCertificateChain(parsedCerts, time.Now().UTC())
	if err != nil {
		t.Fatalf("ValidateCertificateChain: %v", err)
	}
	if err := leaf.VerifyHostname("verifier.example"); err != nil {
		t.Fatalf("VerifyHostname(verifier.example): %v", err)
	}

	clientIDScheme := asVPString(decodedRequest.Payload["client_id_scheme"])
	if clientIDScheme != "x509_san_dns" {
		t.Fatalf("expected client_id_scheme=x509_san_dns in JWT claims, got %q", clientIDScheme)
	}
}

func marshalCertificateChainDER(certs []*x509.Certificate) [][]byte {
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return chain
}

func TestDirectPostPolicyDenialForNonceMismatch(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "invalid-nonce")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	resultObj := resultPayload["result"].(map[string]interface{})
	policyObj := resultObj["policy"].(map[string]interface{})
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasons, _ := policyObj["reasons"].([]interface{})
	if !containsVPReason(reasons, "nonce mismatch") {
		t.Fatalf("expected nonce mismatch reason, got %v", reasons)
	}
}

func TestDirectPostPolicyDenialForNonceFromDifferentRequest(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	requestA := createVPRequest(t, env.Server.URL, "direct_post")
	requestB := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, requestA, wallet, asVPString(requestB["nonce"]))

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(requestA["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "nonce_mismatch") {
		t.Fatalf("expected nonce_mismatch reason code, got %v", reasonCodes)
	}
}

func TestDirectPostPolicyDenialForExpiredVPToken(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	expiredVPToken := createVPTokenWithExpiry(t, createPayload, wallet, time.Now().UTC().Add(-1*time.Minute))

	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"vp_token": {expiredVPToken},
	})
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusOK)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "vp_token_expired") {
		t.Fatalf("expected vp_token_expired reason code, got %v", reasonCodes)
	}
}

func TestWalletResponseRejectsReplayAfterCompletion(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	replayToken := createVPToken(t, createPayload, wallet, "")
	replayResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"vp_token": {replayToken},
	})
	if err != nil {
		t.Fatalf("post replay wallet response failed: %v", err)
	}
	assertVPStatus(t, replayResp, http.StatusBadRequest)
	replayPayload := decodeVPJSONMap(t, replayResp)
	if asVPString(replayPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request, got %v", replayPayload["error"])
	}
	if !strings.Contains(strings.ToLower(asVPString(replayPayload["error_description"])), "already completed") {
		t.Fatalf("expected replay error_description to mention completion, got %v", replayPayload["error_description"])
	}
}

func TestDirectPostPolicyAllowsSelectiveDisclosureSubsetForMatchingDCQL(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	degreeOnlyCredential := filterCredentialDisclosures(t, wallet.CredentialJWT, []string{"degree"})
	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id": "degree_only",
				"meta": map[string]interface{}{
					"vct_values": []string{testCredentialVCT},
				},
				"claims": []map[string]interface{}{
					{
						"path": []string{"degree"},
					},
				},
			},
		},
	})

	wallet.CredentialJWT = degreeOnlyCredential
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)

	resultObj := extractVPResult(t, resultPayload)
	credentialEvidence, ok := resultObj["credential_evidence"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credential evidence in verification result")
	}
	disclosedClaims, _ := credentialEvidence["disclosed_claims"].(map[string]interface{})
	if _, exists := disclosedClaims["degree"]; !exists {
		t.Fatalf("expected degree in disclosed_claims, got %v", disclosedClaims)
	}
	if _, exists := disclosedClaims["graduation_year"]; exists {
		t.Fatalf("expected graduation_year to remain undisclosed, got %v", disclosedClaims)
	}
}

func TestDirectPostPolicyDeniesMissingRequiredDisclosureClaim(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	wallet.CredentialJWT = filterCredentialDisclosures(t, wallet.CredentialJWT, []string{"degree"})
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "missing_required_claim") {
		t.Fatalf("expected missing_required_claim reason code, got %v", reasonCodes)
	}
}

func TestDirectPostPolicyDeniesDCQLFormatMismatch(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "university_degree_jwt",
				"format": "jwt_vc_json",
				"meta": map[string]interface{}{
					"vct_values": []string{testCredentialVCT},
				},
				"claims": []map[string]interface{}{
					{
						"path": []string{"degree"},
					},
				},
			},
		},
	})
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "dcql_format_mismatch") {
		t.Fatalf("expected dcql_format_mismatch reason code, got %v", reasonCodes)
	}
}

func TestDirectPostPolicyAllowsDCQLAcrossSupportedFormats(t *testing.T) {
	testCases := []struct {
		name                      string
		credentialConfigurationID string
		format                    string
		meta                      map[string]interface{}
		claims                    []map[string]interface{}
	}{
		{
			name:                      "dc-sd-jwt",
			credentialConfigurationID: "UniversityDegreeCredential",
			format:                    "dc+sd-jwt",
			meta: map[string]interface{}{
				"vct_values": []string{testCredentialVCT},
			},
			claims: []map[string]interface{}{
				{
					"path": []string{"degree"},
				},
			},
		},
		{
			name:                      "jwt-vc-json",
			credentialConfigurationID: "UniversityDegreeCredentialJWT",
			format:                    "jwt_vc_json",
			meta: map[string]interface{}{
				"type_values": []string{"UniversityDegreeCredential"},
			},
			claims: []map[string]interface{}{
				{
					"path": []string{"degree"},
				},
			},
		},
		{
			name:                      "jwt-vc-json-ld",
			credentialConfigurationID: "UniversityDegreeCredentialJWTLD",
			format:                    "jwt_vc_json-ld",
			meta: map[string]interface{}{
				"type_values": []string{"UniversityDegreeCredential"},
			},
			claims: []map[string]interface{}{
				{
					"path": []string{"degree"},
				},
			},
		},
		{
			name:                      "ldp-vc",
			credentialConfigurationID: "UniversityDegreeCredentialLDP",
			format:                    "ldp_vc",
			meta: map[string]interface{}{
				"type_values": []string{"UniversityDegreeCredential"},
			},
			claims: []map[string]interface{}{
				{
					"path": []string{"degree"},
				},
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			env := newCombinedVCServer(t)
			defer env.Server.Close()

			wallet := issueCredentialForWalletWithSelection(
				t,
				env.Server.URL,
				"alice-"+strings.ReplaceAll(testCase.name, "_", "-"),
				testCase.credentialConfigurationID,
				testCase.format,
			)

			credentialRequirement := map[string]interface{}{
				"id":     "credential_requirement",
				"format": testCase.format,
			}
			if len(testCase.meta) > 0 {
				credentialRequirement["meta"] = testCase.meta
			}
			if len(testCase.claims) > 0 {
				credentialRequirement["claims"] = testCase.claims
			}
			createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", map[string]interface{}{
				"credentials": []map[string]interface{}{credentialRequirement},
			})
			postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

			resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
			assertPolicyAllowed(t, resultPayload)
		})
	}
}

func TestDirectPostPolicyDeniesMissingLineageWithExplicitCode(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	wallet.CredentialJWT = createUntrackedCredentialJWT(t, wallet)
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "missing_lineage") {
		t.Fatalf("expected missing_lineage reason code, got %v", reasonCodes)
	}
}

func TestDirectPostFlowSurvivesVerifierRestartWithPersistentState(t *testing.T) {
	dataDir := t.TempDir()
	env1 := newCombinedVCServerWithOptions(t, combinedServerOptions{
		DataDir: dataDir,
	})
	wallet := issueCredentialForWallet(t, env1.Server.URL, "alice")
	createPayload := createVPRequest(t, env1.Server.URL, "direct_post")
	env1.Server.Close()

	env2 := newCombinedVCServerWithOptions(t, combinedServerOptions{
		DataDir: dataDir,
	})
	defer env2.Server.Close()

	postWalletResponse(t, env2.Server.URL, env2.KeySet, createPayload, wallet, "")
	resultPayload := fetchVerificationResult(t, env2.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestDirectPostJWTRejectsInvalidEncryptedResponse(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post.jwt")
	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"response": {"invalid-jwe-response"},
	})
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusBadRequest)
	errorPayload := decodeVPJSONMap(t, formResp)
	if asVPString(errorPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request error")
	}
}

func TestWalletResponseRejectsUnknownState(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"state":    {"unknown-state"},
		"vp_token": {"placeholder-token"},
	})
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusBadRequest)
	errorPayload := decodeVPJSONMap(t, formResp)
	if asVPString(errorPayload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request error")
	}
}

func TestExternalInteropConformance(t *testing.T) {
	if strings.TrimSpace(os.Getenv("RUN_EXTERNAL_INTEROP_CONFORMANCE")) != "1" {
		t.Skip("set RUN_EXTERNAL_INTEROP_CONFORMANCE=1 to execute external interop conformance")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("CONFORMANCE_BASE_URL")), "/")
	walletSubmitURL := strings.TrimSpace(os.Getenv("CONFORMANCE_EXTERNAL_WALLET_SUBMIT_URL"))
	if baseURL == "" || walletSubmitURL == "" {
		t.Skip("external interop requires CONFORMANCE_BASE_URL and CONFORMANCE_EXTERNAL_WALLET_SUBMIT_URL")
	}

	walletUserID := strings.TrimSpace(os.Getenv("CONFORMANCE_WALLET_USER_ID"))
	if walletUserID == "" {
		walletUserID = "alice"
	}

	wallet := issueCredentialForExternalWallet(t, baseURL, walletUserID)
	runExternalWalletFlow(t, baseURL, walletSubmitURL, wallet, "direct_post")
	runExternalWalletFlow(t, baseURL, walletSubmitURL, wallet, "direct_post.jwt")
}

func createVPRequest(t *testing.T, serverURL string, responseMode string) map[string]interface{} {
	t.Helper()
	return createVPRequestPayload(t, serverURL, map[string]interface{}{
		"response_mode": responseMode,
		"response_uri":  serverURL + "/oid4vp/response",
	})
}

func createVPRequestWithDCQL(
	t *testing.T,
	serverURL string,
	responseMode string,
	dcqlQuery map[string]interface{},
) map[string]interface{} {
	t.Helper()
	return createVPRequestPayload(t, serverURL, map[string]interface{}{
		"response_mode": responseMode,
		"response_uri":  serverURL + "/oid4vp/response",
		"dcql_query":    dcqlQuery,
	})
}

func createVPRequestPayload(t *testing.T, serverURL string, payload map[string]interface{}) map[string]interface{} {
	t.Helper()
	createResp := postVPJSON(t, serverURL+"/oid4vp/request/create", payload)
	assertVPStatus(t, createResp, http.StatusCreated)
	createPayload := decodeVPJSONMap(t, createResp)
	if asVPString(createPayload["request_id"]) == "" {
		t.Fatalf("expected request_id")
	}
	return createPayload
}

func issueCredentialForExternalWallet(t *testing.T, baseURL string, walletUserID string) *walletFixture {
	t.Helper()

	metadataResp, err := http.Get(baseURL + "/.well-known/openid-credential-issuer/oid4vci")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertVPStatus(t, metadataResp, http.StatusOK)
	metadataPayload := decodeVPJSONMap(t, metadataResp)
	issuerID := asVPString(metadataPayload["credential_issuer"])
	if issuerID == "" {
		t.Fatalf("metadata missing credential_issuer")
	}

	offerResp := postVPJSON(t, baseURL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id": walletUserID,
	})
	assertVPStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeVPJSONMap(t, offerResp)
	walletSubject := asVPString(offerPayload["wallet_subject"])
	if walletSubject == "" {
		t.Fatalf("offer response missing wallet_subject")
	}

	tokenResp, err := http.PostForm(baseURL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asVPString(offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertVPStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeVPJSONMap(t, tokenResp)

	walletKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new wallet key set: %v", err)
	}
	proofJWT := createProofJWT(t, walletKeySet, walletSubject, asVPString(tokenPayload["c_nonce"]), issuerID)

	credentialResp := postVPJSONWithHeaders(
		t,
		baseURL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{
					"proof_type": "jwt",
					"jwt":        proofJWT,
				},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + asVPString(tokenPayload["access_token"]),
		},
	)
	assertVPStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeVPJSONMap(t, credentialResp)
	credentialJWT := asVPString(credentialPayload["credential"])
	if credentialJWT == "" {
		t.Fatalf("credential response missing credential")
	}

	return &walletFixture{
		Subject:       walletSubject,
		KeySet:        walletKeySet,
		CredentialJWT: credentialJWT,
	}
}

func issueCredentialForWallet(t *testing.T, serverURL string, walletUserID string) *walletFixture {
	return issueCredentialForWalletWithSelection(t, serverURL, walletUserID, "UniversityDegreeCredential", "")
}

func issueCredentialForWalletWithSelection(
	t *testing.T,
	serverURL string,
	walletUserID string,
	credentialConfigurationID string,
	credentialFormat string,
) *walletFixture {
	t.Helper()

	credentialConfigurationID = strings.TrimSpace(credentialConfigurationID)
	if credentialConfigurationID == "" {
		credentialConfigurationID = "UniversityDegreeCredential"
	}
	credentialFormat = strings.TrimSpace(credentialFormat)

	offerRequestPayload := map[string]interface{}{
		"wallet_user_id": walletUserID,
	}
	if credentialConfigurationID != "" {
		offerRequestPayload["credential_configuration_ids"] = []string{credentialConfigurationID}
	}
	offerResp := postVPJSON(t, serverURL+"/oid4vci/offers/pre-authorized", offerRequestPayload)
	assertVPStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeVPJSONMap(t, offerResp)
	walletSubject := asVPString(offerPayload["wallet_subject"])
	if walletSubject == "" {
		t.Fatalf("offer response missing wallet_subject")
	}

	tokenResp, err := http.PostForm(serverURL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asVPString(offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertVPStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeVPJSONMap(t, tokenResp)

	walletKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new wallet key set: %v", err)
	}
	proofJWT := createProofJWT(t, walletKeySet, walletSubject, asVPString(tokenPayload["c_nonce"]), testIssuerAudience)

	credentialResp := postVPJSONWithHeaders(
		t,
		serverURL+"/oid4vci/credential",
		func() map[string]interface{} {
			payload := map[string]interface{}{
				"credential_configuration_id": credentialConfigurationID,
				"proofs": []map[string]interface{}{
					{
						"proof_type": "jwt",
						"jwt":        proofJWT,
					},
				},
			}
			if credentialFormat != "" {
				payload["format"] = credentialFormat
			}
			return payload
		}(),
		map[string]string{
			"Authorization": "Bearer " + asVPString(tokenPayload["access_token"]),
		},
	)
	assertVPStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeVPJSONMap(t, credentialResp)
	credentialJWT := asVPString(credentialPayload["credential"])
	if credentialJWT == "" {
		t.Fatalf("credential response missing credential")
	}

	return &walletFixture{
		Subject:       walletSubject,
		KeySet:        walletKeySet,
		CredentialJWT: credentialJWT,
	}
}

func runExternalWalletFlow(
	t *testing.T,
	baseURL string,
	externalWalletSubmitURL string,
	wallet *walletFixture,
	responseMode string,
) {
	t.Helper()

	createPayload := createVPRequest(t, baseURL, responseMode)
	requestID := asVPString(createPayload["request_id"])
	if requestID == "" {
		t.Fatalf("request response missing request_id")
	}

	submitResp := postVPJSON(t, externalWalletSubmitURL, map[string]interface{}{
		"request_id":     requestID,
		"request_uri":    asVPString(createPayload["request_uri"]),
		"request":        asVPString(createPayload["request"]),
		"response_mode":  responseMode,
		"response_uri":   asVPString(createPayload["response_uri"]),
		"state":          asVPString(createPayload["state"]),
		"nonce":          asVPString(createPayload["nonce"]),
		"client_id":      asVPString(createPayload["client_id"]),
		"wallet_subject": wallet.Subject,
		"credential_jwt": wallet.CredentialJWT,
	})
	if submitResp.StatusCode < http.StatusOK || submitResp.StatusCode >= http.StatusMultipleChoices {
		payload := decodeVPJSONMap(t, submitResp)
		t.Fatalf("external wallet submit expected 2xx, got %d with payload %v", submitResp.StatusCode, payload)
	}
	_ = submitResp.Body.Close()

	resultPayload := fetchVerificationResultWithTimeout(t, baseURL, requestID, 45*time.Second)
	assertPolicyAllowed(t, resultPayload)
}

func createProofJWT(t *testing.T, keySet *crypto.KeySet, subject string, nonce string, audience string) string {
	t.Helper()
	pubJWK, found := keySet.GetJWKByID(keySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet rsa jwk is unavailable")
	}
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
			"jwk": pubJWK,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["kid"] = keySet.RSAKeyID()
	signed, err := token.SignedString(keySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign proof jwt: %v", err)
	}
	return signed
}

func postWalletResponse(
	t *testing.T,
	serverURL string,
	verifierKeySet *crypto.KeySet,
	createPayload map[string]interface{},
	wallet *walletFixture,
	nonceOverride string,
) {
	t.Helper()
	vpToken := createVPToken(t, createPayload, wallet, nonceOverride)
	state := asVPString(createPayload["state"])
	responseMode := asVPString(createPayload["response_mode"])

	form := url.Values{}
	form.Set("state", state)
	if responseMode == "direct_post.jwt" {
		encryptedResponse := createEncryptedResponseJWT(t, verifierKeySet, createPayload, wallet, vpToken)
		form.Set("response", encryptedResponse)
	} else {
		form.Set("vp_token", vpToken)
	}
	formResp, err := http.PostForm(serverURL+"/oid4vp/response", form)
	if err != nil {
		t.Fatalf("post wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusOK)
}

func createVPToken(t *testing.T, createPayload map[string]interface{}, wallet *walletFixture, nonceOverride string) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet public jwk is unavailable")
	}
	nonce := asVPString(createPayload["nonce"])
	if strings.TrimSpace(nonceOverride) != "" {
		nonce = strings.TrimSpace(nonceOverride)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   wallet.Subject,
		"sub":   wallet.Subject,
		"aud":   asVPString(createPayload["client_id"]),
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"jti":   "vp-" + wallet.Subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
		"vp": map[string]interface{}{
			"credential_jwt": wallet.CredentialJWT,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	signed, err := token.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign vp token: %v", err)
	}
	return signed
}

func createVPTokenWithExpiry(
	t *testing.T,
	createPayload map[string]interface{},
	wallet *walletFixture,
	expiry time.Time,
) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet public jwk is unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   wallet.Subject,
		"sub":   wallet.Subject,
		"aud":   asVPString(createPayload["client_id"]),
		"nonce": asVPString(createPayload["nonce"]),
		"iat":   now.Add(-2 * time.Minute).Unix(),
		"exp":   expiry.Unix(),
		"jti":   "vp-expired-" + wallet.Subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
		"vp": map[string]interface{}{
			"credential_jwt": wallet.CredentialJWT,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vp+jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	signed, err := token.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign vp token: %v", err)
	}
	return signed
}

func createEncryptedResponseJWT(
	t *testing.T,
	verifierKeySet *crypto.KeySet,
	createPayload map[string]interface{},
	wallet *walletFixture,
	vpToken string,
) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet public jwk is unavailable")
	}
	now := time.Now().UTC()
	innerClaims := jwt.MapClaims{
		"iss":      wallet.Subject,
		"sub":      wallet.Subject,
		"aud":      asVPString(createPayload["response_uri"]),
		"state":    asVPString(createPayload["state"]),
		"vp_token": vpToken,
		"iat":      now.Unix(),
		"exp":      now.Add(3 * time.Minute).Unix(),
		"jti":      "resp-" + wallet.Subject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
	}
	innerToken := jwt.NewWithClaims(jwt.SigningMethodRS256, innerClaims)
	innerToken.Header["typ"] = "oauth-authz-resp+jwt"
	innerToken.Header["kid"] = wallet.KeySet.RSAKeyID()
	signedInner, err := innerToken.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign response jwt: %v", err)
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       verifierKeySet.RSAPublicKey(),
		},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		t.Fatalf("create encrypter: %v", err)
	}
	object, err := encrypter.Encrypt([]byte(signedInner))
	if err != nil {
		t.Fatalf("encrypt response jwt: %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize jwe: %v", err)
	}
	return serialized
}

func createEncryptedResponseJWTWithEC(
	t *testing.T,
	verifierKeySet *crypto.KeySet,
	createPayload map[string]interface{},
	walletKeySet *crypto.KeySet,
	walletSubject string,
	vpToken string,
) string {
	t.Helper()
	pubJWK, found := walletKeySet.GetJWKByID(walletKeySet.ECKeyID())
	if !found {
		t.Fatalf("wallet ec jwk is unavailable")
	}
	now := time.Now().UTC()
	innerClaims := jwt.MapClaims{
		"iss":      walletSubject,
		"sub":      walletSubject,
		"aud":      asVPString(createPayload["response_uri"]),
		"state":    asVPString(createPayload["state"]),
		"vp_token": vpToken,
		"iat":      now.Unix(),
		"exp":      now.Add(3 * time.Minute).Unix(),
		"jti":      "resp-ec-" + walletSubject,
		"cnf": map[string]interface{}{
			"jwk": pubJWK,
			"jkt": pubJWK.Thumbprint(),
		},
	}
	innerToken := jwt.NewWithClaims(jwt.SigningMethodES256, innerClaims)
	innerToken.Header["typ"] = "oauth-authz-resp+jwt"
	innerToken.Header["kid"] = walletKeySet.ECKeyID()
	signedInner, err := innerToken.SignedString(walletKeySet.ECPrivateKey())
	if err != nil {
		t.Fatalf("sign ec response jwt: %v", err)
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       verifierKeySet.RSAPublicKey(),
		},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		t.Fatalf("create encrypter: %v", err)
	}
	object, err := encrypter.Encrypt([]byte(signedInner))
	if err != nil {
		t.Fatalf("encrypt ec response jwt: %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize jwe: %v", err)
	}
	return serialized
}

func createRawLDPCredential(
	t *testing.T,
	issuerKeySet *crypto.KeySet,
	issuerJWK crypto.JWK,
	issuerDID string,
	holderDID string,
) string {
	t.Helper()
	credential, err := vc.SecureDataIntegrityDocument(
		map[string]interface{}{
			"@context":       []string{"https://www.w3.org/2018/credentials/v1"},
			"id":             "urn:uuid:raw-ldp-vc",
			"type":           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"issuer":         issuerDID,
			"issuanceDate":   time.Now().UTC().Format(time.RFC3339),
			"expirationDate": time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339),
			"credentialSubject": map[string]interface{}{
				"id":         holderDID,
				"degree":     "BSc",
				"given_name": "Alice",
			},
			"vct": testCredentialVCT,
		},
		map[string]interface{}{
			"created":            time.Now().UTC().Format(time.RFC3339),
			"proofPurpose":       "assertionMethod",
			"verificationMethod": vc.DefaultVerificationMethodID(issuerDID),
		},
		issuerJWK,
		func(data []byte) ([]byte, error) {
			return signECDSAProofBytes(issuerKeySet.ECPrivateKey(), data)
		},
	)
	if err != nil {
		t.Fatalf("secure raw ldp credential: %v", err)
	}
	serialized, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("marshal raw ldp credential: %v", err)
	}
	return string(serialized)
}

func createRawLDPPresentationToken(
	t *testing.T,
	createPayload map[string]interface{},
	holderKeySet *crypto.KeySet,
	holderDID string,
	rawCredential string,
) string {
	t.Helper()
	holderJWK, found := holderKeySet.GetJWKByID(holderKeySet.ECKeyID())
	if !found {
		t.Fatalf("holder ec jwk is unavailable")
	}
	format, ok := vc.DefaultCredentialFormatRegistry().Lookup("ldp_vc")
	if !ok {
		t.Fatalf("ldp_vc format handler is unavailable")
	}
	result, err := format.BuildPresentation(vc.PresentationBuildInput{
		Credential:               rawCredential,
		Holder:                   holderDID,
		HolderPublicJWK:          holderJWK,
		HolderVerificationMethod: vc.DefaultVerificationMethodID(holderDID),
		Audience:                 asVPString(createPayload["client_id"]),
		Nonce:                    asVPString(createPayload["nonce"]),
		ProofSigner: func(data []byte) ([]byte, error) {
			return signECDSAProofBytes(holderKeySet.ECPrivateKey(), data)
		},
	})
	if err != nil {
		t.Fatalf("build raw ldp presentation: %v", err)
	}
	return result.VPToken
}

func signECDSAProofBytes(privateKey interface{}, data []byte) ([]byte, error) {
	key, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", privateKey)
	}
	digest := sha256.Sum256(data)
	rValue, sValue, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	componentSize := 32
	signature := make([]byte, componentSize*2)
	rBytes := rValue.Bytes()
	sBytes := sValue.Bytes()
	copy(signature[componentSize-len(rBytes):componentSize], rBytes)
	copy(signature[len(signature)-len(sBytes):], sBytes)
	return signature, nil
}

func filterCredentialDisclosures(t *testing.T, credentialJWT string, requestedClaims []string) string {
	t.Helper()
	envelope, err := vc.ParseSDJWTEnvelope(credentialJWT)
	if err != nil {
		t.Fatalf("parse sd-jwt envelope: %v", err)
	}
	if len(envelope.Disclosures) == 0 {
		t.Fatalf("expected sd-jwt disclosures in issued credential")
	}
	allow := make(map[string]struct{}, len(requestedClaims))
	for _, claim := range requestedClaims {
		normalized := strings.TrimSpace(claim)
		if normalized == "" {
			continue
		}
		allow[normalized] = struct{}{}
	}
	selected := make([]string, 0, len(envelope.Disclosures))
	for _, encodedDisclosure := range envelope.Disclosures {
		disclosure, err := vc.DecodeSDJWTDisclosure(encodedDisclosure)
		if err != nil {
			t.Fatalf("decode disclosure: %v", err)
		}
		if len(allow) == 0 {
			selected = append(selected, disclosure.Encoded)
			continue
		}
		if _, ok := allow[strings.TrimSpace(disclosure.ClaimName)]; ok {
			selected = append(selected, disclosure.Encoded)
		}
	}
	return vc.BuildSDJWTSerialization(envelope.IssuerSignedJWT, selected, envelope.KeyBindingJWT)
}

func createUntrackedCredentialJWT(t *testing.T, wallet *walletFixture) string {
	t.Helper()
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": "https://example.org/untracked-issuer",
		"sub": wallet.Subject,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"jti": "untracked-" + wallet.Subject,
		"vct": "https://protocolsoup.com/credentials/untracked",
		"vc": map[string]interface{}{
			"credentialSubject": map[string]interface{}{
				"id":     wallet.Subject,
				"degree": "Untracked Credential",
			},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vc+sd-jwt"
	token.Header["kid"] = wallet.KeySet.RSAKeyID()
	signed, err := token.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign untracked credential: %v", err)
	}
	return vc.BuildSDJWTSerialization(signed, nil, "")
}

func fetchVerificationResult(t *testing.T, serverURL string, requestID string) map[string]interface{} {
	t.Helper()
	resultResp, err := http.Get(serverURL + "/oid4vp/result/" + requestID)
	if err != nil {
		t.Fatalf("result request failed: %v", err)
	}
	assertVPStatus(t, resultResp, http.StatusOK)
	resultPayload := decodeVPJSONMap(t, resultResp)
	if asVPString(resultPayload["status"]) != "completed" {
		t.Fatalf("expected completed status, got %v", resultPayload["status"])
	}
	return resultPayload
}

func fetchVerificationResultWithTimeout(t *testing.T, baseURL string, requestID string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(timeout)

	for {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for completed verification result for request %s", requestID)
		}

		resultResp, err := http.Get(baseURL + "/oid4vp/result/" + requestID)
		if err != nil {
			t.Fatalf("result request failed: %v", err)
		}
		assertVPStatus(t, resultResp, http.StatusOK)
		resultPayload := decodeVPJSONMap(t, resultResp)
		if asVPString(resultPayload["status"]) == "completed" {
			return resultPayload
		}
		time.Sleep(1 * time.Second)
	}
}

func assertPolicyAllowed(t *testing.T, resultPayload map[string]interface{}) {
	t.Helper()
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || !allowed {
		t.Fatalf("expected allowed policy decision")
	}
}

func extractVPResult(t *testing.T, resultPayload map[string]interface{}) map[string]interface{} {
	t.Helper()
	resultObj, ok := resultPayload["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result object")
	}
	return resultObj
}

func extractVPPolicy(t *testing.T, resultPayload map[string]interface{}) map[string]interface{} {
	t.Helper()
	resultObj := extractVPResult(t, resultPayload)
	policyObj, ok := resultObj["policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected policy object")
	}
	return policyObj
}

func newCombinedVCServer(t *testing.T) *combinedServer {
	t.Helper()
	return newCombinedVCServerWithOptions(t, combinedServerOptions{})
}

func newCombinedVCServerWithOptions(t *testing.T, options combinedServerOptions) *combinedServer {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()

	keySet := options.KeySet
	if keySet == nil {
		var err error
		keySet, err = crypto.NewKeySet()
		if err != nil {
			t.Fatalf("new key set: %v", err)
		}
	}
	idp := mockidp.NewMockIdP(keySet)

	vciPlugin := oid4vci.NewPlugin()
	if err := vciPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL: "http://localhost:8080",
		DataDir: strings.TrimSpace(options.DataDir),
		KeySet:  keySet,
		MockIdP: idp,
	}); err != nil {
		t.Fatalf("initialize oid4vci plugin: %v", err)
	}

	vpPlugin := NewPlugin()
	if err := vpPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL: "http://localhost:8080",
		DataDir: strings.TrimSpace(options.DataDir),
		KeySet:  keySet,
		MockIdP: idp,
	}); err != nil {
		t.Fatalf("initialize oid4vp plugin: %v", err)
	}

	router := chi.NewRouter()
	router.Route("/oid4vci", func(r chi.Router) {
		vciPlugin.RegisterRoutes(r)
	})
	router.Route("/oid4vp", func(r chi.Router) {
		vpPlugin.RegisterRoutes(r)
	})
	server := httptest.NewServer(router)
	vpPlugin.baseURL = server.URL
	vpPlugin.didWebAllowedHosts = vpPlugin.allowedDIDWebHosts()
	vpPlugin.trustResolver = NewDIDWebResolver(vpPlugin.didWebAllowedHosts)
	if err := vpPlugin.configureVerifierIdentities(); err != nil {
		t.Fatalf("reconfigure oid4vp verifier identities: %v", err)
	}
	return &combinedServer{
		Server: server,
		KeySet: keySet,
	}
}

func postVPJSON(t *testing.T, endpoint string, payload map[string]interface{}) *http.Response {
	t.Helper()
	return postVPJSONWithHeaders(t, endpoint, payload, nil)
}

func postVPJSONWithHeaders(t *testing.T, endpoint string, payload map[string]interface{}, headers map[string]string) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	return resp
}

func assertVPStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
	}
}

func decodeVPJSONMap(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return payload
}

func asVPString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]interface{}, []interface{}:
		serialized, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(serialized)
	default:
		return fmt.Sprint(value)
	}
}

func containsVPReason(reasons []interface{}, expected string) bool {
	for _, reason := range reasons {
		if strings.EqualFold(strings.TrimSpace(asVPString(reason)), expected) {
			return true
		}
	}
	return false
}

func containsVPReasonCode(codes []interface{}, expected string) bool {
	for _, code := range codes {
		if strings.EqualFold(strings.TrimSpace(asVPString(code)), expected) {
			return true
		}
	}
	return false
}

func jwkFromVPValue(t *testing.T, raw interface{}) crypto.JWK {
	t.Helper()
	serialized, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal jwk value: %v", err)
	}
	var jwk crypto.JWK
	if err := json.Unmarshal(serialized, &jwk); err != nil {
		t.Fatalf("unmarshal jwk value: %v", err)
	}
	return jwk
}

func createECDSACertificateChain(t *testing.T, dnsNames []string, commonName string) (*ecdsa.PrivateKey, [][]byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName + " Root CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caCertificateDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(ca): %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caCertificateDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate(ca): %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafCertificateDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate(leaf): %v", err)
	}
	return leafKey, [][]byte{leafCertificateDER, caCertificateDER}
}

func encodeCertificateChainPEM(chain [][]byte) string {
	var builder strings.Builder
	for _, certificateDER := range chain {
		_ = pem.Encode(&builder, &pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	}
	return builder.String()
}

func encodeECDSAPrivateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	privateKeyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER}))
}
