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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
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
	Server   *httptest.Server
	KeySet   *crypto.KeySet
	vpPlugin *Plugin
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

func TestParseClientIDSchemeUsesFinalPrefixFallback(t *testing.T) {
	testCases := []struct {
		name     string
		clientID string
		want     ClientIDScheme
		wantErr  bool
	}{
		{name: "bare identifier", clientID: "example-client", want: ClientIDSchemePreRegistered},
		{name: "URL-shaped identifier", clientID: "https://verifier.example/callback", want: ClientIDSchemePreRegistered},
		{name: "supported prefix", clientID: "redirect_uri:https://verifier.example/callback", want: ClientIDSchemeRedirectURI},
		{name: "known but disabled prefix", clientID: "x509_hash:thumbprint", want: ClientIDSchemeX509Hash},
		{name: "unsupported prefix", clientID: "origin:https://verifier.example", want: ClientIDSchemePreRegistered},
		{name: "malformed empty prefix", clientID: ":example-client", want: ClientIDSchemePreRegistered},
		{name: "malformed spaced prefix", clientID: "redirect_uri :https://verifier.example", want: ClientIDSchemePreRegistered},
		{name: "known prefix with empty value", clientID: "redirect_uri:", want: ClientIDSchemeRedirectURI},
		{name: "empty identifier", clientID: " ", want: ClientIDSchemeUnknown, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := ParseClientIDScheme(testCase.clientID)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("ParseClientIDScheme(%q) error = %v, wantErr %v", testCase.clientID, err, testCase.wantErr)
			}
			if got != testCase.want {
				t.Fatalf("ParseClientIDScheme(%q) = %q, want %q", testCase.clientID, got, testCase.want)
			}
		})
	}
}

func TestAuthorizationNonceContainsFull256Bits(t *testing.T) {
	nonce, err := randomAuthorizationNonce()
	if err != nil {
		t.Fatalf("randomAuthorizationNonce: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("nonce entropy bytes = %d, want 32", len(raw))
	}
}

func TestValidateSupportedClientIDSchemeUsesConfiguredAllowlist(t *testing.T) {
	supported := DefaultClientIDSchemeSet()
	if err := ValidateSupportedClientIDScheme("redirect_uri:https://verifier.example/callback", supported); err != nil {
		t.Fatalf("expected redirect_uri prefix to be allowed: %v", err)
	}
	if err := ValidateSupportedClientIDScheme("x509_hash:thumbprint", supported); err == nil {
		t.Fatal("expected known but disabled x509_hash prefix to be rejected")
	}
	if err := ValidateSupportedClientIDScheme("https://verifier.example/callback", supported); err == nil {
		t.Fatal("expected URL-shaped pre-registered identifier to be rejected")
	}

	supported[ClientIDSchemePreRegistered] = struct{}{}
	if err := ValidateSupportedClientIDScheme("custom:https://verifier.example", supported); err != nil {
		t.Fatalf("expected unknown prefix fallback to follow pre_registered allowlist: %v", err)
	}
}

func TestDefaultClientIDSchemeSetContainsOnlyOperationalUnprovisionedSchemes(t *testing.T) {
	supported := DefaultClientIDSchemeSet()
	if len(supported) != 1 {
		t.Fatalf("default client_id prefix count = %d, want 1: %#v", len(supported), supported)
	}
	if _, ok := supported[ClientIDSchemeRedirectURI]; !ok {
		t.Fatal("redirect_uri must be enabled by default")
	}
	for _, scheme := range []ClientIDScheme{
		ClientIDSchemePreRegistered,
		ClientIDSchemeDecentralizedIdentifier,
		ClientIDSchemeOpenIDFederation,
		ClientIDSchemeX509SANDNS,
		ClientIDSchemeX509Hash,
		ClientIDSchemeVerifierAttestation,
	} {
		if _, ok := supported[scheme]; ok {
			t.Fatalf("%s must not be enabled by default", scheme)
		}
	}
}

func TestConfigureVerifierIdentitiesConditionallyEnablesProvisionedSchemes(t *testing.T) {
	for _, envName := range []string{
		verifierAttestationClientIDEnv,
		verifierAttestationIssuerEnv,
		verifierAttestationPrivateKeyEnv,
		x509SANDNSClientIDEnv,
		x509SANDNSCertificateChainPEMEnv,
		x509SANDNSPrivateKeyPEMEnv,
	} {
		t.Setenv(envName, "")
	}

	withoutProvisioning := NewPlugin()
	if err := withoutProvisioning.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure verifier identities without keyset: %v", err)
	}
	if len(withoutProvisioning.supportedClientIDSchemes) != 1 {
		t.Fatalf("unprovisioned schemes = %#v, want redirect_uri only", withoutProvisioning.supportedClientIDSchemes)
	}

	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("create verifier keyset: %v", err)
	}
	withProvisioning := NewPlugin()
	withProvisioning.baseURL = "https://verifier.example"
	withProvisioning.dataDir = t.TempDir()
	withProvisioning.keySet = keySet
	if err := withProvisioning.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure provisioned verifier identities: %v", err)
	}
	for _, scheme := range []ClientIDScheme{
		ClientIDSchemeRedirectURI,
		ClientIDSchemeVerifierAttestation,
		ClientIDSchemeX509SANDNS,
		ClientIDSchemeX509Hash,
	} {
		if _, ok := withProvisioning.supportedClientIDSchemes[scheme]; !ok {
			t.Fatalf("%s must be enabled when its signing material is provisioned", scheme)
		}
	}
	for _, scheme := range []ClientIDScheme{
		ClientIDSchemePreRegistered,
		ClientIDSchemeDecentralizedIdentifier,
		ClientIDSchemeOpenIDFederation,
	} {
		if _, ok := withProvisioning.supportedClientIDSchemes[scheme]; ok {
			t.Fatalf("%s must remain disabled without registration or trust support", scheme)
		}
	}
}

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

func TestCreateAuthorizationRequestRejectsUnsupportedResponseMode(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createResp := postVPJSON(t, env.Server.URL+"/oid4vp/request/create", map[string]interface{}{
		"response_mode": "fragment",
		"dcql_query": map[string]interface{}{
			"credentials": []map[string]interface{}{{"id": "credential_query"}},
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
	if _, ok := createPayload["client_id_scheme"]; ok {
		t.Fatal("create response must not expose obsolete client_id_scheme")
	}

	requestJWT := asVPString(createPayload["request"])
	decodedRequest, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation(request): %v", err)
	}
	if _, ok := decodedRequest.Payload["client_id_scheme"]; ok {
		t.Fatal("request object must not contain obsolete client_id_scheme claim")
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
	if len(certificates) != 1 {
		t.Fatalf("x5c must omit the trust anchor, got %d certificates", len(certificates))
	}
	roots := x509.NewCertPool()
	rootCertificate, err := x509.ParseCertificate(certificateChain[len(certificateChain)-1])
	if err != nil {
		t.Fatalf("ParseCertificate(root): %v", err)
	}
	roots.AddCert(rootCertificate)
	leaf, err := crypto.ValidateCertificateChainAgainstRoots(certificates, roots, time.Now().UTC())
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

	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	validatedLeaf, err := crypto.ValidateCertificateChainAgainstRoots(certificates, roots, time.Now().UTC())
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

// TestPersistedX509SignerStableAcrossRestart proves that, with a persistence
// root, the auto-generated x509_hash request signer is reloaded on the next
// construction so the x509_hash Client Identifier (HAIP 1.0 Section 5; OID4VP
// 1.0 Section 5.9.3) stays stable across restarts, while a different data dir
// yields a different leaf. The wallet trusts the request signature by the leaf
// hash, so a churning client_id would break trust mid-certification.
func TestPersistedX509SignerStableAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	first, err := newEphemeralX509RequestSigner("https://verifier.example", dir)
	if err != nil {
		t.Fatalf("first signer: %v", err)
	}
	if first == nil {
		t.Fatal("expected a signer for a DNS-name host")
		return
	}
	id1, err := first.x509HashClientID()
	if err != nil {
		t.Fatalf("x509HashClientID: %v", err)
	}

	second, err := newEphemeralX509RequestSigner("https://verifier.example", dir)
	if err != nil {
		t.Fatalf("second signer: %v", err)
	}
	id2, err := second.x509HashClientID()
	if err != nil {
		t.Fatalf("x509HashClientID: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("x509_hash client_id must be stable across restarts: %q vs %q", id1, id2)
	}

	other, err := newEphemeralX509RequestSigner("https://verifier.example", t.TempDir())
	if err != nil {
		t.Fatalf("third signer: %v", err)
	}
	if id3, _ := other.x509HashClientID(); id3 == id1 {
		t.Fatal("a different data dir must produce a different leaf and client_id")
	}

	if time.Until(first.certificates[0].NotAfter) < 48*time.Hour {
		t.Fatalf("persisted leaf must outlive the 24h ephemeral default, expires %s", first.certificates[0].NotAfter)
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
	if !ok || len(rawX5C) != 1 {
		t.Fatalf("expected x5c header with leaf only, got %v", decodedRequest.Header["x5c"])
	}

	parsedCerts, err := crypto.ParseX5CCertificateChain(decodedRequest.Header["x5c"])
	if err != nil {
		t.Fatalf("ParseX5CCertificateChain: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificates[len(certificates)-1])
	leaf, err := crypto.ValidateCertificateChainAgainstRoots(parsedCerts, roots, time.Now().UTC())
	if err != nil {
		t.Fatalf("ValidateCertificateChain: %v", err)
	}
	if err := leaf.VerifyHostname("verifier.example"); err != nil {
		t.Fatalf("VerifyHostname(verifier.example): %v", err)
	}

	if _, ok := decodedRequest.Payload["client_id_scheme"]; ok {
		t.Fatal("request object must not contain obsolete client_id_scheme claim")
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

// credentialSetsDCQLQuery builds a DCQL query with two Credential Queries --
// "degree_sd_jwt" (satisfiable by the wallet fixture's actual dc+sd-jwt
// credential) and "unused_ldp_vc" (an ldp_vc requirement the single-credential
// wallet fixture never presents) -- plus the given top-level credential_sets
// array (OID4VP 1.0 Section 6.2), for exercising the verifier-side
// vc.EvaluateCredentialSets wiring end to end.
func credentialSetsDCQLQuery(credentialSets []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id": "degree_sd_jwt",
				"meta": map[string]interface{}{
					"vct_values": []string{testCredentialVCT},
				},
				"claims": []map[string]interface{}{
					{"path": []string{"degree"}},
				},
			},
			{
				"id":     "unused_ldp_vc",
				"format": "ldp_vc",
				"meta": map[string]interface{}{
					"type_values": []string{"UniversityDegreeCredential"},
				},
			},
		},
		"credential_sets": credentialSets,
	}
}

// TestDirectPostPolicyAllowsCredentialSetSatisfiedByOneAlternative proves a
// required credential_sets entry succeeds when the presented credential
// satisfies at least one of its options, even though it does not satisfy
// every entry in `credentials` (the pre-credential_sets behaviour) -- the
// wallet's real dc+sd-jwt credential only ever matches "degree_sd_jwt", never
// "unused_ldp_vc".
func TestDirectPostPolicyAllowsCredentialSetSatisfiedByOneAlternative(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", credentialSetsDCQLQuery([]map[string]interface{}{
		{"options": [][]string{{"unused_ldp_vc"}, {"degree_sd_jwt"}}, "required": true},
	}))
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

// TestDirectPostPolicyDeniesUnsatisfiedRequiredCredentialSet proves a
// required credential_sets entry whose only option references a Credential
// Query the wallet never satisfies is denied with the new
// dcql_credential_set_unsatisfied reason code, even though a different,
// independently-satisfied credential_sets entry exists for the credential
// that was actually presented.
func TestDirectPostPolicyDeniesUnsatisfiedRequiredCredentialSet(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", credentialSetsDCQLQuery([]map[string]interface{}{
		{"options": [][]string{{"degree_sd_jwt"}}, "required": true},
		{"options": [][]string{{"unused_ldp_vc"}}, "required": true},
	}))
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision, got %v", policyObj)
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "dcql_credential_set_unsatisfied") {
		t.Fatalf("expected dcql_credential_set_unsatisfied reason code, got %v", reasonCodes)
	}
}

// TestDirectPostPolicyAllowsUnsatisfiedOptionalCredentialSet proves a
// credential_sets entry marked required:false does not block the overall
// query from succeeding even when none of its options are satisfiable.
func TestDirectPostPolicyAllowsUnsatisfiedOptionalCredentialSet(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequestWithDCQL(t, env.Server.URL, "direct_post", credentialSetsDCQLQuery([]map[string]interface{}{
		{"options": [][]string{{"degree_sd_jwt"}}, "required": true},
		{"options": [][]string{{"unused_ldp_vc"}}, "required": false},
	}))
	postWalletResponse(t, env.Server.URL, env.KeySet, createPayload, wallet, "")

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
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
				"alice",
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

func TestRedirectWalletResponseRequiresExactStateEvenWithRequestID(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	formResp, err := http.PostForm(env.Server.URL+"/oid4vp/response", url.Values{
		"request_id": {asVPString(createPayload["request_id"])},
		"vp_token":   {"placeholder-token"},
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
	// SD-JWT VC regression coverage: select the university-degree SD-JWT VC query
	// explicitly. The verifier's implicit default DCQL targets the
	// mDL mso_mdoc, so these SD-JWT tests state their format explicitly (the
	// behaviour an SD-JWT verifier always had under the old implicit default).
	return createVPRequestWithDCQL(t, serverURL, responseMode, map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id": "university_degree",
				"meta": map[string]interface{}{
					"vct_values": []string{"https://protocolsoup.com/credentials/university_degree"},
				},
				"claims": []map[string]interface{}{
					{"path": []string{"degree"}},
					{"path": []string{"graduation_year"}},
				},
			},
		},
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
		"wallet_user_id":               walletUserID,
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
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
	accessToken := asVPString(tokenPayload["access_token"])

	walletKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new wallet key set: %v", err)
	}
	proofJWT := createProofJWT(t, walletKeySet, walletSubject, fetchVPNonce(t, baseURL, accessToken), issuerID, "RS256")

	credentialResp := postVPJSONWithHeaders(
		t,
		baseURL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertVPStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeVPJSONMap(t, credentialResp)
	credentialJWT := firstVPCredential(credentialPayload)
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
	accessToken := asVPString(tokenPayload["access_token"])

	walletKeySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new wallet key set: %v", err)
	}
	proofAlgorithm := "RS256"
	if credentialConfigurationID == "UniversityDegreeCredentialLDP" {
		proofAlgorithm = "ES256"
	}
	proofJWT := createProofJWT(t, walletKeySet, walletSubject, fetchVPNonce(t, serverURL, accessToken), testIssuerAudience, proofAlgorithm)

	credentialResp := postVPJSONWithHeaders(
		t,
		serverURL+"/oid4vci/credential",
		func() map[string]interface{} {
			payload := map[string]interface{}{
				"credential_configuration_id": credentialConfigurationID,
				"proofs": map[string]interface{}{
					"jwt": []string{proofJWT},
				},
			}
			if credentialFormat != "" {
				payload["format"] = credentialFormat
			}
			return payload
		}(),
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertVPStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeVPJSONMap(t, credentialResp)
	credentialJWT := firstVPCredential(credentialPayload)
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

func createProofJWT(t *testing.T, keySet *crypto.KeySet, subject string, nonce string, audience string, algorithm string) string {
	t.Helper()
	keyID := keySet.RSAKeyID()
	var method jwt.SigningMethod = jwt.SigningMethodRS256
	var signingKey interface{} = keySet.RSAPrivateKey()
	switch algorithm {
	case "ES256":
		keyID = keySet.ECKeyID()
		method = jwt.SigningMethodES256
		signingKey = keySet.ECPrivateKey()
	case "EdDSA":
		keyID = keySet.Ed25519KeyID()
		method = jwt.SigningMethodEdDSA
		signingKey = keySet.Ed25519PrivateKey()
	}
	pubJWK, found := keySet.GetJWKByID(keyID)
	if !found {
		t.Fatalf("wallet rsa jwk is unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"aud":   audience,
		"nonce": nonce,
		"iat":   now.Unix(),
		"jti":   "proof-" + subject,
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = pubJWK
	signed, err := token.SignedString(signingKey)
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
	body, err := io.ReadAll(formResp.Body)
	if err != nil {
		t.Fatalf("read direct_post acknowledgement: %v", err)
	}
	_ = formResp.Body.Close()
	if strings.TrimSpace(string(body)) != "{}" {
		t.Fatalf("direct_post acknowledgement body = %q, want {}", string(body))
	}
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

// buildRawSDJWTKBVPToken builds a genuine SD-JWT+KB compact serialization
// ("issuer-signed-jwt~disclosure~...~kb-jwt") signed over the wallet's real
// credential, for tests that need to exercise the raw KB-JWT validation path
// in evaluateSDJWTPresentation (aud/nonce/iat/sd_hash) directly, rather than
// the vp+jwt-wrapped credential_jwt path createVPToken produces.
func buildRawSDJWTKBVPToken(t *testing.T, createPayload map[string]interface{}, wallet *walletFixture, kbIssuedAt time.Time) string {
	t.Helper()
	envelope, err := vc.ParseSDJWTEnvelope(wallet.CredentialJWT)
	if err != nil {
		t.Fatalf("parse sd-jwt envelope: %v", err)
	}
	return buildRawSDJWTKBVPTokenFromParts(
		t,
		createPayload,
		wallet,
		kbIssuedAt,
		envelope.IssuerSignedJWT,
		envelope.Disclosures,
	)
}

func buildRawSDJWTKBVPTokenFromParts(
	t *testing.T,
	createPayload map[string]interface{},
	wallet *walletFixture,
	kbIssuedAt time.Time,
	issuerSignedJWT string,
	disclosures []string,
) string {
	t.Helper()
	sdJWTWithoutKB := vc.BuildSDJWTSerialization(issuerSignedJWT, disclosures, "")
	if !strings.HasSuffix(sdJWTWithoutKB, "~") {
		sdJWTWithoutKB += "~"
	}
	sdHashRaw := sha256.Sum256([]byte(sdJWTWithoutKB))

	kbClaims := jwt.MapClaims{
		"aud":     asVPString(createPayload["client_id"]),
		"nonce":   asVPString(createPayload["nonce"]),
		"iat":     kbIssuedAt.Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(sdHashRaw[:]),
	}
	kbToken := jwt.NewWithClaims(jwt.SigningMethodRS256, kbClaims)
	kbToken.Header["typ"] = "kb+jwt"
	kbToken.Header["kid"] = wallet.KeySet.RSAKeyID()
	signedKB, err := kbToken.SignedString(wallet.KeySet.RSAPrivateKey())
	if err != nil {
		t.Fatalf("sign kb-jwt: %v", err)
	}
	return vc.BuildSDJWTSerialization(issuerSignedJWT, disclosures, signedKB)
}

func postRawSDJWTKBResponse(t *testing.T, serverURL string, createPayload map[string]interface{}, vpToken string) {
	t.Helper()
	formResp, err := http.PostForm(serverURL+"/oid4vp/response", url.Values{
		"state":    {asVPString(createPayload["state"])},
		"vp_token": {vpToken},
	})
	if err != nil {
		t.Fatalf("post raw sd-jwt+kb wallet response failed: %v", err)
	}
	assertVPStatus(t, formResp, http.StatusOK)
}

// TestDirectPostPolicyAllowsFreshKBJWTIat proves a raw SD-JWT+KB presentation
// (as opposed to the vp+jwt-wrapped credential_jwt path most tests in this
// file exercise) with a KB-JWT iat inside the freshness window is accepted.
func TestDirectPostPolicyAllowsFreshKBJWTIat(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	vpToken := buildRawSDJWTKBVPToken(t, createPayload, wallet, time.Now().UTC())
	postRawSDJWTKBResponse(t, env.Server.URL, createPayload, vpToken)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	assertPolicyAllowed(t, resultPayload)
}

func TestDirectPostPolicyRejectsUncommittedSDJWTDisclosure(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	envelope, err := vc.ParseSDJWTEnvelope(wallet.CredentialJWT)
	if err != nil {
		t.Fatal(err)
	}
	uncommitted, err := vc.CreateSDJWTDisclosure("uncommitted", "attacker", "test-salt")
	if err != nil {
		t.Fatal(err)
	}
	disclosures := append(append([]string(nil), envelope.Disclosures...), uncommitted.Encoded)
	vpToken := buildRawSDJWTKBVPTokenFromParts(
		t,
		createPayload,
		wallet,
		time.Now().UTC(),
		envelope.IssuerSignedJWT,
		disclosures,
	)
	postRawSDJWTKBResponse(t, env.Server.URL, createPayload, vpToken)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatal("expected uncommitted disclosure to be rejected")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "disclosure_invalid") {
		t.Fatalf("expected disclosure_invalid reason code, got %v", reasonCodes)
	}
}

// TestDirectPostPolicyDeniesStaleKBJWTIat proves a KB-JWT whose iat is further
// in the past than kbJWTFreshnessSkew is rejected (SD-JWT RFC 9901 Section 7.3
// step 5.e).
func TestDirectPostPolicyDeniesStaleKBJWTIat(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	staleIat := time.Now().UTC().Add(-(kbJWTFreshnessSkew + time.Minute))
	vpToken := buildRawSDJWTKBVPToken(t, createPayload, wallet, staleIat)
	postRawSDJWTKBResponse(t, env.Server.URL, createPayload, vpToken)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision for stale kb-jwt iat")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "kb_jwt_invalid") {
		t.Fatalf("expected kb_jwt_invalid reason code, got %v", reasonCodes)
	}
}

// TestDirectPostPolicyDeniesFutureKBJWTIat proves a KB-JWT whose iat is
// further in the future than kbJWTFreshnessSkew is rejected symmetrically
// (clocks can run fast as well as slow).
func TestDirectPostPolicyDeniesFutureKBJWTIat(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	futureIat := time.Now().UTC().Add(kbJWTFreshnessSkew + time.Minute)
	vpToken := buildRawSDJWTKBVPToken(t, createPayload, wallet, futureIat)
	postRawSDJWTKBResponse(t, env.Server.URL, createPayload, vpToken)

	resultPayload := fetchVerificationResult(t, env.Server.URL, asVPString(createPayload["request_id"]))
	policyObj := extractVPPolicy(t, resultPayload)
	if allowed, ok := policyObj["allowed"].(bool); !ok || allowed {
		t.Fatalf("expected denied policy decision for future kb-jwt iat")
	}
	reasonCodes, _ := policyObj["reason_codes"].([]interface{})
	if !containsVPReasonCode(reasonCodes, "kb_jwt_invalid") {
		t.Fatalf("expected kb_jwt_invalid reason code, got %v", reasonCodes)
	}
}

// TestKBJWTIatWithinFreshnessWindowBoundary exercises kbJWTIatWithinFreshnessWindow
// directly against fixed instants so the exact edges of the window (SD-JWT RFC
// 9901 §7.3 step 5.e) are asserted deterministically, without the wall-clock
// drift an HTTP round trip would introduce at an exact boundary.
func TestKBJWTIatWithinFreshnessWindowBoundary(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		issuedAt time.Time
		want     bool
	}{
		{"exactly at past boundary", now.Add(-kbJWTFreshnessSkew), true},
		{"exactly at future boundary", now.Add(kbJWTFreshnessSkew), true},
		{"one second past the boundary", now.Add(-kbJWTFreshnessSkew - time.Second), false},
		{"one second beyond the future boundary", now.Add(kbJWTFreshnessSkew + time.Second), false},
		{"iat equals now", now, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kbJWTIatWithinFreshnessWindow(tc.issuedAt, now); got != tc.want {
				t.Fatalf("kbJWTIatWithinFreshnessWindow(%v, %v) = %v, want %v", tc.issuedAt, now, got, tc.want)
			}
		})
	}
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
	token.Header["typ"] = "dc+sd-jwt"
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
		Server:   server,
		KeySet:   keySet,
		vpPlugin: vpPlugin,
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

func fetchVPNonce(t *testing.T, serverURL string, accessToken string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/oid4vci/nonce", nil)
	if err != nil {
		t.Fatalf("build nonce request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("nonce request failed: %v", err)
	}
	assertVPStatus(t, resp, http.StatusOK)
	payload := decodeVPJSONMap(t, resp)
	cNonce := asVPString(payload["c_nonce"])
	if cNonce == "" {
		t.Fatal("nonce response missing c_nonce")
	}
	return cNonce
}

func firstVPCredential(payload map[string]interface{}) string {
	credentials, ok := payload["credentials"].([]interface{})
	if !ok || len(credentials) == 0 {
		return ""
	}
	credential, ok := credentials[0].(map[string]interface{})
	if !ok {
		return ""
	}
	return asVPString(credential["credential"])
}

func assertVPStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		t.Fatalf("expected status %d, got %d: %s", status, resp.StatusCode, strings.TrimSpace(string(body)))
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

// --- OID4VP spec compliance tests ---

func TestExpiredRequestObjectServedReturnsError(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	requestID := asVPString(createPayload["request_id"])

	// Manually expire the session
	env.vpPlugin.mu.Lock()
	if session, ok := env.vpPlugin.requests[requestID]; ok {
		session.ExpiresAt = time.Now().UTC().Add(-1 * time.Minute)
	}
	env.vpPlugin.mu.Unlock()

	getResp, err := http.Get(env.Server.URL + "/oid4vp/request/" + requestID)
	if err != nil {
		t.Fatalf("GET request object failed: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for expired request, got %d", getResp.StatusCode)
	}

	postResp, err := http.Post(env.Server.URL+"/oid4vp/request/"+requestID, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST request object failed: %v", err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for unsupported request_uri_method=post, got %d", postResp.StatusCode)
	}
}

func TestAuthorizationRequestGETReturnsCompactJWTBody(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	requestID := asVPString(createPayload["request_id"])
	resp, err := http.Get(env.Server.URL + "/oid4vp/request/" + requestID)
	if err != nil {
		t.Fatalf("GET request object failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/oauth-authz-req+jwt" {
		t.Fatalf("unexpected Content-Type %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read request object: %v", err)
	}
	if got, want := strings.TrimSpace(string(body)), asVPString(createPayload["request"]); got != want {
		t.Fatalf("GET body does not equal compact request JWT")
	}
}

func TestAuthorizationRequestPOSTBindsWalletNonceAndIsSafelyRepeatable(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequestPayload(t, env.Server.URL, map[string]interface{}{
		"response_mode":      "direct_post",
		"response_uri":       env.Server.URL + "/oid4vp/response",
		"request_uri_method": "post",
		"dcql_query": map[string]interface{}{
			"credentials": []map[string]interface{}{{
				"id":     "degree",
				"format": "dc+sd-jwt",
				"meta": map[string]interface{}{
					"vct_values": []string{"https://protocolsoup.com/credentials/university_degree"},
				},
			}},
		},
	})
	requestID := asVPString(createPayload["request_id"])
	endpoint := env.Server.URL + "/oid4vp/request/" + requestID

	getResp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("GET request object: %v", err)
	}
	_ = getResp.Body.Close()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET status = %d, want 405", getResp.StatusCode)
	}

	fetch := func(walletNonce string) (int, string) {
		t.Helper()
		resp, err := http.PostForm(endpoint, url.Values{"wallet_nonce": {walletNonce}})
		if err != nil {
			t.Fatalf("POST request object: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read request object: %v", err)
		}
		return resp.StatusCode, string(body)
	}
	status, first := fetch("wallet-nonce-123")
	if status != http.StatusOK {
		t.Fatalf("POST status = %d, want 200: %s", status, first)
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(first)
	if err != nil {
		t.Fatalf("decode request object: %v", err)
	}
	if decoded.Payload["wallet_nonce"] != "wallet-nonce-123" {
		t.Fatalf("wallet_nonce = %v", decoded.Payload["wallet_nonce"])
	}
	status, repeated := fetch("wallet-nonce-123")
	if status != http.StatusOK || repeated != first {
		t.Fatalf("repeated fetch was not stable: status=%d", status)
	}
	status, _ = fetch("different-wallet-nonce")
	if status != http.StatusBadRequest {
		t.Fatalf("different nonce status = %d, want 400", status)
	}
}

func TestRequestObjectTypHeaderValidatedByVerifier(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	requestID := asVPString(createPayload["request_id"])

	// Tamper the stored request JWT to have a wrong typ header
	env.vpPlugin.mu.Lock()
	if session, ok := env.vpPlugin.requests[requestID]; ok {
		badClaims := jwt.MapClaims{"iss": "test", "exp": time.Now().Add(5 * time.Minute).Unix()}
		badToken := jwt.NewWithClaims(jwt.SigningMethodRS256, badClaims)
		badToken.Header["typ"] = "invalid-typ"
		badJWT, _ := badToken.SignedString(env.KeySet.RSAPrivateKey())
		session.RequestJWT = badJWT
	}
	env.vpPlugin.mu.Unlock()

	resp, err := http.Get(env.Server.URL + "/oid4vp/request/" + requestID)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid typ, got %d", resp.StatusCode)
	}
}

func TestRedirectURISchemeResponseURIMustMatchClientID(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	resp := postVPJSON(t, env.Server.URL+"/oid4vp/request/create", map[string]interface{}{
		"client_id":     "redirect_uri:" + env.Server.URL + "/oid4vp/response",
		"response_mode": "direct_post",
		"response_uri":  "https://evil.example/response",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched response_uri, got %d", resp.StatusCode)
	}
	payload := decodeVPJSONMap(t, resp)
	if asVPString(payload["error"]) != "invalid_client" {
		t.Fatalf("expected invalid_client error, got %q", asVPString(payload["error"]))
	}
}

func TestRequestObjectContainsClientMetadataWithVPFormats(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	requestJWT := asVPString(createPayload["request"])
	decodedRequest, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		t.Fatalf("decode request: %v", err)
	}
	clientMetadata, ok := decodedRequest.Payload["client_metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected client_metadata in request claims")
	}
	vpFormats, ok := clientMetadata["vp_formats_supported"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected vp_formats_supported in client_metadata")
	}
	for _, format := range []string{"dc+sd-jwt", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"} {
		if _, ok := vpFormats[format]; !ok {
			t.Fatalf("expected %q in vp_formats_supported", format)
		}
	}
	mdocMetadata, ok := vpFormats["mso_mdoc"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected mso_mdoc metadata")
	}
	for _, field := range []string{"issuerauth_alg_values", "deviceauth_alg_values"} {
		values, ok := mdocMetadata[field].([]interface{})
		if !ok || len(values) != 1 || values[0] != float64(-7) {
			t.Fatalf("%s must contain numeric COSE ES256 identifier -7, got %v", field, mdocMetadata[field])
		}
	}
}

func TestVerifierAttestationDiscoveryIncludesExtendedMetadata(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	resp, err := http.Get(env.Server.URL + "/oid4vp/verifier-attestation/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	assertVPStatus(t, resp, http.StatusOK)
	metadata := decodeVPJSONMap(t, resp)

	if _, ok := metadata["response_types_supported"]; !ok {
		t.Fatalf("expected response_types_supported")
	}
	if _, ok := metadata["vp_formats_supported"]; !ok {
		t.Fatalf("expected vp_formats_supported")
	}
	if _, ok := metadata["request_object_signing_alg_values_supported"]; !ok {
		t.Fatalf("expected request_object_signing_alg_values_supported")
	}
}

func TestSessionExpiryPruningEvictsOldSessions(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	createPayload := createVPRequest(t, env.Server.URL, "direct_post")
	requestID := asVPString(createPayload["request_id"])

	env.vpPlugin.mu.Lock()
	if session, ok := env.vpPlugin.requests[requestID]; ok {
		session.ExpiresAt = time.Now().UTC().Add(-30 * time.Minute)
	}
	env.vpPlugin.mu.Unlock()

	env.vpPlugin.evictExpiredSessions()

	env.vpPlugin.mu.RLock()
	_, exists := env.vpPlugin.requests[requestID]
	env.vpPlugin.mu.RUnlock()
	if exists {
		t.Fatalf("expected expired session to be evicted")
	}
}

func TestExternalSDJWTIssuerRequiresTrustedLeafOnlyX5C(t *testing.T) {
	leafKey, chainDER := createECDSACertificateChain(t, []string{"issuer.example"}, "External VC Issuer")
	root, err := x509.ParseCertificate(chainDER[1])
	if err != nil {
		t.Fatalf("ParseCertificate(root): %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	verifier := &Plugin{sdJWTIssuerTrustAnchors: roots}

	build := func(x5c [][]byte) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": "https://issuer.example",
			"sub": "wallet-subject",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"vct": "urn:example:credential",
		})
		encoded := make([]string, 0, len(x5c))
		for _, certificate := range x5c {
			encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate))
		}
		token.Header["typ"] = "dc+sd-jwt"
		token.Header["x5c"] = encoded
		signed, err := token.SignedString(leafKey)
		if err != nil {
			t.Fatalf("SignedString: %v", err)
		}
		return signed + "~"
	}

	issuerJWK, err := verifier.externalSDJWTIssuerJWK(build(chainDER[:1]))
	if err != nil {
		t.Fatalf("externalSDJWTIssuerJWK: %v", err)
	}
	publicKey, err := issuerJWK.ToPublicKey()
	if err != nil {
		t.Fatalf("ToPublicKey: %v", err)
	}
	valid, err := crypto.VerifySignatureWithKey(strings.TrimSuffix(build(chainDER[:1]), "~"), publicKey)
	if err != nil || !valid {
		t.Fatalf("issuer key did not verify credential: valid=%v err=%v", valid, err)
	}
	if _, err := verifier.externalSDJWTIssuerJWK(build(chainDER)); err == nil ||
		!strings.Contains(err.Error(), "exclude the trust anchor") {
		t.Fatalf("root-inclusive x5c error = %v", err)
	}
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
