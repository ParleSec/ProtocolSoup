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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

func TestHAIPSDJWTCredentialUsesTrustedX5CSigner(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	configuration := env.Plugin.credentialConfigurations["UniversityDegreeCredentialSDJWTHAIP"]
	issued, err := (&sdJWTCredentialIssuerDriver{plugin: env.Plugin}).IssueCredential(
		"wallet-subject",
		configuration,
		&walletIdentity{GivenName: "Alice", FamilyName: "Holder"},
		nil,
	)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}
	serialized, ok := issued.Credential.(string)
	if !ok {
		t.Fatalf("credential type = %T, want string", issued.Credential)
	}
	envelope, err := vc.ParseSDJWTEnvelope(serialized)
	if err != nil {
		t.Fatalf("ParseSDJWTEnvelope: %v", err)
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation: %v", err)
	}
	if decoded.Header["alg"] != "ES256" {
		t.Fatalf("alg = %v, want ES256", decoded.Header["alg"])
	}
	chain, err := crypto.ParseX5CCertificateChain(decoded.Header["x5c"])
	if err != nil {
		t.Fatalf("ParseX5CCertificateChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("x5c length = %d, want leaf only", len(chain))
	}
	if chain[0].IsCA || chain[0].CheckSignatureFrom(chain[0]) == nil {
		t.Fatal("x5c leaf must not be a self-signed trust anchor")
	}
	if _, err := crypto.ValidateCertificateChainAgainstRoots(
		chain,
		env.Plugin.mdocPKI.TrustAnchors(),
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("credential signer chain validation failed: %v", err)
	}
}

func TestSignedCredentialIssuerMetadataUsesTrustedX5CSigner(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	req, err := http.NewRequest(http.MethodGet, env.Server.URL+"/oid4vci/.well-known/openid-credential-issuer", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Accept", "application/jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusOK)
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/jwt" {
		t.Fatalf("Content-Type = %q, want application/jwt", contentType)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(string(raw))
	if err != nil {
		t.Fatalf("DecodeTokenWithoutValidation: %v", err)
	}
	if decoded.Header["typ"] != "openidvci-issuer-metadata+jwt" {
		t.Fatalf("typ = %v", decoded.Header["typ"])
	}
	if decoded.Payload["sub"] != env.Plugin.issuerID() ||
		decoded.Payload["credential_issuer"] != env.Plugin.issuerID() {
		t.Fatalf("signed metadata issuer claims = %#v", decoded.Payload)
	}
	chain, err := crypto.ParseX5CCertificateChain(decoded.Header["x5c"])
	if err != nil {
		t.Fatalf("ParseX5CCertificateChain: %v", err)
	}
	leaf, err := crypto.ValidateCertificateChainAgainstRoots(
		chain,
		env.Plugin.mdocPKI.TrustAnchors(),
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("metadata signer chain validation failed: %v", err)
	}
	parsed, err := jwt.Parse(string(raw), func(_ *jwt.Token) (interface{}, error) {
		return leaf.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("signed metadata signature validation failed: %v", err)
	}
}

func TestHAIPStatusListAllocatesUniqueIndicesAndServesSignedToken(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	configuration := env.Plugin.credentialConfigurations["UniversityDegreeCredentialSDJWTHAIP"]
	driver := &sdJWTCredentialIssuerDriver{plugin: env.Plugin}
	indices := make(map[float64]struct{})
	for _, subject := range []string{"wallet-a", "wallet-b"} {
		issued, err := driver.IssueCredential(
			subject,
			configuration,
			&walletIdentity{GivenName: "Alice", FamilyName: "Holder"},
			nil,
		)
		if err != nil {
			t.Fatalf("IssueCredential: %v", err)
		}
		envelope, err := vc.ParseSDJWTEnvelope(issued.Credential.(string))
		if err != nil {
			t.Fatalf("ParseSDJWTEnvelope: %v", err)
		}
		decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
		if err != nil {
			t.Fatalf("DecodeTokenWithoutValidation: %v", err)
		}
		status, _ := decoded.Payload["status"].(map[string]interface{})
		statusList, _ := status["status_list"].(map[string]interface{})
		index, ok := statusList["idx"].(float64)
		if !ok || statusList["uri"] != env.Plugin.statusListURI() {
			t.Fatalf("status claim = %#v", status)
		}
		if _, duplicate := indices[index]; duplicate {
			t.Fatalf("duplicate status list index %v", index)
		}
		indices[index] = struct{}{}
	}

	resp, err := http.Get(env.Server.URL + "/oid4vci/status-lists/" + haipStatusListID)
	if err != nil {
		t.Fatalf("status list request: %v", err)
	}
	defer resp.Body.Close()
	assertStatus(t, resp, http.StatusOK)
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read status list: %v", err)
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(string(raw))
	if err != nil {
		t.Fatalf("decode status list token: %v", err)
	}
	if decoded.Header["typ"] != "statuslist+jwt" {
		t.Fatalf("status list typ = %v", decoded.Header["typ"])
	}
	statusList, _ := decoded.Payload["status_list"].(map[string]interface{})
	if statusList["bits"] != float64(1) || statusList["lst"] == "" {
		t.Fatalf("status_list claim = %#v", statusList)
	}
}

// --- RFC 8414 Authorization Server metadata (B1) -------------------------

func TestAuthorizationServerMetadataDiscoverable(t *testing.T) {
	server, testPlugin, _ := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)

	if asString(t, payload["issuer"]) != testPlugin.issuerID() {
		t.Fatalf("expected issuer %q, got %v", testPlugin.issuerID(), payload["issuer"])
	}
	if supported, ok := payload["authorization_response_iss_parameter_supported"].(bool); !ok || !supported {
		t.Fatalf("authorization_response_iss_parameter_supported = %#v, want true (RFC 9207 / FAPI 2.0 SP)", payload["authorization_response_iss_parameter_supported"])
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

	// RFC 9449 Section 5.1: a wallet discovering DPoP support via this
	// issuer's own RFC 8414 metadata must see the accepted proof algorithms.
	dpopAlgs, ok := payload["dpop_signing_alg_values_supported"].([]interface{})
	if !ok {
		t.Fatalf("expected dpop_signing_alg_values_supported array, got %#v", payload["dpop_signing_alg_values_supported"])
	}
	for _, want := range []string{"RS256", "ES256", "EdDSA"} {
		found := false
		for _, got := range dpopAlgs {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("dpop_signing_alg_values_supported = %v, missing %q", dpopAlgs, want)
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
	for _, field := range []string{
		"client_attestation_signing_alg_values_supported",
		"client_attestation_pop_signing_alg_values_supported",
	} {
		algorithms, ok := payload[field].([]interface{})
		if !ok || len(algorithms) != 1 || algorithms[0] != "ES256" {
			t.Fatalf("%s = %#v, want [ES256]", field, payload[field])
		}
	}
}

func TestUniversityDegreeTypeMetadataMatchesAdvertisedVCT(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	configuration := env.Plugin.credentialConfigurations["UniversityDegreeCredentialSDJWTHAIP"]
	configuration.VCT = env.Server.URL + "/oid4vci/credential-types/university-degree"
	env.Plugin.credentialConfigurations[configuration.ID] = configuration

	resp, err := http.Get(configuration.VCT)
	if err != nil {
		t.Fatalf("type metadata request: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	metadata := decodeJSONMap(t, resp)
	if asString(t, metadata["vct"]) != configuration.VCT {
		t.Fatalf("type metadata vct = %v, want %q", metadata["vct"], configuration.VCT)
	}
	claims, ok := metadata["claims"].([]interface{})
	if !ok || len(claims) == 0 {
		t.Fatalf("type metadata claims = %#v", metadata["claims"])
	}
}

func TestTokenSecurityPolicyFollowsAuthorizedCredentialProfile(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	for _, testCase := range []struct {
		name            string
		configurationID string
		wantHAIP        bool
	}{
		{name: "HAIP SD-JWT", configurationID: "UniversityDegreeCredentialSDJWTHAIP", wantHAIP: true},
		{name: "HAIP mdoc", configurationID: "MobileDrivingLicenceMsoMdocHAIP", wantHAIP: true},
		{name: "educational SD-JWT", configurationID: "UniversityDegreeCredentialSDJWT", wantHAIP: false},
		{name: "educational mdoc", configurationID: "MobileDrivingLicenceMsoMdoc", wantHAIP: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			code, err := env.IDP.CreateAuthorizationCode(
				"wallet-client",
				"alice",
				"https://wallet.example/callback",
				env.Plugin.credentialConfigurations[testCase.configurationID].Scope,
				"state",
				"",
				"",
				"",
				"",
				time.Now(),
			)
			if err != nil {
				t.Fatalf("CreateAuthorizationCode: %v", err)
			}
			if err := env.IDP.BindCredentialAuthorizationDetails(code.Code, []string{testCase.configurationID}); err != nil {
				t.Fatalf("BindCredentialAuthorizationDetails: %v", err)
			}
			form := url.Values{
				"grant_type": {"authorization_code"},
				"code":       {code.Code},
			}
			request := httptest.NewRequest(http.MethodPost, "/oid4vci/token", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := request.ParseForm(); err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			if got := env.Plugin.tokenRequestRequiresHAIPSecurity(request); got != testCase.wantHAIP {
				t.Fatalf("tokenRequestRequiresHAIPSecurity() = %t, want %t", got, testCase.wantHAIP)
			}
		})
	}
}

func TestPushedAuthorizationRequestBindsAttestationDPoPAndCredentialDetails(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL
	idp.SetIssuer(server.URL)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "attested-par-wallet"
	const redirectURI = "https://wallet.example/callback"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key"),
		time.Now().Add(5*time.Minute),
	)
	dpopKey := newDPoPOID4VCITestKey(t)
	details, err := json.Marshal([]map[string]interface{}{{
		"type":                        "openid_credential",
		"credential_configuration_id": "UniversityDegreeCredentialSDJWTHAIP",
		"locations":                   []string{testPlugin.issuerID()},
	}})
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}

	for _, testCase := range []struct {
		name     string
		withDPoP bool
	}{
		{name: "optional DPoP supplied", withDPoP: true},
		{name: "DPoP introduced at token endpoint", withDPoP: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			headers := map[string]string{
				headerClientAttestation: attestationJWT,
				headerClientAttestationPoP: buildClientAttestationPoPJWT(
					t,
					instanceKey,
					testPlugin.issuerID(),
					"par-pop-jti-"+testCase.name,
					time.Now(),
				),
			}
			if testCase.withDPoP {
				headers[dpop.HeaderName] = dpopKey.proof(
					t,
					http.MethodPost,
					server.URL+"/oid4vci/par",
					nil,
				)
			}
			resp := postFormWithHeaders(t, server.URL+"/oid4vci/par", url.Values{
				"client_id":             {clientID},
				"redirect_uri":          {redirectURI},
				"response_type":         {"code"},
				"scope":                 {"vc:university_degree_haip"},
				"state":                 {"state-123"},
				"code_challenge":        {strings.Repeat("A", 43)},
				"code_challenge_method": {"S256"},
				"authorization_details": {string(details)},
			}, headers)
			assertStatus(t, resp, http.StatusCreated)
			payload := decodeJSONMap(t, resp)
			requestURI := asString(t, payload["request_uri"])
			if !strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
				t.Fatalf("request_uri = %q", requestURI)
			}
			stored, err := idp.GetPushedAuthorizationRequest(requestURI, clientID)
			if err != nil {
				t.Fatalf("GetPushedAuthorizationRequest: %v", err)
			}
			if testCase.withDPoP != (stored.DPoPJKT != "") ||
				len(stored.CredentialConfigurationIDs) != 1 ||
				stored.CredentialConfigurationIDs[0] != "UniversityDegreeCredentialSDJWTHAIP" ||
				!stored.AuthorizationDetailsUsed {
				t.Fatalf("stored pushed request = %#v", stored)
			}
		})
	}
}

func TestPARRejectsRequestURIParameter(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL
	idp.SetIssuer(server.URL)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "attested-par-reject-request-uri"
	const redirectURI = "https://wallet.example/callback"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key"),
		time.Now().Add(5*time.Minute),
	)
	details, err := json.Marshal([]map[string]interface{}{{
		"type":                        "openid_credential",
		"credential_configuration_id": "UniversityDegreeCredentialSDJWTHAIP",
		"locations":                   []string{testPlugin.issuerID()},
	}})
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/par", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"vc:university_degree_haip"},
		"state":                 {"state-123"},
		"code_challenge":        {strings.Repeat("A", 43)},
		"code_challenge_method": {"S256"},
		"authorization_details": {string(details)},
		"request_uri":           {"urn:ietf:params:oauth:request_uri:random-not-allowed"},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"par-reject-request-uri-pop",
			time.Now(),
		),
	})
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if got := asString(t, payload["error"]); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

func TestPARRejectsMismatchedDPoPJKTAndProof(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	server, testPlugin, _ := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "dpop-jkt-mismatch-wallet"
	const redirectURI = "https://wallet.example/callback"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key"),
		time.Now().Add(5*time.Minute),
	)
	details, err := json.Marshal([]map[string]interface{}{{
		"type":                        "openid_credential",
		"credential_configuration_id": "UniversityDegreeCredentialSDJWTHAIP",
		"locations":                   []string{testPlugin.issuerID()},
	}})
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}
	dpopKey := newDPoPOID4VCITestKey(t)
	otherKey := newDPoPOID4VCITestKey(t)
	if dpopKey.jwk.Thumbprint() == otherKey.jwk.Thumbprint() {
		t.Fatal("expected distinct DPoP keys for mismatch fixture")
	}

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/par", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"vc:university_degree_haip"},
		"state":                 {"state-mismatch"},
		"code_challenge":        {strings.Repeat("C", 43)},
		"code_challenge_method": {"S256"},
		"authorization_details": {string(details)},
		"dpop_jkt":              {otherKey.jwk.Thumbprint()},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"par-dpop-jkt-mismatch-pop",
			time.Now(),
		),
		dpop.HeaderName: dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/par", nil),
	})
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if got := asString(t, payload["error"]); got != dpop.ErrorInvalidDPoPProof && got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_dpop_proof or invalid_request", got)
	}
}

func TestPARAcceptsMatchingDPoPJKTWithProof(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "dpop-jkt-match-wallet"
	const redirectURI = "https://wallet.example/callback"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key"),
		time.Now().Add(5*time.Minute),
	)
	details, err := json.Marshal([]map[string]interface{}{{
		"type":                        "openid_credential",
		"credential_configuration_id": "UniversityDegreeCredentialSDJWTHAIP",
		"locations":                   []string{testPlugin.issuerID()},
	}})
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}
	dpopKey := newDPoPOID4VCITestKey(t)
	jkt := dpopKey.jwk.Thumbprint()

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/par", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"vc:university_degree_haip"},
		"state":                 {"state-match"},
		"code_challenge":        {strings.Repeat("D", 43)},
		"code_challenge_method": {"S256"},
		"authorization_details": {string(details)},
		"dpop_jkt":              {jkt},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"par-dpop-jkt-match-pop",
			time.Now(),
		),
		dpop.HeaderName: dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/par", nil),
	})
	assertStatus(t, resp, http.StatusCreated)
	requestURI := asString(t, decodeJSONMap(t, resp)["request_uri"])
	stored, err := idp.GetPushedAuthorizationRequest(requestURI, clientID)
	if err != nil {
		t.Fatalf("GetPushedAuthorizationRequest: %v", err)
	}
	if stored.DPoPJKT != jkt {
		t.Fatalf("stored DPoPJKT = %q, want %q", stored.DPoPJKT, jkt)
	}
}

func TestPARBindsDPoPJKTWithoutProofHeader(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "dpop-jkt-only-wallet"
	const redirectURI = "https://wallet.example/callback"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key"),
		time.Now().Add(5*time.Minute),
	)
	details, err := json.Marshal([]map[string]interface{}{{
		"type":                        "openid_credential",
		"credential_configuration_id": "UniversityDegreeCredentialSDJWTHAIP",
		"locations":                   []string{testPlugin.issuerID()},
	}})
	if err != nil {
		t.Fatalf("marshal authorization_details: %v", err)
	}
	jkt := newDPoPOID4VCITestKey(t).jwk.Thumbprint()

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/par", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"vc:university_degree_haip"},
		"state":                 {"state-jkt-only"},
		"code_challenge":        {strings.Repeat("E", 43)},
		"code_challenge_method": {"S256"},
		"authorization_details": {string(details)},
		"dpop_jkt":              {jkt},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"par-dpop-jkt-only-pop",
			time.Now(),
		),
	})
	assertStatus(t, resp, http.StatusCreated)
	requestURI := asString(t, decodeJSONMap(t, resp)["request_uri"])
	stored, err := idp.GetPushedAuthorizationRequest(requestURI, clientID)
	if err != nil {
		t.Fatalf("GetPushedAuthorizationRequest: %v", err)
	}
	if stored.DPoPJKT != jkt {
		t.Fatalf("stored DPoPJKT = %q, want %q", stored.DPoPJKT, jkt)
	}
}

func TestScopeOnlyPAROmitsAuthorizationDetailsFromTokenResponse(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL
	idp.SetIssuer(server.URL)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "scope-only-par-wallet"
	const redirectURI = "https://wallet.example/callback"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key"),
		time.Now().Add(5*time.Minute),
	)
	parResp := postFormWithHeaders(t, server.URL+"/oid4vci/par", url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"vc:university_degree"},
		"state":                 {"state-scope"},
		"code_challenge":        {strings.Repeat("B", 43)},
		"code_challenge_method": {"S256"},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"scope-par-pop",
			time.Now(),
		),
	})
	assertStatus(t, parResp, http.StatusCreated)
	requestURI := asString(t, decodeJSONMap(t, parResp)["request_uri"])
	stored, err := idp.GetPushedAuthorizationRequest(requestURI, clientID)
	if err != nil {
		t.Fatalf("GetPushedAuthorizationRequest: %v", err)
	}
	if stored.AuthorizationDetailsUsed {
		t.Fatal("scope-only PAR must not mark AuthorizationDetailsUsed")
	}
	if len(stored.CredentialConfigurationIDs) < 1 {
		t.Fatalf("scope-only PAR must bind configuration ids, got %#v", stored.CredentialConfigurationIDs)
	}

	authCode, err := idp.CreateAuthorizationCode(
		clientID, "alice", redirectURI, "vc:university_degree", "state-scope", "",
		"", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	if err := idp.BindCredentialConfigurationIDs(authCode.Code, stored.CredentialConfigurationIDs); err != nil {
		t.Fatalf("BindCredentialConfigurationIDs: %v", err)
	}
	tokenResp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"scope-token-pop",
			time.Now(),
		),
	})
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	if _, present := tokenPayload["authorization_details"]; present {
		t.Fatalf("scope-only token response must omit authorization_details, got %#v", tokenPayload["authorization_details"])
	}
	if asString(t, tokenPayload["access_token"]) == "" {
		t.Fatal("expected access_token")
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
	assertTokenResponseHasNoCredentialNonce(t, payload)
	if asString(t, payload["refresh_token"]) == "" {
		t.Fatal("authorization_code grant must issue a refresh_token for FAPI2 SP refresh tests")
	}
}

func TestRefreshTokenRequiresAttestationAndSameClientInstanceKey(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	const clientID = "refresh-bound-wallet"
	const redirectURI = "https://wallet.example/callback"
	idp.RegisterClient(&models.Client{
		ID:                      clientID,
		Public:                  true,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "attest_jwt_client_auth",
	})
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
	otherInstanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other client instance key: %v", err)
	}
	cnfJWK := crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key")
	attestationJWT := buildClientAttestationJWT(t, attesterKey, attesterLeafDER, caCertDER, clientID, cnfJWK, time.Now().Add(5*time.Minute))
	dpopKey := newDPoPOID4VCITestKey(t)

	tokenResp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "refresh-issue-pop", time.Now()),
		dpop.HeaderName:            dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/token", nil),
	})
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	refreshToken := asString(t, tokenPayload["refresh_token"])
	if refreshToken == "" {
		t.Fatal("expected refresh_token")
	}

	metaResp, err := http.Get(server.URL + "/oid4vci/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	assertStatus(t, metaResp, http.StatusOK)
	grants, _ := decodeJSONMap(t, metaResp)["grant_types_supported"].([]interface{})
	foundRefresh := false
	for _, grant := range grants {
		if grant == "refresh_token" {
			foundRefresh = true
		}
	}
	if !foundRefresh {
		t.Fatalf("grant_types_supported missing refresh_token: %#v", grants)
	}

	// RFC 6749 §6 / FAPI2: omitting client authentication must fail.
	omitAuth := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}, map[string]string{
		dpop.HeaderName: dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/token", nil),
	})
	if omitAuth.StatusCode != http.StatusUnauthorized && omitAuth.StatusCode != http.StatusBadRequest {
		t.Fatalf("omit attestation status = %d, want 400 or 401", omitAuth.StatusCode)
	}

	// OAuth2-ATCA §10.3: different Client Instance Key must be rejected.
	otherAttestation := buildClientAttestationJWT(
		t, attesterKey, attesterLeafDER, caCertDER, clientID,
		crypto.JWKFromECPublicKey(&otherInstanceKey.PublicKey, "other-instance"),
		time.Now().Add(5*time.Minute),
	)
	wrongKey := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}, map[string]string{
		headerClientAttestation:    otherAttestation,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(t, otherInstanceKey, testPlugin.issuerID(), "refresh-wrong-pop", time.Now()),
		dpop.HeaderName:            dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/token", nil),
	})
	assertStatus(t, wrongKey, http.StatusBadRequest)
	if asString(t, decodeJSONMap(t, wrongKey)["error"]) != "invalid_grant" {
		t.Fatalf("wrong instance key error = %#v, want invalid_grant", decodeJSONMap(t, wrongKey))
	}

	okRefresh := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		// FAPI2 RefreshTokenRequestSteps often omits client_id from the form
		// and relies on the attestation sub claim.
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "refresh-ok-pop", time.Now()),
		// FAPI2 RefreshTokenRequestSteps generates a fresh DPoP key on refresh.
		dpop.HeaderName: newDPoPOID4VCITestKey(t).proof(t, http.MethodPost, server.URL+"/oid4vci/token", nil),
	})
	assertStatus(t, okRefresh, http.StatusOK)
	refreshed := decodeJSONMap(t, okRefresh)
	if asString(t, refreshed["access_token"]) == "" {
		t.Fatalf("expected access_token, got %#v", refreshed)
	}
	if asString(t, refreshed["refresh_token"]) != refreshToken {
		t.Fatalf("FAPI2 SP §5.3.2.1-9: refresh_token must not rotate, got %q want %q", refreshed["refresh_token"], refreshToken)
	}
	if asString(t, refreshed["token_type"]) != "DPoP" {
		t.Fatalf("token_type = %q, want DPoP for refreshed access token", refreshed["token_type"])
	}

	// FAPI2: sender-constrained refresh without DPoP must fail.
	noDPoP := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, map[string]string{
		headerClientAttestation:    attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "refresh-no-dpop-pop", time.Now()),
	})
	assertStatus(t, noDPoP, http.StatusBadRequest)
	if asString(t, decodeJSONMap(t, noDPoP)["error"]) != dpop.ErrorInvalidDPoPProof {
		t.Fatalf("no-DPoP refresh error = %#v, want %s", decodeJSONMap(t, noDPoP), dpop.ErrorInvalidDPoPProof)
	}
}

// FAPI2 RefreshTokenRequestSteps regenerates DPoP on use_dpop_nonce retry but
// reuses the same Client Attestation PoP. The issuer must not consume the PoP
// jti when returning the nonce challenge.
func TestRefreshTokenAllowsSameAttestationPoPAfterDPoPNonceChallenge(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL
	testPlugin.dpopASNonceIssuer = dpop.NewNonceIssuer(time.Minute)

	const clientID = "refresh-nonce-wallet"
	const redirectURI = "https://wallet.example/callback"
	idp.RegisterClient(&models.Client{
		ID:                      clientID,
		Public:                  true,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "attest_jwt_client_auth",
	})
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
	issueDPoP := newDPoPOID4VCITestKey(t)
	issueNonce := ""
	for attempt := 0; attempt < 2; attempt++ {
		claims := jwt.MapClaims(nil)
		if issueNonce != "" {
			claims = jwt.MapClaims{"nonce": issueNonce}
		}
		resp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {authCode.Code},
			"redirect_uri": {redirectURI},
			"client_id":    {clientID},
		}, map[string]string{
			headerClientAttestation:    attestationJWT,
			headerClientAttestationPoP: buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), fmt.Sprintf("issue-pop-%d", attempt), time.Now()),
			dpop.HeaderName:            issueDPoP.proof(t, http.MethodPost, server.URL+"/oid4vci/token", claims),
		})
		if resp.StatusCode == http.StatusOK {
			tokenPayload := decodeJSONMap(t, resp)
			refreshToken := asString(t, tokenPayload["refresh_token"])
			if refreshToken == "" {
				t.Fatal("expected refresh_token")
			}

			sharedPoP := buildClientAttestationPoPJWT(t, instanceKey, testPlugin.issuerID(), "refresh-shared-pop", time.Now())
			refreshKey := newDPoPOID4VCITestKey(t)
			first := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
			}, map[string]string{
				headerClientAttestation:    attestationJWT,
				headerClientAttestationPoP: sharedPoP,
				dpop.HeaderName:            refreshKey.proof(t, http.MethodPost, server.URL+"/oid4vci/token", nil),
			})
			if first.StatusCode != http.StatusBadRequest {
				t.Fatalf("first refresh status = %d, want 400 use_dpop_nonce", first.StatusCode)
			}
			firstBody := decodeJSONMap(t, first)
			if asString(t, firstBody["error"]) != dpop.ErrorUseDPoPNonce {
				t.Fatalf("first refresh error = %#v, want %s", firstBody, dpop.ErrorUseDPoPNonce)
			}
			nonce := first.Header.Get(dpop.NonceHeaderName)
			if nonce == "" {
				t.Fatal("expected DPoP-Nonce on refresh challenge")
			}
			_ = first.Body.Close()

			retry := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {refreshToken},
			}, map[string]string{
				headerClientAttestation:    attestationJWT,
				headerClientAttestationPoP: sharedPoP,
				dpop.HeaderName:            newDPoPOID4VCITestKey(t).proof(t, http.MethodPost, server.URL+"/oid4vci/token", jwt.MapClaims{"nonce": nonce}),
			})
			assertStatus(t, retry, http.StatusOK)
			return
		}
		if asString(t, decodeJSONMap(t, resp)["error"]) != dpop.ErrorUseDPoPNonce {
			t.Fatalf("issue status = %d body = %#v", resp.StatusCode, decodeJSONMap(t, resp))
		}
		issueNonce = resp.Header.Get(dpop.NonceHeaderName)
		_ = resp.Body.Close()
		if issueNonce == "" {
			t.Fatal("expected DPoP-Nonce on authorization_code challenge")
		}
	}
	t.Fatal("authorization_code exchange did not succeed after nonce retry")
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

// FAPI2 SP Final ensure-authorization-code-is-bound-to-client: a code issued to
// client A must yield HTTP 400 invalid_grant when redeemed with client B's
// credentials, even when B authenticates with attestation and has never pushed
// its own authorization request (so it is not yet in the client registry).
func TestAuthorizationCodeGrantRejectsOtherAttestedClient(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Client Attestation Test CA")
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, idp := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	const clientA = "bound-client-a"
	const clientB = "bound-client-b"
	const redirectURI = "https://wallet.example/callback"
	registerOID4VCITestClient(idp, clientA, redirectURI)
	authCode := createOID4VCITestAuthorizationCode(t, idp, clientA, redirectURI)

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester leaf key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "Attester Leaf")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	cnfJWK := crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "instance-key-b")
	attestationJWT := buildClientAttestationJWT(
		t, attesterKey, attesterLeafDER, caCertDER, clientB, cnfJWK, time.Now().Add(5*time.Minute),
	)

	if _, exists := idp.GetClient(clientB); exists {
		t.Fatal("client B must not be pre-registered; the suite only authenticates as B at the token endpoint")
	}

	resp := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientB},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t, instanceKey, testPlugin.issuerID(), "pop-jti-bound-client-b", time.Now(),
		),
	})
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["error"]) != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant (not invalid_client/401)", payload["error"])
	}

	// Cross-client failure must not consume the code (RFC 6749 §4.1.2 binding).
	replay := postFormWithHeaders(t, server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientA},
	}, nil)
	assertStatus(t, replay, http.StatusOK)
	if asString(t, decodeJSONMap(t, replay)["access_token"]) == "" {
		t.Fatal("expected issuing client to still redeem the code after a cross-client attempt")
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

func exchangeHAIPPreAuthorizedToken(
	t *testing.T,
	serverURL string,
	testPlugin *Plugin,
	caKey *ecdsa.PrivateKey,
	caCert *x509.Certificate,
	caCertDER []byte,
	preAuthorizedCode string,
) (*http.Response, dpopOID4VCITestKey) {
	t.Helper()
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client attester key: %v", err)
	}
	attesterLeafDER := issueLeafCertificate(t, caKey, caCert, attesterKey, "HAIP Wallet Attester")
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	const clientID = "haip-pre-authorized-wallet"
	attestationJWT := buildClientAttestationJWT(
		t,
		attesterKey,
		attesterLeafDER,
		caCertDER,
		clientID,
		crypto.JWKFromECPublicKey(&instanceKey.PublicKey, "client-instance"),
		time.Now().Add(5*time.Minute),
	)
	dpopKey := newDPoPOID4VCITestKey(t)
	tokenEndpoint := serverURL + "/oid4vci/token"
	response := postFormWithHeaders(t, tokenEndpoint, url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthorizedCode},
	}, map[string]string{
		headerClientAttestation: attestationJWT,
		headerClientAttestationPoP: buildClientAttestationPoPJWT(
			t,
			instanceKey,
			testPlugin.issuerID(),
			"haip-preauth-pop-"+preAuthorizedCode,
			time.Now(),
		),
		dpop.HeaderName: dpopKey.proof(t, http.MethodPost, tokenEndpoint, nil),
	})
	return response, dpopKey
}

func TestCredentialRequestRequiresKeyAttestationForHAIPConfiguration(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Key Attestation Test CA")
	t.Setenv("OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, _ := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, dpopKey := exchangeHAIPPreAuthorizedToken(t, server.URL, testPlugin, caKey, caCert, caCertDER, asString(t, offerPayload["pre_authorized_code"]))
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

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

	proofJWT := createECProofJWTWithKeyAttestation(t, holderKey, holderJWK, cNonce, walletSubject, testPlugin.issuerID(), keyAttestationJWT)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "MobileDrivingLicenceMsoMdocHAIP",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": dpop.HeaderName + " " + accessToken,
			dpop.HeaderName: dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/credential", jwt.MapClaims{"ath": computeTestATH(accessToken)}),
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	if asString(t, firstCredential(t, credentialPayload)) == "" {
		t.Fatalf("expected mso_mdoc credential in response")
	}
}

func TestCredentialRequestRejectsMissingKeyAttestationForHAIPConfiguration(t *testing.T) {
	caKey, caCert, caCertDER := generateTestCA(t, "Key Attestation Test CA")
	t.Setenv("OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, _ := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, dpopKey := exchangeHAIPPreAuthorizedToken(t, server.URL, testPlugin, caKey, caCert, caCertDER, asString(t, offerPayload["pre_authorized_code"]))
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

	// Standard RSA proof with no key_attestation header at all.
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testPlugin.issuerID())

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "MobileDrivingLicenceMsoMdocHAIP",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": dpop.HeaderName + " " + accessToken,
			dpop.HeaderName: dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/credential", jwt.MapClaims{"ath": computeTestATH(accessToken)}),
		},
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
	t.Setenv("OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM", pemEncodeCert(caCertDER))

	server, testPlugin, _ := newAttestationTestServer(t)
	defer server.Close()
	testPlugin.baseURL = server.URL

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, dpopKey := exchangeHAIPPreAuthorizedToken(t, server.URL, testPlugin, caKey, caCert, caCertDER, asString(t, offerPayload["pre_authorized_code"]))
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := fetchCNonce(t, server.URL, accessToken)

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

	proofJWT := createECProofJWTWithKeyAttestation(t, holderKey, holderJWK, cNonce, walletSubject, testPlugin.issuerID(), keyAttestationJWT)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "MobileDrivingLicenceMsoMdocHAIP",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": dpop.HeaderName + " " + accessToken,
			dpop.HeaderName: dpopKey.proof(t, http.MethodPost, server.URL+"/oid4vci/credential", jwt.MapClaims{"ath": computeTestATH(accessToken)}),
		},
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
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	responseKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate response encryption key: %v", err)
	}
	responseJWK := crypto.JWKFromECPublicKey(&responseKey.PublicKey, "response-key")
	responseJWK.Alg = "ECDH-ES"

	req, err := http.NewRequest(http.MethodPost, server.URL+"/oid4vci/credential", strings.NewReader(mustMarshalJSON(t, map[string]interface{}{
		"credential_configuration_id": "UniversityDegreeCredential",
		"proofs": map[string]interface{}{
			"jwt": []string{proofJWT},
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
	if asString(t, firstCredential(t, decrypted)) == "" {
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
	cNonce := fetchCNonce(t, server.URL, accessToken)
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
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
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

func TestCredentialRequestEncryptionRoundTrip(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	tokenResp, err := http.PostForm(env.Server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offer["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	token := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, token["access_token"])
	nonce := fetchCNonce(t, env.Server.URL, accessToken)
	plaintext, err := json.Marshal(map[string]interface{}{
		"credential_configuration_id": "UniversityDegreeCredential",
		"proofs": map[string]interface{}{
			"jwt": []string{createWalletProofJWT(t, nonce, asString(t, offer["wallet_subject"]), testIssuerAudience)},
		},
	})
	if err != nil {
		t.Fatalf("marshal credential request: %v", err)
	}
	encrypter, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.ECDH_ES,
			Key:       &env.Plugin.mdocPKI.DocumentSignerKey().PublicKey,
		},
		nil,
	)
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
	req, err := http.NewRequest(
		http.MethodPost,
		env.Server.URL+"/oid4vci/credential",
		strings.NewReader(compact),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/jwt")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("credential request: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)
	if asString(t, firstCredential(t, payload)) == "" {
		t.Fatal("encrypted credential request did not issue a credential")
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
// to an EC holder key (JOSE jwk), carrying the given raw Key Attestation JWT in
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
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = holderJWK
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
