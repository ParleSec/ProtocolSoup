package oid4vp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// TestValidateHAIPProfileRejectsOutOfProfile proves HAIP mode is a constraining
// profile: out-of-profile choices are rejected, not merely permitted alongside
// conformant ones (HAIP 1.0 Section 5).
func TestValidateHAIPProfileRejectsOutOfProfile(t *testing.T) {
	cases := []struct {
		name         string
		responseMode string
		dcql         string
		scope        string
		scheme       ClientIDScheme
	}{
		{"scope alias instead of dcql", responseModeDCAPIJWT, "", "university_degree", ClientIDSchemeX509Hash},
		{"missing dcql", responseModeDCAPIJWT, "", "", ClientIDSchemeX509Hash},
		{"unencrypted direct_post", responseModeDirectPost, mdocDCQLQuery, "", ClientIDSchemeX509Hash},
		{"unencrypted dc_api", responseModeDCAPI, mdocDCQLQuery, "", ClientIDSchemeX509Hash},
		{"x509_san_dns out of profile", responseModeDCAPIJWT, mdocDCQLQuery, "", ClientIDSchemeX509SANDNS},
		{"verifier_attestation out of profile", responseModeDCAPIJWT, mdocDCQLQuery, "", ClientIDSchemeVerifierAttestation},
		{"redirect_uri out of profile", responseModeDirectPostJWT, mdocDCQLQuery, "", ClientIDSchemeRedirectURI},
		{"pre_registered out of profile", responseModeDirectPostJWT, mdocDCQLQuery, "", ClientIDSchemePreRegistered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateHAIPProfile(tc.responseMode, tc.dcql, tc.scope, tc.scheme); err == nil {
				t.Fatalf("expected HAIP profile to reject %s", tc.name)
			}
		})
	}
}

// TestValidateHAIPProfileAcceptsConformant confirms the in-profile combinations
// pass: DCQL + encrypted response mode + the x509_hash signed scheme.
func TestValidateHAIPProfileAcceptsConformant(t *testing.T) {
	cases := []struct {
		name         string
		responseMode string
		scheme       ClientIDScheme
	}{
		{"dc_api.jwt + x509_hash", responseModeDCAPIJWT, ClientIDSchemeX509Hash},
		{"direct_post.jwt + x509_hash", responseModeDirectPostJWT, ClientIDSchemeX509Hash},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateHAIPProfile(tc.responseMode, mdocDCQLQuery, "", tc.scheme); err != nil {
				t.Fatalf("expected HAIP profile to accept %s: %v", tc.name, err)
			}
		})
	}
}

// TestDCAPIAudienceAndOrigin pins the OID4VP 1.0 Appendix A.4 / B.2.6.2 split:
// the response audience is the Origin prefixed with "origin:", while the
// handover binds the bare Origin without the prefix.
func TestDCAPIAudienceAndOrigin(t *testing.T) {
	if got := dcAPIAudience("https://verifier.example"); got != "origin:https://verifier.example" {
		t.Fatalf("dcAPIAudience mismatch: %q", got)
	}
	if got := dcAPIAudience("origin:https://verifier.example"); got != "origin:https://verifier.example" {
		t.Fatalf("dcAPIAudience must not double-prefix: %q", got)
	}
	normalized, err := normalizeOrigin("https://verifier.example/")
	if err != nil {
		t.Fatalf("normalizeOrigin: %v", err)
	}
	if normalized != "https://verifier.example" {
		t.Fatalf("normalizeOrigin must drop the trailing slash: %q", normalized)
	}
	if _, err := normalizeOrigin("https://verifier.example/path"); err == nil {
		t.Fatal("normalizeOrigin must reject an origin with a path")
	}

	dcapiSession := &requestSession{ResponseMode: responseModeDCAPIJWT, Origin: "https://verifier.example", ClientID: "x509_hash:abc"}
	if got := dcapiSession.expectedResponseAudience(); got != "origin:https://verifier.example" {
		t.Fatalf("dc_api session audience must be origin-prefixed, got %q", got)
	}
	redirectSession := &requestSession{ResponseMode: responseModeDirectPostJWT, ClientID: "x509_hash:abc"}
	if got := redirectSession.expectedResponseAudience(); got != "x509_hash:abc" {
		t.Fatalf("redirect session audience must be client_id, got %q", got)
	}
}

// TestExtractDCQLKeyedSDJWT confirms DCQL-keyed SD-JWT vp_tokens (OID4VP 1.0
// Appendix B.2, used on the DC API path) are unwrapped to the bare compact
// serialization, while mdoc and JSON-LD tokens are left untouched.
func TestExtractDCQLKeyedSDJWT(t *testing.T) {
	sdjwt := "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.sig~WyJzYWx0IiwiZGVncmVlIiwiQlNjII0~kbjwt"
	keyed, _ := json.Marshal(map[string][]string{"university_degree": {sdjwt}})
	got, ok := extractDCQLKeyedSDJWT(string(keyed))
	if !ok || got != sdjwt {
		t.Fatalf("expected to unwrap keyed SD-JWT, ok=%v got=%q", ok, got)
	}
	// Single-string value form.
	keyedSingle, _ := json.Marshal(map[string]string{"university_degree": sdjwt})
	if got, ok := extractDCQLKeyedSDJWT(string(keyedSingle)); !ok || got != sdjwt {
		t.Fatalf("expected to unwrap single-string keyed SD-JWT, ok=%v got=%q", ok, got)
	}
	// mdoc keyed (base64url, no "~") must not be claimed.
	if _, ok := extractDCQLKeyedSDJWT(`{"mdl":["aGVsbG8"]}`); ok {
		t.Fatal("mdoc keyed vp_token must not be treated as SD-JWT")
	}
	// Bare SD-JWT (not keyed) is returned untouched by the caller, so this helper
	// must not match it (it does not start with "{").
	if _, ok := extractDCQLKeyedSDJWT(sdjwt); ok {
		t.Fatal("bare SD-JWT must not be matched by the keyed unwrapper")
	}
}

// newHAIPMdocVerifierServer is newMdocVerifierServer with a DNS-name base URL so
// the HAIP-mandated x509_hash Client Identifier Prefix signer is available
// (the ephemeral x509 signer is only created for DNS-name hosts).
func newHAIPMdocVerifierServer(t *testing.T, trust *mdoc.IssuerPKI) (*Plugin, string) {
	t.Helper()
	p, server := newMdocVerifierServer(t, trust)
	p.baseURL = "https://verifier.example"
	if err := p.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure verifier identities for HAIP: %v", err)
	}
	if _, ok := p.supportedClientIDSchemes[ClientIDSchemeX509Hash]; !ok {
		t.Fatal("x509_hash scheme is not available after HAIP reconfiguration")
	}
	return p, server.URL
}

type dcapiCreateResponse struct {
	RequestID        string   `json:"request_id"`
	ClientID         string   `json:"client_id"`
	Nonce            string   `json:"nonce"`
	State            string   `json:"state"`
	ResponseMode     string   `json:"response_mode"`
	Origin           string   `json:"origin"`
	ResponseAudience string   `json:"response_audience"`
	EncValues        []string `json:"encrypted_response_enc_values_supported"`
	Profile          string   `json:"profile"`
}

func createDCAPIMdocRequest(t *testing.T, serverURL, origin string) dcapiCreateResponse {
	t.Helper()
	createBody, _ := json.Marshal(map[string]interface{}{
		"profile":       profileHAIP,
		"response_mode": responseModeDCAPIJWT,
		"origin":        origin,
		"dcql_query":    json.RawMessage(mdocDCQLQuery),
	})
	resp, err := http.Post(serverURL+"/oid4vp/request/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create dc_api request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(resp.Body)
		t.Fatalf("create dc_api request status %d: %s", resp.StatusCode, body.String())
	}
	var created dcapiCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode dc_api create response: %v", err)
	}
	return created
}

// TestHAIPDCAPIRequestShape verifies a HAIP dc_api.jwt request: it uses the
// x509_hash Client Identifier Prefix, binds the Origin (no response_uri),
// advertises both A128GCM and A256GCM, and exposes the origin-prefixed response
// audience (HAIP 1.0 Section 5 / 5.2; OID4VP 1.0 Appendix A).
func TestHAIPDCAPIRequestShape(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, pki := issueMdocForVerifier(t, deviceKey)
	_, serverURL := newHAIPMdocVerifierServer(t, pki)

	created := createDCAPIMdocRequest(t, serverURL, "https://verifier.example")
	if !strings.HasPrefix(created.ClientID, string(ClientIDSchemeX509Hash)+":") {
		t.Fatalf("HAIP request must use x509_hash client_id, got %q", created.ClientID)
	}
	if created.Origin != "https://verifier.example" {
		t.Fatalf("expected bound origin, got %q", created.Origin)
	}
	if created.ResponseAudience != "origin:https://verifier.example" {
		t.Fatalf("expected origin-prefixed response audience, got %q", created.ResponseAudience)
	}
	if len(created.EncValues) != 2 || created.EncValues[0] != encA128GCM || created.EncValues[1] != encA256GCM {
		t.Fatalf("HAIP must advertise both A128GCM and A256GCM, got %v", created.EncValues)
	}
}

func TestHAIPDirectPostJWTSDJWTProvisionsECDHESEncryption(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, pki := issueMdocForVerifier(t, deviceKey)
	p, serverURL := newHAIPMdocVerifierServer(t, pki)
	sdjwtDCQL := `{"credentials":[{"id":"degree","format":"dc+sd-jwt","meta":{"vct_values":["https://protocolsoup.com/credentials/university_degree"]}}]}`
	if dcqlRequestsMdoc(sdjwtDCQL) {
		t.Fatal("test query must exercise the non-mdoc HAIP branch")
	}

	createBody, _ := json.Marshal(map[string]interface{}{
		"profile":       profileHAIP,
		"response_mode": responseModeDirectPostJWT,
		"response_uri":  serverURL + "/oid4vp/response",
		"dcql_query":    json.RawMessage(sdjwtDCQL),
	})
	resp, err := http.Post(serverURL+"/oid4vp/request/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create HAIP direct_post.jwt request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(resp.Body)
		t.Fatalf("create HAIP direct_post.jwt request status %d: %s", resp.StatusCode, body.String())
	}
	var created dcapiCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	if session == nil || session.ResponseEncryptionJWK == nil {
		t.Fatal("HAIP direct_post.jwt SD-JWT request must provision an ECDH-ES response key")
	}
	if len(created.EncValues) != 2 || created.EncValues[0] != encA128GCM || created.EncValues[1] != encA256GCM {
		t.Fatalf("HAIP must advertise both AES-GCM values, got %v", created.EncValues)
	}
}

// TestInjectMdocTrustedAuthorities pins the AKI Trusted Authorities Query
// injection (OID4VP 1.0 Section 6.1.1; HAIP 1.0 Section 5): an mso_mdoc
// credential without trusted_authorities gains the configured AKI, a credential
// that already declares trusted_authorities is left untouched, a non-mdoc
// credential is never modified, and an empty AKI set is a no-op.
func TestInjectMdocTrustedAuthorities(t *testing.T) {
	akis := []string{"sBdpcyfYjLDg7e6_KdjQQX2v8jY"}

	t.Run("injects for mso_mdoc without trusted_authorities", func(t *testing.T) {
		out, changed, err := injectMdocTrustedAuthorities([]byte(mdocDCQLQuery), akis)
		if err != nil || !changed {
			t.Fatalf("expected injection, changed=%v err=%v", changed, err)
		}
		req := vc.ParseDCQLCredentialRequirements(string(out))
		if len(req) != 1 || len(req[0].TrustedAuthorities) != 1 {
			t.Fatalf("expected one trusted authority, got %+v", req)
		}
		if req[0].TrustedAuthorities[0].Type != "aki" || req[0].TrustedAuthorities[0].Values[0] != akis[0] {
			t.Fatalf("unexpected trusted authority: %+v", req[0].TrustedAuthorities[0])
		}
	})

	t.Run("preserves an explicit trusted_authorities", func(t *testing.T) {
		explicit := `{"credentials":[{"id":"mdl","format":"mso_mdoc","trusted_authorities":[{"type":"etsi_tl","values":["https://tl.example"]}]}]}`
		out, changed, err := injectMdocTrustedAuthorities([]byte(explicit), akis)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if changed {
			t.Fatal("an explicit trusted_authorities must not be overridden")
		}
		_ = out
	})

	t.Run("never touches non-mdoc credentials", func(t *testing.T) {
		sdjwt := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`
		_, changed, err := injectMdocTrustedAuthorities([]byte(sdjwt), akis)
		if err != nil || changed {
			t.Fatalf("non-mdoc credential must be untouched, changed=%v err=%v", changed, err)
		}
	})

	t.Run("no AKI configured is a no-op", func(t *testing.T) {
		_, changed, err := injectMdocTrustedAuthorities([]byte(mdocDCQLQuery), nil)
		if err != nil || changed {
			t.Fatalf("empty AKI set must be a no-op, changed=%v err=%v", changed, err)
		}
	})
}

// TestHAIPMdocRequestAdvertisesAKITrustedAuthority proves the verifier emits the
// AKI Trusted Authorities Query (HAIP 1.0 Section 5) in a HAIP mso_mdoc request,
// with the value equal to the base64url SubjectKeyIdentifier of the configured
// IACA root: the same root the verifier chains the presented credential to.
func TestHAIPMdocRequestAdvertisesAKITrustedAuthority(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, pki := issueMdocForVerifier(t, deviceKey)
	p, serverURL := newHAIPMdocVerifierServer(t, pki)
	// The test harness sets the trust-anchor pool directly; also retain the
	// parsed root so the AKI query can be derived from its SubjectKeyIdentifier.
	p.mdocTrustAnchorCerts = []*x509.Certificate{pki.IACACertificate()}

	created := createDCAPIMdocRequest(t, serverURL, "https://verifier.example")

	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	if session == nil {
		t.Fatal("no session recorded for the created request")
		return
	}

	requirements := vc.ParseDCQLCredentialRequirements(session.DCQLQuery)
	if len(requirements) != 1 || len(requirements[0].TrustedAuthorities) != 1 {
		t.Fatalf("HAIP mdoc request must carry one AKI trusted authority, got %s", session.DCQLQuery)
	}
	authority := requirements[0].TrustedAuthorities[0]
	if authority.Type != "aki" {
		t.Fatalf("expected aki trusted-authority type, got %q", authority.Type)
	}
	expected := base64.RawURLEncoding.EncodeToString(pki.IACACertificate().SubjectKeyId)
	if len(authority.Values) != 1 || authority.Values[0] != expected {
		t.Fatalf("AKI value must equal base64url(IACA SubjectKeyId) %q, got %v", expected, authority.Values)
	}
}

// TestDCAPIMdocRoundTripHAIP is the full OpenID4VP-over-DC-API mdoc presentation
// under HAIP: the verifier creates a dc_api.jwt request bound to its Origin and
// x509_hash identity (advertising an ephemeral ECDH-ES key); the wallet builds
// a DeviceResponse over the OpenID4VPDCAPIHandover (origin + nonce + verifier
// enc-key thumbprint), encrypts the DCQL-keyed vp_token with A256GCM, and
// submits it correlated by request_id (the DC API has no state). The verifier
// reconstructs the DC API handover and accepts it.
func TestDCAPIMdocRoundTripHAIP(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)
	p, serverURL := newHAIPMdocVerifierServer(t, pki)

	created := createDCAPIMdocRequest(t, serverURL, "https://verifier.example")

	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	if session == nil || session.ResponseEncryptionJWK == nil {
		t.Fatal("verifier did not provision a dc_api ECDH-ES response-encryption key")
	}
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = ""
	thumb, err := verifierEncPub.ThumbprintBytes()
	if err != nil {
		t.Fatalf("ThumbprintBytes: %v", err)
	}

	// Wallet builds the DC API handover (Appendix B.2.6.2), NOT the redirect
	// handover, from the bound Origin.
	handover, err := mdoc.NewOpenID4VPDCAPIHandover(created.Origin, created.Nonce, thumb)
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPIHandover: %v", err)
	}
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)
	vpToken, err := encodeMdocVPToken("mdl", wire)
	if err != nil {
		t.Fatalf("encodeMdocVPToken: %v", err)
	}
	// HAIP 1.0 Section 5: A256GCM is in profile and SHOULD be preferred.
	compactJWE, err := encryptECDHESResponse(verifierEncPub, vpToken, "", jose.A256GCM)
	if err != nil {
		t.Fatalf("encryptECDHESResponse: %v", err)
	}

	// DC API responses carry no state; correlate by request_id.
	respondBody, _ := json.Marshal(map[string]interface{}{"request_id": created.RequestID, "response": compactJWE})
	respond, err := http.Post(serverURL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post dc_api response: %v", err)
	}
	defer respond.Body.Close()
	if respond.StatusCode != http.StatusOK {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(respond.Body)
		t.Fatalf("dc_api response status %d: %s", respond.StatusCode, body.String())
	}
	var outcome struct {
		Policy struct {
			Allowed     bool     `json:"allowed"`
			Code        string   `json:"code"`
			ReasonCodes []string `json:"reason_codes"`
		} `json:"policy"`
	}
	if err := json.NewDecoder(respond.Body).Decode(&outcome); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}
	if !outcome.Policy.Allowed {
		t.Fatalf("expected DC API mdoc presentation to be allowed, got code=%q reasons=%v", outcome.Policy.Code, outcome.Policy.ReasonCodes)
	}
}

// TestDCAPIMdocRejectsRedirectHandover proves the DC API path requires the DC
// API handover: a DeviceResponse built over the redirect handover
// (OpenID4VPHandover) is rejected because the verifier reconstructs the
// OpenID4VPDCAPIHandover, so device authentication over the wrong transcript
// fails. Conflating the two would silently break the DC API path.
func TestDCAPIMdocRejectsRedirectHandover(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)
	p, serverURL := newHAIPMdocVerifierServer(t, pki)

	created := createDCAPIMdocRequest(t, serverURL, "https://verifier.example")
	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = ""
	thumb, _ := verifierEncPub.ThumbprintBytes()

	// Wrong: redirect handover instead of the DC API handover.
	redirect := realHandover(t, created.ClientID, created.Nonce, "https://verifier.example/response", thumb)
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, redirect)
	vpToken, _ := encodeMdocVPToken("mdl", wire)
	compactJWE, err := encryptECDHESResponse(verifierEncPub, vpToken, "", jose.A256GCM)
	if err != nil {
		t.Fatalf("encryptECDHESResponse: %v", err)
	}

	respondBody, _ := json.Marshal(map[string]interface{}{"request_id": created.RequestID, "response": compactJWE})
	respond, err := http.Post(serverURL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post dc_api response: %v", err)
	}
	defer respond.Body.Close()
	var outcome struct {
		Policy struct {
			Allowed bool `json:"allowed"`
		} `json:"policy"`
	}
	if err := json.NewDecoder(respond.Body).Decode(&outcome); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}
	if outcome.Policy.Allowed {
		t.Fatal("expected denial when the wallet used the redirect handover on the DC API path")
	}
}

// TestDCAPIMdocWrongOriginRejected proves the Origin binding: a DeviceResponse
// whose DC API handover uses a different Origin than the request fails device
// authentication (the verifier reconstructs the handover from its bound Origin).
func TestDCAPIMdocWrongOriginRejected(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)
	p, serverURL := newHAIPMdocVerifierServer(t, pki)

	created := createDCAPIMdocRequest(t, serverURL, "https://verifier.example")
	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = ""
	thumb, _ := verifierEncPub.ThumbprintBytes()

	// Wrong Origin in the handover.
	handover, err := mdoc.NewOpenID4VPDCAPIHandover("https://attacker.example", created.Nonce, thumb)
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPIHandover: %v", err)
	}
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)
	vpToken, _ := encodeMdocVPToken("mdl", wire)
	compactJWE, err := encryptECDHESResponse(verifierEncPub, vpToken, "", jose.A128GCM)
	if err != nil {
		t.Fatalf("encryptECDHESResponse: %v", err)
	}

	respondBody, _ := json.Marshal(map[string]interface{}{"request_id": created.RequestID, "response": compactJWE})
	respond, err := http.Post(serverURL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post dc_api response: %v", err)
	}
	defer respond.Body.Close()
	var outcome struct {
		Policy struct {
			Allowed bool `json:"allowed"`
		} `json:"policy"`
	}
	if err := json.NewDecoder(respond.Body).Decode(&outcome); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}
	if outcome.Policy.Allowed {
		t.Fatal("expected denial when the DC API handover Origin does not match the request Origin")
	}
}

// buildDCAPIJWTVPToken builds the SD-JWT-family vp_token (a signed vp+jwt that
// embeds the wallet's SD-JWT VC) the wallet returns over the DC API, bound to
// the origin-prefixed response audience (OID4VP 1.0 Appendix A.4) rather than
// the redirect path's client_id audience.
func buildDCAPIJWTVPToken(t *testing.T, wallet *walletFixture, audience, nonce string) string {
	t.Helper()
	pubJWK, found := wallet.KeySet.GetJWKByID(wallet.KeySet.RSAKeyID())
	if !found {
		t.Fatalf("wallet rsa jwk unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   wallet.Subject,
		"sub":   wallet.Subject,
		"aud":   audience,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"jti":   "dcapi-vp-" + wallet.Subject,
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
		t.Fatalf("sign dc_api vp token: %v", err)
	}
	return signed
}

// TestDCAPISDJWTRoundTripHAIP is the full OpenID4VP-over-DC-API presentation for
// the SD-JWT VC family under HAIP: the verifier creates a dc_api.jwt request
// (x509_hash identity, Origin-bound, ECDH-ES key advertised), the wallet returns
// a vp+jwt bound to the origin: audience, encrypts it to the verifier key with
// A256GCM, and submits it correlated by request_id. This proves the DC API path
// works for both credential formats, not only mdoc.
func TestDCAPISDJWTRoundTripHAIP(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()

	// HAIP's x509_hash Client Identifier Prefix requires a DNS-name verifier
	// base URL for the ephemeral signer; credential issuance still runs against
	// the httptest server URL.
	env.vpPlugin.baseURL = "https://verifier.example"
	if err := env.vpPlugin.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure HAIP verifier identities: %v", err)
	}

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")

	createBody, _ := json.Marshal(map[string]interface{}{
		"profile":       profileHAIP,
		"response_mode": responseModeDCAPIJWT,
		"origin":        "https://verifier.example",
		// Select the SD-JWT VC family explicitly. The verifier's
		// implicit default DCQL targets the mDL mso_mdoc, so these SD-JWT DC API
		// tests name their format explicitly.
		"dcql_query": map[string]interface{}{
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
		},
	})
	resp, err := http.Post(env.Server.URL+"/oid4vp/request/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create dc_api sd-jwt request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(resp.Body)
		t.Fatalf("create dc_api sd-jwt request status %d: %s", resp.StatusCode, body.String())
	}
	var created dcapiCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !strings.HasPrefix(created.ClientID, string(ClientIDSchemeX509Hash)+":") {
		t.Fatalf("expected x509_hash client_id, got %q", created.ClientID)
	}
	if created.ResponseAudience != "origin:https://verifier.example" {
		t.Fatalf("expected origin audience, got %q", created.ResponseAudience)
	}

	env.vpPlugin.mu.RLock()
	session := env.vpPlugin.requests[created.RequestID]
	env.vpPlugin.mu.RUnlock()
	if session == nil || session.ResponseEncryptionJWK == nil {
		t.Fatal("verifier did not provision a dc_api ECDH-ES response-encryption key")
	}
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = ""

	vpToken := buildDCAPIJWTVPToken(t, wallet, created.ResponseAudience, created.Nonce)
	compactJWE, err := encryptECDHESResponse(verifierEncPub, vpToken, "", jose.A256GCM)
	if err != nil {
		t.Fatalf("encryptECDHESResponse: %v", err)
	}

	respondBody, _ := json.Marshal(map[string]interface{}{"request_id": created.RequestID, "response": compactJWE})
	respond, err := http.Post(env.Server.URL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post dc_api sd-jwt response: %v", err)
	}
	defer respond.Body.Close()
	if respond.StatusCode != http.StatusOK {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(respond.Body)
		t.Fatalf("dc_api sd-jwt response status %d: %s", respond.StatusCode, body.String())
	}
	var outcome struct {
		Policy struct {
			Allowed     bool     `json:"allowed"`
			Code        string   `json:"code"`
			ReasonCodes []string `json:"reason_codes"`
		} `json:"policy"`
	}
	if err := json.NewDecoder(respond.Body).Decode(&outcome); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}
	if !outcome.Policy.Allowed {
		t.Fatalf("expected DC API SD-JWT presentation to be allowed, got code=%q reasons=%v", outcome.Policy.Code, outcome.Policy.ReasonCodes)
	}
}

// TestDCAPISDJWTWrongAudienceRejected proves the origin-bound audience is
// enforced for the SD-JWT family on the DC API path: a vp+jwt bound to the
// verifier's client_id (the redirect-path audience) instead of the origin:
// audience is rejected.
func TestDCAPISDJWTWrongAudienceRejected(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()
	env.vpPlugin.baseURL = "https://verifier.example"
	if err := env.vpPlugin.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure HAIP verifier identities: %v", err)
	}

	wallet := issueCredentialForWallet(t, env.Server.URL, "alice")
	createBody, _ := json.Marshal(map[string]interface{}{
		"profile":       profileHAIP,
		"response_mode": responseModeDCAPIJWT,
		"origin":        "https://verifier.example",
		// Select the SD-JWT VC family explicitly. The verifier's
		// implicit default DCQL targets the mDL mso_mdoc, so these SD-JWT DC API
		// tests name their format explicitly.
		"dcql_query": map[string]interface{}{
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
		},
	})
	resp, err := http.Post(env.Server.URL+"/oid4vp/request/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	var created dcapiCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	env.vpPlugin.mu.RLock()
	session := env.vpPlugin.requests[created.RequestID]
	env.vpPlugin.mu.RUnlock()
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = ""

	// Wrong: bind to client_id, not the origin: audience.
	vpToken := buildDCAPIJWTVPToken(t, wallet, created.ClientID, created.Nonce)
	compactJWE, err := encryptECDHESResponse(verifierEncPub, vpToken, "", jose.A256GCM)
	if err != nil {
		t.Fatalf("encryptECDHESResponse: %v", err)
	}

	respondBody, _ := json.Marshal(map[string]interface{}{"request_id": created.RequestID, "response": compactJWE})
	respond, err := http.Post(env.Server.URL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post response: %v", err)
	}
	defer respond.Body.Close()
	var outcome struct {
		Policy struct {
			Allowed     bool     `json:"allowed"`
			ReasonCodes []string `json:"reason_codes"`
		} `json:"policy"`
	}
	if err := json.NewDecoder(respond.Body).Decode(&outcome); err != nil {
		t.Fatalf("decode outcome: %v", err)
	}
	if outcome.Policy.Allowed {
		t.Fatalf("expected denial when the SD-JWT audience is the client_id instead of origin: (reasons=%v)", outcome.Policy.ReasonCodes)
	}
}
