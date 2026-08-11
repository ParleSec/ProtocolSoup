package oid4vp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

// buildMdocDeviceResponse builds the wire-encoded DeviceResponse a wallet would
// produce for the given handover (the real OpenID4VPHandover).
func buildMdocDeviceResponse(t *testing.T, deviceKey *ecdsa.PrivateKey, issuerSigned mdoc.IssuerSigned, handover []byte) []byte {
	t.Helper()
	st, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	transcript, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	requested := map[mdoc.NameSpace][]string{mdoc.NameSpaceMDL: {"family_name", "document_number"}}
	response, err := mdoc.BuildDeviceResponse(deviceKey, issuerSigned, mdoc.DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}
	wire, err := mdoc.EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse: %v", err)
	}
	return wire
}

// TestEncodeDecodeMdocVPToken pins the OID4VP 1.0 DCQL vp_token shape: a JSON
// object keyed by the DCQL credential id whose value is an array of base64url
// DeviceResponse strings, and round-trips it back to the DeviceResponse bytes.
func TestEncodeDecodeMdocVPToken(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, _ := issueMdocForVerifier(t, deviceKey)
	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)

	vpToken, err := encodeMdocVPToken("mdl", wire)
	if err != nil {
		t.Fatalf("encodeMdocVPToken: %v", err)
	}

	// Shape: {"mdl":["<base64url>"]}.
	var keyed map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &keyed); err != nil {
		t.Fatalf("vp_token is not a DCQL-keyed object: %v", err)
	}
	if len(keyed["mdl"]) != 1 {
		t.Fatalf("expected one presentation under DCQL id mdl, got %v", keyed)
	}
	if _, err := base64.RawURLEncoding.DecodeString(keyed["mdl"][0]); err != nil {
		t.Fatalf("vp_token value must be base64url: %v", err)
	}

	presentations, ok := extractMdocPresentations(vpToken)
	if !ok || len(presentations) != 1 {
		t.Fatalf("extractMdocPresentations did not round-trip the keyed vp_token: ok=%v n=%d", ok, len(presentations))
	}
	if presentations[0].DCQLID != "mdl" {
		t.Fatalf("expected DCQL id mdl, got %q", presentations[0].DCQLID)
	}
	if !bytes.Equal(presentations[0].Raw, wire) {
		t.Fatal("round-tripped DeviceResponse bytes differ from the original")
	}
}

// TestExtractMdocPresentationsBareForm confirms the bare base64url DeviceResponse
// form (non-DCQL) is still accepted, with an empty DCQL id.
func TestExtractMdocPresentationsBareForm(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, _ := issueMdocForVerifier(t, deviceKey)
	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", nil)
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)
	bare := base64.RawURLEncoding.EncodeToString(wire)

	presentations, ok := extractMdocPresentations(bare)
	if !ok || len(presentations) != 1 {
		t.Fatalf("bare DeviceResponse not extracted: ok=%v n=%d", ok, len(presentations))
	}
	if presentations[0].DCQLID != "" {
		t.Fatalf("bare form should have empty DCQL id, got %q", presentations[0].DCQLID)
	}
}

// TestEncryptDecryptMdocResponseRoundTrip exercises the OID4VP 1.0 Section 8.3
// encrypted response: ECDH-ES + A128GCM to the verifier's enc key, with the
// vp_token + state carried as top-level JSON members of the JWE payload.
func TestEncryptDecryptMdocResponseRoundTrip(t *testing.T) {
	priv, pub, err := newMdocResponseEncryptionKey("enc-kid-1")
	if err != nil {
		t.Fatalf("newMdocResponseEncryptionKey: %v", err)
	}

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, _ := issueMdocForVerifier(t, deviceKey)
	thumb, err := pub.ThumbprintBytes()
	if err != nil {
		t.Fatalf("ThumbprintBytes: %v", err)
	}
	handover := realHandover(t, "verifier-client-1", "nonce-xyz", "https://verifier.example/response", thumb)
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)
	vpToken, err := encodeMdocVPToken("mdl", wire)
	if err != nil {
		t.Fatalf("encodeMdocVPToken: %v", err)
	}

	compactJWE, err := encryptMdocResponse(pub, vpToken, "state-123")
	if err != nil {
		t.Fatalf("encryptMdocResponse: %v", err)
	}
	if parts := strings.Split(compactJWE, "."); len(parts) != 5 {
		t.Fatalf("expected a compact JWE with 5 parts, got %d", len(parts))
	}

	gotVPToken, gotState, err := decryptMdocResponse(compactJWE, priv)
	if err != nil {
		t.Fatalf("decryptMdocResponse: %v", err)
	}
	if gotState != "state-123" {
		t.Fatalf("state mismatch: %q", gotState)
	}
	if gotVPToken != vpToken {
		t.Fatalf("vp_token mismatch after decrypt:\n got: %s\nwant: %s", gotVPToken, vpToken)
	}
}

func TestEncryptedResponseSessionCorrelationDoesNotRequireKid(t *testing.T) {
	privateJWK, publicJWK, err := newMdocResponseEncryptionKey("session-key")
	if err != nil {
		t.Fatalf("newMdocResponseEncryptionKey: %v", err)
	}
	publicJWK.Kid = ""
	compactJWE, err := encryptMdocResponse(publicJWK, `{"credential":["example"]}`, "state-123")
	if err != nil {
		t.Fatalf("encryptMdocResponse: %v", err)
	}

	verifier := NewPlugin()
	verifier.requests["request-123"] = &requestSession{
		ID:                    "request-123",
		State:                 "state-123",
		ResponseEncryptionJWK: &privateJWK,
		ExpiresAt:             time.Now().Add(time.Minute),
	}
	requestID, session := verifier.requestSessionForEncryptedResponse(compactJWE)
	if requestID != "request-123" || session == nil || session.ID != "request-123" {
		t.Fatalf("correlated request = %q, %#v", requestID, session)
	}
}

// newMdocVerifierServer initializes a single OID4VP verifier plugin behind an
// httptest server, with the supplied IACA trust anchor.
func newMdocVerifierServer(t *testing.T, trust *mdoc.IssuerPKI) (*Plugin, *httptest.Server) {
	t.Helper()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new key set: %v", err)
	}
	p := NewPlugin()
	if err := p.Initialize(context.Background(), plugin.PluginConfig{BaseURL: "http://localhost:8080", KeySet: keySet}); err != nil {
		t.Fatalf("initialize oid4vp plugin: %v", err)
	}
	p.mdocTrustAnchors = trust.TrustAnchors()

	router := chi.NewRouter()
	router.Route("/oid4vp", func(r chi.Router) { p.RegisterRoutes(r) })
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	p.baseURL = server.URL
	p.didWebAllowedHosts = p.allowedDIDWebHosts()
	p.trustResolver = NewDIDWebResolver(p.didWebAllowedHosts)
	if err := p.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure verifier identities: %v", err)
	}
	return p, server
}

// TestMdocOnlineProfileEncryptedRoundTrip is the full OID4VP 1.0 mdoc online
// profile through the HTTP handlers: the verifier creates a direct_post.jwt
// request with an mso_mdoc DCQL query (provisioning an ECDH-ES response
// encryption key in client_metadata), the wallet builds a DeviceResponse over
// the reconstructed handover (bound to the verifier enc key thumbprint),
// encrypts the DCQL-keyed vp_token, posts it, and the verifier decrypts and
// accepts it.
func TestMdocOnlineProfileEncryptedRoundTrip(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)
	p, server := newMdocVerifierServer(t, pki)

	// 1. Verifier creates the mdoc direct_post.jwt request.
	createBody, _ := json.Marshal(map[string]interface{}{
		"response_mode": "direct_post.jwt",
		"dcql_query":    json.RawMessage(mdocDCQLQuery),
	})
	resp, err := http.Post(server.URL+"/oid4vp/request/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create request status %d", resp.StatusCode)
	}
	var created struct {
		RequestID    string `json:"request_id"`
		ClientID     string `json:"client_id"`
		Nonce        string `json:"nonce"`
		State        string `json:"state"`
		ResponseURI  string `json:"response_uri"`
		ResponseMode string `json:"response_mode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ResponseMode != "direct_post.jwt" {
		t.Fatalf("expected direct_post.jwt, got %q", created.ResponseMode)
	}

	// The verifier provisioned an ECDH-ES response-encryption key on the session.
	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	if session == nil || session.ResponseEncryptionJWK == nil {
		t.Fatal("verifier did not provision an mdoc response-encryption key")
	}
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = "" // the wallet only ever sees the public half

	// 2. Wallet derives the handover from the request + the verifier enc key
	// thumbprint, builds the DeviceResponse, and the DCQL-keyed vp_token.
	thumb, err := verifierEncPub.ThumbprintBytes()
	if err != nil {
		t.Fatalf("ThumbprintBytes: %v", err)
	}
	handover := realHandover(t, created.ClientID, created.Nonce, created.ResponseURI, thumb)
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)
	vpToken, err := encodeMdocVPToken("mdl", wire)
	if err != nil {
		t.Fatalf("encodeMdocVPToken: %v", err)
	}

	// 3. Wallet encrypts the response to the verifier enc key and posts it.
	compactJWE, err := encryptMdocResponse(verifierEncPub, vpToken, created.State)
	if err != nil {
		t.Fatalf("encryptMdocResponse: %v", err)
	}
	respondBody, _ := json.Marshal(map[string]interface{}{"state": created.State, "response": compactJWE})
	respond, err := http.Post(server.URL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post response: %v", err)
	}
	defer respond.Body.Close()
	if respond.StatusCode != http.StatusOK {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(respond.Body)
		t.Fatalf("response status %d: %s", respond.StatusCode, body.String())
	}
	p.mu.RLock()
	result := p.requests[created.RequestID].Result
	p.mu.RUnlock()
	if result == nil || !result.Policy.Allowed {
		t.Fatalf("expected encrypted mdoc presentation to be allowed, got result=%+v", result)
	}
}

// TestMdocOnlineProfileThumbprintCouplingRejected proves the handover/JWE
// coupling: if the wallet builds the handover with a thumbprint other than the
// verifier's actual encryption key (e.g. a response re-encrypted to a different
// key), device authentication fails. This is the OID4VP 1.0 Appendix B.2.6
// anti-substitution protection.
func TestMdocOnlineProfileThumbprintCouplingRejected(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerSigned, pki := issueMdocForVerifier(t, deviceKey)
	p, server := newMdocVerifierServer(t, pki)

	createBody, _ := json.Marshal(map[string]interface{}{
		"response_mode": "direct_post.jwt",
		"dcql_query":    json.RawMessage(mdocDCQLQuery),
	})
	resp, err := http.Post(server.URL+"/oid4vp/request/create", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	var created struct {
		RequestID   string `json:"request_id"`
		ClientID    string `json:"client_id"`
		Nonce       string `json:"nonce"`
		State       string `json:"state"`
		ResponseURI string `json:"response_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	p.mu.RLock()
	session := p.requests[created.RequestID]
	p.mu.RUnlock()
	if session == nil || session.ResponseEncryptionJWK == nil {
		t.Fatal("verifier did not provision an mdoc response-encryption key")
	}
	verifierEncPub := *session.ResponseEncryptionJWK
	verifierEncPub.D = ""

	// Wallet builds the handover with a WRONG thumbprint (a different key).
	_, wrongPub, err := newMdocResponseEncryptionKey("attacker")
	if err != nil {
		t.Fatalf("newMdocResponseEncryptionKey: %v", err)
	}
	wrongThumb, _ := wrongPub.ThumbprintBytes()
	handover := realHandover(t, created.ClientID, created.Nonce, created.ResponseURI, wrongThumb)
	wire := buildMdocDeviceResponse(t, deviceKey, issuerSigned, handover)
	vpToken, _ := encodeMdocVPToken("mdl", wire)
	// Still encrypt to the real verifier key so the JWE itself decrypts.
	compactJWE, err := encryptMdocResponse(verifierEncPub, vpToken, created.State)
	if err != nil {
		t.Fatalf("encryptMdocResponse: %v", err)
	}

	respondBody, _ := json.Marshal(map[string]interface{}{"state": created.State, "response": compactJWE})
	respond, err := http.Post(server.URL+"/oid4vp/response", "application/json", bytes.NewReader(respondBody))
	if err != nil {
		t.Fatalf("post response: %v", err)
	}
	defer respond.Body.Close()
	if respond.StatusCode != http.StatusOK {
		t.Fatalf("response status %d", respond.StatusCode)
	}
	p.mu.RLock()
	result := p.requests[created.RequestID].Result
	p.mu.RUnlock()
	if result == nil || result.Policy.Allowed {
		t.Fatal("expected denial when the handover thumbprint does not match the verifier encryption key")
	}
}
