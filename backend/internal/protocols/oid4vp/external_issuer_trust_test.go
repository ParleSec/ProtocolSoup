package oid4vp

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidateSDJWTCredentialStatusUsesCredentialIssuerKeyWithoutTrustAnchorPEM(t *testing.T) {
	leafKey, chainDER := createECDSACertificateChain(t, []string{"issuer.example"}, "Status List Signer")
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oid4vci/status-lists/haip-sd-jwt-1" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Accept"); got != "application/statuslist+jwt" {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(token))
	}))
	defer server.Close()
	statusURI := server.URL + "/oid4vci/status-lists/haip-sd-jwt-1"
	token = signStatusListToken(t, leafKey, chainDER[:1], statusURI, compressedZeroStatusList(t))

	verifier := &Plugin{baseURL: server.URL}
	issuerJWK := crypto.JWKFromECPublicKey(&leafKey.PublicKey, "")
	err := verifier.validateSDJWTCredentialStatus(map[string]interface{}{
		"status_list": map[string]interface{}{
			"idx": float64(0),
			"uri": statusURI,
		},
	}, []crypto.JWK{issuerJWK})
	if err != nil {
		t.Fatalf("validateSDJWTCredentialStatus: %v", err)
	}
}

func TestValidateSDJWTCredentialStatusRequiresIssuerKey(t *testing.T) {
	leafKey, chainDER := createECDSACertificateChain(t, []string{"issuer.example"}, "Status List Signer")
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(token))
	}))
	defer server.Close()
	statusURI := server.URL + "/oid4vci/status-lists/haip-sd-jwt-1"
	token = signStatusListToken(t, leafKey, chainDER[:1], statusURI, compressedZeroStatusList(t))

	verifier := &Plugin{baseURL: server.URL}
	err := verifier.validateSDJWTCredentialStatus(map[string]interface{}{
		"status_list": map[string]interface{}{
			"idx": float64(0),
			"uri": statusURI,
		},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "credential issuer key is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateSDJWTCredentialStatusRejectsMismatchedSigner(t *testing.T) {
	leafKey, chainDER := createECDSACertificateChain(t, []string{"issuer.example"}, "Status List Signer")
	otherKey, _ := createECDSACertificateChain(t, []string{"other.example"}, "Other Signer")
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(token))
	}))
	defer server.Close()
	statusURI := server.URL + "/oid4vci/status-lists/haip-sd-jwt-1"
	token = signStatusListToken(t, leafKey, chainDER[:1], statusURI, compressedZeroStatusList(t))

	verifier := &Plugin{baseURL: server.URL}
	err := verifier.validateSDJWTCredentialStatus(map[string]interface{}{
		"status_list": map[string]interface{}{
			"idx": float64(0),
			"uri": statusURI,
		},
	}, []crypto.JWK{crypto.JWKFromECPublicKey(&otherKey.PublicKey, "")})
	if err == nil || !strings.Contains(err.Error(), "does not match the credential issuer key") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateSDJWTCredentialStatusSurfacesHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer server.Close()
	statusURI := server.URL + "/oid4vci/status-lists/haip-sd-jwt-1"
	leafKey, _ := createECDSACertificateChain(t, []string{"issuer.example"}, "Status List Signer")

	verifier := &Plugin{baseURL: server.URL}
	err := verifier.validateSDJWTCredentialStatus(map[string]interface{}{
		"status_list": map[string]interface{}{
			"idx": float64(0),
			"uri": statusURI,
		},
	}, []crypto.JWK{crypto.JWKFromECPublicKey(&leafKey.PublicKey, "")})
	if err == nil || !strings.Contains(err.Error(), "status list returned HTTP 500") {
		t.Fatalf("error = %v", err)
	}

	policyErr := newVerifierPolicyError("credential_status_invalid", "presented credential status validation failed", err)
	if !strings.Contains(policyErr.Error(), "status list returned HTTP 500") {
		t.Fatalf("policy error dropped cause: %v", policyErr)
	}
}

func TestValidateSDJWTCredentialStatusRejectsRevokedIndex(t *testing.T) {
	leafKey, chainDER := createECDSACertificateChain(t, []string{"issuer.example"}, "Status List Signer")
	revoked := []byte{0x01}
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/statuslist+jwt")
		_, _ = w.Write([]byte(token))
	}))
	defer server.Close()
	statusURI := server.URL + "/oid4vci/status-lists/haip-sd-jwt-1"
	token = signStatusListToken(t, leafKey, chainDER[:1], statusURI, compressedStatusListBytes(t, revoked))

	verifier := &Plugin{baseURL: server.URL}
	err := verifier.validateSDJWTCredentialStatus(map[string]interface{}{
		"status_list": map[string]interface{}{
			"idx": float64(0),
			"uri": statusURI,
		},
	}, []crypto.JWK{crypto.JWKFromECPublicKey(&leafKey.PublicKey, "")})
	if err == nil || !strings.Contains(err.Error(), "credential status is not valid") {
		t.Fatalf("error = %v", err)
	}
}

func TestOwnStatusListURIRejectsUnrelatedPaths(t *testing.T) {
	verifier := &Plugin{baseURL: "https://protocolsoup.com"}
	if verifier.isOwnStatusListURI("https://protocolsoup.com/admin") {
		t.Fatal("unrelated path must not be treated as this issuer's status list")
	}
	if verifier.isOwnStatusListURI("https://evil.example/oid4vci/status-lists/haip-sd-jwt-1") {
		t.Fatal("foreign host must not be treated as this issuer's status list")
	}
	if !verifier.isOwnStatusListURI("https://protocolsoup.com/oid4vci/status-lists/haip-sd-jwt-1") {
		t.Fatal("expected own status list URI")
	}
}

func signStatusListToken(t *testing.T, leafKey *ecdsa.PrivateKey, chainDER [][]byte, statusURI, lst string) string {
	t.Helper()
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"sub": statusURI,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"status_list": map[string]interface{}{
			"bits": 1,
			"lst":  lst,
		},
	})
	token.Header["typ"] = "statuslist+jwt"
	encoded := make([]string, 0, len(chainDER))
	for _, certificate := range chainDER {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(certificate))
	}
	token.Header["x5c"] = encoded
	signed, err := token.SignedString(leafKey)
	if err != nil {
		t.Fatalf("sign status list: %v", err)
	}
	return signed
}

func compressedZeroStatusList(t *testing.T) string {
	t.Helper()
	return compressedStatusListBytes(t, make([]byte, 16))
}

func compressedStatusListBytes(t *testing.T, bits []byte) string {
	t.Helper()
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(bits); err != nil {
		t.Fatalf("compress status list: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close status list compressor: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(compressed.Bytes())
}
