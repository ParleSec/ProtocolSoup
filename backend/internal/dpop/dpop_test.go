package dpop

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	internalcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

const testEndpoint = "https://as.example/oauth2/token"

type testSigner struct {
	method     jwt.SigningMethod
	privateKey interface{}
	jwk        internalcrypto.JWK
}

func newES256TestSigner(t *testing.T) testSigner {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{
		method:     jwt.SigningMethodES256,
		privateKey: privateKey,
		jwk:        internalcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "test-key"),
	}
}

func newEdDSATestSigner(t *testing.T) testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{
		method:     jwt.SigningMethodEdDSA,
		privateKey: priv,
		jwk:        internalcrypto.JWKFromEd25519PublicKey(pub, "test-key"),
	}
}

// sign builds a compact DPoP proof JWT. headerOverrides lets tests corrupt
// the header (e.g. alg confusion, private-key jwk) without hand-rolling JWS.
func (s testSigner) sign(t *testing.T, claims jwt.MapClaims, headerOverrides map[string]interface{}) string {
	t.Helper()
	token := jwt.NewWithClaims(s.method, claims)
	token.Header["typ"] = ProofTyp
	jwkMap, err := jwkToMap(s.jwk)
	if err != nil {
		t.Fatal(err)
	}
	token.Header["jwk"] = jwkMap
	for k, v := range headerOverrides {
		if v == nil {
			delete(token.Header, k)
			continue
		}
		token.Header[k] = v
	}
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func jwkToMap(jwk internalcrypto.JWK) (map[string]interface{}, error) {
	out := map[string]interface{}{"kty": jwk.Kty}
	if jwk.Crv != "" {
		out["crv"] = jwk.Crv
	}
	if jwk.X != "" {
		out["x"] = jwk.X
	}
	if jwk.Y != "" {
		out["y"] = jwk.Y
	}
	if jwk.N != "" {
		out["n"] = jwk.N
	}
	if jwk.E != "" {
		out["e"] = jwk.E
	}
	return out, nil
}

func baseClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"jti": "proof-jti-1",
		"htm": "POST",
		"htu": testEndpoint,
		"iat": now.Unix(),
	}
}

func TestValidateProofSucceedsForES256AndEdDSA(t *testing.T) {
	now := time.Now().UTC()
	for _, signer := range []testSigner{newES256TestSigner(t), newEdDSATestSigner(t)} {
		compact := signer.sign(t, baseClaims(now), nil)
		proof, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now})
		if err != nil {
			t.Fatalf("ValidateProof: %v", err)
		}
		if proof.JTI != "proof-jti-1" {
			t.Fatalf("jti = %q", proof.JTI)
		}
		if proof.JKT != signer.jwk.Thumbprint() {
			t.Fatalf("jkt = %q, want %q", proof.JKT, signer.jwk.Thumbprint())
		}
	}
}

func TestValidateProofRejectsWrongTyp(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, baseClaims(now), map[string]interface{}{"typ": "JWT"})
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected typ rejection")
	}
}

func TestValidateProofRejectsAlgNone(t *testing.T) {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims(now))
	token.Header["typ"] = ProofTyp
	signer := newES256TestSigner(t)
	jwkMap, _ := jwkToMap(signer.jwk)
	token.Header["jwk"] = jwkMap
	compact, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected alg=none rejection")
	}
}

func TestValidateProofRejectsSymmetricAlg(t *testing.T) {
	now := time.Now().UTC()
	secret := []byte("shared-secret-key-material-long-enough")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims(now))
	token.Header["typ"] = ProofTyp
	// A symmetric key masquerading as a JWK header: the k member alone
	// should be enough to fail JWKContainsPrivateMaterial even before the
	// alg allowlist would reject HS256 outright.
	token.Header["jwk"] = map[string]interface{}{
		"kty": "oct",
		"k":   base64.RawURLEncoding.EncodeToString(secret),
	}
	compact, err := token.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected symmetric-algorithm rejection")
	}
}

func TestValidateProofRejectsPrivateKeyInJWKHeader(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	leakedJWK, _ := jwkToMap(signer.jwk)
	leakedJWK["d"] = "leaked-private-scalar"
	compact := signer.sign(t, baseClaims(now), map[string]interface{}{"jwk": leakedJWK})
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected private-key-in-jwk rejection")
	}
}

func TestValidateProofRejectsMissingJTI(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now)
	delete(claims, "jti")
	compact := signer.sign(t, claims, nil)
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected missing jti rejection")
	}
}

func TestValidateProofRejectsHTMMismatch(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, baseClaims(now), nil)
	if _, err := ValidateProof(compact, ValidateOptions{Method: "GET", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected htm mismatch rejection")
	}
}

func TestValidateProofHTMIsCaseSensitiveAgainstUppercasedMethod(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims["htm"] = "post" // lowercase htm must not match
	compact := signer.sign(t, claims, nil)
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected case-sensitive htm rejection")
	}
}

func TestValidateProofHTUNormalizationEquivalence(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims["htu"] = "https://x.test:443/token"
	compact := signer.sign(t, claims, nil)
	if _, err := ValidateProof(compact, ValidateOptions{
		Method: "POST",
		URI:    "https://x.test/token",
		Now:    now,
	}); err != nil {
		t.Fatalf("expected default-port htu to normalize as equivalent: %v", err)
	}
}

func TestValidateProofHTUMismatchIsRejected(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, baseClaims(now), nil)
	if _, err := ValidateProof(compact, ValidateOptions{
		Method: "POST",
		URI:    "https://as.example/oauth2/introspect",
		Now:    now,
	}); err == nil {
		t.Fatal("expected htu mismatch rejection")
	}
}

func TestValidateProofRejectsStaleIat(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now.Add(-IatFreshnessWindow - time.Second))
	compact := signer.sign(t, claims, nil)
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected stale iat rejection")
	}
}

func TestValidateProofRejectsFutureIat(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now.Add(IatFreshnessWindow + time.Second))
	compact := signer.sign(t, claims, nil)
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected future iat rejection")
	}
}

func TestValidateProofATHMustMatchAccessToken(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	accessToken := "the-access-token"
	claims := baseClaims(now)
	claims["ath"] = computeATH(accessToken)
	compact := signer.sign(t, claims, nil)

	if _, err := ValidateProof(compact, ValidateOptions{
		Method:      "POST",
		URI:         testEndpoint,
		AccessToken: accessToken,
		Now:         now,
	}); err != nil {
		t.Fatalf("expected matching ath to succeed: %v", err)
	}

	if _, err := ValidateProof(compact, ValidateOptions{
		Method:      "POST",
		URI:         testEndpoint,
		AccessToken: "a-different-access-token",
		Now:         now,
	}); err == nil {
		t.Fatal("expected ath mismatch rejection")
	}
}

func TestValidateProofRequiresNonceWhenInForce(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now)
	claims["nonce"] = "server-nonce-1"
	compact := signer.sign(t, claims, nil)

	if _, err := ValidateProof(compact, ValidateOptions{
		Method:        "POST",
		URI:           testEndpoint,
		RequiredNonce: "server-nonce-1",
		Now:           now,
	}); err != nil {
		t.Fatalf("expected matching nonce to succeed: %v", err)
	}

	if _, err := ValidateProof(compact, ValidateOptions{
		Method:        "POST",
		URI:           testEndpoint,
		RequiredNonce: "a-different-nonce",
		Now:           now,
	}); err == nil {
		t.Fatal("expected nonce mismatch rejection")
	}
}

func TestNormalizeHTUStripsQueryAndFragment(t *testing.T) {
	normalized, err := NormalizeHTU("HTTPS://As.Example:443/oauth2/token?foo=bar#frag")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "https://as.example/oauth2/token" {
		t.Fatalf("normalized = %q", normalized)
	}
}

func TestValidateProofRejectsAlgKeyTypeConfusion(t *testing.T) {
	// An ES256-header alg with an RSA jwk (or vice versa) must be rejected
	// even though the signature itself is validly produced by *some* key,
	// because the header's declared alg and jwk kty disagree.
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	claims := baseClaims(now)
	compact := signer.sign(t, claims, map[string]interface{}{
		"jwk": map[string]interface{}{
			"kty": "RSA",
			"n":   "not-a-real-modulus",
			"e":   "AQAB",
		},
	})
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected alg/key-type confusion rejection")
	}
}

func TestValidateProofRejectsEmptyProof(t *testing.T) {
	if _, err := ValidateProof("", ValidateOptions{Method: "POST", URI: testEndpoint}); err == nil {
		t.Fatal("expected empty proof rejection")
	}
}

func TestValidateProofRejectsMissingJWKHeader(t *testing.T) {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, baseClaims(now))
	token.Header["typ"] = ProofTyp
	signer := newES256TestSigner(t)
	compact, err := token.SignedString(signer.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected missing jwk header rejection")
	}
}

func TestValidateProofRejectsDisallowedAlgHeaderEvenIfSignatureValid(t *testing.T) {
	// RS384/ES512 etc. are asymmetric but not on the explicit allowlist.
	now := time.Now().UTC()
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := internalcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "es512-key")
	token := jwt.NewWithClaims(jwt.SigningMethodES512, baseClaims(now))
	token.Header["typ"] = ProofTyp
	jwkMap, _ := jwkToMap(jwk)
	token.Header["jwk"] = jwkMap
	compact, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now}); err == nil {
		t.Fatal("expected ES512 (not on allowlist) rejection")
	}
}

func TestDuplicateJTIRejectedThroughMemoryStore(t *testing.T) {
	store := NewMemoryReplayStore()
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	until := now.Add(time.Minute)

	ctx := context.Background()
	first, err := store.Reserve(ctx, "jkt-1", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("first reservation should succeed")
	}
	second, err := store.Reserve(ctx, "jkt-1", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("duplicate jti should be rejected")
	}
	// A different jkt scope must not collide with the same jti.
	third, err := store.Reserve(ctx, "jkt-2", "dup-jti", until, now)
	if err != nil {
		t.Fatal(err)
	}
	if !third {
		t.Fatal("same jti under a different jkt scope should be accepted")
	}
}

func TestJKTComputedFromProofMatchesCryptoThumbprint(t *testing.T) {
	signer := newES256TestSigner(t)
	now := time.Now().UTC()
	compact := signer.sign(t, baseClaims(now), nil)
	proof, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if proof.JKT != signer.jwk.Thumbprint() {
		t.Fatalf("jkt = %q, want %q (crypto.JWK.Thumbprint())", proof.JKT, signer.jwk.Thumbprint())
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Fatal("equal strings should compare equal")
	}
	if constantTimeEqual("abc", "abd") {
		t.Fatal("different strings should not compare equal")
	}
	if constantTimeEqual("abc", "ab") {
		t.Fatal("different lengths should not compare equal")
	}
}

func TestValidateProofRSA256Succeeds(t *testing.T) {
	// Exercises the RSA branch of algMatchesKeyType end to end, since the
	// other tests only cover EC/EdDSA and the ES256-with-RSA-header
	// mismatch case.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner{
		method:     jwt.SigningMethodRS256,
		privateKey: privateKey,
		jwk:        internalcrypto.JWKFromRSAPublicKey(&privateKey.PublicKey, "rsa-test-key"),
	}
	now := time.Now().UTC()
	compact := signer.sign(t, baseClaims(now), nil)
	proof, err := ValidateProof(compact, ValidateOptions{Method: "POST", URI: testEndpoint, Now: now})
	if err != nil {
		t.Fatalf("ValidateProof: %v", err)
	}
	if proof.JKT != signer.jwk.Thumbprint() {
		t.Fatalf("jkt = %q, want %q", proof.JKT, signer.jwk.Thumbprint())
	}
}

func TestAlgMatchesKeyTypeRejectsRSAAlgWithNonRSAKey(t *testing.T) {
	ecSigner := newES256TestSigner(t)
	if err := algMatchesKeyType("RS256", ecSigner.jwk); err == nil {
		t.Fatal("expected RS256 to require an RSA key")
	}
}

func TestAlgMatchesKeyTypeRejectsEdDSAAlgWithNonOKPKey(t *testing.T) {
	ecSigner := newES256TestSigner(t)
	if err := algMatchesKeyType("EdDSA", ecSigner.jwk); err == nil {
		t.Fatal("expected EdDSA to require an OKP Ed25519 key")
	}
}

func TestAlgMatchesKeyTypeRejectsUnrecognizedAlg(t *testing.T) {
	ecSigner := newES256TestSigner(t)
	if err := algMatchesKeyType("HS256", ecSigner.jwk); err == nil {
		t.Fatal("expected an unrecognized alg to be rejected")
	}
}

func TestNumericDateToInt64HandlesAllSupportedTypes(t *testing.T) {
	cases := []interface{}{
		float64(1700000000),
		json.Number("1700000000"),
		int64(1700000000),
		int(1700000000),
	}
	for _, raw := range cases {
		value, err := numericDateToInt64(raw)
		if err != nil {
			t.Fatalf("numericDateToInt64(%T): %v", raw, err)
		}
		if value != 1700000000 {
			t.Fatalf("numericDateToInt64(%T) = %d", raw, value)
		}
	}
}

func TestNumericDateToInt64RejectsUnsupportedType(t *testing.T) {
	if _, err := numericDateToInt64("not-a-number"); err == nil {
		t.Fatal("expected unsupported numeric date type rejection")
	}
}

func TestExtractHeaderReturnsEmptyForNoHeader(t *testing.T) {
	value, err := ExtractHeader(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "" {
		t.Fatalf("value = %q, want empty", value)
	}

	value, err = ExtractHeader([]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "" {
		t.Fatalf("value = %q, want empty", value)
	}
}

func TestExtractHeaderReturnsTheSoleValueTrimmed(t *testing.T) {
	value, err := ExtractHeader([]string{"  proof-value  "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "proof-value" {
		t.Fatalf("value = %q, want %q", value, "proof-value")
	}
}

// TestExtractHeaderRejectsMultipleHeaderFields covers RFC 9449 Section 4.3
// check 1: "There is not more than one DPoP HTTP request header field."
// http.Header.Get would silently return only the first of several DPoP
// header lines; ExtractHeader must instead treat that as a hard failure.
func TestExtractHeaderRejectsMultipleHeaderFields(t *testing.T) {
	if _, err := ExtractHeader([]string{"proof-one", "proof-two"}); err == nil {
		t.Fatal("expected an error for more than one DPoP header field")
	}
}

func TestErrorMessagesDoNotLeakSensitiveComparisonValues(t *testing.T) {
	if !strings.Contains(ErrorInvalidDPoPProof, "invalid_dpop_proof") {
		t.Fatalf("unexpected error constant %q", ErrorInvalidDPoPProof)
	}
}
