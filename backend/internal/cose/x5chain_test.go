package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestX5ChainSingleCertRoundTrip checks the single-certificate encoding (a bare
// byte string per RFC 9360 Section 2) round-trips through the unprotected
// header.
func TestX5ChainSingleCertRoundTrip(t *testing.T) {
	ca := newSelfSignedCA(t)

	h := UnprotectedHeader{}
	if err := SetX5Chain(h, []*x509.Certificate{ca.cert}); err != nil {
		t.Fatalf("SetX5Chain: %v", err)
	}
	// A single certificate must be stored as raw DER bytes, not an array.
	if _, ok := h[HeaderLabelX5Chain].([]byte); !ok {
		t.Fatalf("single-cert x5chain stored as %T, want []byte", h[HeaderLabelX5Chain])
	}

	got, err := GetX5Chain(h)
	if err != nil {
		t.Fatalf("GetX5Chain: %v", err)
	}
	if len(got) != 1 || !got[0].Equal(ca.cert) {
		t.Fatal("single certificate did not round-trip")
	}
}

// TestX5ChainMultiCertThroughCOSESign1 puts a 2-cert chain in the IssuerAuth
// unprotected header, signs, parses the signed bytes back, and recovers the
// chain. This mirrors how mdoc carries the issuer chain.
func TestX5ChainMultiCertThroughCOSESign1(t *testing.T) {
	ca := newSelfSignedCA(t)
	leaf := newLeafSignedBy(t, ca)

	unprotected := UnprotectedHeader{}
	if err := SetX5Chain(unprotected, []*x509.Certificate{leaf.cert, ca.cert}); err != nil {
		t.Fatalf("SetX5Chain: %v", err)
	}

	signed, err := Sign1Untagged([]byte("MSO bytes"), nil, leaf.key, ES256ProtectedHeader(), unprotected)
	if err != nil {
		t.Fatalf("Sign1Untagged: %v", err)
	}

	msg, err := ParseSign1(signed)
	if err != nil {
		t.Fatalf("ParseSign1: %v", err)
	}
	chain, err := GetX5Chain(msg.Headers.Unprotected)
	if err != nil {
		t.Fatalf("GetX5Chain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want 2", len(chain))
	}
	if !chain[0].Equal(leaf.cert) || !chain[1].Equal(ca.cert) {
		t.Fatal("chain certificates did not round-trip in order")
	}
}

func TestGetX5ChainMissingLabel(t *testing.T) {
	if _, err := GetX5Chain(UnprotectedHeader{}); err == nil {
		t.Fatal("expected error when x5chain label is absent, got nil")
	}
}

// certKey bundles a certificate with the private key that owns it.
type certKey struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newSelfSignedCA(t *testing.T) *certKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ProtocolSoup Test mdoc CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &certKey{cert: cert, key: key}
}

func newLeafSignedBy(t *testing.T, ca *certKey) *certKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ProtocolSoup Test mdoc Issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return &certKey{cert: cert, key: key}
}
