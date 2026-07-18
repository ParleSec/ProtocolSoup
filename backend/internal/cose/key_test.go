package cose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	libcose "github.com/veraison/go-cose"
)

// TestCOSEKeyMatchesExternalVector builds a COSE_Key from the RFC 8152
// Appendix C.2.1 key coordinates and checks the stored x/y match the published
// values (32-byte, leading zeros preserved), and that the reconstructed public
// key round-trips.
func TestCOSEKeyMatchesExternalVector(t *testing.T) {
	x := mustB64URL(t, rfc8152X)
	y := mustB64URL(t, rfc8152Y)
	pub := p256PublicFromXY(x, y)

	key, err := ECPublicKeyToCOSEKey(pub)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}

	if kty, ok := key.KeyType(); !ok || kty != keyTypeEC2 {
		t.Fatalf("kty = %d (ok=%v), want EC2 (%d)", kty, ok, keyTypeEC2)
	}
	if crv, ok := key.Curve(); !ok || crv != curveP256 {
		t.Fatalf("crv = %d (ok=%v), want P-256 (%d)", crv, ok, curveP256)
	}

	gotX, _ := key.X()
	gotY, _ := key.Y()
	if len(gotX) != p256CoordLen || len(gotY) != p256CoordLen {
		t.Fatalf("coordinate lengths = (%d,%d), want (%d,%d)", len(gotX), len(gotY), p256CoordLen, p256CoordLen)
	}
	if !bytes.Equal(gotX, leftPad(x, p256CoordLen)) {
		t.Fatalf("x mismatch:\n got %x\nwant %x", gotX, leftPad(x, p256CoordLen))
	}
	if !bytes.Equal(gotY, leftPad(y, p256CoordLen)) {
		t.Fatalf("y mismatch:\n got %x\nwant %x", gotY, leftPad(y, p256CoordLen))
	}

	back, err := COSEKeyToECPublicKey(key)
	if err != nil {
		t.Fatalf("COSEKeyToECPublicKey: %v", err)
	}
	if !back.Equal(pub) {
		t.Fatal("reconstructed public key does not equal the original")
	}
}

// TestCOSEKeyPrivateRoundTrip verifies a generated P-256 private key survives
// COSEKey -> CBOR -> COSEKey -> private key intact.
func TestCOSEKeyPrivateRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	key, err := ECPrivateKeyToCOSEKey(priv)
	if err != nil {
		t.Fatalf("ECPrivateKeyToCOSEKey: %v", err)
	}

	encoded, err := EncodeCOSEKey(key)
	if err != nil {
		t.Fatalf("EncodeCOSEKey: %v", err)
	}

	decoded, err := DecodeCOSEKey(encoded)
	if err != nil {
		t.Fatalf("DecodeCOSEKey: %v", err)
	}

	back, err := COSEKeyToECPrivateKey(decoded)
	if err != nil {
		t.Fatalf("COSEKeyToECPrivateKey: %v", err)
	}

	backD, err := back.Bytes()
	if err != nil {
		t.Fatalf("encode reconstructed private key: %v", err)
	}
	originalD, err := priv.Bytes()
	if err != nil {
		t.Fatalf("encode original private key: %v", err)
	}
	if !bytes.Equal(backD, originalD) {
		t.Fatal("private scalar d not preserved")
	}
	if !back.PublicKey.Equal(&priv.PublicKey) {
		t.Fatal("public key not preserved")
	}
}

// TestCOSEKeyDecodesUnderExternalLibrary cross-checks our COSE_Key encoding
// against an independent implementation (veraison/go-cose Key): the library
// must decode our bytes and reconstruct the same public key. This is the
// external-implementation interop check for the key encoding path.
func TestCOSEKeyDecodesUnderExternalLibrary(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	key, err := ECPublicKeyToCOSEKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}
	encoded, err := EncodeCOSEKey(key)
	if err != nil {
		t.Fatalf("EncodeCOSEKey: %v", err)
	}

	var libKey libcose.Key
	if err := libKey.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("veraison/go-cose failed to decode our COSE_Key: %v", err)
	}
	libPub, err := libKey.PublicKey()
	if err != nil {
		t.Fatalf("veraison/go-cose PublicKey: %v", err)
	}
	ecdsaPub, ok := libPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("external library returned %T, want *ecdsa.PublicKey", libPub)
	}
	if !ecdsaPub.Equal(&priv.PublicKey) {
		t.Fatal("external library reconstructed a different public key from our COSE_Key")
	}
}

func TestCOSEKeyRejectsNonP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := ECPublicKeyToCOSEKey(&priv.PublicKey); err == nil {
		t.Fatal("expected error for non-P-256 curve, got nil")
	}
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
