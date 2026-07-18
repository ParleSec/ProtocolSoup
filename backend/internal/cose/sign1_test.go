package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Minimal constants from the published cose-wg RFC 8152 Appendix C.2.1
// COSE_Sign1 example. Keeping them beside the tests avoids standalone fixture
// files while preserving the external interoperability check.
const (
	rfc8152Plaintext   = "This is the content."
	rfc8152X           = "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8"
	rfc8152Y           = "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
	rfc8152D           = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
	rfc8152Sign1CBOR   = "D28443A10126A10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36"
	unprotectedAlgCBOR = "D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F"
)

func mustB64URL(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	return decoded
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return decoded
}

func p256PublicFromXY(x, y []byte) *ecdsa.PublicKey {
	if len(x) != p256CoordLen || len(y) != p256CoordLen {
		panic("P-256 coordinates must be 32 bytes")
	}
	encoded := make([]byte, 1+2*p256CoordLen)
	encoded[0] = 0x04
	copy(encoded[1:1+p256CoordLen], x)
	copy(encoded[1+p256CoordLen:], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), encoded)
	if err != nil {
		panic(err)
	}
	return pub
}

func p256PrivateFromXYD(x, y, d []byte) *ecdsa.PrivateKey {
	expectedPublic := p256PublicFromXY(x, y)
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		panic(err)
	}
	if !priv.PublicKey.Equal(expectedPublic) {
		panic("P-256 private scalar does not match public coordinates")
	}
	return priv
}

// TestVerifySign1ExternalVector verifies the published COSE_Sign1 signature
// from cose-wg/Examples (RFC 8152 Appendix C.2.1, alg in the protected header)
// against the public key carried in the vector. This is the external-vector
// check for COSE_Sign1: a signature produced by another implementation must
// verify under ours.
func TestVerifySign1ExternalVector(t *testing.T) {
	pub := p256PublicFromXY(
		mustB64URL(t, rfc8152X),
		mustB64URL(t, rfc8152Y),
	)
	coseSign1 := mustHex(t, rfc8152Sign1CBOR)

	result, err := VerifySign1(coseSign1, nil, pub)
	if err != nil {
		t.Fatalf("VerifySign1 on external vector: %v", err)
	}
	if string(result.Payload) != rfc8152Plaintext {
		t.Fatalf("payload = %q, want %q", result.Payload, rfc8152Plaintext)
	}
}

// TestVerifySign1RejectsUnprotectedAlg uses cose-wg sign-pass-01, whose
// output.cbor carries a tampered protected header (ChangeProtected=a0): the
// signature was computed over an empty protected header while the message
// serializes a non-empty protected header and places alg in the unprotected
// bucket. A verifier that trusts only the cryptographically protected algorithm
// (RFC 9052 Section 4.4) must reject it. mdoc IssuerAuth always carries alg in
// the protected header, so this strictness is the behaviour we want.
func TestVerifySign1RejectsUnprotectedAlg(t *testing.T) {
	pub := p256PublicFromXY(
		mustB64URL(t, rfc8152X),
		mustB64URL(t, rfc8152Y),
	)
	coseSign1 := mustHex(t, unprotectedAlgCBOR)

	if _, err := VerifySign1(coseSign1, nil, pub); err == nil {
		t.Fatal("expected verification failure for tampered/unprotected-alg message, got nil")
	}
}

// TestVerifySign1RejectsTamperedSignature confirms a flipped signature byte is
// rejected.
func TestVerifySign1RejectsTamperedSignature(t *testing.T) {
	pub := p256PublicFromXY(
		mustB64URL(t, rfc8152X),
		mustB64URL(t, rfc8152Y),
	)
	coseSign1 := mustHex(t, rfc8152Sign1CBOR)
	// The signature is the trailing 64 bytes of the ES256 COSE_Sign1; flip a bit
	// in the last byte.
	tampered := make([]byte, len(coseSign1))
	copy(tampered, coseSign1)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := VerifySign1(tampered, nil, pub); err == nil {
		t.Fatal("expected verification failure on tampered signature, got nil")
	}
}

// TestSign1RoundTripTagged signs with the vector private key and verifies with
// its public key. ECDSA is non-deterministic, so we assert verifiability rather
// than byte-equality of the signature.
func TestSign1RoundTripTagged(t *testing.T) {
	priv := p256PrivateFromXYD(
		mustB64URL(t, rfc8152X),
		mustB64URL(t, rfc8152Y),
		mustB64URL(t, rfc8152D),
	)
	payload := []byte(rfc8152Plaintext)

	signed, err := Sign1(payload, nil, priv, ES256ProtectedHeader(), UnprotectedHeader{HeaderLabelKeyID: []byte("11")})
	if err != nil {
		t.Fatalf("Sign1: %v", err)
	}

	result, err := VerifySign1(signed, nil, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifySign1 round trip: %v", err)
	}
	if string(result.Payload) != rfc8152Plaintext {
		t.Fatalf("payload = %q, want %q", result.Payload, rfc8152Plaintext)
	}
}

// TestSign1UntaggedRoundTrip exercises the untagged COSE_Sign1 form used by
// mdoc IssuerAuth.
func TestSign1UntaggedRoundTrip(t *testing.T) {
	priv := p256PrivateFromXYD(
		mustB64URL(t, rfc8152X),
		mustB64URL(t, rfc8152Y),
		mustB64URL(t, rfc8152D),
	)
	payload := []byte("mdoc IssuerAuth payload")

	signed, err := Sign1Untagged(payload, nil, priv, ES256ProtectedHeader(), UnprotectedHeader{})
	if err != nil {
		t.Fatalf("Sign1Untagged: %v", err)
	}
	// The untagged form must not carry the tag 18 prefix (0xd2).
	if len(signed) > 0 && signed[0] == 0xd2 {
		t.Fatal("Sign1Untagged unexpectedly produced a tagged message")
	}

	result, err := VerifySign1(signed, nil, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifySign1 (untagged) round trip: %v", err)
	}
	if string(result.Payload) != string(payload) {
		t.Fatalf("payload = %q, want %q", result.Payload, payload)
	}
}

// TestVerifySign1WrongKeyFails confirms verification fails under an unrelated
// key.
func TestVerifySign1WrongKeyFails(t *testing.T) {
	coseSign1 := mustHex(t, rfc8152Sign1CBOR)

	// A different, freshly generated valid P-256 key must not verify the
	// signature produced for the vector key.
	wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	if _, err := VerifySign1(coseSign1, nil, &wrong.PublicKey); err == nil {
		t.Fatal("expected verification failure under the wrong key, got nil")
	}
}
