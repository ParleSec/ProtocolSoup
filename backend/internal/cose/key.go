package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// COSE_Key parameter labels and values for EC2/P-256 keys. The labels are
// defined by RFC 9052 Section 7 and the IANA "COSE Key Common Parameters" and
// "COSE Key Type Parameters" registries. ISO/IEC 18013-5 references these
// structures (for the MSO deviceKey) but does not define the labels itself.
const (
	keyLabelKty   = 1  // Common: key type
	keyLabelEC2Crv = -1 // EC2: curve
	keyLabelEC2X   = -2 // EC2: x-coordinate
	keyLabelEC2Y   = -3 // EC2: y-coordinate
	keyLabelEC2D   = -4 // EC2: private key (d)

	keyTypeEC2  = 2 // kty value: EC2
	curveP256   = 1 // crv value: P-256 (secp256r1)
	p256CoordLen = 32
)

// COSEKey is a COSE_Key (RFC 9052 Section 7) represented as a label map. This
// supports kty=EC2 (2) with crv=P-256 (1), which is what mdoc ES256 device and
// issuer keys use. Integer values are stored as int64 and byte values as []byte
// so the map encodes cleanly under the canonical CBOR encoder.
type COSEKey map[int]any

// KeyType returns the COSE_Key kty (label 1) if present.
func (k COSEKey) KeyType() (int64, bool) {
	return k.int64At(keyLabelKty)
}

// Curve returns the EC2 curve (label -1) if present.
func (k COSEKey) Curve() (int64, bool) {
	return k.int64At(keyLabelEC2Crv)
}

// X returns the EC2 x-coordinate (label -2) if present.
func (k COSEKey) X() ([]byte, bool) { return k.bytesAt(keyLabelEC2X) }

// Y returns the EC2 y-coordinate (label -3) if present.
func (k COSEKey) Y() ([]byte, bool) { return k.bytesAt(keyLabelEC2Y) }

// D returns the EC2 private scalar (label -4) if present.
func (k COSEKey) D() ([]byte, bool) { return k.bytesAt(keyLabelEC2D) }

func (k COSEKey) int64At(label int) (int64, bool) {
	v, ok := k[label]
	if !ok {
		return 0, false
	}
	return asInt64(v)
}

func (k COSEKey) bytesAt(label int) ([]byte, bool) {
	v, ok := k[label]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

// ECPublicKeyToCOSEKey converts a P-256 ECDSA public key into a COSE_Key
// (RFC 9052 Section 7). Coordinates are left-padded to 32 bytes so leading zero
// octets are preserved, as required by RFC 9052 Section 7 (Go's big.Int.Bytes
// trims them, which would break interop).
func ECPublicKeyToCOSEKey(key *ecdsa.PublicKey) (COSEKey, error) {
	if key == nil {
		return nil, fmt.Errorf("cose: nil EC public key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("cose: unsupported curve %v, only P-256 is supported in phase 1", key.Curve)
	}
	return COSEKey{
		keyLabelKty:    int64(keyTypeEC2),
		keyLabelEC2Crv: int64(curveP256),
		keyLabelEC2X:   padCoordinate(key.X, p256CoordLen),
		keyLabelEC2Y:   padCoordinate(key.Y, p256CoordLen),
	}, nil
}

// ECPrivateKeyToCOSEKey converts a P-256 ECDSA private key into a COSE_Key that
// also carries the private scalar d (label -4).
func ECPrivateKeyToCOSEKey(key *ecdsa.PrivateKey) (COSEKey, error) {
	if key == nil {
		return nil, fmt.Errorf("cose: nil EC private key")
	}
	pub, err := ECPublicKeyToCOSEKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	pub[keyLabelEC2D] = padCoordinate(key.D, p256CoordLen)
	return pub, nil
}

// COSEKeyToECPublicKey reconstructs a P-256 ECDSA public key from a COSE_Key.
// The decoded point is validated to lie on the curve.
func COSEKeyToECPublicKey(k COSEKey) (*ecdsa.PublicKey, error) {
	if err := requireEC2P256(k); err != nil {
		return nil, err
	}
	x, ok := k.X()
	if !ok {
		return nil, fmt.Errorf("cose: COSE_Key missing x-coordinate (label -2)")
	}
	y, ok := k.Y()
	if !ok {
		return nil, fmt.Errorf("cose: COSE_Key missing y-coordinate (label -3)")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	// ECDH() validates the point lies on the curve and is not the identity,
	// which is the non-deprecated way to reject invalid public points.
	if _, err := pub.ECDH(); err != nil {
		return nil, fmt.Errorf("cose: invalid P-256 public point: %w", err)
	}
	return pub, nil
}

// COSEKeyToECPrivateKey reconstructs a P-256 ECDSA private key from a COSE_Key
// that carries the private scalar d (label -4).
func COSEKeyToECPrivateKey(k COSEKey) (*ecdsa.PrivateKey, error) {
	pub, err := COSEKeyToECPublicKey(k)
	if err != nil {
		return nil, err
	}
	d, ok := k.D()
	if !ok {
		return nil, fmt.Errorf("cose: COSE_Key missing private scalar (label -4)")
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(d),
	}
	if priv.D.Sign() <= 0 || priv.D.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, fmt.Errorf("cose: P-256 private scalar out of range [1, n-1]")
	}
	return priv, nil
}

// EncodeCOSEKey encodes a COSE_Key as canonical CBOR (RFC 7049 canonical, the
// encoding used for the surrounding mdoc data model).
func EncodeCOSEKey(k COSEKey) ([]byte, error) {
	return MarshalDeterministic(map[int]any(k))
}

// DecodeCOSEKey decodes CBOR bytes into a COSEKey.
func DecodeCOSEKey(data []byte) (COSEKey, error) {
	var m map[int]any
	if err := Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("cose: decode COSE_Key: %w", err)
	}
	return COSEKey(m), nil
}

func requireEC2P256(k COSEKey) error {
	kty, ok := k.KeyType()
	if !ok {
		return fmt.Errorf("cose: COSE_Key missing kty (label 1)")
	}
	if kty != keyTypeEC2 {
		return fmt.Errorf("cose: unsupported kty %d, only EC2 (2) is supported in phase 1", kty)
	}
	crv, ok := k.Curve()
	if !ok {
		return fmt.Errorf("cose: COSE_Key missing crv (label -1)")
	}
	if crv != curveP256 {
		return fmt.Errorf("cose: unsupported crv %d, only P-256 (1) is supported in phase 1", crv)
	}
	return nil
}

// padCoordinate returns the big-endian bytes of n left-padded with zeros to
// size. RFC 9052 Section 7 requires EC coordinates to be a fixed length with
// leading zero octets preserved; Go's big.Int.Bytes trims them.
func padCoordinate(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint64:
		return int64(n), true
	default:
		return 0, false
	}
}
