package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // register SHA-256 so ES256 hashing is available
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

// Sign1Message is a decoded COSE_Sign1 message (RFC 9052 Section 4.2).
type Sign1Message = cose.Sign1Message

// Sign1Result holds the verified payload and headers extracted from a
// COSE_Sign1 message.
type Sign1Result struct {
	// Payload is the signed payload (the detached-payload case is not used by
	// mdoc IssuerAuth, so a present payload is expected).
	Payload []byte
	// Protected is the cryptographically protected header bucket.
	Protected ProtectedHeader
	// Unprotected is the unprotected header bucket (where mdoc carries
	// x5chain).
	Unprotected UnprotectedHeader
}

// Sign1 produces a tagged COSE_Sign1 (CBOR tag 18) over payload using a P-256
// ECDSA private key and ES256 (RFC 9052 Section 4.2, RFC 9053 Section 2.1).
//
// externalAAD is the externally supplied additional authenticated data folded
// into the Sig_structure; pass nil when there is none. If protected does not
// already carry alg, ES256 is set automatically.
//
// ECDSA signing uses a random k, so the signature bytes differ on each call;
// they verify deterministically against the public key.
func Sign1(payload, externalAAD []byte, key *ecdsa.PrivateKey, protected ProtectedHeader, unprotected UnprotectedHeader) ([]byte, error) {
	signer, err := newES256Signer(key)
	if err != nil {
		return nil, err
	}
	headers := cose.Headers{Protected: protected, Unprotected: unprotected}
	return cose.Sign1(rand.Reader, signer, headers, payload, externalAAD)
}

// Sign1Untagged is like Sign1 but emits an untagged COSE_Sign1 (a bare 4-element
// array). mdoc embeds IssuerAuth as an untagged COSE_Sign1 inside the
// IssuerSigned structure, so this is the variant the issuer driver uses.
func Sign1Untagged(payload, externalAAD []byte, key *ecdsa.PrivateKey, protected ProtectedHeader, unprotected UnprotectedHeader) ([]byte, error) {
	signer, err := newES256Signer(key)
	if err != nil {
		return nil, err
	}
	headers := cose.Headers{Protected: protected, Unprotected: unprotected}
	return cose.Sign1Untagged(rand.Reader, signer, headers, payload, externalAAD)
}

// VerifySign1 verifies a COSE_Sign1 (tagged or untagged) against a P-256 ECDSA
// public key using ES256, returning the payload and headers on success.
// externalAAD must match the value used at signing time.
func VerifySign1(coseSign1Bytes, externalAAD []byte, key *ecdsa.PublicKey) (*Sign1Result, error) {
	if key == nil {
		return nil, fmt.Errorf("cose: nil EC public key")
	}
	msg, err := ParseSign1(coseSign1Bytes)
	if err != nil {
		return nil, err
	}
	verifier, err := cose.NewVerifier(AlgorithmES256, key)
	if err != nil {
		return nil, fmt.Errorf("cose: build ES256 verifier: %w", err)
	}
	if err := msg.Verify(externalAAD, verifier); err != nil {
		return nil, fmt.Errorf("cose: COSE_Sign1 verification failed: %w", err)
	}
	return &Sign1Result{
		Payload:     msg.Payload,
		Protected:   msg.Headers.Protected,
		Unprotected: msg.Headers.Unprotected,
	}, nil
}

// ParseSign1 decodes a COSE_Sign1 message without verifying its signature,
// accepting both the tagged (CBOR tag 18) and untagged forms. Use this for
// inspection (for example reading the x5chain) before trust is established.
func ParseSign1(coseSign1Bytes []byte) (*Sign1Message, error) {
	if len(coseSign1Bytes) == 0 {
		return nil, fmt.Errorf("cose: empty COSE_Sign1 input")
	}
	var tagged cose.Sign1Message
	taggedErr := tagged.UnmarshalCBOR(coseSign1Bytes)
	if taggedErr == nil {
		return &tagged, nil
	}
	var untagged cose.UntaggedSign1Message
	if untaggedErr := untagged.UnmarshalCBOR(coseSign1Bytes); untaggedErr != nil {
		return nil, fmt.Errorf("cose: parse COSE_Sign1 (tagged: %v; untagged: %w)", taggedErr, untaggedErr)
	}
	msg := cose.Sign1Message(untagged)
	return &msg, nil
}

// Sign1DetachedUntagged produces an untagged COSE_Sign1 (RFC 9052 Section 4.2)
// that signs over payload but is emitted with a detached (nil) payload: the wire
// form carries a CBOR null in the payload slot, and the verifier must supply the
// same payload to verify. The mdoc deviceSignature (ISO/IEC 18013-5 clause
// 9.1.3.4) uses this form -- the signed content is the reconstructed
// DeviceAuthenticationBytes, which is never transmitted inside the COSE_Sign1.
//
// externalAAD is folded into the Sig_structure exactly as in Sign1; pass nil
// when there is none (mdoc device authentication uses an empty external_aad).
func Sign1DetachedUntagged(payload, externalAAD []byte, key *ecdsa.PrivateKey, protected ProtectedHeader, unprotected UnprotectedHeader) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("cose: detached COSE_Sign1 requires a payload to sign over")
	}
	signer, err := newES256Signer(key)
	if err != nil {
		return nil, err
	}
	msg := cose.UntaggedSign1Message{
		Headers: cose.Headers{Protected: protected, Unprotected: unprotected},
		Payload: payload,
	}
	if err := msg.Sign(rand.Reader, externalAAD, signer); err != nil {
		return nil, fmt.Errorf("cose: sign detached COSE_Sign1: %w", err)
	}
	// Detach the payload: ISO/IEC 18013-5 transmits the deviceSignature with a
	// nil payload, and the verifier reconstructs the signed content.
	msg.Payload = nil
	encoded, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("cose: marshal detached COSE_Sign1: %w", err)
	}
	return encoded, nil
}

// VerifySign1Detached verifies a COSE_Sign1 (tagged or untagged) that was
// transmitted with a detached payload, by reattaching the supplied payload
// before verification. It rejects a message that already carries an attached
// payload, since a conforming mdoc deviceSignature must be detached.
// externalAAD must match the value used at signing time.
func VerifySign1Detached(coseSign1Bytes, payload, externalAAD []byte, key *ecdsa.PublicKey) (*Sign1Result, error) {
	if key == nil {
		return nil, fmt.Errorf("cose: nil EC public key")
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("cose: detached verification requires the reconstructed payload")
	}
	msg, err := ParseSign1(coseSign1Bytes)
	if err != nil {
		return nil, err
	}
	if msg.Payload != nil {
		return nil, fmt.Errorf("cose: expected a detached payload (CBOR null), got %d attached bytes", len(msg.Payload))
	}
	msg.Payload = payload
	verifier, err := cose.NewVerifier(AlgorithmES256, key)
	if err != nil {
		return nil, fmt.Errorf("cose: build ES256 verifier: %w", err)
	}
	if err := msg.Verify(externalAAD, verifier); err != nil {
		return nil, fmt.Errorf("cose: detached COSE_Sign1 verification failed: %w", err)
	}
	return &Sign1Result{
		Payload:     payload,
		Protected:   msg.Headers.Protected,
		Unprotected: msg.Headers.Unprotected,
	}, nil
}

func newES256Signer(key *ecdsa.PrivateKey) (cose.Signer, error) {
	if key == nil {
		return nil, errors.New("cose: nil EC private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("cose: ES256 requires a P-256 key, got %v", key.Curve)
	}
	signer, err := cose.NewSigner(AlgorithmES256, key)
	if err != nil {
		return nil, fmt.Errorf("cose: build ES256 signer: %w", err)
	}
	return signer, nil
}
