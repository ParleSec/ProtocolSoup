package mdoc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// VerifyIssuerSigned performs the complete issuer-signed verification flow
// (ISO/IEC 18013-5 clause 9.3.1):
//
//  1. Parse IssuerAuth and extract the x5chain from the unprotected header.
//  2. Validate the certificate chain against the trusted roots.
//  3. Verify the COSE_Sign1 signature with the document-signer public key.
//  4. Decode the MobileSecurityObject from the signed payload.
//  5. For every presented IssuerSignedItem, recompute the digest and compare
//     against the MSO valueDigests.
//  6. Validate the MSO validityInfo against now.
//
// Returns the verified MobileSecurityObject on success.
func VerifyIssuerSigned(is IssuerSigned, roots *x509.CertPool, now time.Time) (*MobileSecurityObject, error) {
	// 1. Parse the IssuerAuth COSE_Sign1.
	msoPayload, sign1Msg, err := ParseIssuerAuth(is.IssuerAuth)
	if err != nil {
		return nil, err
	}

	// 2. Extract the document-signer key from x5chain.
	dsKey, err := extractAndVerifyDocSignerKey(sign1Msg, roots, now)
	if err != nil {
		return nil, err
	}

	// 3. Verify the COSE_Sign1 signature.
	if _, err := intcose.VerifySign1(is.IssuerAuth, nil, dsKey); err != nil {
		return nil, fmt.Errorf("mdoc: IssuerAuth signature verification failed: %w", err)
	}

	// 4. Decode the MSO from the signed payload (tag-24 wrapped).
	mso, err := decodeMSOFromPayload(msoPayload)
	if err != nil {
		return nil, err
	}

	// 5. Verify presented item digests against the MSO valueDigests.
	if len(is.NameSpaces) > 0 {
		if err := VerifyValueDigests(is.NameSpaces, mso.ValueDigests, mso.DigestAlgorithm); err != nil {
			return nil, err
		}
	}

	// 6. Validate temporal validity.
	if err := validateValidity(mso.ValidityInfo, now); err != nil {
		return nil, err
	}

	return &mso, nil
}

// VerifyIssuerSignedWithKey is a simpler variant that skips x5chain validation
// and uses a directly-provided document-signer public key. Useful for tests
// that construct their own signing key without a certificate chain.
func VerifyIssuerSignedWithKey(is IssuerSigned, dsKey *ecdsa.PublicKey, now time.Time) (*MobileSecurityObject, error) {
	msoPayload, _, err := ParseIssuerAuth(is.IssuerAuth)
	if err != nil {
		return nil, err
	}

	if _, err := intcose.VerifySign1(is.IssuerAuth, nil, dsKey); err != nil {
		return nil, fmt.Errorf("mdoc: IssuerAuth signature verification failed: %w", err)
	}

	mso, err := decodeMSOFromPayload(msoPayload)
	if err != nil {
		return nil, err
	}

	if len(is.NameSpaces) > 0 {
		if err := VerifyValueDigests(is.NameSpaces, mso.ValueDigests, mso.DigestAlgorithm); err != nil {
			return nil, err
		}
	}

	if err := validateValidity(mso.ValidityInfo, now); err != nil {
		return nil, err
	}

	return &mso, nil
}

// IssuerAuthorityKeyIdentifier returns the Authority Key Identifier carried by
// the document-signer certificate in IssuerAuth. Callers use it only after
// VerifyIssuerSigned succeeds, so the certificate and identifier are anchored
// in the independently configured issuer trust store.
func IssuerAuthorityKeyIdentifier(is IssuerSigned) ([]byte, error) {
	_, msg, err := ParseIssuerAuth(is.IssuerAuth)
	if err != nil {
		return nil, err
	}
	if msg.Headers.Unprotected == nil {
		return nil, fmt.Errorf("mdoc: IssuerAuth has no unprotected headers")
	}
	chain, err := intcose.GetX5Chain(msg.Headers.Unprotected)
	if err != nil {
		return nil, fmt.Errorf("mdoc: read x5chain from IssuerAuth: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("mdoc: empty x5chain in IssuerAuth")
	}
	if len(chain[0].AuthorityKeyId) == 0 {
		return nil, nil
	}
	return append([]byte(nil), chain[0].AuthorityKeyId...), nil
}

func extractAndVerifyDocSignerKey(msg *intcose.Sign1Message, roots *x509.CertPool, now time.Time) (*ecdsa.PublicKey, error) {
	if msg.Headers.Unprotected == nil {
		return nil, fmt.Errorf("mdoc: IssuerAuth has no unprotected headers")
	}
	chain, err := intcose.GetX5Chain(msg.Headers.Unprotected)
	if err != nil {
		return nil, fmt.Errorf("mdoc: read x5chain from IssuerAuth: %w", err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("mdoc: empty x5chain in IssuerAuth")
	}

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("mdoc: x5chain certificate path validation failed: %w", err)
	}

	ecdsaKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mdoc: document-signer certificate has %T key, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	return ecdsaKey, nil
}

func decodeMSOFromPayload(payload []byte) (MobileSecurityObject, error) {
	// The payload of IssuerAuth is MobileSecurityObjectBytes, which may or may
	// not be tag-24 wrapped depending on how the issuer encoded it. Try tag 24
	// first; fall back to direct decode.
	mso, err := DecodeMSOBytes(payload)
	if err == nil {
		return mso, nil
	}
	// Fallback: try bare decode (some implementations omit the outer tag 24
	// from the COSE payload).
	var bare MobileSecurityObject
	if bareErr := intcose.Unmarshal(payload, &bare); bareErr != nil {
		return MobileSecurityObject{}, fmt.Errorf("mdoc: decode MSO payload (tag24: %v; bare: %w)", err, bareErr)
	}
	return bare, nil
}

func validateValidity(v ValidityInfo, now time.Time) error {
	if now.Before(v.ValidFrom) {
		return fmt.Errorf("mdoc: credential not yet valid (validFrom: %s, now: %s)", v.ValidFrom.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if now.After(v.ValidUntil) {
		return fmt.Errorf("mdoc: credential expired (validUntil: %s, now: %s)", v.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}
