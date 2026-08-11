package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	if roots == nil {
		return nil, fmt.Errorf("mdoc: issuer trust roots are required")
	}
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
	if err := validateMobileSecurityObject(mso); err != nil {
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
	if err := validateMobileSecurityObject(mso); err != nil {
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

// IssuerAuthorityKeyIdentifier returns the Authority Key Identifier used for
// DCQL trusted_authorities (type=aki) matching. Callers use it only after
// VerifyIssuerSigned succeeds, so the certificate and identifier are anchored
// in the independently configured issuer trust store.
//
// Prefer the leaf certificate's AuthorityKeyIdentifier (RFC 5280), which for a
// normal IACA→DS chain equals the IACA SubjectKeyIdentifier that HAIP
// advertises. When IssuerAuth is signed by a self-signed trust anchor that
// omits AKI (self-signed trust-anchor mock-wallet shape), fall back to the
// leaf SubjectKeyIdentifier — that is the authority's key identifier.
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
	return authorityKeyIdentifierFromLeaf(chain[0]), nil
}

// authorityKeyIdentifierFromLeaf returns the AKI used for DCQL trusted_authorities
// matching. See IssuerAuthorityKeyIdentifier.
func authorityKeyIdentifierFromLeaf(leaf *x509.Certificate) []byte {
	if leaf == nil {
		return nil
	}
	if len(leaf.AuthorityKeyId) > 0 {
		return append([]byte(nil), leaf.AuthorityKeyId...)
	}
	if bytes.Equal(leaf.RawSubject, leaf.RawIssuer) && len(leaf.SubjectKeyId) > 0 {
		return append([]byte(nil), leaf.SubjectKeyId...)
	}
	return nil
}

func extractAndVerifyDocSignerKey(msg *intcose.Sign1Message, roots *x509.CertPool, now time.Time) (*ecdsa.PublicKey, error) {
	if roots == nil {
		return nil, fmt.Errorf("mdoc: issuer trust roots are required")
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

	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("mdoc: x5chain certificate path validation failed: %w", err)
	}

	// ISO/IEC 18013-5 Annex B profiles a distinct document-signer leaf
	// (CA=false, digitalSignature, mDL DS EKU). Some mock wallets sign
	// IssuerAuth with the configured IACA itself (a self-signed CA placed
	// alone in x5chain). When path validation shows the leaf is the trust
	// anchor, skip DS-only profile checks; keep them for real IACA→DS chains.
	if !leafIsConfiguredTrustAnchor(verifiedChains) {
		if err := validateDocumentSignerCertificate(leaf); err != nil {
			return nil, err
		}
	}

	ecdsaKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mdoc: document-signer certificate has %T key, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	if ecdsaKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mdoc: document-signer certificate key must use P-256")
	}
	// RFC 9360 x5chain is a certificate transport header, not a certificate
	// thumbprint contract. VerifyIssuerSigned uses this exact leaf key to verify
	// the COSE_Sign1, which proves possession and binds IssuerAuth to the leaf.
	return ecdsaKey, nil
}

// leafIsConfiguredTrustAnchor reports whether path validation accepted the
// IssuerAuth leaf as the trust anchor itself (verified chain length 1), rather
// than as an Annex B document-signer certificate beneath a separate IACA.
func leafIsConfiguredTrustAnchor(chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		if len(chain) == 1 {
			return true
		}
	}
	return false
}

func decodeMSOFromPayload(payload []byte) (MobileSecurityObject, error) {
	mso, err := DecodeMSOBytes(payload)
	if err != nil {
		return MobileSecurityObject{}, fmt.Errorf("mdoc: IssuerAuth payload must be tagged MobileSecurityObjectBytes: %w", err)
	}
	return mso, nil
}

func validateDocumentSignerCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("mdoc: document-signer certificate is nil")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return fmt.Errorf("mdoc: document-signer certificate must have Basic Constraints CA=false")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		return fmt.Errorf("mdoc: document-signer certificate key usage must be digitalSignature only")
	}
	hasMDLDSEKU := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDExtKeyUsageMDLDS) {
			hasMDLDSEKU = true
			break
		}
	}
	if !hasMDLDSEKU {
		return fmt.Errorf("mdoc: document-signer certificate is missing extended key usage %s", OIDExtKeyUsageMDLDS)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 160 {
		return fmt.Errorf("mdoc: document-signer certificate serial number must be positive and at most 20 octets")
	}
	if len(cert.Subject.Country) == 0 || len(cert.Subject.Country[0]) != 2 || len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] == "" {
		return fmt.Errorf("mdoc: document-signer certificate subject must contain countryName and organizationName")
	}
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || !cert.NotBefore.Before(cert.NotAfter) {
		return fmt.Errorf("mdoc: document-signer certificate has an invalid validity period")
	}
	if cert.NotAfter.Sub(cert.NotBefore) > dsMaxValidity {
		return fmt.Errorf("mdoc: document-signer certificate validity exceeds the 15-month profile maximum")
	}
	if len(cert.SubjectKeyId) == 0 || len(cert.AuthorityKeyId) == 0 {
		return fmt.Errorf("mdoc: document-signer certificate must contain subjectKeyIdentifier and authorityKeyIdentifier")
	}
	if len(cert.CRLDistributionPoints) == 0 {
		return fmt.Errorf("mdoc: document-signer certificate must contain a CRL distribution point")
	}
	hasIssuerAltName := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidIssuerAltName) {
			hasIssuerAltName = true
			break
		}
	}
	if !hasIssuerAltName {
		return fmt.Errorf("mdoc: document-signer certificate must contain issuerAltName")
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fmt.Errorf("mdoc: document-signer certificate signature algorithm must be ECDSA-with-SHA256")
	}
	return nil
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
