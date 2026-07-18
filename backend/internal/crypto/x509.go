package crypto

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"
)

// ParseX5CCertificateChain decodes the JOSE x5c header into parsed certificates.
func ParseX5CCertificateChain(raw interface{}) ([]*x509.Certificate, error) {
	rawValues, ok := raw.([]interface{})
	if !ok || len(rawValues) == 0 {
		return nil, fmt.Errorf("x5c header is required")
	}
	certificates := make([]*x509.Certificate, 0, len(rawValues))
	for idx, item := range rawValues {
		encoded, ok := item.(string)
		if !ok || encoded == "" {
			return nil, fmt.Errorf("x5c header entry %d is invalid", idx)
		}
		derBytes, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode x5c certificate %d: %w", idx, err)
		}
		certificate, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, fmt.Errorf("parse x5c certificate %d: %w", idx, err)
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

// ValidateCertificateChain verifies a certificate chain against the operating
// system trust store and returns the leaf certificate. Certificates supplied in
// x5c are untrusted chain material; a self-signed certificate in that header is
// never promoted to a trust anchor.
func ValidateCertificateChain(certificates []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	return ValidateCertificateChainAgainstRoots(certificates, roots, now)
}

// ValidateCertificateChainAgainstRoots verifies x5c chain material against an
// independently configured trust pool. The caller, not the untrusted message,
// determines which roots are trusted.
func ValidateCertificateChainAgainstRoots(certificates []*x509.Certificate, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(certificates) == 0 {
		return nil, fmt.Errorf("certificate chain is required")
	}
	if roots == nil {
		return nil, fmt.Errorf("certificate trust roots are required")
	}
	leaf := certificates[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("verify certificate chain: %w", err)
	}
	return leaf, nil
}
