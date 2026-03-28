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

// ValidateCertificateChain verifies the certificate chain and returns the leaf certificate.
func ValidateCertificateChain(certificates []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if len(certificates) == 0 {
		return nil, fmt.Errorf("certificate chain is required")
	}
	leaf := certificates[0]
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	intermediates := x509.NewCertPool()
	for idx, certificate := range certificates[1:] {
		if idx == len(certificates[1:])-1 && isSelfSignedCertificate(certificate) {
			roots.AddCert(certificate)
			continue
		}
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

func isSelfSignedCertificate(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	return certificate.CheckSignatureFrom(certificate) == nil
}
