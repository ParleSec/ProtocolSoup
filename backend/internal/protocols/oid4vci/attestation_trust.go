package oid4vci

import (
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

// loadTrustAnchorPool builds a certificate pool from a PEM value in the named
// environment variable. It returns (nil, nil) when the variable is unset, so
// callers can distinguish "no trust anchor configured" (feature disabled)
// from a configuration error (variable set but unparsable) -- the same
// discipline already used for the mso_mdoc IACA root
// (oid4vp/mdoc_presentation.go mdocIACARootPEM).
func loadTrustAnchorPool(envVar string) (*x509.CertPool, error) {
	pemValue := strings.TrimSpace(os.Getenv(envVar))
	if pemValue == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemValue)) {
		return nil, fmt.Errorf("%s contains no usable PEM certificates", envVar)
	}
	return pool, nil
}

// validateChainAgainstRoots verifies an x5c-style certificate chain
// (leaf-first, RFC 7515 §4.1.6) against a pinned root pool only. Unlike
// crypto.ValidateCertificateChain (used for the general x5c JOSE header
// helper), this never falls back to the host's system trust store: a pinned
// attestation trust anchor for client- or key-attestation must not also
// accept an otherwise-valid public web certificate.
func validateChainAgainstRoots(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("certificate chain is required")
	}
	if roots == nil {
		return nil, fmt.Errorf("no trust anchor is configured")
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
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
