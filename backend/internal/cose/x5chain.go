package cose

import (
	"crypto/x509"
	"fmt"
)

// x5chain (COSE header label 33, RFC 9360 Section 2) carries an ordered X.509
// certificate chain. Unlike the JOSE x5c header (an array of base64-encoded DER
// strings), COSE x5chain carries raw DER bytes: a single byte string when there
// is exactly one certificate, or an array of byte strings for a chain. The
// certificate containing the signing key comes first (leaf), the trust anchor
// last. mdoc places the issuer chain here in the IssuerAuth unprotected header.

// SetX5Chain stores the certificate chain in the unprotected header under
// label 33 (RFC 9360 Section 2). A single certificate is stored as one byte
// string; multiple certificates as an array of byte strings, leaf first.
func SetX5Chain(h UnprotectedHeader, chain []*x509.Certificate) error {
	if h == nil {
		return fmt.Errorf("cose: nil unprotected header")
	}
	if len(chain) == 0 {
		return fmt.Errorf("cose: x5chain requires at least one certificate")
	}
	if len(chain) == 1 {
		h[HeaderLabelX5Chain] = chain[0].Raw
		return nil
	}
	der := make([][]byte, len(chain))
	for i, cert := range chain {
		if cert == nil {
			return fmt.Errorf("cose: x5chain certificate %d is nil", i)
		}
		der[i] = cert.Raw
	}
	h[HeaderLabelX5Chain] = der
	return nil
}

// GetX5Chain reads and parses the certificate chain from the unprotected header
// label 33. It accepts both the single-certificate (byte string) and
// multi-certificate (array of byte strings) encodings of RFC 9360 Section 2.
func GetX5Chain(h UnprotectedHeader) ([]*x509.Certificate, error) {
	if h == nil {
		return nil, fmt.Errorf("cose: nil unprotected header")
	}
	raw, ok := h[HeaderLabelX5Chain]
	if !ok {
		return nil, fmt.Errorf("cose: unprotected header has no x5chain (label 33)")
	}
	derList, err := x5chainDERList(raw)
	if err != nil {
		return nil, err
	}
	certs := make([]*x509.Certificate, 0, len(derList))
	for i, der := range derList {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("cose: parse x5chain certificate %d: %w", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func x5chainDERList(raw any) ([][]byte, error) {
	switch v := raw.(type) {
	case []byte:
		return [][]byte{v}, nil
	case [][]byte:
		if len(v) == 0 {
			return nil, fmt.Errorf("cose: x5chain array is empty")
		}
		return v, nil
	case []any:
		if len(v) == 0 {
			return nil, fmt.Errorf("cose: x5chain array is empty")
		}
		out := make([][]byte, len(v))
		for i, e := range v {
			der, ok := e.([]byte)
			if !ok {
				return nil, fmt.Errorf("cose: x5chain entry %d is %T, want byte string", i, e)
			}
			out[i] = der
		}
		return out, nil
	default:
		return nil, fmt.Errorf("cose: x5chain value is %T, want byte string or array of byte strings", raw)
	}
}
