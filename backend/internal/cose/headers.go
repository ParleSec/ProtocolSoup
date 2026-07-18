package cose

import "github.com/veraison/go-cose"

// Algorithm is a COSE algorithm identifier from the IANA "COSE Algorithms"
// registry (RFC 9053). mdoc is ES256/P-256 first, so that is the only signing
// algorithm used by the mdoc implementation.
type Algorithm = cose.Algorithm

const (
	// AlgorithmES256 is ECDSA with SHA-256 (RFC 9053 Section 2.1, COSE alg -7).
	// This is the issuer-auth and device-auth signature algorithm for mdoc.
	AlgorithmES256 = cose.AlgorithmES256
)

// COSE header parameter labels from the IANA "COSE Header Parameters" registry
// (RFC 9052 Section 3.1, RFC 9360 Section 2). Re-exported from go-cose so the
// rest of the mdoc code references one set of constants.
const (
	// HeaderLabelAlgorithm is the protected-header "alg" label (1).
	HeaderLabelAlgorithm = cose.HeaderLabelAlgorithm

	// HeaderLabelKeyID is the "kid" label (4).
	HeaderLabelKeyID = cose.HeaderLabelKeyID

	// HeaderLabelX5Chain is the "x5chain" label (33), which carries an X.509
	// certificate chain (RFC 9360 Section 2). mdoc puts the issuer chain here
	// in the IssuerAuth unprotected header.
	HeaderLabelX5Chain = cose.HeaderLabelX5Chain
)

// ProtectedHeader is the cryptographically protected COSE header bucket
// (RFC 9052 Section 3). It is an alias of the go-cose type so values built here
// can be passed straight into the library signer without conversion.
type ProtectedHeader = cose.ProtectedHeader

// UnprotectedHeader is the COSE header bucket that is not cryptographically
// protected (RFC 9052 Section 3).
type UnprotectedHeader = cose.UnprotectedHeader

// Headers groups the two COSE header buckets (RFC 9052 Section 3).
type Headers = cose.Headers

// ES256ProtectedHeader returns a protected header carrying alg=ES256, the usual
// protected header for an mdoc IssuerAuth COSE_Sign1.
func ES256ProtectedHeader() ProtectedHeader {
	return ProtectedHeader{HeaderLabelAlgorithm: AlgorithmES256}
}
