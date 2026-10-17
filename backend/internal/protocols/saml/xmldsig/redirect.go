package xmldsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	dsig "github.com/russellhaering/goxmldsig"
)

// SigAlgRSASHA256 is the SigAlg this deployment uses on HTTP-Redirect.
const SigAlgRSASHA256 = dsig.RSASHA256SignatureMethod

// signatureAlgorithms maps the SigAlg URIs this deployment accepts on the
// HTTP-Redirect binding to the x509 verification algorithm.
var signatureAlgorithms = map[string]x509.SignatureAlgorithm{
	dsig.RSASHA256SignatureMethod: x509.SHA256WithRSA,
	dsig.RSASHA384SignatureMethod: x509.SHA384WithRSA,
	dsig.RSASHA512SignatureMethod: x509.SHA512WithRSA,
}

// SignRedirectOctets signs the octet string built per SAML Bindings Section
// 3.4.4.1 with RSA-SHA256 and returns the base64 signature value.
func SignRedirectOctets(octets string, creds *Credentials) (string, error) {
	digest := sha256.Sum256([]byte(octets))
	signature, err := rsa.SignPKCS1v15(rand.Reader, creds.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyRedirectOctets checks a Redirect-binding Signature against any of the
// signer's published certificates (SAML Metadata Section 2.4.1.1, Errata E68).
func VerifyRedirectOctets(octets, sigAlg, signatureB64 string, trusted []*x509.Certificate) error {
	algorithm, ok := signatureAlgorithms[sigAlg]
	if !ok {
		return fmt.Errorf("SigAlg %q is not accepted", sigAlg)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("query Signature is not valid base64: %w", err)
	}
	if len(trusted) == 0 {
		return errors.New("no signing certificate is published in the signer's metadata")
	}
	for _, cert := range trusted {
		if cert.CheckSignature(algorithm, []byte(octets), signature) == nil {
			return nil
		}
	}
	return errors.New("query Signature does not verify against any signing certificate in the signer's metadata")
}
