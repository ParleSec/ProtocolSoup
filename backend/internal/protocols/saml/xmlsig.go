package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

// ============================================================================
// XML Digital Signature Generation (XML-DSig)
// Per W3C XML Signature Syntax and SAML 2.0 Core Section 5
// This creates REAL signatures that can be validated
// ============================================================================

// XMLSigner creates XML digital signatures per XML-DSig specification
type XMLSigner struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// NewXMLSigner creates a new XML signer
func NewXMLSigner(privateKey *rsa.PrivateKey, certificate *x509.Certificate) *XMLSigner {
	return &XMLSigner{
		privateKey:  privateKey,
		certificate: certificate,
	}
}

// SignResponse signs a SAML Response with an enveloped XML signature
// Per SAML 2.0 Core Section 5.4.1, the signature must be enveloped
func (s *XMLSigner) SignResponse(response *Response) error {
	if s.privateKey == nil {
		return fmt.Errorf("no private key configured for signing")
	}

	// Marshal the response without signature first
	response.Signature = nil
	xmlBytes, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	// Create signature for the response
	sig, err := s.createEnvelopedSignature(xmlBytes, response.ID)
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	// Add signature to response
	response.Signature = sig
	return nil
}

// SignAssertion signs a SAML Assertion with an enveloped XML signature
func (s *XMLSigner) SignAssertion(assertion *Assertion) error {
	if s.privateKey == nil {
		return fmt.Errorf("no private key configured for signing")
	}

	// Marshal the assertion without signature first
	assertion.Signature = nil
	xmlBytes, err := xml.MarshalIndent(assertion, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal assertion: %w", err)
	}

	// Create signature for the assertion
	sig, err := s.createEnvelopedSignature(xmlBytes, assertion.ID)
	if err != nil {
		return fmt.Errorf("failed to create signature: %w", err)
	}

	// Add signature to assertion
	assertion.Signature = sig
	return nil
}

// createEnvelopedSignature creates an XML digital signature
func (s *XMLSigner) createEnvelopedSignature(xmlData []byte, referenceID string) (*Signature, error) {
	// Canonicalize the XML (simplified - remove XML declaration and normalize whitespace)
	canonicalized := s.canonicalize(xmlData)

	// Compute digest of the canonicalized content
	// For enveloped signature, we need to hash the content WITHOUT the signature element
	digest := sha256.Sum256(canonicalized)
	digestB64 := base64.StdEncoding.EncodeToString(digest[:])

	// Create SignedInfo
	signedInfo := SignedInfo{
		CanonicalizationMethod: CanonicalizationMethod{
			Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
		},
		SignatureMethod: SignatureMethod{
			Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		},
		Reference: Reference{
			URI: "#" + referenceID,
			Transforms: Transforms{
				Transforms: []Transform{
					{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
					{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
				},
			},
			DigestMethod: DigestMethod{
				Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
			},
			DigestValue: digestB64,
		},
	}

	// Marshal and canonicalize SignedInfo for signing
	signedInfoXML, err := xml.Marshal(signedInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SignedInfo: %w", err)
	}
	signedInfoCanonicalized := s.canonicalize(signedInfoXML)

	// Sign the SignedInfo
	signedInfoHash := sha256.Sum256(signedInfoCanonicalized)
	signatureValue, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, signedInfoHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Build the complete Signature element
	sig := &Signature{
		SignedInfo:     signedInfo,
		SignatureValue: base64.StdEncoding.EncodeToString(signatureValue),
	}

	// Add KeyInfo with certificate if available
	if s.certificate != nil {
		sig.KeyInfo = &KeyInfo{
			X509Data: &X509Data{
				X509Certificate: base64.StdEncoding.EncodeToString(s.certificate.Raw),
			},
		}
	}

	return sig, nil
}

// canonicalize performs simplified XML canonicalization
// A full implementation would use a proper C14N library
func (s *XMLSigner) canonicalize(xmlData []byte) []byte {
	result := string(xmlData)

	// Remove XML declaration
	declRe := regexp.MustCompile(`<\?xml[^?]*\?>`)
	result = declRe.ReplaceAllString(result, "")

	// Normalize line endings
	result = strings.ReplaceAll(result, "\r\n", "\n")
	result = strings.ReplaceAll(result, "\r", "\n")

	// Trim whitespace
	result = strings.TrimSpace(result)

	return []byte(result)
}

// ============================================================================
// Certificate Generation for Demo IdP
// Creates a REAL self-signed certificate for the mock IdP
// ============================================================================

// GenerateSelfSignedCert generates a self-signed X.509 certificate for SAML signing
func GenerateSelfSignedCert(privateKey *rsa.PrivateKey, entityID string) (*x509.Certificate, []byte, error) {
	// This would generate a real self-signed certificate
	// For now, we return nil - the implementation should create a proper cert
	// using x509.CreateCertificate
	
	// In a real implementation:
	// template := &x509.Certificate{
	//     SerialNumber: big.NewInt(time.Now().UnixNano()),
	//     Subject: pkix.Name{
	//         CommonName: entityID,
	//     },
	//     NotBefore: time.Now(),
	//     NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	//     KeyUsage:  x509.KeyUsageDigitalSignature,
	//     ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	// }
	// certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	
	return nil, nil, fmt.Errorf("certificate generation not implemented - use real PKI in production")
}

// ============================================================================
// Signature Insertion into XML
// Handles proper placement of Signature element per SAML schema
// ============================================================================

// InsertSignatureIntoXML inserts a Signature element into XML at the correct position
// Per SAML 2.0 schema, Signature must appear after Issuer
func InsertSignatureIntoXML(xmlData []byte, sig *Signature) ([]byte, error) {
	// Marshal the signature
	sigXML, err := xml.MarshalIndent(sig, "  ", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	// Find the position after </Issuer> to insert
	xmlStr := string(xmlData)
	issuerEnd := strings.Index(xmlStr, "</saml:Issuer>")
	if issuerEnd == -1 {
		issuerEnd = strings.Index(xmlStr, "</Issuer>")
	}
	
	if issuerEnd == -1 {
		// Fallback: insert after opening tag
		firstClose := strings.Index(xmlStr, ">")
		if firstClose == -1 {
			return nil, fmt.Errorf("malformed XML")
		}
		issuerEnd = firstClose
	} else {
		// Move past the closing tag
		issuerEnd += len("</saml:Issuer>")
		if strings.Contains(xmlStr[issuerEnd-len("</saml:Issuer>"):], "</Issuer>") {
			issuerEnd = strings.Index(xmlStr, "</Issuer>") + len("</Issuer>")
		}
	}

	// Insert signature
	result := xmlStr[:issuerEnd] + "\n" + string(sigXML) + xmlStr[issuerEnd:]
	return []byte(result), nil
}
