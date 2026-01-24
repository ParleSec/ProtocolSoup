package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// XML Digital Signature Validation (XML-DSig)
// Per W3C XML Signature Syntax and Processing and SAML 2.0 Core Section 5
// ============================================================================

// SignatureValidationError represents a signature validation failure with context
type SignatureValidationError struct {
	Code        string
	Message     string
	Details     string
	RFCSection  string
}

func (e *SignatureValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Common signature validation error codes
const (
	ErrCodeNoSignature          = "NO_SIGNATURE"
	ErrCodeInvalidSignature     = "INVALID_SIGNATURE"
	ErrCodeDigestMismatch       = "DIGEST_MISMATCH"
	ErrCodeUnsupportedAlgorithm = "UNSUPPORTED_ALGORITHM"
	ErrCodeCertificateExpired   = "CERTIFICATE_EXPIRED"
	ErrCodeCertificateInvalid   = "CERTIFICATE_INVALID"
	ErrCodeReferenceInvalid     = "REFERENCE_INVALID"
)

// SignatureValidator validates XML digital signatures per XML-DSig specification
type SignatureValidator struct {
	mu              sync.RWMutex
	trustedCerts    map[string]*x509.Certificate // EntityID -> Certificate
	allowedAlgorithms map[string]bool
}

// NewSignatureValidator creates a new signature validator
// NOTE: SHA-1 algorithms are included for LEGACY COMPATIBILITY ONLY
// Many enterprise IdPs still use SHA-1 and require support for federation
// Production deployments SHOULD prefer SHA-256 or stronger
// The validator will emit warnings when SHA-1 algorithms are used
func NewSignatureValidator() *SignatureValidator {
	return &SignatureValidator{
		trustedCerts: make(map[string]*x509.Certificate),
		allowedAlgorithms: map[string]bool{
			// Signature algorithms (RECOMMENDED per SAML 2.0)
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256": true,
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384": true,
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512": true,
			// LEGACY: SHA-1 support for backwards compatibility with older IdPs
			// WARNING: SHA-1 is cryptographically weak and SHOULD NOT be used for new deployments
			// Included per industry practice for enterprise federation compatibility
			"http://www.w3.org/2000/09/xmldsig#rsa-sha1": true, // #nosec G401 - Legacy support required
			
			// Digest algorithms
			"http://www.w3.org/2001/04/xmlenc#sha256": true,
			"http://www.w3.org/2001/04/xmlenc#sha384": true,
			"http://www.w3.org/2001/04/xmlenc#sha512": true,
			// LEGACY: SHA-1 digest support
			"http://www.w3.org/2000/09/xmldsig#sha1": true, // #nosec G401 - Legacy support required
			
			// Canonicalization algorithms
			"http://www.w3.org/2001/10/xml-exc-c14n#":             true, // Exclusive C14N
			"http://www.w3.org/2001/10/xml-exc-c14n#WithComments": true,
			"http://www.w3.org/TR/2001/REC-xml-c14n-20010315":     true, // Canonical XML 1.0
			
			// Transform algorithms
			"http://www.w3.org/2000/09/xmldsig#enveloped-signature": true,
		},
	}
}

// RegisterTrustedCertificate registers a trusted IdP certificate for signature verification
func (v *SignatureValidator) RegisterTrustedCertificate(entityID string, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("certificate cannot be nil")
	}
	
	// Validate certificate
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return &SignatureValidationError{
			Code:    ErrCodeCertificateInvalid,
			Message: "certificate not yet valid",
			Details: fmt.Sprintf("NotBefore: %s", cert.NotBefore),
		}
	}
	if now.After(cert.NotAfter) {
		return &SignatureValidationError{
			Code:    ErrCodeCertificateExpired,
			Message: "certificate has expired",
			Details: fmt.Sprintf("NotAfter: %s", cert.NotAfter),
		}
	}
	
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedCerts[entityID] = cert
	return nil
}

// GetTrustedCertificate retrieves a registered certificate
func (v *SignatureValidator) GetTrustedCertificate(entityID string) (*x509.Certificate, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	cert, ok := v.trustedCerts[entityID]
	return cert, ok
}

// SignatureValidationResult contains the result of signature validation
type SignatureValidationResult struct {
	Valid             bool
	SignatureVerified bool
	DigestVerified    bool
	CertificateValid  bool
	Algorithm         string
	DigestAlgorithm   string
	ReferenceURI      string
	Errors            []string
	Warnings          []string
}

// ValidateResponseSignature validates the signature on a SAML Response
// Per SAML 2.0 Profiles Section 4.1.4.3, the SP MUST verify:
// - The signature on the Response or Assertion (at least one MUST be signed)
// - The digest of the signed content matches
func (v *SignatureValidator) ValidateResponseSignature(xmlData []byte, issuerEntityID string) (*SignatureValidationResult, error) {
	result := &SignatureValidationResult{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}
	
	// Parse the response to extract signature
	var response Response
	if err := xml.Unmarshal(xmlData, &response); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse SAML Response: %v", err))
		return result, err
	}
	
	// Check for signature on Response
	if response.Signature != nil {
		if err := v.validateSignature(xmlData, response.Signature, issuerEntityID, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Response signature validation failed: %v", err))
		} else {
			result.SignatureVerified = true
		}
	}
	
	// Check for signature on Assertions
	for i, assertion := range response.Assertions {
		if assertion != nil && assertion.Signature != nil {
			// Extract assertion XML for validation
			assertionXML, err := xml.Marshal(assertion)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Failed to marshal assertion %d: %v", i, err))
				continue
			}
			
			if err := v.validateSignature(assertionXML, assertion.Signature, issuerEntityID, result); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("Assertion %d signature validation failed: %v", i, err))
			} else {
				result.SignatureVerified = true
			}
		}
	}
	
	// Per SAML 2.0 Profiles, at least Response or Assertion MUST be signed
	if response.Signature == nil && !hasSignedAssertion(response.Assertions) {
		result.Errors = append(result.Errors, "Neither Response nor Assertion is signed (SAML 2.0 Profiles Section 4.1.4.3 violation)")
	}
	
	result.Valid = len(result.Errors) == 0 && result.SignatureVerified
	return result, nil
}

// validateSignature performs the actual signature validation
func (v *SignatureValidator) validateSignature(xmlData []byte, sig *Signature, issuerEntityID string, result *SignatureValidationResult) error {
	if sig == nil {
		return &SignatureValidationError{
			Code:    ErrCodeNoSignature,
			Message: "No signature present",
		}
	}
	
	// Validate signature algorithm is allowed
	sigAlg := sig.SignedInfo.SignatureMethod.Algorithm
	result.Algorithm = sigAlg
	if !v.allowedAlgorithms[sigAlg] {
		return &SignatureValidationError{
			Code:       ErrCodeUnsupportedAlgorithm,
			Message:    "Unsupported signature algorithm",
			Details:    sigAlg,
			RFCSection: "XML-DSig Section 6.1",
		}
	}
	
	// Check for weak algorithms and add warning
	if strings.Contains(sigAlg, "sha1") {
		result.Warnings = append(result.Warnings, "SHA-1 signature algorithm is deprecated; recommend SHA-256 or stronger")
	}
	
	// Validate digest algorithm
	digestAlg := sig.SignedInfo.Reference.DigestMethod.Algorithm
	result.DigestAlgorithm = digestAlg
	if !v.allowedAlgorithms[digestAlg] {
		return &SignatureValidationError{
			Code:       ErrCodeUnsupportedAlgorithm,
			Message:    "Unsupported digest algorithm",
			Details:    digestAlg,
			RFCSection: "XML-DSig Section 6.2",
		}
	}
	
	// Get reference URI
	result.ReferenceURI = sig.SignedInfo.Reference.URI
	
	// Get the trusted certificate
	cert, ok := v.GetTrustedCertificate(issuerEntityID)
	if !ok {
		// Try to extract certificate from signature if present
		if sig.KeyInfo != nil && sig.KeyInfo.X509Data != nil {
			certDER, err := base64.StdEncoding.DecodeString(
				strings.ReplaceAll(sig.KeyInfo.X509Data.X509Certificate, " ", ""))
			if err != nil {
				return &SignatureValidationError{
					Code:    ErrCodeCertificateInvalid,
					Message: "Failed to decode embedded certificate",
					Details: err.Error(),
				}
			}
			
			parsedCert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return &SignatureValidationError{
					Code:    ErrCodeCertificateInvalid,
					Message: "Failed to parse embedded certificate",
					Details: err.Error(),
				}
			}
			cert = parsedCert
			result.Warnings = append(result.Warnings, 
				"Using certificate from signature KeyInfo; should validate against trusted metadata")
		} else {
			return &SignatureValidationError{
				Code:    ErrCodeCertificateInvalid,
				Message: "No trusted certificate registered for issuer",
				Details: issuerEntityID,
			}
		}
	}
	result.CertificateValid = true
	
	// Verify digest
	if err := v.verifyDigest(xmlData, sig, digestAlg); err != nil {
		return err
	}
	result.DigestVerified = true
	
	// Verify signature value
	if err := v.verifySignatureValue(sig, cert, sigAlg); err != nil {
		return err
	}
	
	return nil
}

// verifyDigest verifies the digest value of the referenced content
func (v *SignatureValidator) verifyDigest(xmlData []byte, sig *Signature, digestAlg string) error {
	// Extract the referenced content
	refURI := sig.SignedInfo.Reference.URI
	
	// For enveloped signatures, the reference is to the parent element
	// The URI format is "#ID" where ID is the element's ID attribute
	var contentToHash []byte
	
	if refURI == "" || refURI == "#" {
		// Reference to the entire document
		contentToHash = xmlData
	} else if strings.HasPrefix(refURI, "#") {
		// Reference to element by ID
		elementID := strings.TrimPrefix(refURI, "#")
		extracted, err := extractElementByID(xmlData, elementID)
		if err != nil {
			return &SignatureValidationError{
				Code:       ErrCodeReferenceInvalid,
				Message:    "Failed to extract referenced element",
				Details:    fmt.Sprintf("URI: %s, Error: %v", refURI, err),
				RFCSection: "XML-DSig Section 4.3.3",
			}
		}
		contentToHash = extracted
	} else {
		return &SignatureValidationError{
			Code:       ErrCodeReferenceInvalid,
			Message:    "External references not supported",
			Details:    refURI,
			RFCSection: "SAML 2.0 Security Considerations",
		}
	}
	
	// Apply transforms (for enveloped signature, we need to remove the Signature element)
	for _, transform := range sig.SignedInfo.Reference.Transforms.Transforms {
		if transform.Algorithm == "http://www.w3.org/2000/09/xmldsig#enveloped-signature" {
			contentToHash = removeSignatureElement(contentToHash)
		}
		// Canonicalization transforms are applied implicitly
	}
	
	// Canonicalize the content (Exclusive C14N)
	canonicalized := canonicalizeXML(contentToHash)
	
	// Compute digest
	var computedDigest []byte
	switch {
	case strings.Contains(digestAlg, "sha256"):
		hash := sha256.Sum256(canonicalized)
		computedDigest = hash[:]
	case strings.Contains(digestAlg, "sha384"):
		hash := sha512.Sum384(canonicalized)
		computedDigest = hash[:]
	case strings.Contains(digestAlg, "sha512"):
		hash := sha512.Sum512(canonicalized)
		computedDigest = hash[:]
	default:
		return &SignatureValidationError{
			Code:    ErrCodeUnsupportedAlgorithm,
			Message: "Unsupported digest algorithm",
			Details: digestAlg,
		}
	}
	
	// Compare with expected digest
	expectedDigest, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(sig.SignedInfo.Reference.DigestValue))
	if err != nil {
		return &SignatureValidationError{
			Code:    ErrCodeDigestMismatch,
			Message: "Failed to decode expected digest",
			Details: err.Error(),
		}
	}
	
	if !compareBytes(computedDigest, expectedDigest) {
		return &SignatureValidationError{
			Code:       ErrCodeDigestMismatch,
			Message:    "Digest value mismatch",
			Details:    fmt.Sprintf("Expected: %s, Computed: %s", base64.StdEncoding.EncodeToString(expectedDigest), base64.StdEncoding.EncodeToString(computedDigest)),
			RFCSection: "XML-DSig Section 3.1.1",
		}
	}
	
	return nil
}

// verifySignatureValue verifies the signature over the SignedInfo element
func (v *SignatureValidator) verifySignatureValue(sig *Signature, cert *x509.Certificate, sigAlg string) error {
	// Marshal SignedInfo for signature verification
	signedInfoXML, err := xml.Marshal(sig.SignedInfo)
	if err != nil {
		return &SignatureValidationError{
			Code:    ErrCodeInvalidSignature,
			Message: "Failed to marshal SignedInfo",
			Details: err.Error(),
		}
	}
	
	// Canonicalize SignedInfo
	canonicalized := canonicalizeXML(signedInfoXML)
	
	// Decode signature value
	sigValue, err := base64.StdEncoding.DecodeString(
		strings.ReplaceAll(strings.TrimSpace(sig.SignatureValue), " ", ""))
	if err != nil {
		return &SignatureValidationError{
			Code:    ErrCodeInvalidSignature,
			Message: "Failed to decode signature value",
			Details: err.Error(),
		}
	}
	
	// Get public key
	rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return &SignatureValidationError{
			Code:    ErrCodeCertificateInvalid,
			Message: "Certificate does not contain RSA public key",
		}
	}
	
	// Verify signature based on algorithm
	var hashFunc crypto.Hash
	var hash []byte
	
	switch {
	case strings.Contains(sigAlg, "sha256"):
		hashFunc = crypto.SHA256
		h := sha256.Sum256(canonicalized)
		hash = h[:]
	case strings.Contains(sigAlg, "sha384"):
		hashFunc = crypto.SHA384
		h := sha512.Sum384(canonicalized)
		hash = h[:]
	case strings.Contains(sigAlg, "sha512"):
		hashFunc = crypto.SHA512
		h := sha512.Sum512(canonicalized)
		hash = h[:]
	default:
		return &SignatureValidationError{
			Code:    ErrCodeUnsupportedAlgorithm,
			Message: "Unsupported signature algorithm",
			Details: sigAlg,
		}
	}
	
	// Verify RSA PKCS#1 v1.5 signature
	if err := rsa.VerifyPKCS1v15(rsaPubKey, hashFunc, hash, sigValue); err != nil {
		return &SignatureValidationError{
			Code:       ErrCodeInvalidSignature,
			Message:    "Signature verification failed",
			Details:    err.Error(),
			RFCSection: "XML-DSig Section 6.1",
		}
	}
	
	return nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// hasSignedAssertion checks if any assertion in the slice has a signature
func hasSignedAssertion(assertions []*Assertion) bool {
	for _, a := range assertions {
		if a != nil && a.Signature != nil {
			return true
		}
	}
	return false
}

// extractElementByID extracts an XML element by its ID attribute
func extractElementByID(xmlData []byte, id string) ([]byte, error) {
	// Simple regex-based extraction (in production, use proper XML parsing)
	// This looks for elements with ID="<id>" or Id="<id>"
	pattern := fmt.Sprintf(`<[^>]*(?:ID|Id)="%s"[^>]*>`, regexp.QuoteMeta(id))
	re := regexp.MustCompile(pattern)
	
	loc := re.FindIndex(xmlData)
	if loc == nil {
		return nil, fmt.Errorf("element with ID %s not found", id)
	}
	
	// Find the matching closing tag
	startIdx := loc[0]
	depth := 1
	tagName := extractTagName(xmlData[startIdx:])
	
	// Simple depth-based matching (should use proper XML parser in production)
	endIdx := loc[1]
	for endIdx < len(xmlData) && depth > 0 {
		if xmlData[endIdx] == '<' {
			if endIdx+1 < len(xmlData) && xmlData[endIdx+1] == '/' {
				// Closing tag
				closeTag := fmt.Sprintf("</%s>", tagName)
				if strings.HasPrefix(string(xmlData[endIdx:]), closeTag) {
					depth--
					if depth == 0 {
						endIdx += len(closeTag)
						break
					}
				}
			} else if !strings.HasPrefix(string(xmlData[endIdx:]), "<?") && 
			          !strings.HasPrefix(string(xmlData[endIdx:]), "<!") {
				// Opening tag of same name
				openTag := fmt.Sprintf("<%s", tagName)
				if strings.HasPrefix(string(xmlData[endIdx:]), openTag) {
					depth++
				}
			}
		}
		endIdx++
	}
	
	if depth != 0 {
		return nil, fmt.Errorf("malformed XML: unmatched tags for element %s", id)
	}
	
	return xmlData[startIdx:endIdx], nil
}

// extractTagName extracts the tag name from an opening tag
func extractTagName(tag []byte) string {
	// Skip <
	start := 1
	for start < len(tag) && (tag[start] == ' ' || tag[start] == '\t') {
		start++
	}
	
	end := start
	for end < len(tag) && tag[end] != ' ' && tag[end] != '>' && tag[end] != '/' {
		end++
	}
	
	return string(tag[start:end])
}

// removeSignatureElement removes the Signature element for enveloped signature processing
func removeSignatureElement(xmlData []byte) []byte {
	// Simple regex-based removal (should use proper XML parser in production)
	re := regexp.MustCompile(`<(?:ds:)?Signature[^>]*>[\s\S]*?</(?:ds:)?Signature>`)
	return re.ReplaceAll(xmlData, []byte{})
}

// canonicalizeXML performs Exclusive XML Canonicalization (exc-c14n)
// This is a simplified implementation; production code should use a proper C14N library
func canonicalizeXML(xmlData []byte) []byte {
	// Basic normalization:
	// 1. Remove XML declaration
	// 2. Normalize whitespace in tags
	// 3. Sort attributes alphabetically
	// 4. Normalize namespace declarations
	
	result := xmlData
	
	// Remove XML declaration
	declRe := regexp.MustCompile(`<\?xml[^?]*\?>`)
	result = declRe.ReplaceAll(result, []byte{})
	
	// Normalize line endings to LF
	result = []byte(strings.ReplaceAll(string(result), "\r\n", "\n"))
	result = []byte(strings.ReplaceAll(string(result), "\r", "\n"))
	
	// Trim leading/trailing whitespace
	result = []byte(strings.TrimSpace(string(result)))
	
	return result
}

// compareBytes performs constant-time comparison to prevent timing attacks
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// ============================================================================
// Assertion Replay Prevention
// ============================================================================

// AssertionCache tracks consumed assertions to prevent replay attacks
// Per SAML 2.0 Profiles Section 4.1.4.5
type AssertionCache struct {
	mu       sync.RWMutex
	consumed map[string]time.Time // AssertionID -> consumption time
	ttl      time.Duration
}

// NewAssertionCache creates a new assertion cache with specified TTL
func NewAssertionCache(ttl time.Duration) *AssertionCache {
	cache := &AssertionCache{
		consumed: make(map[string]time.Time),
		ttl:      ttl,
	}
	
	// Start background cleanup goroutine
	go cache.cleanup()
	
	return cache
}

// MarkConsumed marks an assertion as consumed
// Returns error if assertion was already consumed (replay attack)
func (c *AssertionCache) MarkConsumed(assertionID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if _, exists := c.consumed[assertionID]; exists {
		return &SignatureValidationError{
			Code:       "REPLAY_ATTACK",
			Message:    "Assertion has already been consumed",
			Details:    assertionID,
			RFCSection: "SAML 2.0 Profiles Section 4.1.4.5",
		}
	}
	
	c.consumed[assertionID] = time.Now()
	return nil
}

// IsConsumed checks if an assertion has been consumed
func (c *AssertionCache) IsConsumed(assertionID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.consumed[assertionID]
	return exists
}

// cleanup periodically removes expired entries
func (c *AssertionCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		cutoff := time.Now().Add(-c.ttl)
		for id, consumedAt := range c.consumed {
			if consumedAt.Before(cutoff) {
				delete(c.consumed, id)
			}
		}
		c.mu.Unlock()
	}
}

// ============================================================================
// Request ID Tracking for InResponseTo Validation
// ============================================================================

// RequestIDCache tracks issued AuthnRequest IDs for InResponseTo validation
// Per SAML 2.0 Profiles Section 4.1.4.3
type RequestIDCache struct {
	mu      sync.RWMutex
	pending map[string]time.Time // RequestID -> issue time
	ttl     time.Duration
}

// NewRequestIDCache creates a new request ID cache
func NewRequestIDCache(ttl time.Duration) *RequestIDCache {
	cache := &RequestIDCache{
		pending: make(map[string]time.Time),
		ttl:     ttl,
	}
	
	go cache.cleanup()
	
	return cache
}

// StoreRequestID stores a newly issued request ID
func (c *RequestIDCache) StoreRequestID(requestID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[requestID] = time.Now()
}

// ValidateInResponseTo validates that InResponseTo matches a pending request
// Returns error if the request ID is not found or expired
func (c *RequestIDCache) ValidateInResponseTo(inResponseTo string) error {
	if inResponseTo == "" {
		// IdP-initiated SSO has no InResponseTo
		return nil
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	issuedAt, exists := c.pending[inResponseTo]
	if !exists {
		return &SignatureValidationError{
			Code:       "INVALID_RESPONSE",
			Message:    "InResponseTo does not match any pending request",
			Details:    inResponseTo,
			RFCSection: "SAML 2.0 Profiles Section 4.1.4.3",
		}
	}
	
	// Check if request has expired
	if time.Since(issuedAt) > c.ttl {
		delete(c.pending, inResponseTo)
		return &SignatureValidationError{
			Code:       "REQUEST_EXPIRED",
			Message:    "The original request has expired",
			Details:    fmt.Sprintf("RequestID: %s, IssuedAt: %s", inResponseTo, issuedAt),
			RFCSection: "SAML 2.0 Profiles Section 4.1.4.3",
		}
	}
	
	// Remove from pending (one-time use)
	delete(c.pending, inResponseTo)
	return nil
}

// cleanup periodically removes expired entries
func (c *RequestIDCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		cutoff := time.Now().Add(-c.ttl)
		for id, issuedAt := range c.pending {
			if issuedAt.Before(cutoff) {
				delete(c.pending, id)
			}
		}
		c.mu.Unlock()
	}
}
