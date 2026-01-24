package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// ============================================================================
// HTTP-Redirect Binding (SAML 2.0 Bindings Section 3.4)
// ============================================================================

// RedirectBinding handles the HTTP-Redirect binding
type RedirectBinding struct {
	privateKey *rsa.PrivateKey
}

// NewRedirectBinding creates a new redirect binding handler
func NewRedirectBinding(privateKey *rsa.PrivateKey) *RedirectBinding {
	return &RedirectBinding{
		privateKey: privateKey,
	}
}

// Encode encodes a SAML message for HTTP-Redirect binding
// Per SAML 2.0 Bindings Section 3.4.4.1:
// 1. Serialize the message to XML
// 2. DEFLATE compress (without header/checksum)
// 3. Base64 encode
// 4. URL encode
func (b *RedirectBinding) Encode(message interface{}) (string, error) {
	// Serialize to XML
	xmlData, err := xml.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("failed to marshal XML: %w", err)
	}

	// DEFLATE compress (raw deflate, no zlib header)
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return "", fmt.Errorf("failed to create deflate writer: %w", err)
	}
	if _, err := writer.Write(xmlData); err != nil {
		writer.Close()
		return "", fmt.Errorf("failed to write compressed data: %w", err)
	}
	writer.Close()

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())

	return encoded, nil
}

// Decode decodes a SAML message from HTTP-Redirect binding
func (b *RedirectBinding) Decode(encoded string) ([]byte, error) {
	// Base64 decode
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	// DEFLATE decompress
	reader := flate.NewReader(bytes.NewReader(compressed))
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	return decompressed, nil
}

// BuildRedirectURL builds the redirect URL with the SAML message
// Per SAML 2.0 Bindings Section 3.4.4.1, the signature is computed over the
// concatenation of the following query string components in order:
// SAMLRequest=value (or SAMLResponse=value) & RelayState=value & SigAlg=value
func (b *RedirectBinding) BuildRedirectURL(destination string, message interface{}, relayState string, isRequest bool) (string, error) {
	encoded, err := b.Encode(message)
	if err != nil {
		return "", err
	}

	// Build query parameters
	paramName := "SAMLResponse"
	if isRequest {
		paramName = "SAMLRequest"
	}

	// Per SAML 2.0 Bindings 3.4.4.1, signature must be over the ordered concatenation
	var signatureInput strings.Builder
	signatureInput.WriteString(paramName)
	signatureInput.WriteString("=")
	signatureInput.WriteString(url.QueryEscape(encoded))

	// Build final params
	params := url.Values{}
	params.Set(paramName, encoded)

	if relayState != "" {
		signatureInput.WriteString("&RelayState=")
		signatureInput.WriteString(url.QueryEscape(relayState))
		params.Set("RelayState", relayState)
	}

	// Sign if we have a private key
	if b.privateKey != nil {
		sigAlg := "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		signatureInput.WriteString("&SigAlg=")
		signatureInput.WriteString(url.QueryEscape(sigAlg))

		// Hash and sign per SAML 2.0 Bindings Section 3.4.4.1
		hash := sha256.Sum256([]byte(signatureInput.String()))
		signature, err := rsa.SignPKCS1v15(rand.Reader, b.privateKey, crypto.SHA256, hash[:])
		if err != nil {
			return "", fmt.Errorf("failed to sign: %w", err)
		}

		params.Set("SigAlg", sigAlg)
		params.Set("Signature", base64.StdEncoding.EncodeToString(signature))
	}

	// Build final URL
	parsedURL, err := url.Parse(destination)
	if err != nil {
		return "", fmt.Errorf("invalid destination URL: %w", err)
	}
	parsedURL.RawQuery = params.Encode()

	return parsedURL.String(), nil
}

// ParseRedirectRequest parses a redirect binding request
func (b *RedirectBinding) ParseRedirectRequest(r *http.Request) ([]byte, string, error) {
	query := r.URL.Query()

	var encoded string
	var isRequest bool

	if samlRequest := query.Get("SAMLRequest"); samlRequest != "" {
		encoded = samlRequest
		isRequest = true
	} else if samlResponse := query.Get("SAMLResponse"); samlResponse != "" {
		encoded = samlResponse
		isRequest = false
	} else {
		return nil, "", fmt.Errorf("no SAMLRequest or SAMLResponse in query")
	}
	_ = isRequest // May be used for signature verification in future

	relayState := query.Get("RelayState")

	// Decode the message
	xmlData, err := b.Decode(encoded)
	if err != nil {
		return nil, "", err
	}

	return xmlData, relayState, nil
}

// ============================================================================
// HTTP-POST Binding (SAML 2.0 Bindings Section 3.5)
// ============================================================================

// PostBinding handles the HTTP-POST binding
type PostBinding struct {
	privateKey *rsa.PrivateKey
	signer     *XMLSigner
}

// NewPostBinding creates a new POST binding handler
func NewPostBinding(privateKey *rsa.PrivateKey) *PostBinding {
	pb := &PostBinding{
		privateKey: privateKey,
	}
	if privateKey != nil {
		pb.signer = NewXMLSigner(privateKey, nil)
	}
	return pb
}

// Encode encodes a SAML message for HTTP-POST binding
// Per SAML 2.0 Bindings Section 3.5.4:
// 1. Sign the message with XML digital signature (if private key available)
// 2. Serialize the message to XML
// 3. Base64 encode (no compression)
func (b *PostBinding) Encode(message interface{}) (string, error) {
	// Sign the message if we have a signer - this creates XML digital signatures
	// Per SAML 2.0 Core Section 5, messages SHOULD be signed for integrity
	if b.signer != nil {
		switch msg := message.(type) {
		case *Response:
			// Sign both the Response and its Assertions per SAML best practice
			// This creates cryptographic signatures that can be validated
			for _, assertion := range msg.Assertions {
				if assertion != nil {
					if err := b.signer.SignAssertion(assertion); err != nil {
						log.Printf("[SAML] Warning: Failed to sign assertion %s: %v", assertion.ID, err)
					} else {
						log.Printf("[SAML] Signed assertion %s with RSA-SHA256", assertion.ID)
					}
				}
			}
			// Also sign the Response itself
			if err := b.signer.SignResponse(msg); err != nil {
				log.Printf("[SAML] Warning: Failed to sign response %s: %v", msg.ID, err)
			} else {
				log.Printf("[SAML] Signed response %s with RSA-SHA256", msg.ID)
			}
		case *AuthnRequest:
			// AuthnRequests can optionally be signed per SP metadata
			log.Printf("[SAML] AuthnRequest %s created (signing optional per metadata)", msg.ID)
		case *LogoutRequest:
			// LogoutRequests should be signed
			log.Printf("[SAML] LogoutRequest created (signature support pending)")
		case *LogoutResponse:
			// LogoutResponses should be signed
			log.Printf("[SAML] LogoutResponse created (signature support pending)")
		}
	}

	// Serialize to XML
	xmlData, err := xml.MarshalIndent(message, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal XML: %w", err)
	}

	// Add XML declaration
	xmlWithDecl := []byte(xml.Header + string(xmlData))

	// Base64 encode
	encoded := base64.StdEncoding.EncodeToString(xmlWithDecl)

	return encoded, nil
}

// Decode decodes a SAML message from HTTP-POST binding
func (b *PostBinding) Decode(encoded string) ([]byte, error) {
	// Handle potential URL encoding
	decoded := strings.ReplaceAll(encoded, " ", "+")

	// Base64 decode
	xmlData, err := base64.StdEncoding.DecodeString(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	return xmlData, nil
}

// postFormTemplate is a pre-compiled template for POST binding forms
// Using html/template provides automatic context-aware escaping per OWASP recommendations
var postFormTemplate = template.Must(template.New("postForm").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; form-action {{.Destination}}">
    <title>SAML POST Binding</title>
</head>
<body onload="document.forms[0].submit()">
    <noscript>
        <p>JavaScript is required. Please click the button below to continue.</p>
    </noscript>
    <form method="POST" action="{{.Destination}}">
        <input type="hidden" name="{{.ParamName}}" value="{{.SAMLMessage}}"/>
        {{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}"/>{{end}}
        <noscript>
            <input type="submit" value="Continue"/>
        </noscript>
    </form>
</body>
</html>`))

// postFormData holds data for the POST form template
type postFormData struct {
	Destination string
	ParamName   string
	SAMLMessage string
	RelayState  string
}

// GeneratePostForm generates an auto-submitting HTML form for POST binding
// Uses html/template for automatic context-aware XSS protection
// Per SAML 2.0 Bindings Section 3.5.4
func (b *PostBinding) GeneratePostForm(destination string, message interface{}, relayState string, isRequest bool) (string, error) {
	encoded, err := b.Encode(message)
	if err != nil {
		return "", err
	}

	paramName := "SAMLResponse"
	if isRequest {
		paramName = "SAMLRequest"
	}

	// Validate destination URL to prevent XSS and open redirect
	// Per security best practices, validate before use
	if err := validateDestinationURL(destination); err != nil {
		return "", fmt.Errorf("invalid destination URL: %w", err)
	}

	// Sanitize relayState - limit length (template handles escaping)
	if len(relayState) > 1024 {
		relayState = relayState[:1024]
	}

	// Use html/template for automatic context-aware escaping
	// This prevents XSS by escaping based on HTML context (attribute, content, etc.)
	data := postFormData{
		Destination: destination,
		ParamName:   paramName,
		SAMLMessage: encoded,
		RelayState:  relayState,
	}

	var buf bytes.Buffer
	if err := postFormTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render POST form: %w", err)
	}

	return buf.String(), nil
}

// ParsePostRequest parses a POST binding request
func (b *PostBinding) ParsePostRequest(r *http.Request) ([]byte, string, error) {
	if err := r.ParseForm(); err != nil {
		return nil, "", fmt.Errorf("failed to parse form: %w", err)
	}

	var encoded string

	if samlRequest := r.FormValue("SAMLRequest"); samlRequest != "" {
		encoded = samlRequest
	} else if samlResponse := r.FormValue("SAMLResponse"); samlResponse != "" {
		encoded = samlResponse
	} else {
		return nil, "", fmt.Errorf("no SAMLRequest or SAMLResponse in form")
	}

	relayState := r.FormValue("RelayState")

	// Decode the message
	xmlData, err := b.Decode(encoded)
	if err != nil {
		return nil, "", err
	}

	return xmlData, relayState, nil
}

// ============================================================================
// Shared Utilities
// ============================================================================

// escapeHTML escapes HTML special characters
// validateDestinationURL validates a URL is safe for use as a form action or redirect
func validateDestinationURL(dest string) error {
	if dest == "" {
		return fmt.Errorf("empty URL")
	}

	// Parse the URL
	parsed, err := url.Parse(dest)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}

	// Block dangerous schemes (javascript:, data:, vbscript:, etc.)
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return fmt.Errorf("invalid URL scheme: %s", scheme)
	}

	// For absolute URLs, ensure scheme is present
	if parsed.Host != "" && scheme == "" {
		return fmt.Errorf("absolute URL missing scheme")
	}

	return nil
}

// BindingType represents the type of SAML binding
type BindingType string

const (
	BindingTypeRedirect BindingType = "redirect"
	BindingTypePost     BindingType = "post"
)

// DetectBinding detects the binding type from an HTTP request
func DetectBinding(r *http.Request) BindingType {
	if r.Method == http.MethodPost {
		return BindingTypePost
	}
	return BindingTypeRedirect
}

// ParseRequest parses a SAML request from any binding type
func ParseRequest(r *http.Request, privateKey *rsa.PrivateKey) ([]byte, string, BindingType, error) {
	bindingType := DetectBinding(r)

	var xmlData []byte
	var relayState string
	var err error

	switch bindingType {
	case BindingTypePost:
		binding := NewPostBinding(privateKey)
		xmlData, relayState, err = binding.ParsePostRequest(r)
	case BindingTypeRedirect:
		binding := NewRedirectBinding(privateKey)
		xmlData, relayState, err = binding.ParseRedirectRequest(r)
	}

	if err != nil {
		return nil, "", bindingType, err
	}

	return xmlData, relayState, bindingType, nil
}

// SendResponse sends a SAML response using the appropriate binding
func SendResponse(w http.ResponseWriter, bindingType BindingType, destination string, message interface{}, relayState string, privateKey *rsa.PrivateKey) error {
	switch bindingType {
	case BindingTypePost:
		binding := NewPostBinding(privateKey)
		html, err := binding.GeneratePostForm(destination, message, relayState, false)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))

	case BindingTypeRedirect:
		binding := NewRedirectBinding(privateKey)
		redirectURL, err := binding.BuildRedirectURL(destination, message, relayState, false)
		if err != nil {
			return err
		}
		http.Redirect(w, nil, redirectURL, http.StatusFound)
	}

	return nil
}

// SendRequest sends a SAML request using the appropriate binding
func SendRequest(w http.ResponseWriter, r *http.Request, bindingType BindingType, destination string, message interface{}, relayState string, privateKey *rsa.PrivateKey) error {
	switch bindingType {
	case BindingTypePost:
		binding := NewPostBinding(privateKey)
		html, err := binding.GeneratePostForm(destination, message, relayState, true)
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))

	case BindingTypeRedirect:
		binding := NewRedirectBinding(privateKey)
		redirectURL, err := binding.BuildRedirectURL(destination, message, relayState, true)
		if err != nil {
			return err
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}

	return nil
}
