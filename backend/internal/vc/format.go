package vc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
)

// IssuerTrustStatus reports the outcome of ValidateIssuerSignature as a
// tri-state rather than a binary pass/fail. A plain error return cannot
// distinguish "checked the signature against real trust material and it did
// not verify" from "no trust material was available to check against at
// all" (no IACA root for an mdoc, no issuer JWKs for a JWT-based format) --
// yet callers such as the credential decode endpoint (POST
// /lookingglass/decode/credential) must report exactly that distinction to
// the user rather than reconstructing it from context.
//
// The zero value is IssuerTrustNotEvaluated, so a status left unset by
// mistake reads as "not evaluated" rather than as a false Verified.
//
// ValidateIssuerSignature returns a non-nil error for both IssuerTrustFailed
// and IssuerTrustNotEvaluated, never only for IssuerTrustFailed. Every
// existing "if err != nil { reject }" caller therefore keeps its current,
// conservative behaviour unchanged by this signature growing a return value:
// it continues to refuse both a checked failure and an unevaluated
// signature. A nil error occurs only with IssuerTrustVerified. Only a caller
// that explicitly inspects the returned status -- rather than only the error
// -- can tell a checked failure apart from an unevaluated one.
type IssuerTrustStatus int

const (
	IssuerTrustNotEvaluated IssuerTrustStatus = iota
	IssuerTrustVerified
	IssuerTrustFailed
)

// String renders the status for logs and API responses. These values are
// serialized verbatim by the credential decode endpoint, so keep them stable.
func (s IssuerTrustStatus) String() string {
	switch s {
	case IssuerTrustVerified:
		return "verified"
	case IssuerTrustFailed:
		return "failed"
	default:
		return "not_evaluated"
	}
}

// TokenSigner signs a JWT-like claim set with the wallet's active key material.
type TokenSigner func(claims map[string]interface{}, headerOverrides map[string]interface{}) (string, error)

// PresentationBuildInput carries the wallet context required to build a presentation.
type PresentationBuildInput struct {
	Credential               string
	ParsedCredential         *ParsedCredential
	Holder                   string
	HolderPublicJWK          intcrypto.JWK
	HolderJWKThumbprint      string
	HolderVerificationMethod string
	Audience                 string
	Nonce                    string
	PresentationDefinition   map[string]interface{}
	Signer                   TokenSigner
	ProofSigner              func(data []byte) ([]byte, error)
}

// PresentationBuildResult contains the serialized presentation token and its format.
type PresentationBuildResult struct {
	VPToken          string
	CredentialFormat string
}

// CredentialValidationInput supplies the issuer trust material for a format-specific signature check.
type CredentialValidationInput struct {
	Credential       string
	ParsedCredential *ParsedCredential
	IssuerKeys       []intcrypto.JWK
	HTTPClient       *http.Client
	// IssuerTrustAnchors carries IACA root certificates for mso_mdoc's
	// x5chain path validation (mdoc.VerifyIssuerSigned). JWT-based formats
	// use IssuerKeys instead; this field exists because mdoc's trust model is
	// X.509 certificate chains, not JWKs, and CredentialValidationInput was
	// otherwise shaped entirely around the JWT formats it originally served.
	// A nil pool means "no trust anchor was supplied", which MSOMdocFormat
	// reports as IssuerTrustNotEvaluated rather than attempting path
	// validation against it -- x509.Certificate.Verify falls back to the
	// host OS root store when Roots is nil, which would otherwise turn an
	// absent trust anchor into a misleading certificate-path error that
	// reads as IssuerTrustFailed.
	IssuerTrustAnchors *x509.CertPool
}

// ParsedCredential is a normalized, format-agnostic view of a held credential.
type ParsedCredential struct {
	Original         string
	Format           string
	Subject          string
	Issuer           string
	VCT              string
	Doctype          string
	CredentialTypes  []string
	Claims           map[string]interface{}
	VCClaims         map[string]interface{}
	IssuerSignedJWT  string
	DisclosureClaims []string
	DisclosureCount  int
	HasKeyBindingJWT bool
	IsSDJWT          bool
	IssuedAt         time.Time
	ExpiresAt        time.Time
}

// CredentialFormat encapsulates parsing, presentation, and issuer validation for one credential format.
type CredentialFormat interface {
	FormatID() string
	CanPresent() bool
	BuildPresentation(input PresentationBuildInput) (*PresentationBuildResult, error)
	ParseCredential(raw string) (*ParsedCredential, error)
	ValidateIssuerSignature(input CredentialValidationInput) (IssuerTrustStatus, error)
}

// CredentialFormatRegistry stores supported credential format handlers and provides format detection.
type CredentialFormatRegistry struct {
	mu      sync.RWMutex
	formats map[string]CredentialFormat
	order   []CredentialFormat
}

var (
	defaultCredentialFormatRegistry     *CredentialFormatRegistry
	defaultCredentialFormatRegistryOnce sync.Once
)

// NewCredentialFormatRegistry creates a registry with the provided formats.
func NewCredentialFormatRegistry(formats ...CredentialFormat) *CredentialFormatRegistry {
	registry := &CredentialFormatRegistry{
		formats: make(map[string]CredentialFormat),
	}
	for _, format := range formats {
		registry.Register(format)
	}
	return registry
}

// DefaultCredentialFormatRegistry returns the process-wide credential format registry.
func DefaultCredentialFormatRegistry() *CredentialFormatRegistry {
	defaultCredentialFormatRegistryOnce.Do(func() {
		defaultCredentialFormatRegistry = NewCredentialFormatRegistry(
			&SDJWTFormat{},
			&LDPVCFormat{},
			&JWTVCFormat{formatID: "jwt_vc_json-ld"},
			&JWTVCFormat{formatID: "jwt_vc_json"},
			// Registered last: see MSOMdocFormat's doc comment for why
			// ordering here is defensive rather than load-bearing.
			&MSOMdocFormat{},
		)
	})
	return defaultCredentialFormatRegistry
}

// Register adds or replaces a format handler.
func (r *CredentialFormatRegistry) Register(format CredentialFormat) {
	if r == nil || format == nil {
		return
	}
	normalizedID := normalizeCredentialFormatID(format.FormatID())
	if normalizedID == "" {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.formats[normalizedID]; !ok {
		r.order = append(r.order, format)
	} else {
		for idx, registered := range r.order {
			if registered == existing {
				r.order[idx] = format
				break
			}
		}
	}
	r.formats[normalizedID] = format
	if normalizedID == "jwt_vc_json" {
		r.formats["jwt_vc"] = format
	}
}

// Lookup resolves a format handler by format identifier.
func (r *CredentialFormatRegistry) Lookup(formatID string) (CredentialFormat, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	format, ok := r.formats[normalizeCredentialFormatID(formatID)]
	return format, ok
}

// ParseAnyCredential attempts to detect and parse a credential with the registered handlers.
func (r *CredentialFormatRegistry) ParseAnyCredential(raw string) (*ParsedCredential, error) {
	if r == nil {
		return nil, fmt.Errorf("credential format registry is unavailable")
	}
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return nil, fmt.Errorf("credential is required")
	}

	r.mu.RLock()
	formats := append([]CredentialFormat(nil), r.order...)
	r.mu.RUnlock()

	var lastErr error
	for _, format := range formats {
		parsed, err := format.ParseCredential(normalized)
		if err == nil {
			return parsed, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unsupported credential format")
	}
	return nil, lastErr
}

// SDJWTFormat implements dc+sd-jwt parsing and presentation rules.
type SDJWTFormat struct{}

func (f *SDJWTFormat) FormatID() string { return "dc+sd-jwt" }

func (f *SDJWTFormat) CanPresent() bool { return true }

func (f *SDJWTFormat) ParseCredential(raw string) (*ParsedCredential, error) {
	envelope, err := ParseSDJWTEnvelope(raw)
	if err != nil {
		return nil, err
	}
	parsed, err := parseJWTCredential(strings.TrimSpace(envelope.IssuerSignedJWT))
	if err != nil {
		return nil, err
	}
	parsed.Original = strings.TrimSpace(raw)
	parsed.Format = f.FormatID()
	parsed.IsSDJWT = true
	parsed.IssuerSignedJWT = strings.TrimSpace(envelope.IssuerSignedJWT)
	parsed.DisclosureCount = len(envelope.Disclosures)
	parsed.HasKeyBindingJWT = strings.TrimSpace(envelope.KeyBindingJWT) != ""
	disclosureClaims := make([]string, 0, len(envelope.Disclosures))
	for _, disclosure := range envelope.Disclosures {
		decodedDisclosure, err := DecodeSDJWTDisclosure(disclosure)
		if err != nil {
			continue
		}
		claimName := strings.TrimSpace(decodedDisclosure.ClaimName)
		if claimName == "" {
			continue
		}
		disclosureClaims = append(disclosureClaims, claimName)
	}
	sort.Strings(disclosureClaims)
	parsed.DisclosureClaims = dedupeStringsFormat(disclosureClaims)
	return parsed, nil
}

func (f *SDJWTFormat) BuildPresentation(input PresentationBuildInput) (*PresentationBuildResult, error) {
	if input.Signer == nil {
		return nil, fmt.Errorf("presentation signer is required")
	}
	parsed, err := ensureParsedCredential(f, input)
	if err != nil {
		return nil, err
	}
	envelope, err := ParseSDJWTEnvelope(parsed.Original)
	if err != nil {
		return nil, err
	}
	if input.PresentationDefinition != nil {
		return buildWrappedPresentation(input, strings.TrimSpace(envelope.IssuerSignedJWT), parsed.Format)
	}

	sdJWTWithoutKB := BuildSDJWTSerialization(envelope.IssuerSignedJWT, envelope.Disclosures, "")
	if !strings.HasSuffix(sdJWTWithoutKB, "~") {
		sdJWTWithoutKB += "~"
	}
	sdHashRaw := sha256.Sum256([]byte(sdJWTWithoutKB))
	kbClaims := map[string]interface{}{
		"aud":     input.Audience,
		"nonce":   input.Nonce,
		"iat":     time.Now().UTC().Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(sdHashRaw[:]),
	}
	kbJWT, err := input.Signer(kbClaims, map[string]interface{}{"typ": "kb+jwt"})
	if err != nil {
		return nil, fmt.Errorf("sign kb-jwt: %w", err)
	}
	return &PresentationBuildResult{
		VPToken:          BuildSDJWTSerialization(envelope.IssuerSignedJWT, envelope.Disclosures, kbJWT),
		CredentialFormat: parsed.Format,
	}, nil
}

func (f *SDJWTFormat) ValidateIssuerSignature(input CredentialValidationInput) (IssuerTrustStatus, error) {
	parsed, err := ensureParsedCredentialForValidation(f, input)
	if err != nil {
		return IssuerTrustNotEvaluated, err
	}
	return validateJWTSignature(parsed.IssuerSignedJWT, input.IssuerKeys)
}

// JWTVCFormat implements compact JWS-backed JWT VC formats.
type JWTVCFormat struct {
	formatID string
}

func (f *JWTVCFormat) FormatID() string {
	return normalizeCredentialFormatID(f.formatID)
}

func (f *JWTVCFormat) CanPresent() bool { return true }

func (f *JWTVCFormat) ParseCredential(raw string) (*ParsedCredential, error) {
	if _, err := ParseSDJWTEnvelope(raw); err == nil {
		return nil, fmt.Errorf("sd-jwt credential does not match %s", f.FormatID())
	}
	parsed, err := parseJWTCredential(raw)
	if err != nil {
		return nil, err
	}
	switch parsed.Format {
	case "ldp_vc":
		return nil, fmt.Errorf("credential format %q does not match %s", parsed.Format, f.FormatID())
	case "":
		parsed.Format = "jwt_vc_json"
	}
	return parsed, nil
}

func (f *JWTVCFormat) BuildPresentation(input PresentationBuildInput) (*PresentationBuildResult, error) {
	parsed, err := ensureParsedCredential(f, input)
	if err != nil {
		return nil, err
	}
	return buildWrappedPresentation(input, strings.TrimSpace(parsed.Original), firstNonEmptyFormat(parsed.Format, f.FormatID()))
}

func (f *JWTVCFormat) ValidateIssuerSignature(input CredentialValidationInput) (IssuerTrustStatus, error) {
	parsed, err := ensureParsedCredentialForValidation(f, input)
	if err != nil {
		return IssuerTrustNotEvaluated, err
	}
	return validateJWTSignature(parsed.Original, input.IssuerKeys)
}

// LDPVCFormat implements the current ldp_vc profile and the future raw JSON-LD data model.
type LDPVCFormat struct{}

func (f *LDPVCFormat) FormatID() string { return "ldp_vc" }

func (f *LDPVCFormat) CanPresent() bool { return true }

func (f *LDPVCFormat) ParseCredential(raw string) (*ParsedCredential, error) {
	if parsed, err := parseJSONLDCredential(raw, f.FormatID()); err == nil {
		return parsed, nil
	}
	parsed, err := parseJWTCredential(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Format != f.FormatID() {
		return nil, fmt.Errorf("credential format %q does not match %s", parsed.Format, f.FormatID())
	}
	return parsed, nil
}

func (f *LDPVCFormat) BuildPresentation(input PresentationBuildInput) (*PresentationBuildResult, error) {
	parsed, err := ensureParsedCredential(f, input)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(parsed.Original), "{") {
		return buildDataIntegrityPresentation(parsed, input)
	}
	return buildWrappedPresentation(input, strings.TrimSpace(parsed.Original), parsed.Format)
}

func (f *LDPVCFormat) ValidateIssuerSignature(input CredentialValidationInput) error {
	parsed, err := ensureParsedCredentialForValidation(f, input)
	if err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(parsed.Original), "{") {
		return validateDataIntegrityCredential(parsed, input)
	}
	return validateJWTSignature(parsed.Original, input.IssuerKeys)
}

func ensureParsedCredential(format CredentialFormat, input PresentationBuildInput) (*ParsedCredential, error) {
	if input.ParsedCredential != nil {
		return input.ParsedCredential, nil
	}
	parsed, err := format.ParseCredential(input.Credential)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func ensureParsedCredentialForValidation(format CredentialFormat, input CredentialValidationInput) (*ParsedCredential, error) {
	if input.ParsedCredential != nil {
		return input.ParsedCredential, nil
	}
	parsed, err := format.ParseCredential(input.Credential)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func buildWrappedPresentation(input PresentationBuildInput, credentialForVP interface{}, credentialFormat string) (*PresentationBuildResult, error) {
	if input.Signer == nil {
		return nil, fmt.Errorf("presentation signer is required")
	}
	holder := strings.TrimSpace(input.Holder)
	if holder == "" {
		return nil, fmt.Errorf("presentation holder is required")
	}

	now := time.Now().UTC()
	vpClaim := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"verifiableCredential": []interface{}{credentialForVP},
	}
	claims := map[string]interface{}{
		"iss":   holder,
		"aud":   input.Audience,
		"nonce": input.Nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"jti":   randomFormatValue(20),
	}
	if input.PresentationDefinition != nil {
		vpClaim["holder"] = holder
	} else {
		claims["sub"] = holder
		claims["cnf"] = map[string]interface{}{
			"jwk": input.HolderPublicJWK,
			"jkt": input.HolderJWKThumbprint,
		}
	}
	claims["vp"] = vpClaim
	vpToken, err := input.Signer(claims, map[string]interface{}{"typ": "vp+jwt"})
	if err != nil {
		return nil, err
	}
	return &PresentationBuildResult{
		VPToken:          vpToken,
		CredentialFormat: normalizeCredentialFormatID(credentialFormat),
	}, nil
}

func parseJWTCredential(raw string) (*ParsedCredential, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return nil, fmt.Errorf("credential is required")
	}
	decoded, err := intcrypto.DecodeTokenWithoutValidation(normalized)
	if err != nil {
		return nil, err
	}

	parsed := &ParsedCredential{
		Original: normalized,
		Claims:   copyMap(decoded.Payload),
		Issuer:   strings.TrimSpace(formatString(decoded.Payload["iss"])),
		Subject:  strings.TrimSpace(formatString(decoded.Payload["sub"])),
		VCT:      strings.TrimSpace(formatString(decoded.Payload["vct"])),
		Doctype:  strings.TrimSpace(formatString(decoded.Payload["doctype"])),
	}

	if expUnix, err := toUnixTimestampFormat(decoded.Payload["exp"]); err == nil && expUnix > 0 {
		parsed.ExpiresAt = time.Unix(expUnix, 0).UTC()
	}
	if formatClaim := strings.TrimSpace(formatString(decoded.Payload["format"])); formatClaim != "" {
		parsed.Format = normalizeCredentialFormatID(formatClaim)
	}

	vcObject, _ := decoded.Payload["vc"].(map[string]interface{})
	parsed.VCClaims = copyMap(vcObject)
	if len(parsed.VCClaims) > 0 {
		if parsed.Subject == "" {
			if credentialSubject, ok := vcObject["credentialSubject"].(map[string]interface{}); ok {
				parsed.Subject = strings.TrimSpace(formatString(credentialSubject["id"]))
			}
		}
		parsed.CredentialTypes = credentialTypesFromValue(vcObject["type"])
		if parsed.Format == "" {
			switch strings.TrimSpace(formatString(decoded.Header["typ"])) {
			case "vc+ldp-jwt":
				parsed.Format = "ldp_vc"
			case "vc+jwt":
				if _, hasContext := vcObject["@context"]; hasContext {
					parsed.Format = "jwt_vc_json-ld"
				} else {
					parsed.Format = "jwt_vc_json"
				}
			}
		}
	}
	if parsed.Format == "" {
		if strings.TrimSpace(formatString(decoded.Header["typ"])) == "vc+ldp-jwt" {
			parsed.Format = "ldp_vc"
		}
	}
	if parsed.Format == "" && len(parsed.VCClaims) > 0 {
		parsed.Format = "jwt_vc_json"
	}
	if parsed.IssuerSignedJWT == "" {
		parsed.IssuerSignedJWT = normalized
	}
	return parsed, nil
}

func parseJSONLDCredential(raw string, formatID string) (*ParsedCredential, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" || !strings.HasPrefix(normalized, "{") {
		return nil, fmt.Errorf("credential is not raw json-ld")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(normalized), &payload); err != nil {
		return nil, err
	}

	credentialTypes := credentialTypesFromValue(payload["type"])
	if len(credentialTypes) == 0 {
		return nil, fmt.Errorf("json-ld credential is missing type")
	}
	if !containsFormatString(credentialTypes, "VerifiableCredential") {
		return nil, fmt.Errorf("json-ld credential is missing VerifiableCredential type")
	}
	if _, ok := payload["proof"]; !ok {
		return nil, fmt.Errorf("json-ld credential is missing proof")
	}

	parsed := &ParsedCredential{
		Original:        normalized,
		Format:          normalizeCredentialFormatID(formatID),
		Claims:          copyMap(payload),
		VCClaims:        copyMap(payload),
		Issuer:          jsonLDCredentialIssuer(payload["issuer"]),
		CredentialTypes: credentialTypes,
		VCT:             strings.TrimSpace(formatString(payload["vct"])),
	}

	if credentialSubject, ok := payload["credentialSubject"].(map[string]interface{}); ok {
		parsed.Subject = strings.TrimSpace(formatString(credentialSubject["id"]))
	}
	if expTime, err := time.Parse(time.RFC3339, strings.TrimSpace(formatString(payload["expirationDate"]))); err == nil {
		parsed.ExpiresAt = expTime.UTC()
	} else if expTime, err := time.Parse(time.RFC3339, strings.TrimSpace(formatString(payload["validUntil"]))); err == nil {
		parsed.ExpiresAt = expTime.UTC()
	}
	if issuedTime, err := time.Parse(time.RFC3339, strings.TrimSpace(formatString(payload["issuanceDate"]))); err == nil {
		parsed.IssuedAt = issuedTime.UTC()
	} else if issuedTime, err := time.Parse(time.RFC3339, strings.TrimSpace(formatString(payload["validFrom"]))); err == nil {
		parsed.IssuedAt = issuedTime.UTC()
	}
	return parsed, nil
}

// validateJWTSignature verifies token against issuerKeys and reports the
// tri-state outcome. Both an empty token and no issuer keys are
// IssuerTrustNotEvaluated: neither is "checked and failed", each is "there
// was nothing to check, or nothing to check it against". Every other
// negative outcome -- an unusable key, a signature that does not verify --
// is IssuerTrustFailed, because a check was actually attempted against real
// trust material and did not succeed.
func validateJWTSignature(token string, issuerKeys []intcrypto.JWK) (IssuerTrustStatus, error) {
	normalized := strings.TrimSpace(token)
	if normalized == "" {
		return IssuerTrustNotEvaluated, fmt.Errorf("credential jwt is required")
	}
	if len(issuerKeys) == 0 {
		return IssuerTrustNotEvaluated, fmt.Errorf("issuer keys are required")
	}

	decoded, err := intcrypto.DecodeTokenWithoutValidation(normalized)
	if err != nil {
		return IssuerTrustNotEvaluated, fmt.Errorf("decode credential jwt: %w", err)
	}
	kid := strings.TrimSpace(formatString(decoded.Header["kid"]))
	alg := strings.TrimSpace(formatString(decoded.Header["alg"]))

	candidates := make([]intcrypto.JWK, 0, len(issuerKeys))
	for _, issuerKey := range issuerKeys {
		if kid != "" && strings.TrimSpace(issuerKey.Kid) != "" && strings.TrimSpace(issuerKey.Kid) != kid {
			continue
		}
		if alg != "" && strings.TrimSpace(issuerKey.Alg) != "" && strings.TrimSpace(issuerKey.Alg) != alg {
			continue
		}
		candidates = append(candidates, issuerKey)
	}
	if len(candidates) == 0 {
		candidates = append(candidates, issuerKeys...)
	}

	var lastErr error
	for _, issuerKey := range candidates {
		publicKey, err := issuerKey.ToPublicKey()
		if err != nil {
			lastErr = err
			continue
		}
		valid, err := intcrypto.VerifySignatureWithKey(normalized, publicKey)
		if err == nil && valid {
			return IssuerTrustVerified, nil
		}
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = fmt.Errorf("credential signature verification failed")
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable issuer keys were provided")
	}
	return IssuerTrustFailed, lastErr
}

func normalizeCredentialFormatID(formatID string) string {
	switch strings.TrimSpace(formatID) {
	case "jwt_vc":
		return "jwt_vc_json"
	default:
		return strings.TrimSpace(formatID)
	}
}

func credentialTypesFromValue(raw interface{}) []string {
	switch typed := raw.(type) {
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			value := strings.TrimSpace(formatString(item))
			if value != "" {
				values = append(values, value)
			}
		}
		sort.Strings(values)
		return dedupeStringsFormat(values)
	case []string:
		values := append([]string{}, typed...)
		sort.Strings(values)
		return dedupeStringsFormat(values)
	case string:
		value := strings.TrimSpace(typed)
		if value == "" {
			return nil
		}
		return []string{value}
	default:
		return nil
	}
}

func containsFormatString(values []string, needle string) bool {
	normalizedNeedle := strings.TrimSpace(needle)
	for _, value := range values {
		if strings.TrimSpace(value) == normalizedNeedle {
			return true
		}
	}
	return false
}

func dedupeStringsFormat(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func copyMap(source map[string]interface{}) map[string]interface{} {
	if len(source) == 0 {
		return nil
	}
	copied := make(map[string]interface{}, len(source))
	for key, value := range source {
		copied[key] = value
	}
	return copied
}

func formatString(value interface{}) string {
	stringValue, _ := value.(string)
	return stringValue
}

func toUnixTimestampFormat(raw interface{}) (int64, error) {
	switch typed := raw.(type) {
	case int64:
		return typed, nil
	case int32:
		return int64(typed), nil
	case int:
		return int64(typed), nil
	case float64:
		return int64(typed), nil
	case json.Number:
		return typed.Int64()
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, fmt.Errorf("timestamp is empty")
		}
		return json.Number(strings.TrimSpace(typed)).Int64()
	default:
		return 0, fmt.Errorf("unsupported timestamp type %T", raw)
	}
}

func randomFormatValue(size int) string {
	if size <= 0 {
		size = 24
	}
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)[:size]
}

func firstNonEmptyFormat(values ...string) string {
	for _, value := range values {
		if normalized := strings.TrimSpace(value); normalized != "" {
			return normalized
		}
	}
	return ""
}
