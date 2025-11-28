package lookingglass

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Decoder provides decoding utilities for various protocol artifacts
type Decoder struct{}

// NewDecoder creates a new decoder
func NewDecoder() *Decoder {
	return &Decoder{}
}

// DecodedJWT represents a fully decoded JWT with analysis
type DecodedJWT struct {
	Raw       string                 `json:"raw"`
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
	Analysis  JWTAnalysis            `json:"analysis"`
}

// JWTAnalysis contains analysis of a JWT
type JWTAnalysis struct {
	Algorithm    string          `json:"algorithm"`
	Type         string          `json:"type"` // access_token, id_token, refresh_token
	IsExpired    bool            `json:"is_expired"`
	ExpiresIn    string          `json:"expires_in,omitempty"`
	Issuer       string          `json:"issuer,omitempty"`
	Subject      string          `json:"subject,omitempty"`
	Audience     interface{}     `json:"audience,omitempty"`
	Claims       []ClaimAnalysis `json:"claims"`
	SecurityNotes []string       `json:"security_notes"`
}

// ClaimAnalysis provides analysis of individual claims
type ClaimAnalysis struct {
	Name        string      `json:"name"`
	Value       interface{} `json:"value"`
	Description string      `json:"description"`
	Category    string      `json:"category"` // standard, oidc, custom
}

// DecodeJWT decodes and analyzes a JWT
func (d *Decoder) DecodeJWT(tokenString string) (*DecodedJWT, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header JSON: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse payload JSON: %w", err)
	}

	decoded := &DecodedJWT{
		Raw:       tokenString,
		Header:    header,
		Payload:   payload,
		Signature: parts[2],
	}

	decoded.Analysis = d.analyzeJWT(header, payload)

	return decoded, nil
}

func (d *Decoder) analyzeJWT(header, payload map[string]interface{}) JWTAnalysis {
	analysis := JWTAnalysis{
		Claims:        make([]ClaimAnalysis, 0),
		SecurityNotes: make([]string, 0),
	}

	// Algorithm analysis
	if alg, ok := header["alg"].(string); ok {
		analysis.Algorithm = alg
		d.checkAlgorithmSecurity(&analysis, alg)
	}

	// Determine token type
	analysis.Type = d.determineTokenType(payload)

	// Standard claims
	standardClaims := map[string]string{
		"iss": "Issuer - Entity that issued the token",
		"sub": "Subject - Entity identified by the token",
		"aud": "Audience - Recipients the token is intended for",
		"exp": "Expiration Time - After which the token is invalid",
		"nbf": "Not Before - Time before which the token is not valid",
		"iat": "Issued At - Time at which the token was issued",
		"jti": "JWT ID - Unique identifier for the token",
	}

	// OIDC claims
	oidcClaims := map[string]string{
		"nonce":               "Nonce - Mitigates replay attacks",
		"auth_time":           "Authentication Time - When user was authenticated",
		"acr":                 "Authentication Context Class Reference",
		"amr":                 "Authentication Methods References",
		"azp":                 "Authorized Party - Party to which the token was issued",
		"name":                "Full name of the user",
		"given_name":          "Given name(s) or first name(s)",
		"family_name":         "Surname(s) or last name(s)",
		"email":               "Email address",
		"email_verified":      "Whether email has been verified",
		"preferred_username":  "Preferred username",
		"picture":             "URL of profile picture",
	}

	// Analyze each claim
	for key, value := range payload {
		claim := ClaimAnalysis{
			Name:  key,
			Value: value,
		}

		if desc, ok := standardClaims[key]; ok {
			claim.Description = desc
			claim.Category = "standard"
		} else if desc, ok := oidcClaims[key]; ok {
			claim.Description = desc
			claim.Category = "oidc"
		} else if key == "scope" || key == "roles" || key == "permissions" {
			claim.Description = "Authorization-related claim"
			claim.Category = "authorization"
		} else {
			claim.Description = "Custom claim"
			claim.Category = "custom"
		}

		analysis.Claims = append(analysis.Claims, claim)

		// Extract specific values for top-level analysis
		switch key {
		case "iss":
			if s, ok := value.(string); ok {
				analysis.Issuer = s
			}
		case "sub":
			if s, ok := value.(string); ok {
				analysis.Subject = s
			}
		case "aud":
			analysis.Audience = value
		case "exp":
			if exp, ok := value.(float64); ok {
				expTime := time.Unix(int64(exp), 0)
				analysis.IsExpired = time.Now().After(expTime)
				if !analysis.IsExpired {
					analysis.ExpiresIn = time.Until(expTime).Round(time.Second).String()
				}
			}
		}
	}

	return analysis
}

func (d *Decoder) checkAlgorithmSecurity(analysis *JWTAnalysis, alg string) {
	switch alg {
	case "none":
		analysis.SecurityNotes = append(analysis.SecurityNotes,
			"CRITICAL: Algorithm 'none' provides no signature verification!")
	case "HS256", "HS384", "HS512":
		analysis.SecurityNotes = append(analysis.SecurityNotes,
			"Uses symmetric HMAC algorithm - ensure secret key is properly protected")
	case "RS256", "RS384", "RS512":
		analysis.SecurityNotes = append(analysis.SecurityNotes,
			"Uses RSA asymmetric algorithm - verify against published public key")
	case "ES256", "ES384", "ES512":
		analysis.SecurityNotes = append(analysis.SecurityNotes,
			"Uses ECDSA algorithm - compact and efficient")
	case "PS256", "PS384", "PS512":
		analysis.SecurityNotes = append(analysis.SecurityNotes,
			"Uses RSA-PSS algorithm - improved security over PKCS#1 v1.5")
	}
}

func (d *Decoder) determineTokenType(payload map[string]interface{}) string {
	// Check for OIDC ID token indicators
	if _, hasNonce := payload["nonce"]; hasNonce {
		return "id_token"
	}
	if _, hasAuthTime := payload["auth_time"]; hasAuthTime {
		return "id_token"
	}

	// Check for refresh token
	if tokenType, ok := payload["type"].(string); ok && tokenType == "refresh" {
		return "refresh_token"
	}

	// Check for scope (typical for access tokens)
	if _, hasScope := payload["scope"]; hasScope {
		return "access_token"
	}

	return "unknown"
}

// DecodedAuthorizationRequest represents a decoded OAuth authorization request
type DecodedAuthorizationRequest struct {
	ResponseType        string   `json:"response_type"`
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scope               string   `json:"scope"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
	SecurityNotes       []string `json:"security_notes"`
}

// DecodeAuthorizationRequest decodes an authorization request URL
func (d *Decoder) DecodeAuthorizationRequest(requestURL string) (*DecodedAuthorizationRequest, error) {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	query := parsed.Query()
	decoded := &DecodedAuthorizationRequest{
		ResponseType:        query.Get("response_type"),
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		Scope:               query.Get("scope"),
		State:               query.Get("state"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		SecurityNotes:       make([]string, 0),
	}

	// Security analysis
	if decoded.State == "" {
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"WARNING: No state parameter - vulnerable to CSRF attacks")
	}

	if decoded.ResponseType == "code" && decoded.CodeChallenge == "" {
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"RECOMMENDATION: Consider using PKCE (code_challenge) for authorization code flow")
	}

	if decoded.CodeChallenge != "" && decoded.CodeChallengeMethod != "S256" {
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"RECOMMENDATION: Use S256 code_challenge_method instead of plain")
	}

	if !strings.HasPrefix(decoded.RedirectURI, "https://") && !strings.HasPrefix(decoded.RedirectURI, "http://localhost") {
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"WARNING: Redirect URI should use HTTPS in production")
	}

	return decoded, nil
}

// DecodedTokenRequest represents a decoded token request
type DecodedTokenRequest struct {
	GrantType    string   `json:"grant_type"`
	Code         string   `json:"code,omitempty"`
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	CodeVerifier string   `json:"code_verifier,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	SecurityNotes []string `json:"security_notes"`
}

// DecodeTokenRequest decodes a token request body
func (d *Decoder) DecodeTokenRequest(body string) (*DecodedTokenRequest, error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}

	decoded := &DecodedTokenRequest{
		GrantType:    values.Get("grant_type"),
		Code:         values.Get("code"),
		RedirectURI:  values.Get("redirect_uri"),
		ClientID:     values.Get("client_id"),
		CodeVerifier: values.Get("code_verifier"),
		RefreshToken: values.Get("refresh_token"),
		Scope:        values.Get("scope"),
		SecurityNotes: make([]string, 0),
	}

	// Security analysis based on grant type
	switch decoded.GrantType {
	case "authorization_code":
		if decoded.CodeVerifier == "" {
			decoded.SecurityNotes = append(decoded.SecurityNotes,
				"No code_verifier present - PKCE not being used")
		}
	case "refresh_token":
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"Refresh token grant - ensure refresh token rotation is enabled")
	case "client_credentials":
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"Client credentials grant - used for machine-to-machine authentication")
	case "password":
		decoded.SecurityNotes = append(decoded.SecurityNotes,
			"WARNING: Resource Owner Password grant is deprecated and should be avoided")
	}

	return decoded, nil
}

