package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// handleUserInfo handles the UserInfo endpoint
func (p *Plugin) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	
	// Emit UserInfo request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "UserInfo Request", map[string]interface{}{
		"step":     9,
		"from":     "Client",
		"to":       "OpenID Provider",
		"endpoint": "/oidc/userinfo",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "UserInfo Endpoint",
		Description: "Returns claims about the authenticated user. The access token determines which claims are returned based on the scopes.",
		Reference:   "OpenID Connect Core 1.0 Section 5.3",
	})

	// Extract access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Missing Authorization", map[string]interface{}{
			"error": "invalid_token",
		})
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Missing Authorization header")
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Authorization Format", map[string]interface{}{
			"error": "expected_bearer",
		})
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Invalid Authorization header format")
		return
	}

	accessToken := parts[1]

	// Validate the access token
	jwtService := p.mockIdP.JWTService()
	claims, err := jwtService.ValidateToken(accessToken)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Token Validation Failed", map[string]interface{}{
			"error": err.Error(),
		})
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Token validation failed")
		return
	}

	// Get user ID from token
	userID, ok := claims["sub"].(string)
	if !ok {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_token", "Missing subject claim")
		return
	}

	// Get scope from token
	scopeStr, _ := claims["scope"].(string)
	scopes := strings.Split(scopeStr, " ")

	// Get user claims based on scopes
	userClaims := p.mockIdP.CreateUserInfoResponse(userID, scopes)
	if userClaims == nil {
		writeOIDCError(w, http.StatusNotFound, "invalid_request", "User not found")
		return
	}

	// Emit UserInfo response
	p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "UserInfo Response", map[string]interface{}{
		"user_id":      userID,
		"scopes":       scopes,
		"claims_count": len(userClaims),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "UserInfo Claims",
		Description: "The claims returned depend on the scopes in the access token: openid→sub, profile→name/etc, email→email/verified",
		Reference:   "OpenID Connect Core 1.0 Section 5.4",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userClaims)
}

// StandardClaims defines the standard OIDC claims and their descriptions
var StandardClaims = map[string]ClaimDefinition{
	// Required claims
	"sub": {
		Name:        "sub",
		Description: "Subject - Identifier for the End-User at the Issuer",
		Required:    true,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"iss": {
		Name:        "iss",
		Description: "Issuer - Issuer Identifier for the Issuer of the response",
		Required:    true,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"aud": {
		Name:        "aud",
		Description: "Audience - Audience(s) that this ID Token is intended for",
		Required:    true,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"exp": {
		Name:        "exp",
		Description: "Expiration time - Time at which the ID Token expires",
		Required:    true,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"iat": {
		Name:        "iat",
		Description: "Issued At - Time at which the JWT was issued",
		Required:    true,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},

	// Optional standard claims
	"auth_time": {
		Name:        "auth_time",
		Description: "Time when the End-User authentication occurred",
		Required:    false,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"nonce": {
		Name:        "nonce",
		Description: "String value used to associate a Client session with an ID Token",
		Required:    false,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"acr": {
		Name:        "acr",
		Description: "Authentication Context Class Reference",
		Required:    false,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"amr": {
		Name:        "amr",
		Description: "Authentication Methods References",
		Required:    false,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},
	"azp": {
		Name:        "azp",
		Description: "Authorized party - The party to which the ID Token was issued",
		Required:    false,
		Scope:       "openid",
		RFCSection:  "OpenID Connect Core 1.0 Section 2",
	},

	// Profile scope claims
	"name": {
		Name:        "name",
		Description: "End-User's full name in displayable form",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"family_name": {
		Name:        "family_name",
		Description: "Surname(s) or last name(s) of the End-User",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"given_name": {
		Name:        "given_name",
		Description: "Given name(s) or first name(s) of the End-User",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"middle_name": {
		Name:        "middle_name",
		Description: "Middle name(s) of the End-User",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"nickname": {
		Name:        "nickname",
		Description: "Casual name of the End-User",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"preferred_username": {
		Name:        "preferred_username",
		Description: "Shorthand name by which the End-User wishes to be referred to",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"profile": {
		Name:        "profile",
		Description: "URL of the End-User's profile page",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"picture": {
		Name:        "picture",
		Description: "URL of the End-User's profile picture",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"website": {
		Name:        "website",
		Description: "URL of the End-User's Web page or blog",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"gender": {
		Name:        "gender",
		Description: "End-User's gender",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"birthdate": {
		Name:        "birthdate",
		Description: "End-User's birthday in ISO 8601 format",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"zoneinfo": {
		Name:        "zoneinfo",
		Description: "String from zoneinfo time zone database representing the End-User's time zone",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"locale": {
		Name:        "locale",
		Description: "End-User's locale, represented as a BCP47 language tag",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"updated_at": {
		Name:        "updated_at",
		Description: "Time the End-User's information was last updated",
		Required:    false,
		Scope:       "profile",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},

	// Email scope claims
	"email": {
		Name:        "email",
		Description: "End-User's preferred e-mail address",
		Required:    false,
		Scope:       "email",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"email_verified": {
		Name:        "email_verified",
		Description: "True if the End-User's e-mail address has been verified",
		Required:    false,
		Scope:       "email",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},

	// Address scope claims
	"address": {
		Name:        "address",
		Description: "End-User's preferred postal address (JSON object)",
		Required:    false,
		Scope:       "address",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},

	// Phone scope claims
	"phone_number": {
		Name:        "phone_number",
		Description: "End-User's preferred telephone number",
		Required:    false,
		Scope:       "phone",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
	"phone_number_verified": {
		Name:        "phone_number_verified",
		Description: "True if the End-User's phone number has been verified",
		Required:    false,
		Scope:       "phone",
		RFCSection:  "OpenID Connect Core 1.0 Section 5.1",
	},
}

// ClaimDefinition defines metadata about an OIDC claim
type ClaimDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Scope       string `json:"scope"`
	RFCSection  string `json:"rfc_section"`
}

// ScopeDefinitions defines the standard OIDC scopes
var ScopeDefinitions = map[string]ScopeDefinition{
	"openid": {
		Name:        "openid",
		Description: "Required scope for OpenID Connect. Returns the sub claim.",
		Required:    true,
		Claims:      []string{"sub"},
	},
	"profile": {
		Name:        "profile",
		Description: "Requests access to the End-User's default profile Claims.",
		Required:    false,
		Claims:      []string{"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	},
	"email": {
		Name:        "email",
		Description: "Requests access to the email and email_verified Claims.",
		Required:    false,
		Claims:      []string{"email", "email_verified"},
	},
	"address": {
		Name:        "address",
		Description: "Requests access to the address Claim.",
		Required:    false,
		Claims:      []string{"address"},
	},
	"phone": {
		Name:        "phone",
		Description: "Requests access to the phone_number and phone_number_verified Claims.",
		Required:    false,
		Claims:      []string{"phone_number", "phone_number_verified"},
	},
}

// ScopeDefinition defines metadata about an OIDC scope
type ScopeDefinition struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Claims      []string `json:"claims"`
}

// GetClaimsForScopes returns the claims associated with the given scopes
func GetClaimsForScopes(scopes []string) []string {
	claimsMap := make(map[string]bool)
	for _, scope := range scopes {
		if scopeDef, exists := ScopeDefinitions[scope]; exists {
			for _, claim := range scopeDef.Claims {
				claimsMap[claim] = true
			}
		}
	}

	claims := make([]string, 0, len(claimsMap))
	for claim := range claimsMap {
		claims = append(claims, claim)
	}
	return claims
}

// OIDC/OAuth2 error URIs - links to relevant OIDC documentation
var oidcErrorURIs = map[string]string{
	"invalid_request":          "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"invalid_client":           "https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse",
	"invalid_grant":            "https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse",
	"unauthorized_client":      "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"unsupported_grant_type":   "https://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse",
	"invalid_scope":            "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"unsupported_response_type": "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"access_denied":            "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"server_error":             "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"invalid_token":            "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError",
	"login_required":           "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"consent_required":         "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
	"interaction_required":     "https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
}

// Helper function for OIDC errors - includes error_uri per RFC 6749 Section 5.2 and OIDC Core
func writeOIDCError(w http.ResponseWriter, status int, errorCode, description string) {
	writeOIDCErrorWithURI(w, status, errorCode, description, "")
}

// writeOIDCErrorWithURI writes an OIDC-compliant error response with optional error_uri
func writeOIDCErrorWithURI(w http.ResponseWriter, status int, errorCode, description, errorURI string) {
	// Determine error_uri
	uri := errorURI
	if uri == "" {
		if defaultURI, exists := oidcErrorURIs[errorCode]; exists {
			uri = defaultURI
		}
	}
	
	// Build WWW-Authenticate header
	authHeader := `Bearer error="` + errorCode + `", error_description="` + description + `"`
	if uri != "" {
		authHeader += `, error_uri="` + uri + `"`
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", authHeader)
	w.WriteHeader(status)
	
	// Build response body
	response := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}
	if uri != "" {
		response["error_uri"] = uri
	}
	
	json.NewEncoder(w).Encode(response)
}

