package oidc

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// getSessionFromRequest extracts the session ID from request headers or query params
func (p *Plugin) getSessionFromRequest(r *http.Request) string {
	if sessionID := r.Header.Get("X-Looking-Glass-Session"); sessionID != "" {
		return sessionID
	}
	return r.URL.Query().Get("lg_session")
}

// emitEvent emits an event to the Looking Glass session if active
func (p *Plugin) emitEvent(sessionID string, eventType lookingglass.EventType, title string, data map[string]interface{}, annotations ...lookingglass.Annotation) {
	if p.lookingGlass == nil || sessionID == "" {
		return
	}
	broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)
	broadcaster.Emit(eventType, title, data, annotations...)
}

// htmlEscape escapes a string for safe inclusion in HTML
func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// handleAuthorize handles OIDC authorization requests
func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	sessionID := p.getSessionFromRequest(r)

	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	scope := query.Get("scope")
	state := query.Get("state")
	nonce := query.Get("nonce")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	// Emit OIDC authorization request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "OIDC Authentication Request", map[string]interface{}{
		"step":                   1,
		"from":                   "Client",
		"to":                     "OpenID Provider",
		"response_type":          responseType,
		"client_id":              clientID,
		"redirect_uri":           redirectURI,
		"scope":                  scope,
		"scopes":                 strings.Fields(scope),
		"state":                  state,
		"state_present":          state != "",
		"nonce":                  nonce,
		"nonce_present":          nonce != "",
		"code_challenge":         codeChallenge,
		"code_challenge_present": codeChallenge != "",
		"code_challenge_method":  codeChallengeMethod,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OpenID Connect Authentication",
		Description: "OIDC extends OAuth 2.0 with identity verification. The openid scope is required.",
		Reference:   "OpenID Connect Core 1.0 Section 3.1.2",
	})

	// Validate openid scope is present
	if !strings.Contains(scope, "openid") {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Missing openid Scope", map[string]interface{}{
			"scope":     scope,
			"client_id": clientID,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "openid Scope Required",
			Description: "The 'openid' scope is mandatory for OIDC flows to receive an ID token",
			Severity:    "error",
		})
		writeOIDCError(w, http.StatusBadRequest, "invalid_scope", "openid scope is required for OIDC")
		return
	}

	// Emit nonce presence check
	if nonce != "" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Nonce Parameter Present", map[string]interface{}{
			"nonce":        nonce,
			"nonce_length": len(nonce),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeBestPractice,
			Title:       "Nonce for Replay Protection",
			Description: "The nonce binds the ID token to the client session, preventing replay attacks",
			Reference:   "OpenID Connect Core 1.0 Section 3.1.2.1",
		})
	}

	// Validate response type
	validResponseTypes := map[string]bool{
		"code":           true,
		"token":          true,
		"id_token":       true,
		"id_token token": true,
		"token id_token": true,
	}
	if !validResponseTypes[responseType] {
		writeOIDCError(w, http.StatusBadRequest, "unsupported_response_type", "Supported: code, token, id_token, id_token token")
		return
	}

	// OIDC Core 1.0 Section 3.1.2.1: Nonce is REQUIRED for implicit flows that return id_token
	// Section 3.2.2.1: "REQUIRED. String value used to associate a Client session with an ID Token"
	if strings.Contains(responseType, "id_token") && nonce == "" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Missing Required Nonce", map[string]interface{}{
			"response_type": responseType,
			"client_id":     clientID,
			"redirect_uri":  redirectURI,
			"scope":         scope,
			"scopes":        strings.Fields(scope),
			"rfc_violation": true,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Nonce Required (OIDC Core 1.0 Compliance)",
			Description: "Per OIDC Core 1.0 Section 3.2.2.1, nonce is REQUIRED when response_type includes id_token",
			Severity:    "error",
			Reference:   "https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest",
		})
		writeOIDCErrorWithURI(w, http.StatusBadRequest, "invalid_request",
			"nonce is REQUIRED when response_type includes id_token (OIDC Core 1.0 Section 3.2.2.1)",
			"https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest")
		return
	}

	if clientID == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	// Validate client
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		writeOIDCError(w, http.StatusBadRequest, "invalid_client", "Unknown client")
		return
	}

	// Validate redirect URI
	if !p.mockIdP.ValidateRedirectURI(clientID, redirectURI) {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	// Generate login page with HTML-escaped values to prevent XSS
	loginPage := p.generateOIDCLoginPage(
		htmlEscape(clientID),
		htmlEscape(redirectURI),
		htmlEscape(scope),
		htmlEscape(state),
		htmlEscape(nonce),
		htmlEscape(codeChallenge),
		htmlEscape(codeChallengeMethod),
		htmlEscape(sessionID),
		htmlEscape(client.Name),
		htmlEscape(responseType),
	)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(loginPage))
}

// handleAuthorizeSubmit handles OIDC login form submission
func (p *Plugin) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}
	sessionID := p.getSessionFromRequest(r)

	// Get form values
	email := r.FormValue("email")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	responseType := r.FormValue("response_type")
	if responseType == "" {
		responseType = "code"
	}

	// Validate redirect URI against registered client URIs to prevent open redirect
	if !p.mockIdP.ValidateRedirectURI(clientID, redirectURI) {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}

	// Validate user credentials
	user, err := p.mockIdP.ValidateCredentials(email, password)
	if err != nil {
		// Return to login page with error - HTML escape all values to prevent XSS
		client, _ := p.mockIdP.GetClient(clientID)
		clientName := ""
		if client != nil {
			clientName = client.Name
		}
		loginPage := p.generateOIDCLoginPage(
			htmlEscape(clientID),
			htmlEscape(redirectURI),
			htmlEscape(scope),
			htmlEscape(state),
			htmlEscape(nonce),
			htmlEscape(codeChallenge),
			htmlEscape(codeChallengeMethod),
			htmlEscape(sessionID),
			htmlEscape(clientName),
			htmlEscape(responseType),
		)
		loginPage = strings.Replace(loginPage, "<!-- ERROR -->", `<div class="error">Invalid email or password</div>`, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(loginPage))
		return
	}

	// Build redirect URL - redirect URI was already validated above
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Malformed redirect_uri")
		return
	}

	// Handle based on response_type per OIDC Core 1.0
	// - "code": Authorization Code Flow (Section 3.1)
	// - "id_token", "id_token token": Implicit Flow (Section 3.2)
	// - "code id_token", "code token", "code id_token token": Hybrid Flow (Section 3.3)

	hasCode := strings.Contains(responseType, "code")
	// Proper token detection per OIDC Core Section 3
	hasToken := responseType == "token" || strings.Contains(responseType, " token") || strings.HasPrefix(responseType, "token ")
	hasIDToken := strings.Contains(responseType, "id_token")

	jwtService := p.mockIdP.JWTService()
	var authorizationCode string
	var accessToken string

	// Generate authorization code if "code" in response_type
	if hasCode {
		authCode, err := p.mockIdP.CreateAuthorizationCode(
			clientID, user.ID, redirectURI, scope, state, nonce,
			codeChallenge, codeChallengeMethod,
		)
		if err != nil {
			writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to create authorization code")
			return
		}
		authorizationCode = authCode.Code
	}

	// Generate access token if "token" in response_type
	if hasToken {
		var err error
		accessToken, err = jwtService.CreateAccessToken(
			user.ID,
			clientID,
			scope,
			time.Hour,
			nil,
		)
		if err != nil {
			writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to create access token")
			return
		}
	}

	// Generate ID token if "id_token" in response_type
	var idToken string
	if hasIDToken {
		scopes := strings.Split(scope, " ")
		userClaims := p.mockIdP.UserClaims(user.ID, scopes)

		// Build ID token options for OIDC Core 1.0 compliance
		// Per Section 3.3.2.11: Include hash claims based on what's returned
		idTokenOptions := &crypto.IDTokenOptions{}

		// Include at_hash if access_token is being returned (OIDC Core 1.0 Section 3.3.2.11)
		if accessToken != "" {
			idTokenOptions.AccessToken = accessToken
		}

		// Include c_hash if authorization code is being returned (OIDC Core 1.0 Section 3.3.2.11)
		// This is for Hybrid Flow
		if authorizationCode != "" {
			idTokenOptions.AuthorizationCode = authorizationCode
		}

		var err error
		idToken, err = jwtService.CreateIDTokenWithOptions(
			user.ID,
			clientID,
			nonce,
			time.Now(),
			time.Hour,
			userClaims,
			idTokenOptions,
		)
		if err != nil {
			writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
	}

	// Build response based on flow type
	if responseType == "code" {
		// Pure Authorization Code Flow - code in query string
		q := redirectURL.Query()
		q.Set("code", authorizationCode)
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()
	} else if hasCode {
		// Hybrid Flow - code in query string, tokens in fragment (per OIDC Core 1.0 Section 3.3)
		q := redirectURL.Query()
		q.Set("code", authorizationCode)
		if state != "" {
			q.Set("state", state)
		}
		redirectURL.RawQuery = q.Encode()

		// Tokens go in fragment for hybrid flow
		fragment := url.Values{}
		if accessToken != "" {
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", "Bearer")
			fragment.Set("expires_in", "3600")
		}
		if idToken != "" {
			fragment.Set("id_token", idToken)
		}
		if len(fragment) > 0 {
			redirectURL.Fragment = fragment.Encode()
		}
	} else {
		// Implicit Flow - everything in fragment (per OIDC Core 1.0 Section 3.2)
		fragment := url.Values{}
		if accessToken != "" {
			fragment.Set("access_token", accessToken)
			fragment.Set("token_type", "Bearer")
			fragment.Set("expires_in", "3600")
		}
		if idToken != "" {
			fragment.Set("id_token", idToken)
		}
		if state != "" {
			fragment.Set("state", state)
		}
		redirectURL.Fragment = fragment.Encode()
	}

	// Redirect to client (safe - redirect URI validated against registered URIs)
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// handleToken handles OIDC token requests
// Per RFC 6749 Section 4.1.3 and OIDC Core 1.0: Content-Type MUST be application/x-www-form-urlencoded
func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	// RFC 6749 Section 4.1.3 / OIDC Core 1.0: Content-Type validation
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Content-Type", map[string]interface{}{
			"content_type": contentType,
			"expected":     "application/x-www-form-urlencoded",
			"endpoint":     "/oidc/token",
		})
		writeOIDCErrorWithURI(w, http.StatusBadRequest, "invalid_request",
			"Content-Type must be application/x-www-form-urlencoded (RFC 6749 Section 4.1.3)",
			"https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	refreshToken := r.FormValue("refresh_token")
	if clientID == "" {
		if basicClientID, _, ok := r.BasicAuth(); ok {
			clientID = basicClientID
		}
	}
	clientAuthMethod := "none"
	if _, _, ok := r.BasicAuth(); ok {
		clientAuthMethod = "basic"
	} else if r.FormValue("client_secret") != "" {
		clientAuthMethod = "post"
	}

	// Emit token request event
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "OIDC Token Request", map[string]interface{}{
		"grant_type":            grantType,
		"endpoint":              "/oidc/token",
		"client_id":             clientID,
		"client_auth_method":    clientAuthMethod,
		"scope":                 scope,
		"scopes":                strings.Fields(scope),
		"code":                  code,
		"code_present":          code != "",
		"code_verifier":         codeVerifier,
		"code_verifier_present": codeVerifier != "",
		"refresh_token":         refreshToken,
		"refresh_token_present": refreshToken != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OIDC Token Endpoint Request",
		Description: "OIDC uses the OAuth 2.0 token endpoint with additional ID token processing",
		Reference:   "OpenID Connect Core 1.0 Section 3.1.3",
	})

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r, sessionID)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, sessionID)
	default:
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unsupported Grant Type", map[string]interface{}{
			"grant_type": grantType,
			"endpoint":   "/oidc/token",
		})
		writeOIDCError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not supported")
	}
}

func (p *Plugin) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	codeVerifier := r.FormValue("code_verifier")

	// Try to get client credentials from Authorization header
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}
	clientAuthMethod := "none"
	if _, _, ok := r.BasicAuth(); ok {
		clientAuthMethod = "basic"
	} else if clientSecret != "" {
		clientAuthMethod = "post"
	}

	// Emit token exchange request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "OIDC Token Exchange", map[string]interface{}{
		"step":                  6,
		"from":                  "Client",
		"to":                    "OpenID Provider",
		"grant_type":            "authorization_code",
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"code":                  code,
		"code_verifier":         codeVerifier,
		"code_verifier_present": codeVerifier != "",
		"client_auth_method":    clientAuthMethod,
		"client_secret_present": clientSecret != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OIDC Token Request",
		Description: "The client exchanges the authorization code for tokens, including the ID token with identity claims",
		Reference:   "OpenID Connect Core 1.0 Section 3.1.3",
	})

	// Validate client
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unknown Client", map[string]interface{}{
			"client_id":          clientID,
			"client_auth_method": clientAuthMethod,
		})
		writeOIDCError(w, http.StatusUnauthorized, "invalid_client", "Unknown client")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Auth Failed", map[string]interface{}{
				"client_id":          clientID,
				"client_auth_method": clientAuthMethod,
			})
			writeOIDCError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
	}

	// Validate authorization code
	authCode, err := p.mockIdP.ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Code Validation Failed", map[string]interface{}{
			"error":                 err.Error(),
			"client_id":             clientID,
			"redirect_uri":          redirectURI,
			"code":                  code,
			"code_verifier_present": codeVerifier != "",
		})
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	// Generate tokens including ID token
	tokenResponse, err := p.issueOIDCTokens(authCode)
	if err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to issue tokens")
		return
	}

	// Emit ID token issued event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "OIDC Tokens Issued", map[string]interface{}{
		"step":              7,
		"from":              "OpenID Provider",
		"to":                "Client",
		"access_token":      tokenResponse.AccessToken,
		"refresh_token":     tokenResponse.RefreshToken,
		"id_token":          tokenResponse.IDToken,
		"token_type":        "Bearer",
		"has_id_token":      tokenResponse.IDToken != "",
		"scope":             tokenResponse.Scope,
		"scopes":            strings.Fields(tokenResponse.Scope),
		"expires_in":        tokenResponse.ExpiresIn,
		"has_refresh_token": tokenResponse.RefreshToken != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "ID Token Issued",
		Description: "The ID token is a JWT containing claims about the authenticated user. It must be validated before use.",
		Reference:   "OpenID Connect Core 1.0 Section 2",
	})

	// Emit ID token validation reminder
	if tokenResponse.IDToken != "" {
		p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "ID Token Validation Required", map[string]interface{}{
			"step":             8,
			"from":             "Client",
			"to":               "Client",
			"nonce":            authCode.Nonce,
			"nonce_present":    authCode.Nonce != "",
			"validation_steps": []string{"Verify signature", "Check iss", "Check aud", "Check exp", "Verify nonce"},
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeBestPractice,
			Title:       "ID Token Validation Steps",
			Description: "Always validate: signature using JWKS, issuer (iss), audience (aud), expiration (exp), and nonce if present",
			Reference:   "OpenID Connect Core 1.0 Section 3.1.3.7",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(tokenResponse)
}

func (p *Plugin) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")

	// Try to get client credentials from Authorization header
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}
	clientAuthMethod := "none"
	if _, _, ok := r.BasicAuth(); ok {
		clientAuthMethod = "basic"
	} else if clientSecret != "" {
		clientAuthMethod = "post"
	}

	// Emit refresh request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "OIDC Token Refresh", map[string]interface{}{
		"grant_type":            "refresh_token",
		"client_id":             clientID,
		"client_auth_method":    clientAuthMethod,
		"refresh_token":         refreshToken,
		"refresh_token_length":  len(refreshToken),
		"scope":                 scope,
		"scopes":                strings.Fields(scope),
		"refresh_token_present": refreshToken != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Refresh with OIDC",
		Description: "Refreshing tokens in OIDC can also issue a new ID token if openid scope is present",
		Reference:   "OpenID Connect Core 1.0 Section 12",
	})

	// Validate client
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		writeOIDCError(w, http.StatusUnauthorized, "invalid_client", "Unknown client")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			writeOIDCError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
			return
		}
	}

	// Validate refresh token
	rt, err := p.mockIdP.ValidateRefreshToken(refreshToken, clientID)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Refresh Token Invalid", map[string]interface{}{
			"error":                err.Error(),
			"client_id":            clientID,
			"refresh_token":        refreshToken,
			"refresh_token_length": len(refreshToken),
		})
		writeOIDCError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	// Use original scope if not specified
	if scope == "" {
		scope = rt.Scope
	}

	// Generate new tokens (including new ID token if openid scope)
	jwtService := p.mockIdP.JWTService()
	scopes := strings.Split(scope, " ")
	userClaims := p.mockIdP.UserClaims(rt.UserID, scopes)

	// Create access token
	accessToken, err := jwtService.CreateAccessToken(
		rt.UserID,
		clientID,
		scope,
		time.Hour,
		userClaims,
	)
	if err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to create access token")
		return
	}

	// Create new refresh token (rotation)
	newRefreshToken, err := jwtService.CreateRefreshToken(
		rt.UserID,
		clientID,
		scope,
		7*24*time.Hour,
	)
	if err != nil {
		writeOIDCError(w, http.StatusInternalServerError, "server_error", "Failed to create refresh token")
		return
	}

	// Store new refresh token
	p.mockIdP.StoreRefreshToken(newRefreshToken, clientID, rt.UserID, scope, time.Now().Add(7*24*time.Hour))

	response := models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken,
		Scope:        scope,
	}

	// Include new ID token if openid scope is present
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}

	if hasOpenID {
		idToken, err := jwtService.CreateIDToken(
			rt.UserID,
			clientID,
			"", // No nonce for refresh
			time.Now(),
			time.Hour,
			userClaims,
		)
		if err == nil {
			response.IDToken = idToken
		}
	}

	// Emit token refresh success
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "OIDC Tokens Refreshed", map[string]interface{}{
		"access_token":      response.AccessToken,
		"refresh_token":     response.RefreshToken,
		"id_token":          response.IDToken,
		"token_type":        response.TokenType,
		"expires_in":        response.ExpiresIn,
		"scope":             response.Scope,
		"scopes":            strings.Fields(response.Scope),
		"has_id_token":      response.IDToken != "",
		"has_refresh_token": response.RefreshToken != "",
		"token_rotation":    true,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeBestPractice,
		Title:       "OIDC Refresh Response",
		Description: "OIDC refresh responses may include a new ID token when openid scope is present",
		Reference:   "OpenID Connect Core 1.0 Section 12",
	})

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// issueOIDCTokens creates access token, refresh token, and ID token
func (p *Plugin) issueOIDCTokens(authCode *models.AuthorizationCode) (*models.TokenResponse, error) {
	jwtService := p.mockIdP.JWTService()

	// Parse scopes
	scopes := strings.Split(authCode.Scope, " ")
	userClaims := p.mockIdP.UserClaims(authCode.UserID, scopes)

	// Create access token
	accessToken, err := jwtService.CreateAccessToken(
		authCode.UserID,
		authCode.ClientID,
		authCode.Scope,
		time.Hour,
		userClaims,
	)
	if err != nil {
		return nil, err
	}

	// Create refresh token
	refreshToken, err := jwtService.CreateRefreshToken(
		authCode.UserID,
		authCode.ClientID,
		authCode.Scope,
		7*24*time.Hour,
	)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	p.mockIdP.StoreRefreshToken(refreshToken, authCode.ClientID, authCode.UserID, authCode.Scope, time.Now().Add(7*24*time.Hour))

	response := &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}

	// Create ID token if openid scope is present
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}

	if hasOpenID {
		idToken, err := jwtService.CreateIDToken(
			authCode.UserID,
			authCode.ClientID,
			authCode.Nonce,
			time.Now(),
			time.Hour,
			userClaims,
		)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	return response, nil
}

func (p *Plugin) generateOIDCLoginPage(clientID, redirectURI, scope, state, nonce, codeChallenge, codeChallengeMethod, sessionID, clientName, responseType string) string {
	if clientName == "" {
		if client, exists := p.mockIdP.GetClient(clientID); exists {
			clientName = client.Name
		} else {
			clientName = clientID
		}
	}
	if responseType == "" {
		responseType = "code"
	}
	formAction := "/oidc/authorize"
	if sessionID != "" {
		formAction += "?lg_session=" + url.QueryEscape(sessionID)
	}

	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login - OpenID Connect</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e4e4e7;
        }
        .container {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            font-size: 24px;
            font-weight: 600;
            color: #fff;
        }
        .logo .oidc-badge {
            display: inline-block;
            background: linear-gradient(135deg, #f97316 0%, #ea580c 100%);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-top: 8px;
        }
        .client-info {
            background: rgba(249, 115, 22, 0.1);
            border: 1px solid rgba(249, 115, 22, 0.2);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            text-align: center;
        }
        .client-info span {
            color: #fdba74;
            font-size: 14px;
        }
        .client-info strong {
            color: #fff;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
            color: #d4d4d8;
        }
        input[type="email"], input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            background: rgba(0, 0, 0, 0.2);
            color: #fff;
            font-size: 16px;
            transition: all 0.2s;
        }
        input:focus {
            outline: none;
            border-color: #f97316;
            box-shadow: 0 0 0 3px rgba(249, 115, 22, 0.2);
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #f97316 0%, #ea580c 100%);
            border: none;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px -10px rgba(249, 115, 22, 0.5);
        }
        .error {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #fca5a5;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .demo-users {
            margin-top: 24px;
            padding-top: 24px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        .demo-users h3 {
            font-size: 14px;
            color: #a1a1aa;
            margin-bottom: 12px;
        }
        .demo-user {
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .demo-user:hover {
            background: rgba(249, 115, 22, 0.1);
            border-color: rgba(249, 115, 22, 0.2);
        }
        .demo-user .name { font-weight: 500; color: #fff; }
        .demo-user .email { font-size: 12px; color: #71717a; }
        .scopes {
            margin-top: 16px;
            font-size: 12px;
            color: #71717a;
        }
        .scopes span {
            display: inline-block;
            background: rgba(249, 115, 22, 0.1);
            padding: 4px 8px;
            border-radius: 4px;
            margin: 2px;
        }
        .scopes .openid { background: rgba(34, 197, 94, 0.2); color: #86efac; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Protocol Showcase</h1>
            <div class="oidc-badge">OpenID Connect</div>
        </div>
        
        <div class="client-info">
            <span>Signing in to <strong>` + clientName + `</strong></span>
        </div>

        <!-- ERROR -->

        <form method="POST" action="` + formAction + `">
            <input type="hidden" name="client_id" value="` + clientID + `">
            <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
            <input type="hidden" name="scope" value="` + scope + `">
            <input type="hidden" name="state" value="` + state + `">
            <input type="hidden" name="nonce" value="` + nonce + `">
            <input type="hidden" name="code_challenge" value="` + codeChallenge + `">
            <input type="hidden" name="code_challenge_method" value="` + codeChallengeMethod + `">
            <input type="hidden" name="response_type" value="` + responseType + `">
            
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="alice@example.com" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="password" required>
            </div>
            
            <button type="submit">Sign In with OpenID Connect</button>
        </form>

        <div class="demo-users">
            <h3>Demo Users (click to autofill)</h3>
            <div class="demo-user" onclick="fillCredentials('alice@example.com', 'password123')">
                <div class="name">Alice (Standard User)</div>
                <div class="email">alice@example.com</div>
            </div>
            <div class="demo-user" onclick="fillCredentials('admin@example.com', 'admin123')">
                <div class="name">Admin (Elevated Permissions)</div>
                <div class="email">admin@example.com</div>
            </div>
        </div>

        <div class="scopes">
            Requested scopes: ` + formatOIDCScopes(scope) + `
        </div>
    </div>

    <script>
        function fillCredentials(email, password) {
            document.getElementById('email').value = email;
            document.getElementById('password').value = password;
        }
    </script>
</body>
</html>`
}

func formatOIDCScopes(scope string) string {
	if scope == "" {
		return "<span>none</span>"
	}
	scopes := strings.Split(scope, " ")
	result := ""
	for _, s := range scopes {
		if s == "openid" {
			result += `<span class="openid">` + s + `</span>`
		} else {
			result += "<span>" + s + "</span>"
		}
	}
	return result
}
