package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// getSessionFromRequest extracts the session ID from request headers or query params
func (p *Plugin) getSessionFromRequest(r *http.Request) string {
	// Check header first
	if sessionID := r.Header.Get("X-Looking-Glass-Session"); sessionID != "" {
		return sessionID
	}
	// Check query param
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

// Authorization endpoint - GET
func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	sessionID := p.getSessionFromRequest(r)

	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	scope := query.Get("scope")
	state := query.Get("state")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")

	// Emit authorization request event
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Authorization Request Received", map[string]interface{}{
		"step":                  1,
		"from":                  "Client",
		"to":                    "Authorization Server",
		"response_type":         responseType,
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"scope":                 scope,
		"state":                 state != "",
		"code_challenge":        codeChallenge != "",
		"code_challenge_method": codeChallengeMethod,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OAuth 2.0 Authorization Request",
		Description: "The client redirects the user to the authorization server with required parameters",
		Reference:   "RFC 6749 Section 4.1.1",
	})

	// Validate required parameters
	if responseType != "code" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Response Type", map[string]interface{}{
			"error":         "unsupported_response_type",
			"response_type": responseType,
		})
		writeOAuth2Error(w, "unsupported_response_type", "Only 'code' response type is supported", "")
		return
	}

	if clientID == "" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Missing Client ID", map[string]interface{}{
			"error": "invalid_request",
		})
		writeOAuth2Error(w, "invalid_request", "client_id is required", "")
		return
	}

	// Validate client
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unknown Client", map[string]interface{}{
			"error":     "invalid_client",
			"client_id": clientID,
		})
		writeOAuth2Error(w, "invalid_client", "Unknown client", "")
		return
	}

	// Validate redirect URI
	if !p.mockIdP.ValidateRedirectURI(clientID, redirectURI) {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Redirect URI", map[string]interface{}{
			"error":        "invalid_request",
			"redirect_uri": redirectURI,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Redirect URI Validation",
			Description: "Redirect URIs must exactly match pre-registered values to prevent open redirect attacks",
			Severity:    "warning",
			Reference:   "RFC 6749 Section 10.6",
		})
		writeOAuth2Error(w, "invalid_request", "Invalid redirect_uri", "")
		return
	}

	// Security annotations for PKCE
	if codeChallenge != "" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "PKCE Challenge Received", map[string]interface{}{
			"code_challenge_method": codeChallengeMethod,
			"challenge_length":      len(codeChallenge),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeBestPractice,
			Title:       "PKCE Protection Enabled",
			Description: "The client is using PKCE to protect against authorization code interception attacks",
			Reference:   "RFC 7636",
		})
	} else if client.Public {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Public Client Without PKCE", map[string]interface{}{
			"client_type": "public",
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "PKCE Recommended for Public Clients",
			Description: "Public clients should always use PKCE to protect against code interception",
			Severity:    "warning",
			Reference:   "RFC 7636",
		})
	}

	// Emit user authentication step
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "User Authentication Required", map[string]interface{}{
		"step":        2,
		"from":        "User",
		"to":          "Authorization Server",
		"client_name": client.Name,
		"scopes":      strings.Split(scope, " "),
	})

	// For demo purposes, return a login page
	loginPage := p.generateLoginPage(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, client.Name)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(loginPage))
}

// Authorization endpoint - POST (login form submission)
func (p *Plugin) handleAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	if err := r.ParseForm(); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid form data", "")
		return
	}

	// Get form values
	email := r.FormValue("email")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	nonce := r.FormValue("nonce") // For OIDC

	// Security: Re-validate redirect URI to prevent open redirect attacks via form tampering
	if !p.mockIdP.ValidateRedirectURI(clientID, redirectURI) {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Redirect URI (Submit)", map[string]interface{}{
			"error":        "invalid_request",
			"redirect_uri": redirectURI,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeVulnerability,
			Title:       "Open Redirect Prevention",
			Description: "Redirect URI re-validated on form submission to prevent tampering attacks",
			Severity:    "warning",
		})
		writeOAuth2Error(w, "invalid_request", "Invalid redirect_uri", "")
		return
	}

	// Emit credential submission event (without password!)
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "User Credentials Submitted", map[string]interface{}{
		"email":     email,
		"client_id": clientID,
	})

	// Validate user credentials
	user, err := p.mockIdP.ValidateCredentials(email, password)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authentication Failed", map[string]interface{}{
			"email":  email,
			"reason": "Invalid credentials",
		})
		// Return to login page with error
		loginPage := p.generateLoginPage(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, "")
		loginPage = strings.Replace(loginPage, "<!-- ERROR -->", `<div class="error">Invalid email or password</div>`, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(loginPage))
		return
	}

	// Emit successful authentication
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "User Authenticated Successfully", map[string]interface{}{
		"step":    2,
		"from":    "User",
		"to":      "Authorization Server",
		"user_id": user.ID,
		"name":    user.Name,
		"email":   user.Email,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "User Authentication Complete",
		Description: "The user has successfully authenticated. An authorization code will now be issued.",
	})

	// Create authorization code
	authCode, err := p.mockIdP.CreateAuthorizationCode(
		clientID, user.ID, redirectURI, scope, state, nonce,
		codeChallenge, codeChallengeMethod,
	)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authorization Code Creation Failed", map[string]interface{}{
			"error": err.Error(),
		})
		writeOAuth2Error(w, "server_error", "Failed to create authorization code", state)
		return
	}

	// Emit authorization code issued event
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Authorization Code Issued", map[string]interface{}{
		"step":         3,
		"from":         "Authorization Server",
		"to":           "Client",
		"code_length":  len(authCode.Code),
		"code_preview": authCode.Code[:8] + "...",
		"has_pkce":     codeChallenge != "",
		"has_state":    state != "",
		"scopes":       strings.Split(scope, " "),
		"expires_in":   "10 minutes",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Authorization Code",
		Description: "A short-lived, single-use code that the client will exchange for tokens. The code is bound to the client_id, redirect_uri, and PKCE challenge.",
		Reference:   "RFC 6749 Section 4.1.2",
	})

	// Build redirect URL
	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	// Emit redirect event
	p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Redirecting to Client", map[string]interface{}{
		"redirect_uri": redirectURI,
		"has_code":     true,
		"has_state":    state != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "State Parameter Echo",
		Description: "The state parameter is echoed back to the client for CSRF validation",
		Reference:   "RFC 6749 Section 10.12",
	})

	// Redirect to client
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// Token endpoint
// Per RFC 6749 Section 4.1.3: The client MUST send the request body with Content-Type
// of "application/x-www-form-urlencoded"
func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	// RFC 6749 Section 4.1.3: Content-Type MUST be application/x-www-form-urlencoded
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Content-Type", map[string]interface{}{
			"content_type": contentType,
			"expected":     "application/x-www-form-urlencoded",
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "RFC 6749 Section 4.1.3 Compliance",
			Description: "Token endpoint requires Content-Type: application/x-www-form-urlencoded",
			Reference:   "RFC 6749 Section 4.1.3",
		})
		writeOAuth2ErrorWithURI(w, "invalid_request",
			"Content-Type must be application/x-www-form-urlencoded (RFC 6749 Section 4.1.3)",
			"",
			"https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid form data", "")
		return
	}

	grantType := r.FormValue("grant_type")

	// Emit token request event
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Token Request Received", map[string]interface{}{
		"grant_type": grantType,
		"endpoint":   "/oauth2/token",
	})

	switch grantType {
	case "authorization_code":
		p.handleAuthorizationCodeGrant(w, r, sessionID)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, sessionID)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r, sessionID)
	default:
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unsupported Grant Type", map[string]interface{}{
			"grant_type": grantType,
		})
		writeOAuth2Error(w, "unsupported_grant_type", "Grant type not supported", "")
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

	// Emit token exchange step
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Token Exchange Request", map[string]interface{}{
		"step":         4,
		"from":         "Client",
		"to":           "Authorization Server",
		"grant_type":   "authorization_code",
		"client_id":    clientID,
		"has_verifier": codeVerifier != "",
		"code_preview": code[:min(8, len(code))] + "...",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Authorization Code Exchange",
		Description: "The client exchanges the authorization code for tokens via a back-channel request",
		Reference:   "RFC 6749 Section 4.1.3",
	})

	// Validate client (if not public)
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unknown Client", map[string]interface{}{
			"client_id": clientID,
		})
		writeOAuth2Error(w, "invalid_client", "Unknown client", "")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
				"client_id": clientID,
				"reason":    "invalid_credentials",
			})
			writeOAuth2Error(w, "invalid_client", "Client authentication failed", "")
			return
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Client Authenticated", map[string]interface{}{
			"client_id":   clientID,
			"client_type": "confidential",
		})
	}

	// Validate authorization code
	authCode, err := p.mockIdP.ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authorization Code Validation Failed", map[string]interface{}{
			"error":  err.Error(),
			"reason": "invalid_grant",
		})
		writeOAuth2Error(w, "invalid_grant", err.Error(), "")
		return
	}

	// Emit PKCE validation if applicable
	if codeVerifier != "" {
		p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "PKCE Verification Successful", map[string]interface{}{
			"method":          authCode.CodeChallengeMethod,
			"verifier_length": len(codeVerifier),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeBestPractice,
			Title:       "PKCE Verification",
			Description: "The authorization server verified that the code_verifier matches the code_challenge from the authorization request",
			Reference:   "RFC 7636 Section 4.6",
		})
	}

	// Generate tokens
	tokenResponse, err := p.issueTokens(authCode.UserID, clientID, authCode.Scope, authCode.Nonce)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Token Generation Failed", map[string]interface{}{
			"error": err.Error(),
		})
		writeOAuth2Error(w, "server_error", "Failed to issue tokens", "")
		return
	}

	// Emit token issued event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Access Token Issued", map[string]interface{}{
		"step":              5,
		"from":              "Authorization Server",
		"to":                "Client",
		"token_type":        tokenResponse.TokenType,
		"expires_in":        tokenResponse.ExpiresIn,
		"scope":             tokenResponse.Scope,
		"has_refresh_token": tokenResponse.RefreshToken != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Tokens Issued",
		Description: "The authorization server has issued tokens. The access token can now be used to access protected resources.",
		Reference:   "RFC 6749 Section 5.1",
	})

	writeJSON(w, http.StatusOK, tokenResponse)
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

	// Emit refresh token request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Refresh Token Request", map[string]interface{}{
		"grant_type":      "refresh_token",
		"client_id":       clientID,
		"requested_scope": scope,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Refresh",
		Description: "The client is using a refresh token to obtain a new access token without user interaction",
		Reference:   "RFC 6749 Section 6",
	})

	// Validate client
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unknown Client", map[string]interface{}{
			"client_id": clientID,
		})
		writeOAuth2Error(w, "invalid_client", "Unknown client", "")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
				"client_id": clientID,
			})
			writeOAuth2Error(w, "invalid_client", "Client authentication failed", "")
			return
		}
	}

	// Validate refresh token
	rt, err := p.mockIdP.ValidateRefreshToken(refreshToken, clientID)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Refresh Token Invalid", map[string]interface{}{
			"error": err.Error(),
		})
		writeOAuth2Error(w, "invalid_grant", err.Error(), "")
		return
	}

	// Use original scope if not specified
	if scope == "" {
		scope = rt.Scope
	}

	// Generate new tokens
	tokenResponse, err := p.issueTokens(rt.UserID, clientID, scope, "")
	if err != nil {
		writeOAuth2Error(w, "server_error", "Failed to issue tokens", "")
		return
	}

	// Emit token rotation event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Tokens Refreshed", map[string]interface{}{
		"token_type":           tokenResponse.TokenType,
		"expires_in":           tokenResponse.ExpiresIn,
		"new_refresh_token":    tokenResponse.RefreshToken != "",
		"rotation_implemented": true,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeBestPractice,
		Title:       "Refresh Token Rotation",
		Description: "A new refresh token is issued and the old one is invalidated, limiting the window of vulnerability if a refresh token is compromised",
		Reference:   "RFC 6749 Section 10.4",
	})

	writeJSON(w, http.StatusOK, tokenResponse)
}

func (p *Plugin) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")

	// Try to get client credentials from Authorization header
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	// Emit client credentials request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Client Credentials Request", map[string]interface{}{
		"step":            1,
		"from":            "Client",
		"to":              "Authorization Server",
		"grant_type":      "client_credentials",
		"client_id":       clientID,
		"requested_scope": scope,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Client Credentials Flow",
		Description: "Machine-to-machine authentication without a user context. The client authenticates using its own credentials.",
		Reference:   "RFC 6749 Section 4.4",
	})

	// Validate client
	client, err := p.mockIdP.ValidateClient(clientID, clientSecret)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
			"client_id": clientID,
			"error":     "invalid_credentials",
		})
		writeOAuth2Error(w, "invalid_client", "Client authentication failed", "")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Client Authenticated", map[string]interface{}{
		"client_id":   clientID,
		"client_name": client.Name,
	})

	// Check if client is authorized for this grant type
	hasGrant := false
	for _, gt := range client.GrantTypes {
		if gt == "client_credentials" {
			hasGrant = true
			break
		}
	}
	if !hasGrant {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unauthorized Grant Type", map[string]interface{}{
			"client_id":  clientID,
			"grant_type": "client_credentials",
		})
		writeOAuth2Error(w, "unauthorized_client", "Client not authorized for this grant type", "")
		return
	}

	// Issue access token (no refresh token for client credentials)
	jwtService := p.mockIdP.JWTService()
	accessToken, err := jwtService.CreateAccessToken(
		clientID, // Subject is the client itself
		clientID,
		scope,
		time.Hour,
		map[string]interface{}{
			"client_name": client.Name,
		},
	)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Token Generation Failed", map[string]interface{}{
			"error": err.Error(),
		})
		writeOAuth2Error(w, "server_error", "Failed to create access token", "")
		return
	}

	tokenResponse := models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}

	// Emit token issued event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Access Token Issued", map[string]interface{}{
		"step":              2,
		"from":              "Authorization Server",
		"to":                "Client",
		"token_type":        "Bearer",
		"expires_in":        3600,
		"scope":             scope,
		"has_refresh_token": false,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "No Refresh Token",
		Description: "Client credentials grant does not issue refresh tokens. The client must re-authenticate to get a new access token.",
		Reference:   "RFC 6749 Section 4.4.3",
	})

	writeJSON(w, http.StatusOK, tokenResponse)
}

// Token introspection endpoint (RFC 7662)
func (p *Plugin) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	if err := r.ParseForm(); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid form data", "")
		return
	}

	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	// Emit introspection request
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Token Introspection Request", map[string]interface{}{
		"token_type_hint": tokenTypeHint,
		"token_length":    len(token),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Introspection",
		Description: "Allows resource servers to query the authorization server about the current state and metadata of a token",
		Reference:   "RFC 7662",
	})

	// Authenticate the client making the introspection request
	clientID, clientSecret, _ := r.BasicAuth()
	if clientID == "" {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Introspection Client Auth Failed", map[string]interface{}{
			"client_id": clientID,
		})
		writeOAuth2Error(w, "invalid_client", "Client authentication required", "")
		return
	}

	// Validate the token
	jwtService := p.mockIdP.JWTService()
	claims, err := jwtService.ValidateToken(token)
	if err != nil {
		// Token is not active (invalid or expired)
		p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Token Inactive", map[string]interface{}{
			"active": false,
			"reason": err.Error(),
		})
		writeJSON(w, http.StatusOK, models.IntrospectionResponse{Active: false})
		return
	}

	// Check if token has been revoked per RFC 7009
	if p.mockIdP.IsTokenRevoked(token) {
		p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Token Revoked", map[string]interface{}{
			"active": false,
			"reason": "Token has been revoked per RFC 7009",
		})
		writeJSON(w, http.StatusOK, models.IntrospectionResponse{Active: false})
		return
	}

	// Build introspection response
	response := models.IntrospectionResponse{
		Active:    true,
		TokenType: "Bearer",
	}

	if scope, ok := claims["scope"].(string); ok {
		response.Scope = scope
	}
	if sub, ok := claims["sub"].(string); ok {
		response.Sub = sub
		response.Username = sub
	}
	if audClaim, ok := claims["aud"].(string); ok {
		response.ClientID = audClaim
	}
	if exp, ok := claims["exp"].(float64); ok {
		response.Exp = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		response.Iat = int64(iat)
	}
	if iss, ok := claims["iss"].(string); ok {
		response.Iss = iss
	}
	if jti, ok := claims["jti"].(string); ok {
		response.Jti = jti
	}

	// Emit introspection response
	p.emitEvent(sessionID, lookingglass.EventTypeTokenValidated, "Token Introspection Result", map[string]interface{}{
		"active":     true,
		"token_type": "Bearer",
		"sub":        response.Sub,
		"scope":      response.Scope,
		"exp":        response.Exp,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Token Active",
		Description: "The token has been validated and is currently active",
	})

	writeJSON(w, http.StatusOK, response)
}

// Token revocation endpoint (RFC 7009)
func (p *Plugin) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	if err := r.ParseForm(); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid form data", "")
		return
	}

	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")

	// Emit revocation request
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Token Revocation Request", map[string]interface{}{
		"token_type_hint": tokenTypeHint,
		"token_length":    len(token),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Revocation",
		Description: "Allows clients to notify the authorization server that a previously issued token is no longer needed",
		Reference:   "RFC 7009",
	})

	// Authenticate the client
	clientID, clientSecret, _ := r.BasicAuth()
	if clientID == "" {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unknown Client", map[string]interface{}{
			"client_id": clientID,
		})
		writeOAuth2Error(w, "invalid_client", "Unknown client", "")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Auth Failed", map[string]interface{}{
				"client_id": clientID,
			})
			writeOAuth2Error(w, "invalid_client", "Client authentication failed", "")
			return
		}
	}

	// Revoke the token per RFC 7009 Section 2.1
	// The server MUST attempt to revoke the token regardless of token_type_hint
	// token_type_hint is advisory only - server should determine token type if hint is wrong
	p.mockIdP.RevokeToken(token, tokenTypeHint)

	// Emit revocation success
	p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Token Revoked", map[string]interface{}{
		"token_type_hint":     tokenTypeHint,
		"revoked":             true,
		"rfc_compliance":      "RFC 7009 Section 2.1",
		"hint_is_advisory":    true,
		"attempted_all_types": true,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeBestPractice,
		Title:       "Token Revocation Complete (RFC 7009 Compliant)",
		Description: "Per RFC 7009 Section 2.1, the server attempts to revoke the token regardless of token_type_hint. The hint is advisory only.",
		Reference:   "RFC 7009 Section 2.1",
	})

	// Per RFC 7009 Section 2.2, always return 200 OK regardless of whether token was valid
	// This prevents attackers from determining if a token was valid
	w.WriteHeader(http.StatusOK)
}

// Demo endpoint - list users
func (p *Plugin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	presets := p.mockIdP.GetDemoUserPresets()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users": presets,
	})
}

// Demo endpoint - list clients
func (p *Plugin) handleListClients(w http.ResponseWriter, r *http.Request) {
	presets := p.mockIdP.GetDemoClientPresets()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"clients": presets,
	})
}

// issueTokens creates access token and refresh token
func (p *Plugin) issueTokens(userID, clientID, scope, nonce string) (*models.TokenResponse, error) {
	jwtService := p.mockIdP.JWTService()

	// Get user claims
	scopes := strings.Split(scope, " ")
	userClaims := p.mockIdP.UserClaims(userID, scopes)

	// Create access token
	accessToken, err := jwtService.CreateAccessToken(
		userID,
		clientID,
		scope,
		time.Hour,
		userClaims,
	)
	if err != nil {
		return nil, err
	}

	// Create refresh token
	refreshToken, err := jwtService.CreateRefreshToken(
		userID,
		clientID,
		scope,
		7*24*time.Hour,
	)
	if err != nil {
		return nil, err
	}

	// Store refresh token
	p.mockIdP.StoreRefreshToken(refreshToken, clientID, userID, scope, time.Now().Add(7*24*time.Hour))

	response := &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	return response, nil
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RFC 6749 Section 5.2 error URIs - links to relevant documentation
var oauth2ErrorURIs = map[string]string{
	"invalid_request":           "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_client":            "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_grant":             "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"unauthorized_client":       "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"unsupported_grant_type":    "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_scope":             "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"unsupported_response_type": "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
	"access_denied":             "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
	"server_error":              "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
	"temporarily_unavailable":   "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
}

// writeOAuth2Error writes an OAuth2-compliant error response per RFC 6749 Section 5.2
// Includes optional error_uri pointing to relevant RFC documentation
func writeOAuth2Error(w http.ResponseWriter, errorCode, description, state string) {
	writeOAuth2ErrorWithURI(w, errorCode, description, state, "")
}

// writeOAuth2ErrorWithURI writes an OAuth2-compliant error response with optional error_uri
// Per RFC 6749 Section 5.2: error, error_description, and error_uri
func writeOAuth2ErrorWithURI(w http.ResponseWriter, errorCode, description, state, errorURI string) {
	response := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}

	// Add error_uri per RFC 6749 Section 5.2 (OPTIONAL)
	// If not provided, use default RFC documentation URI
	if errorURI != "" {
		response["error_uri"] = errorURI
	} else if defaultURI, exists := oauth2ErrorURIs[errorCode]; exists {
		response["error_uri"] = defaultURI
	}

	if state != "" {
		response["state"] = state
	}
	writeJSON(w, http.StatusBadRequest, response)
}

func (p *Plugin) generateLoginPage(clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, clientName string) string {
	if clientName == "" {
		if client, exists := p.mockIdP.GetClient(clientID); exists {
			clientName = client.Name
		} else {
			clientName = clientID
		}
	}

	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login - Protocol Showcase</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e4e4e7;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
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
        .logo p {
            color: #a1a1aa;
            font-size: 14px;
            margin-top: 8px;
        }
        .client-info {
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            text-align: center;
        }
        .client-info span {
            color: #a5b4fc;
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
            border-color: #6366f1;
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
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
            box-shadow: 0 10px 20px -10px rgba(99, 102, 241, 0.5);
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
            background: rgba(99, 102, 241, 0.1);
            border-color: rgba(99, 102, 241, 0.2);
        }
        .demo-user .name {
            font-weight: 500;
            color: #fff;
        }
        .demo-user .email {
            font-size: 12px;
            color: #71717a;
        }
        .scopes {
            margin-top: 16px;
            font-size: 12px;
            color: #71717a;
        }
        .scopes span {
            display: inline-block;
            background: rgba(99, 102, 241, 0.1);
            padding: 4px 8px;
            border-radius: 4px;
            margin: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Protocol Showcase</h1>
            <p>OAuth 2.0 Authorization</p>
        </div>
        
        <div class="client-info">
            <span>Signing in to <strong>` + clientName + `</strong></span>
        </div>

        <!-- ERROR -->

        <form method="POST" action="/oauth2/authorize">
            <input type="hidden" name="client_id" value="` + clientID + `">
            <input type="hidden" name="redirect_uri" value="` + redirectURI + `">
            <input type="hidden" name="scope" value="` + scope + `">
            <input type="hidden" name="state" value="` + state + `">
            <input type="hidden" name="code_challenge" value="` + codeChallenge + `">
            <input type="hidden" name="code_challenge_method" value="` + codeChallengeMethod + `">
            
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="alice@example.com" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="password" required>
            </div>
            
            <button type="submit">Sign In</button>
        </form>

        <div class="demo-users">
            <h3>Demo Users (click to autofill)</h3>
            <div class="demo-user" onclick="fillCredentials('alice@example.com', 'password123')">
                <div class="name">Alice (Standard User)</div>
                <div class="email">alice@example.com</div>
            </div>
            <div class="demo-user" onclick="fillCredentials('bob@example.com', 'password123')">
                <div class="name">Bob (Standard User)</div>
                <div class="email">bob@example.com</div>
            </div>
            <div class="demo-user" onclick="fillCredentials('admin@example.com', 'admin123')">
                <div class="name">Admin (Elevated Permissions)</div>
                <div class="email">admin@example.com</div>
            </div>
        </div>

        <div class="scopes">
            Requested scopes: ` + formatScopes(scope) + `
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

func formatScopes(scope string) string {
	if scope == "" {
		return "<span>none</span>"
	}
	scopes := strings.Split(scope, " ")
	result := ""
	for _, s := range scopes {
		result += "<span>" + s + "</span>"
	}
	return result
}

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
