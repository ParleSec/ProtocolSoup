package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
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

// handleAuthorize handles OIDC authorization requests.
//
// Request validation follows RFC 6749 Section 4.1.2.1 ordering strictly:
//  1. client_id and redirect_uri are validated first; errors here are shown to
//     the user agent and never redirected.
//  2. response_type and response_mode are resolved so a response channel exists.
//  3. every other request error is delivered by redirecting to the validated
//     redirect_uri with error and state, in that channel.
//
// Interaction (login page versus silent session reuse) is then decided per
// OpenID Connect Core 1.0 Section 3.1.2.1 using prompt and max_age.
func (p *Plugin) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// The authorization endpoint MUST support both HTTP GET and POST (OIDC Core
	// 1.0 Section 3.1.2.1). r.Form merges the URL query and any form-encoded
	// body, so a single handler serves both methods; for GET it is exactly the
	// query parameters.
	if err := r.ParseForm(); err != nil {
		p.writeAuthorizationErrorPage(w, http.StatusBadRequest, "invalid_request", "Invalid request encoding")
		return
	}
	query := r.Form
	sessionID := p.getSessionFromRequest(r)

	responseType := query.Get("response_type")
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	scope := query.Get("scope")
	state := query.Get("state")
	nonce := query.Get("nonce")
	codeChallenge := query.Get("code_challenge")
	codeChallengeMethod := query.Get("code_challenge_method")
	prompt := query.Get("prompt")
	maxAgeRaw := query.Get("max_age")
	responseModeRaw := query.Get("response_mode")
	claimsParam := query.Get("claims")

	// Emit OIDC authorization request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "OIDC Authentication Request", map[string]interface{}{
		"step":                   1,
		"from":                   "Client",
		"to":                     "OpenID Provider",
		"response_type":          responseType,
		"response_mode":          responseModeRaw,
		"client_id":              clientID,
		"redirect_uri":           redirectURI,
		"scope":                  scope,
		"scopes":                 strings.Fields(scope),
		"state":                  state,
		"state_present":          state != "",
		"nonce":                  nonce,
		"nonce_present":          nonce != "",
		"prompt":                 prompt,
		"max_age":                maxAgeRaw,
		"code_challenge":         codeChallenge,
		"code_challenge_present": codeChallenge != "",
		"code_challenge_method":  codeChallengeMethod,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OpenID Connect Authentication",
		Description: "OIDC extends OAuth 2.0 with identity verification. The openid scope is required.",
		Reference:   "OpenID Connect Core 1.0 Section 3.1.2",
	})

	// Step 1 (RFC 6749 Section 4.1.2.1): client_id and redirect_uri are
	// validated BEFORE anything else, and their errors are never redirected.
	if clientID == "" {
		p.writeAuthorizationErrorPage(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		p.writeAuthorizationErrorPage(w, http.StatusBadRequest, "invalid_client", "Unknown client")
		return
	}
	normalizedRedirectURI, err := p.mockIdP.NormalizeRedirectURI(clientID, redirectURI)
	if err != nil {
		p.writeAuthorizationErrorPage(w, http.StatusBadRequest, "invalid_request", "Invalid redirect_uri")
		return
	}
	redirectURI = normalizedRedirectURI

	// Step 2: response_type must be recognised before a channel can be chosen.
	validResponseTypes := map[string]bool{
		"code":                true,
		"token":               true,
		"id_token":            true,
		"id_token token":      true,
		"token id_token":      true,
		"code id_token":       true,
		"code token":          true,
		"code id_token token": true,
		"code token id_token": true,
	}
	if !validResponseTypes[responseType] {
		// No valid response_type means no defined channel; deliver the error in
		// the query default per RFC 6749.
		p.redirectAuthError(w, r, redirectURI, "", "query", state,
			"unsupported_response_type", "Unsupported response_type")
		return
	}

	// Resolve response_mode now that response_type is known (Phase 2e).
	responseMode, rmErrCode, rmErrDesc := resolveResponseMode(responseType, responseModeRaw)
	if rmErrCode != "" {
		p.redirectAuthError(w, r, redirectURI, responseType, defaultResponseMode(responseType), state, rmErrCode, rmErrDesc)
		return
	}

	// Step 3: every remaining request error redirects to redirect_uri.

	// request and request_uri are not supported by this OP. They are rejected
	// before any other request validation so a request object can never mask the
	// rejection, and with the dedicated error codes the spec defines rather than
	// being silently ignored (OIDC Core 1.0 Section 6.2.1, 6.3.1). The discovery
	// metadata advertises request_parameter_supported and
	// request_uri_parameter_supported as false to match.
	if query.Get("request_uri") != "" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"request_uri_not_supported", "The request_uri parameter is not supported (OIDC Core 1.0 Section 6.3.1)")
		return
	}
	if query.Get("request") != "" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"request_not_supported", "The request parameter is not supported (OIDC Core 1.0 Section 6.2.1)")
		return
	}

	// The claims request parameter (OIDC Core 1.0 Section 5.5) is supported and
	// advertised via claims_parameter_supported. Its value MUST be a JSON object;
	// a malformed value is rejected as invalid_request rather than ignored.
	if _, err := parseClaimsParameter(claimsParam); err != nil {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"invalid_request", "The claims parameter is not a valid JSON object (OIDC Core 1.0 Section 5.5)")
		return
	}

	// openid scope is required for an OIDC authorization request.
	if !containsScope(scope, "openid") {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"invalid_scope", "openid scope is required for OIDC")
		return
	}

	// nonce is REQUIRED when response_type includes id_token (OIDC Core 1.0
	// Section 3.2.2.1).
	if strings.Contains(responseType, "id_token") && nonce == "" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"invalid_request", "nonce is REQUIRED when response_type includes id_token (OIDC Core 1.0 Section 3.2.2.1)")
		return
	}

	// prompt syntax (OIDC Core 1.0 Section 3.1.2.1).
	prompts := promptValues(prompt)
	if code, desc := validatePrompt(prompts); code != "" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state, code, desc)
		return
	}

	// max_age syntax (OIDC Core 1.0 Section 3.1.2.1).
	maxAge, maxAgePresent, maxAgeErr := parseMaxAge(maxAgeRaw)
	if maxAgeErr != "" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state, "invalid_request", maxAgeErr)
		return
	}

	// PKCE enforcement for public clients (Phase 2f). A public client that asks
	// for an authorization code MUST supply a code_challenge (RFC 7636 Section
	// 4.4.1, OAuth 2.0 Security BCP Section 2.1.1).
	if client.Public && strings.Contains(responseType, "code") && codeChallenge == "" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"invalid_request", "code_challenge is required for public clients (PKCE, RFC 7636 Section 4.4.1)")
		return
	}
	// Reject unsupported code_challenge_method when a challenge is present.
	if codeChallenge != "" && codeChallengeMethod != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
			"invalid_request", "unsupported code_challenge_method (supported: S256, plain) per RFC 7636 Section 4.3")
		return
	}

	params := authParams{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ResponseType:        responseType,
		ResponseMode:        responseMode,
		Claims:              claimsParam,
	}

	// Interaction decision (OIDC Core 1.0 Section 3.1.2.1).
	session, hasSession := p.currentAuthSession(r)
	now := time.Now()
	needReauth := hasSession && reauthRequired(prompts, maxAge, maxAgePresent, session.CreatedAt, now)

	if containsValue(prompts, "none") {
		// prompt=none MUST NOT display any UI. Without a usable session the OP
		// returns login_required to the client (OIDC Core 1.0 Section 3.1.2.6).
		if !hasSession || needReauth {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "prompt=none login_required", map[string]interface{}{
				"prompt":       prompt,
				"has_session":  hasSession,
				"redirect_uri": redirectURI,
			})
			p.redirectAuthError(w, r, redirectURI, responseType, responseMode, state,
				"login_required", "No End-User session is available for prompt=none")
			return
		}
		p.issueAuthorizationResponse(w, r, sessionID, params, session.UserID, session.CreatedAt)
		return
	}

	// Reuse an existing session without an interactive login when the RP
	// explicitly bounded freshness with max_age and the session is recent
	// enough. A request with neither prompt nor max_age keeps the interactive
	// login so the authentication step stays visible (the OP MAY require fresh
	// authentication, OIDC Core 1.0 Section 3.1.2.1).
	if hasSession && !needReauth && maxAgePresent {
		p.issueAuthorizationResponse(w, r, sessionID, params, session.UserID, session.CreatedAt)
		return
	}

	loginRequestID := p.storeLoginRequest(loginRequestInfo{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ResponseType:        responseType,
		ResponseMode:        responseMode,
		Claims:              claimsParam,
	})

	// Generate login page with HTML-escaped values to prevent XSS
	loginPage := p.generateOIDCLoginPage(
		htmlEscape(clientID),
		htmlEscape(scope),
		htmlEscape(sessionID),
		htmlEscape(client.Name),
		htmlEscape(loginRequestID),
	)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(loginPage))
}

// containsScope reports whether scope (a space-delimited list) contains target
// as a whole token, avoiding substring false positives.
func containsScope(scope, target string) bool {
	for _, s := range strings.Fields(scope) {
		if s == target {
			return true
		}
	}
	return false
}

// handleAuthorizePost dispatches POST requests to the authorization endpoint.
//
// The authorization endpoint MUST accept authorization requests by both GET and
// POST (OIDC Core 1.0 Section 3.1.2.1). This OP also serves its interactive
// login form by POST to the same path. The two are distinguished by the
// login_request_id field, which only the login form carries: its presence means
// a credential submission (handleAuthorizeSubmit); its absence means a direct
// authorization request, handled identically to GET (handleAuthorize).
func (p *Plugin) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}
	if r.PostForm.Get("login_request_id") != "" {
		p.handleAuthorizeSubmit(w, r)
		return
	}
	p.handleAuthorize(w, r)
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
	loginRequestID := r.FormValue("login_request_id")
	if loginRequestID == "" {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Missing login request")
		return
	}

	requestInfo, ok := p.getLoginRequest(loginRequestID)
	if !ok {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Login request expired or invalid")
		return
	}

	clientID := requestInfo.ClientID
	redirectURI := requestInfo.RedirectURI
	scope := requestInfo.Scope
	state := requestInfo.State
	nonce := requestInfo.Nonce
	codeChallenge := requestInfo.CodeChallenge
	codeChallengeMethod := requestInfo.CodeChallengeMethod
	responseType := requestInfo.ResponseType
	if responseType == "" {
		responseType = "code"
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
			htmlEscape(scope),
			htmlEscape(sessionID),
			htmlEscape(clientName),
			htmlEscape(loginRequestID),
		)
		loginPage = strings.Replace(loginPage, "<!-- ERROR -->", `<div class="error">Invalid email or password</div>`, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(loginPage))
		return
	}

	p.consumeLoginRequest(loginRequestID)

	// Record the fresh end-user authentication so later prompt=none and max_age
	// requests can be answered correctly (OIDC Core 1.0 Section 3.1.2.1).
	session := p.establishAuthSession(w, user.ID, clientID)

	responseMode := requestInfo.ResponseMode
	if responseMode == "" {
		responseMode = defaultResponseMode(responseType)
	}

	params := authParams{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ResponseType:        responseType,
		ResponseMode:        responseMode,
		Claims:              requestInfo.Claims,
	}

	// auth_time is the moment this session was established, so a later silent
	// reuse of the same session reports an identical auth_time (OIDC Core 1.0
	// Section 2; keeps max_age evaluation consistent across requests).
	p.issueAuthorizationResponse(w, r, sessionID, params, user.ID, session.CreatedAt)
}

// issueAuthorizationResponse builds and returns the authorization response for a
// resolved request. It is the single issuance path shared by interactive login
// and silent session reuse, so the two can never diverge. Response parameters
// are placed in the channel given by params.ResponseMode (OAuth 2.0 Multiple
// Response Type Encoding Practices Section 2). authTime is the time of the
// End-User authentication that this response is based on and is carried into the
// ID Token (OIDC Core 1.0 Section 2).
func (p *Plugin) issueAuthorizationResponse(w http.ResponseWriter, r *http.Request, sessionID string, params authParams, userID string, authTime time.Time) {
	redirectURL, err := url.Parse(params.RedirectURI)
	if err != nil {
		p.writeAuthorizationErrorPage(w, http.StatusBadRequest, "invalid_request", "Malformed redirect_uri")
		return
	}

	hasCode := strings.Contains(params.ResponseType, "code")
	hasToken := params.ResponseType == "token" ||
		strings.Contains(params.ResponseType, " token") ||
		strings.HasPrefix(params.ResponseType, "token ")
	hasIDToken := strings.Contains(params.ResponseType, "id_token")

	jwtService := p.mockIdP.JWTService()
	var authorizationCode string
	var accessToken string

	if hasCode {
		authCode, err := p.mockIdP.CreateAuthorizationCode(
			params.ClientID, userID, params.RedirectURI, params.Scope, params.State, params.Nonce,
			params.CodeChallenge, params.CodeChallengeMethod, params.Claims, authTime,
		)
		if err != nil {
			// CreateAuthorizationCode validates the code_challenge format; a
			// failure is a request error, not a server error, so it is
			// delivered to the client.
			p.redirectAuthError(w, r, params.RedirectURI, params.ResponseType, params.ResponseMode, params.State,
				"invalid_request", err.Error())
			return
		}
		authorizationCode = authCode.Code
	}

	if hasToken {
		// Requested UserInfo claims (OIDC Core 1.0 Section 5.5) travel with the
		// access token so the UserInfo endpoint knows which extra claims to
		// return; identity claim values are not embedded (Section 5.4).
		accessToken, err = jwtService.CreateAccessToken(userID, params.ClientID, params.Scope, time.Hour, requestedUserInfoClaimNames(params.Claims))
		if err != nil {
			p.redirectAuthError(w, r, params.RedirectURI, params.ResponseType, params.ResponseMode, params.State,
				"server_error", "Failed to create access token")
			return
		}
	}

	var idToken string
	if hasIDToken {
		// Scope-requested claims (profile, email, ...) are returned from the
		// UserInfo endpoint whenever the flow issues an access token, and only
		// carried in the ID Token when no access token is issued, which is the
		// response_type=id_token case (OIDC Core 1.0 Section 5.4). hasCode covers
		// hybrid flows where the access token is issued later at the token
		// endpoint, so the front-channel ID Token still omits the scope claims.
		var idClaims map[string]interface{}
		if !hasCode && !hasToken {
			idClaims = p.mockIdP.UserClaims(userID, strings.Fields(params.Scope))
		}

		// Claims the client requested specifically for the ID Token via the
		// claims parameter (OIDC Core 1.0 Section 5.5) are delivered in the ID
		// Token. UserInfo-targeted requested claims are deliberately not added
		// here; they are served from the UserInfo endpoint instead.
		if rc, _ := parseClaimsParameter(params.Claims); rc != nil && len(rc.idToken) > 0 {
			if idClaims == nil {
				idClaims = make(map[string]interface{})
			}
			for name, value := range p.mockIdP.UserClaimsByNames(userID, rc.idToken) {
				idClaims[name] = value
			}
		}

		// at_hash and c_hash are included based on what the authorization
		// endpoint returns (OIDC Core 1.0 Section 3.3.2.11).
		idTokenOptions := &crypto.IDTokenOptions{
			ACR: acrSingleFactorLogin,
			AMR: amrSingleFactorLogin,
		}
		if accessToken != "" {
			idTokenOptions.AccessToken = accessToken
		}
		if authorizationCode != "" {
			idTokenOptions.AuthorizationCode = authorizationCode
		}

		idToken, err = jwtService.CreateIDTokenWithOptions(
			userID, params.ClientID, params.Nonce, authTime, time.Hour, idClaims, idTokenOptions,
		)
		if err != nil {
			p.redirectAuthError(w, r, params.RedirectURI, params.ResponseType, params.ResponseMode, params.State,
				"server_error", "Failed to create ID token")
			return
		}
	}

	// Assemble response parameters and place them in the resolved channel. The
	// same assembly serves code, implicit, and hybrid flows.
	out := url.Values{}
	if authorizationCode != "" {
		out.Set("code", authorizationCode)
	}
	if accessToken != "" {
		out.Set("access_token", accessToken)
		out.Set("token_type", "Bearer")
		out.Set("expires_in", "3600")
	}
	if idToken != "" {
		out.Set("id_token", idToken)
	}
	if params.State != "" {
		out.Set("state", params.State)
	}

	if params.ResponseMode == "fragment" {
		redirectURL.Fragment = out.Encode()
	} else {
		existing := redirectURL.Query()
		for key := range out {
			existing.Set(key, out.Get(key))
		}
		redirectURL.RawQuery = existing.Encode()
	}

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "OIDC Authorization Response", map[string]interface{}{
		"from":             "OpenID Provider",
		"to":               "Client",
		"response_type":    params.ResponseType,
		"response_mode":    params.ResponseMode,
		"code_present":     authorizationCode != "",
		"token_present":    accessToken != "",
		"id_token_present": idToken != "",
		"state":            params.State,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Authorization Response",
		Description: "Response parameters are returned in the query for the code flow and in the fragment for implicit and hybrid flows.",
		Reference:   "OpenID Connect Core 1.0 Section 3",
	})

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
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_request", "Invalid form data", "")
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
		writeOIDCTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not supported", "")
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
		writeOIDCTokenError(w, http.StatusUnauthorized, "invalid_client", "Unknown client", basicChallenge(clientAuthMethod))
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Auth Failed", map[string]interface{}{
				"client_id":          clientID,
				"client_auth_method": clientAuthMethod,
			})
			writeOIDCTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed", basicChallenge(clientAuthMethod))
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
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error(), "")
		return
	}

	// Generate tokens including ID token
	tokenResponse, err := p.issueOIDCTokens(authCode)
	if err != nil {
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", "Failed to issue tokens", "")
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
		writeOIDCTokenError(w, http.StatusUnauthorized, "invalid_client", "Unknown client", basicChallenge(clientAuthMethod))
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			writeOIDCTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed", basicChallenge(clientAuthMethod))
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
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error(), "")
		return
	}

	// Use original scope if not specified
	if scope == "" {
		scope = rt.Scope
	}

	// Generate new tokens (including new ID token if openid scope)
	jwtService := p.mockIdP.JWTService()
	scopes := strings.Split(scope, " ")

	// As with the code flow, the access token carries the granted scope and the
	// UserInfo endpoint serves the scope-requested claims; the token does not
	// embed identity claims (OIDC Core 1.0 Section 5.4).
	accessToken, err := jwtService.CreateAccessToken(
		rt.UserID,
		clientID,
		scope,
		time.Hour,
		nil,
	)
	if err != nil {
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create access token", "")
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
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create refresh token", "")
		return
	}

	// Store new refresh token, preserving the original authentication time so a
	// rotated chain keeps reporting the same auth_time (OIDC Core 1.0 Section 12.2).
	p.mockIdP.StoreRefreshToken(newRefreshToken, clientID, rt.UserID, scope, rt.AuthTime, time.Now().Add(7*24*time.Hour))

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
		// auth_time MUST be the original authentication time, not now: the
		// End-User did not re-authenticate to refresh. nonce is omitted, which
		// is permitted (OIDC Core 1.0 Section 12.2 only constrains nonce when
		// present). Scope claims are served from UserInfo, so the refreshed ID
		// Token carries only authentication claims (Section 5.4).
		// acr/amr describe the original authentication context, which persists
		// across refresh (the session was established by a password login).
		idToken, err := jwtService.CreateIDTokenWithOptions(
			rt.UserID,
			clientID,
			"", // No nonce for refresh
			rt.AuthTime,
			time.Hour,
			nil,
			&crypto.IDTokenOptions{ACR: acrSingleFactorLogin, AMR: amrSingleFactorLogin},
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

	// The access token carries the granted scope; the UserInfo endpoint derives
	// the profile/email/... claims from that scope on demand. The token itself
	// does not embed identity claims (OIDC Core 1.0 Section 5.4). Any UserInfo
	// claims the client requested via the claims parameter (Section 5.5) ride
	// along as claim names so UserInfo can return them.
	accessToken, err := jwtService.CreateAccessToken(
		authCode.UserID,
		authCode.ClientID,
		authCode.Scope,
		time.Hour,
		requestedUserInfoClaimNames(authCode.Claims),
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

	// Store refresh token, carrying the authentication time so a refreshed ID
	// Token keeps the same auth_time (OIDC Core 1.0 Section 12.2).
	p.mockIdP.StoreRefreshToken(refreshToken, authCode.ClientID, authCode.UserID, authCode.Scope, authCode.AuthTime, time.Now().Add(7*24*time.Hour))

	// Bind the issued tokens to the redeemed code so that, if the code is ever
	// replayed, these exact tokens are revoked (RFC 6749 Section 4.1.2).
	p.mockIdP.RecordIssuedTokens(authCode.Code, accessToken, refreshToken)

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
		// The code flow always issues an access token, so the scope-requested
		// claims are served from UserInfo and the ID Token carries only the
		// authentication claims (sub, auth_time, nonce, ...) per OIDC Core 1.0
		// Section 5.4. auth_time reflects when the End-User actually
		// authenticated, captured at the authorization endpoint (Section 2).
		// acr/amr reflect the password authentication performed at the
		// authorization endpoint (OIDC Core 1.0 Section 2, RFC 8176).
		idToken, err := jwtService.CreateIDTokenWithOptions(
			authCode.UserID,
			authCode.ClientID,
			authCode.Nonce,
			authCode.AuthTime,
			time.Hour,
			nil,
			&crypto.IDTokenOptions{ACR: acrSingleFactorLogin, AMR: amrSingleFactorLogin},
		)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	return response, nil
}

func (p *Plugin) generateOIDCLoginPage(clientID, scope, sessionID, clientName, loginRequestID string) string {
	if clientName == "" {
		if client, exists := p.mockIdP.GetClient(clientID); exists {
			clientName = client.Name
		} else {
			clientName = clientID
		}
	}
	formAction := "/oidc/authorize"
	if sessionID != "" {
		formAction += "?lg_session=" + url.QueryEscape(sessionID)
	}

	demoUsersHTML := buildDemoUsersHTML(p.mockIdP.GetDemoUserPresets())

	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
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
            padding: 16px;
        }
        .container {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 28px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        @media (min-width: 480px) {
            body { padding: 0; }
            .container { padding: 40px; }
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
            <input type="hidden" name="login_request_id" value="` + loginRequestID + `">
            
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

        ` + demoUsersHTML + `

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

func buildDemoUsersHTML(presets []mockidp.DemoUserPreset) string {
	if len(presets) == 0 {
		return ""
	}

	var builder strings.Builder
	builder.WriteString(`<div class="demo-users">`)
	builder.WriteString(`<h3>Demo Users (click to autofill)</h3>`)
	for _, preset := range presets {
		email := preset.Credentials.Email
		password := preset.Credentials.Password
		if email == "" || password == "" {
			continue
		}
		builder.WriteString(`<div class="demo-user" data-email="`)
		builder.WriteString(html.EscapeString(email))
		builder.WriteString(`" data-password="`)
		builder.WriteString(html.EscapeString(password))
		builder.WriteString(`" onclick="fillCredentials(this.dataset.email || '', this.dataset.password || '')">`)
		builder.WriteString(`<div class="name">`)
		builder.WriteString(html.EscapeString(preset.Name))
		builder.WriteString(`</div>`)
		builder.WriteString(`<div class="email">`)
		builder.WriteString(html.EscapeString(email))
		builder.WriteString(`</div></div>`)
	}
	builder.WriteString(`</div>`)
	return builder.String()
}

type loginRequestInfo struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseType        string
	ResponseMode        string
	Claims              string
	CreatedAt           time.Time
}

func (p *Plugin) storeLoginRequest(info loginRequestInfo) string {
	loginRequestID := newLoginRequestID()
	info.CreatedAt = time.Now()

	p.loginRequestsMu.Lock()
	p.loginRequests[loginRequestID] = info
	p.loginRequestsMu.Unlock()

	return loginRequestID
}

func (p *Plugin) getLoginRequest(loginRequestID string) (loginRequestInfo, bool) {
	p.loginRequestsMu.RLock()
	defer p.loginRequestsMu.RUnlock()

	info, ok := p.loginRequests[loginRequestID]
	return info, ok
}

func (p *Plugin) consumeLoginRequest(loginRequestID string) {
	p.loginRequestsMu.Lock()
	delete(p.loginRequests, loginRequestID)
	p.loginRequestsMu.Unlock()
}

func (p *Plugin) cleanupLoginRequests() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-p.loginRequestTTL)
		p.loginRequestsMu.Lock()
		for id, info := range p.loginRequests {
			if info.CreatedAt.Before(cutoff) {
				delete(p.loginRequests, id)
			}
		}
		p.loginRequestsMu.Unlock()
	}
}

func newLoginRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
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
