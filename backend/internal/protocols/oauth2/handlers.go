package oauth2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
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

// oauth2Annotation looks up a keyed set of pre-defined annotations from the
// shared library (mirrors oid4vci's Plugin.vcAnnotation), for RFC citations
// that are stable regardless of which handler is emitting the event.
func (p *Plugin) oauth2Annotation(key string) []lookingglass.Annotation {
	annotationSet := lookingglass.NewAnnotationLibrary().OAuth2Annotations()
	if items, ok := annotationSet[key]; ok {
		return items
	}
	return nil
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
		"step":                   1,
		"from":                   "Client",
		"to":                     "Authorization Server",
		"response_type":          responseType,
		"client_id":              clientID,
		"redirect_uri":           redirectURI,
		"scope":                  scope,
		"scopes":                 strings.Fields(scope),
		"state":                  state,
		"state_present":          state != "",
		"code_challenge":         codeChallenge,
		"code_challenge_present": codeChallenge != "",
		"code_challenge_method":  codeChallengeMethod,
	}, authorizeRequestAnnotation(responseType))

	// RFC 6749 §4.1.1 / §4.2.1: response_type is required. Anything other than
	// "code" or "token" is unsupported. A valid client and redirect URI receive
	// the error in the fragment (§4.2.2.1). A missing or invalid client_id or
	// redirect_uri MUST NOT be redirected (§4.1.2.1 / §4.2.2.1).
	if responseType != "code" && responseType != "token" {
		errorCode := "unsupported_response_type"
		description := "Only 'code' and 'token' response types are supported"
		if responseType == "" {
			errorCode = "invalid_request"
			description = "response_type is required"
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Response Type", map[string]interface{}{
			"error":         errorCode,
			"response_type": responseType,
		})
		p.finishAuthorizeClientError(w, r, clientID, redirectURI, state, errorCode, description)
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
	normalizedRedirectURI, err := p.mockIdP.NormalizeRedirectURI(clientID, redirectURI)
	if err != nil {
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
	redirectURI = normalizedRedirectURI

	// RFC 8707 Section 2.1: a "resource" parameter in the authorization
	// request names the protected resource the grant is for. It is checked
	// here so an unacceptable value is refused before the End-User signs in.
	if _, rejected := p.tokenAudience(query["resource"], scope); rejected != nil {
		p.emitTargetRejected(sessionID, "/oauth2/authorize", query["resource"], scope, rejected)
		if responseType == "token" {
			p.redirectAuthorizeFragmentError(w, r, redirectURI, state, rejected.code, rejected.description)
		} else {
			p.redirectAuthorizeQueryError(w, r, redirectURI, state, rejected.code, rejected.description)
		}
		return
	}

	if responseType == "token" {
		p.beginImplicitAuthorization(w, r, sessionID, client, redirectURI, scope, state)
		return
	}

	loginRequestID := p.storeLoginRequest(loginRequestInfo{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		ResponseType:        "code",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})

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
		"step":          2,
		"from":          "User",
		"to":            "Authorization Server",
		"client_id":     clientID,
		"client_name":   client.Name,
		"redirect_uri":  redirectURI,
		"response_type": responseType,
		"scope":         scope,
		"scopes":        strings.Fields(scope),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Authorization Endpoint User Authentication",
		Description: "The authorization server authenticates the user before granting access",
		Reference:   "RFC 6749 Section 3.1",
	})

	// For demo purposes, return a login page
	loginPage := p.generateLoginPage(clientID, scope, sessionID, client.Name, loginRequestID, "")
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
	loginRequestID := r.FormValue("login_request_id")
	if loginRequestID == "" {
		writeOAuth2Error(w, "invalid_request", "Missing login request", "")
		return
	}

	requestInfo, ok := p.getLoginRequest(loginRequestID)
	if !ok {
		writeOAuth2Error(w, "invalid_request", "Login request expired or invalid", "")
		return
	}

	clientID := requestInfo.ClientID
	redirectURI := requestInfo.RedirectURI
	scope := requestInfo.Scope
	state := requestInfo.State
	codeChallenge := requestInfo.CodeChallenge
	codeChallengeMethod := requestInfo.CodeChallengeMethod
	nonce := "" // OAuth2 flow does not require nonce

	// Emit credential submission event (without password!)
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "User Credentials Submitted", map[string]interface{}{
		"username":  email,
		"client_id": clientID,
		"endpoint":  "/oauth2/authorize",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "User Authentication Submission",
		Description: "Credentials are submitted to the authorization server for authentication",
		Reference:   "RFC 6749 Section 3.1",
	})

	// Validate user credentials
	user, err := p.mockIdP.ValidateCredentials(email, password)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authentication Failed", map[string]interface{}{
			"email":  email,
			"reason": "Invalid credentials",
		})
		// Return to login page with error
		pageSubtitle := ""
		if requestInfo.ResponseType == "token" {
			pageSubtitle = implicitLoginSubtitle
		}
		loginPage := p.generateLoginPage(clientID, scope, sessionID, "", loginRequestID, pageSubtitle)
		loginPage = strings.Replace(loginPage, "<!-- ERROR -->", `<div class="error">Invalid email or password</div>`, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(loginPage))
		return
	}

	p.consumeLoginRequest(loginRequestID)

	// Emit successful authentication
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "User Authenticated Successfully", map[string]interface{}{
		"step":      2,
		"from":      "User",
		"to":        "Authorization Server",
		"user_id":   user.ID,
		"name":      user.Name,
		"email":     user.Email,
		"client_id": clientID,
		"scope":     scope,
		"scopes":    strings.Fields(scope),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "User Authentication Complete",
		Description: authorizeSuccessDescription(requestInfo.ResponseType),
		Reference:   authorizeSuccessReference(requestInfo.ResponseType),
	})

	if requestInfo.ResponseType == "token" {
		p.completeImplicitGrant(w, r, sessionID, user, requestInfo)
		return
	}

	// Create authorization code (auth_time is now: the user just authenticated).
	// OAuth 2.0 has no OIDC claims request parameter, so claims is empty.
	authCode, err := p.mockIdP.CreateAuthorizationCode(
		clientID, user.ID, redirectURI, scope, state, nonce,
		codeChallenge, codeChallengeMethod, "", time.Now(),
	)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authorization Code Creation Failed", map[string]interface{}{
			"error":        err.Error(),
			"client_id":    clientID,
			"redirect_uri": redirectURI,
			"scope":        scope,
		})
		writeOAuth2Error(w, "server_error", "Failed to create authorization code", state)
		return
	}

	// Emit authorization code issued event
	expiresInSeconds := int(time.Until(authCode.ExpiresAt).Seconds())
	if expiresInSeconds < 0 {
		expiresInSeconds = 0
	}
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Authorization Code Issued", map[string]interface{}{
		"step":                   3,
		"from":                   "Authorization Server",
		"to":                     "Client",
		"client_id":              clientID,
		"redirect_uri":           redirectURI,
		"code":                   authCode.Code,
		"code_length":            len(authCode.Code),
		"code_preview":           authCode.Code[:min(8, len(authCode.Code))] + "...",
		"state":                  authCode.State,
		"state_present":          authCode.State != "",
		"code_challenge":         authCode.CodeChallenge,
		"code_challenge_present": authCode.CodeChallenge != "",
		"code_challenge_method":  authCode.CodeChallengeMethod,
		"scope":                  authCode.Scope,
		"scopes":                 strings.Fields(authCode.Scope),
		"expires_at":             authCode.ExpiresAt.Format(time.RFC3339),
		"expires_in_seconds":     expiresInSeconds,
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
	// RFC 9207 Section 2 / FAPI 2.0 SP §5.3.2.2: include iss matching AS metadata.
	if issuer, err := authorizationServerMetadataIssuer(p.baseURL); err == nil {
		q.Set("iss", issuer)
	}
	redirectURL.RawQuery = q.Encode()

	// Emit redirect event
	p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Redirecting to Client", map[string]interface{}{
		"redirect_uri":  redirectURI,
		"response_type": "code",
		"response_mode": "query",
		"code":          authCode.Code,
		"state":         state,
		"has_code":      true,
		"has_state":     state != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "State Parameter Echo",
		Description: "The state parameter is echoed back to the client for CSRF validation",
		Reference:   "RFC 6749 Section 4.1.2",
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
			"endpoint":     "/oauth2/token",
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
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")
	code := r.FormValue("code")
	refreshToken := r.FormValue("refresh_token")
	tokenTypeHint := r.FormValue("token_type_hint")
	assertionTypePresent := r.Form.Has("client_assertion_type")
	assertionPresent := r.Form.Has("client_assertion")
	if assertionTypePresent != assertionPresent {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Incomplete Client Assertion Authentication", map[string]interface{}{
			"reason":                        "client_assertion_parameter_pair_required",
			"client_assertion_type_present": assertionTypePresent,
			"client_assertion_present":      assertionPresent,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "JWT Client Authentication Parameters",
			Description: "client_assertion_type and client_assertion are used together for JWT client authentication.",
			Reference:   "RFC 7523 Section 2.2",
		})
		writeOAuth2Error(w, "invalid_request", "client_assertion_type and client_assertion must be provided together", "")
		return
	}
	if clientID == "" {
		if basicClientID, _, ok := r.BasicAuth(); ok {
			clientID = basicClientID
		}
	}
	clientAuthMethod := "none"
	if _, _, ok := r.BasicAuth(); ok {
		clientAuthMethod = "basic"
	} else if assertionTypePresent {
		clientAuthMethod = "private_key_jwt"
	} else if clientID != "" {
		clientAuthMethod = "post"
	}

	// Emit token request event
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Token Request Received", map[string]interface{}{
		"grant_type":            grantType,
		"endpoint":              "/oauth2/token",
		"client_id":             clientID,
		"client_auth_method":    clientAuthMethod,
		"scope":                 scope,
		"scopes":                strings.Fields(scope),
		"code":                  code,
		"code_present":          code != "",
		"refresh_token":         refreshToken,
		"refresh_token_present": refreshToken != "",
		"token_type_hint":       tokenTypeHint,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Endpoint Request",
		Description: "Token requests are sent to the token endpoint with form-encoded parameters",
		Reference:   "RFC 6749 Section 3.2",
	})

	// RFC 9449 (DPoP): validate an optional proof once, up front, since htm
	// and htu are identical across every grant type at this single token
	// endpoint. Absent header -> zero-value result, no behavioural change.
	dpopResult, dpopErr := p.validateTokenEndpointDPoP(r)
	if dpopErr != nil {
		var infrastructureErr *dpop.InfrastructureError
		if errors.As(dpopErr, &infrastructureErr) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Replay Store Unavailable", map[string]interface{}{
				"error":  "server_error",
				"reason": "dpop_replay_store_unavailable",
			}, lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "DPoP Replay Protection Unavailable",
				Description: "The authorization server failed closed because it could not reserve the proof's jti atomically.",
				Severity:    "warning",
				Reference:   "RFC 9449 Section 11.1",
			})
			writeOAuth2ErrorStatus(w, http.StatusInternalServerError, "server_error", "DPoP validation is temporarily unavailable", "")
			return
		}
		var nonceErr *dpop.NonceRequiredError
		if errors.As(dpopErr, &nonceErr) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Nonce Challenge", map[string]interface{}{
				"error":  dpop.ErrorUseDPoPNonce,
				"reason": "server_requires_fresh_nonce",
			}, p.oauth2Annotation("dpop_nonce")...)
			w.Header().Set(dpop.NonceHeaderName, nonceErr.Nonce)
			writeOAuth2Error(w, dpop.ErrorUseDPoPNonce, "A fresh DPoP proof nonce is required; retry with the nonce from the DPoP-Nonce response header", "")
			return
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Proof Rejected", map[string]interface{}{
			"error":  dpop.ErrorInvalidDPoPProof,
			"reason": dpopErr.Error(),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Invalid DPoP Proof",
			Description: "The DPoP proof JWT failed validation, so the token request was rejected before any grant was processed. Specific validation reasons remain internal; the OAuth response is deliberately generic, matching this endpoint's private_key_jwt error convention.",
			Severity:    "warning",
			Reference:   "RFC 9449 Section 4.3",
		})
		writeOAuth2Error(w, dpop.ErrorInvalidDPoPProof, "DPoP proof validation failed", "")
		return
	}
	if dpopResult.Present {
		dpopAnnotations := append(
			[]lookingglass.Annotation{{
				Type:        lookingglass.AnnotationTypeRFCReference,
				Title:       "DPoP Proof-of-Possession",
				Description: "The client demonstrated possession of the private key bound to this token request. The issued access token will carry a cnf.jkt claim and a DPoP token_type.",
				Reference:   "RFC 9449 Section 4.3",
			}},
			append(p.oauth2Annotation("dpop_proof"), p.oauth2Annotation("dpop_cnf_jkt")...)...,
		)
		p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "DPoP Proof Validated", map[string]interface{}{
			"jkt": dpopResult.JKT,
		}, dpopAnnotations...)
	}

	switch grantType {
	case "authorization_code":
		if assertionPresent {
			p.rejectClientAssertionForUnsupportedGrant(w, r, sessionID, grantType)
			return
		}
		p.handleAuthorizationCodeGrant(w, r, sessionID, dpopResult.JKT)
	case "refresh_token":
		if assertionPresent {
			p.rejectClientAssertionForUnsupportedGrant(w, r, sessionID, grantType)
			return
		}
		p.handleRefreshTokenGrant(w, r, sessionID, dpopResult.JKT)
	case "client_credentials":
		p.handleClientCredentialsGrant(w, r, sessionID, dpopResult.JKT)
	case mockidp.DeviceCodeGrantType:
		if assertionPresent {
			p.rejectClientAssertionForUnsupportedGrant(w, r, sessionID, grantType)
			return
		}
		p.handleDeviceCodeGrant(w, r, sessionID, dpopResult.JKT)
	default:
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unsupported Grant Type", map[string]interface{}{
			"grant_type": grantType,
			"endpoint":   "/oauth2/token",
		})
		writeOAuth2Error(w, "unsupported_grant_type", "Grant type not supported", "")
	}
}

func (p *Plugin) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, sessionID string, dpopJKT string) {
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

	// Emit token exchange step
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Token Exchange Request", map[string]interface{}{
		"step":                  4,
		"from":                  "Client",
		"to":                    "Authorization Server",
		"grant_type":            "authorization_code",
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"code":                  code,
		"code_preview":          code[:min(8, len(code))] + "...",
		"code_verifier":         codeVerifier,
		"code_verifier_present": codeVerifier != "",
		"client_auth_method":    clientAuthMethod,
		"client_secret_present": clientSecret != "",
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
		writeInvalidClient(w, r, "Unknown client")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
				"client_id":          clientID,
				"reason":             "invalid_credentials",
				"client_auth_method": clientAuthMethod,
			})
			writeInvalidClient(w, r, "Client authentication failed")
			return
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Client Authenticated", map[string]interface{}{
			"client_id":          clientID,
			"client_type":        "confidential",
			"client_auth_method": clientAuthMethod,
		})
	}

	// Validate authorization code
	authCode, err := p.mockIdP.ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authorization Code Validation Failed", map[string]interface{}{
			"error":                 err.Error(),
			"reason":                "invalid_grant",
			"client_id":             clientID,
			"redirect_uri":          redirectURI,
			"code":                  code,
			"code_verifier_present": codeVerifier != "",
		})
		var replay *mockidp.AuthorizationCodeReplay
		if errors.As(err, &replay) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Authorization Code Replayed: Tokens Revoked", map[string]interface{}{
				"error":                     "invalid_grant",
				"client_id":                 clientID,
				"code":                      code,
				"access_token_jtis_revoked": replay.AccessTokenJTIs,
				"refresh_tokens_revoked":    replay.RefreshTokens,
			}, lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "A Replayed Code Revokes What It Issued",
				Description: `"If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code." That covers the tokens issued when the code was redeemed and the ones obtained since by refreshing.`,
				Severity:    "warning",
				Reference:   "RFC 6749 Section 4.1.2",
			})
		}
		writeOAuth2Error(w, "invalid_grant", err.Error(), "")
		return
	}

	// Emit PKCE validation if applicable
	if codeVerifier != "" {
		p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "PKCE Verification Successful", map[string]interface{}{
			"code_challenge":        authCode.CodeChallenge,
			"code_challenge_method": authCode.CodeChallengeMethod,
			"code_verifier":         codeVerifier,
			"verifier_length":       len(codeVerifier),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeBestPractice,
			Title:       "PKCE Verification",
			Description: "The authorization server verified that the code_verifier matches the code_challenge from the authorization request",
			Reference:   "RFC 7636 Section 4.6",
		})
	}

	// Generate tokens. Refresh-token DPoP binding is restricted to public
	// clients per RFC 9449 Section 5 -- a confidential client's refresh
	// token is already sender-constrained via its authentication
	// credentials, so it is not additionally bound to the proof key.
	audience, audienceOK := p.tokenAudienceOrError(w, sessionID, r.Form["resource"], authCode.Scope)
	if !audienceOK {
		return
	}
	tokenResponse, err := p.issueTokens(authCode.UserID, clientID, authCode.Scope, audience, dpopJKT, client.Public, nil)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Token Generation Failed", map[string]interface{}{
			"error": err.Error(),
		})
		writeOAuth2Error(w, "server_error", "Failed to issue tokens", "")
		return
	}
	// RFC 6749 Section 4.1.2: record tokens against the redeemed code so a
	// later replay can revoke them (SHOULD). Matches the OIDC / OID4VCI paths.
	p.mockIdP.RecordIssuedTokens(authCode.Code, tokenResponse.AccessToken, tokenResponse.RefreshToken)

	// Emit token issued event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Access Token Issued", map[string]interface{}{
		"step":              5,
		"from":              "Authorization Server",
		"to":                "Client",
		"access_token":      tokenResponse.AccessToken,
		"refresh_token":     tokenResponse.RefreshToken,
		"token_type":        tokenResponse.TokenType,
		"expires_in":        tokenResponse.ExpiresIn,
		"scope":             tokenResponse.Scope,
		"scopes":            strings.Fields(tokenResponse.Scope),
		"has_refresh_token": tokenResponse.RefreshToken != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Tokens Issued",
		Description: "The authorization server has issued tokens. The access token can now be used to access protected resources.",
		Reference:   "RFC 6749 Section 5.1",
	})

	writeJSON(w, http.StatusOK, tokenResponse)
}

func (p *Plugin) rejectClientAssertionForUnsupportedGrant(
	w http.ResponseWriter,
	r *http.Request,
	sessionID string,
	grantType string,
) {
	p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Assertion Authentication Rejected", map[string]interface{}{
		"error":      "invalid_client",
		"reason":     "private_key_jwt_not_enabled_for_grant",
		"grant_type": grantType,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Scoped Client Authentication Method",
		Description: "This ProtocolSoup profile enables private_key_jwt only for the client_credentials grant.",
		Reference:   "RFC 7523 Section 2.2",
	})
	writeInvalidClient(w, r, "Client authentication method is not supported for this grant type")
}

func (p *Plugin) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string, dpopJKT string) {
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

	// Emit refresh token request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Refresh Token Request", map[string]interface{}{
		"grant_type":            "refresh_token",
		"client_id":             clientID,
		"client_auth_method":    clientAuthMethod,
		"refresh_token":         refreshToken,
		"refresh_token_length":  len(refreshToken),
		"requested_scope":       scope,
		"requested_scopes":      strings.Fields(scope),
		"refresh_token_present": refreshToken != "",
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
		writeInvalidClient(w, r, "Unknown client")
		return
	}

	if !client.Public {
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
				"client_id":          clientID,
				"client_auth_method": clientAuthMethod,
			})
			writeInvalidClient(w, r, "Client authentication failed")
			return
		}
	}

	// Validate refresh token
	rt, err := p.mockIdP.ValidateRefreshToken(refreshToken, clientID)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Refresh Token Invalid", map[string]interface{}{
			"error":                err.Error(),
			"refresh_token":        refreshToken,
			"refresh_token_length": len(refreshToken),
		})
		writeOAuth2Error(w, "invalid_grant", err.Error(), "")
		return
	}

	// Use original scope if not specified
	if scope == "" {
		scope = rt.Scope
	}

	// RFC 9449 Section 5: a refresh token issued alongside a DPoP-bound
	// access token remains bound to that same key. The proof presented on
	// this refresh request must demonstrate possession of that same key --
	// a missing proof or a proof for a different key is rejected exactly
	// like any other invalid_grant, not silently downgraded to bearer.
	boundJKT := rt.JKT
	if boundJKT != "" && dpopJKT != boundJKT {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Key Mismatch On Refresh", map[string]interface{}{
			"error":  "invalid_grant",
			"reason": "dpop_proof_key_mismatch",
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "DPoP-Bound Refresh Token",
			Description: "This refresh token is bound to a DPoP key. The refresh request must present a valid proof for that same key.",
			Severity:    "warning",
			Reference:   "RFC 9449 Section 5",
		})
		writeOAuth2Error(w, "invalid_grant", "Refresh token is bound to a different DPoP key", "")
		return
	}

	// Generate new tokens. boundJKT is only ever non-empty for a refresh
	// token that was itself bound at issuance, which -- per the same
	// public-client restriction applied there -- only happens for a
	// public client; client.Public is re-checked here too so the
	// invariant holds even if that upstream guarantee ever changes.
	audience, audienceOK := p.tokenAudienceOrError(w, sessionID, r.Form["resource"], scope)
	if !audienceOK {
		return
	}
	tokenResponse, err := p.issueTokens(rt.UserID, clientID, scope, audience, boundJKT, client.Public, rt)
	if err != nil {
		writeOAuth2Error(w, "server_error", "Failed to issue tokens", "")
		return
	}

	// Emit token rotation event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Tokens Refreshed", map[string]interface{}{
		"access_token":         tokenResponse.AccessToken,
		"refresh_token":        tokenResponse.RefreshToken,
		"token_type":           tokenResponse.TokenType,
		"expires_in":           tokenResponse.ExpiresIn,
		"scope":                tokenResponse.Scope,
		"scopes":               strings.Fields(tokenResponse.Scope),
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

func (p *Plugin) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, sessionID string, dpopJKT string) {
	scope := r.FormValue("scope")

	// Determine client authentication method
	// RFC 6749 Section 2.3: "The client MUST NOT use more than one authentication method
	// in each request."
	postClientID := r.FormValue("client_id")
	postClientSecret := r.FormValue("client_secret")
	basicClientID, basicClientSecret, hasBasicAuth := r.BasicAuth()
	hasPostAuth := r.Form.Has("client_secret")
	hasAssertionAuth := r.Form.Has("client_assertion_type") && r.Form.Has("client_assertion")
	assertionType := r.FormValue("client_assertion_type")
	assertion := r.FormValue("client_assertion")

	// Reject requests using multiple authentication methods (RFC 6749 Section 2.3).
	authMethodCount := 0
	for _, present := range []bool{hasBasicAuth, hasPostAuth, hasAssertionAuth} {
		if present {
			authMethodCount++
		}
	}
	if authMethodCount > 1 {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Dual Authentication Methods Rejected", map[string]interface{}{
			"error":                    "invalid_request",
			"detail":                   "Client sent more than one authentication method",
			"basic_present":            hasBasicAuth,
			"client_secret_present":    hasPostAuth,
			"client_assertion_present": hasAssertionAuth,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Multiple Auth Methods Rejected",
			Description: "A client MUST NOT use more than one authentication method in each request.",
			Reference:   "RFC 6749 Section 2.3",
		})
		writeOAuth2Error(w, "invalid_request",
			"A client MUST NOT use more than one authentication method in each request (RFC 6749 Section 2.3)", "")
		return
	}

	// Resolve credentials from the single authentication method used
	var clientID, clientSecret string
	clientAuthMethod := "none"
	if hasBasicAuth {
		clientID = basicClientID
		clientSecret = basicClientSecret
		clientAuthMethod = "basic"
	} else if hasPostAuth {
		clientID = postClientID
		clientSecret = postClientSecret
		clientAuthMethod = "post"
	} else if hasAssertionAuth {
		clientID = postClientID
		clientAuthMethod = "private_key_jwt"
	} else {
		clientID = postClientID
	}

	// Emit client credentials request
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Client Credentials Request", map[string]interface{}{
		"step":               1,
		"from":               "Client",
		"to":                 "Authorization Server",
		"grant_type":         "client_credentials",
		"client_id":          clientID,
		"client_auth_method": clientAuthMethod,
		"requested_scope":    scope,
		"requested_scopes":   strings.Fields(scope),
		"client_assertion":   assertion,
	}, []lookingglass.Annotation{
		{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "Client Credentials Flow",
			Description: "Machine-to-machine authentication without a user context. The client authenticates using its own credentials.",
			Reference:   "RFC 6749 Section 4.4",
		},
		{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "JWT Client Authentication",
			Description: "A registered public key verifies the client-signed assertion at the token endpoint.",
			Reference:   "RFC 7523 Section 2.2",
		},
	}...)

	// Validate client
	var client *models.Client
	var assertionDetails *validatedClientAssertion
	var err error
	if hasAssertionAuth {
		if assertionType != clientAssertionType {
			err = assertionError("unsupported_client_assertion_type")
		} else {
			client, assertionDetails, err = p.AuthenticatePrivateKeyJWTWithAudiences(
				r.Context(),
				clientID,
				assertion,
				[]string{strings.TrimRight(p.baseURL, "/") + "/oauth2/token"},
			)
		}
	} else {
		client, err = p.mockIdP.ValidateClient(clientID, clientSecret)
	}
	if err != nil {
		var infrastructureErr *clientAssertionInfrastructureError
		if errors.As(err, &infrastructureErr) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Infrastructure Failed", map[string]interface{}{
				"client_id":          clientID,
				"error":              "server_error",
				"reason":             "replay_store_unavailable",
				"client_auth_method": clientAuthMethod,
			}, lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "Replay Protection Unavailable",
				Description: "The authorization server failed closed because it could not reserve the assertion identifier atomically.",
				Reference:   "OpenID Connect Core 1.0 Section 9",
			})
			writeOAuth2ErrorStatus(w, http.StatusInternalServerError, "server_error", "Client authentication is temporarily unavailable", "")
			return
		}
		internalReason := "invalid_credentials"
		externalDescription := "Client authentication failed"
		if hasAssertionAuth {
			internalReason = clientAssertionFailureReason(err)
			externalDescription = "client assertion validation failed"
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
			"client_id":          clientID,
			"error":              "invalid_client",
			"reason":             internalReason,
			"client_auth_method": clientAuthMethod,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Client Authentication Rejected",
			Description: "Detailed validation reasons remain internal; the OAuth response is deliberately generic.",
			Reference:   "RFC 7523 Section 3.2",
		})
		writeInvalidClient(w, r, externalDescription)
		return
	}

	if assertionDetails != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "Client Assertion Signature Verified", map[string]interface{}{
			"client_id": clientID,
			"alg":       assertionDetails.algorithm,
			"kid":       assertionDetails.keyID,
			"jti":       assertionDetails.jti,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "JWT Signature Validation",
			Description: "The authorization server verified the assertion with the client's registered public key.",
			Reference:   "RFC 7523 Section 3",
		})
	}

	p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Client Authenticated", map[string]interface{}{
		"client_id":                     clientID,
		"client_name":                   client.Name,
		"client_auth_method":            clientAuthMethod,
		"client_authentication_methods": []string{clientAuthMethod},
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

	// Validate requested scopes against client's registered scopes (RFC 6749 Section 3.3)
	// "If the client omits the scope parameter when requesting authorization, the
	// authorization server MUST either process the request using a pre-defined default
	// value, or fail the request indicating an invalid scope."
	requestedScopes := strings.Fields(scope)
	if len(requestedScopes) > 0 {
		allowedScopes := make(map[string]bool)
		for _, s := range client.Scopes {
			allowedScopes[s] = true
		}
		var grantedScopes []string
		for _, s := range requestedScopes {
			if allowedScopes[s] {
				grantedScopes = append(grantedScopes, s)
			}
		}
		if len(grantedScopes) == 0 {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Scope", map[string]interface{}{
				"requested_scopes": requestedScopes,
				"allowed_scopes":   client.Scopes,
			})
			writeOAuth2Error(w, "invalid_scope", "None of the requested scopes are permitted for this client", "")
			return
		}
		if len(grantedScopes) < len(requestedScopes) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Scope Narrowed", map[string]interface{}{
				"requested_scopes": requestedScopes,
				"granted_scopes":   grantedScopes,
			}, lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "Scope Narrowing",
				Description: "The authorization server reduced the granted scopes to only those the client is permitted to use.",
				Reference:   "RFC 6749 Section 3.3",
			})
		}
		scope = strings.Join(grantedScopes, " ")
	} else {
		// No scope requested — use client's registered scopes as default (RFC 6749 Section 3.3)
		scope = strings.Join(client.Scopes, " ")
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Default Scope Applied", map[string]interface{}{
			"default_scopes": client.Scopes,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "Default Scope",
			Description: "No scope requested; using client's registered scopes as default.",
			Reference:   "RFC 6749 Section 3.3",
		})
	}

	// Issue access token (no refresh token for client credentials)
	jwtService := p.mockIdP.JWTService()
	accessTokenClaims := map[string]interface{}{
		"client_name": client.Name,
	}
	if dpopJKT != "" {
		// RFC 9449 Section 4.1: bind the token to the presented proof key.
		accessTokenClaims = dpop.WithCnfJKT(accessTokenClaims, dpopJKT)
	}
	// RFC 7519 Section 4.1.3: "Each principal intended to process the JWT
	// MUST identify itself with a value in the audience claim." The
	// principal that processes this access token is the protected resource,
	// so the audience is the resource's own identifier and never the client.
	audience, audienceOK := p.tokenAudienceOrError(w, sessionID, r.Form["resource"], scope)
	if !audienceOK {
		return
	}
	ttl := time.Hour
	expiresIn := 3600
	if audience == p.ssfResourceAudience() {
		ttl = 15 * time.Minute
		expiresIn = 900
	}
	accessToken, err := jwtService.CreateAccessToken(crypto.AccessToken{
		Issuer: p.issuer(),
		// RFC 9068 Section 2.2: with no resource owner in the grant, sub
		// "SHOULD correspond to an identifier the authorization server uses
		// to indicate the client application." client.ID is the
		// authenticated client; a private_key_jwt request may omit the
		// client_id form parameter (RFC 7523 Section 3).
		Subject:  client.ID,
		Audience: audience,
		ClientID: client.ID,
		Scope:    scope,
		Lifetime: ttl,
		Claims:   accessTokenClaims,
	})
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Token Generation Failed", map[string]interface{}{
			"error": err.Error(),
		})
		// server_error is an internal failure, not a client error — use HTTP 500
		writeOAuth2ErrorStatus(w, http.StatusInternalServerError, "server_error", "Failed to create access token", "")
		return
	}

	tokenType := dpop.TokenType(dpopJKT)
	tokenResponse := models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiresIn,
		Scope:       scope,
	}

	// Emit token issued event
	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Access Token Issued", map[string]interface{}{
		"step":              2,
		"from":              "Authorization Server",
		"to":                "Client",
		"access_token":      tokenResponse.AccessToken,
		"token_type":        tokenType,
		"expires_in":        expiresIn,
		"scope":             scope,
		"scopes":            strings.Fields(scope),
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
	clientID, clientSecret, clientAuthMethod, multipleAuthMethods := presentedClientPassword(r)

	// Emit introspection request
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Token Introspection Request", map[string]interface{}{
		"endpoint":           "/oauth2/introspect",
		"client_id":          clientID,
		"client_auth_method": clientAuthMethod,
		"token":              token,
		"token_type_hint":    tokenTypeHint,
		"token_length":       len(token),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Introspection",
		Description: "Allows resource servers to query the authorization server about the current state and metadata of a token",
		Reference:   "RFC 7662",
	})

	if multipleAuthMethods {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Introspection Refused: Two Client Authentication Methods", map[string]interface{}{
			"error":                 "invalid_request",
			"client_id":             clientID,
			"basic_present":         true,
			"client_secret_present": true,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "One Authentication Method Per Request",
			Description: `"The client MUST NOT use more than one authentication method in each request." This request carried HTTP Basic credentials and a client_secret in the body.`,
			Severity:    "warning",
			Reference:   "RFC 6749 Section 2.3",
		})
		writeOAuth2Error(w, "invalid_request",
			"A client MUST NOT use more than one authentication method in each request (RFC 6749 Section 2.3)", "")
		return
	}

	caller, refusal := p.authenticateIntrospectionCaller(clientID, clientSecret, clientAuthMethod)
	if refusal != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, refusal.title, map[string]interface{}{
			"error":              "invalid_client",
			"reason":             refusal.reason,
			"client_id":          clientID,
			"client_auth_method": clientAuthMethod,
		}, refusal.annotations...)
		// RFC 7662 Section 2.3: "If the protected resource uses OAuth 2.0
		// client credentials to authenticate to the introspection endpoint
		// and its credentials are invalid, the authorization server responds
		// with an HTTP 401 (Unauthorized) as described in Section 5.2 of
		// OAuth 2.0 [RFC6749]." And for a bearer token that "does not
		// contain sufficient privileges or is otherwise invalid for this
		// request, the authorization server responds with an HTTP 401 code
		// as described in Section 3 of OAuth 2.0 Bearer Token Usage
		// [RFC6750]", which is where the Bearer challenge gets its "error"
		// attribute. A request with no client credentials and no
		// Authorization header follows RFC 6749 Section 5.2 as it stands.
		if clientAuthMethod == "none" && strings.TrimSpace(r.Header.Get("Authorization")) == "" {
			writeOAuth2Error(w, "invalid_client", refusal.description, "")
		} else {
			writeInvalidClientUnauthorized(w, r, refusal.description, "invalid_token")
		}
		return
	}

	// Validate the token
	jwtService := p.mockIdP.JWTService()
	claims, err := jwtService.ValidateToken(token)
	if err != nil {
		// Token is not active (invalid or expired)
		p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Token Inactive", map[string]interface{}{
			"active":          false,
			"reason":          err.Error(),
			"token":           token,
			"token_type_hint": tokenTypeHint,
			"token_length":    len(token),
		})
		writeJSON(w, http.StatusOK, models.IntrospectionResponse{Active: false})
		return
	}

	// Check if token has been revoked per RFC 7009
	if p.mockIdP.IsTokenRevoked(token) {
		p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Token Revoked", map[string]interface{}{
			"active":          false,
			"reason":          "Token has been revoked per RFC 7009",
			"token":           token,
			"token_type_hint": tokenTypeHint,
			"token_length":    len(token),
		})
		writeJSON(w, http.StatusOK, models.IntrospectionResponse{Active: false})
		return
	}

	// RFC 7662 Section 4: "If the token can be used only at certain resource
	// servers, the authorization server MUST determine whether or not the
	// token can be used at the resource server making the introspection
	// call." Every access token is audience-restricted, so the caller learns
	// about a token only when it is the client the token was issued to or a
	// resource server the token's aud names. Section 2.2: when "the protected
	// resource is not allowed to introspect this particular token, then the
	// authorization server MUST return an introspection response with the
	// "active" field set to "false"", and it "SHOULD NOT include any
	// additional information about an inactive token, including why the
	// token is inactive."
	tokenClientID, _ := claims["client_id"].(string)
	callerResource := p.protectedResourceOf(caller)
	issuedToCaller := tokenClientID != "" && tokenClientID == caller.ID
	usableAtCaller := callerResource != "" && crypto.AudienceContains(claims["aud"], callerResource)
	if !issuedToCaller && !usableAtCaller {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Introspection Refused For This Caller", map[string]interface{}{
			"active":           false,
			"caller":           caller.ID,
			"caller_resource":  callerResource,
			"token_client_id":  tokenClientID,
			"token_aud":        claims["aud"],
			"token":            token,
			"token_type_hint":  tokenTypeHint,
			"response_reveals": "active: false only",
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Introspection Is Limited To The Token's Parties",
			Description: "The authorization server answers active: true only to the client the token was issued to, or to a resource server the token's aud names. Any other caller is told the token is not active and nothing else.",
			Severity:    "warning",
			Reference:   "RFC 7662 Section 4",
		})
		writeJSON(w, http.StatusOK, models.IntrospectionResponse{Active: false})
		return
	}

	// Build introspection response. RFC 9449 Section 6.2: for a DPoP-bound
	// access token, convey the cnf.jkt confirmation as a top-level member so
	// the resource server can validate the DPoP binding itself -- the
	// authorization server does not check a DPoP proof at this endpoint --
	// and if token_type is included it MUST read DPoP, not Bearer.
	response := models.IntrospectionResponse{
		Active:    true,
		TokenType: "Bearer",
	}
	if cnfClaim, ok := claims["cnf"].(map[string]interface{}); ok {
		if jkt, ok := cnfClaim["jkt"].(string); ok && jkt != "" {
			response.TokenType = dpop.TokenType(jkt)
			response.Cnf = &models.IntrospectionCnf{JKT: jkt}
		}
	}

	if scope, ok := claims["scope"].(string); ok {
		response.Scope = scope
	}
	if sub, ok := claims["sub"].(string); ok {
		response.Sub = sub
		response.Username = sub
	}
	// RFC 7662 Section 2.2: aud is the "identifier or list of string
	// identifiers representing the intended audience for this token" and
	// client_id is the "Client identifier for the OAuth 2.0 client that
	// requested this token." Each is reported from its own claim.
	if audClaim, ok := claims["aud"].(string); ok {
		response.Aud = audClaim
	}
	response.ClientID = tokenClientID
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
	eventData := map[string]interface{}{
		"active":     true,
		"token_type": response.TokenType,
		"sub":        response.Sub,
		"username":   response.Username,
		"client_id":  response.ClientID,
		"scope":      response.Scope,
		"scopes":     strings.Fields(response.Scope),
		"exp":        response.Exp,
		"iat":        response.Iat,
		"nbf":        response.Nbf,
		"aud":        response.Aud,
		"iss":        response.Iss,
		"jti":        response.Jti,
	}
	if response.Cnf != nil {
		eventData["cnf"] = map[string]interface{}{"jkt": response.Cnf.JKT}
	}
	p.emitEvent(sessionID, lookingglass.EventTypeTokenValidated, "Token Introspection Result", eventData, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Token Active",
		Description: "The token has been validated and is currently active",
		Reference:   "RFC 7662 Section 2.2",
	})

	writeJSON(w, http.StatusOK, response)
}

// introspectionRefusal is why a caller was not let into the introspection
// endpoint: the reason and annotations go to Looking Glass, the description
// goes into the invalid_client response.
type introspectionRefusal struct {
	reason      string
	title       string
	description string
	annotations []lookingglass.Annotation
}

// authenticateIntrospectionCaller authenticates the caller of the
// introspection endpoint. RFC 7662 Section 2.1: "To prevent token scanning
// attacks, the endpoint MUST also require some form of authorization to
// access this endpoint, such as client authentication as described in OAuth
// 2.0 [RFC6749] or a separate OAuth 2.0 access token". Section 4: "the
// authorization server MUST require authentication of protected resources
// that need to access the introspection endpoint".
//
// This server authorizes the call by client authentication with a client
// password (RFC 6749 Section 2.3.1). A public client is refused: RFC 6749
// Section 2.1 defines it as "incapable of secure client authentication via
// any other means", and Section 2.3 says "the authorization server MUST NOT
// rely on public client authentication for the purpose of identifying the
// client", so a public client_id on its own authorizes nothing. The token
// under introspection is not a credential for introspecting itself either.
func (p *Plugin) authenticateIntrospectionCaller(clientID, clientSecret, clientAuthMethod string) (*models.Client, *introspectionRefusal) {
	requiresAuthorization := lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Introspection Requires Authorization",
		Description: `"To prevent token scanning attacks, the endpoint MUST also require some form of authorization to access this endpoint, such as client authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth 2.0 access token". This server authorizes the call by authenticating a confidential client or resource server registration.`,
		Severity:    "warning",
		Reference:   "RFC 7662 Section 2.1",
	}

	if clientID == "" {
		return nil, &introspectionRefusal{
			reason:      "no_client_authentication",
			title:       "Introspection Refused: No Client Authentication",
			description: "Client authentication required",
			annotations: []lookingglass.Annotation{requiresAuthorization},
		}
	}

	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		return nil, &introspectionRefusal{
			reason:      "unknown_client",
			title:       "Introspection Refused: Unknown Client",
			description: "Unknown client",
			annotations: []lookingglass.Annotation{requiresAuthorization},
		}
	}

	if client.Public {
		return nil, &introspectionRefusal{
			reason:      "public_client",
			title:       "Introspection Refused: Public Client",
			description: "A public client cannot authenticate, so it is not authorized to call the introspection endpoint",
			annotations: []lookingglass.Annotation{requiresAuthorization, {
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "A Public Client Cannot Be Authenticated",
				Description: `"The authorization server MAY establish a client authentication method with public clients. However, the authorization server MUST NOT rely on public client authentication for the purpose of identifying the client." Anyone can send a public client's client_id, so it does not show who is calling.`,
				Severity:    "warning",
				Reference:   "RFC 6749 Section 2.3",
			}},
		}
	}

	if clientAuthMethod == "none" {
		return nil, &introspectionRefusal{
			reason:      "no_client_authentication",
			title:       "Introspection Refused: No Client Authentication",
			description: "Client authentication required",
			annotations: []lookingglass.Annotation{requiresAuthorization},
		}
	}

	if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
		return nil, &introspectionRefusal{
			reason:      "invalid_credentials",
			title:       "Introspection Refused: Client Authentication Failed",
			description: "Client authentication failed",
			annotations: []lookingglass.Annotation{requiresAuthorization, {
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "Invalid Client Credentials Are Answered With 401",
				Description: `"If the protected resource uses OAuth 2.0 client credentials to authenticate to the introspection endpoint and its credentials are invalid, the authorization server responds with an HTTP 401 (Unauthorized) as described in Section 5.2 of OAuth 2.0 [RFC6749]."`,
				Severity:    "warning",
				Reference:   "RFC 7662 Section 2.3",
			}},
		}
	}

	return client, nil
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
	clientID, clientSecret, clientAuthMethod, multipleAuthMethods := presentedClientPassword(r)
	// RFC 7523 Section 2.2: a client registered for private_key_jwt
	// authenticates with client_assertion_type and client_assertion.
	assertionTypePresent := r.PostForm.Has("client_assertion_type")
	assertionPresent := r.PostForm.Has("client_assertion")
	assertion := r.PostForm.Get("client_assertion")
	usesAssertion := assertionTypePresent || assertionPresent
	if usesAssertion {
		multipleAuthMethods = multipleAuthMethods || clientAuthMethod != "none"
		clientAuthMethod = "private_key_jwt"
	}

	// Emit revocation request
	request := map[string]interface{}{
		"endpoint":           "/oauth2/revoke",
		"client_id":          clientID,
		"client_auth_method": clientAuthMethod,
		"token":              token,
		"token_type_hint":    tokenTypeHint,
		"token_length":       len(token),
	}
	if usesAssertion {
		request["client_assertion"] = assertion
	}
	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Token Revocation Request", request, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Token Revocation",
		Description: "Allows clients to notify the authorization server that a previously issued token is no longer needed",
		Reference:   "RFC 7009",
	})

	if assertionTypePresent != assertionPresent {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Incomplete Client Assertion Authentication", map[string]interface{}{
			"error":                         "invalid_request",
			"reason":                        "client_assertion_parameter_pair_required",
			"client_assertion_type_present": assertionTypePresent,
			"client_assertion_present":      assertionPresent,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "JWT Client Authentication Parameters",
			Description: "client_assertion_type and client_assertion are used together for JWT client authentication.",
			Reference:   "RFC 7523 Section 2.2",
		})
		writeOAuth2Error(w, "invalid_request", "client_assertion_type and client_assertion must be provided together", "")
		return
	}

	if multipleAuthMethods {
		_, _, basicPresent := r.BasicAuth()
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Revocation Refused: More Than One Client Authentication Method", map[string]interface{}{
			"error":                    "invalid_request",
			"client_id":                clientID,
			"basic_present":            basicPresent,
			"client_secret_present":    r.PostForm.Has("client_secret"),
			"client_assertion_present": usesAssertion,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "One Authentication Method Per Request",
			Description: `"The client MUST NOT use more than one authentication method in each request." This request carried more than one of HTTP Basic credentials, a client_secret in the body and a client assertion.`,
			Severity:    "warning",
			Reference:   "RFC 6749 Section 2.3",
		})
		writeOAuth2Error(w, "invalid_request",
			"A client MUST NOT use more than one authentication method in each request (RFC 6749 Section 2.3)", "")
		return
	}

	// RFC 7009 Section 2.1: "The client also includes its authentication
	// credentials as described in Section 2.3. of [RFC6749]", and "The
	// authorization server first validates the client credentials (in case
	// of a confidential client)". A public client has none and identifies
	// itself with its client_id. Section 2.2.1: "The error presentation
	// conforms to the definition in Section 5.2 of [RFC6749]."
	var client *models.Client
	if usesAssertion {
		var authenticated bool
		if client, authenticated = p.authenticateRevocationAssertion(w, r, sessionID, clientID, assertion); !authenticated {
			return
		}
		clientID = client.ID
	} else {
		invalidClient := lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Client Authentication Failed",
			Description: `"If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client." Credentials sent in the request body are answered with 400.`,
			Severity:    "warning",
			Reference:   "RFC 6749 Section 5.2",
		}
		var exists bool
		client, exists = p.mockIdP.GetClient(clientID)
		if !exists {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Revocation Refused: Unknown Client", map[string]interface{}{
				"error":              "invalid_client",
				"client_id":          clientID,
				"client_auth_method": clientAuthMethod,
			}, invalidClient)
			writeInvalidClient(w, r, "Unknown client")
			return
		}

		if !client.Public {
			if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
				p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Revocation Refused: Client Authentication Failed", map[string]interface{}{
					"error":              "invalid_client",
					"client_id":          clientID,
					"client_auth_method": clientAuthMethod,
				}, invalidClient)
				writeInvalidClient(w, r, "Client authentication failed")
				return
			}
		}
	}

	// RFC 7009 Section 2.2: "The authorization server responds with HTTP
	// status code 200 if the token has been revoked successfully or if the
	// client submitted an invalid token." A string that is not a currently
	// valid token of this server at all is such a token: there is nothing to
	// revoke and nothing changes.
	tokenClientID, tokenType, live := p.revocableToken(token)
	if !live {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Nothing To Revoke: Invalid Token", map[string]interface{}{
			"token":              token,
			"token_type_hint":    tokenTypeHint,
			"client_id":          clientID,
			"client_auth_method": clientAuthMethod,
			"revoked":            false,
			"status":             http.StatusOK,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "An Invalid Token Is Answered With 200",
			Description: `"The authorization server responds with HTTP status code 200 if the token has been revoked successfully or if the client submitted an invalid token." The submitted value is not a live refresh token or access token of this authorization server, so nothing was revoked.`,
			Reference:   "RFC 7009 Section 2.2",
		})
		w.WriteHeader(http.StatusOK)
		return
	}

	// RFC 7009 Section 2.2.1: "unsupported_token_type: The authorization
	// server does not support the revocation of the presented token type.
	// That is, the client tried to revoke an access token on a server not
	// supporting this feature." This server revokes refresh tokens and
	// access tokens. A valid JWT of its key that is neither, an ID Token for
	// example, is a presented token type it does not revoke.
	if tokenType == "" {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Revocation Refused: Unsupported Token Type", map[string]interface{}{
			"error":              "unsupported_token_type",
			"client_id":          clientID,
			"client_auth_method": clientAuthMethod,
			"token":              token,
			"token_type_hint":    tokenTypeHint,
			"revoked":            false,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Not A Refresh Token Or An Access Token",
			Description: `"unsupported_token_type: The authorization server does not support the revocation of the presented token type. That is, the client tried to revoke an access token on a server not supporting this feature." This server revokes refresh tokens and access tokens. The submitted value is a valid JWT signed with its key that it issued as neither; an ID Token is such a JWT. It is not revoked.`,
			Severity:    "warning",
			Reference:   "RFC 7009 Section 2.2.1",
		})
		writeOAuth2Error(w, "unsupported_token_type",
			"The authorization server does not support the revocation of the presented token type (RFC 7009 Section 2.2.1)", "")
		return
	}

	// RFC 7009 Section 2.1: the authorization server "then verifies whether
	// the token was issued to the client making the revocation request. If
	// this validation fails, the request is refused and the client is
	// informed of the error by the authorization server as described below."
	// RFC 7009 names no error code for that refusal. Section 2.2.1 says only
	// that "The error presentation conforms to the definition in Section 5.2
	// of [RFC6749]", and there invalid_grant is defined as: "The provided
	// authorization grant (e.g., authorization code, resource owner
	// credentials) or refresh token is invalid, expired, revoked, does not
	// match the redirection URI used in the authorization request, or was
	// issued to another client." Those words cover a refresh token. No
	// Section 5.2 code covers an access token by its words; invalid_grant is
	// used for it too, as the only code that names the condition.
	if tokenClientID != client.ID {
		title := "Revocation Refused: Token Issued To Another Client"
		validation := lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Only The Token's Client May Revoke It",
			Description: `"The authorization server first validates the client credentials (in case of a confidential client) and then verifies whether the token was issued to the client making the revocation request. If this validation fails, the request is refused and the client is informed of the error by the authorization server as described below." The token stays valid.`,
			Severity:    "warning",
			Reference:   "RFC 7009 Section 2.1",
		}
		errorCode := lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "Why invalid_grant",
			Description: `RFC 7009 names no error code for this refusal: "The error presentation conforms to the definition in Section 5.2 of [RFC6749]." There, invalid_grant is: "The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client." `,
			Reference:   "RFC 6749 Section 5.2",
		}
		switch {
		case tokenClientID == "":
			// An OID4VCI Pre-Authorized Code Token Request may carry no
			// client_id, so the access token it yields has none either.
			title = "Revocation Refused: Token Issued To No Identified Client"
			validation.Title = "No Client To Verify The Request Against"
			validation.Description += " This access token has no client_id claim: it was issued without client identification, so the server cannot verify that it was issued to the client making this request."
			errorCode.Description += "No Section 5.2 code covers this case by its words. The response uses invalid_grant, the code this server gives every request that fails the Section 2.1 verification."
		case tokenType == "refresh_token":
			errorCode.Description += "This token is a refresh token, which those words cover."
		default:
			errorCode.Description += "This token is an access token. No Section 5.2 code covers an access token by its words; invalid_grant is the only one that names the condition."
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, title, map[string]interface{}{
			"error":              "invalid_grant",
			"client_id":          clientID,
			"client_auth_method": clientAuthMethod,
			"token_client_id":    tokenClientID,
			"token_type":         tokenType,
			"token":              token,
			"token_type_hint":    tokenTypeHint,
			"revoked":            false,
		}, validation, errorCode)
		writeOAuth2Error(w, "invalid_grant",
			"The token was not issued to the client making the revocation request (RFC 7009 Section 2.1)", "")
		return
	}

	revoked := map[string]interface{}{
		"token":              token,
		"token_type":         tokenType,
		"token_type_hint":    tokenTypeHint,
		"client_id":          clientID,
		"client_auth_method": clientAuthMethod,
		"revoked":            true,
	}
	annotations := []lookingglass.Annotation{{
		Type:        lookingglass.AnnotationTypeBestPractice,
		Title:       "Token Revoked By The Client It Was Issued To",
		Description: `The token was issued to this client, so it is revoked: "The invalidation takes place immediately, and the token cannot be used again after the revocation." The server found the token type itself, so token_type_hint was not needed.`,
		Reference:   "RFC 7009 Section 2.1",
	}}
	if tokenType == "refresh_token" {
		revoked["access_token_jtis_revoked"] = p.mockIdP.RevokeRefreshToken(token)
		annotations = append(annotations, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "The Grant's Access Tokens Are Revoked Too",
			Description: `"If the particular token is a refresh token and the authorization server supports the revocation of access tokens, then the authorization server SHOULD also invalidate all access tokens based on the same authorization grant". access_token_jtis_revoked lists the jti of each unexpired access token issued under this grant, through this refresh token and the ones it was rotated from.`,
			Reference:   "RFC 7009 Section 2.1",
		})
	} else {
		p.mockIdP.RevokeAccessToken(token)
	}
	p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Token Revoked", revoked, annotations...)

	w.WriteHeader(http.StatusOK)
}

// authenticateRevocationAssertion authenticates the client of a revocation
// request from its private_key_jwt assertion (RFC 7523 Section 2.2), with the
// checks the token endpoint applies. On failure it writes the response and
// reports false.
func (p *Plugin) authenticateRevocationAssertion(w http.ResponseWriter, r *http.Request, sessionID, clientID, assertion string) (*models.Client, bool) {
	var client *models.Client
	var assertionDetails *validatedClientAssertion
	var err error
	if r.PostForm.Get("client_assertion_type") != clientAssertionType {
		err = assertionError("unsupported_client_assertion_type")
	} else {
		client, assertionDetails, err = p.AuthenticatePrivateKeyJWTWithAudiences(r.Context(), clientID, assertion, p.revocationAssertionAudiences())
	}

	var infrastructureErr *clientAssertionInfrastructureError
	if errors.As(err, &infrastructureErr) {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Infrastructure Failed", map[string]interface{}{
			"client_id":          clientID,
			"error":              "server_error",
			"reason":             "replay_store_unavailable",
			"client_auth_method": "private_key_jwt",
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "The Token Was Not Revoked",
			Description: `The authorization server failed closed because it could not reserve the assertion identifier atomically. "If the server responds with HTTP status code 503, the client must assume the token still exists and may retry after a reasonable delay."`,
			Severity:    "warning",
			Reference:   "RFC 7009 Section 2.2.1",
		})
		writeOAuth2ErrorStatus(w, http.StatusServiceUnavailable, "server_error", "Client authentication is temporarily unavailable", "")
		return nil, false
	}
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Revocation Refused: Client Authentication Failed", map[string]interface{}{
			"error":              "invalid_client",
			"reason":             clientAssertionFailureReason(err),
			"client_id":          clientID,
			"client_auth_method": "private_key_jwt",
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Client Assertion Rejected",
			Description: `"If the client JWT is not valid, the authorization server constructs an error response as defined in OAuth 2.0 [RFC6749]. The value of the "error" parameter MUST be the "invalid_client" error code." The reason is shown here; the OAuth response is deliberately generic.`,
			Severity:    "warning",
			Reference:   "RFC 7523 Section 3.2",
		})
		writeInvalidClient(w, r, "client assertion validation failed")
		return nil, false
	}

	p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "Client Assertion Signature Verified", map[string]interface{}{
		"client_id": client.ID,
		"alg":       assertionDetails.algorithm,
		"kid":       assertionDetails.keyID,
		"jti":       assertionDetails.jti,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeRFCReference,
		Title:       "JWT Signature Validation",
		Description: "The authorization server verified the assertion with the client's registered public key.",
		Reference:   "RFC 7523 Section 3",
	})
	return client, true
}

// revocationAssertionAudiences are the "aud" values that identify this server
// in a client assertion presented at /oauth2/revoke. RFC 7523 Section 3: the
// JWT MUST contain an "aud" claim "containing a value that identifies the
// authorization server as an intended audience. The token endpoint URL of the
// authorization server MAY be used as a value for an "aud" element". Two
// metadata documents name this endpoint as their revocation_endpoint, so the
// issuer identifier and the token endpoint URL of each are accepted: this
// OAuth 2.0 authorization server and the OpenID Provider on the same Mock IdP.
func (p *Plugin) revocationAssertionAudiences() []string {
	providerIssuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
	return []string{
		p.issuer(),
		p.issuer() + "/token",
		providerIssuer,
		providerIssuer + "/oidc/token",
	}
}

// revocableToken classifies the token of a revocation request. live is false
// for an invalid token in the sense of RFC 7009 Section 2.2: a string that is
// not a currently valid token of this server at all. For a live token,
// tokenType is "refresh_token", "access_token", or empty when the token is a
// valid JWT of this server's key that it issued as neither, and clientID is
// the client it was issued to.
//
// The type is detected without token_type_hint (RFC 7009 Section 2.1: "An
// authorization server MAY ignore this parameter, particularly if it is able
// to detect the token type automatically."). A refresh token is live while
// the Mock IdP stores it. An access token is one the JWT service minted as
// such (crypto.JWTService.IssuedAccessToken), never a JWT that merely lacks
// the marks of something else. An access token may have no client_id claim,
// when it was issued without client identification.
func (p *Plugin) revocableToken(token string) (clientID, tokenType string, live bool) {
	if refreshToken, ok := p.mockIdP.GetRefreshToken(token); ok {
		return refreshToken.ClientID, "refresh_token", true
	}
	claims, isAccessToken, err := p.mockIdP.JWTService().IssuedAccessToken(token)
	if err != nil || claims["type"] == "refresh" {
		// Not this server's token, expired, or a refresh token that was
		// already rotated or revoked.
		return "", "", false
	}
	if !isAccessToken {
		return "", "", true
	}
	clientID, _ = claims["client_id"].(string)
	return clientID, "access_token", true
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
		"clients":        presets,
		"token_endpoint": p.tokenEndpointURL(),
	})
}

// handleCAEPRevokeSubject is a demo RP/OP hook used after a verified CAEP
// session-revoked SET. It is not RFC 7009 (that endpoint consumes a token, not
// an email). Auth is a shared service token, not a Looking Glass session.
func (p *Plugin) handleCAEPRevokeSubject(w http.ResponseWriter, r *http.Request) {
	expected := strings.TrimSpace(os.Getenv("SSF_TO_FEDERATION_TOKEN"))
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(got)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if p.mockIdP == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "idp_unavailable"})
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Email) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	sessions, refresh, access, err := p.mockIdP.RevokeSubjectByEmail(strings.TrimSpace(body.Email))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":                  strings.TrimSpace(body.Email),
		"sessions_deleted":       sessions,
		"refresh_tokens_revoked": refresh,
		"access_tokens_revoked":  access,
	})
}

const implicitLoginSubtitle = "OAuth 2.0 Implicit Grant"

func authorizeRequestAnnotation(responseType string) lookingglass.Annotation {
	if responseType == "token" {
		return lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "OAuth 2.0 Implicit Authorization Request",
			Description: "The client requests an access token in the authorization response. The token is returned in the fragment, not the query string.",
			Reference:   "RFC 6749 Section 4.2.1",
		}
	}
	return lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "OAuth 2.0 Authorization Request",
		Description: "The client redirects the user to the authorization server with required parameters",
		Reference:   "RFC 6749 Section 4.1.1",
	}
}

func authorizeSuccessDescription(responseType string) string {
	if responseType == "token" {
		return "The user has successfully authenticated. An access token will be returned in the redirect fragment. No refresh token is issued."
	}
	return "The user has successfully authenticated. An authorization code will now be issued."
}

func authorizeSuccessReference(responseType string) string {
	if responseType == "token" {
		return "RFC 6749 Section 4.2.2"
	}
	return "RFC 6749 Section 3.1"
}

// beginImplicitAuthorization starts RFC 6749 §4.2 for a public client that
// registered the implicit grant. Confidential clients and clients without the
// grant receive unauthorized_client in the fragment. PKCE is ignored: there
// is no authorization code to bind.
func (p *Plugin) beginImplicitAuthorization(
	w http.ResponseWriter,
	r *http.Request,
	sessionID string,
	client *models.Client,
	redirectURI, scope, state string,
) {
	if client == nil || !client.Public || !clientHasGrant(client, "implicit") {
		clientID := ""
		if client != nil {
			clientID = client.ID
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Implicit Grant Not Allowed", map[string]interface{}{
			"error":     "unauthorized_client",
			"client_id": clientID,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Implicit Grant Is For Public Clients",
			Description: "The implicit grant returns the access token to the browser. Confidential clients must use a back-channel grant.",
			Severity:    "warning",
			Reference:   "RFC 6749 Section 4.2",
		})
		p.redirectAuthorizeFragmentError(w, r, redirectURI, state, "unauthorized_client", "The client is not authorized to use the implicit grant")
		return
	}

	granted, ok := intersectClientScopes(client, scope)
	if !ok {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Scope", map[string]interface{}{
			"requested_scopes": strings.Fields(scope),
			"allowed_scopes":   client.Scopes,
		})
		p.redirectAuthorizeFragmentError(w, r, redirectURI, state, "invalid_scope", "None of the requested scopes are permitted for this client")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Implicit Grant", map[string]interface{}{
		"response_type": "token",
		"client_id":     client.ID,
		"scope":         granted,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Implicit Grant Is Not Recommended",
		Description: "RFC 9700 Section 2.1.2: clients SHOULD NOT use the implicit grant. The access token is exposed to the browser. Prefer authorization code with PKCE.",
		Severity:    "warning",
		Reference:   "RFC 9700 Section 2.1.2",
	})

	loginRequestID := p.storeLoginRequest(loginRequestInfo{
		ClientID:     client.ID,
		RedirectURI:  redirectURI,
		Scope:        granted,
		State:        state,
		ResponseType: "token",
	})

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "User Authentication Required", map[string]interface{}{
		"step":          2,
		"from":          "User",
		"to":            "Authorization Server",
		"client_id":     client.ID,
		"client_name":   client.Name,
		"redirect_uri":  redirectURI,
		"response_type": "token",
		"scope":         granted,
		"scopes":        strings.Fields(granted),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Authorization Endpoint User Authentication",
		Description: "The authorization server authenticates the user before returning an access token in the fragment",
		Reference:   "RFC 6749 Section 4.2.2",
	})

	loginPage := p.generateLoginPage(client.ID, granted, sessionID, client.Name, loginRequestID, implicitLoginSubtitle)
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(loginPage))
}

// completeImplicitGrant issues a bearer access token and redirects to the
// fragment. RFC 6749 §4.2.2: the authorization server MUST NOT issue a refresh
// token. DPoP does not apply: there is no token-endpoint proof to bind.
func (p *Plugin) completeImplicitGrant(
	w http.ResponseWriter,
	r *http.Request,
	sessionID string,
	user *models.User,
	info loginRequestInfo,
) {
	client, exists := p.mockIdP.GetClient(info.ClientID)
	if !exists || !client.Public || !clientHasGrant(client, "implicit") {
		p.redirectAuthorizeFragmentError(w, r, info.RedirectURI, info.State, "unauthorized_client", "The client is not authorized to use the implicit grant")
		return
	}

	// The "resource" parameter, if any, was checked against this scope when
	// the authorization request arrived, so it equals the scope's default.
	audience, rejected := p.defaultResource(info.Scope)
	if rejected != nil {
		p.emitTargetRejected(sessionID, "/oauth2/authorize", nil, info.Scope, rejected)
		p.redirectAuthorizeFragmentError(w, r, info.RedirectURI, info.State, rejected.code, rejected.description)
		return
	}
	tokenResponse, err := p.issueImplicitAccessToken(user.ID, info.ClientID, info.Scope, audience)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Implicit Access Token Failed", map[string]interface{}{
			"error":     err.Error(),
			"client_id": info.ClientID,
		})
		p.redirectAuthorizeFragmentError(w, r, info.RedirectURI, info.State, "server_error", "Failed to issue access token")
		return
	}

	params := url.Values{}
	params.Set("access_token", tokenResponse.AccessToken)
	params.Set("token_type", tokenResponse.TokenType)
	params.Set("expires_in", strconv.Itoa(tokenResponse.ExpiresIn))
	if info.Scope != "" {
		params.Set("scope", info.Scope)
	}
	if info.State != "" {
		params.Set("state", info.State)
	}

	p.emitEvent(sessionID, lookingglass.EventTypeResponseReceived, "Redirecting to Client", map[string]interface{}{
		"redirect_uri":  info.RedirectURI,
		"response_type": "token",
		"response_mode": "fragment",
		"access_token":  tokenResponse.AccessToken,
		"token_type":    tokenResponse.TokenType,
		"expires_in":    tokenResponse.ExpiresIn,
		"scope":         info.Scope,
		"state":         info.State,
		"has_state":     info.State != "",
		"refresh_token": false,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Implicit Access Token Response",
		Description: "The access token is delivered in the URI fragment. The authorization server does not issue a refresh token.",
		Reference:   "RFC 6749 Section 4.2.2",
	})

	p.redirectAuthorizationFragment(w, r, info.RedirectURI, params)
}

// issueImplicitAccessToken creates a real bearer access token and does not
// create or store a refresh token (RFC 6749 §4.2.2).
func (p *Plugin) issueImplicitAccessToken(userID, clientID, scope, audience string) (*models.TokenResponse, error) {
	jwtService := p.mockIdP.JWTService()
	userClaims := p.mockIdP.UserClaims(userID, strings.Fields(scope))
	accessToken, err := jwtService.CreateAccessToken(crypto.AccessToken{
		Issuer:   p.issuer(),
		Subject:  userID,
		Audience: audience,
		ClientID: clientID,
		Scope:    scope,
		Lifetime: time.Hour,
		Claims:   userClaims,
	})
	if err != nil {
		return nil, err
	}
	p.mockIdP.TrackAccessToken(userID, accessToken)
	return &models.TokenResponse{
		AccessToken: accessToken,
		TokenType:   dpop.TokenType(""),
		ExpiresIn:   int(time.Hour / time.Second),
		Scope:       scope,
	}, nil
}

// finishAuthorizeClientError reports an authorization-endpoint error. When the
// client_id and redirect_uri are registered, the error is placed in the
// fragment. Otherwise the response is JSON and is not a redirect.
func (p *Plugin) finishAuthorizeClientError(
	w http.ResponseWriter,
	r *http.Request,
	clientID, redirectURI, state, errorCode, description string,
) {
	if redirect, ok := p.registeredAuthorizeRedirect(clientID, redirectURI); ok {
		p.redirectAuthorizeFragmentError(w, r, redirect, state, errorCode, description)
		return
	}
	writeOAuth2Error(w, errorCode, description, "")
}

func (p *Plugin) registeredAuthorizeRedirect(clientID, redirectURI string) (string, bool) {
	if strings.TrimSpace(clientID) == "" || strings.TrimSpace(redirectURI) == "" {
		return "", false
	}
	if _, exists := p.mockIdP.GetClient(clientID); !exists {
		return "", false
	}
	normalized, err := p.mockIdP.NormalizeRedirectURI(clientID, redirectURI)
	if err != nil {
		return "", false
	}
	return normalized, true
}

// redirectAuthorizeQueryError returns an authorization code flow error to the
// client in the query component of the redirection URI (RFC 6749 Section
// 4.1.2.1), with iss when this server's metadata issuer is valid (RFC 9207).
func (p *Plugin) redirectAuthorizeQueryError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI, state, errorCode, description string,
) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuth2Error(w, errorCode, description, state)
		return
	}
	q := redirectURL.Query()
	q.Set("error", errorCode)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	if issuer, err := authorizationServerMetadataIssuer(p.baseURL); err == nil {
		q.Set("iss", issuer)
	}
	redirectURL.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (p *Plugin) redirectAuthorizeFragmentError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI, state, errorCode, description string,
) {
	params := url.Values{}
	params.Set("error", errorCode)
	if description != "" {
		params.Set("error_description", description)
	}
	if state != "" {
		params.Set("state", state)
	}
	p.redirectAuthorizationFragment(w, r, redirectURI, params)
}

// redirectAuthorizationFragment sends an OAuth authorization response in the
// fragment (RFC 6749 §4.2.2). iss is included when the authorization server
// metadata issuer is valid (RFC 9207). Cache-Control and Pragma match the
// token-response practice in RFC 6749 §5.1.
func (p *Plugin) redirectAuthorizationFragment(w http.ResponseWriter, r *http.Request, redirectURI string, params url.Values) {
	values := url.Values{}
	for key, items := range params {
		for _, item := range items {
			values.Add(key, item)
		}
	}
	if issuer, err := authorizationServerMetadataIssuer(p.baseURL); err == nil {
		values.Set("iss", issuer)
	}
	location := redirectURI
	if hash := strings.Index(location, "#"); hash >= 0 {
		location = location[:hash]
	}
	location += "#" + values.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Location", location)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusFound)
	_, _ = w.Write([]byte(`<a href="` + html.EscapeString(location) + `">Found</a>.` + "\n"))
}

// issueTokens creates access token and refresh token. dpopJKT, when
// non-empty, binds the access token to that DPoP key (RFC 9449 Sections 4.1
// and 5): it carries a cnf.jkt claim and the response's token_type is DPoP.
//
// bindRefreshToken additionally binds the refresh token to the same key.
// Callers MUST pass true only for a public client: RFC 9449 Section 5 draws
// this distinction explicitly -- "Refresh tokens issued to confidential
// clients ... are not bound to the DPoP proof public key because they are
// already sender-constrained with a different existing mechanism" (client
// authentication). Binding a confidential client's refresh token anyway
// would remove that mechanism's documented benefit (client credential
// rotation without invalidating the refresh token) for no security gain,
// since the token is already sender-constrained.
//
// audience is the protected resource the access token is for, from
// tokenAudience. The token follows RFC 9068: its "aud" is that resource, its
// "client_id" is the client, and its "iss" is this authorization server.
//
// rotatedOut is the refresh token this request redeemed, or nil for the first
// tokens of an authorization grant. The new access token joins the grant's
// access tokens, which revoking the refresh token invalidates (RFC 7009
// Section 2.1).
func (p *Plugin) issueTokens(userID, clientID, scope, audience, dpopJKT string, bindRefreshToken bool, rotatedOut *models.RefreshToken) (*models.TokenResponse, error) {
	jwtService := p.mockIdP.JWTService()

	// Get user claims
	scopes := strings.Split(scope, " ")
	userClaims := p.mockIdP.UserClaims(userID, scopes)
	if dpopJKT != "" {
		userClaims = dpop.WithCnfJKT(userClaims, dpopJKT)
	}

	// Create access token
	accessToken, err := jwtService.CreateAccessToken(crypto.AccessToken{
		Issuer:   p.issuer(),
		Subject:  userID,
		Audience: audience,
		ClientID: clientID,
		Scope:    scope,
		Lifetime: time.Hour,
		Claims:   userClaims,
	})
	if err != nil {
		return nil, err
	}
	p.mockIdP.TrackAccessToken(userID, accessToken)

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
	p.mockIdP.StoreRefreshToken(refreshToken, clientID, userID, scope, time.Now(), time.Now().Add(7*24*time.Hour))
	if dpopJKT != "" && bindRefreshToken {
		p.mockIdP.BindRefreshTokenKey(refreshToken, dpopJKT)
	}
	p.mockIdP.RecordGrantTokens(accessToken, refreshToken, rotatedOut)

	response := &models.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    dpop.TokenType(dpopJKT),
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

// protectedResourceOf returns the resource identifier a registration serves
// as a resource server, or "" for a registration that is only a client. The
// SSF Transmitter is the one resource server that calls the introspection
// endpoint: on the split SSF image it has no access to this server's
// revocation list. /oauth2/resource, UserInfo and the Credential Issuer run
// in this process and validate tokens locally.
func (p *Plugin) protectedResourceOf(client *models.Client) string {
	if client != nil && client.ID == mockidp.SSFTransmitterClientID {
		return p.ssfResourceAudience()
	}
	return ""
}

func (p *Plugin) ssfResourceAudience() string {
	if v := strings.TrimSpace(os.Getenv("SSF_RESOURCE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(p.baseURL, "/")
}

// RFC 6749 Section 5.2 error URIs - links to relevant documentation
var oauth2ErrorURIs = map[string]string{
	"invalid_request":           "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_client":            "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_grant":             "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"unsupported_token_type":    "https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1",
	"unauthorized_client":       "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"unsupported_grant_type":    "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_scope":             "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
	"invalid_target":            "https://datatracker.ietf.org/doc/html/rfc8707#section-2",
	"unsupported_response_type": "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
	"access_denied":             "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5",
	"authorization_pending":     "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5",
	"slow_down":                 "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5",
	"expired_token":             "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5",
	"server_error":              "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
	"temporarily_unavailable":   "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1",
	dpop.ErrorInvalidDPoPProof:  "https://datatracker.ietf.org/doc/html/rfc9449#section-5",
	dpop.ErrorUseDPoPNonce:      "https://datatracker.ietf.org/doc/html/rfc9449#section-8",
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

// writeOAuth2ErrorStatus writes an OAuth2-compliant error response with a specific HTTP status code.
// Use this instead of writeOAuth2Error when the error requires a non-400 status:
//   - 401 for invalid_client when Authorization header was used (RFC 6749 Section 5.2)
//   - 500 for server_error (internal failures, not client errors)
func writeOAuth2ErrorStatus(w http.ResponseWriter, status int, errorCode, description, state string) {
	response := map[string]string{
		"error":             errorCode,
		"error_description": description,
	}
	if defaultURI, exists := oauth2ErrorURIs[errorCode]; exists {
		response["error_uri"] = defaultURI
	}
	if state != "" {
		response["state"] = state
	}
	writeJSON(w, status, response)
}

// writeInvalidClient answers a failed client authentication. RFC 6749
// Section 5.2: "If the client attempted to authenticate via the
// "Authorization" request header field, the authorization server MUST respond
// with an HTTP 401 (Unauthorized) status code and include the
// "WWW-Authenticate" response header field matching the authentication scheme
// used by the client." A request with no Authorization header gets the
// default 400.
func writeInvalidClient(w http.ResponseWriter, r *http.Request, description string) {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		writeOAuth2Error(w, "invalid_client", description, "")
		return
	}
	writeInvalidClientUnauthorized(w, r, description, "")
}

// writeInvalidClientUnauthorized answers a failed client authentication with
// 401 and one challenge per scheme, each in its own WWW-Authenticate field.
//
// The Basic challenge is always sent, and first. RFC 6749 Section 5.2: the
// authorization server "MAY return an HTTP 401 (Unauthorized) status code to
// indicate which HTTP authentication schemes are supported", and HTTP Basic
// is the scheme these endpoints support (Section 2.3.1). RFC 9110 Section
// 11.3: "Many clients fail to parse a challenge that contains an unknown
// scheme. A workaround for this problem is to list well-supported schemes
// (such as "basic") first."
//
// A client that used another scheme also gets a challenge "matching the
// authentication scheme used by the client" (RFC 6749 Section 5.2). The
// scheme is repeated only when it is an RFC 9110 token ("auth-scheme =
// token", Section 11.1), so no unvalidated input reaches the header. The
// challenge is the scheme alone ("challenge = auth-scheme [ 1*SP ( token68 /
// #auth-param ) ]", Section 11.3), except for Bearer: RFC 6750 Section 3,
// "This scheme MUST be followed by one or more auth-param values."
//
// bearerError is the "error" attribute of the Bearer challenge, for the one
// endpoint that has a rule for it: RFC 7662 Section 2.3 answers a bearer
// token that is "invalid for this request" at the introspection endpoint "as
// described in Section 3 of OAuth 2.0 Bearer Token Usage [RFC6750]". Where
// only RFC 6749 Section 5.2 applies it is empty.
func writeInvalidClientUnauthorized(w http.ResponseWriter, r *http.Request, description, bearerError string) {
	w.Header().Add("WWW-Authenticate", `Basic realm="oauth2"`)
	scheme, _, _ := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	switch {
	case strings.EqualFold(scheme, "Basic") || !isHTTPToken(scheme):
	case strings.EqualFold(scheme, "Bearer") && bearerError != "":
		w.Header().Add("WWW-Authenticate", `Bearer realm="oauth2", error="`+bearerError+`"`)
	case strings.EqualFold(scheme, "Bearer"):
		w.Header().Add("WWW-Authenticate", `Bearer realm="oauth2"`)
	default:
		w.Header().Add("WWW-Authenticate", scheme)
	}
	writeOAuth2ErrorStatus(w, http.StatusUnauthorized, "invalid_client", description, "")
}

// isHTTPToken reports whether value is an RFC 9110 Section 5.6.2 token:
// "token = 1*tchar", where tchar is "!" / "#" / "$" / "%" / "&" / "'" / "*" /
// "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA.
func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// presentedClientPassword reads the client password a request carries (RFC
// 6749 Section 2.3.1): HTTP Basic, or client_id and client_secret in the
// request body. Those two parameters "can only be transmitted in the
// request-body and MUST NOT be included in the request URI", so the query
// string is not read. multiple reports a request that used both methods
// (Section 2.3: "The client MUST NOT use more than one authentication method
// in each request.").
func presentedClientPassword(r *http.Request) (clientID, clientSecret, method string, multiple bool) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	hasPost := r.PostForm.Has("client_secret")
	switch {
	case hasBasic:
		return basicID, basicSecret, "basic", hasPost
	case hasPost:
		return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), "post", false
	default:
		return r.PostForm.Get("client_id"), "", "none", false
	}
}

const oauth2ShowcasePageCSS = `
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #e4e4e7;
            padding: 16px;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
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
        input[type="email"], input[type="password"], input[type="text"] {
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
`

func (p *Plugin) generateLoginPage(clientID, scope, sessionID, clientName, loginRequestID, pageSubtitle string) string {
	if clientName == "" {
		if client, exists := p.mockIdP.GetClient(clientID); exists {
			clientName = client.Name
		} else {
			clientName = clientID
		}
	}
	if pageSubtitle == "" {
		pageSubtitle = "OAuth 2.0 Authorization"
	}
	formAction := "/oauth2/authorize"
	if sessionID != "" {
		formAction += "?lg_session=" + url.QueryEscape(sessionID)
	}

	demoUsersHTML := buildDemoUsersHTML(p.mockIdP.GetDemoUserPresets())

	return `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Login - Protocol Showcase</title>
    <style>
` + oauth2ShowcasePageCSS + `
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Protocol Showcase</h1>
            <p>` + pageSubtitle + `</p>
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
            
            <button type="submit">Sign In</button>
        </form>

        ` + demoUsersHTML + `

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
	ResponseType        string
	CodeChallenge       string
	CodeChallengeMethod string
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
		now := p.now()
		cutoff := now.Add(-p.loginRequestTTL)
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
