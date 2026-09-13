package oauth2

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

func (p *Plugin) deviceVerificationURL() string {
	return strings.TrimRight(p.baseURL, "/") + "/oauth2/device"
}

// handleDeviceAuthorize implements RFC 8628 Section 3.1.
func (p *Plugin) handleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	if err := r.ParseForm(); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid form data", "")
		return
	}
	if formHasDuplicateParams(r, "client_id", "scope") {
		writeOAuth2Error(w, "invalid_request", "Request parameters MUST NOT be included more than once (RFC 8628 Section 3.1)", "")
		return
	}

	client, clientAuthMethod, ok := p.authenticateDeviceClient(w, r, sessionID, "device_authorization")
	if !ok {
		return
	}
	if !clientHasGrant(client, mockidp.DeviceCodeGrantType) {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unauthorized Grant Type", map[string]interface{}{
			"client_id":  client.ID,
			"grant_type": mockidp.DeviceCodeGrantType,
		})
		writeOAuth2Error(w, "unauthorized_client", "Client not authorized for this grant type", "")
		return
	}

	scope, scopeOK := p.grantedScopeOrError(w, sessionID, client, r.FormValue("scope"))
	if !scopeOK {
		return
	}

	now := p.now()
	auth, err := p.mockIdP.CreateDeviceAuthorization(client.ID, scope, sessionID, now)
	if err != nil {
		writeOAuth2ErrorStatus(w, http.StatusInternalServerError, "server_error", "Failed to create device authorization", "")
		return
	}

	verificationURI := p.deviceVerificationURL()
	verificationURIComplete := verificationURI + "?user_code=" + url.QueryEscape(auth.UserCode)

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Device Authorization Issued", map[string]interface{}{
		"step":                      1,
		"from":                      "Authorization Server",
		"to":                        "Device Client",
		"client_id":                 client.ID,
		"client_auth_method":        clientAuthMethod,
		"user_code":                 auth.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURIComplete,
		"expires_in":                int(mockidp.DeviceAuthorizationTTL / time.Second),
		"interval":                  int(auth.Interval / time.Second),
		"scope":                     scope,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Device Authorization Response",
		Description: "The authorization server issues a high-entropy device_code for polling and a short user_code the person types on a second device.",
		Reference:   "RFC 8628 Section 3.2",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "User Code Entropy",
		Description: "The user_code uses the RFC 8628 Section 6.1 base-20 alphabet. Brute force is mitigated by a short lifetime and a five-attempt lockout.",
		Reference:   "RFC 8628 Section 5.1",
		Severity:    "info",
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"device_code":               auth.DeviceCode,
		"user_code":                 auth.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURIComplete,
		"expires_in":                int(mockidp.DeviceAuthorizationTTL / time.Second),
		"interval":                  int(auth.Interval / time.Second),
	})
}

// handleDeviceVerification serves RFC 8628 Section 3.3 user interaction.
func (p *Plugin) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		p.handleDeviceVerificationSubmit(w, r)
		return
	}
	sessionID := p.getSessionFromRequest(r)
	userCode := r.URL.Query().Get("user_code")
	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Device Verification Page", map[string]interface{}{
		"step":      2,
		"from":      "End User",
		"to":        "Authorization Server",
		"user_code": userCode,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "User Interaction",
		Description: "The authorization server authenticates the end user, accepts the user_code, and asks them to approve or deny the device.",
		Reference:   "RFC 8628 Section 3.3",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeSecurityHint,
		Title:       "Confirm the Device",
		Description: "It is RECOMMENDED to inform the user that they are authorizing a device and to confirm that the device is in their possession.",
		Reference:   "RFC 8628 Section 5.4",
		Severity:    "warning",
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	p.writeDeviceVerificationPage(w, userCode, sessionID, "")
}

func (p *Plugin) handleDeviceVerificationSubmit(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	if err := r.ParseForm(); err != nil {
		writeOAuth2Error(w, "invalid_request", "Invalid form data", "")
		return
	}

	userCode := r.FormValue("user_code")
	email := r.FormValue("email")
	password := r.FormValue("password")
	decision := r.FormValue("decision")
	now := p.now()

	if strings.TrimSpace(userCode) == "" {
		p.writeDeviceVerificationPage(w, userCode, sessionID, "user_code is required")
		return
	}

	if p.mockIdP.UserCodeLocked(userCode) {
		p.writeDeviceVerificationPage(w, userCode, sessionID, "Too many attempts for this user_code")
		return
	}

	auth, found := p.mockIdP.LookupDeviceAuthorizationByUserCode(userCode, now)
	if !found {
		p.mockIdP.RecordUserCodeFailure(userCode)
		p.writeDeviceVerificationPage(w, userCode, sessionID, "Unknown or expired user_code")
		return
	}
	if sessionID == "" {
		sessionID = auth.SessionID
	}

	p.emitEvent(sessionID, lookingglass.EventTypeRequestSent, "Device User Code Submitted", map[string]interface{}{
		"user_code": auth.UserCode,
		"client_id": auth.ClientID,
		"endpoint":  "/oauth2/device",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "User Code Binding",
		Description: "The user_code identifies the pending device authorization so the person can approve it on a browser they control.",
		Reference:   "RFC 8628 Section 3.3",
	})

	user, err := p.mockIdP.ValidateCredentials(email, password)
	if err != nil {
		p.mockIdP.RecordUserCodeFailure(userCode)
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Device User Authentication Failed", map[string]interface{}{
			"email":     email,
			"user_code": auth.UserCode,
		})
		p.writeDeviceVerificationPage(w, userCode, sessionID, "Invalid email or password")
		return
	}

	if decision == "deny" {
		if err := p.mockIdP.DenyDeviceAuthorization(userCode, now); err != nil {
			p.writeDeviceVerificationPage(w, userCode, sessionID, "This user_code cannot be denied")
			return
		}
		p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Device Authorization Denied", map[string]interface{}{
			"user_code": auth.UserCode,
			"client_id": auth.ClientID,
			"user_id":   user.ID,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "access_denied",
			Description: "The authorization request was denied. Subsequent token polls return access_denied and the client MUST stop polling.",
			Reference:   "RFC 8628 Section 3.5",
		})
		writeDeviceVerificationResultPage(w, false, auth.UserCode)
		return
	}

	if err := p.mockIdP.AuthorizeDeviceAuthorization(userCode, user.ID, now); err != nil {
		p.writeDeviceVerificationPage(w, userCode, sessionID, "This user_code cannot be approved")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Device Authorization Approved", map[string]interface{}{
		"user_code": auth.UserCode,
		"client_id": auth.ClientID,
		"user_id":   user.ID,
		"email":     user.Email,
		"scope":     auth.Scope,
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Return to the Device",
		Description: "Once the user interaction is complete, the server instructs the user to return to their device. The device obtains tokens by polling, not by a return channel.",
		Reference:   "RFC 8628 Section 3.3",
	})
	writeDeviceVerificationResultPage(w, true, auth.UserCode)
}

func (p *Plugin) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request, sessionID string, dpopJKT string) {
	if formHasDuplicateParams(r, "grant_type", "device_code", "client_id") {
		writeOAuth2Error(w, "invalid_request", "Request parameters MUST NOT be included more than once (RFC 8628 Section 3.4)", "")
		return
	}

	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		writeOAuth2Error(w, "invalid_request", "device_code is required", "")
		return
	}

	client, _, ok := p.authenticateDeviceClient(w, r, sessionID, "device_code")
	if !ok {
		return
	}
	if !clientHasGrant(client, mockidp.DeviceCodeGrantType) {
		writeOAuth2Error(w, "unauthorized_client", "Client not authorized for this grant type", "")
		return
	}

	outcome, auth := p.mockIdP.PollDeviceAuthorization(deviceCode, client.ID, p.now())
	switch outcome {
	case mockidp.DevicePollPending:
		p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Device Authorization Pending", map[string]interface{}{
			"error":    "authorization_pending",
			"interval": int(auth.Interval / time.Second),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "authorization_pending",
			Description: "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps. The client MUST wait at least interval seconds before polling again.",
			Reference:   "RFC 8628 Section 3.5",
		})
		writeOAuth2Error(w, "authorization_pending", "The authorization request is still pending as the end user hasn't yet completed the user-interaction steps", "")
		return
	case mockidp.DevicePollSlowDown:
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Device Poll Slow Down", map[string]interface{}{
			"error":    "slow_down",
			"interval": int(auth.Interval / time.Second),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "slow_down",
			Description: "Polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.",
			Reference:   "RFC 8628 Section 3.5",
		})
		writeOAuth2Error(w, "slow_down", "The authorization request is still pending; increase the polling interval by 5 seconds", "")
		return
	case mockidp.DevicePollDenied:
		writeOAuth2Error(w, "access_denied", "The authorization request was denied", "")
		return
	case mockidp.DevicePollExpired:
		writeOAuth2Error(w, "expired_token", "The device_code has expired, and the device authorization session has concluded", "")
		return
	case mockidp.DevicePollUnknown:
		writeOAuth2Error(w, "invalid_grant", "The provided device_code is invalid", "")
		return
	case mockidp.DevicePollConsumed:
		writeOAuth2Error(w, "invalid_grant", "The provided device_code is invalid", "")
		return
	case mockidp.DevicePollMismatch:
		writeOAuth2Error(w, "invalid_grant", "The provided device_code is invalid", "")
		return
	case mockidp.DevicePollAuthorized:
		// continue
	default:
		writeOAuth2Error(w, "invalid_grant", "The provided device_code is invalid", "")
		return
	}

	bindRefresh := client.Public
	tokenResponse, err := p.issueTokens(auth.UserID, client.ID, auth.Scope, dpopJKT, bindRefresh)
	if err != nil {
		writeOAuth2ErrorStatus(w, http.StatusInternalServerError, "server_error", "Failed to issue tokens", "")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Device Access Token Issued", map[string]interface{}{
		"client_id":     client.ID,
		"user_id":       auth.UserID,
		"scope":         auth.Scope,
		"token_type":    tokenResponse.TokenType,
		"expires_in":    tokenResponse.ExpiresIn,
		"dpop_bound":    dpopJKT != "",
		"refresh_bound": bindRefresh && dpopJKT != "",
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Device Access Token Response",
		Description: "If the user has approved the grant, the token endpoint responds with a success response defined in RFC 6749 Section 5.1.",
		Reference:   "RFC 8628 Section 3.5",
	})
	writeJSON(w, http.StatusOK, tokenResponse)
}

func (p *Plugin) writeDeviceVerificationPage(w http.ResponseWriter, userCode, sessionID, errMsg string) {
	formAction := "/oauth2/device"
	if sessionID != "" {
		formAction += "?lg_session=" + url.QueryEscape(sessionID)
	}
	type demoUser struct {
		Name     string
		Email    string
		Password string
	}
	users := make([]demoUser, 0, 3)
	for _, preset := range p.mockIdP.GetDemoUserPresets() {
		if preset.Credentials.Email == "" || preset.Credentials.Password == "" {
			continue
		}
		users = append(users, demoUser{
			Name:     preset.Name,
			Email:    preset.Credentials.Email,
			Password: preset.Credentials.Password,
		})
	}

	clientName := "this application"
	var scopes []string
	if peek := p.mockIdP.PeekDeviceAuthorizationByUserCode(userCode); peek != nil {
		if client, exists := p.mockIdP.GetClient(peek.ClientID); exists && client.Name != "" {
			clientName = client.Name
		}
		scopes = strings.Fields(peek.Scope)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceVerificationTmpl.Execute(w, struct {
		CSS        template.CSS
		UserCode   string
		FormAction string
		Error      string
		ClientName string
		Scopes     []string
		Users      []demoUser
	}{
		CSS:        template.CSS(oauth2ShowcasePageCSS),
		UserCode:   userCode,
		FormAction: formAction,
		Error:      errMsg,
		ClientName: clientName,
		Scopes:     scopes,
		Users:      users,
	})
}

func writeDeviceVerificationResultPage(w http.ResponseWriter, approved bool, userCode string) {
	title := "Device denied"
	body := "You denied authorization. Return to the device; it will stop polling with access_denied."
	if approved {
		title = "Device approved"
		body = "Return to your device. It will finish polling the token endpoint and receive access tokens."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = deviceVerificationResultTmpl.Execute(w, struct {
		CSS      template.CSS
		Title    string
		Body     string
		UserCode string
		Approved bool
	}{
		CSS:      template.CSS(oauth2ShowcasePageCSS),
		Title:    title,
		Body:     body,
		UserCode: userCode,
		Approved: approved,
	})
}

var deviceVerificationTmpl = template.Must(template.New("device-verify").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Login - Protocol Showcase</title>
    <style>
{{.CSS}}
        .warn {
            background: rgba(251, 191, 36, 0.1);
            border: 1px solid rgba(251, 191, 36, 0.25);
            color: #fbbf24;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 13px;
            line-height: 1.45;
        }
        input.user-code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            letter-spacing: 0.18em;
            text-transform: uppercase;
        }
        button.secondary {
            background: transparent;
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: #d4d4d8;
            box-shadow: none;
            margin-top: 8px;
        }
        button.secondary:hover {
            transform: none;
            background: rgba(239, 68, 68, 0.12);
            border-color: rgba(239, 68, 68, 0.35);
            box-shadow: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Protocol Showcase</h1>
            <p>OAuth 2.0 Device Authorization</p>
        </div>

        <div class="client-info">
            <span>Signing in to <strong>{{.ClientName}}</strong> to authorize a device</span>
        </div>

        <div class="warn">RFC 8628 §5.4: you are authorizing a device. Confirm it is in your possession before signing in. Do not enter a user_code from email or a stranger.</div>

        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}

        <form method="POST" action="{{.FormAction}}">
            <div class="form-group">
                <label for="user_code">User code</label>
                <input type="text" id="user_code" name="user_code" class="user-code" value="{{.UserCode}}" autocomplete="off" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" placeholder="alice@example.com" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="password" required>
            </div>
            <button type="submit" name="decision" value="approve">Sign In</button>
            <button type="submit" name="decision" value="deny" class="secondary">Deny</button>
        </form>

        {{if .Users}}
        <div class="demo-users">
            <h3>Demo Users (click to autofill)</h3>
            {{range .Users}}
            <div class="demo-user" data-email="{{.Email}}" data-password="{{.Password}}" onclick="fillCredentials(this.dataset.email || '', this.dataset.password || '')">
                <div class="name">{{.Name}}</div>
                <div class="email">{{.Email}}</div>
            </div>
            {{end}}
        </div>
        {{end}}

        {{if .Scopes}}
        <div class="scopes">
            Requested scopes: {{range .Scopes}}<span>{{.}}</span>{{end}}
        </div>
        {{end}}
    </div>
    <script>
        function fillCredentials(email, password) {
            document.getElementById('email').value = email;
            document.getElementById('password').value = password;
        }
    </script>
</body>
</html>`))

var deviceVerificationResultTmpl = template.Must(template.New("device-result").Parse(`<!DOCTYPE html>
<html data-approved="{{.Approved}}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{{.Title}} - Protocol Showcase</title>
    <style>
{{.CSS}}
        .result-body {
            color: #a1a1aa;
            font-size: 14px;
            line-height: 1.5;
            margin-bottom: 16px;
        }
        .result-code {
            color: #71717a;
            font-size: 12px;
        }
        .result-code code {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            letter-spacing: 0.15em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h1>Protocol Showcase</h1>
            <p>OAuth 2.0 Device Authorization</p>
        </div>
        <div class="client-info">
            <span>{{.Title}}</span>
        </div>
        <p class="result-body">{{.Body}}</p>
        <p class="result-code">User code: <code>{{.UserCode}}</code></p>
    </div>
    <script>
        (function () {
            var approved = document.documentElement.getAttribute('data-approved') === 'true';
            if (window.opener && window.opener !== window) {
                window.opener.postMessage(
                    { type: 'oauth_device_complete', approved: approved },
                    window.location.origin
                );
                window.setTimeout(function () { window.close(); }, 400);
            }
        })();
    </script>
</body>
</html>`))

func clientHasGrant(client *models.Client, grant string) bool {
	if client == nil {
		return false
	}
	for _, gt := range client.GrantTypes {
		if gt == grant {
			return true
		}
	}
	return false
}

func formHasDuplicateParams(r *http.Request, names ...string) bool {
	for _, name := range names {
		if len(r.Form[name]) > 1 {
			return true
		}
	}
	return false
}

// authenticateDeviceClient authenticates the client for the device
// authorization endpoint (RFC 8628 §3.1) and the device_code token grant.
// Confidential clients MUST authenticate. private_key_jwt is rejected for
// this grant, matching the authorization_code profile.
func (p *Plugin) authenticateDeviceClient(
	w http.ResponseWriter,
	r *http.Request,
	sessionID string,
	contextName string,
) (*models.Client, string, bool) {
	if r.Form.Has("client_assertion_type") || r.Form.Has("client_assertion") {
		p.rejectClientAssertionForUnsupportedGrant(w, sessionID, contextName)
		return nil, "", false
	}

	basicID, basicSecret, hasBasic := r.BasicAuth()
	hasPost := r.Form.Has("client_secret") && strings.TrimSpace(r.FormValue("client_secret")) != ""
	if hasBasic && hasPost {
		writeOAuth2Error(w, "invalid_request", "A client MUST NOT use more than one authentication method in each request (RFC 6749 Section 2.3)", "")
		return nil, "", false
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	clientAuthMethod := "none"
	if hasBasic {
		clientID = basicID
		clientSecret = basicSecret
		clientAuthMethod = "basic"
	} else if hasPost {
		clientAuthMethod = "post"
	}

	if clientID == "" {
		writeOAuth2Error(w, "invalid_client", "client_id is required", "")
		return nil, "", false
	}

	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		writeOAuth2Error(w, "invalid_client", "Unknown client", "")
		return nil, "", false
	}

	if !client.Public {
		authenticated, err := p.mockIdP.ValidateClient(clientID, clientSecret)
		if err != nil {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Client Authentication Failed", map[string]interface{}{
				"client_id":          clientID,
				"error":              "invalid_client",
				"client_auth_method": clientAuthMethod,
			})
			if hasBasic {
				w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
				writeOAuth2ErrorStatus(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed", "")
			} else {
				writeOAuth2Error(w, "invalid_client", "Client authentication failed", "")
			}
			return nil, "", false
		}
		client = authenticated
	}

	return client, clientAuthMethod, true
}

func (p *Plugin) grantedScopeOrError(
	w http.ResponseWriter,
	sessionID string,
	client *models.Client,
	scope string,
) (string, bool) {
	requestedScopes := strings.Fields(scope)
	if len(requestedScopes) == 0 {
		return strings.Join(client.Scopes, " "), true
	}
	allowed := make(map[string]bool, len(client.Scopes))
	for _, s := range client.Scopes {
		allowed[s] = true
	}
	var granted []string
	for _, s := range requestedScopes {
		if allowed[s] {
			granted = append(granted, s)
		}
	}
	if len(granted) == 0 {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Invalid Scope", map[string]interface{}{
			"requested_scopes": requestedScopes,
			"allowed_scopes":   client.Scopes,
		})
		writeOAuth2Error(w, "invalid_scope", "None of the requested scopes are permitted for this client", "")
		return "", false
	}
	return strings.Join(granted, " "), true
}
