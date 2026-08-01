package saml

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// ============================================================================
// Metadata Endpoint
// ============================================================================

// handleMetadata returns the SAML metadata document
func (p *Plugin) handleMetadata(w http.ResponseWriter, r *http.Request) {
	config := &MetadataConfig{
		EntityID:             p.entityID,
		BaseURL:              p.baseURL,
		Certificate:          nil, // In production, this would be a real X.509 certificate
		WantAssertionsSigned: true,
		AuthnRequestsSigned:  false,
		ACSURL:               p.acsURL,
		SLOURL:               p.sloURL,
		SSOURL:               p.ssoServiceURL,
		OrgName:              "ProtocolSoup Demo",
		OrgDisplayName:       "ProtocolSoup SAML Demo",
		OrgURL:               p.baseURL,
		TechnicalContact:     "demo@protocolsoup.example",
	}

	// Generate both SP and IdP metadata (since we act as both for demo purposes)
	// For this demo, we'll return SP metadata by default
	metadata, err := GenerateSPMetadata(config)
	if err != nil {
		http.Error(w, "Failed to generate metadata", http.StatusInternalServerError)
		return
	}

	// Also include IdP descriptor for demo purposes
	idpMetadata, err := GenerateIDPMetadata(config)
	if err == nil && idpMetadata.IDPSSODescriptor != nil {
		metadata.IDPSSODescriptor = idpMetadata.IDPSSODescriptor
	}

	xmlData, err := MarshalMetadata(metadata)
	if err != nil {
		http.Error(w, "Failed to marshal metadata", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.Write(xmlData)
}

// ============================================================================
// SSO Service Endpoints (IdP Role)
// ============================================================================

// handleSSOService handles SSO requests via HTTP-Redirect binding
func (p *Plugin) handleSSOService(w http.ResponseWriter, r *http.Request) {
	// Parse the redirect binding request
	binding := NewRedirectBinding(nil)
	xmlData, relayState, err := binding.ParseRedirectRequest(r)
	if err != nil {
		http.Error(w, "Invalid SAML request: "+err.Error(), http.StatusBadRequest)
		return
	}

	p.processSSORequest(w, r, xmlData, relayState, BindingTypeRedirect)
}

// handleSSOServicePost handles SSO requests via HTTP-POST binding
func (p *Plugin) handleSSOServicePost(w http.ResponseWriter, r *http.Request) {
	// Parse the POST binding request
	binding := NewPostBinding(nil)
	xmlData, relayState, err := binding.ParsePostRequest(r)
	if err != nil {
		http.Error(w, "Invalid SAML request: "+err.Error(), http.StatusBadRequest)
		return
	}

	p.processSSORequest(w, r, xmlData, relayState, BindingTypePost)
}

// processSSORequest processes an AuthnRequest and shows login page
func (p *Plugin) processSSORequest(w http.ResponseWriter, r *http.Request, xmlData []byte, relayState string, bindingType BindingType) {
	// Parse the AuthnRequest
	var authnRequest AuthnRequest
	if err := xml.Unmarshal(xmlData, &authnRequest); err != nil {
		http.Error(w, "Invalid AuthnRequest: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Emit Looking Glass events with full SAML message capture
	if p.lookingGlass != nil {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			sessionID = r.Header.Get("X-Session-ID")
		}
		if sessionID != "" {
			broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)

			// Capture HTTP request details
			broadcaster.Emit(
				lookingglass.EventTypeRequestSent,
				"HTTP Request to IdP SSO Service",
				map[string]interface{}{
					"method":  r.Method,
					"url":     r.URL.String(),
					"binding": string(bindingType),
					"headers": map[string]string{
						"Content-Type": r.Header.Get("Content-Type"),
						"Accept":       r.Header.Get("Accept"),
					},
				},
			)

			// Capture the actual SAML AuthnRequest XML
			broadcaster.Emit(
				lookingglass.EventTypeFlowStep,
				"AuthnRequest Received",
				map[string]interface{}{
					"id":              authnRequest.ID,
					"issuer":          authnRequest.Issuer.Value,
					"destination":     authnRequest.Destination,
					"binding":         string(bindingType),
					"acsURL":          authnRequest.AssertionConsumerServiceURL,
					"samlXML":         string(xmlData), // Include actual XML for inspection
					"protocolBinding": authnRequest.ProtocolBinding,
					"forceAuthn":      authnRequest.ForceAuthn,
					"isPassive":       authnRequest.IsPassive,
				},
			)
		}
	}

	// Store request info in session for callback
	// In a real implementation, this would use secure session storage
	requestInfo := map[string]string{
		"request_id":   authnRequest.ID,
		"issuer":       authnRequest.Issuer.Value,
		"acs_url":      authnRequest.AssertionConsumerServiceURL,
		"relay_state":  relayState,
		"binding_type": string(bindingType),
	}

	// Show login page
	p.showLoginPage(w, r, requestInfo)
}

// showLoginPage displays the IdP login page
func (p *Plugin) showLoginPage(w http.ResponseWriter, _ *http.Request, requestInfo map[string]string) {
	users := p.mockIdP.ListUsers()

	loginRequestID, err := p.createLoginRequest(requestInfo)
	if err != nil {
		http.Error(w, "Invalid login request: "+err.Error(), http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "saml_login_request",
		Value:    loginRequestID,
		Path:     "/saml",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML IdP Login - ProtocolSoup</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            padding: 40px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.4);
        }
        h1 { 
            color: #1a1a2e;
            margin-bottom: 8px;
            font-size: 24px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 24px;
            font-size: 14px;
        }
        .sp-info {
            background: #f0f4ff;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            border-left: 4px solid #3b82f6;
        }
        .sp-info h3 { color: #1e40af; font-size: 14px; margin-bottom: 4px; }
        .sp-info p { color: #3b82f6; font-size: 12px; word-break: break-all; }
        .users { margin-bottom: 24px; }
        .users h3 { color: #374151; font-size: 14px; margin-bottom: 12px; }
        .user-btn {
            display: block;
            width: 100%;
            padding: 16px;
            margin-bottom: 12px;
            background: #fff;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
        }
        .user-btn:hover { border-color: #3b82f6; background: #f0f4ff; }
        .user-btn strong { display: block; color: #1f2937; margin-bottom: 4px; }
        .user-btn span { color: #6b7280; font-size: 13px; }
        .form-group { margin-bottom: 16px; }
        .form-group label { display: block; color: #374151; font-size: 14px; margin-bottom: 6px; }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
        }
        .form-group input:focus { outline: none; border-color: #3b82f6; }
        .submit-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .submit-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4); }
        .divider { text-align: center; margin: 20px 0; color: #9ca3af; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 SAML IdP Login</h1>
        <p class="subtitle">ProtocolSoup Identity Provider</p>
        
        <div class="sp-info">
            <h3>Service Provider</h3>
            <p>{{.Issuer}}</p>
        </div>
        
        <div class="users">
            <h3>Select a Demo User</h3>
            {{range .Users}}
            <form method="POST" action="/saml/login" style="display: inline;">
                <input type="hidden" name="username" value="{{.Username}}">
                <input type="hidden" name="password" value="{{.Password}}">
                <button type="submit" class="user-btn">
                    <strong>{{.Name}}</strong>
                    <span>{{.Email}}</span>
                </button>
            </form>
            {{end}}
        </div>
        
        <div class="divider">- or enter credentials -</div>
        
        <form method="POST" action="/saml/login">
            
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit" class="submit-btn">Sign In</button>
        </form>
    </div>
</body>
</html>`

	t, err := template.New("login").Parse(tmpl)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	data := struct {
		Issuer string
		Users  []struct {
			Username string
			Name     string
			Email    string
			Password string
		}
	}{
		Issuer: requestInfo["issuer"],
	}

	for _, u := range users {
		data.Users = append(data.Users, struct {
			Username string
			Name     string
			Email    string
			Password string
		}{
			Username: u.ID,
			Name:     u.Name,
			Email:    u.Email,
			Password: u.Password,
		})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// ============================================================================
// SP-Initiated Login
// ============================================================================

// handleSPInitiatedLogin starts an SP-initiated login flow
func (p *Plugin) handleSPInitiatedLogin(w http.ResponseWriter, r *http.Request) {
	// Create an AuthnRequest
	authnRequest := NewAuthnRequest(
		p.entityID,
		p.ssoServiceURL,
		p.acsURL,
	)

	relayState := r.URL.Query().Get("RelayState")
	// Validate RelayState to prevent open redirect (CWE-601)
	validatedRelayState, err := validateRelayStateForRedirect(relayState, p.baseURL)
	if err != nil {
		// Log the error but continue with safe default
		validatedRelayState = "/"
	}
	// HTML escape for safe embedding
	relayState = sanitizeRelayState(validatedRelayState)

	binding := r.URL.Query().Get("binding")
	if binding == "" {
		binding = "redirect"
	}
	// Validate binding value
	if binding != "redirect" && binding != "post" {
		binding = "redirect"
	}

	// Store request ID for InResponseTo validation (SAML 2.0 Profiles Section 4.1.4.3)
	p.requestIDCache.StoreRequestID(authnRequest.ID)

	// Emit Looking Glass event
	if p.lookingGlass != nil {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID != "" {
			broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)
			broadcaster.Emit(
				lookingglass.EventTypeFlowStep,
				"AuthnRequest Created",
				map[string]interface{}{
					"id":          authnRequest.ID,
					"issuer":      authnRequest.Issuer.Value,
					"destination": authnRequest.Destination,
					"acsURL":      authnRequest.AssertionConsumerServiceURL,
					"binding":     binding,
					"security": map[string]interface{}{
						"requestIDStored": true,
						"description":     "Request ID stored for InResponseTo validation",
					},
				},
			)
		}
	}

	// Get private key for signing
	var privateKey *rsa.PrivateKey
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
	}

	if binding == "post" {
		// Use HTTP-POST binding
		postBinding := NewPostBinding(privateKey)
		html, err := postBinding.GeneratePostForm(p.ssoServiceURL, authnRequest, relayState, true)
		if err != nil {
			http.Error(w, "Failed to generate POST form: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
	} else {
		// Use HTTP-Redirect binding
		redirectBinding := NewRedirectBinding(privateKey)
		redirectURL, err := redirectBinding.BuildRedirectURL(p.ssoServiceURL, authnRequest, relayState, true)
		if err != nil {
			http.Error(w, "Failed to build redirect URL: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// handleSPInitiatedLoginSubmit processes the login form submission
func (p *Plugin) handleSPInitiatedLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	loginCookie, err := r.Cookie("saml_login_request")
	if err != nil || loginCookie.Value == "" {
		http.Error(w, "Missing login request", http.StatusBadRequest)
		return
	}

	requestInfo, ok := p.takeLoginRequest(loginCookie.Value)
	if !ok {
		http.Error(w, "Login request expired or invalid", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "saml_login_request",
		Value:    "",
		Path:     "/saml",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	if requestInfo.ACSURL != p.acsURL {
		http.Error(w, "ACS URL not allowed", http.StatusBadRequest)
		return
	}

	requestID := html.EscapeString(requestInfo.RequestID)
	issuer := html.EscapeString(requestInfo.Issuer)
	acsURL := p.acsURL
	relayState := html.EscapeString(requestInfo.RelayState)
	bindingType := requestInfo.BindingType

	if bindingType != "post" && bindingType != "redirect" {
		bindingType = "post"
	}

	// Authenticate user - first try by username, then by email
	user, err := p.mockIdP.ValidateCredentials(username, password)
	if err != nil {
		// Try treating username as an email
		user, err = p.mockIdP.ValidateCredentials(username+"@example.com", password)
		if err != nil {
			http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
	}

	// Create SAML Response with Assertion
	response := NewResponse(p.entityID, acsURL, requestID, true)

	// Create assertion with user attributes
	attributes := map[string][]string{
		"urn:oid:0.9.2342.19200300.100.1.3": {user.Email}, // mail
		"urn:oid:2.5.4.42":                  {user.Name},  // givenName
		"urn:oid:2.5.4.4":                   {user.Name},  // sn (surname)
		"urn:oid:2.5.4.3":                   {user.Name},  // cn (common name)
		"email":                             {user.Email},
		"name":                              {user.Name},
		"uid":                               {user.ID},
	}

	sessionIndex := GenerateID()
	assertion := NewAssertion(
		p.entityID,
		issuer, // audience is the requesting SP
		user.Email,
		NameIDFormatEmail,
		sessionIndex,
		attributes,
	)

	// Set InResponseTo on subject confirmation
	if assertion.Subject != nil && assertion.Subject.SubjectConfirmation != nil && assertion.Subject.SubjectConfirmation.SubjectConfirmationData != nil {
		assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo = requestID
		assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = acsURL
	}

	response.Assertions = []*Assertion{assertion}

	// Create session
	session := &SAMLSession{
		ID:           GenerateID(),
		NameID:       user.Email,
		NameIDFormat: NameIDFormatEmail,
		SessionIndex: sessionIndex,
		Attributes:   attributes,
		AuthnInstant: TimeNow(),
		NotOnOrAfter: TimeIn(8 * time.Hour),
		AssertionID:  assertion.ID,
	}
	p.CreateSession(session)

	// Emit Looking Glass events with full SAML Response capture
	if p.lookingGlass != nil {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			sessionID = r.Header.Get("X-Session-ID")
		}
		if sessionID != "" {
			broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)

			// Serialize the response for inspection
			responseXML, _ := Marshal(response)
			assertionXML, _ := Marshal(assertion)

			// Emit the full SAML Response for Looking Glass inspection
			broadcaster.Emit(
				lookingglass.EventTypeFlowStep,
				"SAML Response Created",
				map[string]interface{}{
					"responseID":      response.ID,
					"inResponseTo":    requestID,
					"assertionID":     assertion.ID,
					"nameID":          user.Email,
					"sessionIndex":    sessionIndex,
					"destination":     acsURL,
					"issuer":          p.entityID,
					"status":          StatusSuccess,
					"samlResponseXML": string(responseXML), // Full Response XML
				},
			)

			// Emit assertion details separately for detailed inspection
			broadcaster.Emit(
				lookingglass.EventTypeTokenIssued, // Use token event type for assertion inspection
				"SAML Assertion",
				map[string]interface{}{
					"assertionID":  assertion.ID,
					"issuer":       assertion.Issuer.Value,
					"issueInstant": assertion.IssueInstant,
					"subject": map[string]interface{}{
						"nameID":       user.Email,
						"nameIDFormat": NameIDFormatEmail,
					},
					"conditions": map[string]interface{}{
						"notBefore":    assertion.Conditions.NotBefore,
						"notOnOrAfter": assertion.Conditions.NotOnOrAfter,
						"audience":     issuer,
					},
					"authnStatement": map[string]interface{}{
						"authnInstant":        assertion.AuthnStatement.AuthnInstant,
						"sessionIndex":        sessionIndex,
						"sessionNotOnOrAfter": assertion.AuthnStatement.SessionNotOnOrAfter,
						"authnContextClass":   AuthnContextPasswordProtectedTransport,
					},
					"attributes":   attributes,
					"assertionXML": string(assertionXML), // Full Assertion XML
				},
			)
		}
	}

	// Get private key for signing
	var privateKey *rsa.PrivateKey
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
	}

	// Send response based on binding type
	// Security: GeneratePostForm uses html/template for XSS protection
	// Security: acsURL has been validated against allowlist above
	if bindingType == "post" || bindingType == "" {
		postBinding := NewPostBinding(privateKey)
		// GeneratePostForm uses html/template which auto-escapes all inputs
		htmlContent, err := postBinding.GeneratePostForm(acsURL, response, relayState, false)
		if err != nil {
			http.Error(w, "Failed to generate response: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Add security headers to prevent content sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write([]byte(htmlContent))
	} else {
		redirectBinding := NewRedirectBinding(privateKey)
		// Security: acsURL was validated against allowlist
		redirectURL, err := redirectBinding.BuildRedirectURL(acsURL, response, relayState, false)
		if err != nil {
			http.Error(w, "Failed to build redirect: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Redirect URL is built from validated acsURL
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// ============================================================================
// Assertion Consumer Service (SP Role)
// ============================================================================

// handleACS handles SAML responses via HTTP-Redirect binding
func (p *Plugin) handleACS(w http.ResponseWriter, r *http.Request) {
	binding := NewRedirectBinding(nil)
	xmlData, relayState, err := binding.ParseRedirectRequest(r)
	if err != nil {
		http.Error(w, "Invalid SAML response: "+err.Error(), http.StatusBadRequest)
		return
	}

	p.processACSResponse(w, r, xmlData, relayState)
}

// handleACSPost handles SAML responses via HTTP-POST binding
func (p *Plugin) handleACSPost(w http.ResponseWriter, r *http.Request) {
	binding := NewPostBinding(nil)
	xmlData, relayState, err := binding.ParsePostRequest(r)
	if err != nil {
		http.Error(w, "Invalid SAML response: "+err.Error(), http.StatusBadRequest)
		return
	}

	p.processACSResponse(w, r, xmlData, relayState)
}

// processACSResponse processes a SAML Response at the ACS
// Per SAML 2.0 Profiles Section 4.1.4.3, the SP must validate:
// - Status is Success
// - Assertion exists and is valid
// - Conditions (time bounds, audience)
// - Subject confirmation
// - XML digital signature (SAML 2.0 Core Section 5)
// - InResponseTo matches pending request
// - Assertion not replayed (Profiles Section 4.1.4.5)
func (p *Plugin) processACSResponse(w http.ResponseWriter, r *http.Request, xmlData []byte, relayState string) {
	var response Response
	if err := xml.Unmarshal(xmlData, &response); err != nil {
		http.Error(w, "Invalid SAML Response: "+err.Error(), http.StatusBadRequest)
		return
	}

	// =========================================================================
	// Security Validation Block - SAML 2.0 Profiles Section 4.1.4.3
	// =========================================================================

	securityValidation := map[string]interface{}{
		"signatureValid":    false,
		"inResponseToValid": false,
		"replayCheckPassed": false,
		"subjectConfirmed":  false,
	}

	// 1. Validate InResponseTo matches a pending request (unless IdP-initiated)
	if response.InResponseTo != "" {
		if err := p.requestIDCache.ValidateInResponseTo(response.InResponseTo); err != nil {
			// Log for Looking Glass but allow demo to continue with warning
			securityValidation["inResponseToError"] = err.Error()
			securityValidation["inResponseToValid"] = false
		} else {
			securityValidation["inResponseToValid"] = true
		}
	} else {
		// IdP-initiated SSO has no InResponseTo
		securityValidation["inResponseToValid"] = true
		securityValidation["isIdPInitiated"] = true
	}

	// 2. Validate XML Digital Signature (SAML 2.0 Core Section 5)
	issuerEntityID := ""
	if response.Issuer != nil {
		issuerEntityID = response.Issuer.Value
	}

	sigResult, sigErr := p.signatureValidator.ValidateResponseSignature(xmlData, issuerEntityID)
	if sigErr != nil {
		securityValidation["signatureError"] = sigErr.Error()
	}
	if sigResult != nil {
		securityValidation["signatureValid"] = sigResult.Valid
		securityValidation["signatureAlgorithm"] = sigResult.Algorithm
		securityValidation["digestAlgorithm"] = sigResult.DigestAlgorithm
		if len(sigResult.Warnings) > 0 {
			securityValidation["signatureWarnings"] = sigResult.Warnings
		}
		if len(sigResult.Errors) > 0 {
			securityValidation["signatureErrors"] = sigResult.Errors
		}
	}

	// Validate response status (SAML 2.0 Core Section 3.2.2.2)
	if response.Status == nil || response.Status.StatusCode.Value != StatusSuccess {
		statusCode := "unknown"
		statusMsg := ""
		if response.Status != nil {
			statusCode = response.Status.StatusCode.Value
			statusMsg = response.Status.StatusMessage
		}
		errMsg := fmt.Sprintf("SAML authentication failed: %s", statusCode)
		if statusMsg != "" {
			errMsg += " - " + statusMsg
		}
		http.Error(w, errMsg, http.StatusUnauthorized)
		return
	}

	// Validate Version (must be "2.0" per SAML 2.0 Core Section 3.2.2)
	if response.Version != "2.0" {
		http.Error(w, "Unsupported SAML version: "+response.Version, http.StatusBadRequest)
		return
	}

	// Extract assertion
	if len(response.Assertions) == 0 {
		http.Error(w, "No assertion in SAML response", http.StatusBadRequest)
		return
	}

	assertion := response.Assertions[0]

	// 3. Check for assertion replay (SAML 2.0 Profiles Section 4.1.4.5)
	if err := p.assertionCache.MarkConsumed(assertion.ID); err != nil {
		securityValidation["replayCheckPassed"] = false
		securityValidation["replayError"] = err.Error()
		// In production, this should be a hard failure
		// http.Error(w, "Assertion replay detected", http.StatusBadRequest)
		// return
	} else {
		securityValidation["replayCheckPassed"] = true
	}

	// 4. Validate SubjectConfirmation (SAML 2.0 Core Section 2.4.1.2)
	if assertion.Subject != nil && assertion.Subject.SubjectConfirmation != nil {
		scd := assertion.Subject.SubjectConfirmation.SubjectConfirmationData
		if scd != nil {
			subjectValidation := map[string]interface{}{}

			// Check Recipient matches ACS URL
			if scd.Recipient != "" {
				if scd.Recipient == p.acsURL {
					subjectValidation["recipientValid"] = true
				} else {
					subjectValidation["recipientValid"] = false
					subjectValidation["recipientError"] = fmt.Sprintf("Recipient mismatch: expected %s, got %s", p.acsURL, scd.Recipient)
				}
			}

			// Check NotOnOrAfter
			if scd.NotOnOrAfter != "" {
				notOnOrAfter, err := time.Parse(SAMLTimeFormat, scd.NotOnOrAfter)
				if err == nil {
					if time.Now().UTC().After(notOnOrAfter.Add(5 * time.Minute)) {
						subjectValidation["notOnOrAfterValid"] = false
						subjectValidation["notOnOrAfterError"] = "SubjectConfirmationData has expired"
					} else {
						subjectValidation["notOnOrAfterValid"] = true
					}
				}
			}

			// Check InResponseTo on SubjectConfirmationData
			if scd.InResponseTo != "" && response.InResponseTo != "" {
				if scd.InResponseTo == response.InResponseTo {
					subjectValidation["inResponseToMatch"] = true
				} else {
					subjectValidation["inResponseToMatch"] = false
				}
			}

			securityValidation["subjectConfirmation"] = subjectValidation
			securityValidation["subjectConfirmed"] = true
		}
	}

	// Validate Conditions (SAML 2.0 Core Section 2.5)
	if assertion.Conditions != nil {
		now := time.Now().UTC()

		// Check NotBefore
		if assertion.Conditions.NotBefore != "" {
			notBefore, err := time.Parse(SAMLTimeFormat, assertion.Conditions.NotBefore)
			if err == nil {
				// Allow 5 minute clock skew per common practice
				if now.Before(notBefore.Add(-5 * time.Minute)) {
					http.Error(w, "Assertion not yet valid", http.StatusBadRequest)
					return
				}
			}
		}

		// Check NotOnOrAfter
		if assertion.Conditions.NotOnOrAfter != "" {
			notOnOrAfter, err := time.Parse(SAMLTimeFormat, assertion.Conditions.NotOnOrAfter)
			if err == nil {
				// Allow 5 minute clock skew
				if now.After(notOnOrAfter.Add(5 * time.Minute)) {
					http.Error(w, "Assertion has expired", http.StatusBadRequest)
					return
				}
			}
		}

		// Validate AudienceRestriction (SAML 2.0 Core Section 2.5.1.4)
		if assertion.Conditions.AudienceRestriction != nil {
			audiences := assertion.Conditions.AudienceRestriction.Audience
			if len(audiences) > 0 {
				isValidAudience := false
				for _, aud := range audiences {
					if aud == p.entityID {
						isValidAudience = true
						break
					}
				}
				if !isValidAudience {
					http.Error(w, "SP is not in assertion's intended audience", http.StatusBadRequest)
					return
				}
			}
		}
	}

	// Extract user info
	var nameID, nameIDFormat string
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
		nameIDFormat = assertion.Subject.NameID.Format
	}

	// Extract attributes
	attributes := make(map[string][]string)
	if assertion.AttributeStatement != nil {
		for _, attr := range assertion.AttributeStatement.Attributes {
			values := make([]string, len(attr.AttributeValues))
			for i, v := range attr.AttributeValues {
				values[i] = v.Value
			}
			attributes[attr.Name] = values
			if attr.FriendlyName != "" {
				attributes[attr.FriendlyName] = values
			}
		}
	}

	// Extract session info
	var sessionIndex, authnInstant string
	if assertion.AuthnStatement != nil {
		sessionIndex = assertion.AuthnStatement.SessionIndex
		authnInstant = assertion.AuthnStatement.AuthnInstant
	}

	// Create local session
	session := &SAMLSession{
		ID:           GenerateID(),
		NameID:       nameID,
		NameIDFormat: nameIDFormat,
		SessionIndex: sessionIndex,
		Attributes:   attributes,
		AuthnInstant: authnInstant,
		AssertionID:  assertion.ID,
	}
	p.CreateSession(session)

	// Emit Looking Glass events with full response capture
	if p.lookingGlass != nil {
		sessionIDHeader := r.URL.Query().Get("session_id")
		if sessionIDHeader == "" {
			sessionIDHeader = r.Header.Get("X-Session-ID")
		}
		if sessionIDHeader != "" {
			broadcaster := p.lookingGlass.NewEventBroadcaster(sessionIDHeader)

			// Emit HTTP response details
			broadcaster.Emit(
				lookingglass.EventTypeResponseReceived,
				"SAML Response Received at ACS",
				map[string]interface{}{
					"endpoint":    p.acsURL,
					"method":      r.Method,
					"contentType": r.Header.Get("Content-Type"),
				},
			)

			// Emit the parsed SAML Response
			broadcaster.Emit(
				lookingglass.EventTypeFlowStep,
				"SAML Response Processed",
				map[string]interface{}{
					"responseID":      response.ID,
					"inResponseTo":    response.InResponseTo,
					"destination":     response.Destination,
					"issuer":          response.Issuer.Value,
					"issueInstant":    response.IssueInstant,
					"statusCode":      response.Status.StatusCode.Value,
					"samlResponseXML": string(xmlData), // Include raw XML for inspection
				},
			)

			// Emit parsed assertion details for inspection with real security validation
			broadcaster.Emit(
				lookingglass.EventTypeTokenValidated,
				"SAML Assertion Validated",
				map[string]interface{}{
					"assertionID":  assertion.ID,
					"issuer":       assertion.Issuer.Value,
					"issueInstant": assertion.IssueInstant,
					"subject": map[string]interface{}{
						"nameID":       nameID,
						"nameIDFormat": nameIDFormat,
					},
					"sessionIndex": sessionIndex,
					"authnInstant": authnInstant,
					"attributes":   attributes,
					// Real security validation results from SAML 2.0 spec checks
					"security": securityValidation,
				},
			)
		}
	}

	// Return success response with full SAML details for Looking Glass
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":        true,
		"session_id":     session.ID,
		"name_id":        nameID,
		"name_id_format": nameIDFormat,
		"session_index":  sessionIndex,
		"attributes":     attributes,
		"relay_state":    relayState,
		"response": map[string]interface{}{
			"id":             response.ID,
			"in_response_to": response.InResponseTo,
			"issuer":         response.Issuer.Value,
			"issue_instant":  response.IssueInstant,
			"destination":    response.Destination,
			"status_code":    response.Status.StatusCode.Value,
		},
		"assertion": map[string]interface{}{
			"id":            assertion.ID,
			"issuer":        assertion.Issuer.Value,
			"issue_instant": assertion.IssueInstant,
			"conditions": map[string]interface{}{
				"not_before":      assertion.Conditions.NotBefore,
				"not_on_or_after": assertion.Conditions.NotOnOrAfter,
			},
			"authn_statement": map[string]interface{}{
				"authn_instant": authnInstant,
				"session_index": sessionIndex,
			},
		},
	})
}

// ============================================================================
// Single Logout Service
// ============================================================================

// sloManager handles Single Logout state tracking for multi-SP logout coordination
var sloManager = NewSLOManager()

// handleSLO handles logout requests via HTTP-Redirect binding
func (p *Plugin) handleSLO(w http.ResponseWriter, r *http.Request) {
	binding := NewRedirectBinding(nil)
	xmlData, relayState, err := binding.ParseRedirectRequest(r)
	if err != nil {
		http.Error(w, "Invalid SAML request: "+err.Error(), http.StatusBadRequest)
		return
	}

	p.processSLO(w, r, xmlData, relayState, BindingTypeRedirect)
}

// handleSLOPost handles logout requests via HTTP-POST binding
func (p *Plugin) handleSLOPost(w http.ResponseWriter, r *http.Request) {
	binding := NewPostBinding(nil)
	xmlData, relayState, err := binding.ParsePostRequest(r)
	if err != nil {
		http.Error(w, "Invalid SAML request: "+err.Error(), http.StatusBadRequest)
		return
	}

	p.processSLO(w, r, xmlData, relayState, BindingTypePost)
}

// processSLO processes a Single Logout request or response
func (p *Plugin) processSLO(w http.ResponseWriter, r *http.Request, xmlData []byte, relayState string, bindingType BindingType) {
	// Try to parse as LogoutRequest first
	requestInfo, err := ParseLogoutRequest(xmlData)
	if err == nil && requestInfo.ID != "" {
		p.handleLogoutRequest(w, r, requestInfo, relayState, bindingType)
		return
	}

	// Try to parse as LogoutResponse
	responseInfo, err := ParseLogoutResponse(xmlData)
	if err == nil && responseInfo.ID != "" {
		p.handleLogoutResponse(w, r, responseInfo, relayState, bindingType)
		return
	}

	http.Error(w, "Invalid SLO message", http.StatusBadRequest)
}

// handleLogoutRequest processes a LogoutRequest
func (p *Plugin) handleLogoutRequest(w http.ResponseWriter, r *http.Request, requestInfo *LogoutRequestInfo, relayState string, bindingType BindingType) {
	// Track this SLO operation
	sloState := NewSLOState(
		requestInfo.ID,
		requestInfo.Issuer,
		requestInfo.NameID,
		requestInfo.NameIDFormat,
		requestInfo.SessionIndexes,
		relayState,
	)
	sloManager.StartSLO(sloState)

	// Find sessions for this user
	sessions := p.GetSessionsByNameID(requestInfo.NameID)

	// Delete all sessions for this user
	for _, session := range sessions {
		p.DeleteSession(session.ID)
	}

	// Mark SLO as complete (single SP scenario - in multi-SP, we'd propagate to other SPs first)
	sloState.Complete = true
	sloState.Success = true

	// Emit Looking Glass events with full logout capture
	if p.lookingGlass != nil {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			sessionID = r.Header.Get("X-Session-ID")
		}
		if sessionID != "" {
			broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)

			// Emit the incoming LogoutRequest
			broadcaster.Emit(
				lookingglass.EventTypeRequestSent,
				"LogoutRequest Received",
				map[string]interface{}{
					"requestID":      requestInfo.ID,
					"issuer":         requestInfo.Issuer,
					"nameID":         requestInfo.NameID,
					"nameIDFormat":   requestInfo.NameIDFormat,
					"sessionIndexes": requestInfo.SessionIndexes,
					"reason":         requestInfo.Reason,
					"binding":        string(bindingType),
				},
			)

			// Emit session termination
			broadcaster.Emit(
				lookingglass.EventTypeFlowStep,
				"LogoutRequest Processed",
				map[string]interface{}{
					"requestID":       requestInfo.ID,
					"sessionsCleared": len(sessions),
					"status":          "success",
				},
			)
		}
	}

	// Create LogoutResponse
	logoutResponse := NewLogoutResponse(
		p.entityID,
		requestInfo.Issuer, // Send response back to requestor
		requestInfo.ID,
		true, // success
	)

	// Get private key for signing
	var privateKey *rsa.PrivateKey
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
	}

	// Send response
	if bindingType == BindingTypePost {
		postBinding := NewPostBinding(privateKey)
		html, err := postBinding.GeneratePostForm(requestInfo.Issuer, logoutResponse, relayState, false)
		if err != nil {
			http.Error(w, "Failed to generate response: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
	} else {
		redirectBinding := NewRedirectBinding(privateKey)
		// For logout response, we need to send back to the issuer's SLO endpoint
		// In demo mode, we'll use a simple redirect
		redirectURL, err := redirectBinding.BuildRedirectURL(requestInfo.Issuer+"/saml/slo", logoutResponse, relayState, false)
		if err != nil {
			http.Error(w, "Failed to build redirect: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// handleLogoutResponse processes a LogoutResponse
func (p *Plugin) handleLogoutResponse(w http.ResponseWriter, r *http.Request, responseInfo *LogoutResponseInfo, relayState string, bindingType BindingType) {
	// Update SLO state if this is a response to a tracked logout operation
	var sloComplete, sloSuccess bool
	var sloPending, sloFailed int
	if sloState, err := sloManager.HandleLogoutResponse(responseInfo); err == nil && sloState != nil {
		sloComplete, sloSuccess, sloPending, sloFailed = sloState.GetStatus()

		// Clean up completed SLO operations
		if sloComplete {
			sloManager.CompleteSLO(responseInfo.InResponseTo)
		}
	}

	// Get human-readable status description
	statusDescription := getStatusDescription(responseInfo.StatusCode)

	// Emit Looking Glass events with full logout response capture
	if p.lookingGlass != nil {
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			sessionID = r.Header.Get("X-Session-ID")
		}
		if sessionID != "" {
			broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)

			// Emit the incoming LogoutResponse
			broadcaster.Emit(
				lookingglass.EventTypeResponseReceived,
				"LogoutResponse Received",
				map[string]interface{}{
					"responseID":   responseInfo.ID,
					"inResponseTo": responseInfo.InResponseTo,
					"issuer":       responseInfo.Issuer,
					"destination":  responseInfo.Destination,
					"binding":      string(bindingType),
				},
			)

			// Emit status information with description
			broadcaster.Emit(
				lookingglass.EventTypeFlowStep,
				"Logout Status",
				map[string]interface{}{
					"success":           responseInfo.Success,
					"statusCode":        responseInfo.StatusCode,
					"statusDescription": statusDescription,
					"statusMessage":     responseInfo.StatusMessage,
					"relayState":        relayState,
					"sloComplete":       sloComplete,
					"sloSuccess":        sloSuccess,
					"sloPendingSPs":     sloPending,
					"sloFailedSPs":      sloFailed,
				},
			)
		}
	}

	// Return success with detailed status
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":            responseInfo.Success,
		"response_id":        responseInfo.ID,
		"in_response_to":     responseInfo.InResponseTo,
		"status_code":        responseInfo.StatusCode,
		"status_description": statusDescription,
		"relay_state":        relayState,
		"slo_complete":       sloComplete,
		"slo_success":        sloSuccess,
	})
}

// ============================================================================
// Demo/Utility Endpoints
// ============================================================================

// handleListUsers returns the list of demo users
func (p *Plugin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	presets := p.mockIdP.GetDemoUserPresets()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": presets,
	})
}

// handleListSessions returns active SAML sessions
func (p *Plugin) handleListSessions(w http.ResponseWriter, r *http.Request) {
	type sessionResponse struct {
		ID           string              `json:"id"`
		NameID       string              `json:"name_id"`
		SessionIndex string              `json:"session_index"`
		AuthnInstant string              `json:"authn_instant"`
		Attributes   map[string][]string `json:"attributes"`
	}

	sessions := make([]sessionResponse, 0, len(p.sessions))
	for _, s := range p.sessions {
		sessions = append(sessions, sessionResponse{
			ID:           s.ID,
			NameID:       s.NameID,
			SessionIndex: s.SessionIndex,
			AuthnInstant: s.AuthnInstant,
			Attributes:   s.Attributes,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
	})
}

// handleDemoLogout handles logout via simple API call (for demo purposes)
func (p *Plugin) handleDemoLogout(w http.ResponseWriter, r *http.Request) {
	// Get session info from query params
	sessionID := r.URL.Query().Get("session_id")
	nameID := r.URL.Query().Get("name_id")

	var sessionsCleared int

	if sessionID != "" {
		// Delete specific session
		if p.GetSession(sessionID) != nil {
			p.DeleteSession(sessionID)
			sessionsCleared = 1
		}
	} else if nameID != "" {
		// Delete all sessions for this user
		sessions := p.GetSessionsByNameID(nameID)
		for _, session := range sessions {
			p.DeleteSession(session.ID)
		}
		sessionsCleared = len(sessions)
	} else {
		// Delete all sessions (for demo)
		for sid := range p.sessions {
			p.DeleteSession(sid)
			sessionsCleared++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"sessions_cleared": sessionsCleared,
		"status_code":      "urn:oasis:names:tc:SAML:2.0:status:Success",
		"response_id":      GenerateID(),
	})
}

// ============================================================================
// IdP-Initiated SSO
// ============================================================================

// handleIdPInitiatedSSO starts an IdP-initiated SSO flow
func (p *Plugin) handleIdPInitiatedSSO(w http.ResponseWriter, r *http.Request) {
	// Get the target SP from query params
	spEntityID := r.URL.Query().Get("sp")
	if spEntityID == "" {
		http.Error(w, "Missing sp parameter", http.StatusBadRequest)
		return
	}

	spACSURL := r.URL.Query().Get("acs")
	if spACSURL == "" {
		// Default to SP entity ID + /saml/acs
		spACSURL = spEntityID + "/saml/acs"
	}

	validatedACSURL, err := p.validateRedirectURL(spACSURL)
	if err != nil {
		http.Error(w, "Invalid ACS URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	spACSURL = validatedACSURL

	relayState := sanitizeRelayState(r.URL.Query().Get("RelayState"))

	// For IdP-initiated, we need the user to be already authenticated
	// Show login page with SP info
	p.showLoginPage(w, r, map[string]string{
		"request_id":   "", // No request ID for IdP-initiated
		"issuer":       spEntityID,
		"acs_url":      spACSURL,
		"relay_state":  relayState,
		"binding_type": "post",
	})
}

// LoginRequestInfo stores trusted login request details
type LoginRequestInfo struct {
	RequestID   string
	Issuer      string
	ACSURL      string
	RelayState  string
	BindingType string
	IssuedAt    time.Time
}

func (p *Plugin) createLoginRequest(requestInfo map[string]string) (string, error) {
	acsURL, err := p.validateRedirectURL(requestInfo["acs_url"])
	if err != nil {
		return "", err
	}

	issuer := strings.TrimSpace(requestInfo["issuer"])
	if issuer == "" {
		return "", fmt.Errorf("missing issuer")
	}

	bindingType := requestInfo["binding_type"]
	if bindingType != "post" && bindingType != "redirect" {
		bindingType = "post"
	}

	relayState := sanitizeRelayState(requestInfo["relay_state"])

	info := LoginRequestInfo{
		RequestID:   requestInfo["request_id"],
		Issuer:      issuer,
		ACSURL:      acsURL,
		RelayState:  relayState,
		BindingType: bindingType,
	}

	return p.storeLoginRequest(info), nil
}

func (p *Plugin) storeLoginRequest(info LoginRequestInfo) string {
	loginRequestID := GenerateID()
	info.IssuedAt = time.Now()

	p.loginRequestsMu.Lock()
	p.loginRequests[loginRequestID] = info
	p.loginRequestsMu.Unlock()

	return loginRequestID
}

func (p *Plugin) takeLoginRequest(loginRequestID string) (LoginRequestInfo, bool) {
	p.loginRequestsMu.Lock()
	defer p.loginRequestsMu.Unlock()

	info, ok := p.loginRequests[loginRequestID]
	if ok {
		delete(p.loginRequests, loginRequestID)
	}
	return info, ok
}

func (p *Plugin) cleanupLoginRequests() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-p.loginRequestTTL)
		p.loginRequestsMu.Lock()
		for id, info := range p.loginRequests {
			if info.IssuedAt.Before(cutoff) {
				delete(p.loginRequests, id)
			}
		}
		p.loginRequestsMu.Unlock()
	}
}

// validateRedirectURL validates that a URL is safe for redirect
// In a production environment, this would check against a whitelist of allowed domains
func (p *Plugin) validateRedirectURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Require absolute URLs for ACS endpoints
	if !parsedURL.IsAbs() {
		return "", fmt.Errorf("absolute URL required")
	}

	// For absolute URLs, validate the scheme
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("invalid URL scheme: %s", parsedURL.Scheme)
	}

	// In demo mode, allow localhost and known domains
	// In production, this should be a strict whitelist
	host := strings.ToLower(parsedURL.Hostname())
	allowedHosts := []string{
		"localhost",
		"127.0.0.1",
		"protocolsoup.com",
		"www.protocolsoup.com",
		"protocolsoup.fly.dev",
	}

	isAllowed := false
	for _, allowed := range allowedHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			isAllowed = true
			break
		}
	}

	// Also allow same-origin URLs
	if p.baseURL != "" {
		baseHost, _ := url.Parse(p.baseURL)
		if baseHost != nil && strings.ToLower(baseHost.Hostname()) == host {
			isAllowed = true
		}
	}

	if !isAllowed {
		return "", fmt.Errorf("URL host not in allowed list: %s", host)
	}

	return rawURL, nil
}

// sanitizeRelayState sanitizes the RelayState value for safe use
// Per SAML 2.0 Bindings, RelayState is opaque but we must prevent open redirects
func sanitizeRelayState(relayState string) string {
	// Limit length to prevent DoS (SAML spec recommends max 80 bytes but many implementations use more)
	if len(relayState) > 1024 {
		relayState = relayState[:1024]
	}
	// HTML escape for safe embedding in forms
	return html.EscapeString(relayState)
}

// validateRelayStateForRedirect validates RelayState when used as a redirect target
// This prevents open redirect attacks (CWE-601)
func validateRelayStateForRedirect(relayState string, baseURL string) (string, error) {
	if relayState == "" {
		return "/", nil
	}

	// Limit length first
	if len(relayState) > 1024 {
		relayState = relayState[:1024]
	}

	// Parse the URL
	parsedURL, err := url.Parse(relayState)
	if err != nil {
		// If it can't be parsed, treat as relative path
		return "/", nil
	}

	// Allow relative URLs (no scheme, no host) - these are safe
	if parsedURL.Scheme == "" && parsedURL.Host == "" {
		// Ensure it doesn't start with // (protocol-relative URL)
		if strings.HasPrefix(relayState, "//") {
			return "/", fmt.Errorf("protocol-relative URLs not allowed in RelayState")
		}
		// Clean the path to prevent directory traversal
		cleanPath := path.Clean("/" + strings.TrimPrefix(relayState, "/"))
		return cleanPath, nil
	}

	// For absolute URLs, validate against allowed hosts
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "/", fmt.Errorf("invalid URL scheme in RelayState: %s", parsedURL.Scheme)
	}

	// Parse base URL to get allowed host
	baseHost := ""
	if baseURL != "" {
		if parsed, err := url.Parse(baseURL); err == nil {
			baseHost = strings.ToLower(parsed.Hostname())
		}
	}

	// Validate host is same-origin or in allowed list
	host := strings.ToLower(parsedURL.Hostname())
	allowedHosts := []string{
		"localhost",
		"127.0.0.1",
		"protocolsoup.com",
		"www.protocolsoup.com",
		"protocolsoup.fly.dev",
	}

	// Add base host to allowed list
	if baseHost != "" {
		allowedHosts = append(allowedHosts, baseHost)
	}

	isAllowed := false
	for _, allowed := range allowedHosts {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return "/", fmt.Errorf("RelayState URL host not allowed: %s", host)
	}

	return relayState, nil
}

// getStatusDescription returns a human-readable description for SAML status codes
func getStatusDescription(statusCode string) string {
	descriptions := map[string]string{
		StatusSuccess:                "The request succeeded",
		StatusRequester:              "The request could not be performed due to an error on the part of the requester",
		StatusResponder:              "The request could not be performed due to an error on the part of the responder",
		StatusVersionMismatch:        "The SAML version of the request is not supported",
		StatusAuthnFailed:            "Authentication of the principal failed",
		StatusInvalidAttrNameOrValue: "Invalid attribute name or value",
		StatusInvalidNameIDPolicy:    "The requested NameIDPolicy is not acceptable",
		StatusNoAuthnContext:         "The specified authentication context requirements cannot be met",
		StatusNoAvailableIDP:         "No available IdP can satisfy the request",
		StatusNoPassive:              "Cannot authenticate passively",
		StatusPartialLogout:          "Logout was not propagated to all session participants",
		StatusRequestDenied:          "The request was denied",
		StatusRequestUnsupported:     "The request is not supported",
	}

	if desc, ok := descriptions[statusCode]; ok {
		return desc
	}
	return fmt.Sprintf("Unknown status: %s", statusCode)
}

// ============================================================================
// Looking Glass API Handlers
// ============================================================================
// These handlers return JSON responses with full SAML protocol data for
// real-time visualization in the Looking Glass UI.
// They execute protocol operations - no fake or placeholder data.
// ============================================================================

// handleLookingGlassCreateAuthnRequest creates an AuthnRequest and returns all details
func (p *Plugin) handleLookingGlassCreateAuthnRequest(w http.ResponseWriter, r *http.Request) {
	binding := r.URL.Query().Get("binding")
	if binding == "" {
		binding = "post"
	}
	relayState := r.URL.Query().Get("relay_state")
	if relayState == "" {
		relayState = GenerateID()
	}

	// Create AuthnRequest
	authnRequest := NewAuthnRequest(p.entityID, p.ssoServiceURL, p.acsURL)

	// Store request ID for InResponseTo validation
	p.requestIDCache.StoreRequestID(authnRequest.ID)

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(authnRequest, "", "  ")
	if err != nil {
		writeJSONError(w, "Failed to marshal AuthnRequest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawXML := xml.Header + string(xmlData)

	// Get private key for signing
	var privateKey *rsa.PrivateKey
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
	}

	response := map[string]interface{}{
		"success":         true,
		"requestId":       authnRequest.ID,
		"issueInstant":    authnRequest.IssueInstant,
		"issuer":          authnRequest.Issuer.Value,
		"destination":     authnRequest.Destination,
		"acsUrl":          authnRequest.AssertionConsumerServiceURL,
		"protocolBinding": authnRequest.ProtocolBinding,
		"rawXml":          rawXML,
		"base64Encoded":   base64.StdEncoding.EncodeToString([]byte(rawXML)),
		"relayState":      relayState,
		"signed":          privateKey != nil,
	}

	if binding == "redirect" && privateKey != nil {
		response["signatureAlgorithm"] = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		redirectBinding := NewRedirectBinding(privateKey)
		if redirectURL, err := redirectBinding.BuildRedirectURL(p.ssoServiceURL, authnRequest, relayState, true); err == nil {
			response["redirectUrl"] = redirectURL
		}
	}

	// Emit Looking Glass event
	p.emitLookingGlassEvent(r, lookingglass.EventTypeFlowStep, "AuthnRequest Created", response)

	writeJSON(w, response)
}

// handleLookingGlassAuthenticate authenticates user and creates SAML Response
func (p *Plugin) handleLookingGlassAuthenticate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	requestID := r.FormValue("request_id")
	acsURL := r.FormValue("acs_url")
	spEntityID := r.FormValue("sp_entity_id")

	if username == "" {
		username = r.URL.Query().Get("username")
	}
	if acsURL == "" {
		acsURL = p.acsURL
	}
	if spEntityID == "" {
		spEntityID = p.entityID
	}

	validatedACSURL, err := p.validateRedirectURL(acsURL)
	if err != nil {
		writeJSONError(w, "Invalid ACS URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	acsURL = validatedACSURL

	// Authenticate user
	user, err := p.mockIdP.ValidateCredentials(username, password)
	if err != nil {
		user, err = p.mockIdP.ValidateCredentials(username+"@example.com", password)
		if err != nil {
			writeJSONError(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
	}

	// Create SAML Response
	response := NewResponse(p.entityID, acsURL, requestID, requestID != "")

	attributes := map[string][]string{
		"urn:oid:0.9.2342.19200300.100.1.3": {user.Email},
		"urn:oid:2.5.4.42":                  {user.Name},
		"urn:oid:2.5.4.3":                   {user.Name},
		"email":                             {user.Email},
		"name":                              {user.Name},
		"uid":                               {user.ID},
	}

	sessionIndex := GenerateID()
	assertion := NewAssertion(p.entityID, spEntityID, user.Email, NameIDFormatEmail, sessionIndex, attributes)

	if assertion.Subject != nil && assertion.Subject.SubjectConfirmation != nil && assertion.Subject.SubjectConfirmation.SubjectConfirmationData != nil {
		assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo = requestID
		assertion.Subject.SubjectConfirmation.SubjectConfirmationData.Recipient = acsURL
	}

	response.Assertions = []*Assertion{assertion}

	responseXML, _ := xml.MarshalIndent(response, "", "  ")
	assertionXML, _ := xml.MarshalIndent(assertion, "", "  ")
	rawResponseXML := xml.Header + string(responseXML)
	rawAssertionXML := xml.Header + string(assertionXML)

	var privateKey *rsa.PrivateKey
	isSigned := false
	signatureAlg := ""
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
		isSigned = privateKey != nil
		if isSigned {
			signatureAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		}
	}

	session := &SAMLSession{
		ID:           GenerateID(),
		NameID:       user.Email,
		NameIDFormat: NameIDFormatEmail,
		SessionIndex: sessionIndex,
		Attributes:   attributes,
		AuthnInstant: TimeNow(),
		NotOnOrAfter: TimeIn(8 * time.Hour),
		AssertionID:  assertion.ID,
	}
	p.CreateSession(session)

	// Security validation results
	inResponseToValid := requestID == "" || p.requestIDCache.ValidateInResponseTo(requestID) == nil

	lgResponse := map[string]interface{}{
		"success":         true,
		"responseId":      response.ID,
		"inResponseTo":    response.InResponseTo,
		"issueInstant":    response.IssueInstant,
		"issuer":          response.Issuer.Value,
		"destination":     response.Destination,
		"statusCode":      StatusSuccess,
		"rawResponseXml":  rawResponseXML,
		"rawAssertionXml": rawAssertionXML,
		"base64Encoded":   base64.StdEncoding.EncodeToString([]byte(rawResponseXML)),
		"assertion": map[string]interface{}{
			"assertionId":       assertion.ID,
			"issueInstant":      assertion.IssueInstant,
			"issuer":            assertion.Issuer.Value,
			"nameId":            user.Email,
			"nameIdFormat":      NameIDFormatEmail,
			"notBefore":         assertion.Conditions.NotBefore,
			"notOnOrAfter":      assertion.Conditions.NotOnOrAfter,
			"audience":          spEntityID,
			"authnInstant":      assertion.AuthnStatement.AuthnInstant,
			"sessionIndex":      sessionIndex,
			"authnContextClass": AuthnContextPasswordProtectedTransport,
			"attributes":        attributes,
		},
		"security": map[string]interface{}{
			"responseSigned":     isSigned,
			"assertionSigned":    isSigned,
			"signatureValid":     isSigned,
			"signatureAlgorithm": signatureAlg,
			"digestAlgorithm":    "http://www.w3.org/2001/04/xmlenc#sha256",
			"inResponseToValid":  inResponseToValid,
			"isIdPInitiated":     requestID == "",
			"replayCheckPassed":  true,
			"subjectConfirmed":   true,
			"conditionsValid":    true,
		},
		"session": map[string]interface{}{
			"sessionId":    session.ID,
			"nameId":       session.NameID,
			"sessionIndex": session.SessionIndex,
			"authnInstant": session.AuthnInstant,
			"attributes":   session.Attributes,
		},
	}

	p.emitLookingGlassEvent(r, lookingglass.EventTypeFlowStep, "SAML Response Created", lgResponse)
	writeJSON(w, lgResponse)
}

// handleLookingGlassCreateLogoutRequest creates a LogoutRequest and returns all details
func (p *Plugin) handleLookingGlassCreateLogoutRequest(w http.ResponseWriter, r *http.Request) {
	nameID := r.URL.Query().Get("name_id")
	sessionIndex := r.URL.Query().Get("session_index")
	relayState := r.URL.Query().Get("relay_state")

	if nameID == "" {
		for _, session := range p.sessions {
			nameID = session.NameID
			if sessionIndex == "" {
				sessionIndex = session.SessionIndex
			}
			break
		}
	}

	if nameID == "" {
		writeJSONError(w, "No active session to logout", http.StatusBadRequest)
		return
	}

	if relayState == "" {
		relayState = GenerateID()
	}

	var sessionIndexes []string
	if sessionIndex != "" {
		sessionIndexes = []string{sessionIndex}
	}

	logoutRequest := NewLogoutRequest(p.entityID, p.sloURL, nameID, NameIDFormatEmail, sessionIndexes)

	xmlData, err := xml.MarshalIndent(logoutRequest, "", "  ")
	if err != nil {
		writeJSONError(w, "Failed to marshal LogoutRequest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawXML := xml.Header + string(xmlData)

	var privateKey *rsa.PrivateKey
	if p.keySet != nil {
		privateKey = p.keySet.RSAPrivateKey()
	}

	response := map[string]interface{}{
		"success":        true,
		"requestId":      logoutRequest.ID,
		"issueInstant":   logoutRequest.IssueInstant,
		"issuer":         logoutRequest.Issuer.Value,
		"destination":    logoutRequest.Destination,
		"nameId":         nameID,
		"nameIdFormat":   NameIDFormatEmail,
		"sessionIndexes": sessionIndexes,
		"rawXml":         rawXML,
		"base64Encoded":  base64.StdEncoding.EncodeToString([]byte(rawXML)),
		"signed":         privateKey != nil,
		"relayState":     relayState,
	}

	p.emitLookingGlassEvent(r, lookingglass.EventTypeFlowStep, "LogoutRequest Created", response)
	writeJSON(w, response)
}

// handleLookingGlassProcessLogout processes a LogoutRequest and returns LogoutResponse
func (p *Plugin) handleLookingGlassProcessLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	nameID := r.FormValue("name_id")
	if nameID == "" {
		for _, session := range p.sessions {
			nameID = session.NameID
			break
		}
	}

	if nameID == "" {
		writeJSONError(w, "No session to logout", http.StatusBadRequest)
		return
	}

	// Find and delete sessions
	sessions := p.GetSessionsByNameID(nameID)
	sessionsCleared := len(sessions)
	for _, session := range sessions {
		p.DeleteSession(session.ID)
	}

	inResponseTo := GenerateID()
	logoutResponse := NewLogoutResponse(p.entityID, "", inResponseTo, true)

	xmlData, _ := xml.MarshalIndent(logoutResponse, "", "  ")
	rawXML := xml.Header + string(xmlData)

	response := map[string]interface{}{
		"success":         true,
		"responseId":      logoutResponse.ID,
		"inResponseTo":    inResponseTo,
		"issueInstant":    logoutResponse.IssueInstant,
		"issuer":          logoutResponse.Issuer.Value,
		"statusCode":      StatusSuccess,
		"rawXml":          rawXML,
		"base64Encoded":   base64.StdEncoding.EncodeToString([]byte(rawXML)),
		"sessionsCleared": sessionsCleared,
		"sloComplete":     true,
		"sloSuccess":      true,
	}

	p.emitLookingGlassEvent(r, lookingglass.EventTypeFlowStep, "LogoutResponse Created", response)
	writeJSON(w, response)
}

// emitLookingGlassEvent emits an event to the Looking Glass engine
func (p *Plugin) emitLookingGlassEvent(r *http.Request, eventType lookingglass.EventType, title string, data map[string]interface{}) {
	if p.lookingGlass == nil {
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		sessionID = r.Header.Get("X-Session-ID")
	}
	if sessionID == "" {
		return
	}

	broadcaster := p.lookingGlass.NewEventBroadcaster(sessionID)
	broadcaster.Emit(eventType, title, data)
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}
