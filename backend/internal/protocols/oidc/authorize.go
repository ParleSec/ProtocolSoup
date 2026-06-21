package oidc

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// oidcSessionCookie names the OP's end-user authentication session. It backs
// prompt and max_age handling (OpenID Connect Core 1.0 Section 3.1.2.1): the OP
// must be able to tell whether an End-User is already authenticated and how
// long ago, without that there is no honest way to answer prompt=none or
// max_age.
const oidcSessionCookie = "ps_oidc_auth"

// acrSingleFactorLogin is the Authentication Context Class Reference for the
// only authentication this OP performs: a single-factor username/password login.
// OIDC Core 1.0 Section 2 permits an absolute URI as the acr value, so this
// custom URI honestly names the real context. It is returned truthfully and is
// never set to a requested assurance level (for example "1" or "2") the OP does
// not actually satisfy, and it is advertised in acr_values_supported.
const acrSingleFactorLogin = "urn:protocolsoup:ac:password"

// amrSingleFactorLogin is the Authentication Methods References list (RFC 8176)
// for the single-factor login the OP performs ("pwd").
var amrSingleFactorLogin = []string{"pwd"}

// authParams holds the authorization request parameters needed to build a
// response. Building is identical whether issuance happens directly (existing
// session or prompt=none) or after an interactive login, so both paths funnel
// through the same struct to avoid divergent behaviour.
type authParams struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ResponseType        string
	ResponseMode        string // effective mode: "query" or "fragment"
	// Claims is the raw OIDC claims request parameter (OpenID Connect Core 1.0
	// Section 5.5), carried through issuance so individually requested claims are
	// honoured.
	Claims string
}

// defaultResponseMode returns the default response mode for a response type per
// OAuth 2.0 Multiple Response Type Encoding Practices Section 2.1: the code
// flow defaults to query, every response type that returns a token or id_token
// from the authorization endpoint defaults to fragment.
func defaultResponseMode(responseType string) string {
	if responseType == "code" {
		return "query"
	}
	return "fragment"
}

// resolveResponseMode validates the requested response_mode against the
// response_type and returns the effective mode. It returns an OAuth error code
// and description when the combination is invalid. An empty requested mode
// yields the default for the response type.
//
// query MUST NOT be used for response types that return tokens in the front
// channel: a token in the query string leaks through Referer headers, browser
// history, and server logs (OAuth 2.0 Multiple Response Type Encoding Practices
// Section 2.1, OAuth 2.0 Security BCP Section 4.1).
//
// form_post is valid for every response type: the response parameters are
// delivered in an HTTP POST body rather than a URL, so there is no
// front-channel leakage even when tokens are returned (OAuth 2.0 Form Post
// Response Mode, Section 2).
func resolveResponseMode(responseType, requested string) (mode, errCode, errDesc string) {
	def := defaultResponseMode(responseType)
	if requested == "" {
		return def, "", ""
	}
	switch requested {
	case "query":
		if responseType != "code" {
			return "", "invalid_request", "response_mode=query is not permitted for response types that return tokens in the front channel"
		}
		return "query", "", ""
	case "fragment":
		return "fragment", "", ""
	case "form_post":
		return "form_post", "", ""
	default:
		return "", "invalid_request", "unsupported response_mode (supported: query, fragment, form_post)"
	}
}

// errorResponseModeForMissingType selects the channel for delivering an error
// when response_type is missing or unrecognised, so no per-response-type default
// applies. An explicitly requested form_post or fragment is honoured (both are
// safe for any response type), so a client receives the error in the channel it
// asked for (OAuth 2.0 Form Post Response Mode; OAuth 2.0 Multiple Response Type
// Encoding Section 2). Otherwise the error is delivered in the query, the RFC
// 6749 default, which is safe because an error response carries no token.
func errorResponseModeForMissingType(requested string) string {
	switch requested {
	case "form_post":
		return "form_post"
	case "fragment":
		return "fragment"
	default:
		return "query"
	}
}

// requestObjectResponseHints extracts only the response_mode and state from a
// by-value request object (the JWT passed in the request parameter), WITHOUT
// verifying its signature and without using any other claim. The OP does not
// support request objects and rejects them with request_not_supported, but that
// rejection is an authorization error response that must be returned in the
// client's requested response_mode and must echo state (RFC 6749 Section
// 4.1.2.1, OIDC Core 1.0 Section 6.2). For a by-value request object the
// suite carries these response-delivery values inside the JWT, so they are read
// from it purely to deliver the rejection in the correct channel. Any parse
// failure yields empty strings, so the caller falls back to the top-level
// request values.
func requestObjectResponseHints(raw string) (responseMode, state string) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", ""
	}
	var claims struct {
		ResponseMode string `json:"response_mode"`
		State        string `json:"state"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ""
	}
	return claims.ResponseMode, claims.State
}

// promptValues splits the space-delimited prompt parameter.
func promptValues(prompt string) []string {
	return strings.Fields(prompt)
}

func containsValue(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// validatePrompt enforces OpenID Connect Core 1.0 Section 3.1.2.1: if prompt
// contains none it MUST NOT contain any other value. Unknown values are
// ignored per the same section.
func validatePrompt(values []string) (errCode, errDesc string) {
	if containsValue(values, "none") && len(values) > 1 {
		return "invalid_request", "prompt=none must not be combined with any other prompt value (OIDC Core 1.0 Section 3.1.2.1)"
	}
	return "", ""
}

// parseMaxAge parses the optional max_age parameter. It returns (seconds, true,
// "") on a valid non-negative integer, (0, false, "") when absent, or an error
// description when malformed (OIDC Core 1.0 Section 3.1.2.1 defines max_age as
// a non-negative integer number of seconds).
func parseMaxAge(raw string) (seconds int, present bool, errDesc string) {
	if raw == "" {
		return 0, false, ""
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, false, "max_age must be a non-negative integer number of seconds"
	}
	return n, true, ""
}

// reauthRequired decides whether an existing session must be re-authenticated
// given the prompt and max_age parameters.
func reauthRequired(prompts []string, maxAge int, maxAgePresent bool, authTime time.Time, now time.Time) bool {
	if containsValue(prompts, "login") {
		return true
	}
	if maxAgePresent {
		if now.Sub(authTime) > time.Duration(maxAge)*time.Second {
			return true
		}
	}
	return false
}

// buildErrorRedirect constructs the redirect target for an authorization error
// in the given response mode, preserving any pre-existing query on the
// redirect_uri and always echoing state when present (RFC 6749 Section
// 4.1.2.1).
func buildErrorRedirect(redirectURI, responseMode, state, errorCode, errorDescription string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	params := url.Values{}
	params.Set("error", errorCode)
	if errorDescription != "" {
		params.Set("error_description", errorDescription)
	}
	if state != "" {
		params.Set("state", state)
	}
	if responseMode == "fragment" {
		u.Fragment = params.Encode()
	} else {
		existing := u.Query()
		for key := range params {
			existing.Set(key, params.Get(key))
		}
		u.RawQuery = existing.Encode()
	}
	return u.String(), nil
}

// redirectAuthError delivers an authorization error to the client by
// redirecting to the validated redirect_uri, in the correct response channel,
// echoing state. This is mandatory once client_id and redirect_uri are known to
// be valid (RFC 6749 Section 4.1.2.1, OpenID Connect Core 1.0 Section 3.1.2.6).
func (p *Plugin) redirectAuthError(w http.ResponseWriter, r *http.Request, redirectURI, responseType, responseMode, state, errorCode, errorDescription string) {
	mode := responseMode
	if mode == "" {
		mode = defaultResponseMode(responseType)
	}
	// form_post errors are delivered in an HTTP POST body, not a redirect, so
	// the same response mode is honoured for errors as for success (OAuth 2.0
	// Form Post Response Mode, Section 2).
	if mode == "form_post" {
		params := url.Values{}
		params.Set("error", errorCode)
		if errorDescription != "" {
			params.Set("error_description", errorDescription)
		}
		if state != "" {
			params.Set("state", state)
		}
		p.writeFormPost(w, redirectURI, params)
		return
	}
	target, err := buildErrorRedirect(redirectURI, mode, state, errorCode, errorDescription)
	if err != nil {
		// A malformed redirect_uri should already have been rejected before
		// this point; fail closed without redirecting.
		p.writeAuthorizationErrorPage(w, http.StatusBadRequest, "invalid_request", "Malformed redirect_uri")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// formPostField is one hidden input in a Form Post response document.
type formPostField struct {
	Name  string
	Value string
}

// formPostResponseTemplate renders the OAuth 2.0 Form Post Response Mode
// document: a self-submitting HTML form that POSTs the authorization response
// parameters to the redirect URI. html/template escapes the action URL and each
// field value in their respective HTML contexts, so a parameter value can never
// break out of the markup (defence in depth; values are OP-generated). The form
// auto-submits on load, with a no-script submit button as a fallback.
var formPostResponseTemplate = template.Must(template.New("form_post").Parse(
	`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">` +
		`<title>Submit This Form</title></head>` +
		`<body onload="document.forms[0].submit()">` +
		`<form method="post" action="{{.Action}}">` +
		`{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}"/>{{end}}` +
		`<noscript><button type="submit">Continue</button></noscript>` +
		`</form></body></html>`))

// writeFormPost delivers authorization response parameters to redirectURI using
// OAuth 2.0 Form Post Response Mode (Section 2): a self-submitting HTML form
// POSTs the parameters as an application/x-www-form-urlencoded body. The
// redirect URI has already been validated against the client's registered set,
// so it is a trusted form action. Parameters are emitted in a stable order, and
// the page is marked non-cacheable because it may carry credentials (RFC 6749
// Section 5.1).
func (p *Plugin) writeFormPost(w http.ResponseWriter, redirectURI string, params url.Values) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fields := make([]formPostField, 0, len(keys))
	for _, k := range keys {
		fields = append(fields, formPostField{Name: k, Value: params.Get(k)})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = formPostResponseTemplate.Execute(w, struct {
		Action string
		Fields []formPostField
	}{Action: redirectURI, Fields: fields})
}

// writeAuthorizationErrorPage informs the user agent of an authorization error
// WITHOUT redirecting. It is used only for errors in client_id or redirect_uri,
// where redirecting would be unsafe (RFC 6749 Section 4.1.2.1: the OP MUST NOT
// automatically redirect to an unverified URI).
func (p *Plugin) writeAuthorizationErrorPage(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	body := `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">` +
		`<title>Authorization Error</title></head><body>` +
		`<h1>Authorization request rejected</h1>` +
		`<p>The OpenID Provider cannot continue and will not redirect, because the ` +
		`request did not present a valid client_id and redirect_uri.</p>` +
		`<p><strong>error:</strong> ` + htmlEscape(errorCode) + `</p>` +
		`<p><strong>error_description:</strong> ` + htmlEscape(description) + `</p>` +
		`</body></html>`
	_, _ = w.Write([]byte(body))
}

// currentAuthSession returns the authenticated end-user session if the request
// carries a valid, unexpired session cookie.
func (p *Plugin) currentAuthSession(r *http.Request) (*models.Session, bool) {
	cookie, err := r.Cookie(oidcSessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	return p.mockIdP.GetSession(cookie.Value)
}

// establishAuthSession records a fresh end-user authentication and sets the
// session cookie. The cookie is SameSite=None; Secure so it is sent on the
// cross-site top-level navigations that the OIDC authorization flow relies on,
// and is only transmitted over TLS.
func (p *Plugin) establishAuthSession(w http.ResponseWriter, userID, clientID string) *models.Session {
	session := p.mockIdP.CreateSession(userID, clientID)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcSessionCookie,
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})
	return session
}
