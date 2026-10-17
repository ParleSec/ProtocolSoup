package idp

import (
	"errors"
	"html/template"
	"net/http"
	"sort"

	"github.com/ParleSec/ProtocolSoup/internal/gel"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/logout"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/go-chi/chi/v5"
)

const (
	loginCookieName = "saml_idp_login"
	loginCookiePath = "/saml/idp"
)

// Routes mounts the IdP's endpoints; the plugin mounts them under /saml/idp.
func (idp *IdentityProvider) Routes(r chi.Router) {
	slo := idp.sloService()
	r.Get("/metadata", idp.handleMetadata)
	r.Get("/sso", idp.handleSSO)  // HTTP-Redirect binding
	r.Post("/sso", idp.handleSSO) // HTTP-POST binding
	r.Post("/login", idp.handleLogin)
	r.Get("/initiate", idp.handleInitiate)
	r.Get("/logout", idp.handleLogout)
	r.Method(http.MethodGet, "/slo", slo)
	r.Method(http.MethodPost, "/slo", slo)
}

func (idp *IdentityProvider) sloService() logout.Service {
	return logout.Service{
		Role:            logout.RoleSessionAuthority,
		EntityID:        idp.cfg.EntityID,
		Credentials:     idp.cfg.Credentials,
		Events:          idp.cfg.Events,
		HandleRequest:   idp.HandleLogoutRequest,
		ConsumeResponse: idp.ConsumeLogoutResponse,
	}
}

func (idp *IdentityProvider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata.Write(w, idp.Metadata())
}

// handleSSO is the SingleSignOnService for HTTP-Redirect (GET) and HTTP-POST
// (POST).
func (idp *IdentityProvider) handleSSO(w http.ResponseWriter, r *http.Request) {
	msg, err := binding.Decode(r)
	if err != nil {
		http.Error(w, "Invalid SAML message: "+err.Error(), http.StatusBadRequest)
		return
	}
	login, err := idp.AcceptAuthnRequest(r.Context(), msg)
	var rejected *RequestError
	if errors.As(err, &rejected) {
		data := map[string]interface{}{
			"binding": msg.Binding, "samlXML": string(msg.XML), "status": rejected.Status, "validation": rejected.Validation,
		}
		annotation := binding.Reference("Request processing", "The IdP answers a request it will not satisfy with an error <Response>, or discards it when it cannot be trusted.", "SAML Profiles Section 4.1.4.1")
		if rejected.Response == nil {
			idp.cfg.Events.Emit(r, lookingglass.EventTypeSecurityWarning, "AuthnRequest discarded", data, annotation)
			http.Error(w, "AuthnRequest discarded: "+rejected.Error(), http.StatusBadRequest)
			return
		}
		wire, err := binding.Send(w, r, rejected.Response, idp.cfg.Credentials)
		if err != nil {
			http.Error(w, "Failed to send error Response: "+err.Error(), http.StatusInternalServerError)
			return
		}
		data["destination"] = rejected.Response.Location
		data["samlResponseXML"] = string(wire)
		idp.cfg.Events.Emit(r, lookingglass.EventTypeSecurityWarning, "AuthnRequest rejected with an error Response", data, annotation)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	idp.cfg.Events.Emit(r, lookingglass.EventTypeFlowStep, "AuthnRequest accepted", map[string]interface{}{
		"binding": msg.Binding, "samlXML": string(msg.XML), "relayState": msg.RelayState,
		"acsUrl": login.ACSURL, "validation": login.Validation,
	}, binding.Reference("AuthnRequest", "Verified against the SP's metadata before the principal is asked to authenticate.", "SAML Profiles Section 4.1.4.1"))
	idp.showLoginPage(w, r, login)
}

// handleInitiate starts IdP-initiated SSO to the registered SP.
func (idp *IdentityProvider) handleInitiate(w http.ResponseWriter, r *http.Request) {
	login, err := idp.StartUnsolicited(r.Context(), r.URL.Query().Get("RelayState"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	idp.cfg.Events.Emit(r, lookingglass.EventTypeFlowStep, "IdP-initiated SSO started", map[string]interface{}{
		"acsUrl": login.ACSURL, "relayState": login.RelayState,
	}, binding.Reference("Unsolicited Response", "The IdP sends a <Response> without a preceding <AuthnRequest>, so it carries no InResponseTo.", "SAML Profiles Section 4.1.5"))
	idp.showLoginPage(w, r, login)
}

// handleLogin authenticates the principal and posts the signed <Response> to
// the SP's assertion consumer service.
func (idp *IdentityProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "No pending SAML login at this IdP", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookieName, Path: loginCookiePath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	login, ok := idp.logins.take(cookie.Value)
	if !ok {
		http.Error(w, "SAML login request expired or unknown", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	user, err := idp.Authenticate(r.PostForm.Get("email"), r.PostForm.Get("password"))
	if err != nil {
		http.Error(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	out, _, err := idp.IssueResponse(login, user)
	if err != nil {
		http.Error(w, "Failed to issue Response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	wire, err := binding.Send(w, r, out, idp.cfg.Credentials)
	if err != nil {
		http.Error(w, "Failed to send Response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	idp.cfg.Events.Emit(r, lookingglass.EventTypeTokenIssued, "SAML Response issued", map[string]interface{}{
		"destination": out.Location, "relayState": out.RelayState, "samlResponseXML": string(wire),
	}, binding.Reference("Response", "Sent through the user agent with the HTTP-POST binding; the assertion and the Response are each signed.", "SAML Profiles Section 4.1.4.5"))
}

// handleLogout starts IdP-initiated Single Logout for one IdP session.
func (idp *IdentityProvider) handleLogout(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	out, err := idp.NewLogoutRequest(r.Context(), r.URL.Query().Get("session_id"), binding.FromQuery(r, message.BindingHTTPRedirect), relayState)
	idp.sloService().SendRequest(w, r, out, err)
}

var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAML Identity Provider - ProtocolSoup</title>
<style>{{.CSS}}</style>
</head>
<body>
<main>
<h1>SAML Identity Provider</h1>
<p class="muted">{{.IdP}}</p>
<div class="panel">
<dl>
<dt>Service provider</dt><dd>{{.SP}}</dd>
<dt>Assertion consumer service</dt><dd>{{.ACS}}</dd>
{{if .RequestID}}<dt>AuthnRequest</dt><dd>{{.RequestID}}</dd>{{else}}<dt>AuthnRequest</dt><dd>none: unsolicited Response (SAML Profiles Section 4.1.5)</dd>{{end}}
</dl>
</div>
<p class="status status-info">{{.IconInfo}}<span>Mock IdP demo users. Never enter real credentials.</span></p>
<h2>Sign in as a demo user</h2>
{{range .Users}}<form method="post" action="{{$.Action}}">
<input type="hidden" name="email" value="{{.Email}}">
<input type="hidden" name="password" value="{{.Password}}">
<button type="submit">{{.Name}} <span class="user-email">{{.Email}}</span></button>
</form>
{{end}}<h2>Or enter credentials</h2>
<form method="post" action="{{.Action}}">
<label for="email">Email</label><input id="email" type="email" name="email" autocomplete="username" required>
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="current-password" required>
<p><button type="submit">Sign in</button></p>
</form>
</main>
</body>
</html>`))

func (idp *IdentityProvider) showLoginPage(w http.ResponseWriter, r *http.Request, login *PendingLogin) {
	http.SetCookie(w, &http.Cookie{
		Name: loginCookieName, Value: login.ID, Path: loginCookiePath,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	type demoUser struct{ Name, Email, Password string }
	var users []demoUser
	for _, u := range idp.cfg.Users.ListUsers() {
		users = append(users, demoUser{Name: u.Name, Email: u.Email, Password: u.Password})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = loginPageTemplate.Execute(w, map[string]interface{}{
		"CSS":       gel.PageCSS(),
		"IconInfo":  gel.IconInfo,
		"IdP":       idp.cfg.EntityID,
		"SP":        idp.cfg.SPEntityID,
		"ACS":       login.ACSURL,
		"RequestID": login.RequestID,
		"Action":    binding.WithSession(r, idp.cfg.LoginURL),
		"Users":     users,
	})
}
