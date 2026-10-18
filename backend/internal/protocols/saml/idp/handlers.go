package idp

import (
	"errors"
	"net/http"

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
// (POST). With a live authentication session the IdP answers at once;
// otherwise it asks the principal to sign in.
func (idp *IdentityProvider) handleSSO(w http.ResponseWriter, r *http.Request) {
	msg, err := binding.Decode(r)
	if err != nil {
		http.Error(w, "Invalid SAML message: "+err.Error(), http.StatusBadRequest)
		return
	}
	existing, _ := idp.authn.lookup(r)
	login, err := idp.AcceptAuthnRequest(r.Context(), msg, existing)
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
		"acsUrl": login.ACSURL, "forceAuthn": login.ForceAuthn, "validation": login.Validation,
	}, binding.Reference("AuthnRequest", "Verified against the SP's metadata before the principal is identified.", "SAML Profiles Section 4.1.4.1"))
	idp.continueLogin(w, r, login)
}

// handleInitiate starts IdP-initiated SSO to the registered SP.
func (idp *IdentityProvider) handleInitiate(w http.ResponseWriter, r *http.Request) {
	existing, _ := idp.authn.lookup(r)
	login, err := idp.StartUnsolicited(r.Context(), r.URL.Query().Get("RelayState"), existing)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	idp.cfg.Events.Emit(r, lookingglass.EventTypeFlowStep, "IdP-initiated SSO started", map[string]interface{}{
		"acsUrl": login.ACSURL, "relayState": login.RelayState,
	}, binding.Reference("Unsolicited Response", "The IdP sends a <Response> without a preceding <AuthnRequest>, so it carries no InResponseTo.", "SAML Profiles Section 4.1.5"))
	idp.continueLogin(w, r, login)
}

// continueLogin answers from the existing authentication session, or shows
// the sign-in page.
func (idp *IdentityProvider) continueLogin(w http.ResponseWriter, r *http.Request, login *PendingLogin) {
	if login.Reuse == nil {
		idp.showLoginPage(w, r, login, http.StatusOK, "")
		return
	}
	out, _, err := idp.IssueResponse(login, login.Reuse.User, login.Reuse.AuthnInstant)
	if err != nil {
		http.Error(w, "Failed to issue Response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	wire, err := binding.Send(w, r, out, idp.cfg.Credentials)
	if err != nil {
		http.Error(w, "Failed to send Response: "+err.Error(), http.StatusInternalServerError)
		return
	}
	idp.cfg.Events.Emit(r, lookingglass.EventTypeTokenIssued, "SAML Response issued from the existing IdP session", map[string]interface{}{
		"user":            login.Reuse.User.Email,
		"authnInstant":    message.FormatTime(login.Reuse.AuthnInstant),
		"destination":     out.Location,
		"relayState":      out.RelayState,
		"samlResponseXML": string(wire),
	}, binding.Reference("Single sign-on", "The principal already authenticated at this IdP, so no credentials are asked for; the assertion's AuthnInstant is that earlier authentication.", "SAML Profiles Section 4.1.3.4"))
}

// handleLogin authenticates the principal, starts the IdP authentication
// session, and posts the signed <Response> to the SP's assertion consumer
// service. Cancel answers with an AuthnFailed error <Response>.
func (idp *IdentityProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(loginCookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "No pending SAML login at this IdP", http.StatusBadRequest)
		return
	}
	login, ok := idp.logins.get(cookie.Value)
	if !ok {
		http.Error(w, "SAML login request expired or unknown", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	if r.PostForm.Get("user_action") == "cancel" {
		clearLoginCookie(w)
		out := idp.FailLogin(login, message.StatusInfo{Code: message.StatusResponder, SubCode: message.StatusAuthnFailed, Message: "The principal cancelled authentication at the IdP"})
		wire, err := binding.Send(w, r, out, idp.cfg.Credentials)
		if err != nil {
			http.Error(w, "Failed to send error Response: "+err.Error(), http.StatusInternalServerError)
			return
		}
		idp.cfg.Events.Emit(r, lookingglass.EventTypeSecurityWarning, "Authentication cancelled; error Response sent", map[string]interface{}{
			"destination": out.Location, "relayState": out.RelayState, "samlResponseXML": string(wire),
		}, binding.Reference("Response", "\"Regardless of the success or failure of the <AuthnRequest>, the identity provider SHOULD produce an HTTP response to the user agent containing a <Response> message\".", "SAML Profiles Section 4.1.3.5"))
		return
	}

	user, err := idp.Authenticate(r.PostForm.Get("email"), r.PostForm.Get("password"))
	if err != nil {
		idp.showLoginPage(w, r, login, http.StatusUnauthorized, "Invalid email or password")
		return
	}
	clearLoginCookie(w)
	authn := idp.authn.start(w, user)
	idp.cfg.Events.Emit(r, lookingglass.EventTypeFlowStep, "Principal authenticated; IdP session started", map[string]interface{}{
		"user": user.Email, "authnInstant": message.FormatTime(authn.AuthnInstant), "sessionLifetime": authnLifetime.String(),
	}, binding.Reference("Identity Provider Identifies Principal", "Later AuthnRequests reuse this session unless they carry ForceAuthn=\"true\".", "SAML Profiles Section 4.1.3.4"))

	out, _, err := idp.IssueResponse(login, user, authn.AuthnInstant)
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

func clearLoginCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: loginCookieName, Path: loginCookiePath, MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
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
