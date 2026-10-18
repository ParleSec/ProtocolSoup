package sp

import (
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/logout"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/go-chi/chi/v5"
)

// Routes mounts the SP's endpoints; the plugin mounts them under /saml/sp.
func (sp *ServiceProvider) Routes(r chi.Router) {
	slo := sp.sloService()
	r.Get("/metadata", sp.handleMetadata)
	r.Get("/login", sp.handleLogin)
	r.Post("/acs", sp.handleACS) // HTTP-POST only (SAML Profiles Section 4.1.2)
	r.Get("/logout", sp.handleLogout)
	r.Method(http.MethodGet, "/slo", slo)
	r.Method(http.MethodPost, "/slo", slo)
}

func (sp *ServiceProvider) sloService() logout.Service {
	return logout.Service{
		Role:            logout.RoleSessionParticipant,
		EntityID:        sp.cfg.EntityID,
		Credentials:     sp.cfg.Credentials,
		Events:          sp.cfg.Events,
		HandleRequest:   sp.HandleLogoutRequest,
		ConsumeResponse: sp.ConsumeLogoutResponse,
	}
}

func (sp *ServiceProvider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata.Write(w, sp.Metadata())
}

// handleLogin starts SP-initiated SSO: it sends a signed <AuthnRequest> to the
// IdP over HTTP-Redirect (default) or HTTP-POST. force_authn=true and
// is_passive=true set ForceAuthn and IsPassive on the request.
func (sp *ServiceProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	query := r.URL.Query()
	out, err := sp.NewAuthnRequest(r.Context(), binding.FromQuery(r, message.BindingHTTPRedirect), relayState,
		query.Get("force_authn") == "true", query.Get("is_passive") == "true")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	wire, err := binding.Send(w, r, out, sp.cfg.Credentials)
	if err != nil {
		http.Error(w, "Failed to send AuthnRequest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sp.cfg.Events.Emit(r, lookingglass.EventTypeRequestSent, "AuthnRequest sent", map[string]interface{}{
		"binding": out.Binding, "destination": out.Location, "relayState": relayState, "samlXML": string(wire),
	}, binding.Reference("AuthnRequest", "Signed because this SP publishes AuthnRequestsSigned=\"true\".", "SAML Profiles Section 4.1.4.1"))
}

// handleACS is the HTTP-POST assertion consumer service. It answers with the
// outcome page: what arrived, every check that ran, and the session created.
func (sp *ServiceProvider) handleACS(w http.ResponseWriter, r *http.Request) {
	msg, err := binding.DecodePost(r)
	if err != nil {
		http.Error(w, "Invalid SAML message: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := sp.ConsumeResponse(r.Context(), msg)
	status, eventType := http.StatusOK, lookingglass.EventTypeTokenValidated
	if err != nil {
		status, eventType = http.StatusForbidden, lookingglass.EventTypeSecurityWarning
	}
	outcome := binding.NewOutcome("sso", sp.cfg.EntityID, "SAML Response processed at the assertion consumer service", "SAML Profiles Section 4.1.4.3", msg, result.Report, err)
	details := map[string]interface{}{"unsolicited": result.Unsolicited}
	if result.Response != nil {
		details["statusCode"] = result.Response.Status.StatusCode.Value
		details["inResponseTo"] = result.Response.InResponseTo
	}
	if result.Session != nil {
		details["session"] = result.Session
	}
	outcome.Details = details
	sp.cfg.Events.WriteOutcome(w, r, eventType, status, outcome)
}

// handleLogout starts SP-initiated Single Logout for one SP session.
func (sp *ServiceProvider) handleLogout(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	out, err := sp.NewLogoutRequest(r.Context(), r.URL.Query().Get("session_id"), binding.FromQuery(r, message.BindingHTTPRedirect), relayState)
	sp.sloService().SendRequest(w, r, out, err)
}
