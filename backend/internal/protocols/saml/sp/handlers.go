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
	r.Get("/metadata", sp.handleMetadata)
	r.Get("/login", sp.handleLogin)
	r.Post("/acs", sp.handleACS) // HTTP-POST only (SAML Profiles Section 4.1.2)
	r.Get("/logout", sp.handleLogout)
	r.Get("/slo", sp.handleSLO)
	r.Post("/slo", sp.handleSLO)
}

func (sp *ServiceProvider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata.Write(w, sp.Metadata())
}

// handleLogin starts SP-initiated SSO: it sends a signed <AuthnRequest> to the
// IdP over HTTP-Redirect (default) or HTTP-POST.
func (sp *ServiceProvider) handleLogin(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	out, err := sp.NewAuthnRequest(r.Context(), binding.FromQuery(r, message.BindingHTTPRedirect), relayState)
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

// handleACS is the HTTP-POST assertion consumer service.
func (sp *ServiceProvider) handleACS(w http.ResponseWriter, r *http.Request) {
	msg, err := binding.DecodePost(r)
	if err != nil {
		binding.WriteJSON(w, http.StatusBadRequest, map[string]interface{}{"success": false, "error": "Invalid SAML message: " + err.Error()})
		return
	}
	result, err := sp.ConsumeResponse(r.Context(), msg)
	status := http.StatusOK
	eventType := lookingglass.EventTypeTokenValidated
	if err != nil {
		status = http.StatusForbidden
		eventType = lookingglass.EventTypeSecurityWarning
	}
	sp.cfg.Events.Emit(r, eventType, "SAML Response processed at ACS", map[string]interface{}{
		"samlResponseXML": string(msg.XML), "relayState": msg.RelayState, "validation": result.Report,
	}, binding.Reference("Response processing", "Every check below ran on the received Response; any failure rejects it.", "SAML Profiles Section 4.1.4.3"))
	body := map[string]interface{}{
		"success":    err == nil,
		"validation": result.Report,
		"relayState": result.RelayState,
		"session":    result.Session,
	}
	if err != nil {
		body["error"] = err.Error()
	}
	binding.WriteJSON(w, status, body)
}

// handleLogout starts SP-initiated Single Logout for one SP session.
func (sp *ServiceProvider) handleLogout(w http.ResponseWriter, r *http.Request) {
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	out, err := sp.NewLogoutRequest(r.Context(), r.URL.Query().Get("session_id"), binding.FromQuery(r, message.BindingHTTPRedirect), relayState)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := binding.Send(w, r, out, sp.cfg.Credentials); err != nil {
		http.Error(w, "Failed to send LogoutRequest: "+err.Error(), http.StatusInternalServerError)
	}
}

// handleSLO is the SP's SingleLogoutService.
func (sp *ServiceProvider) handleSLO(w http.ResponseWriter, r *http.Request) {
	msg, err := binding.Decode(r)
	if err != nil {
		http.Error(w, "Invalid SAML message: "+err.Error(), http.StatusBadRequest)
		return
	}
	if msg.Param == binding.ParamSAMLResponse {
		result, err := sp.ConsumeLogoutResponse(r.Context(), msg)
		logout.WriteResult(w, r, sp.cfg.Events, "LogoutResponse processed by SP", msg, result, err)
		return
	}
	out, result, err := sp.HandleLogoutRequest(r.Context(), msg)
	if out == nil {
		logout.WriteResult(w, r, sp.cfg.Events, "LogoutRequest rejected by SP", msg, result, err)
		return
	}
	if _, err := binding.Send(w, r, out, sp.cfg.Credentials); err != nil {
		http.Error(w, "Failed to send LogoutResponse: "+err.Error(), http.StatusInternalServerError)
	}
}
