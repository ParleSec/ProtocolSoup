package logout

import (
	"context"
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
)

// Role names which side of the Single Logout Profile an entity plays.
type Role string

const (
	// RoleSessionParticipant is the service provider.
	RoleSessionParticipant Role = "SP"
	// RoleSessionAuthority is the identity provider.
	RoleSessionAuthority Role = "IdP"
)

// Service is one entity's SingleLogoutService and logout initiator, over the
// front-channel HTTP-Redirect and HTTP-POST bindings.
type Service struct {
	Role            Role
	EntityID        string
	Credentials     *xmldsig.Credentials
	Events          binding.Events
	HandleRequest   func(context.Context, *binding.Received) (*binding.Outbound, *Result, error)
	ConsumeResponse func(context.Context, *binding.Received) (*Result, error)
}

// SAML Profiles sections for each step, by who takes it (Section 4.4.3).
func (s Service) initiateReference() string {
	if s.Role == RoleSessionAuthority {
		return "SAML Profiles Section 4.4.3.3"
	}
	return "SAML Profiles Section 4.4.3.1"
}

func (s Service) respondReference() string {
	if s.Role == RoleSessionAuthority {
		return "SAML Profiles Section 4.4.3.5"
	}
	return "SAML Profiles Section 4.4.3.4"
}

func (s Service) responseReceivedReference() string {
	if s.Role == RoleSessionAuthority {
		return "SAML Profiles Section 4.4.3.4"
	}
	return "SAML Profiles Section 4.4.3.5"
}

// SendRequest sends the signed <LogoutRequest> this entity built to start
// Single Logout.
func (s Service) SendRequest(w http.ResponseWriter, r *http.Request, out *binding.Outbound, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	wire, err := binding.Send(w, r, out, s.Credentials)
	if err != nil {
		http.Error(w, "Failed to send LogoutRequest: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.Events.Emit(r, lookingglass.EventTypeRequestSent, "LogoutRequest sent by "+string(s.Role), map[string]interface{}{
		"binding": out.Binding, "destination": out.Location, "relayState": out.RelayState, "samlXML": string(wire),
	}, binding.Reference("LogoutRequest", "\"The <LogoutRequest> message MUST be signed if the HTTP POST or Redirect binding is used.\"", s.initiateReference()))
}

// ServeHTTP is the SingleLogoutService. A <LogoutRequest> is processed and
// answered with a signed <LogoutResponse> on the same binding; a
// <LogoutResponse> ends the exchange this entity started, and the outcome is
// shown to the user agent.
func (s Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	msg, err := binding.Decode(r)
	if err != nil {
		http.Error(w, "Invalid SAML message: "+err.Error(), http.StatusBadRequest)
		return
	}
	if msg.Param == binding.ParamSAMLResponse {
		result, err := s.ConsumeResponse(r.Context(), msg)
		s.writeOutcome(w, r, "LogoutResponse processed by "+string(s.Role), s.responseReceivedReference(), msg, result, err)
		return
	}
	out, result, err := s.HandleRequest(r.Context(), msg)
	if out == nil {
		s.writeOutcome(w, r, "LogoutRequest rejected by "+string(s.Role), "SAML Core Section 3.7.3", msg, result, err)
		return
	}
	wire, err := binding.Send(w, r, out, s.Credentials)
	if err != nil {
		http.Error(w, "Failed to send LogoutResponse: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.Events.Emit(r, lookingglass.EventTypeFlowStep, "LogoutRequest processed by "+string(s.Role), map[string]interface{}{
		"binding":           msg.Binding,
		"samlXML":           string(msg.XML),
		"validation":        result.Report,
		"sessionsEnded":     result.SessionsEnded,
		"statusCode":        result.StatusCode,
		"destination":       out.Location,
		"logoutResponseXML": string(wire),
	}, binding.Reference("LogoutResponse", "The recipient ended the matching sessions and returned a signed LogoutResponse on the same binding.", s.respondReference()))
}

func (s Service) writeOutcome(w http.ResponseWriter, r *http.Request, title, reference string, msg *binding.Received, result *Result, err error) {
	status := http.StatusOK
	eventType := lookingglass.EventTypeFlowStep
	if err != nil {
		status = http.StatusForbidden
		eventType = lookingglass.EventTypeSecurityWarning
	}
	outcome := binding.NewOutcome("slo", s.EntityID, title, reference, msg, result.Report, err)
	outcome.Details = map[string]interface{}{
		"statusCode":    result.StatusCode,
		"inResponseTo":  result.InResponseTo,
		"sessionsEnded": result.SessionsEnded,
	}
	s.Events.WriteOutcome(w, r, eventType, status, outcome)
}
