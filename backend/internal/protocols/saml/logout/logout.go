// Package logout processes the SAML Single Logout protocol (SAML Core Section
// 3.7, SAML Profiles Section 4.4) for whichever entity receives a message: the
// SP when the IdP initiates, the IdP when an SP initiates.
package logout

import (
	"errors"
	"fmt"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/session"
)

// defaultRetention bounds how long a processed logout is remembered when the
// LogoutRequest carries no NotOnOrAfter.
const defaultRetention = 10 * time.Minute

// Party is the receiving side of a Single Logout exchange.
type Party struct {
	EntityID string
	Location string           // this party's SingleLogoutService URL
	Peer     *metadata.Peer   // the sender, as published in its metadata
	Sessions *session.Store   // sessions shared with the peer
	Pending  *session.Pending // LogoutRequests this party sent

	// LoggedOut, when set, records each processed LogoutRequest so that late
	// assertions for the same session are refused (SAML Core Section 3.7.3.1).
	LoggedOut *session.LogoutRecords

	// RequireSessionIndex is set on the IdP: a session participant "MUST
	// include at least one <SessionIndex> element" (SAML Profiles Section
	// 4.4.4.1, Errata E38).
	RequireSessionIndex bool
}

// Result reports what a Single Logout step did.
type Result struct {
	Report        *binding.Report    `json:"validation"`
	SessionsEnded []*session.Session `json:"sessionsEnded,omitempty"`
	StatusCode    string             `json:"statusCode,omitempty"`
	InResponseTo  string             `json:"inResponseTo,omitempty"`
}

// ProcessRequest validates a received <LogoutRequest> (SAML Core Section
// 3.7.1), ends the matching sessions, and builds the <LogoutResponse> to
// return to the requester on the same binding.
func ProcessRequest(msg *binding.Received, party Party) (*binding.Outbound, *Result, error) {
	result := &Result{Report: &binding.Report{}}
	report := result.Report
	fail := func(name, detail, reference string) (*binding.Outbound, *Result, error) {
		report.Add(name, false, detail, reference)
		return nil, result, errors.New(detail)
	}

	if msg.Param != binding.ParamSAMLRequest || !message.IsElement(msg.Root, message.NamespaceSAMLp, "LogoutRequest") {
		return fail("Message type", "expected a <samlp:LogoutRequest> as SAMLRequest", "SAML Core Section 3.7.1")
	}
	trusted, authReport, err := binding.Authenticate(msg, party.Peer.SigningCerts, party.Location)
	report.Merge(authReport)
	if err != nil {
		return nil, result, err
	}
	// "The <LogoutRequest> message MUST be signed if the HTTP POST or
	// Redirect binding is used" (SAML Profiles Section 4.4.3.1).
	if !report.Signed {
		return fail("Signature", "unsigned <LogoutRequest> over a front-channel binding", "SAML Profiles Section 4.4.3.1")
	}

	var request message.LogoutRequest
	if err := message.Unmarshal(trusted, &request); err != nil {
		return fail("LogoutRequest", "could not decode <samlp:LogoutRequest>: "+err.Error(), "SAML Core Section 3.7.1")
	}
	if request.Version != "2.0" {
		return fail("Version", fmt.Sprintf("Version is %q, not 2.0", request.Version), "SAML Core Section 3.2.1")
	}
	if !message.IsEntityIssuer(request.Issuer, party.Peer.EntityID) {
		return fail("Issuer", fmt.Sprintf("Issuer %q is not %q with Format omitted or entity", message.IssuerValue(request.Issuer), party.Peer.EntityID), "SAML Profiles Section 4.4.4.1")
	}
	report.Add("Issuer", true, party.Peer.EntityID, "SAML Profiles Section 4.4.4.1")
	if request.NameID == nil || request.NameID.Value == "" {
		return fail("NameID", "<LogoutRequest> names no principal", "SAML Core Section 3.7.1")
	}
	if party.RequireSessionIndex && len(request.SessionIndexes) == 0 {
		return fail("SessionIndex", "a session participant's <LogoutRequest> MUST include at least one <SessionIndex>", "SAML Profiles Section 4.4.4.1 (Errata E38)")
	}

	ep, ok := party.Peer.SingleLogoutService(msg.Binding)
	if !ok {
		return fail("SingleLogoutService", fmt.Sprintf("%s metadata publishes no SingleLogoutService for %s", party.Peer.EntityID, msg.Binding), "SAML Metadata Section 2.4.2")
	}
	responseLocation := ep.Location
	if ep.ResponseLocation != "" {
		responseLocation = ep.ResponseLocation
	}

	status := message.StatusInfo{Code: message.StatusSuccess}
	until := time.Now().Add(defaultRetention)
	if request.NotOnOrAfter != "" {
		expires, err := message.ParseTime(request.NotOnOrAfter)
		switch {
		case err != nil:
			return fail("NotOnOrAfter", err.Error(), "SAML Core Section 3.7.1")
		case !time.Now().Before(expires.Add(message.ClockSkew)):
			status = message.StatusInfo{Code: message.StatusRequester, SubCode: message.StatusRequestDenied, Message: "LogoutRequest NotOnOrAfter " + request.NotOnOrAfter + " has passed"}
			report.Add("NotOnOrAfter", false, status.Message, "SAML Core Section 3.7.1")
		default:
			until = expires.Add(message.ClockSkew)
			report.Add("NotOnOrAfter", true, "request has not expired", "SAML Core Section 3.7.1")
		}
	}

	if status.Code == message.StatusSuccess {
		if party.LoggedOut != nil {
			party.LoggedOut.Add(session.LogoutRecord{NameID: request.NameID.Value, SessionIndexes: request.SessionIndexes, Until: until})
		}
		result.SessionsEnded = party.Sessions.RemoveMatching(party.Peer.EntityID, request.NameID.Value, request.SessionIndexes)
		report.Add("Sessions", true, fmt.Sprintf("ended %d session(s) for %s", len(result.SessionsEnded), request.NameID.Value), "SAML Core Section 3.7.3.1")
	}
	result.StatusCode = status.Code
	result.InResponseTo = request.ID

	response := message.BuildLogoutResponse(party.EntityID, responseLocation, request.ID, status)
	return &binding.Outbound{
		Element:    response,
		Location:   responseLocation,
		Binding:    msg.Binding,
		Param:      binding.ParamSAMLResponse,
		RelayState: msg.RelayState,
	}, result, nil
}

// ProcessResponse matches a received <LogoutResponse> (SAML Core Section
// 3.7.2) to the <LogoutRequest> this party sent.
func ProcessResponse(msg *binding.Received, party Party) (*Result, error) {
	result := &Result{Report: &binding.Report{}}
	report := result.Report
	fail := func(name, detail, reference string) (*Result, error) {
		report.Add(name, false, detail, reference)
		return result, errors.New(detail)
	}

	if msg.Param != binding.ParamSAMLResponse || !message.IsElement(msg.Root, message.NamespaceSAMLp, "LogoutResponse") {
		return fail("Message type", "expected a <samlp:LogoutResponse> as SAMLResponse", "SAML Core Section 3.7.2")
	}
	trusted, authReport, err := binding.Authenticate(msg, party.Peer.SigningCerts, party.Location)
	report.Merge(authReport)
	if err != nil {
		return result, err
	}
	// "The <LogoutResponse> message MUST be signed if the HTTP POST or
	// Redirect binding is used" (SAML Profiles Section 4.4.3.4).
	if !report.Signed {
		return fail("Signature", "unsigned <LogoutResponse> over a front-channel binding", "SAML Profiles Section 4.4.3.4")
	}

	var response message.LogoutResponse
	if err := message.Unmarshal(trusted, &response); err != nil {
		return fail("LogoutResponse", "could not decode <samlp:LogoutResponse>: "+err.Error(), "SAML Core Section 3.7.2")
	}
	if !message.IsEntityIssuer(response.Issuer, party.Peer.EntityID) {
		return fail("Issuer", fmt.Sprintf("Issuer %q is not %q with Format omitted or entity", message.IssuerValue(response.Issuer), party.Peer.EntityID), "SAML Profiles Section 4.4.4.2")
	}
	report.Add("Issuer", true, party.Peer.EntityID, "SAML Profiles Section 4.4.4.2")

	pending, ok := party.Pending.Take(response.InResponseTo)
	if !ok {
		return fail("InResponseTo", fmt.Sprintf("InResponseTo %q matches no outstanding LogoutRequest", response.InResponseTo), "SAML Core Section 3.2.2")
	}
	report.Add("InResponseTo", true, "matches LogoutRequest "+pending.ID, "SAML Core Section 3.2.2")
	if pending.RelayState != msg.RelayState {
		return fail("RelayState", fmt.Sprintf("RelayState %q differs from the %q sent with the LogoutRequest", msg.RelayState, pending.RelayState), binding.RelayStateSection(msg.Binding))
	}
	report.Add("RelayState", true, "matches the value sent with the LogoutRequest", binding.RelayStateSection(msg.Binding))

	result.InResponseTo = response.InResponseTo
	result.StatusCode = response.Status.StatusCode.Value
	report.Add("Status", response.Status.StatusCode.Value == message.StatusSuccess, response.Status.Describe(), "SAML Core Section 3.7.2")
	if response.Status.StatusCode.Value != message.StatusSuccess {
		return result, errors.New("logout was not fully successful: " + response.Status.Describe())
	}
	return result, nil
}
