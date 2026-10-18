package idp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/session"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// PendingLogin is an accepted <AuthnRequest>, or an IdP-initiated start. When
// Reuse is set, the IdP answers it from its existing authentication session;
// otherwise it waits for the principal to authenticate.
type PendingLogin struct {
	ID         string
	RequestID  string // empty for an unsolicited response
	ACSURL     string
	RelayState string
	ForceAuthn bool
	Reuse      *AuthnSession
	Validation *binding.Report
	IssuedAt   time.Time
}

type loginStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	pending map[string]*PendingLogin
}

func newLoginStore(ttl time.Duration) *loginStore {
	return &loginStore{ttl: ttl, pending: map[string]*PendingLogin{}}
}

func (s *loginStore) store(login *PendingLogin) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, existing := range s.pending {
		if now.Sub(existing.IssuedAt) > s.ttl {
			delete(s.pending, id)
		}
	}
	login.ID = message.GenerateID()
	login.IssuedAt = now
	s.pending[login.ID] = login
}

// get returns the pending login with id without consuming it, so a mistyped
// password can be retried.
func (s *loginStore) get(id string) (*PendingLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	login, ok := s.pending[id]
	if !ok || time.Since(login.IssuedAt) > s.ttl {
		delete(s.pending, id)
		return nil, false
	}
	return login, true
}

func (s *loginStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id)
}

// RequestError is an <AuthnRequest> the IdP will not satisfy. When the SP is
// identified, the IdP answers with a SAML error <Response>: "If the identity
// provider cannot or will not satisfy the request, it MUST respond with a
// <Response> message containing an appropriate error status code or codes"
// (SAML Profiles Section 4.1.4.1). Without a trustworthy destination the
// request is discarded instead.
type RequestError struct {
	Status     message.StatusInfo
	Response   *binding.Outbound // nil when the request is discarded
	Validation *binding.Report
}

func (e *RequestError) Error() string {
	return e.Status.Message
}

// AcceptAuthnRequest validates a received <AuthnRequest>, resolves the
// assertion consumer service from the SP's metadata, and decides whether the
// principal's existing authentication session (existing, which may be nil)
// can answer it.
func (idp *IdentityProvider) AcceptAuthnRequest(ctx context.Context, msg *binding.Received, existing *AuthnSession) (*PendingLogin, error) {
	report := &binding.Report{}
	discard := func(name, detail, reference string) (*PendingLogin, error) {
		report.Add(name, false, detail, reference)
		return nil, &RequestError{Status: message.StatusInfo{Code: message.StatusRequester, Message: detail}, Validation: report}
	}

	if msg.Param != binding.ParamSAMLRequest || !message.IsElement(msg.Root, message.NamespaceSAMLp, "AuthnRequest") {
		return discard("Message type", "expected a <samlp:AuthnRequest> as SAMLRequest", "SAML Core Section 3.4.1")
	}
	// The unauthenticated request is read only to find which SP sent it; its
	// content "MUST NOT be trusted except as advisory" until verified
	// (SAML Profiles Section 4.1.4.1).
	var advisory message.AuthnRequest
	if err := message.Unmarshal(msg.Root, &advisory); err != nil {
		return discard("AuthnRequest", "could not decode <samlp:AuthnRequest>: "+err.Error(), "SAML Core Section 3.4.1")
	}
	if !message.IsEntityIssuer(advisory.Issuer, idp.cfg.SPEntityID) {
		return discard("Issuer", fmt.Sprintf("Issuer %q is not a service provider this IdP knows (Format must be omitted or entity)", message.IssuerValue(advisory.Issuer)), "SAML Profiles Section 4.1.4.1")
	}
	meta, err := idp.spMetadata(ctx)
	if err != nil {
		return discard("SP metadata", err.Error(), "SAML Metadata Section 4.1")
	}
	defaultACS, ok := meta.DefaultACS()
	if !ok {
		return discard("AssertionConsumerService", "SP metadata publishes no HTTP-POST AssertionConsumerService", "SAML Metadata Section 2.4.4")
	}

	trusted, authReport, err := binding.Authenticate(msg, meta.SigningCerts, idp.cfg.SSOURL)
	report.Merge(authReport)
	if err != nil {
		// Core Section 3.2.1: on an invalid signature the responder "MUST NOT
		// rely on the contents of the request"; on a Destination mismatch "the
		// request MUST be discarded".
		return nil, &RequestError{Status: message.StatusInfo{Code: message.StatusRequester, Message: err.Error()}, Validation: report}
	}

	reject := func(status message.StatusInfo, name, reference string) (*PendingLogin, error) {
		report.Add(name, false, status.Message, reference)
		response := message.BuildResponse(idp.cfg.EntityID, defaultACS.Location, advisory.ID, status, nil)
		return nil, &RequestError{
			Status:     status,
			Validation: report,
			Response: &binding.Outbound{
				Element: response, Location: defaultACS.Location, Binding: message.BindingHTTPPost,
				Param: binding.ParamSAMLResponse, RelayState: msg.RelayState,
			},
		}
	}

	// The SP publishes AuthnRequestsSigned="true" and this IdP publishes
	// WantAuthnRequestsSigned="true": "an identity provider that receives an
	// unsigned <samlp:AuthnRequest> message from a service provider whose
	// metadata contains this attribute with a value of true MUST return a SAML
	// error response and MUST NOT fulfill the request" (SAML Metadata Section
	// 2.4.4, Errata E7).
	if !report.Signed {
		return reject(message.StatusInfo{Code: message.StatusRequester, SubCode: message.StatusRequestDenied, Message: "AuthnRequest is unsigned; the SP's metadata declares AuthnRequestsSigned=\"true\""},
			"Signature", "SAML Metadata Section 2.4.4 (Errata E7)")
	}

	var request message.AuthnRequest
	if err := message.Unmarshal(trusted, &request); err != nil {
		return discard("AuthnRequest", "could not decode verified <samlp:AuthnRequest>: "+err.Error(), "SAML Core Section 3.4.1")
	}
	if request.Version != "2.0" {
		return reject(message.StatusInfo{Code: message.StatusVersionMismatch, Message: fmt.Sprintf("Version %q is not supported", request.Version)}, "Version", "SAML Core Section 3.2.1")
	}
	report.Add("Issuer", true, idp.cfg.SPEntityID, "SAML Profiles Section 4.1.4.1")

	// "Whether the request is signed or not, the identity provider MUST ensure
	// that any <AssertionConsumerServiceURL> or <AssertionConsumerServiceIndex>
	// elements in the request are verified as belonging to the service
	// provider" (SAML Profiles Section 4.1.4.1).
	acs := defaultACS
	switch {
	case request.ProtocolBinding != "" && request.ProtocolBinding != message.BindingHTTPPost:
		return reject(message.StatusInfo{Code: message.StatusResponder, SubCode: message.StatusRequestUnsupported, Message: "ProtocolBinding " + request.ProtocolBinding + " is not supported; this IdP delivers responses over HTTP-POST"},
			"ProtocolBinding", "SAML Profiles Section 4.1.2")
	case request.AssertionConsumerServiceURL != "":
		if acs, ok = meta.ACSByURL(request.AssertionConsumerServiceURL); !ok {
			return reject(message.StatusInfo{Code: message.StatusRequester, Message: "AssertionConsumerServiceURL " + request.AssertionConsumerServiceURL + " is not an HTTP-POST endpoint in the SP's metadata"},
				"AssertionConsumerServiceURL", "SAML Profiles Section 4.1.4.1")
		}
	case request.AssertionConsumerServiceIndex != "":
		if acs, ok = meta.ACSByIndex(request.AssertionConsumerServiceIndex); !ok {
			return reject(message.StatusInfo{Code: message.StatusRequester, Message: "AssertionConsumerServiceIndex " + request.AssertionConsumerServiceIndex + " is not an HTTP-POST endpoint in the SP's metadata"},
				"AssertionConsumerServiceIndex", "SAML Profiles Section 4.1.4.1")
		}
	}
	report.Add("AssertionConsumerService", true, acs.Location+" is published in the SP's metadata", "SAML Profiles Section 4.1.4.1")

	if policy := request.NameIDPolicy; policy != nil && policy.Format != "" &&
		policy.Format != message.NameIDFormatEmail && policy.Format != message.NameIDFormatUnspecified {
		return reject(message.StatusInfo{Code: message.StatusRequester, SubCode: message.StatusInvalidNameIDPolicy, Message: "NameIDPolicy Format " + policy.Format + " is not supported"},
			"NameIDPolicy", "SAML Core Section 3.4.1.1")
	}
	login := &PendingLogin{
		RequestID:  request.ID,
		ACSURL:     acs.Location,
		RelayState: msg.RelayState,
		ForceAuthn: request.ForceAuthn,
		Validation: report,
	}
	switch {
	// IsPassive: "the identity provider and the user agent itself MUST NOT
	// visibly take control of the user interface from the requester and
	// interact with the presenter in a noticeable fashion." With ForceAuthn as
	// well, "the identity provider MUST NOT freshly authenticate the presenter
	// unless the constraints of IsPassive can be met" (SAML Core Section 3.4.1).
	case request.IsPassive && existing == nil:
		return reject(message.StatusInfo{Code: message.StatusResponder, SubCode: message.StatusNoPassive, Message: "IsPassive was requested and the principal has no authentication session at this IdP"},
			"IsPassive", "SAML Core Section 3.4.1")
	case request.IsPassive && request.ForceAuthn:
		return reject(message.StatusInfo{Code: message.StatusResponder, SubCode: message.StatusNoPassive, Message: "ForceAuthn and IsPassive were both requested; fresh authentication would require interacting with the principal"},
			"IsPassive", "SAML Core Section 3.4.1")
	case existing != nil && request.ForceAuthn:
		report.Add("ForceAuthn", true, "ForceAuthn=\"true\": the IdP \"MUST authenticate the presenter directly rather than rely on a previous security context\"", "SAML Core Section 3.4.1")
	case existing != nil:
		login.Reuse = existing
		report.Add("Authentication", true, fmt.Sprintf("existing IdP session for %s, authenticated at %s, is reused", existing.User.Email, message.FormatTime(existing.AuthnInstant)), "SAML Profiles Section 4.1.3.4")
		return login, nil
	}
	idp.logins.store(login)
	return login, nil
}

// StartUnsolicited prepares an IdP-initiated login to the SP's default
// assertion consumer service (SAML Profiles Section 4.1.5), answered from the
// existing authentication session when there is one.
func (idp *IdentityProvider) StartUnsolicited(ctx context.Context, relayState string, existing *AuthnSession) (*PendingLogin, error) {
	if err := binding.CheckRelayState(relayState); err != nil {
		return nil, err
	}
	meta, err := idp.spMetadata(ctx)
	if err != nil {
		return nil, err
	}
	acs, ok := meta.DefaultACS()
	if !ok {
		return nil, errors.New("SP metadata publishes no HTTP-POST AssertionConsumerService")
	}
	login := &PendingLogin{ACSURL: acs.Location, RelayState: relayState, Reuse: existing}
	if existing == nil {
		idp.logins.store(login)
	}
	return login, nil
}

// FailLogin answers a pending login the principal did not complete with an
// error <Response>: "Regardless of the success or failure of the
// <AuthnRequest>, the identity provider SHOULD produce an HTTP response to the
// user agent containing a <Response> message" (SAML Profiles Section 4.1.3.5).
func (idp *IdentityProvider) FailLogin(login *PendingLogin, status message.StatusInfo) *binding.Outbound {
	idp.logins.remove(login.ID)
	response := message.BuildResponse(idp.cfg.EntityID, login.ACSURL, login.RequestID, status, nil)
	return &binding.Outbound{
		Element: response, Location: login.ACSURL, Binding: message.BindingHTTPPost,
		Param: binding.ParamSAMLResponse, RelayState: login.RelayState,
	}
}

// IssueResponse builds the signed <Assertion> for a user authenticated at
// authnInstant and the <Response> that carries it over HTTP-POST. The Response
// itself is signed when the binding serializes it.
func (idp *IdentityProvider) IssueResponse(login *PendingLogin, user *models.User, authnInstant time.Time) (*binding.Outbound, *session.Session, error) {
	idp.logins.remove(login.ID)
	sessionIndex := message.GenerateID()
	assertion := message.BuildAssertion(message.AssertionParams{
		Issuer:       idp.cfg.EntityID,
		NameID:       user.Email,
		NameIDFormat: message.NameIDFormatEmail,
		Recipient:    login.ACSURL,
		InResponseTo: login.RequestID,
		Audience:     idp.cfg.SPEntityID,
		SessionIndex: sessionIndex,
		AuthnInstant: authnInstant,
		Lifetime:     assertionLifetime,
		Attributes:   releasedAttributes(user),
	})
	// The SP publishes WantAssertionsSigned="true", so the assertion carries
	// its own signature in addition to the Response's.
	if err := xmldsig.SignEnveloped(assertion, idp.cfg.Credentials); err != nil {
		return nil, nil, err
	}
	response := message.BuildResponse(idp.cfg.EntityID, login.ACSURL, login.RequestID, message.StatusInfo{Code: message.StatusSuccess}, assertion)

	sess := &session.Session{
		PeerEntityID: idp.cfg.SPEntityID,
		NameID:       user.Email,
		NameIDFormat: message.NameIDFormatEmail,
		SessionIndex: sessionIndex,
		AuthnInstant: message.FormatTime(authnInstant),
		AssertionID:  assertion.SelectAttrValue("ID", ""),
	}
	idp.sessions.Add(sess)
	return &binding.Outbound{
		Element: response, Location: login.ACSURL, Binding: message.BindingHTTPPost,
		Param: binding.ParamSAMLResponse, RelayState: login.RelayState,
	}, sess, nil
}
