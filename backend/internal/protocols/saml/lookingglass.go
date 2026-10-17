package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/idp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/logout"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
)

// The Looking Glass endpoints run the real IdP and SP code paths in one
// request so the current Looking Glass executors can show the messages and
// every validation result. The messages do not travel through the browser
// here; the binding endpoints in packages idp and sp are where they do. Both
// roles are reached only through their exported APIs.

func writeError(w http.ResponseWriter, status int, msg string, extra map[string]interface{}) {
	body := map[string]interface{}{"success": false, "error": msg}
	for k, v := range extra {
		body[k] = v
	}
	binding.WriteJSON(w, status, body)
}

// deliverInProcess encodes out exactly as binding.Send would put it on the
// wire and decodes it as the recipient's endpoint would, returning the
// received message and the URL or XML that carried it.
func deliverInProcess(out *binding.Outbound, creds *xmldsig.Credentials) (*binding.Received, string, []byte, error) {
	if out.Binding == message.BindingHTTPRedirect {
		location, err := binding.RedirectURL(out.Location, out.Param, out.Element, out.RelayState, creds)
		if err != nil {
			return nil, "", nil, err
		}
		parsed, err := url.Parse(location)
		if err != nil {
			return nil, "", nil, err
		}
		msg, err := binding.DecodeRedirect(parsed.RawQuery)
		if err != nil {
			return nil, "", nil, err
		}
		return msg, location, msg.XML, nil
	}
	wire, err := binding.SignedPostXML(out.Element, creds)
	if err != nil {
		return nil, "", nil, err
	}
	msg, err := binding.PostMessage(out.Param, wire, out.RelayState)
	return msg, "", wire, err
}

// receivedFromForm reads a request message passed to a Looking Glass endpoint
// either as the HTTP-Redirect URL (redirect_url) or as HTTP-POST form values
// (SAMLRequest, RelayState). It returns nil when neither is present.
func receivedFromForm(r *http.Request) (*binding.Received, error) {
	if redirect := r.PostForm.Get("redirect_url"); redirect != "" {
		parsed, err := url.Parse(redirect)
		if err != nil {
			return nil, errors.New("redirect_url is not a URL")
		}
		return binding.DecodeRedirect(parsed.RawQuery)
	}
	if encoded := r.PostForm.Get(binding.ParamSAMLRequest); encoded != "" {
		xmlBytes, err := binding.DecodeBase64(encoded)
		if err != nil {
			return nil, errors.New("SAMLRequest is not valid base64")
		}
		return binding.PostMessage(binding.ParamSAMLRequest, xmlBytes, r.PostForm.Get(binding.ParamRelayState))
	}
	return nil, nil
}

// ============================================================================
// Demo helpers
// ============================================================================

func (p *Plugin) handleListUsers(w http.ResponseWriter, r *http.Request) {
	binding.WriteJSON(w, http.StatusOK, map[string]interface{}{"users": p.mockIdP.GetDemoUserPresets()})
}

// handleListSessions lists the security contexts each role currently holds.
func (p *Plugin) handleListSessions(w http.ResponseWriter, r *http.Request) {
	binding.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"sp":  p.sp.Sessions(),
		"idp": p.idp.Sessions(),
	})
}

// ============================================================================
// Single Sign-On
// ============================================================================

func (p *Plugin) handleLookingGlassCreateAuthnRequest(w http.ResponseWriter, r *http.Request) {
	bindingID := binding.FromQuery(r, message.BindingHTTPPost)
	relayState := r.URL.Query().Get("relay_state")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	out, err := p.sp.NewAuthnRequest(r.Context(), bindingID, relayState)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	_, location, xmlBytes, err := deliverInProcess(out, p.sp.Credentials())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	body := map[string]interface{}{
		"success":            true,
		"binding":            bindingID,
		"requestId":          out.Element.SelectAttrValue("ID", ""),
		"issueInstant":       out.Element.SelectAttrValue("IssueInstant", ""),
		"issuer":             p.sp.EntityID(),
		"destination":        out.Location,
		"acsUrl":             p.sp.ACSURL(),
		"protocolBinding":    message.BindingHTTPPost,
		"relayState":         relayState,
		"signed":             true,
		"signatureAlgorithm": xmldsig.SigAlgRSASHA256,
		"rawXml":             string(xmlBytes),
	}
	if location != "" {
		body["redirectUrl"] = location
	} else {
		body["base64Encoded"] = base64.StdEncoding.EncodeToString(xmlBytes)
	}
	p.events.Emit(r, lookingglass.EventTypeFlowStep, "AuthnRequest created", body,
		binding.Reference("AuthnRequest", "Built and signed by the SP for the IdP's SingleSignOnService from the IdP metadata.", "SAML Core Section 3.4.1"))
	binding.WriteJSON(w, http.StatusOK, body)
}

func (p *Plugin) handleLookingGlassAuthenticate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form data", nil)
		return
	}
	ctx := r.Context()

	request, err := receivedFromForm(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	var login *idp.PendingLogin
	if request != nil {
		login, err = p.idp.AcceptAuthnRequest(ctx, request)
	} else {
		login, err = p.idp.StartUnsolicited(ctx, r.PostForm.Get(binding.ParamRelayState))
	}

	var out *binding.Outbound
	var idpValidation *binding.Report
	var rejected *idp.RequestError
	switch {
	case errors.As(err, &rejected) && rejected.Response != nil:
		out, idpValidation = rejected.Response, rejected.Validation
	case errors.As(err, &rejected):
		writeError(w, http.StatusBadRequest, "AuthnRequest discarded: "+rejected.Error(), map[string]interface{}{"idpValidation": rejected.Validation})
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	default:
		idpValidation = login.Validation
		user, aerr := p.idp.Authenticate(r.PostForm.Get("username"), r.PostForm.Get("password"))
		if aerr != nil {
			writeError(w, http.StatusUnauthorized, "Authentication failed: "+aerr.Error(), nil)
			return
		}
		if out, _, err = p.idp.IssueResponse(login, user); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error(), nil)
			return
		}
	}

	msg, _, wire, err := deliverInProcess(out, p.idp.Credentials())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	result, consumeErr := p.sp.ConsumeResponse(ctx, msg)

	body := map[string]interface{}{
		"success":        consumeErr == nil,
		"responseId":     out.Element.SelectAttrValue("ID", ""),
		"inResponseTo":   out.Element.SelectAttrValue("InResponseTo", ""),
		"issueInstant":   out.Element.SelectAttrValue("IssueInstant", ""),
		"issuer":         p.idp.EntityID(),
		"destination":    out.Location,
		"relayState":     out.RelayState,
		"rawResponseXml": string(wire),
		"base64Encoded":  base64.StdEncoding.EncodeToString(wire),
		"idpValidation":  idpValidation,
		"validation":     result.Report,
		"session":        result.Session,
		"unsolicited":    result.Unsolicited,
	}
	if result.Response != nil {
		body["statusCode"] = result.Response.Status.StatusCode.Value
	}
	if a := result.Assertion; a != nil {
		body["assertion"] = map[string]interface{}{
			"assertionId":       a.ID,
			"issueInstant":      a.IssueInstant,
			"issuer":            message.IssuerValue(a.Issuer),
			"nameId":            a.Subject.NameID.Value,
			"nameIdFormat":      a.Subject.NameID.Format,
			"notBefore":         a.Conditions.NotBefore,
			"notOnOrAfter":      a.Conditions.NotOnOrAfter,
			"audience":          a.Conditions.AudienceRestrictions[0].Audiences,
			"authnInstant":      a.AuthnStatements[0].AuthnInstant,
			"sessionIndex":      a.AuthnStatements[0].SessionIndex,
			"authnContextClass": a.AuthnStatements[0].AuthnContextClassRef,
			"attributes":        a.Attributes(),
			"rawXml":            firstAssertionXML(msg.Root),
		}
	}
	status := http.StatusOK
	if consumeErr != nil {
		body["error"] = consumeErr.Error()
		status = http.StatusForbidden
	}
	p.events.Emit(r, lookingglass.EventTypeTokenValidated, "SAML Response processed by SP", body,
		binding.Reference("Response processing", "The SP verified the IdP's signatures with the certificate from the IdP metadata and applied every Web Browser SSO check.", "SAML Profiles Section 4.1.4.3"))
	binding.WriteJSON(w, status, body)
}

func firstAssertionXML(response *etree.Element) string {
	if el := message.Child(response, message.NamespaceSAML, "Assertion"); el != nil {
		if b, err := message.Serialize(el); err == nil {
			return string(b)
		}
	}
	return ""
}

// ============================================================================
// Single Logout
// ============================================================================

// handleLookingGlassCreateLogoutRequest builds a signed <LogoutRequest> from
// the SP (initiator=sp, default) or the IdP (initiator=idp) for one of that
// role's sessions.
func (p *Plugin) handleLookingGlassCreateLogoutRequest(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	relayState := q.Get("relay_state")
	if relayState == "" {
		relayState = message.GenerateID()
	}
	initiatorIsIdP := q.Get("initiator") == "idp"
	sessions, creds := p.sp.Sessions(), p.sp.Credentials()
	if initiatorIsIdP {
		sessions, creds = p.idp.Sessions(), p.idp.Credentials()
	}
	sessionID := q.Get("session_id")
	if sessionID == "" && len(sessions) > 0 {
		sessionID = sessions[0].ID
	}
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "No active session to log out", nil)
		return
	}

	bindingID := binding.FromQuery(r, message.BindingHTTPPost)
	var out *binding.Outbound
	var err error
	if initiatorIsIdP {
		out, err = p.idp.NewLogoutRequest(r.Context(), sessionID, bindingID, relayState)
	} else {
		out, err = p.sp.NewLogoutRequest(r.Context(), sessionID, bindingID, relayState)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}
	var request message.LogoutRequest
	_ = message.Unmarshal(out.Element, &request)
	_, location, xmlBytes, err := deliverInProcess(out, creds)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	body := map[string]interface{}{
		"success":        true,
		"binding":        bindingID,
		"requestId":      request.ID,
		"issueInstant":   request.IssueInstant,
		"issuer":         message.IssuerValue(request.Issuer),
		"destination":    request.Destination,
		"nameId":         request.NameID.Value,
		"nameIdFormat":   request.NameID.Format,
		"sessionIndexes": request.SessionIndexes,
		"rawXml":         string(xmlBytes),
		"signed":         true,
		"relayState":     relayState,
	}
	if location != "" {
		body["redirectUrl"] = location
	} else {
		body["base64Encoded"] = base64.StdEncoding.EncodeToString(xmlBytes)
	}
	p.events.Emit(r, lookingglass.EventTypeFlowStep, "LogoutRequest created", body,
		binding.Reference("LogoutRequest", "Signed, because a front-channel LogoutRequest MUST be signed.", "SAML Profiles Section 4.4.3.1"))
	binding.WriteJSON(w, http.StatusOK, body)
}

// handleLookingGlassProcessLogout delivers a signed <LogoutRequest> to the
// role it names as Destination, then hands that role's <LogoutResponse> back
// to the requester.
func (p *Plugin) handleLookingGlassProcessLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid form data", nil)
		return
	}
	msg, err := receivedFromForm(r)
	if err != nil || msg == nil {
		writeError(w, http.StatusBadRequest, "send the LogoutRequest as redirect_url or as SAMLRequest", nil)
		return
	}
	ctx := r.Context()

	var out *binding.Outbound
	var responder *logout.Result
	var responderCreds *xmldsig.Credentials
	var consume func(*binding.Received) (*logout.Result, error)
	switch msg.Root.SelectAttrValue("Destination", "") {
	case p.idp.SLOURL():
		out, responder, err = p.idp.HandleLogoutRequest(ctx, msg)
		responderCreds = p.idp.Credentials()
		consume = func(m *binding.Received) (*logout.Result, error) { return p.sp.ConsumeLogoutResponse(ctx, m) }
	case p.sp.SLOURL():
		out, responder, err = p.sp.HandleLogoutRequest(ctx, msg)
		responderCreds = p.sp.Credentials()
		consume = func(m *binding.Received) (*logout.Result, error) { return p.idp.ConsumeLogoutResponse(ctx, m) }
	default:
		writeError(w, http.StatusBadRequest, "LogoutRequest Destination is neither the IdP nor the SP SingleLogoutService", nil)
		return
	}
	if out == nil {
		detail := "LogoutRequest rejected"
		if err != nil {
			detail = err.Error()
		}
		writeError(w, http.StatusForbidden, detail, map[string]interface{}{"responderValidation": responder.Report})
		return
	}
	responseMsg, location, wire, err := deliverInProcess(out, responderCreds)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}
	requester, consumeErr := consume(responseMsg)

	body := map[string]interface{}{
		"success":             consumeErr == nil,
		"responseId":          out.Element.SelectAttrValue("ID", ""),
		"inResponseTo":        out.Element.SelectAttrValue("InResponseTo", ""),
		"issueInstant":        out.Element.SelectAttrValue("IssueInstant", ""),
		"issuer":              message.IssuerText(out.Element),
		"statusCode":          responder.StatusCode,
		"binding":             out.Binding,
		"rawXml":              string(wire),
		"redirectUrl":         location,
		"sessionsCleared":     len(responder.SessionsEnded),
		"relayState":          out.RelayState,
		"responderValidation": responder.Report,
		"requesterValidation": requester.Report,
	}
	status := http.StatusOK
	if consumeErr != nil {
		body["error"] = consumeErr.Error()
		status = http.StatusForbidden
	}
	p.events.Emit(r, lookingglass.EventTypeFlowStep, "Single Logout exchange processed", body,
		binding.Reference("Single Logout", "The responder ended the sessions and returned a signed LogoutResponse; the requester matched it to its LogoutRequest.", "SAML Profiles Section 4.4.3.4"))
	binding.WriteJSON(w, status, body)
}
