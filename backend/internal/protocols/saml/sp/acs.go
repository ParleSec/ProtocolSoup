package sp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/session"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
)

// SSOResult is what the assertion consumer service established.
type SSOResult struct {
	Report      *binding.Report    `json:"validation"`
	Response    *message.Response  `json:"-"`
	Assertion   *message.Assertion `json:"-"`
	Session     *session.Session   `json:"session,omitempty"`
	RelayState  string             `json:"relayState,omitempty"`
	Unsolicited bool               `json:"unsolicited"`
}

// ConsumeResponse runs the SAML Profiles Section 4.1.4.3 processing rules on
// a <Response> delivered to the assertion consumer service. Every check is
// recorded; any failure rejects the response and no session is created.
func (sp *ServiceProvider) ConsumeResponse(ctx context.Context, msg *binding.Received) (*SSOResult, error) {
	result := &SSOResult{Report: &binding.Report{}, RelayState: msg.RelayState}
	report := result.Report
	fail := func(name, detail, reference string) (*SSOResult, error) {
		report.Add(name, false, detail, reference)
		return result, errors.New(detail)
	}

	if msg.Param != binding.ParamSAMLResponse || !message.IsElement(msg.Root, message.NamespaceSAMLp, "Response") {
		return fail("Message type", "the assertion consumer service accepts only <samlp:Response> as SAMLResponse", "SAML Profiles Section 4.1.4.2")
	}
	if msg.Binding != message.BindingHTTPPost {
		return fail("Binding", "the <Response> arrived over HTTP-Redirect; \"The HTTP Redirect binding MUST NOT be used\"", "SAML Profiles Section 4.1.2")
	}
	meta, err := sp.idpMetadata(ctx)
	if err != nil {
		return fail("IdP metadata", err.Error(), "SAML Metadata Section 4.1")
	}

	trusted, authReport, err := binding.Authenticate(msg, meta.SigningCerts, sp.cfg.ACSURL)
	report.Merge(authReport)
	if err != nil {
		return result, err
	}
	var response message.Response
	if err := message.Unmarshal(trusted, &response); err != nil {
		return fail("Response", "could not decode <samlp:Response>: "+err.Error(), "SAML Core Section 3.3.3")
	}
	result.Response = &response

	if response.Version != "2.0" {
		return fail("Version", fmt.Sprintf("Version is %q, not 2.0", response.Version), "SAML Core Section 3.2.2")
	}
	// Profiles Section 4.1.4.2 (Errata E17): Issuer MUST be present when the
	// response is signed, and if present MUST identify the IdP.
	issuer := message.IssuerValue(response.Issuer)
	switch {
	case issuer == "" && report.Signed:
		return fail("Response Issuer", "signed <Response> has no <Issuer>", "SAML Profiles Section 4.1.4.2 (Errata E17)")
	case issuer != "" && !message.IsEntityIssuer(response.Issuer, sp.cfg.IdPEntityID):
		return fail("Response Issuer", fmt.Sprintf("Issuer %q (Format %q) is not the IdP %q", issuer, response.Issuer.Format, sp.cfg.IdPEntityID), "SAML Profiles Section 4.1.4.2")
	case issuer != "":
		report.Add("Response Issuer", true, issuer, "SAML Profiles Section 4.1.4.2")
	}

	// InResponseTo binds the response to an AuthnRequest this SP sent. A
	// response without it is unsolicited (SAML Profiles Section 4.1.5).
	if response.InResponseTo != "" {
		pending, ok := sp.authnRequests.Take(response.InResponseTo)
		if !ok {
			return fail("InResponseTo", fmt.Sprintf("InResponseTo %q matches no outstanding AuthnRequest from this SP", response.InResponseTo), "SAML Core Section 3.2.2")
		}
		report.Add("InResponseTo", true, "matches AuthnRequest "+pending.ID, "SAML Core Section 3.2.2")
		// Bindings Sections 3.4.3/3.5.3: the responder MUST return "the exact
		// data it received with the request" as RelayState.
		if pending.RelayState != msg.RelayState {
			return fail("RelayState", fmt.Sprintf("RelayState %q differs from the %q sent with the AuthnRequest", msg.RelayState, pending.RelayState), "SAML Bindings Section 3.5.3")
		}
		report.Add("RelayState", true, "matches the value sent with the AuthnRequest", "SAML Bindings Section 3.5.3")
	} else {
		result.Unsolicited = true
		report.Add("InResponseTo", true, "absent: unsolicited response", "SAML Profiles Section 4.1.5")
	}

	if response.Status.StatusCode.Value != message.StatusSuccess {
		if len(message.Children(trusted, message.NamespaceSAML, "Assertion")) > 0 {
			return fail("Status", "error <Response> contains assertions; \"it MUST NOT include any assertions\"", "SAML Profiles Section 4.1.4.2")
		}
		return fail("Status", "IdP returned "+response.Status.Describe(), "SAML Core Section 3.2.2.2")
	}
	report.Add("Status", true, message.StatusSuccess, "SAML Core Section 3.2.2.2")

	if len(message.Children(trusted, message.NamespaceSAML, "EncryptedAssertion")) > 0 {
		return fail("EncryptedAssertion", "this SP publishes no encryption key and does not accept <saml:EncryptedAssertion>", "SAML Core Section 2.3.4")
	}
	assertionEls := message.Children(trusted, message.NamespaceSAML, "Assertion")
	if len(assertionEls) == 0 {
		return fail("Assertion", "<Response> contains no <Assertion>; it \"MUST contain at least one\"", "SAML Profiles Section 4.1.4.2 (Errata E26)")
	}

	// "each assertion, if more than one is present, MUST be evaluated
	// independently" (SAML Profiles Section 4.1.4.3, Errata E26).
	var accepted []*message.Assertion
	for i, el := range assertionEls {
		assertion, err := sp.validateAssertion(el, &response, fmt.Sprintf("Assertion %d", i+1), report, meta)
		if err != nil {
			return result, err
		}
		accepted = append(accepted, assertion)
	}

	// Replay detection runs last so a rejected response does not burn IDs.
	for _, assertion := range accepted {
		keepUntil := bearerNotOnOrAfter(assertion).Add(message.ClockSkew)
		if !sp.replay.Consume(assertion.ID, keepUntil) {
			return fail("Replay", fmt.Sprintf("assertion %s has already been consumed", assertion.ID), "SAML Profiles Section 4.1.4.5")
		}
	}
	report.Add("Replay", true, "assertion ID not seen before; recorded until its NotOnOrAfter", "SAML Profiles Section 4.1.4.5")

	assertion := accepted[0]
	result.Assertion = assertion
	authn := assertion.AuthnStatements[0]
	result.Session = &session.Session{
		PeerEntityID: sp.cfg.IdPEntityID,
		NameID:       assertion.Subject.NameID.Value,
		NameIDFormat: assertion.Subject.NameID.Format,
		SessionIndex: authn.SessionIndex,
		AuthnInstant: authn.AuthnInstant,
		AssertionID:  assertion.ID,
		Attributes:   assertion.Attributes(),
	}
	sp.sessions.Add(result.Session)
	return result, nil
}

// validateAssertion verifies one assertion's own signature and applies the
// Web Browser SSO rules to the verified copy.
func (sp *ServiceProvider) validateAssertion(el *etree.Element, response *message.Response, label string, report *binding.Report, meta *metadata.Peer) (*message.Assertion, error) {
	fail := func(name, detail, reference string) (*message.Assertion, error) {
		report.Add(label+" "+name, false, detail, reference)
		return nil, fmt.Errorf("%s: %s", label, detail)
	}
	pass := func(name, detail, reference string) {
		report.Add(label+" "+name, true, detail, reference)
	}

	// This SP publishes WantAssertionsSigned="true": "an enclosing signature
	// at the SAML binding or protocol layer does not suffice to meet this
	// requirement" (SAML Metadata Section 2.4.4, Errata E7).
	verified, info, err := xmldsig.VerifyEnveloped(el, meta.SigningCerts)
	if errors.Is(err, xmldsig.ErrUnsigned) {
		return fail("signature", "assertion is unsigned and this SP publishes WantAssertionsSigned=\"true\"", "SAML Metadata Section 2.4.4 (Errata E7)")
	}
	if err != nil {
		return fail("signature", err.Error(), "SAML Core Section 5.4")
	}
	if report.Signature == nil {
		report.Signature = info
	}
	pass("signature", "enveloped signature verified with the certificate from IdP metadata", "SAML Profiles Section 4.1.4.5 (Errata E26)")

	var assertion message.Assertion
	if err := message.Unmarshal(verified, &assertion); err != nil {
		return fail("decode", err.Error(), "SAML Core Section 2.3.3")
	}
	if assertion.Version != "2.0" {
		return fail("Version", fmt.Sprintf("Version is %q, not 2.0", assertion.Version), "SAML Core Section 2.3.3")
	}
	if !message.IsEntityIssuer(assertion.Issuer, sp.cfg.IdPEntityID) {
		return fail("Issuer", fmt.Sprintf("Issuer %q is not the IdP %q", message.IssuerValue(assertion.Issuer), sp.cfg.IdPEntityID), "SAML Profiles Section 4.1.4.2 (Errata E26)")
	}
	pass("Issuer", message.IssuerValue(assertion.Issuer), "SAML Profiles Section 4.1.4.2 (Errata E26)")

	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		return fail("Subject", "assertion has no <Subject><NameID>", "SAML Profiles Section 4.1.4.2 (Errata E26)")
	}

	now := time.Now()
	detail, ok := sp.confirmBearer(assertion.Subject, response, now)
	if !ok {
		return fail("SubjectConfirmation", detail, "SAML Profiles Section 4.1.4.3")
	}
	pass("SubjectConfirmation", detail, "SAML Profiles Section 4.1.4.3")

	if assertion.Conditions == nil {
		return fail("Conditions", "bearer assertion has no <Conditions>/<AudienceRestriction>", "SAML Profiles Section 4.1.4.2 (Errata E26)")
	}
	detail, ok = checkConditionsTime(assertion.Conditions, now)
	if !ok {
		return fail("Conditions validity", detail, "SAML Core Section 2.5.1.2")
	}
	pass("Conditions validity", detail, "SAML Core Section 2.5.1.2")
	if len(assertion.Conditions.AudienceRestrictions) == 0 {
		return fail("AudienceRestriction", "bearer assertion has no <AudienceRestriction>", "SAML Profiles Section 4.1.4.2 (Errata E26)")
	}
	for _, restriction := range assertion.Conditions.AudienceRestrictions {
		if !slices.Contains(restriction.Audiences, sp.cfg.EntityID) {
			return fail("AudienceRestriction", fmt.Sprintf("this SP (%s) is not an <Audience> in %v", sp.cfg.EntityID, restriction.Audiences), "SAML Core Section 2.5.1.4")
		}
	}
	pass("AudienceRestriction", "includes "+sp.cfg.EntityID, "SAML Core Section 2.5.1.4")

	if len(assertion.AuthnStatements) == 0 {
		return fail("AuthnStatement", "bearer assertion has no <AuthnStatement>", "SAML Profiles Section 4.1.4.2 (Errata E26)")
	}
	// The IdP publishes SingleLogoutService, so "any authentication statements
	// MUST include a SessionIndex attribute" (Profiles Section 4.1.4.2).
	var sessionIndexes []string
	for _, authn := range assertion.AuthnStatements {
		if authn.SessionIndex == "" {
			return fail("AuthnStatement", "<AuthnStatement> has no SessionIndex although the IdP supports Single Logout", "SAML Profiles Section 4.1.4.2")
		}
		sessionIndexes = append(sessionIndexes, authn.SessionIndex)
	}
	pass("AuthnStatement", "AuthnInstant "+assertion.AuthnStatements[0].AuthnInstant+", SessionIndex present", "SAML Profiles Section 4.1.4.2")

	if sp.loggedOut.Matches(assertion.Subject.NameID.Value, sessionIndexes) {
		return fail("Logout", "a LogoutRequest already processed for this principal and session still applies", "SAML Core Section 3.7.3.1")
	}
	return &assertion, nil
}

// confirmBearer looks for one bearer <SubjectConfirmation> that satisfies
// SAML Profiles Section 4.1.4.3; one success is sufficient (Errata E26).
func (sp *ServiceProvider) confirmBearer(subject *message.Subject, response *message.Response, now time.Time) (string, bool) {
	reason := "no bearer <SubjectConfirmation>"
	for _, confirmation := range subject.SubjectConfirmations {
		if confirmation.Method != message.SubjectConfirmationBearer {
			continue
		}
		data := confirmation.SubjectConfirmationData
		switch {
		case data == nil:
			reason = "bearer <SubjectConfirmation> has no <SubjectConfirmationData>"
		case data.Recipient != sp.cfg.ACSURL:
			reason = fmt.Sprintf("Recipient %q is not this assertion consumer service %q", data.Recipient, sp.cfg.ACSURL)
		case data.NotOnOrAfter == "":
			reason = "<SubjectConfirmationData> has no NotOnOrAfter"
		case data.NotBefore != "":
			reason = "<SubjectConfirmationData> carries NotBefore, which \"MUST NOT\" be present"
		case response.InResponseTo == "" && data.InResponseTo != "":
			reason = "unsolicited response carries <SubjectConfirmationData> InResponseTo (SAML Profiles Section 4.1.5)"
		case data.InResponseTo != response.InResponseTo:
			reason = fmt.Sprintf("<SubjectConfirmationData> InResponseTo %q does not equal the AuthnRequest ID %q", data.InResponseTo, response.InResponseTo)
		default:
			notOnOrAfter, err := message.ParseTime(data.NotOnOrAfter)
			if err != nil {
				reason = err.Error()
				continue
			}
			if !now.Before(notOnOrAfter.Add(message.ClockSkew)) {
				reason = fmt.Sprintf("<SubjectConfirmationData> NotOnOrAfter %s has passed (clock skew %s)", data.NotOnOrAfter, message.ClockSkew)
				continue
			}
			return fmt.Sprintf("bearer: Recipient matches, NotOnOrAfter %s, InResponseTo %q", data.NotOnOrAfter, data.InResponseTo), true
		}
	}
	return reason, false
}

// checkConditionsTime applies SAML Core Section 2.5.1.2 with the clock skew
// allowance Errata E92 asks relying parties to make.
func checkConditionsTime(conditions *message.Conditions, now time.Time) (string, bool) {
	var notBefore, notOnOrAfter time.Time
	var err error
	if conditions.NotBefore != "" {
		if notBefore, err = message.ParseTime(conditions.NotBefore); err != nil {
			return err.Error(), false
		}
		if now.Add(message.ClockSkew).Before(notBefore) {
			return fmt.Sprintf("NotBefore %s is in the future (clock skew %s)", conditions.NotBefore, message.ClockSkew), false
		}
	}
	if conditions.NotOnOrAfter != "" {
		if notOnOrAfter, err = message.ParseTime(conditions.NotOnOrAfter); err != nil {
			return err.Error(), false
		}
		if !now.Before(notOnOrAfter.Add(message.ClockSkew)) {
			return fmt.Sprintf("NotOnOrAfter %s has passed (clock skew %s)", conditions.NotOnOrAfter, message.ClockSkew), false
		}
	}
	// "If both attributes are present, the value for NotBefore MUST be less
	// than (earlier than) the value for NotOnOrAfter."
	if conditions.NotBefore != "" && conditions.NotOnOrAfter != "" && !notBefore.Before(notOnOrAfter) {
		return fmt.Sprintf("NotBefore %s is not earlier than NotOnOrAfter %s", conditions.NotBefore, conditions.NotOnOrAfter), false
	}
	return fmt.Sprintf("NotBefore %s, NotOnOrAfter %s", conditions.NotBefore, conditions.NotOnOrAfter), true
}

func bearerNotOnOrAfter(assertion *message.Assertion) time.Time {
	latest := time.Now()
	for _, confirmation := range assertion.Subject.SubjectConfirmations {
		if data := confirmation.SubjectConfirmationData; data != nil {
			if t, err := message.ParseTime(data.NotOnOrAfter); err == nil && t.After(latest) {
				latest = t
			}
		}
	}
	return latest
}
