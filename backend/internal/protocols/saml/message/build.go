package message

import (
	"sort"
	"time"

	"github.com/beevik/etree"
)

// Builders return unsigned elements with samlp:/saml: prefixes. Signing is
// the binding's job: an enveloped signature for HTTP-POST, a query-string
// signature for HTTP-Redirect.

func newProtocolRoot(tag, id, issueInstant, destination string) *etree.Element {
	root := etree.NewElement("samlp:" + tag)
	root.CreateAttr("xmlns:samlp", NamespaceSAMLp)
	root.CreateAttr("xmlns:saml", NamespaceSAML)
	root.CreateAttr("ID", id)
	root.CreateAttr("Version", "2.0")
	root.CreateAttr("IssueInstant", issueInstant)
	if destination != "" {
		root.CreateAttr("Destination", destination)
	}
	return root
}

func addIssuer(parent *etree.Element, entityID string) {
	parent.CreateElement("saml:Issuer").SetText(entityID)
}

// StatusInfo is a <samlp:Status> to build: a top-level code from SAML Core
// Section 3.2.2.2, an optional second-level code, and an optional message.
type StatusInfo struct {
	Code    string
	SubCode string
	Message string
}

func addStatus(parent *etree.Element, status StatusInfo) {
	el := parent.CreateElement("samlp:Status")
	code := el.CreateElement("samlp:StatusCode")
	code.CreateAttr("Value", status.Code)
	if status.SubCode != "" {
		code.CreateElement("samlp:StatusCode").CreateAttr("Value", status.SubCode)
	}
	if status.Message != "" {
		el.CreateElement("samlp:StatusMessage").SetText(status.Message)
	}
}

// AuthnRequestParams describes an <AuthnRequest>.
type AuthnRequestParams struct {
	Issuer       string
	Destination  string
	ACSURL       string
	NameIDFormat string
}

// BuildAuthnRequest returns an <samlp:AuthnRequest> (SAML Core Section 3.4.1)
// asking for the response over HTTP-POST at ACSURL.
func BuildAuthnRequest(p AuthnRequestParams) *etree.Element {
	root := newProtocolRoot("AuthnRequest", GenerateID(), FormatTime(time.Now()), p.Destination)
	root.CreateAttr("ProtocolBinding", BindingHTTPPost)
	root.CreateAttr("AssertionConsumerServiceURL", p.ACSURL)
	addIssuer(root, p.Issuer)
	policy := root.CreateElement("samlp:NameIDPolicy")
	policy.CreateAttr("Format", p.NameIDFormat)
	policy.CreateAttr("AllowCreate", "true")
	return root
}

// ReleasedAttribute is an attribute to place in an <AttributeStatement>.
type ReleasedAttribute struct {
	Name         string
	FriendlyName string
	Values       []string
}

// AssertionParams describes a Web Browser SSO assertion.
type AssertionParams struct {
	Issuer       string
	NameID       string
	NameIDFormat string
	Recipient    string
	InResponseTo string
	Audience     string
	SessionIndex string
	AuthnInstant time.Time
	Lifetime     time.Duration
	Attributes   []ReleasedAttribute
}

// BuildAssertion returns a <saml:Assertion> for the Web Browser SSO Profile:
// a bearer <SubjectConfirmation> (SAML Profiles Section 4.1.4.2), an
// <AudienceRestriction> naming the relying party, and an <AuthnStatement>.
func BuildAssertion(p AssertionParams) *etree.Element {
	now := time.Now()
	notOnOrAfter := FormatTime(now.Add(p.Lifetime))

	assertion := etree.NewElement("saml:Assertion")
	// Declared on the assertion itself so it can be signed before it is
	// placed in a <Response>.
	assertion.CreateAttr("xmlns:saml", NamespaceSAML)
	assertion.CreateAttr("ID", GenerateID())
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateAttr("IssueInstant", FormatTime(now))
	addIssuer(assertion, p.Issuer)

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", p.NameIDFormat)
	nameID.SetText(p.NameID)
	confirmation := subject.CreateElement("saml:SubjectConfirmation")
	confirmation.CreateAttr("Method", SubjectConfirmationBearer)
	data := confirmation.CreateElement("saml:SubjectConfirmationData")
	if p.InResponseTo != "" {
		data.CreateAttr("InResponseTo", p.InResponseTo)
	}
	data.CreateAttr("NotOnOrAfter", notOnOrAfter)
	data.CreateAttr("Recipient", p.Recipient)

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", FormatTime(now))
	conditions.CreateAttr("NotOnOrAfter", notOnOrAfter)
	conditions.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(p.Audience)

	authn := assertion.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", FormatTime(p.AuthnInstant))
	authn.CreateAttr("SessionIndex", p.SessionIndex)
	authn.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(AuthnContextPasswordProtectedTransport)

	if len(p.Attributes) > 0 {
		attrs := append([]ReleasedAttribute(nil), p.Attributes...)
		sort.Slice(attrs, func(i, j int) bool { return attrs[i].Name < attrs[j].Name })
		statement := assertion.CreateElement("saml:AttributeStatement")
		for _, attr := range attrs {
			el := statement.CreateElement("saml:Attribute")
			el.CreateAttr("Name", attr.Name)
			el.CreateAttr("NameFormat", AttrNameFormatURI)
			if attr.FriendlyName != "" {
				el.CreateAttr("FriendlyName", attr.FriendlyName)
			}
			for _, value := range attr.Values {
				el.CreateElement("saml:AttributeValue").SetText(value)
			}
		}
	}
	return assertion
}

// BuildResponse returns a <samlp:Response> (SAML Core Section 3.3.3) wrapping
// assertion, which is nil for an error status.
func BuildResponse(issuer, destination, inResponseTo string, status StatusInfo, assertion *etree.Element) *etree.Element {
	root := newProtocolRoot("Response", GenerateID(), FormatTime(time.Now()), destination)
	if inResponseTo != "" {
		root.CreateAttr("InResponseTo", inResponseTo)
	}
	addIssuer(root, issuer)
	addStatus(root, status)
	if assertion != nil {
		root.AddChild(assertion)
	}
	return root
}

// LogoutRequestParams describes a <LogoutRequest>.
type LogoutRequestParams struct {
	Issuer       string
	Destination  string
	NameID       string
	NameIDFormat string
	SessionIndex string
	Lifetime     time.Duration
	Reason       string
}

// BuildLogoutRequest returns a <samlp:LogoutRequest> (SAML Core Section 3.7.1).
func BuildLogoutRequest(p LogoutRequestParams) *etree.Element {
	now := time.Now()
	root := newProtocolRoot("LogoutRequest", GenerateID(), FormatTime(now), p.Destination)
	root.CreateAttr("NotOnOrAfter", FormatTime(now.Add(p.Lifetime)))
	if p.Reason != "" {
		root.CreateAttr("Reason", p.Reason)
	}
	addIssuer(root, p.Issuer)
	nameID := root.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", p.NameIDFormat)
	nameID.SetText(p.NameID)
	if p.SessionIndex != "" {
		root.CreateElement("samlp:SessionIndex").SetText(p.SessionIndex)
	}
	return root
}

// BuildLogoutResponse returns a <samlp:LogoutResponse> (SAML Core Section 3.7.2).
func BuildLogoutResponse(issuer, destination, inResponseTo string, status StatusInfo) *etree.Element {
	root := newProtocolRoot("LogoutResponse", GenerateID(), FormatTime(time.Now()), destination)
	if inResponseTo != "" {
		root.CreateAttr("InResponseTo", inResponseTo)
	}
	addIssuer(root, issuer)
	addStatus(root, status)
	return root
}
