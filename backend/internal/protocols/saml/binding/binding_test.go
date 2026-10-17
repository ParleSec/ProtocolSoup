package binding

import (
	"crypto/x509"
	"net/url"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
)

func newRequest(destination string) *Outbound {
	return &Outbound{
		Element: message.BuildAuthnRequest(message.AuthnRequestParams{
			Issuer: "https://sp.example/metadata", Destination: destination,
			ACSURL: "https://sp.example/acs", NameIDFormat: message.NameIDFormatEmail,
		}),
		Location: destination,
		Param:    ParamSAMLRequest,
	}
}

func TestRedirectBindingRoundTrip(t *testing.T) {
	creds, err := xmldsig.NewCredentials("https://sp.example/metadata")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*x509.Certificate{creds.Certificate()}
	out := newRequest("https://idp.example/sso")
	location, err := RedirectURL(out.Location, out.Param, out.Element, "state 1", creds)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(location)
	msg, err := DecodeRedirect(parsed.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	if msg.RelayState != "state 1" || msg.Root.SelectAttrValue("ID", "") != out.Element.SelectAttrValue("ID", "") {
		t.Fatalf("decoded message differs: %+v", msg)
	}
	if _, report, err := Authenticate(msg, trusted, "https://idp.example/sso"); err != nil || !report.Signed {
		t.Fatalf("authenticate: %v %+v", err, report)
	}
	if _, _, err := Authenticate(msg, trusted, "https://other.example/sso"); err == nil || !strings.Contains(err.Error(), "Destination") {
		t.Fatalf("Destination mismatch accepted: %v", err)
	}

	tampered, err := DecodeRedirect(strings.Replace(parsed.RawQuery, "RelayState=state+1", "RelayState=state+2", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Authenticate(tampered, trusted, "https://idp.example/sso"); err == nil {
		t.Fatal("tampered query string verified")
	}
}

func TestPostBindingRoundTrip(t *testing.T) {
	creds, err := xmldsig.NewCredentials("https://sp.example/metadata")
	if err != nil {
		t.Fatal(err)
	}
	out := newRequest("https://idp.example/sso")
	wire, err := SignedPostXML(out.Element, creds)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := PostMessage(ParamSAMLRequest, wire, "")
	if err != nil {
		t.Fatal(err)
	}
	trusted, report, err := Authenticate(msg, []*x509.Certificate{creds.Certificate()}, "https://idp.example/sso")
	if err != nil || !report.Signed || report.Signature == nil {
		t.Fatalf("authenticate: %v %+v", err, report)
	}
	if message.IssuerText(trusted) != "https://sp.example/metadata" {
		t.Fatal("trusted element lost its content")
	}
}

func TestRelayStateLimit(t *testing.T) {
	if err := CheckRelayState(strings.Repeat("a", MaxRelayStateBytes)); err != nil {
		t.Fatalf("80-byte RelayState refused: %v", err)
	}
	if err := CheckRelayState(strings.Repeat("a", MaxRelayStateBytes+1)); err == nil {
		t.Fatal("81-byte RelayState accepted")
	}
}

func TestRedirectRefusesSignedXML(t *testing.T) {
	creds, err := xmldsig.NewCredentials("https://sp.example/metadata")
	if err != nil {
		t.Fatal(err)
	}
	out := newRequest("https://idp.example/sso")
	if err := xmldsig.SignEnveloped(out.Element, creds); err != nil {
		t.Fatal(err)
	}
	if _, err := RedirectURL(out.Location, out.Param, out.Element, "", creds); err == nil {
		t.Fatal("HTTP-Redirect accepted a message carrying <ds:Signature> (SAML Bindings Section 3.4.4.1)")
	}
}
