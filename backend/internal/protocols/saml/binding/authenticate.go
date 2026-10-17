package binding

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
)

// Authenticate verifies the sender's signature on a received protocol message,
// whichever binding carried it, and enforces the Destination rules. It returns
// the element whose content may be trusted.
//
//   - HTTP-Redirect: the query-string signature (Bindings Section 3.4.4.1)
//     covers the whole message, so the parsed root is returned.
//   - HTTP-POST: the enveloped signature is verified and only the verified
//     copy is returned (Core Section 5.4).
//   - Destination: "If it is present, the actual recipient MUST check that the
//     URI reference identifies the location at which the message was
//     received" (Core Sections 3.2.1 and 3.2.2); signed messages MUST carry it
//     (Bindings Sections 3.4.5.2 and 3.5.5.2).
func Authenticate(msg *Received, trusted []*x509.Certificate, receivedAt string) (*etree.Element, *Report, error) {
	report := &Report{}
	trustedRoot := msg.Root

	switch {
	case msg.Binding == message.BindingHTTPRedirect && msg.Signature != "":
		err := xmldsig.VerifyRedirectOctets(msg.SignedOctets, msg.SigAlg, msg.Signature, trusted)
		if err != nil {
			report.Add("Redirect query signature", false, err.Error(), "SAML Bindings Section 3.4.4.1")
			return nil, report, err
		}
		report.Add("Redirect query signature", true, "SigAlg "+msg.SigAlg+" verified over the received query string", "SAML Bindings Section 3.4.4.1")
		report.Signed = true
	case msg.Binding == message.BindingHTTPPost:
		verified, info, err := xmldsig.VerifyEnveloped(msg.Root, trusted)
		if errors.Is(err, xmldsig.ErrUnsigned) {
			break
		}
		report.Signature = info
		if err != nil {
			report.Add("XML signature", false, err.Error(), "SAML Core Section 5.4")
			return nil, report, err
		}
		report.Add("XML signature", true, "enveloped signature verified with the certificate from metadata", "SAML Core Section 5.4")
		trustedRoot = verified
		report.Signed = true
	}

	destination := trustedRoot.SelectAttrValue("Destination", "")
	switch {
	case destination == "" && report.Signed:
		err := errors.New("signed message has no Destination attribute")
		report.Add("Destination", false, err.Error(), securitySection(msg.Binding))
		return nil, report, err
	case destination != "" && destination != receivedAt:
		err := fmt.Errorf("message Destination %q does not identify the location %q at which it was received", destination, receivedAt)
		report.Add("Destination", false, err.Error(), "SAML Core Sections 3.2.1 and 3.2.2")
		return nil, report, err
	case destination != "":
		report.Add("Destination", true, "matches "+receivedAt, "SAML Core Sections 3.2.1 and 3.2.2")
	}
	return trustedRoot, report, nil
}

func securitySection(binding string) string {
	if binding == message.BindingHTTPRedirect {
		return "SAML Bindings Section 3.4.5.2"
	}
	return "SAML Bindings Section 3.5.5.2"
}

// RelayStateSection is the RelayState section for binding.
func RelayStateSection(binding string) string {
	if binding == message.BindingHTTPRedirect {
		return "SAML Bindings Section 3.4.3"
	}
	return "SAML Bindings Section 3.5.3"
}
