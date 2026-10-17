package xmldsig

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
)

func TestSignAndVerifyEnveloped(t *testing.T) {
	creds, err := NewCredentials("https://idp.example/metadata")
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*x509.Certificate{creds.Certificate()}
	request := message.BuildAuthnRequest(message.AuthnRequestParams{
		Issuer: "https://sp.example/metadata", Destination: "https://idp.example/sso",
		ACSURL: "https://sp.example/acs", NameIDFormat: message.NameIDFormatEmail,
	})
	if err := SignEnveloped(request, creds); err != nil {
		t.Fatal(err)
	}
	if sig := request.ChildElements()[1]; !message.IsElement(sig, message.NamespaceDS, "Signature") {
		t.Fatalf("<ds:Signature> is not immediately after <saml:Issuer>: got <%s>", sig.FullTag())
	}

	// Verify the bytes as they would arrive, not the in-memory tree.
	wire, err := message.Serialize(request)
	if err != nil {
		t.Fatal(err)
	}
	received, err := message.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	verified, info, err := VerifyEnveloped(received, trusted)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if info.Canonicalization != "http://www.w3.org/2001/10/xml-exc-c14n#" || info.ReferenceURI != "#"+request.SelectAttrValue("ID", "") {
		t.Fatalf("unexpected signature details: %+v", info)
	}
	if message.IssuerText(verified) != "https://sp.example/metadata" {
		t.Fatalf("verified element lost its content")
	}

	received.CreateAttr("AssertionConsumerServiceURL", "https://attacker.example/acs")
	if _, _, err := VerifyEnveloped(received, trusted); err == nil {
		t.Fatal("tampered element verified")
	}
	other, _ := NewCredentials("https://other.example")
	if _, _, err := VerifyEnveloped(received, []*x509.Certificate{other.Certificate()}); err == nil {
		t.Fatal("element verified against an unrelated certificate")
	}
}

func TestRedirectOctetSignature(t *testing.T) {
	creds, err := NewCredentials("https://sp.example/metadata")
	if err != nil {
		t.Fatal(err)
	}
	octets := "SAMLRequest=abc&RelayState=xyz&SigAlg=" + SigAlgRSASHA256
	signature, err := SignRedirectOctets(octets, creds)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*x509.Certificate{creds.Certificate()}
	if err := VerifyRedirectOctets(octets, SigAlgRSASHA256, signature, trusted); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyRedirectOctets(octets+"x", SigAlgRSASHA256, signature, trusted); err == nil {
		t.Fatal("altered octets verified")
	}
	if err := VerifyRedirectOctets(octets, "http://www.w3.org/2000/09/xmldsig#dsa-sha1", signature, trusted); err == nil {
		t.Fatal("unaccepted SigAlg verified")
	}
}

// TestVerifiesSignatureFromIndependentImplementation checks an assertion
// signed by .NET System.Security.Cryptography.Xml.SignedXml (exclusive C14N,
// enveloped, RSA-SHA256), so signing and verification are not only tested
// against each other.
func TestVerifiesSignatureFromIndependentImplementation(t *testing.T) {
	xmlBytes, err := os.ReadFile("testdata/dotnet-signed-response.xml")
	if err != nil {
		t.Fatal(err)
	}
	certB64, err := os.ReadFile("testdata/dotnet-signer-cert.b64")
	if err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(certB64)))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	root, err := message.Parse(xmlBytes)
	if err != nil {
		t.Fatal(err)
	}
	assertion := message.Child(root, message.NamespaceSAML, "Assertion")
	verified, info, err := VerifyEnveloped(assertion, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf(".NET-signed assertion did not verify: %v", err)
	}
	if info.Canonicalization != "http://www.w3.org/2001/10/xml-exc-c14n#" || verified.FindElement(".//NameID").Text() != "alice@example.com" {
		t.Fatalf("unexpected verification result: %+v", info)
	}

	assertion.FindElement(".//NameID").SetText("attacker@example.com")
	if _, _, err := VerifyEnveloped(assertion, []*x509.Certificate{cert}); err == nil {
		t.Fatal("tampered .NET-signed assertion verified")
	}
}
