package capture

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// verifySAMLMessage checks a SAML Response the way its recipient must before
// trusting it. The message and every Assertion in it name the same issuer,
// that issuer is the entityID of the metadata the scenario fetched, and the
// enveloped XML Signature of the message and of each Assertion verifies with
// a signing certificate that metadata publishes for its identity provider
// role. It uses the XML Signature library directly, not the product's SAML
// code, so the check is independent of what produced the message.
func verifySAMLMessage(value string, exchanges []lookingglass.CapturedExchange, metadataExchange *int) (conformance.ExampleVerification, error) {
	var none conformance.ExampleVerification
	if metadataExchange == nil || *metadataExchange < 0 || *metadataExchange >= len(exchanges) {
		return none, fmt.Errorf("the scenario did not name the exchange that fetched the SAML metadata")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return none, fmt.Errorf("the value is not the base64 encoding of a SAML message: %w", err)
	}
	message := etree.NewDocument()
	if err := message.ReadFromBytes(decoded); err != nil {
		return none, fmt.Errorf("parse the SAML message: %w", err)
	}
	response := message.Root()
	if response == nil || response.Tag != "Response" {
		return none, fmt.Errorf("the value is not a SAML Response")
	}

	body, err := payloadBytes(exchanges[*metadataExchange].Response.Body)
	if err != nil {
		return none, err
	}
	metadata := etree.NewDocument()
	if err := metadata.ReadFromBytes(body); err != nil {
		return none, fmt.Errorf("parse the SAML metadata from exchange %d: %w", *metadataExchange, err)
	}
	entity := metadata.Root()
	if entity == nil || entity.Tag != "EntityDescriptor" {
		return none, fmt.Errorf("exchange %d did not fetch an EntityDescriptor", *metadataExchange)
	}
	entityID := entity.SelectAttrValue("entityID", "")
	certificates, err := signingCertificates(entity)
	if err != nil {
		return none, err
	}

	signed := append([]*etree.Element{response}, response.SelectElements("Assertion")...)
	if len(signed) < 2 {
		return none, fmt.Errorf("the Response carries no Assertion")
	}
	var algorithm string
	for _, element := range signed {
		issuer := element.SelectElement("Issuer")
		if issuer == nil || entityID == "" || strings.TrimSpace(issuer.Text()) != entityID {
			return none, fmt.Errorf("the %s's Issuer is not the metadata's entityID %q", element.Tag, entityID)
		}
		method := element.FindElement("./Signature/SignedInfo/SignatureMethod")
		if method == nil {
			return none, fmt.Errorf("the %s is not signed", element.Tag)
		}
		algorithm = method.SelectAttrValue("Algorithm", "")
		context := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certificates})
		if _, err := context.Validate(detach(element)); err != nil {
			return none, fmt.Errorf("the %s's signature does not verify: %w", element.Tag, err)
		}
	}

	index := *metadataExchange
	return conformance.ExampleVerification{
		Method:       conformance.VerifiedByXMLSignature,
		Algorithm:    algorithm,
		JWKSExchange: &index,
	}, nil
}

// detach copies a signed element into a document of its own, so nothing
// outside it can stand in for what the signature covers. The copy keeps the
// namespace declarations that were in scope: one made on an ancestor is
// repeated on the copy unless a nearer one already binds that prefix.
func detach(element *etree.Element) *etree.Element {
	copied := element.Copy()
	for ancestor := element.Parent(); ancestor != nil; ancestor = ancestor.Parent() {
		for _, attribute := range ancestor.Attr {
			declares := attribute.Space == "xmlns" || (attribute.Space == "" && attribute.Key == "xmlns")
			if declares && copied.SelectAttr(attribute.FullKey()) == nil {
				copied.CreateAttr(attribute.FullKey(), attribute.Value)
			}
		}
	}
	etree.NewDocument().SetRoot(copied)
	return copied
}

// signingCertificates returns the certificates an EntityDescriptor publishes
// for signing in its identity provider role: every KeyDescriptor of the
// IDPSSODescriptor whose use is signing or unstated.
func signingCertificates(entity *etree.Element) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	for _, descriptor := range entity.FindElements("./IDPSSODescriptor/KeyDescriptor") {
		if use := descriptor.SelectAttrValue("use", "signing"); use != "signing" {
			continue
		}
		for _, element := range descriptor.FindElements("./KeyInfo/X509Data/X509Certificate") {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(element.Text()), ""))
			if err != nil {
				return nil, fmt.Errorf("decode a metadata X509Certificate: %w", err)
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("parse a metadata X509Certificate: %w", err)
			}
			certificates = append(certificates, certificate)
		}
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("the metadata publishes no signing certificate for its identity provider role")
	}
	return certificates, nil
}
