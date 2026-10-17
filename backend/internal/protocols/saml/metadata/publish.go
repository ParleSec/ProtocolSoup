// Package metadata publishes an entity's SAML 2.0 metadata and resolves a
// peer's metadata from the well-known location that is its entityID (SAML
// Metadata Sections 2 and 4.1). A peer's metadata is the only source of trust
// for its keys and endpoints.
package metadata

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
)

// MediaType is required by SAML Metadata Section 4.1.1: "the content type of
// the metadata instance MUST be application/samlmetadata+xml".
const MediaType = "application/samlmetadata+xml"

const (
	validity      = 48 * time.Hour
	cacheDuration = "PT1H"
)

// Endpoint is a published service endpoint (SAML Metadata Section 2.2.2).
type Endpoint struct {
	Binding  string
	Location string
}

// Entity carries what an entity publishes about itself in any role.
type Entity struct {
	EntityID         string
	Credentials      *xmldsig.Credentials
	SingleLogout     []Endpoint
	OrganizationName string
	OrganizationURL  string
}

func newEntityDescriptor(entity Entity) *etree.Element {
	root := etree.NewElement("md:EntityDescriptor")
	root.CreateAttr("xmlns:md", message.NamespaceMetadata)
	root.CreateAttr("xmlns:ds", message.NamespaceDS)
	root.CreateAttr("xmlns:saml", message.NamespaceSAML)
	root.CreateAttr("entityID", entity.EntityID)
	// Metadata Section 2.3.2: the root element "MUST contain either a
	// validUntil or cacheDuration attribute".
	root.CreateAttr("validUntil", message.FormatTime(time.Now().Add(validity)))
	root.CreateAttr("cacheDuration", cacheDuration)
	return root
}

func newRoleDescriptor(parent *etree.Element, tag string) *etree.Element {
	descriptor := parent.CreateElement("md:" + tag)
	descriptor.CreateAttr("protocolSupportEnumeration", message.NamespaceSAMLp)
	return descriptor
}

func addKeyDescriptor(descriptor *etree.Element, creds *xmldsig.Credentials) {
	key := descriptor.CreateElement("md:KeyDescriptor")
	key.CreateAttr("use", "signing")
	key.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(creds.Certificate().Raw))
}

func addEndpoints(descriptor *etree.Element, tag string, endpoints []Endpoint) {
	for _, ep := range endpoints {
		el := descriptor.CreateElement("md:" + tag)
		el.CreateAttr("Binding", ep.Binding)
		el.CreateAttr("Location", ep.Location)
	}
}

// addOrganization adds <md:Organization>; Metadata Section 2.3.2.1 requires
// each of its three children at least once.
func addOrganization(root *etree.Element, entity Entity) {
	org := root.CreateElement("md:Organization")
	for _, child := range []struct{ tag, value string }{
		{"OrganizationName", entity.OrganizationName},
		{"OrganizationDisplayName", entity.OrganizationName},
		{"OrganizationURL", entity.OrganizationURL},
	} {
		el := org.CreateElement("md:" + child.tag)
		el.CreateAttr("xml:lang", "en")
		el.SetText(child.value)
	}
}

// IdPParams describes an identity provider's metadata.
type IdPParams struct {
	Entity                  Entity
	SingleSignOn            []Endpoint
	WantAuthnRequestsSigned bool
	Attributes              []message.ReleasedAttribute
}

// BuildIdP returns the identity provider's <md:EntityDescriptor> (SAML
// Metadata Section 2.4.3). Child order follows the schema.
func BuildIdP(p IdPParams) *etree.Element {
	root := newEntityDescriptor(p.Entity)
	idp := newRoleDescriptor(root, "IDPSSODescriptor")
	idp.CreateAttr("WantAuthnRequestsSigned", strconv.FormatBool(p.WantAuthnRequestsSigned))
	addKeyDescriptor(idp, p.Entity.Credentials)
	addEndpoints(idp, "SingleLogoutService", p.Entity.SingleLogout)
	idp.CreateElement("md:NameIDFormat").SetText(message.NameIDFormatEmail)
	addEndpoints(idp, "SingleSignOnService", p.SingleSignOn)
	for _, attr := range p.Attributes {
		el := idp.CreateElement("saml:Attribute")
		el.CreateAttr("Name", attr.Name)
		el.CreateAttr("NameFormat", message.AttrNameFormatURI)
		el.CreateAttr("FriendlyName", attr.FriendlyName)
	}
	addOrganization(root, p.Entity)
	return root
}

// SPParams describes a service provider's metadata.
type SPParams struct {
	Entity               Entity
	ACSURL               string
	AuthnRequestsSigned  bool
	WantAssertionsSigned bool
}

// BuildSP returns the service provider's <md:EntityDescriptor> (SAML Metadata
// Section 2.4.4). The only assertion consumer service is HTTP-POST: "The HTTP
// Redirect binding MUST NOT be used" to deliver the <Response> (SAML Profiles
// Section 4.1.2).
func BuildSP(p SPParams) *etree.Element {
	root := newEntityDescriptor(p.Entity)
	sp := newRoleDescriptor(root, "SPSSODescriptor")
	sp.CreateAttr("AuthnRequestsSigned", strconv.FormatBool(p.AuthnRequestsSigned))
	sp.CreateAttr("WantAssertionsSigned", strconv.FormatBool(p.WantAssertionsSigned))
	addKeyDescriptor(sp, p.Entity.Credentials)
	addEndpoints(sp, "SingleLogoutService", p.Entity.SingleLogout)
	sp.CreateElement("md:NameIDFormat").SetText(message.NameIDFormatEmail)
	acs := sp.CreateElement("md:AssertionConsumerService")
	acs.CreateAttr("Binding", message.BindingHTTPPost)
	acs.CreateAttr("Location", p.ACSURL)
	acs.CreateAttr("index", "0")
	acs.CreateAttr("isDefault", "true")
	addOrganization(root, p.Entity)
	return root
}

// Write serves descriptor with the metadata media type.
func Write(w http.ResponseWriter, descriptor *etree.Element) {
	body, err := message.Serialize(descriptor)
	if err != nil {
		http.Error(w, "failed to serialize metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", MediaType)
	_, _ = w.Write(body)
}
