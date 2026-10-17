// Package message holds the SAML 2.0 vocabulary shared by every other SAML
// package: protocol constants, identifier and time rules, XML parsing and
// serialization, message builders and read-only message types.
package message

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
)

// SAML 2.0 XML namespaces (SAML Core Section 1.2).
const (
	NamespaceSAML     = "urn:oasis:names:tc:SAML:2.0:assertion"
	NamespaceSAMLp    = "urn:oasis:names:tc:SAML:2.0:protocol"
	NamespaceDS       = "http://www.w3.org/2000/09/xmldsig#"
	NamespaceMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"
)

// NameID formats (SAML Core Section 8.3).
const (
	NameIDFormatEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEntity      = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

// Binding identifiers (SAML Bindings Sections 3.4.1 and 3.5.1).
const (
	BindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
)

// Status codes (SAML Core Section 3.2.2.2).
const (
	StatusSuccess                = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusRequester              = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	StatusResponder              = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusVersionMismatch        = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
	StatusAuthnFailed            = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	StatusInvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
	StatusInvalidNameIDPolicy    = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	StatusNoAuthnContext         = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
	StatusNoAvailableIDP         = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"
	StatusNoPassive              = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	StatusPartialLogout          = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	StatusRequestDenied          = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	StatusRequestUnsupported     = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
)

// SubjectConfirmationBearer is the bearer confirmation method (SAML Profiles
// Section 3.3).
const SubjectConfirmationBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// AttrNameFormatURI names URI-named attributes (SAML Core Section 8.2.2).
const AttrNameFormatURI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

// LogoutReasonUser is a <LogoutRequest> Reason (SAML Core Section 3.7.3).
const LogoutReasonUser = "urn:oasis:names:tc:SAML:2.0:logout:user"

const authnContextBase = "urn:oasis:names:tc:SAML:2.0:ac:classes:"

var authnContextPasswordLabel = string([]byte{0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})

// AuthnContextPasswordProtectedTransport is the class reference for password
// authentication over TLS (SAML Authn Context Section 3.4).
var AuthnContextPasswordProtectedTransport = authnContextBase + authnContextPasswordLabel + "ProtectedTransport"

// ClockSkew follows SAML Core Section 1.3.3 (Errata E92): "Tolerances of 3-5
// minutes are reasonable defaults".
const ClockSkew = 3 * time.Minute

// ============================================================================
// Identifiers and time values
// ============================================================================

// GenerateID returns an xs:ID value with 160 bits of randomness. SAML Core
// Section 1.3.4 requires identifiers to be unique with a negligible chance of
// collision; the leading underscore keeps the value a valid NCName.
func GenerateID() string {
	id := make([]byte, 20)
	if _, err := rand.Read(id); err != nil {
		panic(fmt.Sprintf("saml: crypto/rand failed: %v", err))
	}
	return "_" + hex.EncodeToString(id)
}

// timeFormat renders xs:dateTime in UTC with the "Z" designator, as SAML Core
// Section 1.3.3 requires for every SAML time value.
const timeFormat = "2006-01-02T15:04:05Z"

// FormatTime renders t as a SAML time value.
func FormatTime(t time.Time) string {
	return t.UTC().Format(timeFormat)
}

// ParseTime accepts any xs:dateTime in UTC ("Z"), including fractional seconds.
func ParseTime(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("time value %q is not expressed in UTC (SAML Core Section 1.3.3)", value)
	}
	return time.Parse(time.RFC3339Nano, value)
}

// ============================================================================
// XML handling
// ============================================================================

// Serialize renders el as a standalone UTF-8 XML document. The bytes returned
// are exactly what goes on the wire, so signatures computed over el remain
// valid.
func Serialize(el *etree.Element) ([]byte, error) {
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(el.Copy())
	return doc.WriteToBytes()
}

// Parse parses a received SAML message. Documents carrying a DOCTYPE are
// rejected outright: no SAML message needs one, and refusing them removes the
// entity-expansion attack surface.
func Parse(data []byte) (*etree.Element, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("message is not well-formed XML: %w", err)
	}
	for _, token := range doc.Child {
		if _, ok := token.(*etree.Directive); ok {
			return nil, errors.New("message contains a DOCTYPE or other XML directive")
		}
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("message has no root element")
	}
	return root, nil
}

// Unmarshal decodes el into one of the read-only message types in types.go.
func Unmarshal(el *etree.Element, v any) error {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	data, err := doc.WriteToBytes()
	if err != nil {
		return err
	}
	return xml.NewDecoder(bytes.NewReader(data)).Decode(v)
}

// IsElement reports whether el is namespace:local.
func IsElement(el *etree.Element, namespace, local string) bool {
	return el != nil && el.Tag == local && el.NamespaceURI() == namespace
}

// Child returns el's first child element named namespace:local, or nil.
func Child(el *etree.Element, namespace, local string) *etree.Element {
	for _, child := range el.ChildElements() {
		if IsElement(child, namespace, local) {
			return child
		}
	}
	return nil
}

// Children returns el's child elements named namespace:local.
func Children(el *etree.Element, namespace, local string) []*etree.Element {
	var out []*etree.Element
	for _, child := range el.ChildElements() {
		if IsElement(child, namespace, local) {
			out = append(out, child)
		}
	}
	return out
}

// IssuerText returns the text of el's <saml:Issuer> child.
func IssuerText(el *etree.Element) string {
	if issuer := Child(el, NamespaceSAML, "Issuer"); issuer != nil {
		return strings.TrimSpace(issuer.Text())
	}
	return ""
}
