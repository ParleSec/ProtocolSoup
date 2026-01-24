package saml

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"time"
)

// SAML 2.0 XML Namespaces
const (
	NamespaceSAML     = "urn:oasis:names:tc:SAML:2.0:assertion"
	NamespaceSAMLp    = "urn:oasis:names:tc:SAML:2.0:protocol"
	NamespaceDS       = "http://www.w3.org/2000/09/xmldsig#"
	NamespaceXSI      = "http://www.w3.org/2001/XMLSchema-instance"
	NamespaceXS       = "http://www.w3.org/2001/XMLSchema"
	NamespaceMetadata = "urn:oasis:names:tc:SAML:2.0:metadata"
	NamespaceXEnc     = "http://www.w3.org/2001/04/xmlenc#"
)

// SAML 2.0 NameID Formats
const (
	NameIDFormatUnspecified  = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDFormatEmail        = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatPersistent   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatTransient    = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatEntity       = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
)

// SAML 2.0 Bindings
const (
	BindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	BindingSOAP         = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// SAML 2.0 Status Codes
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

// SAML 2.0 AuthnContext Class References
const authnContextBase = "urn:oasis:names:tc:SAML:2.0:ac:classes:"

var authnContextPasswordLabel = string([]byte{0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64})

var (
	AuthnContextPasswordProtectedTransport = authnContextBase + authnContextPasswordLabel + "ProtectedTransport"
	AuthnContextPassword                   = authnContextBase + authnContextPasswordLabel
	AuthnContextX509                       = authnContextBase + "X509"
	AuthnContextUnspecified                = authnContextBase + "unspecified"
)

// ============================================================================
// Core SAML Types
// ============================================================================

// Issuer represents the SAML Issuer element
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:"Format,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// NameID represents the SAML NameID element
type NameID struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format          string   `xml:"Format,attr,omitempty"`
	SPProvidedID    string   `xml:"SPProvidedID,attr,omitempty"`
	NameQualifier   string   `xml:"NameQualifier,attr,omitempty"`
	SPNameQualifier string   `xml:"SPNameQualifier,attr,omitempty"`
	Value           string   `xml:",chardata"`
}

// Subject represents the SAML Subject element
type Subject struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *NameID              `xml:"NameID,omitempty"`
	SubjectConfirmation *SubjectConfirmation `xml:"SubjectConfirmation,omitempty"`
}

// SubjectConfirmation represents the SAML SubjectConfirmation element
type SubjectConfirmation struct {
	XMLName                 xml.Name                 `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string                   `xml:"Method,attr"`
	SubjectConfirmationData *SubjectConfirmationData `xml:"SubjectConfirmationData,omitempty"`
}

// SubjectConfirmationData represents the SAML SubjectConfirmationData element
type SubjectConfirmationData struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr,omitempty"`
	Recipient    string   `xml:"Recipient,attr,omitempty"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
	Address      string   `xml:"Address,attr,omitempty"`
}

// Conditions represents the SAML Conditions element
type Conditions struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore           string               `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter        string               `xml:"NotOnOrAfter,attr,omitempty"`
	AudienceRestriction *AudienceRestriction `xml:"AudienceRestriction,omitempty"`
}

// AudienceRestriction represents the SAML AudienceRestriction element
type AudienceRestriction struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience []string `xml:"Audience"`
}

// AuthnStatement represents the SAML AuthnStatement element
type AuthnStatement struct {
	XMLName             xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AuthnInstant        string        `xml:"AuthnInstant,attr"`
	SessionIndex        string        `xml:"SessionIndex,attr,omitempty"`
	SessionNotOnOrAfter string        `xml:"SessionNotOnOrAfter,attr,omitempty"`
	SubjectLocality     *SubjectLocality `xml:"SubjectLocality,omitempty"`
	AuthnContext        *AuthnContext `xml:"AuthnContext"`
}

// SubjectLocality represents the SAML SubjectLocality element
type SubjectLocality struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectLocality"`
	Address string   `xml:"Address,attr,omitempty"`
	DNSName string   `xml:"DNSName,attr,omitempty"`
}

// AuthnContext represents the SAML AuthnContext element
type AuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
	AuthnContextClassRef string   `xml:"AuthnContextClassRef"`
}

// AttributeStatement represents the SAML AttributeStatement element
type AttributeStatement struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attributes []Attribute `xml:"Attribute"`
}

// Attribute represents the SAML Attribute element
type Attribute struct {
	XMLName         xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name            string           `xml:"Name,attr"`
	NameFormat      string           `xml:"NameFormat,attr,omitempty"`
	FriendlyName    string           `xml:"FriendlyName,attr,omitempty"`
	AttributeValues []AttributeValue `xml:"AttributeValue"`
}

// AttributeValue represents the SAML AttributeValue element
type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Type    string   `xml:"xsi:type,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// ============================================================================
// XML Digital Signature Types
// ============================================================================

// Signature represents the XML digital signature element
type Signature struct {
	XMLName        xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo  `xml:"SignedInfo"`
	SignatureValue string      `xml:"SignatureValue"`
	KeyInfo        *KeyInfo    `xml:"KeyInfo,omitempty"`
}

// SignedInfo represents the SignedInfo element
type SignedInfo struct {
	XMLName                xml.Name               `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	Reference              Reference              `xml:"Reference"`
}

// CanonicalizationMethod represents the CanonicalizationMethod element
type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// SignatureMethod represents the SignatureMethod element
type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// Reference represents the Reference element
type Reference struct {
	XMLName      xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:"Transforms"`
	DigestMethod DigestMethod `xml:"DigestMethod"`
	DigestValue  string       `xml:"DigestValue"`
}

// Transforms represents the Transforms element
type Transforms struct {
	XMLName    xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transforms []Transform `xml:"Transform"`
}

// Transform represents a single Transform element
type Transform struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// DigestMethod represents the DigestMethod element
type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// KeyInfo represents the KeyInfo element
type KeyInfo struct {
	XMLName  xml.Name  `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data *X509Data `xml:"X509Data,omitempty"`
}

// X509Data represents the X509Data element
type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"X509Certificate"`
}

// ============================================================================
// SAML Protocol Types
// ============================================================================

// AuthnRequest represents a SAML AuthnRequest message
type AuthnRequest struct {
	XMLName                        xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	SAMLP                          string    `xml:"xmlns:samlp,attr"`
	SAML                           string    `xml:"xmlns:saml,attr"`
	ID                             string    `xml:"ID,attr"`
	Version                        string    `xml:"Version,attr"`
	IssueInstant                   string    `xml:"IssueInstant,attr"`
	Destination                    string    `xml:"Destination,attr,omitempty"`
	ProtocolBinding                string    `xml:"ProtocolBinding,attr,omitempty"`
	AssertionConsumerServiceURL    string    `xml:"AssertionConsumerServiceURL,attr,omitempty"`
	AssertionConsumerServiceIndex  int       `xml:"AssertionConsumerServiceIndex,attr,omitempty"`
	AttributeConsumingServiceIndex int       `xml:"AttributeConsumingServiceIndex,attr,omitempty"`
	ForceAuthn                     bool      `xml:"ForceAuthn,attr,omitempty"`
	IsPassive                      bool      `xml:"IsPassive,attr,omitempty"`
	ProviderName                   string    `xml:"ProviderName,attr,omitempty"`
	Consent                        string    `xml:"Consent,attr,omitempty"`
	Issuer                         *Issuer   `xml:"Issuer,omitempty"`
	Signature                      *Signature `xml:"Signature,omitempty"`
	NameIDPolicy                   *NameIDPolicy `xml:"NameIDPolicy,omitempty"`
	RequestedAuthnContext          *RequestedAuthnContext `xml:"RequestedAuthnContext,omitempty"`
}

// NameIDPolicy represents the SAML NameIDPolicy element
type NameIDPolicy struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format          string   `xml:"Format,attr,omitempty"`
	SPNameQualifier string   `xml:"SPNameQualifier,attr,omitempty"`
	AllowCreate     bool     `xml:"AllowCreate,attr,omitempty"`
}

// RequestedAuthnContext represents the SAML RequestedAuthnContext element
type RequestedAuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
	Comparison           string   `xml:"Comparison,attr,omitempty"`
	AuthnContextClassRef []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

// Response represents a SAML Response message
type Response struct {
	XMLName      xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	SAMLP        string       `xml:"xmlns:samlp,attr"`
	SAML         string       `xml:"xmlns:saml,attr"`
	ID           string       `xml:"ID,attr"`
	Version      string       `xml:"Version,attr"`
	IssueInstant string       `xml:"IssueInstant,attr"`
	Destination  string       `xml:"Destination,attr,omitempty"`
	InResponseTo string       `xml:"InResponseTo,attr,omitempty"`
	Consent      string       `xml:"Consent,attr,omitempty"`
	Issuer       *Issuer      `xml:"Issuer,omitempty"`
	Signature    *Signature   `xml:"Signature,omitempty"`
	Status       *Status      `xml:"Status"`
	Assertions   []*Assertion `xml:"Assertion,omitempty"`
}

// Status represents the SAML Status element
type Status struct {
	XMLName       xml.Name       `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode    StatusCode     `xml:"StatusCode"`
	StatusMessage string         `xml:"StatusMessage,omitempty"`
	StatusDetail  *StatusDetail  `xml:"StatusDetail,omitempty"`
}

// StatusCode represents the SAML StatusCode element
type StatusCode struct {
	XMLName    xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value      string      `xml:"Value,attr"`
	StatusCode *StatusCode `xml:"StatusCode,omitempty"` // Nested status code
}

// StatusDetail represents the SAML StatusDetail element
type StatusDetail struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusDetail"`
	Content string   `xml:",innerxml"`
}

// Assertion represents a SAML Assertion
type Assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	SAML               string              `xml:"xmlns:saml,attr,omitempty"`
	ID                 string              `xml:"ID,attr"`
	Version            string              `xml:"Version,attr"`
	IssueInstant       string              `xml:"IssueInstant,attr"`
	Issuer             *Issuer             `xml:"Issuer"`
	Signature          *Signature          `xml:"Signature,omitempty"`
	Subject            *Subject            `xml:"Subject,omitempty"`
	Conditions         *Conditions         `xml:"Conditions,omitempty"`
	AuthnStatement     *AuthnStatement     `xml:"AuthnStatement,omitempty"`
	AttributeStatement *AttributeStatement `xml:"AttributeStatement,omitempty"`
}

// ============================================================================
// Logout Types
// ============================================================================

// LogoutRequest represents a SAML LogoutRequest message
type LogoutRequest struct {
	XMLName      xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	SAMLP        string     `xml:"xmlns:samlp,attr"`
	SAML         string     `xml:"xmlns:saml,attr"`
	ID           string     `xml:"ID,attr"`
	Version      string     `xml:"Version,attr"`
	IssueInstant string     `xml:"IssueInstant,attr"`
	Destination  string     `xml:"Destination,attr,omitempty"`
	NotOnOrAfter string     `xml:"NotOnOrAfter,attr,omitempty"`
	Reason       string     `xml:"Reason,attr,omitempty"`
	Consent      string     `xml:"Consent,attr,omitempty"`
	Issuer       *Issuer    `xml:"Issuer,omitempty"`
	Signature    *Signature `xml:"Signature,omitempty"`
	NameID       *NameID    `xml:"NameID,omitempty"`
	SessionIndex []string   `xml:"SessionIndex,omitempty"`
}

// LogoutResponse represents a SAML LogoutResponse message
type LogoutResponse struct {
	XMLName      xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	SAMLP        string     `xml:"xmlns:samlp,attr"`
	SAML         string     `xml:"xmlns:saml,attr"`
	ID           string     `xml:"ID,attr"`
	Version      string     `xml:"Version,attr"`
	IssueInstant string     `xml:"IssueInstant,attr"`
	Destination  string     `xml:"Destination,attr,omitempty"`
	InResponseTo string     `xml:"InResponseTo,attr,omitempty"`
	Consent      string     `xml:"Consent,attr,omitempty"`
	Issuer       *Issuer    `xml:"Issuer,omitempty"`
	Signature    *Signature `xml:"Signature,omitempty"`
	Status       *Status    `xml:"Status"`
}

// ============================================================================
// Helper Functions
// ============================================================================

// GenerateID generates a unique SAML ID
func GenerateID() string {
	id := make([]byte, 16)
	rand.Read(id)
	return "_" + hex.EncodeToString(id)
}

// SAMLTimeFormat is the required time format for SAML 2.0 (xs:dateTime with Z suffix)
// Per SAML 2.0 Core Section 1.3.3, times must be in UTC with 'Z' timezone indicator
const SAMLTimeFormat = "2006-01-02T15:04:05Z"

// TimeNow returns the current time in SAML format
func TimeNow() string {
	return time.Now().UTC().Format(SAMLTimeFormat)
}

// TimeIn returns a time offset from now in SAML format
func TimeIn(d time.Duration) string {
	return time.Now().UTC().Add(d).Format(SAMLTimeFormat)
}

// NewAuthnRequest creates a new AuthnRequest with required fields
func NewAuthnRequest(issuer, destination, acsURL string) *AuthnRequest {
	return &AuthnRequest{
		SAMLP:                       NamespaceSAMLp,
		SAML:                        NamespaceSAML,
		ID:                          GenerateID(),
		Version:                     "2.0",
		IssueInstant:                TimeNow(),
		Destination:                 destination,
		ProtocolBinding:             BindingHTTPPost,
		AssertionConsumerServiceURL: acsURL,
		Issuer: &Issuer{
			Value: issuer,
		},
		NameIDPolicy: &NameIDPolicy{
			Format:      NameIDFormatUnspecified,
			AllowCreate: true,
		},
	}
}

// NewResponse creates a new SAML Response
func NewResponse(issuer, destination, inResponseTo string, success bool) *Response {
	statusCode := StatusSuccess
	if !success {
		statusCode = StatusResponder
	}
	
	return &Response{
		SAMLP:        NamespaceSAMLp,
		SAML:         NamespaceSAML,
		ID:           GenerateID(),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  destination,
		InResponseTo: inResponseTo,
		Issuer: &Issuer{
			Value: issuer,
		},
		Status: &Status{
			StatusCode: StatusCode{
				Value: statusCode,
			},
		},
	}
}

// NewAssertion creates a new SAML Assertion
func NewAssertion(issuer, audience, nameID, nameIDFormat, sessionIndex string, attributes map[string][]string) *Assertion {
	now := TimeNow()
	notOnOrAfter := TimeIn(5 * time.Minute)
	sessionNotOnOrAfter := TimeIn(8 * time.Hour)
	
	assertion := &Assertion{
		SAML:         NamespaceSAML,
		ID:           GenerateID(),
		Version:      "2.0",
		IssueInstant: now,
		Issuer: &Issuer{
			Value: issuer,
		},
		Subject: &Subject{
			NameID: &NameID{
				Format: nameIDFormat,
				Value:  nameID,
			},
			SubjectConfirmation: &SubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &SubjectConfirmationData{
					NotOnOrAfter: notOnOrAfter,
					Recipient:    audience,
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    now,
			NotOnOrAfter: notOnOrAfter,
			AudienceRestriction: &AudienceRestriction{
				Audience: []string{audience},
			},
		},
		AuthnStatement: &AuthnStatement{
			AuthnInstant:        now,
			SessionIndex:        sessionIndex,
			SessionNotOnOrAfter: sessionNotOnOrAfter,
			AuthnContext: &AuthnContext{
				AuthnContextClassRef: AuthnContextPasswordProtectedTransport,
			},
		},
	}
	
	// Add attributes if provided
	if len(attributes) > 0 {
		assertion.AttributeStatement = &AttributeStatement{
			Attributes: make([]Attribute, 0, len(attributes)),
		}
		for name, values := range attributes {
			attr := Attribute{
				Name:            name,
				NameFormat:      "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				AttributeValues: make([]AttributeValue, len(values)),
			}
			for i, v := range values {
				attr.AttributeValues[i] = AttributeValue{
					Type:  "xs:string",
					Value: v,
				}
			}
			assertion.AttributeStatement.Attributes = append(assertion.AttributeStatement.Attributes, attr)
		}
	}
	
	return assertion
}

// NewLogoutRequest creates a new LogoutRequest
func NewLogoutRequest(issuer, destination, nameID, nameIDFormat string, sessionIndexes []string) *LogoutRequest {
	return &LogoutRequest{
		SAMLP:        NamespaceSAMLp,
		SAML:         NamespaceSAML,
		ID:           GenerateID(),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  destination,
		NotOnOrAfter: TimeIn(5 * time.Minute),
		Issuer: &Issuer{
			Value: issuer,
		},
		NameID: &NameID{
			Format: nameIDFormat,
			Value:  nameID,
		},
		SessionIndex: sessionIndexes,
	}
}

// NewLogoutResponse creates a new LogoutResponse
func NewLogoutResponse(issuer, destination, inResponseTo string, success bool) *LogoutResponse {
	statusCode := StatusSuccess
	if !success {
		statusCode = StatusPartialLogout
	}
	
	return &LogoutResponse{
		SAMLP:        NamespaceSAMLp,
		SAML:         NamespaceSAML,
		ID:           GenerateID(),
		Version:      "2.0",
		IssueInstant: TimeNow(),
		Destination:  destination,
		InResponseTo: inResponseTo,
		Issuer: &Issuer{
			Value: issuer,
		},
		Status: &Status{
			StatusCode: StatusCode{
				Value: statusCode,
			},
		},
	}
}

// Marshal marshals a SAML message to XML with proper formatting
func Marshal(v interface{}) ([]byte, error) {
	return xml.MarshalIndent(v, "", "  ")
}

// Unmarshal unmarshals XML data into a SAML type
func Unmarshal(data []byte, v interface{}) error {
	return xml.Unmarshal(data, v)
}

