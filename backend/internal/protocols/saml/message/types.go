package message

import (
	"encoding/xml"
	"strings"
)

// Read-only message types, decoded with Unmarshal from received XML or from
// the element a signature verification returned.

type Issuer struct {
	Format string `xml:"Format,attr"`
	Value  string `xml:",chardata"`
}

type NameID struct {
	Format          string `xml:"Format,attr"`
	NameQualifier   string `xml:"NameQualifier,attr"`
	SPNameQualifier string `xml:"SPNameQualifier,attr"`
	Value           string `xml:",chardata"`
}

type StatusCode struct {
	Value      string      `xml:"Value,attr"`
	StatusCode *StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
}

type Status struct {
	StatusCode    StatusCode `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	StatusMessage string     `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusMessage"`
}

// Describe renders the status codes and message as one line.
func (s Status) Describe() string {
	text := s.StatusCode.Value
	if s.StatusCode.StatusCode != nil {
		text += " / " + s.StatusCode.StatusCode.Value
	}
	if s.StatusMessage != "" {
		text += ": " + s.StatusMessage
	}
	return text
}

type NameIDPolicy struct {
	Format      string `xml:"Format,attr"`
	AllowCreate bool   `xml:"AllowCreate,attr"`
}

type AuthnRequest struct {
	XMLName                       xml.Name      `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                            string        `xml:"ID,attr"`
	Version                       string        `xml:"Version,attr"`
	IssueInstant                  string        `xml:"IssueInstant,attr"`
	Destination                   string        `xml:"Destination,attr"`
	ProtocolBinding               string        `xml:"ProtocolBinding,attr"`
	AssertionConsumerServiceURL   string        `xml:"AssertionConsumerServiceURL,attr"`
	AssertionConsumerServiceIndex string        `xml:"AssertionConsumerServiceIndex,attr"`
	ForceAuthn                    bool          `xml:"ForceAuthn,attr"`
	IsPassive                     bool          `xml:"IsPassive,attr"`
	Issuer                        *Issuer       `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                  *NameIDPolicy `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

type Response struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	Issuer       *Issuer  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

type SubjectConfirmationData struct {
	NotBefore    string `xml:"NotBefore,attr"`
	NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	Recipient    string `xml:"Recipient,attr"`
	InResponseTo string `xml:"InResponseTo,attr"`
	Address      string `xml:"Address,attr"`
}

type SubjectConfirmation struct {
	Method                  string                   `xml:"Method,attr"`
	SubjectConfirmationData *SubjectConfirmationData `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
}

type Subject struct {
	NameID               *NameID               `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SubjectConfirmations []SubjectConfirmation `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
}

type AudienceRestriction struct {
	Audiences []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type Conditions struct {
	NotBefore            string                `xml:"NotBefore,attr"`
	NotOnOrAfter         string                `xml:"NotOnOrAfter,attr"`
	AudienceRestrictions []AudienceRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
}

type AuthnStatement struct {
	AuthnInstant         string `xml:"AuthnInstant,attr"`
	SessionIndex         string `xml:"SessionIndex,attr"`
	SessionNotOnOrAfter  string `xml:"SessionNotOnOrAfter,attr"`
	AuthnContextClassRef string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext>AuthnContextClassRef"`
}

type Attribute struct {
	Name         string   `xml:"Name,attr"`
	NameFormat   string   `xml:"NameFormat,attr"`
	FriendlyName string   `xml:"FriendlyName,attr"`
	Values       []string `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
}

type AttributeStatement struct {
	Attributes []Attribute `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
}

type Assertion struct {
	XMLName             xml.Name             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                  string               `xml:"ID,attr"`
	Version             string               `xml:"Version,attr"`
	IssueInstant        string               `xml:"IssueInstant,attr"`
	Issuer              *Issuer              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Subject             *Subject             `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	Conditions          *Conditions          `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	AuthnStatements     []AuthnStatement     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AttributeStatements []AttributeStatement `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
}

// Attributes flattens the assertion's attribute statements by attribute Name.
func (a *Assertion) Attributes() map[string][]string {
	attributes := map[string][]string{}
	for _, statement := range a.AttributeStatements {
		for _, attr := range statement.Attributes {
			attributes[attr.Name] = append(attributes[attr.Name], attr.Values...)
		}
	}
	return attributes
}

type LogoutRequest struct {
	XMLName        xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	ID             string   `xml:"ID,attr"`
	Version        string   `xml:"Version,attr"`
	IssueInstant   string   `xml:"IssueInstant,attr"`
	Destination    string   `xml:"Destination,attr"`
	NotOnOrAfter   string   `xml:"NotOnOrAfter,attr"`
	Reason         string   `xml:"Reason,attr"`
	Issuer         *Issuer  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameID         *NameID  `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	SessionIndexes []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
}

type LogoutResponse struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutResponse"`
	ID           string   `xml:"ID,attr"`
	Version      string   `xml:"Version,attr"`
	IssueInstant string   `xml:"IssueInstant,attr"`
	Destination  string   `xml:"Destination,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	Issuer       *Issuer  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status       Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

// IsEntityIssuer applies the SAML profiles' Issuer rule: it "MUST contain the
// unique identifier" of the entity and "the Format attribute MUST be omitted or
// have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity".
func IsEntityIssuer(issuer *Issuer, entityID string) bool {
	return issuer != nil && IssuerValue(issuer) == entityID &&
		(issuer.Format == "" || issuer.Format == NameIDFormatEntity)
}

// IssuerValue returns the trimmed Issuer text, or "" for a nil Issuer.
func IssuerValue(issuer *Issuer) string {
	if issuer == nil {
		return ""
	}
	return strings.TrimSpace(issuer.Value)
}
