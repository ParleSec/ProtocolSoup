package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
)

// ============================================================================
// SAML Metadata Types (SAML 2.0 Metadata)
// ============================================================================

// EntityDescriptor represents a SAML metadata EntityDescriptor
type EntityDescriptor struct {
	XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	DS               string            `xml:"xmlns:ds,attr"`
	EntityID         string            `xml:"entityID,attr"`
	ValidUntil       string            `xml:"validUntil,attr,omitempty"`
	CacheDuration    string            `xml:"cacheDuration,attr,omitempty"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
	Organization     *Organization     `xml:"Organization,omitempty"`
	ContactPerson    []ContactPerson   `xml:"ContactPerson,omitempty"`
}

// SPSSODescriptor represents the Service Provider SSO Descriptor
type SPSSODescriptor struct {
	XMLName                    xml.Name                     `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	ProtocolSupportEnumeration string                       `xml:"protocolSupportEnumeration,attr"`
	AuthnRequestsSigned        bool                         `xml:"AuthnRequestsSigned,attr,omitempty"`
	WantAssertionsSigned       bool                         `xml:"WantAssertionsSigned,attr,omitempty"`
	KeyDescriptors             []KeyDescriptor              `xml:"KeyDescriptor,omitempty"`
	SingleLogoutServices       []SingleLogoutService        `xml:"SingleLogoutService,omitempty"`
	NameIDFormats              []string                     `xml:"NameIDFormat,omitempty"`
	AssertionConsumerServices  []AssertionConsumerService   `xml:"AssertionConsumerService"`
	AttributeConsumingServices []AttributeConsumingService  `xml:"AttributeConsumingService,omitempty"`
}

// IDPSSODescriptor represents the Identity Provider SSO Descriptor
type IDPSSODescriptor struct {
	XMLName                    xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	ProtocolSupportEnumeration string                  `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    bool                    `xml:"WantAuthnRequestsSigned,attr,omitempty"`
	KeyDescriptors             []KeyDescriptor         `xml:"KeyDescriptor,omitempty"`
	SingleLogoutServices       []SingleLogoutService   `xml:"SingleLogoutService,omitempty"`
	NameIDFormats              []string                `xml:"NameIDFormat,omitempty"`
	SingleSignOnServices       []SingleSignOnService   `xml:"SingleSignOnService"`
	Attributes                 []MetadataAttribute     `xml:"Attribute,omitempty"`
}

// KeyDescriptor represents a key descriptor in metadata
type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use     string   `xml:"use,attr,omitempty"` // "signing" or "encryption"
	KeyInfo KeyInfo  `xml:"KeyInfo"`
}

// SingleLogoutService represents a Single Logout Service endpoint
type SingleLogoutService struct {
	XMLName          xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Binding          string   `xml:"Binding,attr"`
	Location         string   `xml:"Location,attr"`
	ResponseLocation string   `xml:"ResponseLocation,attr,omitempty"`
}

// SingleSignOnService represents a Single Sign-On Service endpoint
type SingleSignOnService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// AssertionConsumerService represents an Assertion Consumer Service endpoint
type AssertionConsumerService struct {
	XMLName   xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	Binding   string   `xml:"Binding,attr"`
	Location  string   `xml:"Location,attr"`
	Index     int      `xml:"index,attr"`
	IsDefault bool     `xml:"isDefault,attr,omitempty"`
}

// AttributeConsumingService represents requested attributes
type AttributeConsumingService struct {
	XMLName             xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:metadata AttributeConsumingService"`
	Index               int                        `xml:"index,attr"`
	IsDefault           bool                       `xml:"isDefault,attr,omitempty"`
	ServiceNames        []LocalizedName            `xml:"ServiceName"`
	ServiceDescriptions []LocalizedName            `xml:"ServiceDescription,omitempty"`
	RequestedAttributes []RequestedAttribute       `xml:"RequestedAttribute,omitempty"`
}

// LocalizedName represents a localized string
type LocalizedName struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata ServiceName"`
	Lang    string   `xml:"xml:lang,attr"`
	Value   string   `xml:",chardata"`
}

// RequestedAttribute represents a requested attribute
type RequestedAttribute struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata RequestedAttribute"`
	Name         string   `xml:"Name,attr"`
	NameFormat   string   `xml:"NameFormat,attr,omitempty"`
	FriendlyName string   `xml:"FriendlyName,attr,omitempty"`
	IsRequired   bool     `xml:"isRequired,attr,omitempty"`
}

// MetadataAttribute represents an attribute in IdP metadata
type MetadataAttribute struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name         string   `xml:"Name,attr"`
	NameFormat   string   `xml:"NameFormat,attr,omitempty"`
	FriendlyName string   `xml:"FriendlyName,attr,omitempty"`
}

// Organization represents organization information
type Organization struct {
	XMLName                  xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata Organization"`
	OrganizationNames        []LocalizedName   `xml:"OrganizationName"`
	OrganizationDisplayNames []LocalizedName   `xml:"OrganizationDisplayName"`
	OrganizationURLs         []LocalizedURL    `xml:"OrganizationURL"`
}

// LocalizedURL represents a localized URL
type LocalizedURL struct {
	Lang  string `xml:"xml:lang,attr"`
	Value string `xml:",chardata"`
}

// ContactPerson represents contact information
type ContactPerson struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata ContactPerson"`
	ContactType  string   `xml:"contactType,attr"` // technical, support, administrative, billing, other
	Company      string   `xml:"Company,omitempty"`
	GivenName    string   `xml:"GivenName,omitempty"`
	SurName      string   `xml:"SurName,omitempty"`
	EmailAddress []string `xml:"EmailAddress,omitempty"`
	TelephoneNumber []string `xml:"TelephoneNumber,omitempty"`
}

// ============================================================================
// Metadata Generation Functions
// ============================================================================

// MetadataConfig contains configuration for generating metadata
type MetadataConfig struct {
	EntityID            string
	BaseURL             string
	Certificate         *x509.Certificate
	WantAssertionsSigned bool
	AuthnRequestsSigned  bool
	
	// SP-specific
	ACSURL              string
	SLOURL              string
	
	// IdP-specific
	SSOURL              string
	
	// Organization info
	OrgName             string
	OrgDisplayName      string
	OrgURL              string
	
	// Contact info
	TechnicalContact    string
	SupportContact      string
}

// GenerateSPMetadata generates Service Provider metadata
func GenerateSPMetadata(config *MetadataConfig) (*EntityDescriptor, error) {
	metadata := &EntityDescriptor{
		DS:       NamespaceDS,
		EntityID: config.EntityID,
		SPSSODescriptor: &SPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			AuthnRequestsSigned:        config.AuthnRequestsSigned,
			WantAssertionsSigned:       config.WantAssertionsSigned,
			NameIDFormats: []string{
				NameIDFormatEmail,
				NameIDFormatPersistent,
				NameIDFormatTransient,
				NameIDFormatUnspecified,
			},
			AssertionConsumerServices: []AssertionConsumerService{
				{
					Binding:   BindingHTTPPost,
					Location:  config.ACSURL,
					Index:     0,
					IsDefault: true,
				},
				{
					Binding:  BindingHTTPRedirect,
					Location: config.ACSURL,
					Index:    1,
				},
			},
			SingleLogoutServices: []SingleLogoutService{
				{
					Binding:  BindingHTTPPost,
					Location: config.SLOURL,
				},
				{
					Binding:  BindingHTTPRedirect,
					Location: config.SLOURL,
				},
			},
		},
	}
	
	// Add certificate if provided
	// Per XML Signature spec and SAML Metadata, X509Certificate contains
	// the base64-encoded DER certificate (not PEM)
	if config.Certificate != nil {
		certB64 := base64.StdEncoding.EncodeToString(config.Certificate.Raw)
		
		metadata.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{
			{
				Use: "signing",
				KeyInfo: KeyInfo{
					X509Data: &X509Data{
						X509Certificate: certB64,
					},
				},
			},
			{
				Use: "encryption",
				KeyInfo: KeyInfo{
					X509Data: &X509Data{
						X509Certificate: certB64,
					},
				},
			},
		}
	}
	
	// Add organization info
	if config.OrgName != "" {
		metadata.Organization = &Organization{
			OrganizationNames: []LocalizedName{
				{Lang: "en", Value: config.OrgName},
			},
			OrganizationDisplayNames: []LocalizedName{
				{Lang: "en", Value: config.OrgDisplayName},
			},
			OrganizationURLs: []LocalizedURL{
				{Lang: "en", Value: config.OrgURL},
			},
		}
	}
	
	// Add contact persons
	if config.TechnicalContact != "" {
		metadata.ContactPerson = append(metadata.ContactPerson, ContactPerson{
			ContactType:  "technical",
			EmailAddress: []string{config.TechnicalContact},
		})
	}
	if config.SupportContact != "" {
		metadata.ContactPerson = append(metadata.ContactPerson, ContactPerson{
			ContactType:  "support",
			EmailAddress: []string{config.SupportContact},
		})
	}
	
	return metadata, nil
}

// GenerateIDPMetadata generates Identity Provider metadata
func GenerateIDPMetadata(config *MetadataConfig) (*EntityDescriptor, error) {
	metadata := &EntityDescriptor{
		DS:       NamespaceDS,
		EntityID: config.EntityID,
		IDPSSODescriptor: &IDPSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			WantAuthnRequestsSigned:    config.AuthnRequestsSigned,
			NameIDFormats: []string{
				NameIDFormatEmail,
				NameIDFormatPersistent,
				NameIDFormatTransient,
				NameIDFormatUnspecified,
			},
			SingleSignOnServices: []SingleSignOnService{
				{
					Binding:  BindingHTTPPost,
					Location: config.SSOURL,
				},
				{
					Binding:  BindingHTTPRedirect,
					Location: config.SSOURL,
				},
			},
			SingleLogoutServices: []SingleLogoutService{
				{
					Binding:  BindingHTTPPost,
					Location: config.SLOURL,
				},
				{
					Binding:  BindingHTTPRedirect,
					Location: config.SLOURL,
				},
			},
			// Declare supported attributes
			Attributes: []MetadataAttribute{
				{Name: "urn:oid:0.9.2342.19200300.100.1.3", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", FriendlyName: "mail"},
				{Name: "urn:oid:2.5.4.42", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", FriendlyName: "givenName"},
				{Name: "urn:oid:2.5.4.4", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", FriendlyName: "sn"},
				{Name: "urn:oid:2.5.4.3", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", FriendlyName: "cn"},
			},
		},
	}
	
	// Add certificate if provided
	// Per XML Signature spec and SAML Metadata, X509Certificate contains
	// the base64-encoded DER certificate (not PEM)
	if config.Certificate != nil {
		certB64 := base64.StdEncoding.EncodeToString(config.Certificate.Raw)
		
		metadata.IDPSSODescriptor.KeyDescriptors = []KeyDescriptor{
			{
				Use: "signing",
				KeyInfo: KeyInfo{
					X509Data: &X509Data{
						X509Certificate: certB64,
					},
				},
			},
		}
	}
	
	// Add organization info
	if config.OrgName != "" {
		metadata.Organization = &Organization{
			OrganizationNames: []LocalizedName{
				{Lang: "en", Value: config.OrgName},
			},
			OrganizationDisplayNames: []LocalizedName{
				{Lang: "en", Value: config.OrgDisplayName},
			},
			OrganizationURLs: []LocalizedURL{
				{Lang: "en", Value: config.OrgURL},
			},
		}
	}
	
	return metadata, nil
}

// MarshalMetadata marshals metadata to XML with proper formatting
func MarshalMetadata(metadata *EntityDescriptor) ([]byte, error) {
	xmlData, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}
	
	// Add XML declaration
	return []byte(xml.Header + string(xmlData)), nil
}

