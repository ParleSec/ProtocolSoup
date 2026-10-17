package metadata

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
)

const maxBytes = 512 * 1024

// Role selects the role descriptor read from a peer's metadata.
type Role string

const (
	RoleIdP Role = "IDPSSODescriptor"
	RoleSP  Role = "SPSSODescriptor"
)

// PeerEndpoint is an endpoint as published in a peer's metadata.
type PeerEndpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr"`
	Index            string `xml:"index,attr"`
	IsDefault        string `xml:"isDefault,attr"`
}

type keyDescriptor struct {
	Use     string `xml:"use,attr"`
	KeyInfo struct {
		X509Data []struct {
			Certificates []string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
		} `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	} `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type roleDescriptor struct {
	ProtocolSupportEnumeration string          `xml:"protocolSupportEnumeration,attr"`
	WantAuthnRequestsSigned    string          `xml:"WantAuthnRequestsSigned,attr"`
	AuthnRequestsSigned        string          `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       string          `xml:"WantAssertionsSigned,attr"`
	KeyDescriptors             []keyDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	SingleLogoutServices       []PeerEndpoint  `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	SingleSignOnServices       []PeerEndpoint  `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	AssertionConsumerServices  []PeerEndpoint  `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
}

type entityDescriptor struct {
	XMLName       xml.Name         `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID      string           `xml:"entityID,attr"`
	ValidUntil    string           `xml:"validUntil,attr"`
	CacheDuration string           `xml:"cacheDuration,attr"`
	IDPSSO        []roleDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	SPSSO         []roleDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
}

// Peer is what an entity learned about a peer from the peer's published
// metadata. It is the only source of trust for the peer's keys.
type Peer struct {
	EntityID     string
	SigningCerts []*x509.Certificate
	SingleLogout []PeerEndpoint

	// IDPSSODescriptor
	SingleSignOn            []PeerEndpoint
	WantAuthnRequestsSigned bool

	// SPSSODescriptor
	AssertionConsumers   []PeerEndpoint
	AuthnRequestsSigned  bool
	WantAssertionsSigned bool

	cacheUntil time.Time
}

// SingleLogoutService returns the peer's SingleLogoutService for binding.
func (p *Peer) SingleLogoutService(binding string) (PeerEndpoint, bool) {
	for _, ep := range p.SingleLogout {
		if ep.Binding == binding {
			return ep, true
		}
	}
	return PeerEndpoint{}, false
}

// SingleSignOnService returns the IdP's SingleSignOnService location for binding.
func (p *Peer) SingleSignOnService(binding string) (string, bool) {
	for _, ep := range p.SingleSignOn {
		if ep.Binding == binding {
			return ep.Location, true
		}
	}
	return "", false
}

// DefaultACS applies the IndexedEndpointType default rule of SAML Metadata
// Section 2.2.3 to the HTTP-POST assertion consumer services.
func (p *Peer) DefaultACS() (PeerEndpoint, bool) {
	var post []PeerEndpoint
	for _, ep := range p.AssertionConsumers {
		if ep.Binding == message.BindingHTTPPost {
			post = append(post, ep)
		}
	}
	for _, ep := range post {
		if parseBool(ep.IsDefault) {
			return ep, true
		}
	}
	for _, ep := range post {
		if ep.IsDefault == "" {
			return ep, true
		}
	}
	if len(post) > 0 {
		return post[0], true
	}
	return PeerEndpoint{}, false
}

// ACSByURL returns the HTTP-POST assertion consumer service at location, so an
// <AuthnRequest>'s AssertionConsumerServiceURL can be "verified as belonging
// to the service provider" (SAML Profiles Section 4.1.4.1).
func (p *Peer) ACSByURL(location string) (PeerEndpoint, bool) {
	for _, ep := range p.AssertionConsumers {
		if ep.Binding == message.BindingHTTPPost && ep.Location == location {
			return ep, true
		}
	}
	return PeerEndpoint{}, false
}

// ACSByIndex returns the HTTP-POST assertion consumer service with index.
func (p *Peer) ACSByIndex(index string) (PeerEndpoint, bool) {
	for _, ep := range p.AssertionConsumers {
		if ep.Binding == message.BindingHTTPPost && ep.Index == index {
			return ep, true
		}
	}
	return PeerEndpoint{}, false
}

func parseBool(value string) bool {
	return value == "true" || value == "1"
}

// Parse reads a single <md:EntityDescriptor> for expectedEntityID and the
// given role descriptor.
func Parse(data []byte, expectedEntityID string, role Role, now time.Time) (*Peer, error) {
	root, err := message.Parse(data)
	if err != nil {
		return nil, err
	}
	if !message.IsElement(root, message.NamespaceMetadata, "EntityDescriptor") {
		return nil, fmt.Errorf("metadata root is <%s>, not <md:EntityDescriptor> (SAML Metadata Section 4.1.1)", root.FullTag())
	}
	var descriptor entityDescriptor
	if err := message.Unmarshal(root, &descriptor); err != nil {
		return nil, fmt.Errorf("metadata could not be decoded: %w", err)
	}
	// Metadata Section 4.1.1: "the root element MUST be an <EntityDescriptor>
	// with an entityID matching the location".
	if descriptor.EntityID != expectedEntityID {
		return nil, fmt.Errorf("metadata entityID %q does not match %q", descriptor.EntityID, expectedEntityID)
	}

	peer := &Peer{EntityID: descriptor.EntityID, cacheUntil: now.Add(time.Hour)}
	if descriptor.CacheDuration != "" {
		if d, err := parseISODuration(descriptor.CacheDuration); err == nil {
			peer.cacheUntil = now.Add(d)
		}
	}
	if descriptor.ValidUntil != "" {
		validUntil, err := message.ParseTime(descriptor.ValidUntil)
		if err != nil {
			return nil, fmt.Errorf("metadata validUntil: %w", err)
		}
		if !now.Before(validUntil) {
			return nil, fmt.Errorf("metadata expired at %s", descriptor.ValidUntil)
		}
		if validUntil.Before(peer.cacheUntil) {
			peer.cacheUntil = validUntil
		}
	}

	descriptors := descriptor.IDPSSO
	if role == RoleSP {
		descriptors = descriptor.SPSSO
	}
	var rd *roleDescriptor
	for i := range descriptors {
		// Metadata Section 2.4.1: the enumeration "MUST include the SAML
		// protocol namespace URI" for SAML V2.0 entities.
		for _, protocol := range strings.Fields(descriptors[i].ProtocolSupportEnumeration) {
			if protocol == message.NamespaceSAMLp {
				rd = &descriptors[i]
			}
		}
		if rd != nil {
			break
		}
	}
	if rd == nil {
		return nil, fmt.Errorf("metadata has no <md:%s> supporting %s", role, message.NamespaceSAMLp)
	}

	for _, kd := range rd.KeyDescriptors {
		// Errata E62: an omitted use attribute applies to both signing and
		// encryption.
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, x509Data := range kd.KeyInfo.X509Data {
			for _, encoded := range x509Data.Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
				if err != nil {
					return nil, fmt.Errorf("metadata X509Certificate is not valid base64: %w", err)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("metadata X509Certificate could not be parsed: %w", err)
				}
				peer.SigningCerts = append(peer.SigningCerts, cert)
			}
		}
	}
	peer.SingleLogout = rd.SingleLogoutServices
	peer.SingleSignOn = rd.SingleSignOnServices
	peer.WantAuthnRequestsSigned = parseBool(rd.WantAuthnRequestsSigned)
	peer.AssertionConsumers = rd.AssertionConsumerServices
	peer.AuthnRequestsSigned = parseBool(rd.AuthnRequestsSigned)
	peer.WantAssertionsSigned = parseBool(rd.WantAssertionsSigned)
	return peer, nil
}

var isoDurationPattern = regexp.MustCompile(`^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// parseISODuration handles the day/time subset of xs:duration that metadata
// cacheDuration values use in practice.
func parseISODuration(value string) (time.Duration, error) {
	match := isoDurationPattern.FindStringSubmatch(value)
	if match == nil || value == "P" || value == "PT" {
		return 0, fmt.Errorf("unsupported xs:duration %q", value)
	}
	var total time.Duration
	units := []time.Duration{24 * time.Hour, time.Hour, time.Minute, time.Second}
	for i, unit := range units {
		if match[i+1] == "" {
			continue
		}
		n, err := strconv.ParseFloat(match[i+1], 64)
		if err != nil {
			return 0, err
		}
		total += time.Duration(n * float64(unit))
	}
	return total, nil
}

// Resolver fetches a peer's metadata from the well-known location that is its
// entityID (SAML Metadata Section 4.1) and caches it until cacheDuration or
// validUntil, whichever comes first.
type Resolver struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*Peer
}

// NewResolver returns a Resolver using client, or a 10-second default client.
func NewResolver(client *http.Client) *Resolver {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Resolver{client: client, cache: map[string]*Peer{}}
}

// Resolve returns the peer's metadata for role, fetching it when the cached
// copy has expired.
func (r *Resolver) Resolve(ctx context.Context, entityID string, role Role) (*Peer, error) {
	now := time.Now()
	key := entityID + "|" + string(role)
	r.mu.Lock()
	cached := r.cache[key]
	r.mu.Unlock()
	if cached != nil && now.Before(cached.cacheUntil) {
		return cached, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, entityID, nil)
	if err != nil {
		return nil, fmt.Errorf("metadata location %q: %w", entityID, err)
	}
	req.Header.Set("Accept", MediaType)
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata from %s: %w", entityID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch metadata from %s: HTTP %d", entityID, resp.StatusCode)
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != MediaType {
		return nil, fmt.Errorf("metadata from %s has Content-Type %q, not %s (SAML Metadata Section 4.1.1)", entityID, resp.Header.Get("Content-Type"), MediaType)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBytes {
		return nil, errors.New("metadata document is too large")
	}
	peer, err := Parse(body, entityID, role, now)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[key] = peer
	r.mu.Unlock()
	return peer, nil
}
