package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// registrationRequest is the subset of OIDC Dynamic Client Registration metadata
// this OP understands. Unknown fields are ignored by decoding into this typed
// struct (OIDC Dynamic Client Registration 1.0 Section 3.2 / RFC 7591 Section 2).
type registrationRequest struct {
	ClientID                    string       `json:"client_id"`
	ClientSecret                string       `json:"client_secret"`
	RedirectURIs                []string     `json:"redirect_uris"`
	ResponseTypes               []string     `json:"response_types"`
	GrantTypes                  []string     `json:"grant_types"`
	ApplicationType             string       `json:"application_type"`
	Contacts                    []string     `json:"contacts"`
	ClientName                  string       `json:"client_name"`
	LogoURI                     string       `json:"logo_uri"`
	ClientURI                   string       `json:"client_uri"`
	PolicyURI                   string       `json:"policy_uri"`
	TosURI                      string       `json:"tos_uri"`
	JwksURI                     string       `json:"jwks_uri"`
	Jwks                        *crypto.JWKS `json:"jwks"`
	SubjectType                 string       `json:"subject_type"`
	SectorIdentifierURI         string       `json:"sector_identifier_uri"`
	IDTokenSignedResponseAlg    string       `json:"id_token_signed_response_alg"`
	UserinfoSignedResponseAlg   string       `json:"userinfo_signed_response_alg"`
	RequestObjectSigningAlg     string       `json:"request_object_signing_alg"`
	TokenEndpointAuthMethod     string       `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg string       `json:"token_endpoint_auth_signing_alg"`
	DefaultMaxAge               *int64       `json:"default_max_age"`
	RequireAuthTime             *bool        `json:"require_auth_time"`
	InitiateLoginURI            string       `json:"initiate_login_uri"`
	Scope                       string       `json:"scope"`
}

type registrationValidationError struct {
	Code        string
	Description string
}

func (e *registrationValidationError) Error() string {
	return e.Description
}

func invalidRedirectURI(desc string) error {
	return &registrationValidationError{Code: "invalid_redirect_uri", Description: desc}
}

func invalidClientMetadata(desc string) error {
	return &registrationValidationError{Code: "invalid_client_metadata", Description: desc}
}

func validateRegistrationRequest(req *registrationRequest) error {
	if req == nil {
		return invalidClientMetadata("registration request is required")
	}
	if len(req.RedirectURIs) == 0 {
		return invalidRedirectURI("redirect_uris is required (OpenID Connect Dynamic Client Registration 1.0 Section 2)")
	}

	applicationType := strings.TrimSpace(req.ApplicationType)
	if applicationType == "" {
		applicationType = "web"
	}
	if applicationType != "web" && applicationType != "native" {
		return invalidClientMetadata("application_type must be web or native")
	}
	req.ApplicationType = applicationType

	for _, raw := range req.RedirectURIs {
		if err := validateRedirectURI(raw, applicationType); err != nil {
			return err
		}
	}

	responseTypes, grantTypes, err := normalizeResponseAndGrantTypes(req.ResponseTypes, req.GrantTypes)
	if err != nil {
		return err
	}
	req.ResponseTypes = responseTypes
	req.GrantTypes = grantTypes

	authMethod := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	switch authMethod {
	case "client_secret_basic", "client_secret_post", "private_key_jwt", "none":
	default:
		return invalidClientMetadata("unsupported token_endpoint_auth_method")
	}
	req.TokenEndpointAuthMethod = authMethod

	if req.Jwks != nil && strings.TrimSpace(req.JwksURI) != "" {
		return invalidClientMetadata("jwks and jwks_uri must not be used together (OIDC Dynamic Client Registration 1.0 Section 2)")
	}
	if strings.TrimSpace(req.JwksURI) != "" {
		if err := validateHTTPSURL(req.JwksURI, "jwks_uri"); err != nil {
			return err
		}
	}
	if req.Jwks != nil {
		if err := validatePublicJWKS(req.Jwks); err != nil {
			return err
		}
	}
	if authMethod == "private_key_jwt" && req.Jwks == nil && strings.TrimSpace(req.JwksURI) == "" {
		return invalidClientMetadata("private_key_jwt requires jwks or jwks_uri")
	}

	if strings.TrimSpace(req.SubjectType) != "" && req.SubjectType != "public" && req.SubjectType != "pairwise" {
		return invalidClientMetadata("subject_type must be public or pairwise")
	}
	if req.SubjectType == "" {
		req.SubjectType = "public"
	}
	if req.SubjectType == "pairwise" {
		if err := validatePairwiseSectorRequest(req); err != nil {
			return err
		}
	} else if strings.TrimSpace(req.SectorIdentifierURI) != "" {
		return invalidClientMetadata("sector_identifier_uri is valid only for subject_type=pairwise")
	}

	idTokenAlg := strings.TrimSpace(req.IDTokenSignedResponseAlg)
	if idTokenAlg == "" {
		idTokenAlg = "RS256"
	}
	if idTokenAlg != "RS256" {
		return invalidClientMetadata("id_token_signed_response_alg must be RS256")
	}
	req.IDTokenSignedResponseAlg = idTokenAlg

	if alg := strings.TrimSpace(req.UserinfoSignedResponseAlg); alg != "" && alg != "RS256" {
		return invalidClientMetadata("userinfo_signed_response_alg must be RS256 when requested")
	}
	if alg := strings.TrimSpace(req.RequestObjectSigningAlg); alg != "" && alg != "RS256" {
		return invalidClientMetadata("request_object_signing_alg must be RS256 when requested")
	}
	if alg := strings.TrimSpace(req.TokenEndpointAuthSigningAlg); alg != "" {
		switch alg {
		case "RS256", "ES256", "EdDSA":
		default:
			return invalidClientMetadata("unsupported token_endpoint_auth_signing_alg")
		}
	}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"logo_uri", req.LogoURI},
		{"client_uri", req.ClientURI},
		{"policy_uri", req.PolicyURI},
		{"tos_uri", req.TosURI},
	} {
		if strings.TrimSpace(field.value) == "" {
			continue
		}
		if err := validateHTTPSURL(field.value, field.name); err != nil {
			return err
		}
	}

	if uri := strings.TrimSpace(req.InitiateLoginURI); uri != "" {
		if err := validateHTTPSURL(uri, "initiate_login_uri"); err != nil {
			return err
		}
	}

	if req.DefaultMaxAge != nil && *req.DefaultMaxAge < 0 {
		return invalidClientMetadata("default_max_age must be non-negative")
	}

	return nil
}

// validateRegistrationUpdateRequest applies RFC 7592 Section 2.2 checks that
// only apply to an authenticated replacement of an existing registration.
func validateRegistrationUpdateRequest(body []byte, req *registrationRequest, client *models.Client) error {
	if client == nil {
		return invalidClientMetadata("client registration is required")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return invalidClientMetadata("client_id is required for a registration update")
	}
	if req.ClientID != client.ID {
		return invalidClientMetadata("client_id must match the client configuration endpoint")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return invalidClientMetadata("registration request must be a JSON object")
	}
	for _, name := range []string{
		"registration_access_token",
		"registration_client_uri",
		"client_secret_expires_at",
		"client_id_issued_at",
	} {
		if _, present := fields[name]; present {
			return invalidClientMetadata(name + " must not be included in a registration update")
		}
	}
	_, includesSecret := fields["client_secret"]
	if client.Secret != "" && !includesSecret {
		return invalidClientMetadata("client_secret is required for a confidential client registration update")
	}
	if includesSecret && !subtleConstantTimeEqual(client.Secret, req.ClientSecret) {
		return invalidClientMetadata("client_secret must match the currently issued client secret")
	}
	return nil
}

func normalizeResponseAndGrantTypes(responseTypes, grantTypes []string) ([]string, []string, error) {
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	normalizedRT := make([]string, 0, len(responseTypes))
	seenRT := map[string]bool{}
	for _, rt := range responseTypes {
		canonical, ok := canonicalizeResponseType(rt)
		if !ok {
			return nil, nil, invalidClientMetadata("unsupported response_type: " + rt)
		}
		if seenRT[canonical] {
			continue
		}
		seenRT[canonical] = true
		normalizedRT = append(normalizedRT, canonical)
	}

	if len(grantTypes) == 0 {
		grantTypes = defaultGrantTypesForResponseTypes(normalizedRT)
	}
	normalizedGT := make([]string, 0, len(grantTypes))
	seenGT := map[string]bool{}
	for _, gt := range grantTypes {
		gt = strings.TrimSpace(gt)
		switch gt {
		case "authorization_code", "implicit", "refresh_token":
		default:
			return nil, nil, invalidClientMetadata("unsupported grant_type: " + gt)
		}
		if seenGT[gt] {
			continue
		}
		seenGT[gt] = true
		normalizedGT = append(normalizedGT, gt)
	}

	required := defaultGrantTypesForResponseTypes(normalizedRT)
	for _, need := range required {
		if !seenGT[need] {
			return nil, nil, invalidClientMetadata(fmt.Sprintf("grant_types must include %s for the registered response_types", need))
		}
	}
	return normalizedRT, normalizedGT, nil
}

func defaultGrantTypesForResponseTypes(responseTypes []string) []string {
	needCode := false
	needImplicit := false
	for _, rt := range responseTypes {
		parts := strings.Fields(rt)
		for _, part := range parts {
			switch part {
			case "code":
				needCode = true
			case "token", "id_token":
				needImplicit = true
			}
		}
	}
	out := make([]string, 0, 2)
	if needCode {
		out = append(out, "authorization_code")
	}
	if needImplicit {
		out = append(out, "implicit")
	}
	if len(out) == 0 {
		out = []string{"authorization_code"}
	}
	return out
}

func canonicalizeResponseType(raw string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return "", false
	}
	seen := map[string]bool{}
	for _, part := range parts {
		switch part {
		case "code", "token", "id_token":
		default:
			return "", false
		}
		seen[part] = true
	}
	canonicalOrder := []string{"code", "id_token", "token"}
	sorted := make([]string, 0, len(seen))
	for _, part := range canonicalOrder {
		if seen[part] {
			sorted = append(sorted, part)
		}
	}
	value := strings.Join(sorted, " ")
	switch value {
	case "code", "token", "id_token", "id_token token", "code id_token", "code token", "code id_token token":
		return value, true
	default:
		return "", false
	}
}

func validateRedirectURI(raw, applicationType string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return invalidRedirectURI("redirect_uris entries must not be empty")
	}
	if strings.Contains(raw, "#") {
		return invalidRedirectURI("redirect_uris must not include a fragment (RFC 6749 Section 3.1.2)")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return invalidRedirectURI("redirect_uris must be valid absolute URIs")
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	switch applicationType {
	case "web":
		if scheme != "https" {
			if scheme == "http" && isLoopbackHost(host) {
				return nil
			}
			return invalidRedirectURI("web clients must register https redirect_uris (except loopback http)")
		}
		if host == "localhost" {
			return invalidRedirectURI("web clients must not use localhost as the hostname")
		}
		if host == "" {
			return invalidRedirectURI("redirect_uris must include a host")
		}
	case "native":
		switch {
		case isCustomScheme(scheme):
			return nil
		case scheme == "http" && isLoopbackHost(host):
			return nil
		case scheme == "https" && host != "":
			return nil
		default:
			return invalidRedirectURI("native clients must use custom schemes or loopback http redirect_uris")
		}
	}
	return nil
}

func isCustomScheme(scheme string) bool {
	switch scheme {
	case "http", "https":
		return false
	default:
		return scheme != ""
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func validateHTTPSURL(raw, field string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return invalidClientMetadata(field + " must be a valid absolute URI")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return invalidClientMetadata(field + " must use the https scheme")
	}
	if parsed.Fragment != "" {
		return invalidClientMetadata(field + " must not include a fragment")
	}
	return nil
}

func validatePublicJWKS(jwks *crypto.JWKS) error {
	if jwks == nil || len(jwks.Keys) == 0 {
		return invalidClientMetadata("jwks must contain at least one key")
	}
	for _, key := range jwks.Keys {
		if key.D != "" || key.P != "" || key.Q != "" || key.DP != "" || key.DQ != "" || key.QI != "" || key.K != "" {
			return invalidClientMetadata("jwks must not contain private or symmetric key values")
		}
		if key.Kty == "" {
			return invalidClientMetadata("jwks keys must include kty")
		}
	}
	return nil
}

func decodeRegistrationRequest(body []byte) (*registrationRequest, error) {
	var req registrationRequest
	// Unknown fields MUST be ignored (OIDCR §3.2 / RFC 7591 §2).
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, invalidClientMetadata("registration request must be a JSON object")
	}
	return &req, nil
}

// validatePairwiseSectorRequest applies OIDC Core Section 8.1 before the
// registration endpoint fetches a provided sector identifier document.
func validatePairwiseSectorRequest(req *registrationRequest) error {
	hosts := make(map[string]struct{})
	for _, raw := range req.RedirectURIs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return invalidRedirectURI("redirect_uris must contain valid hosts for pairwise subjects")
		}
		hosts[strings.ToLower(parsed.Hostname())] = struct{}{}
	}
	if strings.TrimSpace(req.SectorIdentifierURI) == "" {
		if len(hosts) > 1 {
			return invalidClientMetadata("pairwise clients with multiple redirect URI hosts require sector_identifier_uri")
		}
		return nil
	}
	return validateHTTPSURL(req.SectorIdentifierURI, "sector_identifier_uri")
}

// validateSectorIdentifierDocument validates the sector_identifier_uri at
// registration time as required by OIDC Registration Section 5.
func (p *Plugin) validateSectorIdentifierDocument(req *registrationRequest) error {
	if req.SubjectType != "pairwise" || strings.TrimSpace(req.SectorIdentifierURI) == "" {
		return nil
	}
	redirectURIs, err := fetchSectorRedirectURIs(req.SectorIdentifierURI)
	if err != nil {
		return invalidClientMetadata("sector_identifier_uri validation failed: " + err.Error())
	}
	allowed := make(map[string]struct{}, len(redirectURIs))
	for _, redirectURI := range redirectURIs {
		allowed[redirectURI] = struct{}{}
	}
	for _, redirectURI := range req.RedirectURIs {
		if _, found := allowed[redirectURI]; !found {
			return invalidClientMetadata("sector_identifier_uri does not list every registered redirect_uri")
		}
	}
	return nil
}

const maxSectorIdentifierDocumentBytes = 64 * 1024

func fetchSectorRedirectURIs(rawURL string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("sector_identifier_uri must be an HTTPS URL without userinfo or fragment")
	}
	if err := rejectSectorSSRF(ctx, parsed.Hostname()); err != nil {
		return nil, err
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = secureSectorDialContext
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("sector_identifier_uri redirects are not allowed")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sector_identifier_uri returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSectorIdentifierDocumentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxSectorIdentifierDocumentBytes {
		return nil, errors.New("sector_identifier_uri response exceeds 64KB")
	}
	var redirectURIs []string
	if err := json.Unmarshal(body, &redirectURIs); err != nil {
		return nil, errors.New("sector_identifier_uri must contain a JSON array of redirect_uri values")
	}
	if len(redirectURIs) == 0 {
		return nil, errors.New("sector_identifier_uri document is empty")
	}
	return redirectURIs, nil
}

func rejectSectorSSRF(ctx context.Context, host string) error {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	if len(addresses) == 0 {
		return errors.New("sector_identifier_uri host resolved to no addresses")
	}
	for _, address := range addresses {
		if isBlockedSectorAddress(address.IP) {
			return fmt.Errorf("sector_identifier_uri resolves to blocked address %s", address.IP)
		}
	}
	return nil
}

func secureSectorDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	var lastErr error
	for _, candidate := range addresses {
		if isBlockedSectorAddress(candidate.IP) {
			lastErr = fmt.Errorf("refusing blocked sector_identifier_uri address %s", candidate.IP)
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("sector_identifier_uri host resolved to no usable addresses")
	}
	return nil, lastErr
}

func isBlockedSectorAddress(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range blockedSectorAddressPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

var blockedSectorAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}
