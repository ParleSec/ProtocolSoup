package oid4vp

import (
	"fmt"
	"strings"
)

// ClientIDScheme represents an OpenID4VP client_id prefix profile.
type ClientIDScheme string

const (
	ClientIDSchemePreRegistered           ClientIDScheme = "pre_registered"
	ClientIDSchemeRedirectURI             ClientIDScheme = "redirect_uri"
	ClientIDSchemeDecentralizedIdentifier ClientIDScheme = "decentralized_identifier"
	ClientIDSchemeOpenIDFederation        ClientIDScheme = "openid_federation"
	ClientIDSchemeX509SANDNS              ClientIDScheme = "x509_san_dns"
	ClientIDSchemeX509Hash                ClientIDScheme = "x509_hash"
	ClientIDSchemeVerifierAttestation     ClientIDScheme = "verifier_attestation"
	ClientIDSchemeUnknown                 ClientIDScheme = "unknown"
)

var prefixedClientIDSchemes = map[string]ClientIDScheme{
	"redirect_uri":             ClientIDSchemeRedirectURI,
	"decentralized_identifier": ClientIDSchemeDecentralizedIdentifier,
	"openid_federation":        ClientIDSchemeOpenIDFederation,
	"x509_san_dns":             ClientIDSchemeX509SANDNS,
	"x509_hash":                ClientIDSchemeX509Hash,
	"verifier_attestation":     ClientIDSchemeVerifierAttestation,
}

// ParseClientIDSchemeName resolves a raw client_id_scheme name to a known profile.
func ParseClientIDSchemeName(raw string) (ClientIDScheme, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		return ClientIDSchemeUnknown, fmt.Errorf("client_id_scheme is required")
	}
	if normalized == string(ClientIDSchemePreRegistered) {
		return ClientIDSchemePreRegistered, nil
	}
	scheme, ok := prefixedClientIDSchemes[normalized]
	if !ok {
		return ClientIDSchemeUnknown, fmt.Errorf("client_id_scheme %q is not supported", normalized)
	}
	return scheme, nil
}

// DefaultMVPClientIDSchemeSet returns the initial OID4VP client_id scheme allowlist.
func DefaultMVPClientIDSchemeSet() map[ClientIDScheme]struct{} {
	return map[ClientIDScheme]struct{}{
		ClientIDSchemeRedirectURI:             {},
		ClientIDSchemeDecentralizedIdentifier: {},
	}
}

// ParseClientIDScheme resolves the client_id scheme from a raw client_id value.
func ParseClientIDScheme(clientID string) (ClientIDScheme, error) {
	trimmed := strings.TrimSpace(clientID)
	if trimmed == "" {
		return ClientIDSchemeUnknown, fmt.Errorf("client_id is required")
	}

	idx := strings.Index(trimmed, ":")
	if idx == -1 {
		return ClientIDSchemePreRegistered, nil
	}

	prefix := trimmed[:idx]
	scheme, ok := prefixedClientIDSchemes[prefix]
	if !ok {
		return ClientIDSchemeUnknown, nil
	}
	return scheme, nil
}

// ValidateSupportedClientIDScheme enforces the configured MVP client_id scheme matrix.
func ValidateSupportedClientIDScheme(clientID string, supported map[ClientIDScheme]struct{}) error {
	scheme, err := ParseClientIDScheme(clientID)
	if err != nil {
		return err
	}

	if _, ok := supported[scheme]; !ok {
		return fmt.Errorf("client_id scheme %q is not supported by this profile", scheme)
	}
	return nil
}

// ValidateDCQLQueryContract enforces OpenID4VP's dcql_query vs scope alias XOR rule.
func ValidateDCQLQueryContract(dcqlQuery string, scopeAlias string) error {
	hasDCQL := strings.TrimSpace(dcqlQuery) != ""
	hasScopeAlias := strings.TrimSpace(scopeAlias) != ""

	switch {
	case hasDCQL && hasScopeAlias:
		return fmt.Errorf("dcql_query and scope alias are mutually exclusive")
	case !hasDCQL && !hasScopeAlias:
		return fmt.Errorf("either dcql_query or scope alias is required")
	default:
		return nil
	}
}

// ValidateDirectPostContract enforces response_uri and redirect_uri constraints for direct_post modes.
func ValidateDirectPostContract(responseMode string, responseURI string, redirectURI string) error {
	mode := strings.TrimSpace(responseMode)
	if mode != "direct_post" && mode != "direct_post.jwt" {
		return nil
	}

	if strings.TrimSpace(responseURI) == "" {
		return fmt.Errorf("response_uri is required for response_mode %q", mode)
	}
	if strings.TrimSpace(redirectURI) != "" {
		return fmt.Errorf("redirect_uri must not be present for response_mode %q", mode)
	}
	return nil
}

// ValidateRequestObjectType enforces the request object typ header value.
func ValidateRequestObjectType(typ string) error {
	if strings.TrimSpace(typ) != "oauth-authz-req+jwt" {
		return fmt.Errorf("request object typ must be oauth-authz-req+jwt")
	}
	return nil
}

// ValidateResponseJWTType enforces the direct_post.jwt response typ header value.
func ValidateResponseJWTType(typ string) error {
	if strings.TrimSpace(typ) != "oauth-authz-resp+jwt" {
		return fmt.Errorf("direct_post.jwt typ must be oauth-authz-resp+jwt")
	}
	return nil
}

// ValidateVPTokenType enforces VP token typ header value.
func ValidateVPTokenType(typ string) error {
	if strings.TrimSpace(typ) != "vp+jwt" {
		return fmt.Errorf("vp_token typ must be vp+jwt")
	}
	return nil
}

// ValidateNoncePresence enforces non-empty nonce value for OpenID4VP requests.
func ValidateNoncePresence(nonce string) error {
	if strings.TrimSpace(nonce) == "" {
		return fmt.Errorf("nonce is required")
	}
	return nil
}
