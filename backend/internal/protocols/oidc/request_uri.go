package oidc

import (
	"encoding/json"
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

const (
	maxRequestObjectBytes  = 32 * 1024
	requestURIFetchTimeout = 5 * time.Second
)

// applyRequestURI fetches and merges a Request Object passed by reference
// (OIDC Core 1.0 Section 6.2 / §15.2 Dynamic OP MTI). Parameters in the Request
// Object take precedence over duplicate OAuth query parameters.
func (p *Plugin) applyRequestURI(query url.Values) (url.Values, string, string) {
	requestURI := strings.TrimSpace(query.Get("request_uri"))
	if requestURI == "" {
		return query, "", ""
	}
	if strings.HasPrefix(requestURI, "urn:ietf:params:oauth:request_uri:") {
		return p.applyPushedAuthorizationRequest(query, requestURI)
	}
	if !p.registrationEnabled() {
		return nil, "request_uri_not_supported", "The request_uri parameter is not supported"
	}
	if strings.TrimSpace(query.Get("request")) != "" {
		return nil, "invalid_request", "request and request_uri must not be used together"
	}

	clientID := query.Get("client_id")
	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		return nil, "invalid_client", "Unknown client"
	}

	rawJWT, err := p.fetchRequestObject(requestURI)
	if err != nil {
		return nil, "invalid_request_uri", err.Error()
	}

	claims, err := p.verifyRequestObjectJWT(rawJWT, client)
	if err != nil {
		return nil, "invalid_request_object", err.Error()
	}

	merged := cloneValues(query)
	merged.Del("request_uri")
	for key, value := range claims {
		switch typed := value.(type) {
		case string:
			merged.Set(key, typed)
		case float64:
			merged.Set(key, trimFloat(typed))
		case bool:
			merged.Set(key, fmt.Sprintf("%t", typed))
		case map[string]interface{}, []interface{}:
			encoded, err := json.Marshal(typed)
			if err != nil {
				return nil, "invalid_request_object", "unable to encode request object claim " + key
			}
			merged.Set(key, string(encoded))
		default:
			// Ignore unrecognized claim shapes while preserving known strings.
		}
	}

	if responseType := merged.Get("response_type"); responseType != "" && query.Get("response_type") != "" {
		if canonicalizeSet(responseType) != canonicalizeSet(query.Get("response_type")) {
			return nil, "invalid_request", "response_type in request object must match the OAuth request parameter"
		}
	}
	if objectClientID := merged.Get("client_id"); objectClientID != "" && objectClientID != clientID {
		return nil, "invalid_request", "client_id in request object must match the OAuth request parameter"
	}
	return merged, "", ""
}

func (p *Plugin) applyPushedAuthorizationRequest(query url.Values, requestURI string) (url.Values, string, string) {
	if p.mockIdP == nil {
		return nil, "server_error", "authorization server state is unavailable"
	}
	if strings.TrimSpace(query.Get("request")) != "" {
		return nil, "invalid_request", "request and request_uri must not be used together"
	}
	pushed, err := p.mockIdP.GetPushedAuthorizationRequest(requestURI, query.Get("client_id"))
	if err != nil {
		return nil, "invalid_request_uri", err.Error()
	}
	merged := cloneValues(query)
	merged.Del("request_uri")
	merged.Set("client_id", pushed.ClientID)
	merged.Set("redirect_uri", pushed.RedirectURI)
	merged.Set("response_type", pushed.ResponseType)
	merged.Set("scope", pushed.Scope)
	merged.Set("state", pushed.State)
	merged.Set("nonce", pushed.Nonce)
	merged.Set("code_challenge", pushed.CodeChallenge)
	merged.Set("code_challenge_method", pushed.CodeChallengeMethod)
	if pushed.AuthorizationDetailsUsed {
		// Restore the wallet's RFC 9396 authorization_details so the shared
		// authorize endpoint validates locations and marks the code as RAR-bound.
		details := make([]map[string]interface{}, 0, len(pushed.CredentialConfigurationIDs))
		for _, configurationID := range pushed.CredentialConfigurationIDs {
			details = append(details, map[string]interface{}{
				"type":                        "openid_credential",
				"credential_configuration_id": configurationID,
				"locations":                   []string{strings.TrimRight(p.baseURL, "/") + "/oid4vci"},
			})
		}
		encodedDetails, err := json.Marshal(details)
		if err != nil {
			return nil, "server_error", "unable to restore pushed authorization details"
		}
		merged.Set("authorization_details", string(encodedDetails))
		merged.Set("_ps_authorization_details_used", "true")
	} else if len(pushed.CredentialConfigurationIDs) > 0 {
		// Scope-only OID4VCI PAR: carry authorized configuration IDs without
		// synthesizing authorization_details. OID4VCI §6.2 token-response
		// authorization_details is OPTIONAL for scope; inventing configuration
		// IDs beyond what was authorized is incorrect.
		encodedIDs, err := json.Marshal(pushed.CredentialConfigurationIDs)
		if err != nil {
			return nil, "server_error", "unable to restore pushed credential configuration ids"
		}
		merged.Set("_ps_credential_configuration_ids", string(encodedIDs))
	}
	merged.Set("_ps_par_request_uri", pushed.RequestURI)
	merged.Set("_ps_dpop_jkt", pushed.DPoPJKT)
	merged.Set("_ps_issuer_state", pushed.IssuerState)
	return merged, "", ""
}

func (p *Plugin) fetchRequestObject(requestURI string) (string, error) {
	parsed, err := url.Parse(requestURI)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return "", fmt.Errorf("request_uri must be an https URL")
	}
	if err := rejectSSRFHost(parsed.Hostname()); err != nil {
		return "", err
	}

	client := &http.Client{
		Timeout: requestURIFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return fmt.Errorf("too many redirects fetching request_uri")
			}
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("request_uri redirects must remain https")
			}
			return rejectSSRFHost(req.URL.Hostname())
		},
	}
	resp, err := client.Get(requestURI)
	if err != nil {
		return "", fmt.Errorf("failed to fetch request_uri")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request_uri returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestObjectBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read request_uri body")
	}
	if len(body) > maxRequestObjectBytes {
		return "", fmt.Errorf("request_uri body too large")
	}
	return strings.TrimSpace(string(body)), nil
}

func (p *Plugin) verifyRequestObjectJWT(raw string, client *models.Client) (map[string]interface{}, error) {
	decoded, err := crypto.DecodeTokenWithoutValidation(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed request object")
	}
	alg, _ := decoded.Header["alg"].(string)
	if alg != "RS256" {
		return nil, fmt.Errorf("request object must be signed with RS256")
	}
	if client.RequestObjectSigningAlg != "" && client.RequestObjectSigningAlg != alg {
		return nil, fmt.Errorf("request object alg does not match registered request_object_signing_alg")
	}

	keyID, _ := decoded.Header["kid"].(string)
	jwk, err := resolveClientJWK(client, keyID)
	if err != nil {
		return nil, err
	}
	publicKey, err := jwk.ToPublicKey()
	if err != nil {
		return nil, fmt.Errorf("invalid client signing key")
	}
	valid, err := crypto.VerifySignatureWithKey(raw, publicKey)
	if err != nil || !valid {
		return nil, fmt.Errorf("request object signature invalid")
	}

	issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
	if aud, ok := decoded.Payload["aud"]; ok && !audienceIncludes(aud, issuer) {
		return nil, fmt.Errorf("request object aud must target the OP issuer")
	}
	if iss, ok := decoded.Payload["iss"].(string); ok && iss != "" && iss != client.ID {
		return nil, fmt.Errorf("request object iss must be the client_id")
	}
	return decoded.Payload, nil
}

func resolveClientJWK(client *models.Client, kid string) (*crypto.JWK, error) {
	if client == nil {
		return nil, fmt.Errorf("client required")
	}
	if client.JWKS != nil {
		for i := range client.JWKS.Keys {
			key := client.JWKS.Keys[i]
			if kid == "" || key.Kid == kid {
				return &key, nil
			}
		}
	}
	if client.JWKSURI != "" {
		resp, err := (&http.Client{Timeout: requestURIFetchTimeout}).Get(client.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch client jwks_uri")
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxClientJWKSResponseSize))
		if err != nil {
			return nil, fmt.Errorf("failed to read client jwks_uri")
		}
		var jwks crypto.JWKS
		if err := json.Unmarshal(body, &jwks); err != nil {
			return nil, fmt.Errorf("invalid client jwks_uri document")
		}
		for i := range jwks.Keys {
			key := jwks.Keys[i]
			if kid == "" || key.Kid == kid {
				return &key, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching client key for request object")
}

const maxClientJWKSResponseSize = 64 * 1024

func rejectSSRFHost(host string) error {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return fmt.Errorf("request_uri host is required")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("request_uri must not target loopback hosts")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("request_uri host could not be resolved")
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("request_uri must not target private or link-local addresses")
		}
	}
	return nil
}

func audienceIncludes(raw interface{}, expected string) bool {
	switch value := raw.(type) {
	case string:
		return value == expected
	case []interface{}:
		for _, item := range value {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, s := range value {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, vals := range in {
		out[k] = append([]string{}, vals...)
	}
	return out
}

func canonicalizeSet(responseType string) string {
	canonical, ok := canonicalizeResponseType(responseType)
	if !ok {
		return strings.Join(strings.Fields(responseType), " ")
	}
	return canonical
}

func trimFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}
