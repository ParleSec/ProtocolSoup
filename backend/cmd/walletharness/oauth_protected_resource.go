package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
)

// startProtectedResourceAuthorization runs the wallet's HAIP authorization_code
// client against an AS discovery document, then stores pending state so the
// callback uses the DPoP-bound access token at resourceEndpoint (RFC 6750 /
// DPoP resource access — the same client path OID4VCI uses before credential
// redeem). Scope is the OAuth scope requested at PAR.
func (s *walletHarnessServer) startProtectedResourceAuthorization(
	ctx context.Context,
	wallet *walletMaterial,
	discoveryURL string,
	resourceEndpoint string,
	scope string,
	walletBaseURL string,
	lookingGlassSessionID string,
) (*externalIssuerImportResult, error) {
	if !s.haipIssuanceEnabled() {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "protected resource authorization requires HAIP client attestation material",
		}
	}
	discoveryURL = strings.TrimSpace(discoveryURL)
	resourceEndpoint = strings.TrimSpace(resourceEndpoint)
	scope = strings.TrimSpace(scope)
	callbackBaseURL := strings.TrimRight(strings.TrimSpace(walletBaseURL), "/")
	if discoveryURL == "" || resourceEndpoint == "" || scope == "" || callbackBaseURL == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "discovery_url, resource_endpoint, scope, and wallet_base_url are required",
		}
	}
	if _, err := s.validateExternalURL(discoveryURL); err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("validate discovery_url: %v", err),
		}
	}
	validatedResource, err := s.validateExternalURL(resourceEndpoint)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("validate resource_endpoint: %v", err),
		}
	}
	resourceEndpoint = validatedResource

	asMetadata, err := s.resolveAuthorizationServerMetadataFromDiscoveryURL(ctx, discoveryURL, lookingGlassSessionID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(asMetadata.PushedAuthorizationRequestEndpoint) == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "authorization server does not advertise pushed_authorization_request_endpoint",
		}
	}
	if strings.TrimSpace(asMetadata.AuthorizationEndpoint) == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "authorization server metadata is missing authorization_endpoint",
		}
	}

	clientID := firstNonEmpty(strings.TrimSpace(s.haipAttestedClientID), strings.TrimSpace(s.oid4vciClientID), callbackBaseURL)
	redirectURI := callbackBaseURL + "/api/oid4vci/callback"
	state := randomValue(24)
	codeVerifier, codeChallenge, _, err := buildPKCES256Pair(asMetadata.CodeChallengeMethodsSupported, true)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: err.Error(),
		}
	}
	expectedIss := authorizationServerIssuer(asMetadata, asMetadata.AuthorizationServer)
	popAudience := popAudienceForAS(asMetadata, expectedIss)
	haipSession, err := s.newHAIPIssuanceSession()
	if err != nil {
		return nil, err
	}
	requestURI, err := s.pushAuthorizationRequest(ctx, pushAuthorizationRequestInput{
		PAREndpoint:           asMetadata.PushedAuthorizationRequestEndpoint,
		AuthorizationEndpoint: asMetadata.AuthorizationEndpoint,
		ClientID:              clientID,
		RedirectURI:           redirectURI,
		State:                 state,
		CodeChallenge:         codeChallenge,
		Scope:                 scope,
		LookingGlassSessionID: lookingGlassSessionID,
		Session:               haipSession,
		PopAudience:           popAudience,
		ChallengeEndpoint:     asMetadata.ChallengeEndpoint,
	})
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("PAR request failed: %v", err),
		}
	}
	authorizationURL, err := buildAuthorizationURLFromPAR(asMetadata.AuthorizationEndpoint, clientID, requestURI)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.oid4vciAuthStates == nil {
		s.oid4vciAuthStates = make(map[string]*pendingOID4VCIAuthState)
	}
	s.pruneOID4VCIAuthStatesLocked(time.Now().UTC())
	s.oid4vciAuthStates[state] = &pendingOID4VCIAuthState{
		State:                       state,
		ScopeKey:                    wallet.ScopeKey,
		WalletSubject:               wallet.Subject,
		WalletBaseURL:               callbackBaseURL,
		ClientID:                    clientID,
		ClientSecret:                strings.TrimSpace(s.oid4vciClientSecret),
		RedirectURI:                 redirectURI,
		CodeVerifier:                codeVerifier,
		AuthorizationServerMetadata: asMetadata,
		LookingGlassSessionID:       strings.TrimSpace(lookingGlassSessionID),
		HAIPSession:                 haipSession,
		ExpectedIss:                 expectedIss,
		PopAudience:                 popAudience,
		UseHAIP:                     true,
		ResourceEndpoint:            resourceEndpoint,
		CreatedAt:                   time.Now().UTC(),
		ExpiresAt:                   time.Now().UTC().Add(oid4vciAuthorizationStateTTL),
	}
	s.mu.Unlock()

	return &externalIssuerImportResult{
		Source:                      "protected_resource_pending",
		AuthorizationRequired:       true,
		AuthorizationURL:            authorizationURL,
		CredentialIssuer:            expectedIss,
		AuthorizationServerMetadata: asMetadata.Raw,
		TokenEndpoint:               asMetadata.TokenEndpoint,
	}, nil
}

func (s *walletHarnessServer) resolveAuthorizationServerMetadataFromDiscoveryURL(
	ctx context.Context,
	discoveryURL string,
	lookingGlassSessionID string,
) (*resolvedAuthorizationServerMetadata, error) {
	validatedURL, err := s.validateExternalURL(discoveryURL)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("validate discovery_url: %v", err),
		}
	}
	validatedURL = preferOIDCDiscoveryURL(validatedURL)
	payload, err := s.fetchJSONDocument(ctx, validatedURL, "application/json", lookingGlassSessionID)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("fetch discovery document: %v", err),
		}
	}
	issuer := strings.TrimSpace(asString(payload["issuer"]))
	if expectedIssuer, ok := issuerIdentifierFromWellKnownDiscoveryURL(validatedURL); ok {
		// OIDC Discovery 1.0 §4.3 / RFC 8414 §3.3: the issuer (authorization
		// server identifier) in the document MUST match the Issuer URL that was
		// used as the prefix to retrieve the configuration. On mismatch the
		// client MUST stop — do not continue to PAR/authorize/token.
		if issuer == "" || !sameURLIdentifier(issuer, expectedIssuer) {
			return nil, &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "discovery_issuer_mismatch",
				Description: fmt.Sprintf(
					"discovery issuer %q does not match Issuer URL %q derived from discovery URL (OIDC Discovery §4.3 / RFC 8414 §3.3); stopping",
					issuer,
					expectedIssuer,
				),
			}
		}
	}
	tokenEndpoint := strings.TrimSpace(asString(payload["token_endpoint"]))
	if tokenEndpoint == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "discovery document missing token_endpoint",
		}
	}
	requirePAR, _ := payload["require_pushed_authorization_requests"].(bool)
	issSupported, _ := payload["authorization_response_iss_parameter_supported"].(bool)
	return &resolvedAuthorizationServerMetadata{
		Raw:                                payload,
		AuthorizationServer:                firstNonEmpty(issuer, validatedURL),
		Issuer:                             firstNonEmpty(issuer, validatedURL),
		AuthorizationEndpoint:              strings.TrimSpace(asString(payload["authorization_endpoint"])),
		TokenEndpoint:                      tokenEndpoint,
		JWKSURI:                            strings.TrimSpace(asString(payload["jwks_uri"])),
		PushedAuthorizationRequestEndpoint: strings.TrimSpace(asString(payload["pushed_authorization_request_endpoint"])),
		ChallengeEndpoint:                  strings.TrimSpace(asString(payload["challenge_endpoint"])),
		RequirePushedAuthorizationRequests: requirePAR,
		CodeChallengeMethodsSupported:      stringSliceFromValue(payload["code_challenge_methods_supported"]),
		DPoPSigningAlgValuesSupported:      stringSliceFromValue(payload["dpop_signing_alg_values_supported"]),
		TokenEndpointAuthMethodsSupported:  stringSliceFromValue(payload["token_endpoint_auth_methods_supported"]),
		AuthorizationResponseIssSupported:  issSupported,
	}, nil
}

// issuerIdentifierFromWellKnownDiscoveryURL recovers the Issuer URL that was
// used as the prefix to form a well-known discovery URL (OIDC Discovery §4 /
// RFC 8414 §3.1): either path-append (.../issuer/.well-known/NAME) or
// path-insert (https://host/.well-known/NAME/issuer/path).
func issuerIdentifierFromWellKnownDiscoveryURL(discoveryURL string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(discoveryURL))
	if err != nil || !parsed.IsAbs() || strings.TrimSpace(parsed.Host) == "" {
		return "", false
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = parsed.Path
	}
	for _, marker := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
	} {
		idx := strings.Index(path, marker)
		if idx < 0 {
			continue
		}
		prefixPath := path[:idx]
		suffixPath := strings.TrimPrefix(path[idx+len(marker):], "/")
		out := *parsed
		out.RawQuery = ""
		out.Fragment = ""
		out.RawPath = ""
		switch {
		case suffixPath != "":
			// RFC 8414 insertion form.
			out.Path = "/" + strings.Trim(suffixPath, "/")
			if strings.HasSuffix(suffixPath, "/") && out.Path != "/" {
				out.Path += "/"
			}
		default:
			// OIDC Discovery append form: {issuer}/.well-known/...
			if prefixPath == "" {
				out.Path = ""
			} else {
				out.Path = prefixPath
			}
		}
		issuer := out.String()
		// Issuer identifiers in discovery documents are compared without a
		// trailing slash for path-based issuers; keep empty path as
		// scheme://host (no trailing slash) for root issuers.
		if out.Path == "/" || out.Path == "" {
			out.Path = ""
			issuer = out.String()
		}
		return strings.TrimRight(issuer, "/"), true
	}
	return "", false
}

// preferOIDCDiscoveryURL maps the OIDC append placement of
// oauth-authorization-server onto openid-configuration. FAPI2 client discovery
// (OIDC Discovery §4) uses {issuer}/.well-known/openid-configuration; the suite
// rejects GET {alias}/.well-known/oauth-authorization-server. RFC 8414 insertion
// (/.well-known/oauth-authorization-server/{path}) is left unchanged for HAIP.
func preferOIDCDiscoveryURL(discoveryURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(discoveryURL))
	if err != nil || !parsed.IsAbs() {
		return discoveryURL
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = parsed.Path
	}
	const marker = "/.well-known/oauth-authorization-server"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return discoveryURL
	}
	suffix := strings.TrimPrefix(path[idx+len(marker):], "/")
	if suffix != "" {
		return discoveryURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.RawPath = ""
	parsed.Path = path[:idx] + "/.well-known/openid-configuration"
	return parsed.String()
}

// fetchProtectedResource GETs a protected resource with a DPoP-bound access
// token. Includes x-fapi-interaction-id (FAPI2 SP Final client resource
// request) and retries on DPoP nonce challenges.
func (s *walletHarnessServer) fetchProtectedResource(
	ctx context.Context,
	resourceURL string,
	accessToken string,
	tokenType string,
	session *haipIssuanceSession,
	lookingGlassSessionID string,
) error {
	validatedURL, err := s.validateExternalURL(resourceURL)
	if err != nil {
		return fmt.Errorf("validate resource endpoint: %w", err)
	}
	if session == nil {
		return fmt.Errorf("dpop session is required for protected resource request")
	}
	input := dpopAuthenticatedRequestInput{
		Method:                http.MethodGet,
		URL:                   validatedURL,
		Accept:                "application/json",
		AccessToken:           accessToken,
		TokenType:             tokenType,
		Session:               session,
		LookingGlassSessionID: lookingGlassSessionID,
		IncludeDPoP:           true,
		Ath:                   true,
		ExtraHeaders: map[string]string{
			"x-fapi-interaction-id": randomFAPIInteractionID(),
		},
	}
	payload, status, headers, body, reqErr := s.doDPoPRequest(ctx, input, "")
	if isSuccessfulOID4VCIJSONStatus(status) {
		return nil
	}
	if isUseDPoPNonceChallenge(status, payload, headers, body) {
		nonce := strings.TrimSpace(headers.Get(dpop.NonceHeaderName))
		if nonce == "" {
			return fmt.Errorf("protected resource returned use_dpop_nonce without %s header", dpop.NonceHeaderName)
		}
		_, status, _, _, retryErr := s.doDPoPRequest(ctx, input, nonce)
		if isSuccessfulOID4VCIJSONStatus(status) {
			return nil
		}
		if retryErr != nil {
			return fmt.Errorf("protected resource request retry: %w", retryErr)
		}
		return fmt.Errorf("protected resource request retry returned %d", status)
	}
	if reqErr != nil {
		return fmt.Errorf("protected resource request: %w", reqErr)
	}
	return fmt.Errorf("protected resource request returned %d: %s", status, oneLine(string(body)))
}

func randomFAPIInteractionID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return randomValue(16)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
