package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	oid4vciprotocol "github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

type apiImportRequest struct {
	WalletSubject      string `json:"wallet_subject,omitempty"`
	Offer              string `json:"offer,omitempty"`
	Credential         string `json:"credential,omitempty"`
	TxCode             string `json:"tx_code,omitempty"`
	CredentialFormat   string `json:"credential_format,omitempty"`
	CredentialConfigID string `json:"credential_configuration_id,omitempty"`
	// CredentialIssuer starts wallet-initiated OID4VCI: fetch Credential
	// Issuer Metadata and either return configurations or, with
	// credential_configuration_id, begin authorization_code without an offer.
	CredentialIssuer      string `json:"credential_issuer,omitempty"`
	LookingGlassSessionID string `json:"looking_glass_session_id,omitempty"`
	// DiscoveryURL + ResourceEndpoint + Scope drive HAIP authorization_code
	// against an AS, then DPoP GET of the protected resource (no credential).
	DiscoveryURL     string `json:"discovery_url,omitempty"`
	ResourceEndpoint string `json:"resource_endpoint,omitempty"`
	Scope            string `json:"scope,omitempty"`
	WalletBaseURL    string `json:"wallet_base_url,omitempty"`
}

type walletAPIError struct {
	Status      int
	Code        string
	Description string
	Fields      map[string]interface{}
}

func (e *walletAPIError) Error() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.Description)
}

// normalizeWalletImportHTTPStatus keeps true upstream outages as 502 while
// remapping protocol/application failures away from Bad Gateway. Some CDNs
// replace 502 responses and drop Access-Control-Allow-Origin, which browsers
// surface only as "Failed to fetch".
func normalizeWalletImportHTTPStatus(status int) int {
	if status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == 0 {
		return http.StatusBadRequest
	}
	return status
}

type resolvedCredentialOfferInput struct {
	Offer         models.VCCredentialOffer
	RawOffer      map[string]interface{}
	OfferURI      string
	TransportMode string
}

type resolvedExternalIssuerMetadata struct {
	Raw                               map[string]interface{}
	CredentialIssuer                  string
	CredentialEndpoint                string
	NonceEndpoint                     string
	NotificationEndpoint              string
	DeferredCredentialEndpoint        string
	JWKSURI                           string
	AuthorizationServers              []string
	CredentialConfigurationsSupported map[string]map[string]interface{}
	CredentialResponseEncryption      credentialResponseEncryptionSupport
	CredentialRequestEncryption       credentialRequestEncryptionSupport
	BatchCredentialIssuanceSize       int
	BatchCredentialIssuanceAdvertised bool
}

type resolvedAuthorizationServerMetadata struct {
	Raw                                map[string]interface{}
	AuthorizationServer                string
	Issuer                             string
	AuthorizationEndpoint              string
	TokenEndpoint                      string
	JWKSURI                            string
	PushedAuthorizationRequestEndpoint string
	ChallengeEndpoint                  string
	RequirePushedAuthorizationRequests bool
	CodeChallengeMethodsSupported      []string
	DPoPSigningAlgValuesSupported      []string
	TokenEndpointAuthMethodsSupported  []string
	AuthorizationResponseIssSupported  bool
}

type externalIssuerImportRequest struct {
	OfferInput            string
	TxCode                string
	CredentialFormat      string
	CredentialConfigID    string
	CredentialIssuer      string
	LookingGlassSessionID string
	WalletBaseURL         string
}

type externalIssuerImportResult struct {
	Source                            string
	AuthorizationRequired             bool
	AuthorizationURL                  string
	IssuedCredential                  *issuedWalletCredential
	CredentialOffer                   map[string]interface{}
	CredentialOfferURI                string
	CredentialOfferTransport          string
	CredentialIssuer                  string
	IssuerMetadata                    map[string]interface{}
	AuthorizationServerMetadata       map[string]interface{}
	TokenEndpoint                     string
	CredentialEndpoint                string
	NonceEndpoint                     string
	TxCodeRequired                    bool
	TxCodeDescription                 string
	TxCodeLength                      int
	TxCodeInputMode                   string
	ConfigurationSelectionRequired    bool
	CredentialConfigurations          []map[string]interface{}
	SelectedCredentialConfigurationID string
	SelectedCredentialFormat          string
	IssuanceRequirements              map[string]interface{}
}

type pendingOID4VCIAuthState struct {
	State                       string
	ScopeKey                    string
	WalletSubject               string
	WalletBaseURL               string
	ClientID                    string
	ClientSecret                string
	RedirectURI                 string
	CodeVerifier                string
	CredentialConfigurationID   string
	CredentialFormat            string
	JWTProofRequired            bool
	IssuerMetadata              *resolvedExternalIssuerMetadata
	AuthorizationServerMetadata *resolvedAuthorizationServerMetadata
	LookingGlassSessionID       string
	HAIPSession                 *haipIssuanceSession
	ExpectedIss                 string
	PopAudience                 string
	UseHAIP                     bool
	// ResourceEndpoint, when set, means this authorization was for protected
	// resource access: after token exchange the wallet GETs this URL with the
	// DPoP-bound access token instead of redeeming an OID4VCI credential.
	ResourceEndpoint string
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

const oid4vciAuthorizationStateTTL = 15 * time.Minute

// maxCredentialImportBodyBytes caps the request body for handleAPIImport,
// the HTTP entry point through which a caller can paste an arbitrary
// credential directly (apiImportRequest.Credential) rather than one this
// server fetched itself from a negotiated OID4VCI credential endpoint. Per
// internal/cose's decModeUntrusted, this is one of the two externally-supplied
// credential surfaces (the other is the Looking Glass decode endpoint);
// enforcing the cap here, before the body is buffered, keeps it consistent
// with that surface rather than relying solely on decodeJSONBody's general
// 1 MiB safety net. 64 KiB comfortably covers a real mDL or SD-JWT VC
// (including one carrying a portrait image), well above anything this
// project issues.
const maxCredentialImportBodyBytes = 64 * 1024

func (s *walletHarnessServer) handleAPIImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCredentialImportBodyBytes)

	var req apiImportRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	scopeKey, _, err := s.resolveAPIScopeKey(w, r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	subject := strings.TrimSpace(req.WalletSubject)
	if subject == "" {
		subject = scopedWalletSubject(s.defaultWalletSubject, scopeKey)
	}
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": err.Error(),
		})
		return
	}

	hasOffer := strings.TrimSpace(req.Offer) != ""
	hasCredential := strings.TrimSpace(req.Credential) != ""
	hasIssuer := strings.TrimSpace(req.CredentialIssuer) != ""
	hasResourceAuth := strings.TrimSpace(req.DiscoveryURL) != "" ||
		strings.TrimSpace(req.ResourceEndpoint) != "" ||
		strings.TrimSpace(req.Scope) != ""
	modes := 0
	if hasOffer {
		modes++
	}
	if hasCredential {
		modes++
	}
	if hasIssuer {
		modes++
	}
	if hasResourceAuth {
		modes++
	}
	if modes > 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "provide only one of offer, credential, credential_issuer, or discovery_url+resource_endpoint+scope",
		})
		return
	}
	if hasResourceAuth && (strings.TrimSpace(req.DiscoveryURL) == "" ||
		strings.TrimSpace(req.ResourceEndpoint) == "" ||
		strings.TrimSpace(req.Scope) == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "discovery_url, resource_endpoint, and scope are all required for protected resource authorization",
		})
		return
	}

	transcript := &protocolTranscript{}
	ctx := withProtocolTranscript(r.Context(), transcript)
	attachTranscript := func(response map[string]interface{}) {
		hops, events := transcript.snapshot()
		if len(hops) > 0 {
			response["_protocol_exchanges"] = hops
		}
		if len(events) > 0 {
			response["_looking_glass_events"] = events
		}
	}

	walletBaseURL := firstNonEmpty(strings.TrimSpace(req.WalletBaseURL), requestBaseURL(r))
	var importResult *externalIssuerImportResult
	switch {
	case hasResourceAuth:
		importResult, err = s.startProtectedResourceAuthorization(
			ctx,
			wallet,
			strings.TrimSpace(req.DiscoveryURL),
			strings.TrimSpace(req.ResourceEndpoint),
			strings.TrimSpace(req.Scope),
			walletBaseURL,
			strings.TrimSpace(req.LookingGlassSessionID),
		)
	case hasCredential:
		importResult, err = s.importDirectCredential(ctx, externalIssuerImportRequest{
			CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
			CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
			LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
			WalletBaseURL:         walletBaseURL,
		}, strings.TrimSpace(req.Credential))
	case hasIssuer:
		importResult, err = s.startWalletInitiatedIssuance(ctx, wallet, externalIssuerImportRequest{
			CredentialIssuer:      strings.TrimSpace(req.CredentialIssuer),
			CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
			CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
			LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
			WalletBaseURL:         walletBaseURL,
		})
	default:
		importResult, err = s.issueFromExternalIssuer(ctx, wallet, externalIssuerImportRequest{
			OfferInput:            strings.TrimSpace(req.Offer),
			TxCode:                strings.TrimSpace(req.TxCode),
			CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
			CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
			LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
			WalletBaseURL:         walletBaseURL,
		})
	}
	if err != nil {
		var apiErr *walletAPIError
		if errors.As(err, &apiErr) {
			response := map[string]interface{}{
				"error":             firstNonEmpty(apiErr.Code, "invalid_request"),
				"error_description": firstNonEmpty(apiErr.Description, "wallet import failed"),
			}
			for key, value := range apiErr.Fields {
				response[key] = value
			}
			attachTranscript(response)
			writeJSON(w, normalizeWalletImportHTTPStatus(apiErr.Status), response)
			return
		}
		// Prefer 4xx for application failures so edge proxies that rewrite 502
		// without CORS headers do not turn a protocol error into "Failed to fetch".
		response := map[string]interface{}{
			"error":             "wallet_import_failed",
			"error_description": err.Error(),
		}
		attachTranscript(response)
		writeJSON(w, http.StatusBadRequest, response)
		return
	}

	if importResult == nil {
		response := map[string]interface{}{
			"error":             "wallet_import_failed",
			"error_description": "wallet import did not produce a result",
		}
		attachTranscript(response)
		writeJSON(w, http.StatusBadRequest, response)
		return
	}
	if importResult.ConfigurationSelectionRequired {
		response := map[string]interface{}{
			"wallet_subject":                   wallet.Subject,
			"wallet_scope":                     wallet.ScopeKey,
			"wallet_did_method":                wallet.DIDMethod,
			"credential_source":                importResult.credentialSource(),
			"configuration_selection_required": true,
			"credential_issuer":                importResult.CredentialIssuer,
			"credential_configurations":        importResult.CredentialConfigurations,
			"issuance_requirements":            importResult.IssuanceRequirements,
			"issuer_metadata":                  importResult.IssuerMetadata,
			"authorization_server_metadata":    importResult.AuthorizationServerMetadata,
			"token_endpoint":                   importResult.TokenEndpoint,
			"credential_endpoint":              importResult.CredentialEndpoint,
			"nonce_endpoint":                   importResult.NonceEndpoint,
		}
		attachTranscript(response)
		writeJSON(w, http.StatusOK, response)
		return
	}
	if importResult.AuthorizationRequired && strings.TrimSpace(importResult.AuthorizationURL) != "" {
		response := map[string]interface{}{
			"wallet_subject":                wallet.Subject,
			"wallet_scope":                  wallet.ScopeKey,
			"wallet_did_method":             wallet.DIDMethod,
			"credential_source":             importResult.credentialSource(),
			"authorization_required":        true,
			"authorization_url":             importResult.AuthorizationURL,
			"credential_offer":              importResult.CredentialOffer,
			"credential_offer_uri":          importResult.CredentialOfferURI,
			"credential_offer_transport":    importResult.CredentialOfferTransport,
			"credential_issuer":             importResult.CredentialIssuer,
			"credential_configuration_id":   importResult.SelectedCredentialConfigurationID,
			"credential_format":             importResult.SelectedCredentialFormat,
			"issuance_requirements":         importResult.IssuanceRequirements,
			"issuer_metadata":               importResult.IssuerMetadata,
			"authorization_server_metadata": importResult.AuthorizationServerMetadata,
			"token_endpoint":                importResult.TokenEndpoint,
			"credential_endpoint":           importResult.CredentialEndpoint,
			"nonce_endpoint":                importResult.NonceEndpoint,
		}
		attachTranscript(response)
		writeJSON(w, http.StatusOK, response)
		return
	}
	if importResult.IssuedCredential == nil {
		response := map[string]interface{}{
			"error":             "wallet_import_failed",
			"error_description": "external issuer did not return a credential",
		}
		attachTranscript(response)
		writeJSON(w, http.StatusBadRequest, response)
		return
	}

	if err := s.bindCredential(
		wallet,
		importResult.IssuedCredential.CredentialJWT,
		importResult.IssuedCredential.CredentialConfigID,
		importResult.IssuedCredential.CredentialFormat,
	); err != nil {
		response := map[string]interface{}{
			"error":             "invalid_credential",
			"error_description": err.Error(),
		}
		attachTranscript(response)
		writeJSON(w, http.StatusBadRequest, response)
		return
	}
	if err := s.notifyCredentialAccepted(ctx, importResult.IssuedCredential, req.LookingGlassSessionID); err != nil {
		log.Printf("wallet harness: credential notification failed after import: %v", err)
	}

	response := map[string]interface{}{
		"wallet_subject":                wallet.Subject,
		"wallet_scope":                  wallet.ScopeKey,
		"wallet_did_method":             wallet.DIDMethod,
		"credential_source":             importResult.credentialSource(),
		"credential_id":                 wallet.CredentialID,
		"credential_format":             wallet.CredentialFormat,
		"credential_configuration_id":   wallet.CredentialConfigurationID,
		"credential_jwt":                wallet.CredentialJWT,
		"credential_summary":            summarizeCredential(wallet.CredentialJWT),
		"credentials":                   walletCredentialEntries(wallet),
		"credential_offer":              importResult.CredentialOffer,
		"credential_offer_uri":          importResult.CredentialOfferURI,
		"credential_offer_transport":    importResult.CredentialOfferTransport,
		"credential_issuer":             importResult.CredentialIssuer,
		"issuer_metadata":               importResult.IssuerMetadata,
		"authorization_server_metadata": importResult.AuthorizationServerMetadata,
		"token_endpoint":                importResult.TokenEndpoint,
		"credential_endpoint":           importResult.CredentialEndpoint,
		"nonce_endpoint":                importResult.NonceEndpoint,
		"tx_code_required":              importResult.TxCodeRequired,
		"tx_code_description":           importResult.TxCodeDescription,
		"tx_code_length":                importResult.TxCodeLength,
		"tx_code_input_mode":            importResult.TxCodeInputMode,
	}
	attachTranscript(response)
	writeJSON(w, http.StatusOK, response)
}

func (r *externalIssuerImportResult) credentialSource() string {
	if r == nil || strings.TrimSpace(r.Source) == "" {
		return "external_oid4vci"
	}
	return strings.TrimSpace(r.Source)
}

func (s *walletHarnessServer) handleAPIOID4VCICallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	now := time.Now().UTC()
	s.mu.Lock()
	s.pruneOID4VCIAuthStatesLocked(now)
	pending, consumeErr := consumePendingOID4VCIAuthState(s.oid4vciAuthStates, state, now)
	s.mu.Unlock()
	if consumeErr != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", consumeErr.Error())
		return
	}
	if upstreamError := strings.TrimSpace(r.URL.Query().Get("error")); upstreamError != "" {
		message := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("error_description")), upstreamError)
		s.redirectOID4VCICallbackResult(w, r, "error", message)
		return
	}
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		s.redirectOID4VCICallbackResult(w, r, "error", "authorization response is missing code")
		return
	}
	requireIss := pending.UseHAIP ||
		(pending.AuthorizationServerMetadata != nil && pending.AuthorizationServerMetadata.AuthorizationResponseIssSupported)
	if err := validateAuthorizationResponseIss(pending.ExpectedIss, r.URL.Query().Get("iss"), requireIss); err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
		return
	}
	if err := validateExactRedirectURI(pending.RedirectURI, ""); err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
		return
	}

	wallet, err := s.getOrCreateWallet(pending.ScopeKey, pending.WalletSubject, strings.TrimSpace(pending.WalletBaseURL))
	if err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
		return
	}

	tokenPayload, err := s.exchangeExternalAuthorizationCodeToken(
		r.Context(),
		valueOrEmpty(pending.AuthorizationServerMetadata, func(metadata *resolvedAuthorizationServerMetadata) string { return metadata.TokenEndpoint }),
		code,
		pending.ClientID,
		pending.ClientSecret,
		pending.RedirectURI,
		pending.CodeVerifier,
		pending.LookingGlassSessionID,
		pending.HAIPSession,
		pending.PopAudience,
		valueOrEmpty(pending.AuthorizationServerMetadata, func(metadata *resolvedAuthorizationServerMetadata) string { return metadata.ChallengeEndpoint }),
		pending.UseHAIP,
	)
	if err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
		return
	}

	if resourceEndpoint := strings.TrimSpace(pending.ResourceEndpoint); resourceEndpoint != "" {
		accessToken := strings.TrimSpace(asString(tokenPayload["access_token"]))
		tokenType := firstNonEmpty(strings.TrimSpace(asString(tokenPayload["token_type"])), "Bearer")
		if accessToken == "" {
			s.redirectOID4VCICallbackResult(w, r, "error", "token response missing access_token")
			return
		}
		if err := s.fetchProtectedResource(
			r.Context(),
			resourceEndpoint,
			accessToken,
			tokenType,
			pending.HAIPSession,
			pending.LookingGlassSessionID,
		); err != nil {
			s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
			return
		}
		s.redirectOID4VCICallbackResult(w, r, "success", "protected resource request completed")
		return
	}

	importResult, err := s.completeExternalCredentialImport(
		r.Context(),
		wallet,
		externalIssuerImportRequest{
			CredentialFormat:      pending.CredentialFormat,
			CredentialConfigID:    pending.CredentialConfigurationID,
			LookingGlassSessionID: pending.LookingGlassSessionID,
			WalletBaseURL:         pending.WalletBaseURL,
		},
		nil,
		pending.IssuerMetadata,
		pending.AuthorizationServerMetadata,
		pending.CredentialConfigurationID,
		pending.CredentialFormat,
		pending.JWTProofRequired,
		tokenPayload,
		nil,
		pending.HAIPSession,
	)
	if err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
		return
	}
	if importResult == nil || importResult.IssuedCredential == nil {
		s.redirectOID4VCICallbackResult(w, r, "error", "authorization flow did not return a credential")
		return
	}
	if err := s.bindCredential(
		wallet,
		importResult.IssuedCredential.CredentialJWT,
		importResult.IssuedCredential.CredentialConfigID,
		importResult.IssuedCredential.CredentialFormat,
	); err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
		return
	}
	if err := s.notifyCredentialAccepted(r.Context(), importResult.IssuedCredential, pending.LookingGlassSessionID); err != nil {
		log.Printf("wallet harness: credential notification failed after authorization-code import: %v", err)
	}
	s.redirectOID4VCICallbackResult(w, r, "success", "credential imported")
}

func (s *walletHarnessServer) redirectOID4VCICallbackResult(w http.ResponseWriter, r *http.Request, status string, message string) {
	redirectURL := &url.URL{Path: oid4vciCallbackAppPath(r)}
	query := redirectURL.Query()
	query.Set("oid4vci_status", firstNonEmpty(strings.TrimSpace(status), "error"))
	if strings.TrimSpace(message) != "" {
		query.Set("oid4vci_message", strings.TrimSpace(message))
	}
	redirectURL.RawQuery = query.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func oid4vciCallbackAppPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	requestPath := strings.TrimSpace(r.URL.Path)
	if requestPath == "" {
		return "/"
	}
	const callbackSuffix = "/api/oid4vci/callback"
	if strings.HasSuffix(requestPath, callbackSuffix) {
		requestPath = strings.TrimSuffix(requestPath, callbackSuffix)
	} else if idx := strings.Index(requestPath, callbackSuffix); idx >= 0 {
		requestPath = requestPath[:idx]
	} else {
		return "/"
	}
	cleaned := path.Clean("/" + strings.Trim(requestPath, "/"))
	if cleaned == "." || cleaned == "" {
		return "/"
	}
	return cleaned
}

func (s *walletHarnessServer) pruneOID4VCIAuthStatesLocked(now time.Time) {
	if s == nil || s.oid4vciAuthStates == nil {
		return
	}
	for state, pending := range s.oid4vciAuthStates {
		if pending == nil || now.After(pending.ExpiresAt) {
			delete(s.oid4vciAuthStates, state)
		}
	}
}

func (s *walletHarnessServer) importDirectCredential(
	ctx context.Context,
	input externalIssuerImportRequest,
	rawCredential string,
) (*externalIssuerImportResult, error) {
	normalizedCredential := strings.TrimSpace(rawCredential)
	if normalizedCredential == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential is required",
		}
	}

	var (
		issuerMetadata              *resolvedExternalIssuerMetadata
		authorizationServerMetadata *resolvedAuthorizationServerMetadata
	)
	parsedCredential, parseErr := vc.DefaultCredentialFormatRegistry().ParseAnyCredential(normalizedCredential)
	if parseErr == nil && isHTTPSURL(parsedCredential.Issuer) {
		issuerMetadata, _ = s.resolveExternalIssuerMetadata(ctx, parsedCredential.Issuer, input.LookingGlassSessionID)
		if issuerMetadata != nil {
			authorizationServerMetadata, _ = s.resolveExternalAuthorizationServerMetadata(ctx, issuerMetadata, input.LookingGlassSessionID)
		}
	}
	parsedCredential, err := s.validateImportedCredential(
		ctx,
		normalizedCredential,
		input.CredentialFormat,
		issuerMetadata,
		authorizationServerMetadata,
		input.LookingGlassSessionID,
	)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_credential",
			Description: err.Error(),
		}
	}

	credentialFormat := firstNonEmpty(
		strings.TrimSpace(input.CredentialFormat),
		strings.TrimSpace(parsedCredential.Format),
		summaryFormat(summarizeCredential(normalizedCredential)),
	)
	issuerMetadataRaw := map[string]interface{}{}
	if issuerMetadata != nil && issuerMetadata.Raw != nil {
		issuerMetadataRaw = issuerMetadata.Raw
	} else if strings.TrimSpace(parsedCredential.Issuer) != "" {
		issuerMetadataRaw["credential_issuer"] = strings.TrimSpace(parsedCredential.Issuer)
	}
	var authorizationMetadataRaw map[string]interface{}
	if authorizationServerMetadata != nil && authorizationServerMetadata.Raw != nil {
		authorizationMetadataRaw = authorizationServerMetadata.Raw
	}
	return &externalIssuerImportResult{
		Source: "direct_import",
		IssuedCredential: &issuedWalletCredential{
			CredentialJWT:      normalizedCredential,
			CredentialFormat:   credentialFormat,
			CredentialConfigID: strings.TrimSpace(input.CredentialConfigID),
		},
		CredentialIssuer:            strings.TrimSpace(parsedCredential.Issuer),
		IssuerMetadata:              issuerMetadataRaw,
		AuthorizationServerMetadata: authorizationMetadataRaw,
		TokenEndpoint:               valueOrEmpty(authorizationServerMetadata, func(metadata *resolvedAuthorizationServerMetadata) string { return metadata.TokenEndpoint }),
	}, nil
}

func (s *walletHarnessServer) startWalletInitiatedIssuance(
	ctx context.Context,
	wallet *walletMaterial,
	input externalIssuerImportRequest,
) (*externalIssuerImportResult, error) {
	issuerID, err := normalizeCredentialIssuerIdentifier(input.CredentialIssuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.CredentialConfigID) == "" {
		return s.discoverWalletInitiatedIssuer(ctx, issuerID, input.LookingGlassSessionID)
	}
	offerJSON, err := json.Marshal(map[string]interface{}{
		"credential_issuer":            issuerID,
		"credential_configuration_ids": []string{strings.TrimSpace(input.CredentialConfigID)},
		"grants": map[string]interface{}{
			"authorization_code": map[string]interface{}{},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode wallet-initiated offer: %w", err)
	}
	input.OfferInput = string(offerJSON)
	result, err := s.issueFromExternalIssuer(ctx, wallet, input)
	if err != nil {
		return nil, err
	}
	if result != nil && strings.TrimSpace(result.CredentialOfferTransport) == "by_value" {
		result.CredentialOfferTransport = "wallet_initiated"
		result.Source = "wallet_initiated"
	}
	return result, nil
}

func (s *walletHarnessServer) discoverWalletInitiatedIssuer(
	ctx context.Context,
	credentialIssuer string,
	lookingGlassSessionID string,
) (*externalIssuerImportResult, error) {
	issuerMetadata, err := s.resolveExternalIssuerMetadata(ctx, credentialIssuer, lookingGlassSessionID)
	if err != nil {
		return nil, err
	}
	configurations := summarizeCredentialConfigurations(issuerMetadata)
	if len(configurations) == 0 {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "credential issuer metadata does not advertise credential_configurations_supported",
		}
	}
	var authorizationServerMetadata *resolvedAuthorizationServerMetadata
	asMetadata, asErr := s.resolveExternalAuthorizationServerMetadata(ctx, issuerMetadata, lookingGlassSessionID)
	if asErr == nil {
		authorizationServerMetadata = asMetadata
	}
	var authorizationRaw map[string]interface{}
	tokenEndpoint := ""
	if authorizationServerMetadata != nil {
		authorizationRaw = authorizationServerMetadata.Raw
		tokenEndpoint = authorizationServerMetadata.TokenEndpoint
	}
	return &externalIssuerImportResult{
		Source:                         "wallet_initiated",
		ConfigurationSelectionRequired: true,
		CredentialIssuer:               issuerMetadata.CredentialIssuer,
		IssuerMetadata:                 issuerMetadata.Raw,
		AuthorizationServerMetadata:    authorizationRaw,
		TokenEndpoint:                  tokenEndpoint,
		CredentialEndpoint:             issuerMetadata.CredentialEndpoint,
		NonceEndpoint:                  issuerMetadata.NonceEndpoint,
		CredentialConfigurations:       configurations,
		IssuanceRequirements:           issuanceRequirementsFromMetadata(issuerMetadata, authorizationServerMetadata, nil),
	}, nil
}

func (s *walletHarnessServer) issueFromExternalIssuer(
	ctx context.Context,
	wallet *walletMaterial,
	input externalIssuerImportRequest,
) (*externalIssuerImportResult, error) {
	if wallet == nil || wallet.KeySet == nil {
		return nil, fmt.Errorf("wallet key material is unavailable")
	}

	resolvedOffer, err := s.resolveExternalCredentialOffer(ctx, input.OfferInput, input.LookingGlassSessionID)
	if err != nil {
		return nil, err
	}
	if resolvedOffer == nil {
		return nil, fmt.Errorf("credential offer is required")
	}

	authCodeGrant := resolvedOffer.Offer.Grants.AuthorizationCode
	preAuthorizedGrant := resolvedOffer.Offer.Grants.PreAuthorizedCode
	if preAuthorizedGrant != nil {
		if strings.TrimSpace(preAuthorizedGrant.PreAuthorizedCode) == "" {
			return nil, &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_request",
				Description: "credential offer is missing pre-authorized_code",
			}
		}
		if err := oid4vciprotocol.ValidatePreAuthorizedTxCodeRequirement(preAuthorizedGrant.TxCode != nil, input.TxCode); err != nil {
			fields := map[string]interface{}{
				"tx_code_required": preAuthorizedGrant.TxCode != nil,
			}
			if preAuthorizedGrant.TxCode != nil {
				fields["tx_code_description"] = strings.TrimSpace(preAuthorizedGrant.TxCode.Description)
				fields["tx_code_length"] = preAuthorizedGrant.TxCode.Length
				fields["tx_code_input_mode"] = strings.TrimSpace(preAuthorizedGrant.TxCode.InputMode)
			}
			return nil, &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_request",
				Description: err.Error(),
				Fields:      fields,
			}
		}
	}
	issuerMetadata, err := s.resolveExternalIssuerMetadata(ctx, resolvedOffer.Offer.CredentialIssuer, input.LookingGlassSessionID)
	if err != nil {
		return nil, err
	}

	selectedConfigurationID, configurationMetadata, err := resolveExternalCredentialConfiguration(
		resolvedOffer.Offer,
		issuerMetadata,
		input.CredentialConfigID,
		input.CredentialFormat,
	)
	if err != nil {
		return nil, err
	}

	// Match the issuer's advertised proof algorithms. Prefer ES256 when the
	// configuration advertises it (the hosted wallet holder key is P-256);
	// otherwise switch to RS256/EdDSA so Looking Glass import does not send
	// an unadvertised proof algorithm.
	configurationFormat := normalizeCredentialFormat(asString(configurationMetadata["format"]))
	if preferredAlg := preferredCredentialProofSigningAlgorithm(configurationMetadata); preferredAlg != "" &&
		configurationFormat != credentialFormatMsoMdoc {
		if err := selectWalletSigningAlgorithm(wallet, preferredAlg); err != nil {
			return nil, &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "unsupported_wallet_key",
				Description: fmt.Sprintf("wallet cannot satisfy proof algorithm %q: %v", preferredAlg, err),
			}
		}
	}

	jwtProofRequired, err := resolveJWTProofRequirement(configurationMetadata, wallet.SigningAlgorithm)
	if err != nil {
		return nil, err
	}

	if authCodeGrant != nil && strings.TrimSpace(authCodeGrant.AuthorizationServer) != "" {
		issuerMetadata.AuthorizationServers = dedupeStringList(append([]string{strings.TrimSpace(authCodeGrant.AuthorizationServer)}, issuerMetadata.AuthorizationServers...))
	}
	authorizationServerMetadata, err := s.resolveExternalAuthorizationServerMetadata(ctx, issuerMetadata, input.LookingGlassSessionID)
	if err != nil {
		return nil, err
	}
	if authCodeGrant != nil && preAuthorizedGrant == nil {
		return s.startExternalAuthorizationCodeImport(
			ctx,
			wallet,
			input,
			resolvedOffer,
			issuerMetadata,
			authorizationServerMetadata,
			selectedConfigurationID,
			strings.TrimSpace(asString(configurationMetadata["format"])),
			jwtProofRequired,
		)
	}
	if preAuthorizedGrant == nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential offer must include a supported authorization_code or pre-authorized_code grant",
		}
	}

	tokenPayload, haipSession, err := s.exchangeExternalPreAuthorizedToken(
		ctx,
		authorizationServerMetadata.TokenEndpoint,
		preAuthorizedGrant.PreAuthorizedCode,
		input.TxCode,
		input.LookingGlassSessionID,
		selectedConfigurationID,
		configurationMetadata,
		authorizationServerMetadata,
	)
	if err != nil {
		return nil, err
	}

	return s.completeExternalCredentialImport(
		ctx,
		wallet,
		input,
		resolvedOffer,
		issuerMetadata,
		authorizationServerMetadata,
		selectedConfigurationID,
		strings.TrimSpace(asString(configurationMetadata["format"])),
		jwtProofRequired,
		tokenPayload,
		preAuthorizedGrant,
		haipSession,
	)
}

func (s *walletHarnessServer) startExternalAuthorizationCodeImport(
	ctx context.Context,
	wallet *walletMaterial,
	input externalIssuerImportRequest,
	resolvedOffer *resolvedCredentialOfferInput,
	issuerMetadata *resolvedExternalIssuerMetadata,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	selectedConfigurationID string,
	credentialFormat string,
	jwtProofRequired bool,
) (*externalIssuerImportResult, error) {
	if wallet == nil {
		return nil, fmt.Errorf("wallet context is required")
	}
	if authorizationServerMetadata == nil || strings.TrimSpace(authorizationServerMetadata.AuthorizationEndpoint) == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "authorization server metadata is missing authorization_endpoint",
		}
	}
	callbackBaseURL := strings.TrimRight(strings.TrimSpace(input.WalletBaseURL), "/")
	if callbackBaseURL == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "wallet public base URL is required for authorization_code imports",
		}
	}

	configurationMetadata := map[string]interface{}{}
	if issuerMetadata != nil && issuerMetadata.CredentialConfigurationsSupported != nil {
		configurationMetadata = issuerMetadata.CredentialConfigurationsSupported[selectedConfigurationID]
	}
	useHAIP := s.shouldUseHAIPIssuancePath(selectedConfigurationID, configurationMetadata, authorizationServerMetadata)
	usePAR := s.shouldUsePAR(authorizationServerMetadata, selectedConfigurationID, configurationMetadata)
	// HAIP 4.3 / CW-H010: PAR and token MUST use the same client authentication.
	// pushAuthorizationRequest always presents client attestation when it runs.
	if usePAR && s.haipIssuanceEnabled() {
		useHAIP = true
	}
	if useHAIP && !s.haipIssuanceEnabled() {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("credential configuration %q requires haip attestation material", selectedConfigurationID),
		}
	}
	if usePAR && strings.TrimSpace(authorizationServerMetadata.PushedAuthorizationRequestEndpoint) == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "authorization server requires PAR but does not advertise pushed_authorization_request_endpoint",
		}
	}

	clientID := firstNonEmpty(strings.TrimSpace(s.oid4vciClientID), callbackBaseURL)
	if useHAIP && strings.TrimSpace(s.haipAttestedClientID) != "" {
		clientID = strings.TrimSpace(s.haipAttestedClientID)
	}
	redirectURI := callbackBaseURL + "/api/oid4vci/callback"
	state := randomValue(24)
	codeVerifier, codeChallenge, codeChallengeMethod, err := buildPKCES256Pair(
		authorizationServerMetadata.CodeChallengeMethodsSupported,
		usePAR || useHAIP,
	)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: err.Error(),
		}
	}

	expectedIss := authorizationServerIssuer(authorizationServerMetadata, authorizationServerMetadata.AuthorizationServer)
	popAudience := popAudienceForAS(authorizationServerMetadata, expectedIss)
	var haipSession *haipIssuanceSession
	authorizationURL := ""
	if usePAR {
		haipSession, err = s.newHAIPIssuanceSession()
		if err != nil {
			return nil, err
		}
		issuerState := ""
		if resolvedOffer != nil && resolvedOffer.Offer.Grants.AuthorizationCode != nil {
			issuerState = strings.TrimSpace(resolvedOffer.Offer.Grants.AuthorizationCode.IssuerState)
		}
		requestURI, parErr := s.pushAuthorizationRequest(ctx, pushAuthorizationRequestInput{
			PAREndpoint:           authorizationServerMetadata.PushedAuthorizationRequestEndpoint,
			AuthorizationEndpoint: authorizationServerMetadata.AuthorizationEndpoint,
			ClientID:              clientID,
			RedirectURI:           redirectURI,
			State:                 state,
			CodeChallenge:         codeChallenge,
			Scope:                 scopeFromCredentialConfiguration(configurationMetadata, authorizationServerMetadata),
			IssuerState:           issuerState,
			ConfigurationID:       selectedConfigurationID,
			LookingGlassSessionID: input.LookingGlassSessionID,
			Session:               haipSession,
			PopAudience:           popAudience,
			ChallengeEndpoint:     authorizationServerMetadata.ChallengeEndpoint,
		})
		if parErr != nil {
			return nil, &walletAPIError{
				Status:      http.StatusBadGateway,
				Code:        "wallet_import_failed",
				Description: fmt.Sprintf("PAR request failed: %v", parErr),
			}
		}
		authorizationURL, err = buildAuthorizationURLFromPAR(
			authorizationServerMetadata.AuthorizationEndpoint,
			clientID,
			requestURI,
		)
		if err != nil {
			return nil, err
		}
	} else {
		if useHAIP {
			haipSession, err = s.newHAIPIssuanceSession()
			if err != nil {
				return nil, err
			}
		}
		authorizationURL, err = buildExternalAuthorizationURL(
			authorizationServerMetadata.AuthorizationEndpoint,
			clientID,
			redirectURI,
			state,
			selectedConfigurationID,
			resolvedOffer,
			authorizationServerMetadata,
			configurationMetadata,
			codeChallenge,
			codeChallengeMethod,
		)
		if err != nil {
			return nil, err
		}
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
		CredentialConfigurationID:   selectedConfigurationID,
		CredentialFormat:            strings.TrimSpace(credentialFormat),
		JWTProofRequired:            jwtProofRequired,
		IssuerMetadata:              issuerMetadata,
		AuthorizationServerMetadata: authorizationServerMetadata,
		LookingGlassSessionID:       strings.TrimSpace(input.LookingGlassSessionID),
		HAIPSession:                 haipSession,
		ExpectedIss:                 expectedIss,
		PopAudience:                 popAudience,
		UseHAIP:                     useHAIP,
		CreatedAt:                   time.Now().UTC(),
		ExpiresAt:                   time.Now().UTC().Add(oid4vciAuthorizationStateTTL),
	}
	s.mu.Unlock()

	return &externalIssuerImportResult{
		Source:                            "authorization_code_pending",
		AuthorizationRequired:             true,
		AuthorizationURL:                  authorizationURL,
		CredentialOffer:                   resolvedOffer.RawOffer,
		CredentialOfferURI:                resolvedOffer.OfferURI,
		CredentialOfferTransport:          resolvedOffer.TransportMode,
		CredentialIssuer:                  issuerMetadata.CredentialIssuer,
		IssuerMetadata:                    issuerMetadata.Raw,
		AuthorizationServerMetadata:       authorizationServerMetadata.Raw,
		TokenEndpoint:                     authorizationServerMetadata.TokenEndpoint,
		CredentialEndpoint:                issuerMetadata.CredentialEndpoint,
		NonceEndpoint:                     issuerMetadata.NonceEndpoint,
		SelectedCredentialConfigurationID: selectedConfigurationID,
		SelectedCredentialFormat:          strings.TrimSpace(credentialFormat),
		IssuanceRequirements:              issuanceRequirementsFromMetadata(issuerMetadata, authorizationServerMetadata, configurationMetadata),
	}, nil
}

func (s *walletHarnessServer) completeExternalCredentialImport(
	ctx context.Context,
	wallet *walletMaterial,
	input externalIssuerImportRequest,
	resolvedOffer *resolvedCredentialOfferInput,
	issuerMetadata *resolvedExternalIssuerMetadata,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	selectedConfigurationID string,
	credentialFormatHint string,
	jwtProofRequired bool,
	tokenPayload map[string]interface{},
	preAuthorizedGrant *models.VCPreAuthorizedCodeGrant,
	haipSession *haipIssuanceSession,
) (*externalIssuerImportResult, error) {
	accessToken := strings.TrimSpace(asString(tokenPayload["access_token"]))
	if accessToken == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "token response missing access_token",
		}
	}

	proofJWTs := []string{}
	proofThumbprints := []string{}
	var err error
	configurationMetadata := map[string]interface{}{}
	if issuerMetadata != nil && issuerMetadata.CredentialConfigurationsSupported != nil {
		configurationMetadata = issuerMetadata.CredentialConfigurationsSupported[selectedConfigurationID]
	}
	haipIssuance := s.shouldUseHAIPIssuancePath(selectedConfigurationID, configurationMetadata, authorizationServerMetadata)
	if haipIssuance && haipSession == nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "haip issuance session is required",
		}
	}
	credentialFormatForBatch := firstNonEmpty(
		credentialFormatHint,
		asString(configurationMetadata["format"]),
		input.CredentialFormat,
	)
	isMdoc := strings.EqualFold(normalizeCredentialFormat(credentialFormatForBatch), credentialFormatMsoMdoc)
	proofCount := 1
	if issuerMetadata != nil {
		proofCount = batchCredentialProofCount(
			issuerMetadata.BatchCredentialIssuanceSize,
			issuerMetadata.BatchCredentialIssuanceAdvertised,
			credentialFormatForBatch,
		)
		// Defensive: re-parse from raw metadata if structured fields missed it.
		if proofCount < 2 && issuerMetadata.Raw != nil {
			if size, advertised := parseBatchCredentialIssuance(issuerMetadata.Raw["batch_credential_issuance"]); advertised {
				proofCount = batchCredentialProofCount(size, true, credentialFormatForBatch)
			}
		}
	}
	if jwtProofRequired || haipIssuance {
		if strings.TrimSpace(issuerMetadata.NonceEndpoint) == "" {
			return nil, &walletAPIError{
				Status:      http.StatusBadGateway,
				Code:        "wallet_import_failed",
				Description: "issuer requires jwt proof but does not advertise nonce_endpoint",
			}
		}
		cNonce, nonceErr := s.fetchExternalNonce(ctx, issuerMetadata.NonceEndpoint, accessToken, input.LookingGlassSessionID)
		if nonceErr != nil {
			return nil, nonceErr
		}
		for proofIndex := 0; proofIndex < proofCount; proofIndex++ {
			var proofJWT string
			var thumbprint string
			switch {
			case isMdoc && proofIndex == 0 && haipIssuance:
				proofJWT, err = s.createHAIPCredentialProofJWT(
					wallet,
					wallet.Subject,
					cNonce,
					issuerMetadata.CredentialIssuer,
					selectedConfigurationID,
					credentialFormatHint,
				)
				if s.deviceKey != nil {
					thumbprint = strings.TrimSpace(intcrypto.JWKFromECPublicKey(&s.deviceKey.PublicKey, s.deviceKeyID).Thumbprint())
				}
			case isMdoc && proofIndex == 0:
				// Non-HAIP mso_mdoc must bind the persistent device key on the
				// first proof; additional batch proofs use distinct ephemeral keys.
				proofJWT, err = s.createMdocDeviceProofJWT(wallet.Subject, cNonce, issuerMetadata.CredentialIssuer)
				if s.deviceKey != nil {
					thumbprint = strings.TrimSpace(intcrypto.JWKFromECPublicKey(&s.deviceKey.PublicKey, s.deviceKeyID).Thumbprint())
				}
			case haipIssuance && proofIndex == 0:
				proofJWT, err = s.createHAIPCredentialProofJWT(
					wallet,
					wallet.Subject,
					cNonce,
					issuerMetadata.CredentialIssuer,
					selectedConfigurationID,
					credentialFormatHint,
				)
				if pubJWK, tp, jwkErr := walletActiveJWK(wallet); jwkErr == nil {
					_ = pubJWK
					thumbprint = tp
				}
			case haipIssuance:
				ephemeralKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if keyErr != nil {
					return nil, fmt.Errorf("generate batch proof key: %w", keyErr)
				}
				holderJWK := intcrypto.JWKFromECPublicKey(&ephemeralKey.PublicKey, fmt.Sprintf("wallet-batch-%d", proofIndex))
				if isMdoc {
					keyStorage, userAuthentication := keyAttestationClaimsFromEnv()
					keyAttestationJWT, attestErr := buildKeyAttestationJWT(
						s.haipKeyAttestation.PrivateKey,
						s.haipKeyAttestation.X5C,
						[]intcrypto.JWK{holderJWK},
						keyStorage,
						userAuthentication,
						cNonce,
					)
					if attestErr != nil {
						return nil, fmt.Errorf("build batch mdoc key attestation jwt: %w", attestErr)
					}
					proofJWT, err = createCredentialProofJWTWithKeyAttestation(
						ephemeralKey,
						holderJWK,
						cNonce,
						wallet.Subject,
						issuerMetadata.CredentialIssuer,
						keyAttestationJWT,
					)
				} else {
					proofJWT, err = s.createSDJWTHAIPCredentialProofJWTFromKey(
						ephemeralKey,
						holderJWK,
						wallet.Subject,
						cNonce,
						issuerMetadata.CredentialIssuer,
					)
				}
				thumbprint = strings.TrimSpace(holderJWK.Thumbprint())
			case proofIndex == 0:
				proofJWT, err = s.createCredentialProofJWT(wallet, wallet.Subject, cNonce, issuerMetadata.CredentialIssuer)
				if pubJWK, tp, jwkErr := walletActiveJWK(wallet); jwkErr == nil {
					_ = pubJWK
					thumbprint = tp
				}
			default:
				proofJWT, thumbprint, err = createDistinctBatchProofJWT(
					wallet.SigningAlgorithm,
					cNonce,
					issuerMetadata.CredentialIssuer,
				)
			}
			if err != nil {
				return nil, fmt.Errorf("create credential proof jwt: %w", err)
			}
			proofJWTs = append(proofJWTs, proofJWT)
			proofThumbprints = append(proofThumbprints, thumbprint)
		}
		if transcript := protocolTranscriptFrom(ctx); transcript != nil {
			transcript.addEvent("crypto", "Build Credential Proof JWT", map[string]interface{}{
				"rfc_reference": "OpenID4VCI 1.0 Section 8.2",
				"proof_count":   len(proofJWTs),
				"batch_size":    issuerMetadata.BatchCredentialIssuanceSize,
				"proof":         decodeProofJWTForTranscript(proofJWTs[0]),
				"format":        firstNonEmpty(credentialFormatHint, asString(configurationMetadata["format"])),
			})
		}
	}

	tokenType := firstNonEmpty(strings.TrimSpace(asString(tokenPayload["token_type"])), "Bearer")
	credentialIdentifiers := credentialIdentifiersFromTokenResponse(tokenPayload)
	encryptionSupport := issuerMetadata.CredentialResponseEncryption
	requestEncryptionSupport := issuerMetadata.CredentialRequestEncryption
	var credentialPayload map[string]interface{}
	if haipIssuance {
		if haipSession == nil {
			return nil, &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_request",
				Description: "haip issuance session is required",
			}
		}
		credentialPayload, err = s.requestHAIPCredential(
			ctx,
			issuerMetadata.CredentialEndpoint,
			selectedConfigurationID,
			accessToken,
			tokenType,
			proofJWTs,
			haipSession,
			input.LookingGlassSessionID,
			&encryptionSupport,
			&requestEncryptionSupport,
			credentialIdentifiers,
		)
	} else {
		credentialPayload, err = s.requestExternalCredential(
			ctx,
			issuerMetadata.CredentialEndpoint,
			selectedConfigurationID,
			credentialFormatHint,
			accessToken,
			tokenType,
			proofJWTs,
			input.LookingGlassSessionID,
			credentialIdentifiers,
			&encryptionSupport,
			&requestEncryptionSupport,
			false,
		)
	}
	if err != nil {
		return nil, err
	}

	if txID := strings.TrimSpace(asString(credentialPayload["transaction_id"])); txID != "" {
		deferredEndpoint := strings.TrimSpace(issuerMetadata.DeferredCredentialEndpoint)
		if deferredEndpoint == "" {
			return nil, &walletAPIError{
				Status:      http.StatusBadGateway,
				Code:        "wallet_import_failed",
				Description: "credential response included transaction_id but issuer metadata has no deferred_credential_endpoint",
			}
		}
		if waitErr := waitDeferredInterval(ctx, credentialPayload); waitErr != nil {
			return nil, waitErr
		}
		credentialPayload, err = s.pollDeferredCredentialAt(
			ctx,
			deferredEndpoint,
			accessToken,
			tokenType,
			txID,
			input.LookingGlassSessionID,
			haipSession,
			&encryptionSupport,
			&requestEncryptionSupport,
			haipIssuance && len(encryptionSupport.AlgValuesSupported) > 0 && requestEncryptionSupport.advertised(),
		)
		if err != nil {
			return nil, err
		}
	}

	rawCredentials, err := credentialResponseValues(credentialPayload)
	if err != nil {
		return nil, err
	}
	// OID4VCI 1.0: credentials array order is not correlated with proofs order.
	// Prefer the credential bound to the wallet's primary proof key; otherwise
	// take the first validated credential.
	primaryThumbprint := ""
	if len(proofThumbprints) > 0 {
		primaryThumbprint = proofThumbprints[0]
	}
	var (
		selectedCredentialJWT string
		selectedFormat        string
		selectedMatchesDevice bool
	)
	for _, rawCredential := range rawCredentials {
		credentialJWT, jwtErr := credentialPayloadToString(rawCredential)
		if jwtErr != nil {
			return nil, jwtErr
		}
		if strings.TrimSpace(credentialJWT) == "" {
			continue
		}
		credentialFormat := firstNonEmpty(
			strings.TrimSpace(asString(credentialPayload["format"])),
			strings.TrimSpace(credentialFormatHint),
			input.CredentialFormat,
			summaryFormat(summarizeCredential(credentialJWT)),
		)
		if _, validateErr := s.validateImportedCredential(
			ctx,
			credentialJWT,
			credentialFormat,
			issuerMetadata,
			authorizationServerMetadata,
			input.LookingGlassSessionID,
		); validateErr != nil {
			return nil, &walletAPIError{
				Status:      http.StatusBadGateway,
				Code:        "wallet_import_failed",
				Description: fmt.Sprintf("validate issuer signature: %v", validateErr),
			}
		}
		isMdocFormat := strings.EqualFold(normalizeCredentialFormat(credentialFormat), credentialFormatMsoMdoc)
		matchesPrimary := false
		if isMdocFormat {
			// mso_mdoc has no JWT cnf; match the wallet device key from MSO
			// deviceKeyInfo. Batch secondaries use ephemeral proof keys and are
			// stored without requiring that device-key match.
			matchesDevice := s.mdocCredentialMatchesWalletDeviceKey(credentialJWT)
			if bindErr := s.bindMdocCredentialWithPolicy(wallet, credentialJWT, selectedConfigurationID, matchesDevice); bindErr != nil {
				return nil, &walletAPIError{
					Status:      http.StatusBadGateway,
					Code:        "wallet_import_failed",
					Description: fmt.Sprintf("bind credential: %v", bindErr),
				}
			}
			matchesPrimary = matchesDevice
		} else {
			if bindErr := s.bindCredential(wallet, credentialJWT, selectedConfigurationID, credentialFormat); bindErr != nil {
				return nil, &walletAPIError{
					Status:      http.StatusBadGateway,
					Code:        "wallet_import_failed",
					Description: fmt.Sprintf("bind credential: %v", bindErr),
				}
			}
			if primaryThumbprint != "" && holderKeyThumbprintFromCredential(credentialJWT) == primaryThumbprint {
				matchesPrimary = true
			}
		}
		if selectedCredentialJWT == "" {
			selectedCredentialJWT = credentialJWT
			selectedFormat = credentialFormat
			selectedMatchesDevice = matchesPrimary
		}
		if matchesPrimary {
			selectedCredentialJWT = credentialJWT
			selectedFormat = credentialFormat
			selectedMatchesDevice = true
		}
	}
	if strings.TrimSpace(selectedCredentialJWT) == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "credential response missing credential",
		}
	}
	// Ensure the wallet-primary binding is the active credential after reverse-order batches.
	if strings.EqualFold(normalizeCredentialFormat(selectedFormat), credentialFormatMsoMdoc) {
		requireDevice := selectedMatchesDevice || s.mdocCredentialMatchesWalletDeviceKey(selectedCredentialJWT)
		_ = s.bindMdocCredentialWithPolicy(wallet, selectedCredentialJWT, selectedConfigurationID, requireDevice)
	} else {
		_ = s.bindCredential(wallet, selectedCredentialJWT, selectedConfigurationID, selectedFormat)
	}

	result := &externalIssuerImportResult{
		Source: "external_oid4vci",
		IssuedCredential: &issuedWalletCredential{
			CredentialJWT:      selectedCredentialJWT,
			CredentialFormat:   selectedFormat,
			CredentialConfigID: selectedConfigurationID,
			NotificationID:     strings.TrimSpace(asString(credentialPayload["notification_id"])),
			NotificationURL:    issuerMetadata.NotificationEndpoint,
			AccessToken:        accessToken,
			TokenType:          tokenType,
			HAIPDPoPSession:    haipSession,
		},
		CredentialIssuer:            issuerMetadata.CredentialIssuer,
		IssuerMetadata:              issuerMetadata.Raw,
		AuthorizationServerMetadata: valueOrEmptyMap(authorizationServerMetadata, func(metadata *resolvedAuthorizationServerMetadata) map[string]interface{} { return metadata.Raw }),
		TokenEndpoint:               valueOrEmpty(authorizationServerMetadata, func(metadata *resolvedAuthorizationServerMetadata) string { return metadata.TokenEndpoint }),
		CredentialEndpoint:          issuerMetadata.CredentialEndpoint,
		NonceEndpoint:               issuerMetadata.NonceEndpoint,
	}
	if resolvedOffer != nil {
		result.CredentialOffer = resolvedOffer.RawOffer
		result.CredentialOfferURI = resolvedOffer.OfferURI
		result.CredentialOfferTransport = resolvedOffer.TransportMode
	}
	if preAuthorizedGrant != nil {
		result.TxCodeRequired = preAuthorizedGrant.TxCode != nil
		result.TxCodeDescription = strings.TrimSpace(valueOrEmpty(preAuthorizedGrant.TxCode, func(tx *models.VCTxCode) string { return tx.Description }))
		result.TxCodeLength = valueOrZero(preAuthorizedGrant.TxCode, func(tx *models.VCTxCode) int { return tx.Length })
		result.TxCodeInputMode = strings.TrimSpace(valueOrEmpty(preAuthorizedGrant.TxCode, func(tx *models.VCTxCode) string { return tx.InputMode }))
	}
	return result, nil
}

func buildExternalAuthorizationURL(
	authorizationEndpoint string,
	clientID string,
	redirectURI string,
	state string,
	selectedConfigurationID string,
	resolvedOffer *resolvedCredentialOfferInput,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	configurationMetadata map[string]interface{},
	codeChallenge string,
	codeChallengeMethod string,
) (string, error) {
	authorizationURL, err := url.Parse(strings.TrimSpace(authorizationEndpoint))
	if err != nil {
		return "", &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("parse authorization endpoint: %v", err),
		}
	}
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", strings.TrimSpace(clientID))
	query.Set("redirect_uri", strings.TrimSpace(redirectURI))
	query.Set("state", strings.TrimSpace(state))
	query.Set("code_challenge", strings.TrimSpace(codeChallenge))
	query.Set("code_challenge_method", strings.TrimSpace(codeChallengeMethod))
	query.Set("nonce", randomValue(16))
	if scope := scopeFromCredentialConfiguration(configurationMetadata, authorizationServerMetadata); scope != "" {
		query.Set("scope", scope)
	}
	authorizationDetails := []map[string]interface{}{
		{
			"type":                        "openid_credential",
			"credential_configuration_id": strings.TrimSpace(selectedConfigurationID),
		},
	}
	if rawAuthorizationDetails, err := json.Marshal(authorizationDetails); err == nil {
		query.Set("authorization_details", string(rawAuthorizationDetails))
	}
	if resolvedOffer != nil && resolvedOffer.Offer.Grants.AuthorizationCode != nil && strings.TrimSpace(resolvedOffer.Offer.Grants.AuthorizationCode.IssuerState) != "" {
		query.Set("issuer_state", strings.TrimSpace(resolvedOffer.Offer.Grants.AuthorizationCode.IssuerState))
	}
	authorizationURL.RawQuery = query.Encode()
	return authorizationURL.String(), nil
}

func valueOrEmptyMap[T any](value *T, accessor func(*T) map[string]interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}
	result := accessor(value)
	if result == nil {
		return map[string]interface{}{}
	}
	return result
}

func (s *walletHarnessServer) resolveExternalCredentialOffer(
	ctx context.Context,
	rawInput string,
	lookingGlassSessionID string,
) (*resolvedCredentialOfferInput, error) {
	normalizedInput := strings.TrimSpace(rawInput)
	if normalizedInput == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential offer input is required",
		}
	}

	resolvedOffer, err := parseExternalCredentialOfferInput(normalizedInput)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: err.Error(),
		}
	}
	if resolvedOffer == nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential offer could not be resolved",
		}
	}
	if strings.TrimSpace(resolvedOffer.OfferURI) == "" {
		return resolvedOffer, nil
	}

	rawOfferPayload, err := s.fetchJSONDocument(
		ctx,
		resolvedOffer.OfferURI,
		"application/credential-offer+json, application/json",
		lookingGlassSessionID,
	)
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("fetch credential_offer_uri: %v", err),
		}
	}
	rawOfferBytes, err := json.Marshal(rawOfferPayload)
	if err != nil {
		return nil, fmt.Errorf("serialize credential offer response: %w", err)
	}
	fetchedOffer, err := parseExternalCredentialOfferJSON(string(rawOfferBytes))
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("parse credential offer response: %v", err),
		}
	}
	fetchedOffer.OfferURI = resolvedOffer.OfferURI
	fetchedOffer.TransportMode = "by_reference"
	return fetchedOffer, nil
}

func (s *walletHarnessServer) resolveExternalIssuerMetadata(
	ctx context.Context,
	credentialIssuer string,
	lookingGlassSessionID string,
) (*resolvedExternalIssuerMetadata, error) {
	candidateURLs, err := wellKnownMetadataURLCandidates(credentialIssuer, "openid-credential-issuer")
	if err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: err.Error(),
		}
	}

	var attemptErrors []string
	for _, candidateURL := range candidateURLs {
		payload, fetchErr := s.fetchJSONDocument(ctx, candidateURL, "application/json", lookingGlassSessionID)
		if fetchErr != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", candidateURL, fetchErr))
			continue
		}
		metadataIssuer := strings.TrimSpace(asString(payload["credential_issuer"]))
		if metadataIssuer == "" {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: metadata is missing credential_issuer", candidateURL))
			continue
		}
		if !sameURLIdentifier(metadataIssuer, credentialIssuer) {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: metadata credential_issuer %q does not match offer %q", candidateURL, metadataIssuer, strings.TrimSpace(credentialIssuer)))
			continue
		}
		credentialEndpoint := strings.TrimSpace(asString(payload["credential_endpoint"]))
		if credentialEndpoint == "" {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: metadata is missing credential_endpoint", candidateURL))
			continue
		}
		configurationMap, err := configurationSupportMap(payload["credential_configurations_supported"])
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", candidateURL, err))
			continue
		}
		batchSize, batchAdvertised := parseBatchCredentialIssuance(payload["batch_credential_issuance"])
		return &resolvedExternalIssuerMetadata{
			Raw:                               payload,
			CredentialIssuer:                  metadataIssuer,
			CredentialEndpoint:                credentialEndpoint,
			NonceEndpoint:                     strings.TrimSpace(asString(payload["nonce_endpoint"])),
			NotificationEndpoint:              strings.TrimSpace(asString(payload["notification_endpoint"])),
			DeferredCredentialEndpoint:        strings.TrimSpace(asString(payload["deferred_credential_endpoint"])),
			JWKSURI:                           strings.TrimSpace(asString(payload["jwks_uri"])),
			AuthorizationServers:              stringSliceFromValue(payload["authorization_servers"]),
			CredentialConfigurationsSupported: configurationMap,
			CredentialResponseEncryption:      parseCredentialResponseEncryptionSupport(payload["credential_response_encryption"]),
			CredentialRequestEncryption:       parseCredentialRequestEncryptionSupport(payload["credential_request_encryption"]),
			BatchCredentialIssuanceSize:       batchSize,
			BatchCredentialIssuanceAdvertised: batchAdvertised,
		}, nil
	}

	return nil, &walletAPIError{
		Status:      http.StatusBadGateway,
		Code:        "wallet_import_failed",
		Description: fmt.Sprintf("resolve issuer metadata: %s", strings.Join(attemptErrors, "; ")),
	}
}

func (s *walletHarnessServer) resolveExternalAuthorizationServerMetadata(
	ctx context.Context,
	issuerMetadata *resolvedExternalIssuerMetadata,
	lookingGlassSessionID string,
) (*resolvedAuthorizationServerMetadata, error) {
	if issuerMetadata == nil {
		return nil, fmt.Errorf("issuer metadata is required")
	}

	candidates := dedupeStringList(issuerMetadata.AuthorizationServers)
	if len(candidates) == 0 && strings.TrimSpace(issuerMetadata.CredentialIssuer) != "" {
		candidates = []string{strings.TrimSpace(issuerMetadata.CredentialIssuer)}
	}
	if len(candidates) == 0 {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "issuer metadata does not advertise an authorization server",
		}
	}

	for _, candidate := range candidates {
		// OID4VCI / HAIP require RFC 8414 oauth-authorization-server
		// discovery. Do not fall back to openid-configuration.
		candidateURLs, err := wellKnownMetadataURLCandidates(candidate, "oauth-authorization-server")
		if err != nil {
			continue
		}
		for _, candidateURL := range candidateURLs {
			payload, fetchErr := s.fetchJSONDocument(ctx, candidateURL, "application/json", lookingGlassSessionID)
			if fetchErr != nil {
				continue
			}
			tokenEndpoint := strings.TrimSpace(asString(payload["token_endpoint"]))
			if tokenEndpoint == "" {
				continue
			}
			issuer := strings.TrimSpace(asString(payload["issuer"]))
			if issuer != "" && !sameURLIdentifier(issuer, candidate) {
				return nil, &walletAPIError{
					Status: http.StatusBadRequest,
					Code:   "discovery_issuer_mismatch",
					Description: fmt.Sprintf(
						"discovery issuer %q does not match Issuer URL %q (OIDC Discovery §4.3 / RFC 8414 §3.3); stopping",
						issuer,
						candidate,
					),
				}
			}
			requirePAR, _ := payload["require_pushed_authorization_requests"].(bool)
			issSupported, _ := payload["authorization_response_iss_parameter_supported"].(bool)
			return &resolvedAuthorizationServerMetadata{
				Raw:                                payload,
				AuthorizationServer:                candidate,
				Issuer:                             firstNonEmpty(issuer, candidate),
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
	}

	return nil, &walletAPIError{
		Status:      http.StatusBadGateway,
		Code:        "wallet_import_failed",
		Description: "authorization server metadata could not be resolved",
	}
}

func (s *walletHarnessServer) exchangeExternalPreAuthorizedToken(
	ctx context.Context,
	tokenEndpoint string,
	preAuthorizedCode string,
	txCode string,
	lookingGlassSessionID string,
	credentialConfigurationID string,
	configurationMetadata map[string]interface{},
	asMetadata *resolvedAuthorizationServerMetadata,
) (map[string]interface{}, *haipIssuanceSession, error) {
	validatedEndpoint, err := s.validateExternalURL(tokenEndpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("validate token endpoint: %w", err)
	}
	tokenEndpoint = validatedEndpoint
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	form.Set("pre-authorized_code", strings.TrimSpace(preAuthorizedCode))
	if strings.TrimSpace(txCode) != "" {
		form.Set("tx_code", strings.TrimSpace(txCode))
	}

	haipIssuance := s.shouldUseHAIPIssuancePath(credentialConfigurationID, configurationMetadata, asMetadata)
	if haipIssuance {
		if !s.haipIssuanceEnabled() {
			return nil, nil, &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_request",
				Description: fmt.Sprintf("credential configuration %q requires haip attestation material", credentialConfigurationID),
			}
		}
		session, err := s.newHAIPIssuanceSession()
		if err != nil {
			return nil, nil, err
		}
		payload, err := s.exchangeHAIPPreAuthorizedToken(ctx, haipTokenExchangeInput{
			TokenEndpoint:         tokenEndpoint,
			Form:                  form,
			LookingGlassSessionID: lookingGlassSessionID,
			Session:               session,
			PopAudience:           popAudienceForAS(asMetadata, ""),
			ChallengeEndpoint:     valueOrEmpty(asMetadata, func(metadata *resolvedAuthorizationServerMetadata) string { return metadata.ChallengeEndpoint }),
		})
		if err != nil {
			return nil, nil, err
		}
		return payload, session, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, walletAPIErrorFromUpstream(resp.StatusCode, body, "token request")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, fmt.Errorf("decode token response: %w", err)
	}
	return payload, nil, nil
}

func (s *walletHarnessServer) exchangeExternalAuthorizationCodeToken(
	ctx context.Context,
	tokenEndpoint string,
	code string,
	clientID string,
	clientSecret string,
	redirectURI string,
	codeVerifier string,
	lookingGlassSessionID string,
	haipSession *haipIssuanceSession,
	popAudience string,
	challengeEndpoint string,
	useHAIP bool,
) (map[string]interface{}, error) {
	validatedEndpoint, err := s.validateExternalURL(tokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("validate token endpoint: %w", err)
	}
	tokenEndpoint = validatedEndpoint
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.TrimSpace(code))
	form.Set("client_id", strings.TrimSpace(clientID))
	form.Set("redirect_uri", strings.TrimSpace(redirectURI))
	if strings.TrimSpace(codeVerifier) != "" {
		form.Set("code_verifier", strings.TrimSpace(codeVerifier))
	}
	if strings.TrimSpace(clientSecret) != "" {
		form.Set("client_secret", strings.TrimSpace(clientSecret))
	}

	if useHAIP || (haipSession != nil && s.haipIssuanceEnabled()) {
		if haipSession == nil {
			return nil, fmt.Errorf("haip issuance session is required for attested authorization_code token exchange")
		}
		return s.exchangeHAIPPreAuthorizedToken(ctx, haipTokenExchangeInput{
			TokenEndpoint:         tokenEndpoint,
			Form:                  form,
			LookingGlassSessionID: lookingGlassSessionID,
			Session:               haipSession,
			PopAudience:           popAudience,
			ChallengeEndpoint:     challengeEndpoint,
		})
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, walletAPIErrorFromUpstream(resp.StatusCode, body, "authorization code token request")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return payload, nil
}

func (s *walletHarnessServer) fetchExternalNonce(
	ctx context.Context,
	nonceEndpoint string,
	_ string,
	lookingGlassSessionID string,
) (string, error) {
	validatedEndpoint, err := s.validateExternalURL(nonceEndpoint)
	if err != nil {
		return "", fmt.Errorf("validate nonce endpoint: %w", err)
	}
	nonceEndpoint = validatedEndpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nonceEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return "", fmt.Errorf("nonce request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", walletAPIErrorFromUpstream(resp.StatusCode, body, "nonce request")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode nonce response: %w", err)
	}
	cNonce := strings.TrimSpace(asString(payload["c_nonce"]))
	if cNonce == "" {
		return "", fmt.Errorf("nonce response missing c_nonce")
	}
	return cNonce, nil
}

func (s *walletHarnessServer) requestExternalCredential(
	ctx context.Context,
	credentialEndpoint string,
	credentialConfigurationID string,
	_ string,
	accessToken string,
	tokenType string,
	proofJWTs []string,
	lookingGlassSessionID string,
	credentialIdentifiers []string,
	encryption *credentialResponseEncryptionSupport,
	requestEncryption *credentialRequestEncryptionSupport,
	requireEncryption bool,
) (map[string]interface{}, error) {
	validatedEndpoint, err := s.validateExternalURL(credentialEndpoint)
	if err != nil {
		return nil, fmt.Errorf("validate credential endpoint: %w", err)
	}
	credentialEndpoint = validatedEndpoint
	return s.requestCredentialWithLifecycle(ctx, credentialEndpoint, credentialRequestBuildInput{
		CredentialConfigurationID: credentialConfigurationID,
		CredentialIdentifiers:     credentialIdentifiers,
		ProofJWTs:                 proofJWTs,
		Encryption:                encryption,
		RequestEncryption:         requestEncryption,
		RequireEncryption:         requireEncryption,
	}, accessToken, tokenType, nil, lookingGlassSessionID)
}

func (s *walletHarnessServer) validateImportedCredential(
	ctx context.Context,
	credential string,
	credentialFormat string,
	issuerMetadata *resolvedExternalIssuerMetadata,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	lookingGlassSessionID string,
) (*vc.ParsedCredential, error) {
	registry := vc.DefaultCredentialFormatRegistry()
	parsedCredential, err := registry.ParseAnyCredential(strings.TrimSpace(credential))
	if err != nil {
		return nil, err
	}
	if normalizedExpectedFormat := normalizeCredentialFormat(credentialFormat); normalizedExpectedFormat != "" {
		if normalizedActualFormat := normalizeCredentialFormat(parsedCredential.Format); normalizedActualFormat != "" && normalizedActualFormat != normalizedExpectedFormat {
			return nil, fmt.Errorf("credential format %q does not match requested format %q", parsedCredential.Format, credentialFormat)
		}
	}
	if issuerMetadata != nil && strings.TrimSpace(issuerMetadata.CredentialIssuer) != "" {
		if credentialIssuer := strings.TrimSpace(parsedCredential.Issuer); credentialIssuer != "" && isHTTPSURL(credentialIssuer) && !sameURLIdentifier(credentialIssuer, issuerMetadata.CredentialIssuer) {
			return nil, fmt.Errorf("credential issuer %q does not match credential_issuer %q", credentialIssuer, issuerMetadata.CredentialIssuer)
		}
	}

	formatHandler, ok := registry.Lookup(parsedCredential.Format)
	if !ok {
		return nil, fmt.Errorf("unsupported credential format %q", parsedCredential.Format)
	}

	validationInput := vc.CredentialValidationInput{
		Credential:         strings.TrimSpace(credential),
		ParsedCredential:   parsedCredential,
		HTTPClient:         s.httpClient,
		IssuerTrustAnchors: s.mdocIssuerRoots,
	}
	actualFormat := normalizeCredentialFormat(parsedCredential.Format)
	// mso_mdoc trust is x5chain → IACA, not JWKS. Skip JWKS lookup.
	if actualFormat != credentialFormatMsoMdoc {
		issuerKeys, resolveErr := s.resolveExternalIssuerKeys(ctx, parsedCredential, issuerMetadata, authorizationServerMetadata, lookingGlassSessionID)
		if resolveErr != nil {
			return nil, resolveErr
		}
		validationInput.IssuerKeys = issuerKeys
	}
	// This accepts arbitrary pasted or externally-fetched credentials, so it
	// is a trust boundary rather than a reporting surface: not-evaluated must
	// refuse import exactly like a checked failure, never fall through as an
	// accepted-but-unverified credential. vc.IssuerTrustStatus guarantees a
	// non-nil error for both IssuerTrustFailed and IssuerTrustNotEvaluated,
	// so keeping this as a plain err != nil check -- rather than special
	// casing on trustStatus -- is what enforces that refusal.
	if trustStatus, err := formatHandler.ValidateIssuerSignature(validationInput); err != nil {
		return nil, fmt.Errorf("validate issuer signature (issuer_trust=%s): %w", trustStatus, err)
	}
	return parsedCredential, nil
}

func (s *walletHarnessServer) resolveExternalIssuerKeys(
	ctx context.Context,
	parsedCredential *vc.ParsedCredential,
	issuerMetadata *resolvedExternalIssuerMetadata,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	lookingGlassSessionID string,
) ([]intcrypto.JWK, error) {
	if parsedCredential == nil {
		return nil, fmt.Errorf("parsed credential is required")
	}
	// Advertised jwks_uri values are the only JWKS locations the issuer
	// declared (OID4VCI Credential Issuer Metadata / RFC 8414 §2). Fetch
	// those first and stop on the first non-empty set so we never probe
	// invented well-known paths.
	advertisedJWKSURIs := make([]string, 0, 2)
	if issuerMetadata != nil {
		advertisedJWKSURIs = append(advertisedJWKSURIs, strings.TrimSpace(issuerMetadata.JWKSURI))
	}
	if authorizationServerMetadata != nil {
		advertisedJWKSURIs = append(advertisedJWKSURIs, strings.TrimSpace(authorizationServerMetadata.JWKSURI))
	}
	speculativeJWKSURIs := make([]string, 0, 8)
	if issuerMetadata != nil {
		speculativeJWKSURIs = append(speculativeJWKSURIs, defaultJWKSURLCandidates(issuerMetadata.CredentialIssuer)...)
	}
	if authorizationServerMetadata != nil {
		speculativeJWKSURIs = append(speculativeJWKSURIs, defaultJWKSURLCandidates(authorizationServerMetadata.AuthorizationServer)...)
	}
	speculativeJWKSURIs = append(speculativeJWKSURIs, defaultJWKSURLCandidates(parsedCredential.Issuer)...)

	keys, attemptErrors := s.collectIssuerJWKS(ctx, advertisedJWKSURIs, lookingGlassSessionID)
	if len(keys) > 0 {
		return keys, nil
	}
	hasAdvertisedJWKSURI := false
	for _, advertisedURI := range advertisedJWKSURIs {
		if strings.TrimSpace(advertisedURI) != "" {
			hasAdvertisedJWKSURI = true
			break
		}
	}
	if !hasAdvertisedJWKSURI {
		fallbackKeys, fallbackErrors := s.collectIssuerJWKS(ctx, speculativeJWKSURIs, lookingGlassSessionID)
		attemptErrors = append(attemptErrors, fallbackErrors...)
		if len(fallbackKeys) > 0 {
			return fallbackKeys, nil
		}
	}
	if strings.HasPrefix(strings.TrimSpace(parsedCredential.Original), "{") {
		return nil, nil
	}
	if len(attemptErrors) == 0 {
		return nil, fmt.Errorf("issuer jwks could not be resolved")
	}
	return nil, fmt.Errorf("issuer jwks could not be resolved: %s", strings.Join(attemptErrors, "; "))
}

func (s *walletHarnessServer) collectIssuerJWKS(
	ctx context.Context,
	candidateJWKSURIs []string,
	lookingGlassSessionID string,
) ([]intcrypto.JWK, []string) {
	var attemptErrors []string
	for _, candidateURI := range dedupeStringList(candidateJWKSURIs) {
		if strings.TrimSpace(candidateURI) == "" {
			continue
		}
		jwksPayload, err := s.fetchJWKS(ctx, candidateURI, lookingGlassSessionID)
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", candidateURI, err))
			continue
		}
		if jwksPayload != nil && len(jwksPayload.Keys) > 0 {
			return dedupeJWKs(jwksPayload.Keys), attemptErrors
		}
		attemptErrors = append(attemptErrors, fmt.Sprintf("%s: empty jwks", candidateURI))
	}
	return nil, attemptErrors
}

func (s *walletHarnessServer) fetchJWKS(
	ctx context.Context,
	jwksURI string,
	lookingGlassSessionID string,
) (*intcrypto.JWKS, error) {
	normalizedJWKSURI := strings.TrimSpace(jwksURI)
	if normalizedJWKSURI == "" {
		return nil, fmt.Errorf("jwks uri is required")
	}
	if s != nil && s.jwksFetcher != nil && strings.TrimSpace(lookingGlassSessionID) == "" {
		return s.jwksFetcher.Fetch(normalizedJWKSURI)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedJWKSURI, nil)
	if err != nil {
		return nil, fmt.Errorf("build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}
	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("jwks request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jwks request returned %d: %s", resp.StatusCode, oneLine(string(body)))
	}
	var payload intcrypto.JWKS
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode jwks response: %w", err)
	}
	return &payload, nil
}

func normalizeCredentialFormat(format string) string {
	switch strings.TrimSpace(format) {
	case "jwt_vc":
		return "jwt_vc_json"
	default:
		return strings.TrimSpace(format)
	}
}

func defaultJWKSURLCandidates(identifier string) []string {
	normalizedIdentifier := strings.TrimSpace(identifier)
	if !isHTTPSURL(normalizedIdentifier) {
		return nil
	}
	parsed, err := url.Parse(normalizedIdentifier)
	if err != nil {
		return nil
	}
	root := strings.TrimRight(parsed.Scheme+"://"+parsed.Host, "/")
	candidates := []string{
		root + "/.well-known/jwks.json",
		// ProtocolSoup publishes the shared showcase JWKS under /api and OIDC.
		root + "/api/.well-known/jwks.json",
		root + "/oidc/.well-known/jwks.json",
	}
	path := strings.TrimSpace(parsed.Path)
	if path != "" && path != "/" {
		trimmedIdentifier := strings.TrimRight(normalizedIdentifier, "/")
		candidates = append(candidates, trimmedIdentifier+"/jwks")
	}
	return dedupeStringList(candidates)
}

func isHTTPSURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Scheme, "https") || strings.EqualFold(parsed.Scheme, "http")
}

func dedupeJWKs(keys []intcrypto.JWK) []intcrypto.JWK {
	if len(keys) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(keys))
	result := make([]intcrypto.JWK, 0, len(keys))
	for _, key := range keys {
		fingerprint := firstNonEmpty(
			strings.TrimSpace(key.Kid),
			strings.TrimSpace(key.Thumbprint()),
			strings.TrimSpace(key.Kty)+"|"+strings.TrimSpace(key.Crv)+"|"+strings.TrimSpace(key.X)+"|"+strings.TrimSpace(key.Y)+"|"+strings.TrimSpace(key.N)+"|"+strings.TrimSpace(key.E),
		)
		if fingerprint == "" {
			continue
		}
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		result = append(result, key)
	}
	return result
}

func (s *walletHarnessServer) fetchJSONDocument(
	ctx context.Context,
	targetURL string,
	acceptHeader string,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	validatedURL, err := s.validateExternalURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("validate request URL: %w", err)
	}
	targetURL = validatedURL
	accept := firstNonEmpty(strings.TrimSpace(acceptHeader), "application/json")
	flightKey := "GET " + targetURL + "\nAccept: " + accept

	if s != nil {
		s.jsonFetchMu.Lock()
		if s.jsonFetchFlights == nil {
			s.jsonFetchFlights = make(map[string]*jsonFetchFlight)
		}
		if existing, ok := s.jsonFetchFlights[flightKey]; ok {
			s.jsonFetchMu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-existing.ready:
				return cloneJSONObject(existing.payload), existing.err
			}
		}
		flight := &jsonFetchFlight{ready: make(chan struct{})}
		s.jsonFetchFlights[flightKey] = flight
		s.jsonFetchMu.Unlock()

		payload, fetchErr := s.fetchJSONDocumentUnshared(ctx, targetURL, accept, lookingGlassSessionID)
		flight.payload = payload
		flight.err = fetchErr
		s.jsonFetchMu.Lock()
		delete(s.jsonFetchFlights, flightKey)
		s.jsonFetchMu.Unlock()
		close(flight.ready)
		return cloneJSONObject(payload), fetchErr
	}

	return s.fetchJSONDocumentUnshared(ctx, targetURL, accept, lookingGlassSessionID)
}

func (s *walletHarnessServer) fetchJSONDocumentUnshared(
	ctx context.Context,
	targetURL string,
	acceptHeader string,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", firstNonEmpty(strings.TrimSpace(acceptHeader), "application/json"))
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%d %s", resp.StatusCode, oneLine(string(body)))
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, fmt.Errorf("empty response body")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode json response: %w", err)
	}
	return payload, nil
}

func cloneJSONObject(payload map[string]interface{}) map[string]interface{} {
	if payload == nil {
		return nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return payload
	}
	var cloned map[string]interface{}
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return payload
	}
	return cloned
}

func parseExternalCredentialOfferInput(rawInput string) (*resolvedCredentialOfferInput, error) {
	normalizedInput := strings.TrimSpace(rawInput)
	if normalizedInput == "" {
		return nil, fmt.Errorf("credential offer input is required")
	}
	if strings.HasPrefix(normalizedInput, "{") {
		return parseExternalCredentialOfferJSON(normalizedInput)
	}

	parsed, err := url.Parse(normalizedInput)
	if err != nil {
		return nil, fmt.Errorf("parse credential offer input: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "openid-credential-offer":
		return parseExternalCredentialOfferQuery(parsed.Query())
	case "http", "https":
		query := parsed.Query()
		if len(query) == 0 || (!query.Has("credential_offer") && !query.Has("credential_offer_uri")) {
			return &resolvedCredentialOfferInput{
				OfferURI:      normalizedInput,
				TransportMode: "by_reference",
			}, nil
		}
		return parseExternalCredentialOfferQuery(query)
	default:
		return nil, fmt.Errorf("unsupported credential offer input scheme %q", parsed.Scheme)
	}
}

func parseExternalCredentialOfferQuery(values url.Values) (*resolvedCredentialOfferInput, error) {
	rawOffer := strings.TrimSpace(values.Get("credential_offer"))
	rawOfferURI := strings.TrimSpace(values.Get("credential_offer_uri"))
	if err := oid4vciprotocol.ValidateCredentialOfferEnvelope(rawOffer != "", rawOfferURI != ""); err != nil {
		return nil, err
	}
	if rawOfferURI != "" {
		return &resolvedCredentialOfferInput{
			OfferURI:      rawOfferURI,
			TransportMode: "by_reference",
		}, nil
	}
	resolvedOffer, err := parseExternalCredentialOfferJSON(rawOffer)
	if err != nil {
		return nil, err
	}
	resolvedOffer.TransportMode = "by_value"
	return resolvedOffer, nil
}

func parseExternalCredentialOfferJSON(raw string) (*resolvedCredentialOfferInput, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &payload); err != nil {
		return nil, fmt.Errorf("decode credential offer json: %w", err)
	}
	if payload == nil {
		return nil, fmt.Errorf("credential offer json is empty")
	}

	hasOfferByValue := payload["credential_offer"] != nil
	hasOfferByReference := strings.TrimSpace(asString(payload["credential_offer_uri"])) != ""
	if hasOfferByValue || hasOfferByReference {
		if err := oid4vciprotocol.ValidateCredentialOfferEnvelope(hasOfferByValue, hasOfferByReference); err != nil {
			return nil, err
		}
		if hasOfferByReference {
			return &resolvedCredentialOfferInput{
				OfferURI:      strings.TrimSpace(asString(payload["credential_offer_uri"])),
				TransportMode: "by_reference",
			}, nil
		}
		offerMap, err := rawObjectMap(payload["credential_offer"])
		if err != nil {
			return nil, fmt.Errorf("decode credential_offer object: %w", err)
		}
		offer, err := parseCredentialOfferMap(offerMap)
		if err != nil {
			return nil, err
		}
		return &resolvedCredentialOfferInput{
			Offer:         offer,
			RawOffer:      offerMap,
			TransportMode: "by_value",
		}, nil
	}

	offer, err := parseCredentialOfferMap(payload)
	if err != nil {
		return nil, err
	}
	return &resolvedCredentialOfferInput{
		Offer:         offer,
		RawOffer:      payload,
		TransportMode: "by_value",
	}, nil
}

func parseCredentialOfferMap(payload map[string]interface{}) (models.VCCredentialOffer, error) {
	rawBytes, err := json.Marshal(payload)
	if err != nil {
		return models.VCCredentialOffer{}, fmt.Errorf("serialize credential offer: %w", err)
	}
	var offer models.VCCredentialOffer
	if err := json.Unmarshal(rawBytes, &offer); err != nil {
		return models.VCCredentialOffer{}, fmt.Errorf("decode credential offer: %w", err)
	}
	if strings.TrimSpace(offer.CredentialIssuer) == "" {
		return models.VCCredentialOffer{}, fmt.Errorf("credential offer is missing credential_issuer")
	}
	if len(offer.CredentialConfigurationIDs) == 0 {
		return models.VCCredentialOffer{}, fmt.Errorf("credential offer is missing credential_configuration_ids")
	}
	return offer, nil
}

func resolveExternalCredentialConfiguration(
	offer models.VCCredentialOffer,
	issuerMetadata *resolvedExternalIssuerMetadata,
	requestedCredentialConfigID string,
	requestedCredentialFormat string,
) (string, map[string]interface{}, error) {
	if issuerMetadata == nil {
		return "", nil, fmt.Errorf("issuer metadata is required")
	}
	offeredConfigurationIDs := dedupeStringList(offer.CredentialConfigurationIDs)
	if len(offeredConfigurationIDs) == 0 {
		return "", nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential offer does not advertise credential_configuration_ids",
		}
	}

	normalizedRequestedConfigID := strings.TrimSpace(requestedCredentialConfigID)
	normalizedRequestedFormat := strings.TrimSpace(requestedCredentialFormat)
	if normalizedRequestedConfigID != "" {
		for _, offeredID := range offeredConfigurationIDs {
			if offeredID != normalizedRequestedConfigID {
				continue
			}
			configuration, ok := issuerMetadata.CredentialConfigurationsSupported[normalizedRequestedConfigID]
			if !ok {
				return "", nil, &walletAPIError{
					Status:      http.StatusBadGateway,
					Code:        "wallet_import_failed",
					Description: fmt.Sprintf("issuer metadata does not describe credential_configuration_id %q", normalizedRequestedConfigID),
				}
			}
			if normalizedRequestedFormat != "" && strings.TrimSpace(asString(configuration["format"])) != normalizedRequestedFormat {
				return "", nil, &walletAPIError{
					Status:      http.StatusBadRequest,
					Code:        "invalid_request",
					Description: fmt.Sprintf("credential_configuration_id %q does not match requested format %q", normalizedRequestedConfigID, normalizedRequestedFormat),
				}
			}
			return normalizedRequestedConfigID, configuration, nil
		}
		return "", nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("credential offer does not include credential_configuration_id %q", normalizedRequestedConfigID),
		}
	}

	if normalizedRequestedFormat != "" {
		for _, offeredID := range offeredConfigurationIDs {
			configuration, ok := issuerMetadata.CredentialConfigurationsSupported[offeredID]
			if !ok {
				continue
			}
			if strings.TrimSpace(asString(configuration["format"])) == normalizedRequestedFormat {
				return offeredID, configuration, nil
			}
		}
		return "", nil, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("credential offer does not include a configuration for format %q", normalizedRequestedFormat),
		}
	}

	for _, offeredID := range offeredConfigurationIDs {
		if configuration, ok := issuerMetadata.CredentialConfigurationsSupported[offeredID]; ok {
			return offeredID, configuration, nil
		}
	}

	return "", nil, &walletAPIError{
		Status:      http.StatusBadGateway,
		Code:        "wallet_import_failed",
		Description: fmt.Sprintf("issuer metadata does not describe any offered credential_configuration_ids (%s)", strings.Join(offeredConfigurationIDs, ", ")),
	}
}

func resolveJWTProofRequirement(configuration map[string]interface{}, walletSigningAlgorithm string) (bool, error) {
	proofTypes, _ := configuration["proof_types_supported"].(map[string]interface{})
	if len(proofTypes) == 0 {
		return false, nil
	}
	jwtProofRaw, ok := proofTypes["jwt"]
	if !ok {
		return false, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "unsupported_grant",
			Description: "credential configuration requires a proof type other than jwt",
		}
	}
	jwtProof, _ := jwtProofRaw.(map[string]interface{})
	supportedAlgs := stringSliceFromValue(jwtProof["proof_signing_alg_values_supported"])
	if len(supportedAlgs) > 0 && !containsStringFold(supportedAlgs, walletSigningAlgorithm) {
		return false, &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "unsupported_wallet_key",
			Description: fmt.Sprintf("wallet signing algorithm %q is not supported by the credential configuration", walletSigningAlgorithm),
		}
	}
	return true, nil
}

func configurationSupportMap(raw interface{}) (map[string]map[string]interface{}, error) {
	typed, ok := raw.(map[string]interface{})
	if !ok || len(typed) == 0 {
		return nil, fmt.Errorf("issuer metadata is missing credential_configurations_supported")
	}
	configurations := make(map[string]map[string]interface{}, len(typed))
	for key, value := range typed {
		configuration, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("credential configuration %q is invalid", key)
		}
		configurations[strings.TrimSpace(key)] = configuration
	}
	return configurations, nil
}

func rawObjectMap(raw interface{}) (map[string]interface{}, error) {
	switch typed := raw.(type) {
	case map[string]interface{}:
		return typed, nil
	case string:
		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(strings.TrimSpace(typed)), &decoded); err != nil {
			return nil, err
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unexpected object type %T", raw)
	}
}

func wellKnownMetadataURLCandidates(identifier string, wellKnownName string) ([]string, error) {
	parsed, err := url.Parse(strings.TrimSpace(identifier))
	if err != nil {
		return nil, fmt.Errorf("parse identifier: %w", err)
	}
	if !parsed.IsAbs() || strings.TrimSpace(parsed.Host) == "" {
		return nil, fmt.Errorf("identifier %q must be an absolute URL", strings.TrimSpace(identifier))
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""

	rawPath := strings.TrimSpace(parsed.Path)
	normalizedPath := strings.Trim(rawPath, "/")
	// OID4VCI 1.0 §12.2.2 inserts /.well-known/openid-credential-issuer before the
	// issuer path and preserves a trailing slash. RFC 8414 §3.1 strips it for
	// oauth-authorization-server / openid-configuration discovery.
	preserveIssuerTrailingSlash := wellKnownName == "openid-credential-issuer" &&
		strings.HasSuffix(rawPath, "/") &&
		rawPath != "/"

	candidates := make([]string, 0, 2)

	canonical := *parsed
	switch {
	case normalizedPath == "":
		canonical.Path = "/.well-known/" + strings.Trim(strings.TrimSpace(wellKnownName), "/")
	case preserveIssuerTrailingSlash:
		canonical.Path = "/.well-known/" + strings.Trim(strings.TrimSpace(wellKnownName), "/") + "/" + normalizedPath + "/"
	default:
		canonical.Path = "/.well-known/" + strings.Trim(strings.TrimSpace(wellKnownName), "/") + "/" + normalizedPath
	}
	candidates = append(candidates, canonical.String())

	// OIDC Discovery 1.0 §4 uses {issuer}/.well-known/openid-configuration.
	// RFC 8414 §3.1 uses insertion for oauth-authorization-server; the OIDC
	// append placement of that name is not a valid RFC 8414 URL.
	if wellKnownName == "openid-configuration" {
		fallback := strings.TrimRight(strings.TrimSpace(identifier), "/") + "/.well-known/openid-configuration"
		candidates = append(candidates, fallback)
	}
	return dedupeStringList(candidates), nil
}

const openidCredentialIssuerWellKnownPath = "/.well-known/openid-credential-issuer"

func normalizeCredentialIssuerIdentifier(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential_issuer is required",
		}
	}
	if strings.HasPrefix(trimmed, "{") {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
			return "", &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_request",
				Description: fmt.Sprintf("decode credential issuer input: %v", err),
			}
		}
		trimmed = strings.TrimSpace(asString(payload["credential_issuer"]))
		if trimmed == "" {
			return "", &walletAPIError{
				Status:      http.StatusBadRequest,
				Code:        "invalid_request",
				Description: "JSON input must include credential_issuer",
			}
		}
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || !parsed.IsAbs() || strings.TrimSpace(parsed.Host) == "" {
		return "", &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: fmt.Sprintf("credential_issuer %q must be an absolute URL", strings.TrimSpace(raw)),
		}
	}
	if !strings.EqualFold(parsed.Scheme, "https") && !strings.EqualFold(parsed.Scheme, "http") {
		return "", &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "credential_issuer must be an HTTP(S) URL",
		}
	}
	lowerPath := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(lowerPath, "/.well-known/oauth-authorization-server") ||
		strings.Contains(lowerPath, "/.well-known/openid-configuration") {
		return "", &walletAPIError{
			Status:      http.StatusBadRequest,
			Code:        "invalid_request",
			Description: "that URL is Authorization Server discovery metadata, not a Credential Issuer identifier. Paste credential_issuer or /.well-known/openid-credential-issuer; for protected-resource access paste discovery URL plus resource URL",
		}
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	if idx := strings.Index(lowerPath, openidCredentialIssuerWellKnownPath); idx >= 0 {
		rest := parsed.EscapedPath()[idx+len(openidCredentialIssuerWellKnownPath):]
		parsed.Path = rest
		parsed.RawPath = ""
	}
	return parsed.String(), nil
}

func summarizeCredentialConfigurations(metadata *resolvedExternalIssuerMetadata) []map[string]interface{} {
	if metadata == nil || len(metadata.CredentialConfigurationsSupported) == 0 {
		return nil
	}
	ids := make([]string, 0, len(metadata.CredentialConfigurationsSupported))
	for id := range metadata.CredentialConfigurationsSupported {
		if strings.TrimSpace(id) == "" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	summaries := make([]map[string]interface{}, 0, len(ids))
	for _, id := range ids {
		configuration := metadata.CredentialConfigurationsSupported[id]
		entry := map[string]interface{}{
			"id":     id,
			"format": strings.TrimSpace(asString(configuration["format"])),
		}
		if vct := strings.TrimSpace(asString(configuration["vct"])); vct != "" {
			entry["vct"] = vct
		}
		if doctype := strings.TrimSpace(asString(configuration["doctype"])); doctype != "" {
			entry["doctype"] = doctype
		}
		if binding := configuration["cryptographic_binding_methods_supported"]; binding != nil {
			entry["cryptographic_binding_methods_supported"] = binding
		}
		if display := configuration["display"]; display != nil {
			entry["display"] = display
		}
		entry["key_attestation_required"] = configurationRequiresKeyAttestation(configuration)
		entry["cryptographic_holder_binding"] = credentialConfigurationRequiresHolderBinding(configuration)
		summaries = append(summaries, entry)
	}
	return summaries
}

func credentialConfigurationRequiresHolderBinding(configuration map[string]interface{}) bool {
	if configuration == nil {
		return false
	}
	methods := stringSliceFromValue(configuration["cryptographic_binding_methods_supported"])
	return len(methods) > 0
}

func issuanceRequirementsFromMetadata(
	issuerMetadata *resolvedExternalIssuerMetadata,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	configuration map[string]interface{},
) map[string]interface{} {
	requirements := map[string]interface{}{}
	if authorizationServerMetadata != nil {
		requirements["par"] = authorizationServerMetadata.RequirePushedAuthorizationRequests ||
			strings.TrimSpace(authorizationServerMetadata.PushedAuthorizationRequestEndpoint) != ""
		requirements["dpop"] = len(authorizationServerMetadata.DPoPSigningAlgValuesSupported) > 0
		requirements["client_attestation"] = containsStringFold(
			authorizationServerMetadata.TokenEndpointAuthMethodsSupported,
			"attest_jwt_client_auth",
		)
	}
	if issuerMetadata != nil {
		requirements["credential_request_encryption"] = issuerMetadata.CredentialRequestEncryption.EncryptionRequired ||
			len(issuerMetadata.CredentialRequestEncryption.Keys) > 0
		requirements["credential_response_encryption"] = issuerMetadata.CredentialResponseEncryption.EncryptionRequired ||
			len(issuerMetadata.CredentialResponseEncryption.AlgValuesSupported) > 0
	}
	if configuration != nil {
		requirements["key_attestation"] = configurationRequiresKeyAttestation(configuration)
		requirements["cryptographic_holder_binding"] = credentialConfigurationRequiresHolderBinding(configuration)
		if format := strings.TrimSpace(asString(configuration["format"])); format != "" {
			requirements["format"] = format
		}
		if vct := strings.TrimSpace(asString(configuration["vct"])); vct != "" {
			requirements["vct"] = vct
		}
		if doctype := strings.TrimSpace(asString(configuration["doctype"])); doctype != "" {
			requirements["doctype"] = doctype
		}
	}
	return requirements
}

func walletAPIErrorFromUpstream(status int, body []byte, operation string) error {
	description := oneLine(string(body))
	code := "wallet_import_failed"
	if len(body) > 0 {
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err == nil {
			if upstreamCode := strings.TrimSpace(asString(payload["error"])); upstreamCode != "" {
				code = upstreamCode
			}
			if upstreamDescription := strings.TrimSpace(asString(payload["error_description"])); upstreamDescription != "" {
				description = upstreamDescription
			}
		}
	}
	if description == "" {
		description = fmt.Sprintf("%s returned HTTP %d", strings.TrimSpace(operation), status)
	}
	if status >= 500 {
		return &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("%s returned HTTP %d: %s", strings.TrimSpace(operation), status, description),
		}
	}
	return &walletAPIError{
		Status:      http.StatusBadRequest,
		Code:        code,
		Description: fmt.Sprintf("%s returned HTTP %d: %s", strings.TrimSpace(operation), status, description),
	}
}

func stringSliceFromValue(raw interface{}) []string {
	switch typed := raw.(type) {
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value := strings.TrimSpace(fmt.Sprint(item)); value != "" && value != "<nil>" {
				values = append(values, value)
			}
		}
		return dedupeStringList(values)
	case []string:
		return dedupeStringList(typed)
	default:
		return nil
	}
}

func containsStringFold(values []string, target string) bool {
	normalizedTarget := strings.TrimSpace(target)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), normalizedTarget) {
			return true
		}
	}
	return false
}

func sameURLIdentifier(left string, right string) bool {
	return strings.TrimRight(strings.TrimSpace(left), "/") == strings.TrimRight(strings.TrimSpace(right), "/")
}

func valueOrEmpty[T any](value *T, selector func(*T) string) string {
	if value == nil || selector == nil {
		return ""
	}
	return selector(value)
}

func valueOrZero[T any](value *T, selector func(*T) int) int {
	if value == nil || selector == nil {
		return 0
	}
	return selector(value)
}
