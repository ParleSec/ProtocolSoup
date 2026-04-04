package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	oid4vciprotocol "github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

type apiImportRequest struct {
	WalletSubject         string `json:"wallet_subject,omitempty"`
	Offer                 string `json:"offer,omitempty"`
	Credential            string `json:"credential,omitempty"`
	TxCode                string `json:"tx_code,omitempty"`
	CredentialFormat      string `json:"credential_format,omitempty"`
	CredentialConfigID    string `json:"credential_configuration_id,omitempty"`
	LookingGlassSessionID string `json:"looking_glass_session_id,omitempty"`
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
	JWKSURI                           string
	AuthorizationServers              []string
	CredentialConfigurationsSupported map[string]map[string]interface{}
}

type resolvedAuthorizationServerMetadata struct {
	Raw                           map[string]interface{}
	AuthorizationServer           string
	AuthorizationEndpoint         string
	TokenEndpoint                 string
	JWKSURI                       string
	CodeChallengeMethodsSupported []string
}

type externalIssuerImportRequest struct {
	OfferInput            string
	TxCode                string
	CredentialFormat      string
	CredentialConfigID    string
	LookingGlassSessionID string
	WalletBaseURL         string
}

type externalIssuerImportResult struct {
	Source                      string
	AuthorizationRequired       bool
	AuthorizationURL            string
	IssuedCredential            *issuedWalletCredential
	CredentialOffer             map[string]interface{}
	CredentialOfferURI          string
	CredentialOfferTransport    string
	CredentialIssuer            string
	IssuerMetadata              map[string]interface{}
	AuthorizationServerMetadata map[string]interface{}
	TokenEndpoint               string
	CredentialEndpoint          string
	NonceEndpoint               string
	TxCodeRequired              bool
	TxCodeDescription           string
	TxCodeLength                int
	TxCodeInputMode             string
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
	CreatedAt                   time.Time
	ExpiresAt                   time.Time
}

const oid4vciAuthorizationStateTTL = 15 * time.Minute

func (s *walletHarnessServer) handleAPIImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

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

	if strings.TrimSpace(req.Offer) != "" && strings.TrimSpace(req.Credential) != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "provide either offer or credential, not both",
		})
		return
	}

	var importResult *externalIssuerImportResult
	if strings.TrimSpace(req.Credential) != "" {
		importResult, err = s.importDirectCredential(r.Context(), externalIssuerImportRequest{
			CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
			CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
			LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
			WalletBaseURL:         requestBaseURL(r),
		}, strings.TrimSpace(req.Credential))
	} else {
		importResult, err = s.issueFromExternalIssuer(r.Context(), wallet, externalIssuerImportRequest{
			OfferInput:            strings.TrimSpace(req.Offer),
			TxCode:                strings.TrimSpace(req.TxCode),
			CredentialFormat:      strings.TrimSpace(req.CredentialFormat),
			CredentialConfigID:    strings.TrimSpace(req.CredentialConfigID),
			LookingGlassSessionID: strings.TrimSpace(req.LookingGlassSessionID),
			WalletBaseURL:         requestBaseURL(r),
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
			writeJSON(w, apiErr.Status, response)
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_import_failed",
			"error_description": err.Error(),
		})
		return
	}

	if importResult == nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_import_failed",
			"error_description": "wallet import did not produce a result",
		})
		return
	}
	if importResult.AuthorizationRequired && strings.TrimSpace(importResult.AuthorizationURL) != "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
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
			"issuer_metadata":               importResult.IssuerMetadata,
			"authorization_server_metadata": importResult.AuthorizationServerMetadata,
		})
		return
	}
	if importResult.IssuedCredential == nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error":             "wallet_import_failed",
			"error_description": "external issuer did not return a credential",
		})
		return
	}

	if err := s.bindCredential(
		wallet,
		importResult.IssuedCredential.CredentialJWT,
		importResult.IssuedCredential.CredentialConfigID,
		importResult.IssuedCredential.CredentialFormat,
	); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_credential",
			"error_description": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
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
	})
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
	pending := s.oid4vciAuthStates[state]
	if strings.TrimSpace(state) != "" {
		delete(s.oid4vciAuthStates, state)
	}
	s.mu.Unlock()
	if pending == nil {
		s.redirectOID4VCICallbackResult(w, r, "error", "authorization state is missing or expired")
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
	)
	if err != nil {
		s.redirectOID4VCICallbackResult(w, r, "error", err.Error())
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

	tokenPayload, err := s.exchangeExternalPreAuthorizedToken(
		ctx,
		authorizationServerMetadata.TokenEndpoint,
		preAuthorizedGrant.PreAuthorizedCode,
		input.TxCode,
		input.LookingGlassSessionID,
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
	)
}

func (s *walletHarnessServer) startExternalAuthorizationCodeImport(
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
	clientID := firstNonEmpty(strings.TrimSpace(s.oid4vciClientID), callbackBaseURL)
	redirectURI := callbackBaseURL + "/api/oid4vci/callback"
	state := randomValue(24)
	codeVerifier, codeChallenge, codeChallengeMethod := buildPKCEPair(authorizationServerMetadata.CodeChallengeMethodsSupported)
	if codeVerifier == "" || codeChallenge == "" {
		return nil, fmt.Errorf("pkce challenge generation failed")
	}
	authorizationURL, err := buildExternalAuthorizationURL(
		authorizationServerMetadata.AuthorizationEndpoint,
		clientID,
		redirectURI,
		state,
		selectedConfigurationID,
		resolvedOffer,
		authorizationServerMetadata,
		codeChallenge,
		codeChallengeMethod,
	)
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
		CredentialConfigurationID:   selectedConfigurationID,
		CredentialFormat:            strings.TrimSpace(credentialFormat),
		JWTProofRequired:            jwtProofRequired,
		IssuerMetadata:              issuerMetadata,
		AuthorizationServerMetadata: authorizationServerMetadata,
		LookingGlassSessionID:       strings.TrimSpace(input.LookingGlassSessionID),
		CreatedAt:                   time.Now().UTC(),
		ExpiresAt:                   time.Now().UTC().Add(oid4vciAuthorizationStateTTL),
	}
	s.mu.Unlock()

	return &externalIssuerImportResult{
		Source:                      "authorization_code_pending",
		AuthorizationRequired:       true,
		AuthorizationURL:            authorizationURL,
		CredentialOffer:             resolvedOffer.RawOffer,
		CredentialOfferURI:          resolvedOffer.OfferURI,
		CredentialOfferTransport:    resolvedOffer.TransportMode,
		CredentialIssuer:            issuerMetadata.CredentialIssuer,
		IssuerMetadata:              issuerMetadata.Raw,
		AuthorizationServerMetadata: authorizationServerMetadata.Raw,
		TokenEndpoint:               authorizationServerMetadata.TokenEndpoint,
		CredentialEndpoint:          issuerMetadata.CredentialEndpoint,
		NonceEndpoint:               issuerMetadata.NonceEndpoint,
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
) (*externalIssuerImportResult, error) {
	accessToken := strings.TrimSpace(asString(tokenPayload["access_token"]))
	if accessToken == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "token response missing access_token",
		}
	}

	proofJWT := ""
	var err error
	if jwtProofRequired {
		cNonce := strings.TrimSpace(asString(tokenPayload["c_nonce"]))
		if cNonce == "" && strings.TrimSpace(issuerMetadata.NonceEndpoint) != "" {
			cNonce, err = s.fetchExternalNonce(ctx, issuerMetadata.NonceEndpoint, accessToken, input.LookingGlassSessionID)
			if err != nil {
				return nil, err
			}
		}
		if cNonce == "" {
			return nil, &walletAPIError{
				Status:      http.StatusBadGateway,
				Code:        "wallet_import_failed",
				Description: "issuer requires jwt proof but no c_nonce was provided",
			}
		}
		proofJWT, err = s.createCredentialProofJWT(wallet, wallet.Subject, cNonce, issuerMetadata.CredentialIssuer)
		if err != nil {
			return nil, fmt.Errorf("create credential proof jwt: %w", err)
		}
	}

	credentialPayload, err := s.requestExternalCredential(
		ctx,
		issuerMetadata.CredentialEndpoint,
		selectedConfigurationID,
		credentialFormatHint,
		accessToken,
		proofJWT,
		input.LookingGlassSessionID,
	)
	if err != nil {
		return nil, err
	}

	credentialJWT, err := credentialPayloadToString(credentialPayload["credential"])
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(credentialJWT) == "" {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: "credential response missing credential",
		}
	}

	credentialFormat := firstNonEmpty(
		strings.TrimSpace(asString(credentialPayload["format"])),
		strings.TrimSpace(credentialFormatHint),
		input.CredentialFormat,
		summaryFormat(summarizeCredential(credentialJWT)),
	)
	if _, err := s.validateImportedCredential(
		ctx,
		credentialJWT,
		credentialFormat,
		issuerMetadata,
		authorizationServerMetadata,
		input.LookingGlassSessionID,
	); err != nil {
		return nil, &walletAPIError{
			Status:      http.StatusBadGateway,
			Code:        "wallet_import_failed",
			Description: fmt.Sprintf("validate issuer signature: %v", err),
		}
	}

	result := &externalIssuerImportResult{
		Source: "external_oid4vci",
		IssuedCredential: &issuedWalletCredential{
			CredentialJWT:      credentialJWT,
			CredentialFormat:   credentialFormat,
			CredentialConfigID: selectedConfigurationID,
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

func buildPKCEPair(supportedMethods []string) (string, string, string) {
	codeVerifier, codeChallenge := mockidp.GeneratePKCE()
	method := "S256"
	if len(supportedMethods) == 0 || containsStringFold(supportedMethods, "S256") {
		return codeVerifier, codeChallenge, method
	}
	if containsStringFold(supportedMethods, "plain") {
		return codeVerifier, codeVerifier, "plain"
	}
	return codeVerifier, codeChallenge, method
}

func buildExternalAuthorizationURL(
	authorizationEndpoint string,
	clientID string,
	redirectURI string,
	state string,
	selectedConfigurationID string,
	resolvedOffer *resolvedCredentialOfferInput,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
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
	if scopesSupported := stringSliceFromValue(valueOrEmptyMap(authorizationServerMetadata, func(metadata *resolvedAuthorizationServerMetadata) map[string]interface{} { return metadata.Raw })["scopes_supported"]); containsStringFold(scopesSupported, "openid") {
		query.Set("scope", "openid")
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
		return &resolvedExternalIssuerMetadata{
			Raw:                               payload,
			CredentialIssuer:                  metadataIssuer,
			CredentialEndpoint:                credentialEndpoint,
			NonceEndpoint:                     strings.TrimSpace(asString(payload["nonce_endpoint"])),
			JWKSURI:                           strings.TrimSpace(asString(payload["jwks_uri"])),
			AuthorizationServers:              stringSliceFromValue(payload["authorization_servers"]),
			CredentialConfigurationsSupported: configurationMap,
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
	if tokenEndpoint := strings.TrimSpace(asString(issuerMetadata.Raw["token_endpoint"])); tokenEndpoint != "" {
		return &resolvedAuthorizationServerMetadata{
			Raw:                           issuerMetadata.Raw,
			AuthorizationServer:           issuerMetadata.CredentialIssuer,
			AuthorizationEndpoint:         strings.TrimSpace(asString(issuerMetadata.Raw["authorization_endpoint"])),
			TokenEndpoint:                 tokenEndpoint,
			JWKSURI:                       strings.TrimSpace(asString(issuerMetadata.Raw["jwks_uri"])),
			CodeChallengeMethodsSupported: stringSliceFromValue(issuerMetadata.Raw["code_challenge_methods_supported"]),
		}, nil
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
		for _, wellKnownName := range []string{"oauth-authorization-server", "openid-configuration"} {
			candidateURLs, err := wellKnownMetadataURLCandidates(candidate, wellKnownName)
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
				if issuer := strings.TrimSpace(asString(payload["issuer"])); issuer != "" && !sameURLIdentifier(issuer, candidate) {
					continue
				}
				return &resolvedAuthorizationServerMetadata{
					Raw:                           payload,
					AuthorizationServer:           candidate,
					AuthorizationEndpoint:         strings.TrimSpace(asString(payload["authorization_endpoint"])),
					TokenEndpoint:                 tokenEndpoint,
					JWKSURI:                       strings.TrimSpace(asString(payload["jwks_uri"])),
					CodeChallengeMethodsSupported: stringSliceFromValue(payload["code_challenge_methods_supported"]),
				}, nil
			}
		}
	}

	return &resolvedAuthorizationServerMetadata{
		AuthorizationServer: candidates[0],
		TokenEndpoint:       strings.TrimRight(candidates[0], "/") + "/token",
	}, nil
}

func (s *walletHarnessServer) exchangeExternalPreAuthorizedToken(
	ctx context.Context,
	tokenEndpoint string,
	preAuthorizedCode string,
	txCode string,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	form.Set("pre-authorized_code", strings.TrimSpace(preAuthorizedCode))
	if strings.TrimSpace(txCode) != "" {
		form.Set("tx_code", strings.TrimSpace(txCode))
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

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, walletAPIErrorFromUpstream(resp.StatusCode, body, "token request")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return payload, nil
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
) (map[string]interface{}, error) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.httpClient.Do(req)
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
	accessToken string,
	lookingGlassSessionID string,
) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, nonceEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.httpClient.Do(req)
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
	credentialFormat string,
	accessToken string,
	proofJWT string,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	requestBody := map[string]interface{}{
		"credential_configuration_id": strings.TrimSpace(credentialConfigurationID),
	}
	if strings.TrimSpace(credentialFormat) != "" {
		requestBody["format"] = strings.TrimSpace(credentialFormat)
	}
	if strings.TrimSpace(proofJWT) != "" {
		requestBody["proofs"] = []map[string]interface{}{
			{
				"proof_type": "jwt",
				"jwt":        strings.TrimSpace(proofJWT),
			},
		}
	}

	rawBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credentialEndpoint, strings.NewReader(string(rawBody)))
	if err != nil {
		return nil, fmt.Errorf("build credential request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, walletAPIErrorFromUpstream(resp.StatusCode, body, "credential request")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode credential response: %w", err)
	}
	return payload, nil
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
	issuerKeys, err := s.resolveExternalIssuerKeys(ctx, parsedCredential, issuerMetadata, authorizationServerMetadata, lookingGlassSessionID)
	if err != nil {
		return nil, err
	}
	if err := formatHandler.ValidateIssuerSignature(vc.CredentialValidationInput{
		Credential:       strings.TrimSpace(credential),
		ParsedCredential: parsedCredential,
		IssuerKeys:       issuerKeys,
		HTTPClient:       s.httpClient,
	}); err != nil {
		return nil, err
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
	candidateJWKSURIs := make([]string, 0, 4)
	if issuerMetadata != nil {
		candidateJWKSURIs = append(candidateJWKSURIs, strings.TrimSpace(issuerMetadata.JWKSURI))
		candidateJWKSURIs = append(candidateJWKSURIs, defaultJWKSURLCandidates(issuerMetadata.CredentialIssuer)...)
	}
	if authorizationServerMetadata != nil {
		candidateJWKSURIs = append(candidateJWKSURIs, strings.TrimSpace(authorizationServerMetadata.JWKSURI))
		candidateJWKSURIs = append(candidateJWKSURIs, defaultJWKSURLCandidates(authorizationServerMetadata.AuthorizationServer)...)
	}
	candidateJWKSURIs = append(candidateJWKSURIs, defaultJWKSURLCandidates(parsedCredential.Issuer)...)
	candidateJWKSURIs = dedupeStringList(candidateJWKSURIs)

	if len(candidateJWKSURIs) == 0 {
		return nil, nil
	}

	var (
		keys          []intcrypto.JWK
		attemptErrors []string
	)
	for _, candidateURI := range candidateJWKSURIs {
		jwksPayload, err := s.fetchJWKS(ctx, candidateURI, lookingGlassSessionID)
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", candidateURI, err))
			continue
		}
		keys = append(keys, jwksPayload.Keys...)
	}
	keys = dedupeJWKs(keys)
	if len(keys) > 0 {
		return keys, nil
	}
	if strings.HasPrefix(strings.TrimSpace(parsedCredential.Original), "{") {
		return nil, nil
	}
	if len(attemptErrors) == 0 {
		return nil, fmt.Errorf("issuer jwks could not be resolved")
	}
	return nil, fmt.Errorf("issuer jwks could not be resolved: %s", strings.Join(attemptErrors, "; "))
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
	resp, err := s.httpClient.Do(req)
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
	root := parsed.Scheme + "://" + parsed.Host
	candidates := []string{
		strings.TrimRight(root, "/") + "/.well-known/jwks.json",
	}
	if strings.TrimSpace(parsed.Path) != "" && strings.TrimSpace(parsed.Path) != "/" {
		candidates = append(candidates, strings.TrimRight(normalizedIdentifier, "/")+"/jwks")
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", firstNonEmpty(strings.TrimSpace(acceptHeader), "application/json"))
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}

	resp, err := s.httpClient.Do(req)
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
	normalizedPath := strings.Trim(strings.TrimSpace(parsed.Path), "/")

	candidates := make([]string, 0, 2)

	canonical := *parsed
	if normalizedPath == "" {
		canonical.Path = path.Join("/", ".well-known", wellKnownName)
	} else {
		canonical.Path = path.Join("/", ".well-known", wellKnownName, normalizedPath)
	}
	candidates = append(candidates, canonical.String())

	fallback := strings.TrimRight(strings.TrimSpace(identifier), "/") + "/.well-known/" + strings.Trim(strings.TrimSpace(wellKnownName), "/")
	candidates = append(candidates, fallback)
	return dedupeStringList(candidates), nil
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
