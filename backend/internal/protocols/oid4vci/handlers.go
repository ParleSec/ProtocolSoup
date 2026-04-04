package oid4vci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

type createOfferRequest struct {
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`
	TxCodeRequired             bool     `json:"tx_code_required"`
	Deferred                   bool     `json:"deferred"`
	WalletUserID               string   `json:"wallet_user_id,omitempty"`
}

type credentialRequest struct {
	Format                    string            `json:"format,omitempty"`
	CredentialConfigurationID string            `json:"credential_configuration_id,omitempty"`
	Proof                     *credentialProof  `json:"proof,omitempty"`
	Proofs                    []credentialProof `json:"proofs,omitempty"`
}

type credentialProof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

type deferredCredentialRequest struct {
	TransactionID string `json:"transaction_id"`
}

func (p *Plugin) handleCredentialIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	if !p.isAllowedMetadataRequestPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	sessionID := p.getSessionFromRequest(r)
	issuerID := p.issuerID()
	nonceEndpoint := issuerID + "/nonce"

	if err := ValidateNonceEndpointRequirement(true, nonceEndpoint); err != nil {
		writeOID4VCIError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	metadata := map[string]interface{}{
		"credential_issuer":                   issuerID,
		"authorization_servers":               []string{issuerID},
		"token_endpoint":                      issuerID + "/token",
		"credential_endpoint":                 issuerID + "/credential",
		"deferred_credential_endpoint":        issuerID + "/deferred_credential",
		"nonce_endpoint":                      nonceEndpoint,
		"credential_configurations_supported": p.credentialConfigurationsSupported(),
		"display": []map[string]interface{}{
			{
				"name":   "ProtocolSoup Credential Issuer",
				"locale": "en-US",
			},
		},
		"credential_response_encryption": map[string]interface{}{
			"required": false,
		},
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Credential Issuer Metadata Retrieved",
		map[string]interface{}{
			"issuer":            issuerID,
			"metadata_endpoint": p.metadataWellKnownPath(),
			"request_path":      r.URL.Path,
		},
		p.vcAnnotation("metadata_discovery")...,
	)

	writeJSON(w, http.StatusOK, metadata)
}

func (p *Plugin) handleCreatePreAuthorizedOffer(w http.ResponseWriter, r *http.Request) {
	p.handleCreateOffer(w, r, false, false)
}

func (p *Plugin) handleCreatePreAuthorizedOfferByValue(w http.ResponseWriter, r *http.Request) {
	p.handleCreateOffer(w, r, true, false)
}

func (p *Plugin) handleCreateDeferredPreAuthorizedOffer(w http.ResponseWriter, r *http.Request) {
	p.handleCreateOffer(w, r, false, true)
}

func (p *Plugin) handleCreateOffer(w http.ResponseWriter, r *http.Request, byValue bool, deferred bool) {
	sessionID := p.getSessionFromRequest(r)

	var req createOfferRequest
	if err := jsonDecode(r, &req); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.Deferred = req.Deferred || deferred
	credentialIDs := p.normalizeCredentialConfigurationIDs(req.CredentialConfigurationIDs)
	wallet, err := p.getOrCreateWallet(req.WalletUserID)
	if err != nil {
		writeServerError(w, "create wallet identity", err)
		return
	}

	preAuthorizedCode := p.randomValue(32)
	offerID := p.randomValue(24)
	txCodeValue := ""
	var txCodeObject *models.VCTxCode
	if req.TxCodeRequired {
		txCodeValue = "123456"
		txCodeObject = &models.VCTxCode{
			Description: "Transaction code delivered via out-of-band channel",
			Length:      6,
			InputMode:   "numeric",
		}
	}

	offer := models.VCCredentialOffer{
		CredentialIssuer:           p.issuerID(),
		CredentialConfigurationIDs: credentialIDs,
		Grants: models.VCCredentialOfferGrants{
			PreAuthorizedCode: &models.VCPreAuthorizedCodeGrant{
				PreAuthorizedCode: preAuthorizedCode,
				TxCode:            txCodeObject,
			},
		},
		CreatedAt: time.Now().UTC(),
	}

	record := &offerRecord{
		ID:             offerID,
		Offer:          offer,
		TxCodeRequired: req.TxCodeRequired,
		TxCodeValue:    txCodeValue,
		WalletID:       wallet.ID,
		Deferred:       req.Deferred,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(15 * time.Minute),
	}

	p.mu.Lock()
	p.offers[offerID] = record
	p.offersByPreAuthCode[preAuthorizedCode] = offerID
	p.mu.Unlock()

	data := map[string]interface{}{
		"offer_id":                     offerID,
		"pre_authorized_code":          preAuthorizedCode,
		"credential_configuration_ids": credentialIDs,
		"deferred":                     req.Deferred,
		"wallet_id":                    wallet.ID,
		"wallet_subject":               wallet.Subject,
		"wallet_user_id":               wallet.UserID,
	}
	if req.TxCodeRequired {
		data["tx_code_required"] = true
		// Looking Glass capture channel for the issuer's out-of-band tx_code value.
		data["tx_code_oob_value"] = txCodeValue
	}

	if byValue {
		if err := ValidateCredentialOfferEnvelope(true, false); err != nil {
			writeOID4VCIError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		data["credential_offer"] = offer
	} else {
		if err := ValidateCredentialOfferEnvelope(false, true); err != nil {
			writeOID4VCIError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		data["credential_offer_uri"] = p.issuerID() + "/credential-offer/" + offerID
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Credential Offer Created",
		data,
		p.vcAnnotation("metadata_discovery")...,
	)
	writeJSON(w, http.StatusCreated, data)
}

func (p *Plugin) handleCredentialOfferByReference(w http.ResponseWriter, r *http.Request) {
	offerID := strings.TrimSpace(chi.URLParam(r, "offerID"))
	if offerID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "offerID is required")
		return
	}

	p.mu.RLock()
	record, ok := p.offers[offerID]
	p.mu.RUnlock()
	if !ok {
		writeOID4VCIError(w, http.StatusNotFound, "invalid_request", "credential offer not found")
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "credential offer expired")
		return
	}

	writeJSON(w, http.StatusOK, record.Offer)
}

func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		p.handlePreAuthorizedTokenGrant(w, r, sessionID)
	case "authorization_code":
		p.handleAuthorizationCodeTokenGrant(w, r, sessionID)
	default:
		writeOID4VCIError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type is not supported")
	}
}

func (p *Plugin) handlePreAuthorizedTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	preAuthorizedCode := strings.TrimSpace(r.FormValue("pre-authorized_code"))
	if preAuthorizedCode == "" {
		preAuthorizedCode = strings.TrimSpace(r.FormValue("pre_authorized_code"))
	}
	txCode := strings.TrimSpace(r.FormValue("tx_code"))
	if preAuthorizedCode == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "pre-authorized_code is required")
		return
	}

	p.mu.RLock()
	offerID, ok := p.offersByPreAuthCode[preAuthorizedCode]
	record := p.offers[offerID]
	p.mu.RUnlock()
	if !ok || record == nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "unknown pre-authorized code")
		return
	}
	if record.Exchanged {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "pre-authorized code has already been exchanged")
		return
	}
	if time.Now().UTC().After(record.ExpiresAt) {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "pre-authorized code expired")
		return
	}
	if err := ValidatePreAuthorizedTxCodeRequirement(record.TxCodeRequired, txCode); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	if record.TxCodeRequired && txCode != record.TxCodeValue {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "invalid tx_code")
		return
	}

	if p.mockIDP == nil {
		writeOID4VCIError(w, http.StatusServiceUnavailable, "server_error", "mock identity provider is unavailable")
		return
	}

	scope := "vc:issue"
	accessToken, err := p.mockIDP.JWTService().CreateAccessToken(
		"wallet:"+offerID,
		"oid4vci",
		scope,
		tokenTTL,
		map[string]interface{}{
			"offer_id":                     offerID,
			"credential_configuration_ids": record.Offer.CredentialConfigurationIDs,
		},
	)
	if err != nil {
		writeServerError(w, "issue access token", err)
		return
	}

	nonce := models.VCNonce{
		Value:     p.randomValue(24),
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(nonceTTL),
	}

	allowedCredentialIDs := make(map[string]struct{}, len(record.Offer.CredentialConfigurationIDs))
	for _, id := range record.Offer.CredentialConfigurationIDs {
		allowedCredentialIDs[id] = struct{}{}
	}

	wallet, ok := p.getWalletByID(record.WalletID)
	if !ok {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "wallet context for offer is unavailable")
		return
	}

	p.mu.Lock()
	record.Exchanged = true
	delete(p.offersByPreAuthCode, preAuthorizedCode)
	p.accessGrants[accessToken] = &accessGrant{
		Token:                      accessToken,
		Subject:                    wallet.Subject,
		WalletID:                   wallet.ID,
		CredentialConfigurationIDs: allowedCredentialIDs,
		CNonce:                     nonce,
		CNonceUsed:                 false,
		OfferID:                    offerID,
		Deferred:                   record.Deferred,
		ExpiresAt:                  time.Now().UTC().Add(tokenTTL),
	}
	p.mu.Unlock()

	response := map[string]interface{}{
		"access_token":       accessToken,
		"token_type":         "Bearer",
		"expires_in":         int(tokenTTL.Seconds()),
		"scope":              scope,
		"c_nonce":            nonce.Value,
		"c_nonce_expires_in": int(nonceTTL.Seconds()),
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Pre-Authorized Token Issued",
		map[string]interface{}{
			"grant_type":             "pre-authorized_code",
			"offer_id":               offerID,
			"tx_code_required":       record.TxCodeRequired,
			"tx_code_supplied":       txCode != "",
			"credential_ids":         record.Offer.CredentialConfigurationIDs,
			"deferred":               record.Deferred,
			"wallet_id":              wallet.ID,
			"wallet_subject":         wallet.Subject,
			"c_nonce_expires_in":     int(nonceTTL.Seconds()),
			"access_token_expires":   int(tokenTTL.Seconds()),
			"access_token_issued_at": time.Now().UTC().Format(time.RFC3339),
		},
		p.vcAnnotation("c_nonce")...,
	)
	writeJSON(w, http.StatusOK, response)
}

func (p *Plugin) handleAuthorizationCodeTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	if p.mockIDP == nil {
		writeOID4VCIError(w, http.StatusServiceUnavailable, "server_error", "mock identity provider is unavailable")
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	codeVerifier := strings.TrimSpace(r.FormValue("code_verifier"))
	if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	if code == "" || clientID == "" || redirectURI == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "code, client_id, and redirect_uri are required")
		return
	}

	client, exists := p.mockIDP.GetClient(clientID)
	if !exists {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if !client.Public {
		if _, err := p.mockIDP.ValidateClient(clientID, clientSecret); err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}

	authCode, err := p.mockIDP.ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier)
	if err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	authorizedCredentialConfigurationIDs := authCode.CredentialConfigurationIDs
	if len(authorizedCredentialConfigurationIDs) == 0 {
		authorizedCredentialConfigurationIDs = sortedCredentialConfigurationIDs(p.credentialConfigurations)
	}
	if len(authorizedCredentialConfigurationIDs) == 0 {
		authorizedCredentialConfigurationIDs = []string{defaultCredentialConfigurationID}
	}

	scope := "vc:issue"
	accessToken, err := p.mockIDP.JWTService().CreateAccessToken(
		authCode.UserID,
		"oid4vci",
		scope,
		tokenTTL,
		map[string]interface{}{
			"credential_configuration_ids": authorizedCredentialConfigurationIDs,
		},
	)
	if err != nil {
		writeServerError(w, "issue access token", err)
		return
	}

	nonce := models.VCNonce{
		Value:     p.randomValue(24),
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(nonceTTL),
	}

	wallet, err := p.getOrCreateWallet(authCode.UserID)
	if err != nil {
		writeServerError(w, "create wallet identity", err)
		return
	}

	authorizedCredentialConfigurations := make(map[string]struct{}, len(authorizedCredentialConfigurationIDs))
	for _, credentialConfigurationID := range authorizedCredentialConfigurationIDs {
		authorizedCredentialConfigurations[credentialConfigurationID] = struct{}{}
	}

	p.mu.Lock()
	p.accessGrants[accessToken] = &accessGrant{
		Token:                      accessToken,
		Subject:                    wallet.Subject,
		WalletID:                   wallet.ID,
		CredentialConfigurationIDs: authorizedCredentialConfigurations,
		CNonce:                     nonce,
		CNonceUsed:                 false,
		OfferID:                    "authorization_code",
		Deferred:                   false,
		ExpiresAt:                  time.Now().UTC().Add(tokenTTL),
	}
	p.mu.Unlock()

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Authorization Code Token Issued",
		map[string]interface{}{
			"grant_type":     "authorization_code",
			"client_id":      clientID,
			"user_id":        authCode.UserID,
			"wallet_id":      wallet.ID,
			"wallet_subject": wallet.Subject,
			"scope":          scope,
			"c_nonce":        nonce.Value,
			"expires_in":     int(tokenTTL.Seconds()),
			"nonce_expires":  int(nonceTTL.Seconds()),
		},
		p.vcAnnotation("c_nonce")...,
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":       accessToken,
		"token_type":         "Bearer",
		"expires_in":         int(tokenTTL.Seconds()),
		"scope":              scope,
		"c_nonce":            nonce.Value,
		"c_nonce_expires_in": int(nonceTTL.Seconds()),
	})
}

func (p *Plugin) handleNonce(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	accessToken, err := parseBearerToken(r)
	if err != nil {
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	p.mu.Lock()
	grant, ok := p.accessGrants[accessToken]
	if !ok {
		p.mu.Unlock()
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_token", "unknown access token")
		return
	}
	if time.Now().UTC().After(grant.ExpiresAt) {
		delete(p.accessGrants, accessToken)
		p.mu.Unlock()
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_token", "access token expired")
		return
	}
	previousNonce := grant.CNonce.Value
	grant.CNonce = models.VCNonce{
		Value:     p.randomValue(24),
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(nonceTTL),
	}
	grant.CNonceUsed = false
	newNonce := grant.CNonce.Value
	p.mu.Unlock()

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Nonce Rotated",
		map[string]interface{}{
			"previous_nonce":     previousNonce,
			"new_nonce":          newNonce,
			"c_nonce_expires_in": int(nonceTTL.Seconds()),
			"offer_id":           grant.OfferID,
		},
		p.vcAnnotation("c_nonce")...,
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"c_nonce":            newNonce,
		"c_nonce_expires_in": int(nonceTTL.Seconds()),
	})
}

func (p *Plugin) handleCredential(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	accessToken, err := parseBearerToken(r)
	if err != nil {
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	p.mu.RLock()
	grant, ok := p.accessGrants[accessToken]
	p.mu.RUnlock()
	if !ok || time.Now().UTC().After(grant.ExpiresAt) {
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_token", "token is unknown or expired")
		return
	}

	var req credentialRequest
	if err := jsonDecode(r, &req); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.CredentialConfigurationID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_configuration_id is required")
		return
	}
	credentialConfiguration, supported := p.credentialConfigurations[req.CredentialConfigurationID]
	if !supported {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_configuration_id is not supported by issuer metadata")
		return
	}
	if _, allowed := grant.CredentialConfigurationIDs[req.CredentialConfigurationID]; !allowed {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_configuration_id is not authorized")
		return
	}
	if requestedFormat := strings.TrimSpace(req.Format); requestedFormat != "" && requestedFormat != credentialConfiguration.Format {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "format does not match credential_configuration_id")
		return
	}

	proofs := p.collectProofs(req)
	if err := ValidateProofRequirement(true, len(proofs)); err != nil {
		p.emitEvent(
			sessionID,
			lookingglass.EventTypeSecurityWarning,
			"Credential Request Rejected",
			map[string]interface{}{
				"reason":             "missing_or_invalid_proofs",
				"proof_count":        len(proofs),
				"credential_request": req.CredentialConfigurationID,
			},
			p.vcAnnotation("proof_validation")...,
		)
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", err.Error())
		return
	}

	if grant.CNonceUsed || time.Now().UTC().After(grant.CNonce.ExpiresAt) {
		p.emitEvent(
			sessionID,
			lookingglass.EventTypeSecurityWarning,
			"Credential Request Rejected",
			map[string]interface{}{
				"reason":         "nonce_replay_or_expired",
				"credential_id":  req.CredentialConfigurationID,
				"nonce_expires":  grant.CNonce.ExpiresAt.Format(time.RFC3339),
				"nonce_consumed": grant.CNonceUsed,
			},
			p.vcAnnotation("c_nonce")...,
		)
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_nonce", "c_nonce is expired or already consumed")
		return
	}

	proofDeclaredSubject := ""
	var holderJWK *crypto.JWK
	for _, proof := range proofs {
		nonce, proofSub, proofKey, err := p.validateProofJWT(proof, p.issuerID(), grant.Subject)
		if err != nil {
			p.emitEvent(
				sessionID,
				lookingglass.EventTypeSecurityWarning,
				"Credential Request Rejected",
				map[string]interface{}{
					"reason":        "proof_validation_failed",
					"proof_type":    proof.ProofType,
					"proof_message": err.Error(),
				},
				p.vcAnnotation("proof_validation")...,
			)
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", err.Error())
			return
		}
		if proofSub != "" {
			proofDeclaredSubject = proofSub
		}
		if strings.TrimSpace(proofKey.Kty) != "" {
			holderJWK = &proofKey
		}
		if nonce != grant.CNonce.Value {
			p.emitEvent(
				sessionID,
				lookingglass.EventTypeSecurityWarning,
				"Credential Request Rejected",
				map[string]interface{}{
					"reason":         "nonce_mismatch",
					"expected_nonce": grant.CNonce.Value,
					"proof_nonce":    nonce,
				},
				p.vcAnnotation("c_nonce")...,
			)
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_nonce", "proof nonce does not match active c_nonce")
			return
		}
	}

	effectiveSubject := grant.Subject
	if proofDeclaredSubject != "" {
		effectiveSubject = proofDeclaredSubject
	}

	wallet, ok := p.getWalletByID(grant.WalletID)
	if !ok {
		wallet = &walletIdentity{
			ID:             "derived-" + p.randomValue(12),
			UserID:         effectiveSubject,
			Subject:        effectiveSubject,
			GivenName:      "Credential",
			FamilyName:     "Holder",
			Department:     "General",
			Degree:         "General Credential",
			GraduationYear: time.Now().UTC().Year() - 5,
			CreatedAt:      time.Now().UTC(),
		}
	}

	p.mu.Lock()
	grant.CNonceUsed = true
	p.mu.Unlock()

	issuedCredential, err := p.issueCredential(effectiveSubject, req.CredentialConfigurationID, wallet, holderJWK)
	if err != nil {
		writeServerError(w, "issue credential", err)
		return
	}
	if p.walletStore == nil {
		writeServerError(w, "persist credential lineage", fmt.Errorf("wallet credential store is unavailable"))
		return
	}
	issuerJWK := issuedCredential.IssuerJWK
	if strings.TrimSpace(issuerJWK.Kty) == "" {
		writeServerError(w, "persist credential lineage", fmt.Errorf("issuer jwk is unavailable"))
		return
	}
	issuerID := strings.TrimSpace(issuedCredential.Issuer)
	if issuerID == "" {
		issuerID = p.issuerID()
	}
	if !p.walletStore.Put(vc.WalletCredentialRecord{
		Subject:                   effectiveSubject,
		Format:                    issuedCredential.Format,
		CredentialConfigurationID: req.CredentialConfigurationID,
		VCT:                       issuedCredential.VCT,
		Doctype:                   issuedCredential.Doctype,
		CredentialTypes:           issuedCredential.CredentialTypes,
		CredentialJWT:             issuedCredential.CredentialJWT,
		IssuerSignedJWT:           issuedCredential.IssuerSignedJWT,
		CredentialID:              issuedCredential.CredentialID,
		Issuer:                    issuerID,
		IssuerJWK:                 issuerJWK,
		IssuedAt:                  time.Now().UTC(),
	}) {
		writeServerError(w, "persist credential lineage", fmt.Errorf("failed to persist issued credential in wallet store"))
		return
	}

	nextNonce := models.VCNonce{
		Value:     p.randomValue(24),
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(nonceTTL),
	}
	p.mu.Lock()
	grant.CNonce = nextNonce
	grant.CNonceUsed = false
	p.mu.Unlock()

	if grant.Deferred {
		transactionID := p.randomValue(24)
		now := time.Now().UTC()
		deferredRetryAfterSeconds := int(math.Ceil(deferredReadyDelay.Seconds()))
		if deferredRetryAfterSeconds < 1 {
			deferredRetryAfterSeconds = 1
		}
		p.mu.Lock()
		p.issuanceTransactions[transactionID] = &issuanceTransaction{
			Model: models.VCIssuanceTransaction{
				TransactionID:             transactionID,
				CredentialConfigurationID: req.CredentialConfigurationID,
				Format:                    issuedCredential.Format,
				AccessTokenID:             accessToken,
				Deferred:                  true,
				Status:                    "pending",
				CreatedAt:                 now,
				UpdatedAt:                 now,
			},
			Subject:    grant.Subject,
			ReadyAt:    now.Add(deferredReadyDelay),
			Credential: issuedCredential.Credential,
		}
		p.mu.Unlock()

		p.emitEvent(
			sessionID,
			lookingglass.EventTypeFlowStep,
			"Deferred Credential Transaction Created",
			map[string]interface{}{
				"transaction_id":                transactionID,
				"credential_configuration_id":   req.CredentialConfigurationID,
				"deferred_ready_in_seconds":     int(deferredReadyDelay.Seconds()),
				"c_nonce_expires_in_seconds":    int(nonceTTL.Seconds()),
				"deferred_credential_endpoint":  "/oid4vci/deferred_credential",
				"proofs_submitted":              len(proofs),
				"credential_request_deferred":   true,
				"credential_response_immediate": false,
			},
			p.vcAnnotation("proof_validation")...,
		)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"transaction_id":               transactionID,
			"c_nonce":                      nextNonce.Value,
			"c_nonce_expires_in":           int(nonceTTL.Seconds()),
			"credential_response":          "deferred",
			"deferred_retry_after_seconds": deferredRetryAfterSeconds,
		})
		return
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeTokenIssued,
		"Credential Issued",
		map[string]interface{}{
			"credential_configuration_id": req.CredentialConfigurationID,
			"format":                      issuedCredential.Format,
			"proofs_submitted":            len(proofs),
		},
		p.vcAnnotation("credential_endpoint")...,
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"format":             issuedCredential.Format,
		"credential":         issuedCredential.Credential,
		"c_nonce":            nextNonce.Value,
		"c_nonce_expires_in": int(nonceTTL.Seconds()),
	})
}

func (p *Plugin) handleDeferredCredential(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	accessToken, err := parseBearerToken(r)
	if err != nil {
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	var req deferredCredentialRequest
	if err := jsonDecode(r, &req); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.TransactionID == "" {
		if err := r.ParseForm(); err == nil {
			req.TransactionID = strings.TrimSpace(r.FormValue("transaction_id"))
		}
	}
	if req.TransactionID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "transaction_id is required")
		return
	}

	p.mu.RLock()
	transaction, ok := p.issuanceTransactions[req.TransactionID]
	p.mu.RUnlock()
	if !ok {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_transaction_id", "transaction_id not found")
		return
	}
	if transaction.Model.AccessTokenID != accessToken {
		writeOID4VCIError(w, http.StatusForbidden, "invalid_token", "transaction does not belong to access token")
		return
	}

	now := time.Now().UTC()
	if now.Before(transaction.ReadyAt) {
		retryAfterSeconds := int(math.Ceil(transaction.ReadyAt.Sub(now).Seconds()))
		if retryAfterSeconds < 1 {
			retryAfterSeconds = 1
		}

		p.emitEvent(
			sessionID,
			lookingglass.EventTypeFlowStep,
			"Deferred Credential Pending",
			map[string]interface{}{
				"transaction_id":      req.TransactionID,
				"retry_after_seconds": retryAfterSeconds,
				"ready_at":            transaction.ReadyAt.Format(time.RFC3339),
				"format":              transaction.Model.Format,
			},
			p.vcAnnotation("deferred_credential")...,
		)

		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"error":               "issuance_pending",
			"error_description":   "credential is not ready yet",
			"retry_after_seconds": retryAfterSeconds,
		})
		return
	}

	nextNonce := models.VCNonce{
		Value:     p.randomValue(24),
		IssuedAt:  now,
		ExpiresAt: now.Add(nonceTTL),
	}

	p.mu.Lock()
	transaction.Model.Status = "issued"
	transaction.Model.UpdatedAt = now
	delete(p.issuanceTransactions, req.TransactionID)
	if grant, ok := p.accessGrants[accessToken]; ok {
		grant.CNonce = nextNonce
		grant.CNonceUsed = false
	}
	p.mu.Unlock()

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Deferred Credential Issued",
		map[string]interface{}{
			"transaction_id":     req.TransactionID,
			"format":             transaction.Model.Format,
			"c_nonce":            nextNonce.Value,
			"c_nonce_expires_in": int(nonceTTL.Seconds()),
		},
		p.vcAnnotation("deferred_credential")...,
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"format":             transaction.Model.Format,
		"credential":         transaction.Credential,
		"c_nonce":            nextNonce.Value,
		"c_nonce_expires_in": int(nonceTTL.Seconds()),
	})
}

func (p *Plugin) normalizeCredentialConfigurationIDs(rawIDs []string) []string {
	return normalizeCredentialConfigurationIDs(rawIDs, p.credentialConfigurations)
}

func (p *Plugin) collectProofs(req credentialRequest) []credentialProof {
	proofs := make([]credentialProof, 0, len(req.Proofs)+1)
	if req.Proof != nil {
		proofs = append(proofs, *req.Proof)
	}
	proofs = append(proofs, req.Proofs...)
	return proofs
}

func (p *Plugin) validateProofJWT(proof credentialProof, expectedAudience string, expectedSubject string) (string, string, crypto.JWK, error) {
	emptyJWK := crypto.JWK{}
	if strings.TrimSpace(proof.JWT) == "" {
		return "", "", emptyJWK, fmt.Errorf("proof jwt is required")
	}
	if strings.TrimSpace(strings.ToLower(proof.ProofType)) != "jwt" {
		return "", "", emptyJWK, fmt.Errorf("unsupported proof_type %q", proof.ProofType)
	}

	decodedToken, err := crypto.DecodeTokenWithoutValidation(proof.JWT)
	if err != nil {
		return "", "", emptyJWK, fmt.Errorf("proof jwt decode failed: %w", err)
	}
	if err := ValidateOID4VCIProofType(fmt.Sprint(decodedToken.Header["typ"])); err != nil {
		return "", "", emptyJWK, err
	}
	iss, _ := decodedToken.Payload["iss"].(string)
	sub, _ := decodedToken.Payload["sub"].(string)
	if strings.TrimSpace(iss) == "" || strings.TrimSpace(sub) == "" {
		return "", "", emptyJWK, fmt.Errorf("proof iss and sub are required")
	}
	proofSubject := strings.TrimSpace(iss)

	if strings.HasPrefix(expectedSubject, "did:example:") &&
		strings.HasPrefix(proofSubject, "did:example:") &&
		proofSubject != expectedSubject {
		return "", "", emptyJWK, fmt.Errorf("proof subject %q does not match grant subject %q", proofSubject, expectedSubject)
	}

	verificationKey, expectedAlgPrefix, proofJWK, err := proofVerificationKeyFromClaims(decodedToken.Payload)
	if err != nil {
		return "", "", emptyJWK, err
	}
	parsed, err := jwt.Parse(proof.JWT, func(token *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(token.Method.Alg(), expectedAlgPrefix) {
			return nil, fmt.Errorf("proof jwt uses unexpected algorithm")
		}
		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(proofJWK.Kid) != "" && strings.TrimSpace(kid) != "" && strings.TrimSpace(proofJWK.Kid) != strings.TrimSpace(kid) {
			return nil, fmt.Errorf("proof kid does not match cnf.jwk kid")
		}
		return verificationKey, nil
	})
	if err != nil {
		return "", "", emptyJWK, fmt.Errorf("invalid proof jwt: %w", err)
	}
	if !parsed.Valid {
		return "", "", emptyJWK, fmt.Errorf("proof jwt failed signature validation")
	}
	if err := ValidateOID4VCIProofType(fmt.Sprint(parsed.Header["typ"])); err != nil {
		return "", "", emptyJWK, err
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", emptyJWK, fmt.Errorf("proof claims are invalid")
	}
	if err := validateAudienceClaim(claims["aud"], expectedAudience); err != nil {
		return "", "", emptyJWK, err
	}
	expUnix, err := numericDateToInt64(claims["exp"])
	if err != nil {
		return "", "", emptyJWK, fmt.Errorf("proof exp claim is invalid")
	}
	iatUnix, err := numericDateToInt64(claims["iat"])
	if err != nil {
		return "", "", emptyJWK, fmt.Errorf("proof iat claim is invalid")
	}
	now := time.Now().UTC().Unix()
	if now >= expUnix {
		return "", "", emptyJWK, fmt.Errorf("proof is expired")
	}
	if iatUnix > now+60 {
		return "", "", emptyJWK, fmt.Errorf("proof iat is in the future")
	}
	nonceValue, _ := claims["nonce"].(string)
	if strings.TrimSpace(nonceValue) == "" {
		return "", "", emptyJWK, fmt.Errorf("proof nonce is required")
	}
	return nonceValue, proofSubject, proofJWK, nil
}

func proofVerificationKeyFromClaims(claims map[string]interface{}) (interface{}, string, crypto.JWK, error) {
	cnfMap, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return nil, "", crypto.JWK{}, fmt.Errorf("proof cnf claim is required")
	}
	jwkRaw, exists := cnfMap["jwk"]
	if !exists {
		return nil, "", crypto.JWK{}, fmt.Errorf("proof cnf.jwk claim is required")
	}
	jwk, err := parseProofJWK(jwkRaw)
	if err != nil {
		return nil, "", crypto.JWK{}, err
	}
	switch strings.ToUpper(strings.TrimSpace(jwk.Kty)) {
	case "RSA":
		key, parseErr := crypto.ParseRSAPublicKeyFromJWK(jwk)
		if parseErr != nil {
			return nil, "", crypto.JWK{}, fmt.Errorf("proof cnf.jwk RSA parse failed: %w", parseErr)
		}
		return key, "RS", jwk, nil
	case "EC":
		key, parseErr := crypto.ParseECPublicKeyFromJWK(jwk)
		if parseErr != nil {
			return nil, "", crypto.JWK{}, fmt.Errorf("proof cnf.jwk EC parse failed: %w", parseErr)
		}
		return key, "ES", jwk, nil
	default:
		return nil, "", crypto.JWK{}, fmt.Errorf("unsupported proof cnf.jwk kty %q", jwk.Kty)
	}
}

func parseProofJWK(raw interface{}) (crypto.JWK, error) {
	jwkBytes, err := json.Marshal(raw)
	if err != nil {
		return crypto.JWK{}, fmt.Errorf("proof cnf.jwk is invalid JSON: %w", err)
	}
	var jwk crypto.JWK
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return crypto.JWK{}, fmt.Errorf("proof cnf.jwk parse failed: %w", err)
	}
	if strings.TrimSpace(jwk.Kty) == "" {
		return crypto.JWK{}, fmt.Errorf("proof cnf.jwk kty is required")
	}
	return jwk, nil
}

func validateAudienceClaim(rawAudience interface{}, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return fmt.Errorf("expected audience is empty")
	}
	switch value := rawAudience.(type) {
	case string:
		if value == expected {
			return nil
		}
	case []interface{}:
		for _, candidate := range value {
			if candidateString, ok := candidate.(string); ok && candidateString == expected {
				return nil
			}
		}
	}
	return fmt.Errorf("proof audience does not include issuer identifier")
}

func numericDateToInt64(raw interface{}) (int64, error) {
	switch value := raw.(type) {
	case float64:
		return int64(value), nil
	case json.Number:
		return value.Int64()
	case int64:
		return value, nil
	case int:
		return int64(value), nil
	default:
		return 0, fmt.Errorf("unsupported numeric date type %T", raw)
	}
}

func nowIssuer(issuer string) string {
	return strings.TrimSpace(issuer)
}

func parseBearerToken(r *http.Request) (string, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization == "" {
		return "", errors.New("missing bearer token")
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("invalid authorization header")
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("missing bearer token")
	}
	return token, nil
}

func jsonDecode(r *http.Request, target interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(target)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func (p *Plugin) isAllowedMetadataRequestPath(requestPath string) bool {
	normalized := normalizePathForMatch(requestPath)
	canonical := normalizePathForMatch(p.metadataWellKnownPath())
	pluginLocal := normalizePathForMatch("/oid4vci/.well-known/openid-credential-issuer")
	return normalized == canonical || normalized == pluginLocal
}

func normalizePathForMatch(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "/"
	}
	normalized := strings.TrimSuffix(trimmed, "/")
	if normalized == "" {
		return "/"
	}
	return normalized
}
