package oid4vci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
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
	// CredentialOfferEndpoint is the wallet's OID4VCI ?4.1.2 Credential Offer
	// Endpoint. When set on an issuer-initiated create, the issuer performs a
	// real HTTPS GET that delivers credential_offer as a query parameter.
	CredentialOfferEndpoint string `json:"credential_offer_endpoint,omitempty"`
}

const credentialOfferDeliveryTimeout = 15 * time.Second
const maxCredentialOfferDeliveryBodyBytes = 64 * 1024

const (
	issuerInitiatedStatusWaitingForWallet             = "waiting_for_wallet"
	issuerInitiatedStatusAuthorizationRequestReceived = "authorization_request_received"
	issuerInitiatedStatusTokenIssued                  = "token_issued"
	issuerInitiatedStatusCredentialIssued             = "credential_issued"
)

type credentialRequest struct {
	CredentialConfigurationID    string                               `json:"credential_configuration_id,omitempty"`
	CredentialIdentifier         string                               `json:"credential_identifier,omitempty"`
	Proofs                       json.RawMessage                      `json:"proofs,omitempty"`
	CredentialResponseEncryption *credentialResponseEncryptionRequest `json:"credential_response_encryption,omitempty"`
}

type credentialProof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

type deferredCredentialRequest struct {
	TransactionID                string                               `json:"transaction_id"`
	CredentialResponseEncryption *credentialResponseEncryptionRequest `json:"credential_response_encryption,omitempty"`
}

type authorizationDetail struct {
	Type                      string   `json:"type"`
	CredentialConfigurationID string   `json:"credential_configuration_id"`
	Locations                 []string `json:"locations,omitempty"`
}

type notificationRequest struct {
	NotificationID   string `json:"notification_id"`
	Event            string `json:"event"`
	EventDescription string `json:"event_description,omitempty"`
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

	metadata := p.credentialIssuerMetadata(issuerID, nonceEndpoint)

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

	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/jwt") {
		signedMetadata, err := p.signCredentialIssuerMetadata(metadata)
		if err != nil {
			writeServerError(w, "sign credential issuer metadata", err)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedMetadata))
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (p *Plugin) credentialIssuerMetadata(issuerID, nonceEndpoint string) map[string]interface{} {
	metadata := map[string]interface{}{
		"credential_issuer":                   issuerID,
		"authorization_servers":               []string{issuerID},
		"credential_endpoint":                 issuerID + "/credential",
		"deferred_credential_endpoint":        issuerID + "/deferred_credential",
		"notification_endpoint":               issuerID + "/notification",
		"nonce_endpoint":                      nonceEndpoint,
		"credential_configurations_supported": p.credentialConfigurationsSupported(),
		// OID4VCI 1.0 ?11.2.3: presence advertises multi-proof batch issuance
		// of the same Credential Dataset via the Credential Endpoint.
		"batch_credential_issuance": map[string]interface{}{
			"batch_size": batchCredentialIssuanceBatchSize,
		},
		"display": []map[string]interface{}{
			{
				"name":   "ProtocolSoup Credential Issuer",
				"locale": "en-US",
			},
		},
		"credential_response_encryption": credentialResponseEncryptionMetadata(),
	}
	if requestEncryption, err := p.credentialRequestEncryptionMetadata(); err == nil {
		metadata["credential_request_encryption"] = requestEncryption
	}
	return metadata
}

func (p *Plugin) signCredentialIssuerMetadata(metadata map[string]interface{}) (string, error) {
	if p.mdocPKI == nil || p.mdocPKI.DocumentSignerKey() == nil {
		return "", fmt.Errorf("certificate-backed metadata signer is unavailable")
	}
	chain := p.mdocPKI.DocumentSignerChain()
	if len(chain) == 0 {
		return "", fmt.Errorf("certificate-backed metadata signer chain is unavailable")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss": p.issuerID(),
		"sub": p.issuerID(),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	for name, value := range metadata {
		claims[name] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openidvci-issuer-metadata+jwt"
	x5c := make([]string, 0, len(chain))
	for _, certificate := range chain {
		if certificate == nil {
			return "", fmt.Errorf("certificate-backed metadata signer chain contains an empty certificate")
		}
		x5c = append(x5c, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	token.Header["x5c"] = x5c
	return token.SignedString(p.mdocPKI.DocumentSignerKey())
}

func (p *Plugin) handleUniversityDegreeTypeMetadata(w http.ResponseWriter, r *http.Request) {
	configuration, ok := p.credentialConfigurations["UniversityDegreeCredentialSDJWTHAIP"]
	if !ok || strings.TrimSpace(configuration.VCT) == "" {
		writeOID4VCIError(w, http.StatusNotFound, "invalid_request", "credential type metadata is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"vct":         configuration.VCT,
		"name":        "ProtocolSoup University Degree Credential",
		"description": "A selectively disclosable university degree credential issued by ProtocolSoup's HAIP profile.",
		"claims": []map[string]interface{}{
			{
				"path":      []string{"given_name"},
				"mandatory": true,
				"sd":        "always",
			},
			{
				"path":      []string{"family_name"},
				"mandatory": true,
				"sd":        "always",
			},
		},
	})
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
		txCodeValue = p.randomNumericCode(6)
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
		"credential_issuer":            p.issuerID(),
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

// handleCreateAuthorizationCodeOffer builds an issuer-initiated OID4VCI 1.0
// Section 4.1 Credential Offer for the authorization_code grant. Unlike the
// pre-authorized offer endpoints, this never issues a code itself: the
// wallet is expected to use the returned issuer_state as the
// `issuer_state` parameter on its own RFC 9126 PAR request to this
// issuer's authorization server, per Section 5.1. The issuer persists the
// processing context so issuer_state can be authenticated as issuer-created,
// bound to the offered credential configurations, and observed through the
// real PAR, token, and credential requests that follow.
func (p *Plugin) handleCreateAuthorizationCodeOffer(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)

	var req createOfferRequest
	if err := jsonDecode(r, &req); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	credentialIDs := p.normalizeCredentialConfigurationIDs(req.CredentialConfigurationIDs)
	if len(credentialIDs) == 0 {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "credential_configuration_ids must name at least one known credential configuration")
		return
	}

	now := time.Now().UTC()
	issuerState := p.randomValue(32)
	statusID := p.randomValue(32)
	issuerID := p.issuerID()
	offer := models.VCCredentialOffer{
		CredentialIssuer:           issuerID,
		CredentialConfigurationIDs: credentialIDs,
		Grants: models.VCCredentialOfferGrants{
			AuthorizationCode: &models.VCAuthorizationCodeGrant{
				IssuerState:         issuerState,
				AuthorizationServer: issuerID,
			},
		},
		CreatedAt: now,
	}

	transaction := &issuerInitiatedTransaction{
		StatusID:                   statusID,
		IssuerState:                issuerState,
		SessionID:                  sessionID,
		CredentialConfigurationIDs: append([]string(nil), credentialIDs...),
		Status:                     issuerInitiatedStatusWaitingForWallet,
		CreatedAt:                  now,
		UpdatedAt:                  now,
		ExpiresAt:                  now.Add(issuerInitiatedTransactionTTL),
	}
	p.mu.Lock()
	p.issuerInitiatedOffers[issuerState] = transaction
	p.issuerInitiatedStatus[statusID] = issuerState
	p.mu.Unlock()

	data := map[string]interface{}{
		"credential_issuer":            issuerID,
		"credential_configuration_ids": credentialIDs,
		"issuer_state":                 issuerState,
		"credential_offer":             offer,
		"status_uri":                   issuerID + "/offers/authorization-code/status/" + statusID,
		"expires_in":                   int(issuerInitiatedTransactionTTL.Seconds()),
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Issuer-Initiated Credential Offer Created",
		data,
		p.vcAnnotation("metadata_discovery")...,
	)

	if endpoint := strings.TrimSpace(req.CredentialOfferEndpoint); endpoint != "" {
		deliveryURL, statusCode, err := p.deliverCredentialOffer(r.Context(), endpoint, offer)
		if err != nil {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		data["credential_offer_endpoint"] = endpoint
		data["credential_offer_delivery_url"] = deliveryURL
		data["credential_offer_delivered"] = true
		data["credential_offer_delivery_status"] = statusCode
		p.emitEvent(
			sessionID,
			lookingglass.EventTypeHTTPExchange,
			"Credential Offer Delivered to Wallet Endpoint",
			map[string]interface{}{
				"credential_offer_endpoint": endpoint,
				"delivery_url":              deliveryURL,
				"status_code":               statusCode,
			},
			p.vcAnnotation("metadata_discovery")...,
		)
	}

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, data)
}

// deliverCredentialOffer performs the OID4VCI 1.0 ?4.1.2 issuer-to-wallet
// handoff: an HTTPS GET to the wallet's Credential Offer Endpoint with the
// Credential Offer object as the credential_offer query parameter.
func (p *Plugin) deliverCredentialOffer(ctx context.Context, endpoint string, offer models.VCCredentialOffer) (string, int, error) {
	deliveryURL, err := buildCredentialOfferDeliveryURL(endpoint, offer)
	if err != nil {
		return "", 0, err
	}
	if err := rejectCredentialOfferEndpointSSRF(deliveryURL); err != nil {
		return "", 0, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, credentialOfferDeliveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, deliveryURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("build credential offer delivery request: %w", err)
	}
	req.Header.Set("Accept", "application/json, text/html, */*")

	client := &http.Client{
		Timeout: credentialOfferDeliveryTimeout,
		// Wallets often 302 after accepting the offer. The
		// Credential Offer Endpoint has already received credential_offer on
		// the first response; do not follow redirects into HTML/error pages.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("deliver credential offer: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxCredentialOfferDeliveryBodyBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		detail := strings.TrimSpace(string(body))
		if detail == "" {
			return "", resp.StatusCode, fmt.Errorf("wallet credential_offer_endpoint returned HTTP %d", resp.StatusCode)
		}
		if len(detail) > 240 {
			detail = detail[:240] + "?"
		}
		return "", resp.StatusCode, fmt.Errorf("wallet credential_offer_endpoint returned HTTP %d: %s", resp.StatusCode, detail)
	}
	return deliveryURL, resp.StatusCode, nil
}

func buildCredentialOfferDeliveryURL(endpoint string, offer models.VCCredentialOffer) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("credential_offer_endpoint must be an absolute URL")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		host := strings.ToLower(parsed.Hostname())
		if host != "localhost" && !strings.HasPrefix(host, "127.") {
			return "", fmt.Errorf("credential_offer_endpoint must use https:// (OID4VCI 1.0 Section 4.1.2)")
		}
	}
	if parsed.User != nil {
		return "", fmt.Errorf("credential_offer_endpoint must not include userinfo")
	}
	rawOffer, err := marshalCredentialOfferForWire(offer)
	if err != nil {
		return "", fmt.Errorf("marshal credential_offer: %w", err)
	}
	query := parsed.Query()
	query.Set("credential_offer", string(rawOffer))
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// marshalCredentialOfferForWire encodes the OID4VCI Credential Offer object
// without ProtocolSoup-internal fields (for example created_at) that are not
// part of OpenID4VCI 1.0 Section 4.1.1.
func marshalCredentialOfferForWire(offer models.VCCredentialOffer) ([]byte, error) {
	wire := struct {
		CredentialIssuer           string                        `json:"credential_issuer"`
		CredentialConfigurationIDs []string                      `json:"credential_configuration_ids"`
		Grants                     models.VCCredentialOfferGrants `json:"grants,omitempty"`
	}{
		CredentialIssuer:           offer.CredentialIssuer,
		CredentialConfigurationIDs: offer.CredentialConfigurationIDs,
		Grants:                     offer.Grants,
	}
	return json.Marshal(wire)
}

func rejectCredentialOfferEndpointSSRF(rawURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Hostname() == "" {
		return fmt.Errorf("credential_offer_endpoint host is required")
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		// Local Looking Glass / test harnesses may expose the endpoint on loopback.
		return nil
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("credential_offer_endpoint must not target internal hosts")
	}
	if ip := net.ParseIP(host); ip != nil {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return fmt.Errorf("credential_offer_endpoint host is invalid")
		}
		addr = addr.Unmap()
		// Literal loopback is allowed for local harness delivery only.
		if addr.IsLoopback() {
			return nil
		}
		if addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("credential_offer_endpoint must not target private or link-local addresses")
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("credential_offer_endpoint host could not be resolved")
	}
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("credential_offer_endpoint must not target private or link-local addresses")
		}
	}
	return nil
}

func (p *Plugin) handleAuthorizationCodeOfferStatus(w http.ResponseWriter, r *http.Request) {
	statusID := strings.TrimSpace(chi.URLParam(r, "statusID"))
	p.mu.RLock()
	issuerState := p.issuerInitiatedStatus[statusID]
	transaction := p.issuerInitiatedOffers[issuerState]
	if transaction == nil {
		p.mu.RUnlock()
		writeOID4VCIError(w, http.StatusNotFound, "invalid_request", "issuer-initiated transaction not found")
		return
	}
	snapshot := *transaction
	snapshot.CredentialConfigurationIDs = append([]string(nil), transaction.CredentialConfigurationIDs...)
	p.mu.RUnlock()

	now := time.Now().UTC()
	status := snapshot.Status
	terminal := status == issuerInitiatedStatusCredentialIssued
	if now.After(snapshot.ExpiresAt) && !terminal {
		status = "expired"
		terminal = true
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":                       status,
		"terminal":                     terminal,
		"credential_configuration_ids": snapshot.CredentialConfigurationIDs,
		"created_at":                   snapshot.CreatedAt,
		"updated_at":                   snapshot.UpdatedAt,
		"expires_at":                   snapshot.ExpiresAt,
	})
}

func (p *Plugin) acceptIssuerInitiatedAuthorizationRequest(issuerState, clientID string, credentialConfigurationIDs []string) (*issuerInitiatedTransaction, error) {
	issuerState = strings.TrimSpace(issuerState)
	if issuerState == "" {
		return nil, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	transaction := p.issuerInitiatedOffers[issuerState]
	if transaction == nil || time.Now().UTC().After(transaction.ExpiresAt) {
		return nil, fmt.Errorf("issuer_state is unknown or expired")
	}
	// OpenID4VCI 1.0 Section 5.1.3 defines issuer_state as an opaque Issuer
	// processing context returned with the Credential Offer. It does not
	// require single-use. Multi-client happy flows reuse the same issuer_state
	// for a consecutive second client (with a distinct redirect_uri query
	// suffix), so the offer remains redeemable until ExpiresAt while still
	// enforcing Credential Configuration binding.
	offered := make(map[string]struct{}, len(transaction.CredentialConfigurationIDs))
	for _, configurationID := range transaction.CredentialConfigurationIDs {
		offered[configurationID] = struct{}{}
	}
	if err := validateCredentialConfigurationSubset(credentialConfigurationIDs, offered); err != nil {
		return nil, fmt.Errorf("issuer_state credential binding failed: %w", err)
	}
	transaction.ClientID = strings.TrimSpace(clientID)
	transaction.Status = issuerInitiatedStatusAuthorizationRequestReceived
	transaction.UpdatedAt = time.Now().UTC()
	snapshot := *transaction
	snapshot.CredentialConfigurationIDs = append([]string(nil), transaction.CredentialConfigurationIDs...)
	return &snapshot, nil
}

func (p *Plugin) updateIssuerInitiatedTransaction(issuerState, status string) *issuerInitiatedTransaction {
	issuerState = strings.TrimSpace(issuerState)
	if issuerState == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	transaction := p.issuerInitiatedOffers[issuerState]
	if transaction == nil || time.Now().UTC().After(transaction.ExpiresAt) {
		return nil
	}
	transaction.Status = status
	transaction.UpdatedAt = time.Now().UTC()
	snapshot := *transaction
	snapshot.CredentialConfigurationIDs = append([]string(nil), transaction.CredentialConfigurationIDs...)
	return &snapshot
}

func (p *Plugin) issuerInitiatedSessionID(issuerState string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	transaction := p.issuerInitiatedOffers[strings.TrimSpace(issuerState)]
	if transaction == nil {
		return ""
	}
	return transaction.SessionID
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

	if !requestHasMediaType(r, "application/x-www-form-urlencoded") {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	requiresHAIPSecurity := p.tokenRequestRequiresHAIPSecurity(r)

	// OAuth 2.0 Attestation-Based Client Authentication: when a
	// request presents OAuth-Client-Attestation(-PoP) headers at all, that is
	// the authentication verdict -- a failure here is never treated as "no
	// attestation attempted, fall back to client_secret", since that would
	// silently downgrade a rejected stronger method to a weaker one.
	attestation, attestationUsed, err := p.authenticateClientAttestation(r)
	if attestationUsed && err != nil {
		p.emitEvent(
			sessionID,
			lookingglass.EventTypeSecurityWarning,
			"Client Attestation Rejected",
			map[string]interface{}{"reason": err.Error()},
			p.vcAnnotation("client_attestation")...,
		)
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if requiresHAIPSecurity && !attestationUsed {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "OAuth client attestation is required for HAIP issuance")
		return
	}

	// RFC 9449 (DPoP): validate an optional proof once, up front, since htm
	// and htu are identical across both grant types at this single token
	// endpoint. Absent header -> zero-value result, no behavioural change.
	// Validate DPoP before committing the Client Attestation PoP jti so a
	// use_dpop_nonce challenge can be retried with the same attestation PoP
	// (FAPI2 RefreshTokenRequestSteps regenerates DPoP only).
	dpopResult, dpopErr := p.validateTokenEndpointDPoP(r)
	if dpopErr != nil {
		var infrastructureErr *dpop.InfrastructureError
		if errors.As(dpopErr, &infrastructureErr) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Replay Store Unavailable", map[string]interface{}{
				"error":  "server_error",
				"reason": "dpop_replay_store_unavailable",
			}, lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "DPoP Replay Protection Unavailable",
				Description: "The issuer failed closed because it could not reserve the proof's jti atomically.",
				Severity:    "warning",
				Reference:   "RFC 9449 Section 11.1",
			})
			writeOID4VCIError(w, http.StatusInternalServerError, "server_error", "DPoP validation is temporarily unavailable")
			return
		}
		var nonceErr *dpop.NonceRequiredError
		if errors.As(dpopErr, &nonceErr) {
			p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Nonce Challenge", map[string]interface{}{
				"error":  dpop.ErrorUseDPoPNonce,
				"reason": "server_requires_fresh_nonce",
			}, lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeSecurityHint,
				Title:       "DPoP Nonce Required",
				Description: "The issuer requires the DPoP proof to carry a server-provided nonce. The wallet must retry with a fresh proof echoing the nonce from the DPoP-Nonce response header.",
				Severity:    "info",
				Reference:   "RFC 9449 Section 8",
			})
			w.Header().Set(dpop.NonceHeaderName, nonceErr.Nonce)
			writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorUseDPoPNonce, "A fresh DPoP proof nonce is required; retry with the nonce from the DPoP-Nonce response header")
			return
		}
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "DPoP Proof Rejected", map[string]interface{}{
			"error":  dpop.ErrorInvalidDPoPProof,
			"reason": dpopErr.Error(),
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "Invalid DPoP Proof",
			Description: "The DPoP proof JWT failed validation, so the token request was rejected before any grant was processed.",
			Severity:    "warning",
			Reference:   "RFC 9449 Section 4.3",
		})
		writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorInvalidDPoPProof, dpopErr.Error())
		return
	}
	if requiresHAIPSecurity && !dpopResult.Present {
		writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorInvalidDPoPProof, "a DPoP proof is required for HAIP issuance")
		return
	}
	if p.tokenRequestRequiresDPoP(r) && !dpopResult.Present {
		writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorInvalidDPoPProof, "a DPoP proof is required to redeem this refresh token")
		return
	}
	if attestationUsed {
		if commitErr := p.commitClientAttestationPoP(attestation); commitErr != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", commitErr.Error())
			return
		}
	}
	if dpopResult.Present {
		p.emitEvent(sessionID, lookingglass.EventTypeCryptoOperation, "DPoP Proof Validated", map[string]interface{}{
			"jkt": dpopResult.JKT,
		}, lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "DPoP Proof-of-Possession",
			Description: "The wallet demonstrated possession of the private key bound to this token request. The issued access token will carry a cnf.jkt claim and a DPoP token_type.",
			Reference:   "RFC 9449 Section 4.3",
		})
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		p.handlePreAuthorizedTokenGrant(w, r, sessionID, attestation, attestationUsed, dpopResult.JKT)
	case "authorization_code":
		p.handleAuthorizationCodeTokenGrant(w, r, sessionID, attestation, attestationUsed, dpopResult.JKT)
	case "refresh_token":
		p.handleRefreshTokenGrant(w, r, sessionID, attestation, attestationUsed, dpopResult.JKT)
	default:
		writeOID4VCIError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type is not supported")
	}
}

// tokenRequestRequiresHAIPSecurity resolves the credential configurations
// bound to the grant without consuming it. HAIP 1.0 requires OAuth client
// authentication and DPoP sender-constrained access tokens for HAIP issuance;
// the issuer's non-HAIP educational profiles retain their own OAuth policy.
func (p *Plugin) tokenRequestRequiresHAIPSecurity(r *http.Request) bool {
	if r == nil {
		return false
	}
	var configurationIDs []string
	switch r.FormValue("grant_type") {
	case "urn:ietf:params:oauth:grant-type:pre-authorized_code":
		code := strings.TrimSpace(r.FormValue("pre-authorized_code"))
		p.mu.RLock()
		offerID := p.offersByPreAuthCode[code]
		record := p.offers[offerID]
		if record != nil {
			configurationIDs = append(configurationIDs, record.Offer.CredentialConfigurationIDs...)
		}
		p.mu.RUnlock()
	case "authorization_code":
		if p.mockIDP != nil {
			if authCode, ok := p.mockIDP.GetAuthorizationCode(r.FormValue("code")); ok {
				configurationIDs = append(configurationIDs, authCode.CredentialConfigurationIDs...)
			}
		}
	case "refresh_token":
		refreshToken := strings.TrimSpace(r.FormValue("refresh_token"))
		p.mu.RLock()
		if grant := p.refreshGrants[refreshToken]; grant != nil {
			for configurationID := range grant.CredentialConfigurationIDs {
				configurationIDs = append(configurationIDs, configurationID)
			}
		}
		p.mu.RUnlock()
	}
	for _, configurationID := range configurationIDs {
		if configuration, ok := p.credentialConfigurations[configurationID]; ok && configuration.HAIP {
			return true
		}
	}
	return false
}

// tokenRequestRequiresDPoP reports whether a refresh_token request must present
// a DPoP proof because the grant was originally issued with a DPoP-bound access
// token (FAPI2 SP sender-constrained refresh without proof must fail).
func (p *Plugin) tokenRequestRequiresDPoP(r *http.Request) bool {
	if r == nil || r.FormValue("grant_type") != "refresh_token" {
		return false
	}
	refreshToken := strings.TrimSpace(r.FormValue("refresh_token"))
	p.mu.RLock()
	grant := p.refreshGrants[refreshToken]
	p.mu.RUnlock()
	return grant != nil && grant.RequireDPoP
}

// parseAuthorizationDetails implements the OpenID4VCI Final ?5.1.1 profile of
// RFC 9396 used at the Token Endpoint.
func (p *Plugin) parseAuthorizationDetails(raw string) ([]string, bool, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, false, nil
	}
	var details []authorizationDetail
	if err := json.Unmarshal([]byte(raw), &details); err != nil || len(details) == 0 {
		return nil, true, fmt.Errorf("authorization_details must be a non-empty JSON array")
	}

	seen := make(map[string]struct{}, len(details))
	configurationIDs := make([]string, 0, len(details))
	for _, detail := range details {
		if detail.Type != "openid_credential" {
			return nil, true, fmt.Errorf("authorization_details type must be openid_credential")
		}
		configurationID := strings.TrimSpace(detail.CredentialConfigurationID)
		if configurationID == "" {
			return nil, true, fmt.Errorf("credential_configuration_id is required")
		}
		if _, supported := p.credentialConfigurations[configurationID]; !supported {
			return nil, true, fmt.Errorf("credential_configuration_id %q is not supported", configurationID)
		}
		locationMatched := false
		for _, location := range detail.Locations {
			if strings.TrimSpace(location) == p.issuerID() {
				locationMatched = true
				break
			}
		}
		if !locationMatched {
			return nil, true, fmt.Errorf("locations must contain the Credential Issuer identifier")
		}
		if _, duplicate := seen[configurationID]; duplicate {
			continue
		}
		seen[configurationID] = struct{}{}
		configurationIDs = append(configurationIDs, configurationID)
	}
	return configurationIDs, true, nil
}

func validateCredentialConfigurationSubset(requested []string, authorized map[string]struct{}) error {
	for _, configurationID := range requested {
		if _, allowed := authorized[configurationID]; !allowed {
			return fmt.Errorf("credential_configuration_id %q exceeds the authorized set", configurationID)
		}
	}
	return nil
}

func (p *Plugin) createCredentialAuthorization(configurationIDs []string, used bool) (map[string]string, []map[string]interface{}) {
	if !used {
		return nil, nil
	}
	identifiers := make(map[string]string, len(configurationIDs))
	details := make([]map[string]interface{}, 0, len(configurationIDs))
	for _, configurationID := range configurationIDs {
		identifier := p.randomValue(32)
		identifiers[identifier] = configurationID
		details = append(details, map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": configurationID,
			"credential_identifiers":      []string{identifier},
		})
	}
	return identifiers, details
}

func (p *Plugin) handlePreAuthorizedTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string, attestation clientAttestationAuth, attestationUsed bool, dpopJKT string) {
	preAuthorizedCode := strings.TrimSpace(r.FormValue("pre-authorized_code"))
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
	if record.TxCodeRequired && txCode == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "tx_code is required")
		return
	}
	if !record.TxCodeRequired && txCode != "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "tx_code was not expected")
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

	allowedCredentialIDs := make(map[string]struct{}, len(record.Offer.CredentialConfigurationIDs))
	for _, id := range record.Offer.CredentialConfigurationIDs {
		allowedCredentialIDs[id] = struct{}{}
	}
	requestedCredentialIDs, authorizationDetailsUsed, err := p.parseAuthorizationDetails(r.FormValue("authorization_details"))
	if err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if authorizationDetailsUsed {
		if err := validateCredentialConfigurationSubset(requestedCredentialIDs, allowedCredentialIDs); err != nil {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		allowedCredentialIDs = make(map[string]struct{}, len(requestedCredentialIDs))
		for _, configurationID := range requestedCredentialIDs {
			allowedCredentialIDs[configurationID] = struct{}{}
		}
	} else {
		requestedCredentialIDs = append([]string(nil), record.Offer.CredentialConfigurationIDs...)
	}
	p.mu.Lock()
	currentOfferID, stillAvailable := p.offersByPreAuthCode[preAuthorizedCode]
	currentRecord := p.offers[currentOfferID]
	if !stillAvailable || currentRecord == nil || currentRecord != record || currentRecord.Exchanged {
		p.mu.Unlock()
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "pre-authorized code has already been exchanged")
		return
	}
	currentRecord.Exchanged = true
	delete(p.offersByPreAuthCode, preAuthorizedCode)
	p.mu.Unlock()

	credentialIdentifiers, responseAuthorizationDetails := p.createCredentialAuthorization(requestedCredentialIDs, authorizationDetailsUsed)

	scope := "vc:issue"
	accessTokenClaims := map[string]interface{}{
		"offer_id":                     offerID,
		"credential_configuration_ids": requestedCredentialIDs,
	}
	if dpopJKT != "" {
		// RFC 9449 Section 4.1: bind the token to the presented proof key.
		accessTokenClaims = dpop.WithCnfJKT(accessTokenClaims, dpopJKT)
	}
	accessToken, err := p.mockIDP.JWTService().CreateAccessToken(
		"wallet:"+offerID,
		"oid4vci",
		scope,
		tokenTTL,
		accessTokenClaims,
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

	wallet, ok := p.getWalletByID(record.WalletID)
	if !ok {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "wallet context for offer is unavailable")
		return
	}

	p.mu.Lock()
	p.accessGrants[accessToken] = &accessGrant{
		Token:                      accessToken,
		Subject:                    wallet.Subject,
		WalletID:                   wallet.ID,
		CredentialConfigurationIDs: allowedCredentialIDs,
		CredentialIdentifiers:      credentialIdentifiers,
		AuthorizationDetailsUsed:   authorizationDetailsUsed,
		CNonce:                     nonce,
		CNonceUsed:                 false,
		OfferID:                    offerID,
		Deferred:                   record.Deferred,
		ExpiresAt:                  time.Now().UTC().Add(tokenTTL),
		JKT:                        dpopJKT,
	}
	p.mu.Unlock()

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   dpop.TokenType(dpopJKT),
		"expires_in":   int(tokenTTL.Seconds()),
		"scope":        scope,
	}
	if authorizationDetailsUsed {
		response["authorization_details"] = responseAuthorizationDetails
	}

	eventData := map[string]interface{}{
		"grant_type":             "pre-authorized_code",
		"offer_id":               offerID,
		"tx_code_required":       record.TxCodeRequired,
		"tx_code_supplied":       txCode != "",
		"credential_ids":         requestedCredentialIDs,
		"deferred":               record.Deferred,
		"wallet_id":              wallet.ID,
		"wallet_subject":         wallet.Subject,
		"c_nonce_expires_in":     int(nonceTTL.Seconds()),
		"access_token_expires":   int(tokenTTL.Seconds()),
		"access_token_issued_at": time.Now().UTC().Format(time.RFC3339),
	}
	if attestationUsed {
		eventData["client_attestation_client_id"] = attestation.ClientID
	}
	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Pre-Authorized Token Issued",
		eventData,
		p.vcAnnotation("c_nonce")...,
	)
	writeJSON(w, http.StatusOK, response)
}

func (p *Plugin) handleAuthorizationCodeTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string, attestation clientAttestationAuth, attestationUsed bool, dpopJKT string) {
	if p.mockIDP == nil {
		writeOID4VCIError(w, http.StatusServiceUnavailable, "server_error", "mock identity provider is unavailable")
		return
	}

	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	codeVerifier := strings.TrimSpace(r.FormValue("code_verifier"))
	if attestationUsed {
		// draft-ietf-oauth-attestation-based-client-auth-09 ?7: the Client
		// Attestation authenticates the Client Instance; its sub claim is the
		// authoritative client_id, so it takes precedence over (and must not
		// contradict) any client_id form parameter.
		if clientID == "" {
			clientID = attestation.ClientID
		} else if clientID != attestation.ClientID {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_client", "client_id does not match the authenticated client attestation subject")
			return
		}
		// Attestation alone authenticates the Client Instance. FAPI2
		// ensure-authorization-code-is-bound-to-client authenticates as the
		// second client without a prior PAR from that client; register it here
		// so the grant check can return invalid_grant (HTTP 400) instead of
		// treating a successfully attested client as unknown (HTTP 401).
		p.ensureAttestedWalletClient(clientID, redirectURI)
	} else if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	if code == "" || clientID == "" || redirectURI == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "code, client_id, and redirect_uri are required")
		return
	}
	tokenRequestedCredentialIDs, tokenAuthorizationDetailsUsed, err := p.parseAuthorizationDetails(r.FormValue("authorization_details"))
	if err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	client, exists := p.mockIDP.GetClient(clientID)
	if !exists {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if client.TokenEndpointAuthMethod == "attest_jwt_client_auth" && !attestationUsed {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "OAuth client attestation is required for this client")
		return
	}
	if !attestationUsed && !client.Public {
		// draft-ietf-oauth-attestation-based-client-auth-09 ?7: a validated
		// Client Attestation + PoP already authenticates the Client Instance,
		// replacing (not stacking with) client_secret authentication.
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
	if authCode.DPoPJKT != "" && dpopJKT != authCode.DPoPJKT {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "authorization code is bound to a different DPoP key")
		return
	}

	authorizedCredentialConfigurationIDs := authCode.CredentialConfigurationIDs
	if len(authorizedCredentialConfigurationIDs) == 0 {
		authorizedCredentialConfigurationIDs = sortedCredentialConfigurationIDs(p.credentialConfigurations)
	}
	if len(authorizedCredentialConfigurationIDs) == 0 {
		authorizedCredentialConfigurationIDs = []string{defaultCredentialConfigurationID}
	}
	authorizedCredentialConfigurations := make(map[string]struct{}, len(authorizedCredentialConfigurationIDs))
	for _, credentialConfigurationID := range authorizedCredentialConfigurationIDs {
		if _, supported := p.credentialConfigurations[credentialConfigurationID]; !supported {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "authorization code contains an unsupported credential_configuration_id")
			return
		}
		authorizedCredentialConfigurations[credentialConfigurationID] = struct{}{}
	}
	if tokenAuthorizationDetailsUsed {
		if err := validateCredentialConfigurationSubset(tokenRequestedCredentialIDs, authorizedCredentialConfigurations); err != nil {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		authorizedCredentialConfigurationIDs = tokenRequestedCredentialIDs
		authorizedCredentialConfigurations = make(map[string]struct{}, len(tokenRequestedCredentialIDs))
		for _, credentialConfigurationID := range tokenRequestedCredentialIDs {
			authorizedCredentialConfigurations[credentialConfigurationID] = struct{}{}
		}
	}
	authorizationDetailsUsed := authCode.CredentialAuthorizationDetailsUsed || tokenAuthorizationDetailsUsed
	credentialIdentifiers, responseAuthorizationDetails := p.createCredentialAuthorization(authorizedCredentialConfigurationIDs, authorizationDetailsUsed)

	scope := "vc:issue"
	accessTokenClaims := map[string]interface{}{
		"credential_configuration_ids": authorizedCredentialConfigurationIDs,
	}
	if dpopJKT != "" {
		accessTokenClaims = dpop.WithCnfJKT(accessTokenClaims, dpopJKT)
	}
	accessToken, err := p.mockIDP.JWTService().CreateAccessToken(
		authCode.UserID,
		"oid4vci",
		scope,
		tokenTTL,
		accessTokenClaims,
	)
	if err != nil {
		writeServerError(w, "issue access token", err)
		return
	}
	// RFC 6749 Section 4.1.2: if an authorization code is replayed, the
	// Authorization Server SHOULD revoke tokens previously issued from it.
	refreshToken, err := p.mockIDP.JWTService().CreateRefreshToken(
		authCode.UserID,
		clientID,
		scope,
		refreshTokenTTL,
	)
	if err != nil {
		writeServerError(w, "issue refresh token", err)
		return
	}
	p.mockIDP.StoreRefreshToken(refreshToken, clientID, authCode.UserID, scope, authCode.AuthTime, time.Now().Add(refreshTokenTTL))
	// RFC 9449 ?5: DPoP-bind refresh tokens only for public clients that are
	// not otherwise sender-constrained. Attestation-authenticated clients are
	// bound to the Client Instance Key (OAuth2-ATCA ?9.3); FAPI2 refresh
	// tests also rotate the DPoP proof key on refresh and expect success.
	if dpopJKT != "" && !attestationUsed {
		p.mockIDP.BindRefreshTokenKey(refreshToken, dpopJKT)
	}
	if attestationUsed && attestation.InstanceJKT != "" {
		// draft-ietf-oauth-attestation-based-client-auth ?9.3: bind to the
		// Client Instance Key, not merely the client_id.
		p.mockIDP.BindRefreshTokenClientInstanceKey(refreshToken, attestation.InstanceJKT)
	}
	p.mockIDP.RecordIssuedTokens(authCode.Code, accessToken, refreshToken)

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

	p.mu.Lock()
	p.accessGrants[accessToken] = &accessGrant{
		Token:                      accessToken,
		Subject:                    wallet.Subject,
		WalletID:                   wallet.ID,
		CredentialConfigurationIDs: authorizedCredentialConfigurations,
		CredentialIdentifiers:      credentialIdentifiers,
		AuthorizationDetailsUsed:   authorizationDetailsUsed,
		CNonce:                     nonce,
		CNonceUsed:                 false,
		OfferID:                    "authorization_code",
		IssuerState:                authCode.IssuerState,
		Deferred:                   false,
		ExpiresAt:                  time.Now().UTC().Add(tokenTTL),
		JKT:                        dpopJKT,
	}
	p.refreshGrants[refreshToken] = &refreshGrant{
		Subject:                    wallet.Subject,
		WalletID:                   wallet.ID,
		CredentialConfigurationIDs: cloneStringSet(authorizedCredentialConfigurations),
		CredentialIdentifiers:      cloneStringMap(credentialIdentifiers),
		AuthorizationDetailsUsed:   authorizationDetailsUsed,
		IssuerState:                authCode.IssuerState,
		Scope:                      scope,
		RequireDPoP:                dpopJKT != "",
	}
	p.mu.Unlock()

	issuerTransaction := p.updateIssuerInitiatedTransaction(authCode.IssuerState, issuerInitiatedStatusTokenIssued)
	effectiveSessionID := sessionID
	if effectiveSessionID == "" && issuerTransaction != nil {
		effectiveSessionID = issuerTransaction.SessionID
	}
	authEventData := map[string]interface{}{
		"grant_type":                           "authorization_code",
		"client_id":                            clientID,
		"user_id":                              authCode.UserID,
		"wallet_id":                            wallet.ID,
		"wallet_subject":                       wallet.Subject,
		"scope":                                scope,
		"c_nonce":                              nonce.Value,
		"expires_in":                           int(tokenTTL.Seconds()),
		"nonce_expires":                        int(nonceTTL.Seconds()),
		"client_authenticated_via_attestation": attestationUsed,
		"issuer_initiated":                     issuerTransaction != nil,
		"refresh_token_issued":                 true,
	}
	p.emitEvent(
		effectiveSessionID,
		lookingglass.EventTypeFlowStep,
		"Authorization Code Token Issued",
		authEventData,
		p.vcAnnotation("c_nonce")...,
	)

	response := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    dpop.TokenType(dpopJKT),
		"expires_in":    int(tokenTTL.Seconds()),
		"scope":         scope,
		"refresh_token": refreshToken,
	}
	if authorizationDetailsUsed {
		response["authorization_details"] = responseAuthorizationDetails
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *Plugin) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, sessionID string, attestation clientAttestationAuth, attestationUsed bool, dpopJKT string) {
	if p.mockIDP == nil {
		writeOID4VCIError(w, http.StatusServiceUnavailable, "server_error", "mock identity provider is unavailable")
		return
	}

	refreshToken := strings.TrimSpace(r.FormValue("refresh_token"))
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	scope := strings.TrimSpace(r.FormValue("scope"))
	if attestationUsed {
		if clientID == "" {
			clientID = attestation.ClientID
		} else if clientID != attestation.ClientID {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_client", "client_id does not match the authenticated client attestation subject")
			return
		}
		p.ensureAttestedWalletClient(clientID, "")
	} else if clientID == "" {
		clientID, clientSecret, _ = r.BasicAuth()
	}

	if refreshToken == "" || clientID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "refresh_token and client_id are required")
		return
	}

	client, exists := p.mockIDP.GetClient(clientID)
	if !exists {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	// RFC 6749 ?6 / FAPI2 SP: confidential and attestation-authenticated
	// clients MUST authenticate on refresh; omitting auth is rejected.
	if client.TokenEndpointAuthMethod == "attest_jwt_client_auth" && !attestationUsed {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "OAuth client attestation is required for this client")
		return
	}
	if !attestationUsed && !client.Public {
		if _, err := p.mockIDP.ValidateClient(clientID, clientSecret); err != nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	}

	rt, ok := p.mockIDP.GetRefreshToken(refreshToken)
	if !ok {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	if rt.ClientID != clientID {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "client ID mismatch")
		return
	}
	if rt.ExpiresAt.Before(time.Now()) {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}

	if rt.ClientInstanceJKT != "" {
		// draft-ietf-oauth-attestation-based-client-auth ?10.3: refresh MUST
		// use attestation with the same Client Instance Key as issuance.
		if !attestationUsed {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", "OAuth client attestation is required to redeem this refresh token")
			return
		}
		if attestation.InstanceJKT != rt.ClientInstanceJKT {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "refresh token is bound to a different client instance key")
			return
		}
	}
	if rt.JKT != "" && dpopJKT != rt.JKT {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "refresh token is bound to a different DPoP key")
		return
	}

	p.mu.RLock()
	priorGrant := p.refreshGrants[refreshToken]
	p.mu.RUnlock()
	if priorGrant == nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_grant", "refresh token grant context is unavailable")
		return
	}
	if scope == "" {
		scope = priorGrant.Scope
	}

	accessTokenClaims := map[string]interface{}{
		"credential_configuration_ids": sortedSetKeys(priorGrant.CredentialConfigurationIDs),
	}
	// Prefer the DPoP key presented on this refresh (FAPI2 rotates it). Only
	// fall back to the refresh-token binding when the token itself is DPoP-bound.
	boundJKT := dpopJKT
	if rt.JKT != "" {
		boundJKT = rt.JKT
	}
	if boundJKT != "" {
		accessTokenClaims = dpop.WithCnfJKT(accessTokenClaims, boundJKT)
	}
	accessToken, err := p.mockIDP.JWTService().CreateAccessToken(
		rt.UserID,
		"oid4vci",
		scope,
		tokenTTL,
		accessTokenClaims,
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
	p.mu.Lock()
	p.accessGrants[accessToken] = &accessGrant{
		Token:                      accessToken,
		Subject:                    priorGrant.Subject,
		WalletID:                   priorGrant.WalletID,
		CredentialConfigurationIDs: cloneStringSet(priorGrant.CredentialConfigurationIDs),
		CredentialIdentifiers:      cloneStringMap(priorGrant.CredentialIdentifiers),
		AuthorizationDetailsUsed:   priorGrant.AuthorizationDetailsUsed,
		CNonce:                     nonce,
		CNonceUsed:                 false,
		OfferID:                    "refresh_token",
		IssuerState:                priorGrant.IssuerState,
		Deferred:                   false,
		ExpiresAt:                  time.Now().UTC().Add(tokenTTL),
		JKT:                        boundJKT,
	}
	// FAPI2 SP Final ?5.3.2.1-9: do not rotate refresh tokens. Keep the same
	// refresh_token and grant context so the client can retry after a lost
	// access-token response.
	if scope != "" {
		priorGrant.Scope = scope
	}
	if boundJKT != "" {
		priorGrant.RequireDPoP = true
	}
	p.mu.Unlock()

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Refresh Token Redeemed", map[string]interface{}{
		"grant_type":                           "refresh_token",
		"client_id":                            clientID,
		"client_authenticated_via_attestation": attestationUsed,
		"dpop_bound":                           boundJKT != "",
		"refresh_token_rotated":                false,
	})

	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   dpop.TokenType(boundJKT),
		"expires_in":   int(tokenTTL.Seconds()),
		"scope":        scope,
		// Same refresh_token value (FAPI2 SP Final ?5.3.2.1-9: no rotation).
		"refresh_token": refreshToken,
	}
	if priorGrant.AuthorizationDetailsUsed {
		response["authorization_details"] = p.authorizationDetailsForIdentifiers(priorGrant.CredentialIdentifiers)
	}
	writeJSON(w, http.StatusOK, response)
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	if in == nil {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for key := range in {
		out[key] = struct{}{}
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func sortedSetKeys(in map[string]struct{}) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (p *Plugin) authorizationDetailsForIdentifiers(identifiers map[string]string) []map[string]interface{} {
	details := make([]map[string]interface{}, 0, len(identifiers))
	for credentialIdentifier, configurationID := range identifiers {
		details = append(details, map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": configurationID,
			"credential_identifiers":      []string{credentialIdentifier},
		})
	}
	return details
}

func (p *Plugin) handleNonce(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	now := time.Now().UTC()
	newNonce := p.randomValue(24)
	p.mu.Lock()
	p.credentialNonces[newNonce] = now.Add(nonceTTL)
	p.mu.Unlock()

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Credential Nonce Issued",
		map[string]interface{}{
			"new_nonce":          newNonce,
			"c_nonce_expires_in": int(nonceTTL.Seconds()),
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
	accessToken, grant, authErr := p.authorizeResourceRequest(r)
	if authErr != nil {
		authErr.respond(w)
		return
	}
	if sessionID == "" {
		sessionID = p.issuerInitiatedSessionID(grant.IssuerState)
	}
	var req credentialRequest
	if err := p.decodeCredentialRequest(r, &req); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", err.Error())
		return
	}
	req.CredentialConfigurationID = strings.TrimSpace(req.CredentialConfigurationID)
	req.CredentialIdentifier = strings.TrimSpace(req.CredentialIdentifier)
	if req.CredentialConfigurationID != "" && req.CredentialIdentifier != "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_identifier and credential_configuration_id are mutually exclusive")
		return
	}
	// OID4VCI 1.0 ?8.3.1.2 unknown_credential_configuration: when the wallet
	// presents credential_configuration_id, validate it against issuer metadata
	// before other Credential Request shape rules. An unknown configuration id
	// must yield unknown_credential_configuration even on tokens that returned
	// credential_identifiers (where credential_configuration_id MUST NOT be
	// used), rather than invalid_credential_request for the missing identifier.
	if req.CredentialConfigurationID != "" {
		if _, supported := p.credentialConfigurations[req.CredentialConfigurationID]; !supported {
			writeOID4VCIError(w, http.StatusBadRequest, "unknown_credential_configuration", "credential_configuration_id is not supported by issuer metadata")
			return
		}
	}
	// OID4VCI 1.0 ?8.3.1.2 unknown_credential_identifier takes precedence over a
	// generic invalid_credential_request when the Wallet presents a
	// credential_identifier that is not bound to this access token ? including
	// when the Token Response never returned credential_identifiers.
	if req.CredentialIdentifier != "" {
		configurationID, allowed := grant.CredentialIdentifiers[req.CredentialIdentifier]
		if !allowed {
			writeOID4VCIError(w, http.StatusBadRequest, "unknown_credential_identifier", "credential_identifier is unknown or is not bound to this access token")
			return
		}
		req.CredentialConfigurationID = configurationID
	} else if grant.AuthorizationDetailsUsed {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_identifier is required for this access token")
		return
	} else if req.CredentialConfigurationID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_configuration_id is required")
		return
	}
	credentialConfiguration, supported := p.credentialConfigurations[req.CredentialConfigurationID]
	if !supported {
		writeOID4VCIError(w, http.StatusBadRequest, "unknown_credential_configuration", "credential_configuration_id is not supported by issuer metadata")
		return
	}
	if _, allowed := grant.CredentialConfigurationIDs[req.CredentialConfigurationID]; !allowed {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "credential_configuration_id is not authorized")
		return
	}
	if req.CredentialResponseEncryption != nil {
		// OID4VCI 1.0 ?8.2/?10: the
		// wallet MAY request an encrypted response; encryption_required stays
		// false (credentialResponseEncryptionMetadata), so a missing object is
		// never rejected here.
		if err := req.CredentialResponseEncryption.validate(); err != nil {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_encryption_parameters", err.Error())
			return
		}
	}

	proofs, err := p.collectProofs(req)
	if err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", err.Error())
		return
	}
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

	proofDeclaredSubject := ""
	holderJWKs := make([]*crypto.JWK, 0, len(proofs))
	credentialNonce := ""
	seenHolderThumbprints := make(map[string]struct{}, len(proofs))
	for _, proof := range proofs {
		nonce, proofSub, proofKey, keyAttestationJWT, err := p.validateProofJWT(
			proof,
			p.issuerID(),
			grant.Subject,
			credentialConfiguration.ProofSigningAlgsSupported,
		)
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
		var holderJWK *crypto.JWK
		if strings.TrimSpace(proofKey.Kty) != "" {
			keyCopy := proofKey
			holderJWK = &keyCopy
			// OID4VCI 1.0 ?3.3.2: batch credentials SHOULD use different
			// cryptographic keys; reject duplicate proof keys so each issued
			// credential binds to a distinct key from the proofs array.
			thumbprint := keyCopy.Thumbprint()
			if thumbprint != "" {
				if _, duplicate := seenHolderThumbprints[thumbprint]; duplicate {
					writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", "batch Credential Request proofs must use distinct cryptographic keys")
					return
				}
				seenHolderThumbprints[thumbprint] = struct{}{}
			}
		}
		holderJWKs = append(holderJWKs, holderJWK)
		if credentialNonce == "" {
			credentialNonce = nonce
		} else if nonce != credentialNonce {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_nonce", "all proofs must use the same c_nonce")
			return
		}

		// OID4VCI 1.0 Appendix D.1/F.1 key_attestations_required (registry.go
		// RequireKeyAttestation): gated per credential_configuration_id so the
		// unattested Final plan keeps working while a HAIP-flavoured
		// configuration can demand it.
		if credentialConfiguration.RequireKeyAttestation {
			if err := ValidateKeyAttestationRequirement(true, keyAttestationJWT != ""); err != nil {
				writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", err.Error())
				return
			}
			attestation, err := p.validateKeyAttestationJWT(keyAttestationJWT, credentialNonce)
			if err != nil {
				p.emitEvent(
					sessionID,
					lookingglass.EventTypeSecurityWarning,
					"Credential Request Rejected",
					map[string]interface{}{
						"reason":        "key_attestation_invalid",
						"proof_message": err.Error(),
					},
					p.vcAnnotation("proof_validation")...,
				)
				writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", fmt.Sprintf("key_attestation: %v", err))
				return
			}
			if err := keyAttestationSatisfiesRequirement(attestation, proofKey, credentialConfiguration.KeyAttestationKeyStorage, credentialConfiguration.KeyAttestationUserAuth); err != nil {
				writeOID4VCIError(w, http.StatusBadRequest, "invalid_proof", fmt.Sprintf("key_attestation: %v", err))
				return
			}
		}
	}
	if !p.consumeCredentialNonce(grant, credentialNonce, time.Now().UTC()) {
		p.emitEvent(
			sessionID,
			lookingglass.EventTypeSecurityWarning,
			"Credential Request Rejected",
			map[string]interface{}{
				"reason":        "nonce_mismatch_replay_or_expired",
				"credential_id": req.CredentialConfigurationID,
				"proof_nonce":   credentialNonce,
			},
			p.vcAnnotation("c_nonce")...,
		)
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_nonce", "c_nonce is unknown, expired, or already consumed")
		return
	}

	effectiveSubject := grant.Subject
	if proofDeclaredSubject != "" {
		effectiveSubject = proofDeclaredSubject
	}

	wallet, ok := p.getWalletByID(grant.WalletID)
	if !ok {
		writeServerError(w, "resolve wallet identity", fmt.Errorf("wallet identity %q is unavailable", grant.WalletID))
		return
	}

	if p.walletStore == nil {
		writeServerError(w, "persist credential lineage", fmt.Errorf("wallet credential store is unavailable"))
		return
	}

	// OID4VCI 1.0 ?3.3.2 / ?8: one Credential per proof, same Credential
	// Dataset and Format, distinct Cryptographic Data (per-proof key binding).
	// Response MUST NOT contain more credentials than proofs submitted.
	issuedArtifacts := make([]deferredCredentialArtifact, 0, len(holderJWKs))
	credentialEntries := make([]map[string]interface{}, 0, len(holderJWKs))
	credentialIDs := make([]string, 0, len(holderJWKs))
	issuedFormat := ""
	for _, holderJWK := range holderJWKs {
		issuedCredential, err := p.issueCredential(effectiveSubject, req.CredentialConfigurationID, wallet, holderJWK)
		if err != nil {
			writeServerError(w, "issue credential", err)
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
		issuedCredentialID := strings.TrimSpace(issuedCredential.CredentialID)
		if issuedCredentialID == "" {
			issuedCredentialID = p.randomValue(24)
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
			CredentialID:              issuedCredentialID,
			Issuer:                    issuerID,
			IssuerJWK:                 issuerJWK,
			IssuedAt:                  time.Now().UTC(),
		}) {
			writeServerError(w, "persist credential lineage", fmt.Errorf("failed to persist issued credential in wallet store"))
			return
		}
		issuedArtifacts = append(issuedArtifacts, deferredCredentialArtifact{
			Credential:   issuedCredential.Credential,
			CredentialID: issuedCredentialID,
		})
		credentialEntries = append(credentialEntries, map[string]interface{}{
			"credential": issuedCredential.Credential,
		})
		credentialIDs = append(credentialIDs, issuedCredentialID)
		issuedFormat = issuedCredential.Format
	}
	p.updateIssuerInitiatedTransaction(grant.IssuerState, issuerInitiatedStatusCredentialIssued)

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
				Format:                    issuedFormat,
				AccessTokenID:             accessToken,
				Deferred:                  true,
				Status:                    "pending",
				CreatedAt:                 now,
				UpdatedAt:                 now,
			},
			Subject:     grant.Subject,
			ReadyAt:     now.Add(deferredReadyDelay),
			Credentials: issuedArtifacts,
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
				"credentials_prepared":          len(issuedArtifacts),
				"credential_request_deferred":   true,
				"credential_response_immediate": false,
			},
			p.vcAnnotation("proof_validation")...,
		)

		if err := writeCredentialResponse(w, http.StatusAccepted, map[string]interface{}{
			"transaction_id": transactionID,
			"interval":       deferredRetryAfterSeconds,
		}, req.CredentialResponseEncryption); err != nil {
			writeServerError(w, "encrypt credential response", err)
		}
		return
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeTokenIssued,
		"Credential Issued",
		map[string]interface{}{
			"credential_configuration_id": req.CredentialConfigurationID,
			"format":                      issuedFormat,
			"proofs_submitted":            len(proofs),
			"credentials_issued":          len(credentialEntries),
		},
		p.vcAnnotation("credential_endpoint")...,
	)

	notificationID := p.createNotificationRecord(
		accessToken,
		req.CredentialConfigurationID,
		credentialIDs,
		grant.ExpiresAt,
	)
	if err := writeCredentialResponse(w, http.StatusOK, map[string]interface{}{
		"credentials":     credentialEntries,
		"notification_id": notificationID,
	}, req.CredentialResponseEncryption); err != nil {
		writeServerError(w, "encrypt credential response", err)
	}
}

func (p *Plugin) handleDeferredCredential(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	accessToken, grant, authErr := p.authorizeResourceRequest(r)
	if authErr != nil {
		authErr.respond(w)
		return
	}
	var req deferredCredentialRequest
	if err := p.decodeJSONOrEncryptedJWTRequest(r, &req, "deferred credential request"); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", err.Error())
		return
	}
	req.TransactionID = strings.TrimSpace(req.TransactionID)
	if req.TransactionID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_credential_request", "transaction_id is required")
		return
	}
	if req.CredentialResponseEncryption != nil {
		// OID4VCI 1.0 ?9.1: the Deferred Credential Request's own encryption
		// parameters govern the Deferred Credential Response, independent of
		// what (if anything) was sent on the original Credential Request.
		if err := req.CredentialResponseEncryption.validate(); err != nil {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_encryption_parameters", err.Error())
			return
		}
	}

	now := time.Now().UTC()
	p.mu.Lock()
	transaction, ok := p.issuanceTransactions[req.TransactionID]
	if !ok {
		p.mu.Unlock()
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_transaction_id", "transaction_id not found")
		return
	}
	if transaction.Model.AccessTokenID != accessToken {
		p.mu.Unlock()
		writeOID4VCIError(w, http.StatusForbidden, "invalid_token", "transaction does not belong to access token")
		return
	}
	if now.Before(transaction.ReadyAt) {
		readyAt := transaction.ReadyAt
		transactionFormat := transaction.Model.Format
		p.mu.Unlock()
		retryAfterSeconds := int(math.Ceil(readyAt.Sub(now).Seconds()))
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
				"ready_at":            readyAt.Format(time.RFC3339),
				"format":              transactionFormat,
			},
			p.vcAnnotation("deferred_credential")...,
		)

		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"transaction_id": req.TransactionID,
			"interval":       retryAfterSeconds,
		})
		return
	}

	// OID4VCI 1.0 Final Section 9.1 requires transaction_id invalidation after
	// the Credential is obtained. Removal occurs while holding the same lock as
	// the readiness and token-lineage checks, so concurrent polls cannot both
	// obtain the Credential.
	delete(p.issuanceTransactions, req.TransactionID)
	transaction.Model.Status = "issued"
	transaction.Model.UpdatedAt = now
	p.mu.Unlock()

	nextNonce := models.VCNonce{
		Value:     p.randomValue(24),
		IssuedAt:  now,
		ExpiresAt: now.Add(nonceTTL),
	}

	p.mu.Lock()
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

	deferredCredentialIDs := make([]string, 0, len(transaction.Credentials))
	deferredCredentialEntries := make([]map[string]interface{}, 0, len(transaction.Credentials))
	for _, artifact := range transaction.Credentials {
		deferredCredentialIDs = append(deferredCredentialIDs, artifact.CredentialID)
		deferredCredentialEntries = append(deferredCredentialEntries, map[string]interface{}{
			"credential": artifact.Credential,
		})
	}
	notificationID := p.createNotificationRecord(
		accessToken,
		transaction.Model.CredentialConfigurationID,
		deferredCredentialIDs,
		grant.ExpiresAt,
	)
	if err := writeCredentialResponse(w, http.StatusOK, map[string]interface{}{
		"credentials":     deferredCredentialEntries,
		"notification_id": notificationID,
	}, req.CredentialResponseEncryption); err != nil {
		writeServerError(w, "encrypt deferred credential response", err)
	}
}

func (p *Plugin) createNotificationRecord(accessToken, credentialConfigurationID string, credentialIDs []string, expiresAt time.Time) string {
	notificationID := p.randomValue(32)
	now := time.Now().UTC()
	p.mu.Lock()
	p.notifications[notificationID] = &notificationRecord{
		ID:                        notificationID,
		AccessToken:               accessToken,
		CredentialConfigurationID: credentialConfigurationID,
		CredentialIDs:             append([]string(nil), credentialIDs...),
		Events:                    make([]notificationEvent, 0, 1),
		EventKeys:                 make(map[string]struct{}),
		CreatedAt:                 now,
		UpdatedAt:                 now,
		ExpiresAt:                 expiresAt,
	}
	p.mu.Unlock()
	return notificationID
}

func validNotificationEventDescription(value string) bool {
	for _, character := range value {
		if character < 0x20 || character > 0x7e || character == 0x22 || character == 0x5c {
			return false
		}
	}
	return true
}

func decodeNotificationRequest(body io.Reader) (notificationRequest, error) {
	decoder := json.NewDecoder(body)
	start, err := decoder.Token()
	if err != nil {
		return notificationRequest{}, fmt.Errorf("invalid JSON body: %w", err)
	}
	if delimiter, ok := start.(json.Delim); !ok || delimiter != '{' {
		return notificationRequest{}, fmt.Errorf("notification request must be a JSON object")
	}

	var req notificationRequest
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return notificationRequest{}, fmt.Errorf("invalid JSON body: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return notificationRequest{}, fmt.Errorf("notification request contains a non-string member name")
		}
		if _, duplicate := seen[key]; duplicate {
			return notificationRequest{}, fmt.Errorf("notification request repeats parameter %q", key)
		}
		seen[key] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return notificationRequest{}, fmt.Errorf("invalid JSON body: %w", err)
		}
		switch key {
		case "notification_id":
			if err := json.Unmarshal(value, &req.NotificationID); err != nil {
				return notificationRequest{}, fmt.Errorf("notification_id must be a string")
			}
		case "event":
			if err := json.Unmarshal(value, &req.Event); err != nil {
				return notificationRequest{}, fmt.Errorf("event must be a string")
			}
		case "event_description":
			if err := json.Unmarshal(value, &req.EventDescription); err != nil {
				return notificationRequest{}, fmt.Errorf("event_description must be a string")
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return notificationRequest{}, fmt.Errorf("invalid JSON body: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return notificationRequest{}, fmt.Errorf("notification request must contain exactly one JSON object")
	}
	return req, nil
}

func decodeRequestObject(body io.Reader, target interface{}, requestName string) error {
	decoder := json.NewDecoder(body)
	start, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if delimiter, ok := start.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s must be a JSON object", requestName)
	}

	members := make(map[string]json.RawMessage)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON body: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("%s contains a non-string member name", requestName)
		}
		if _, duplicate := members[key]; duplicate {
			return fmt.Errorf("%s repeats parameter %q", requestName, key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("invalid JSON body: %w", err)
		}
		members[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("%s must contain exactly one JSON object", requestName)
	}
	encoded, err := json.Marshal(members)
	if err != nil {
		return fmt.Errorf("encode %s: %w", requestName, err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("invalid %s: %w", requestName, err)
	}
	return nil
}

func (p *Plugin) handleNotification(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	accessToken, _, authErr := p.authorizeResourceRequest(r)
	if authErr != nil {
		authErr.respond(w)
		return
	}
	if !requestHasMediaType(r, "application/json") {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_notification_request", "Content-Type must be application/json")
		return
	}

	req, err := decodeNotificationRequest(r.Body)
	if err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_notification_request", err.Error())
		return
	}
	req.NotificationID = strings.TrimSpace(req.NotificationID)
	if req.NotificationID == "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_notification_request", "notification_id is required")
		return
	}
	switch req.Event {
	case "credential_accepted", "credential_failure", "credential_deleted":
	default:
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_notification_request", "event must be credential_accepted, credential_failure, or credential_deleted")
		return
	}
	if !validNotificationEventDescription(req.EventDescription) {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_notification_request", "event_description contains characters outside the allowed US-ASCII set")
		return
	}

	eventKey := req.Event + "\x00" + req.EventDescription
	now := time.Now().UTC()
	p.mu.Lock()
	record, exists := p.notifications[req.NotificationID]
	if !exists || record.AccessToken != accessToken {
		p.mu.Unlock()
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_notification_id", "notification_id is invalid for this access token")
		return
	}
	_, idempotentRetry := record.EventKeys[eventKey]
	if !idempotentRetry {
		if !notificationTransitionAllowed(record.State, req.Event) {
			currentState := record.State
			p.mu.Unlock()
			writeOID4VCIError(
				w,
				http.StatusBadRequest,
				"invalid_notification_request",
				fmt.Sprintf("event %q conflicts with notification state %q", req.Event, currentState),
			)
			return
		}
		record.EventKeys[eventKey] = struct{}{}
		record.Events = append(record.Events, notificationEvent{
			Event:            req.Event,
			EventDescription: req.EventDescription,
			ReceivedAt:       now,
		})
		record.State = req.Event
		record.UpdatedAt = now
	}
	credentialConfigurationID := record.CredentialConfigurationID
	credentialIDs := append([]string(nil), record.CredentialIDs...)
	p.mu.Unlock()

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"Credential Status Notification Received",
		map[string]interface{}{
			"notification_id":             req.NotificationID,
			"event":                       req.Event,
			"event_description":           req.EventDescription,
			"credential_configuration_id": credentialConfigurationID,
			"credential_ids":              credentialIDs,
			"idempotent_retry":            idempotentRetry,
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeRFCReference,
			Title:       "OID4VCI Credential Notification",
			Description: "The wallet reported the outcome of storing the issued Credential, and the issuer mutated the notification state associated with the issuing access grant.",
			Reference:   "OpenID for Verifiable Credential Issuance 1.0 Final Section 11",
		},
	)
	w.WriteHeader(http.StatusNoContent)
}

func (p *Plugin) normalizeCredentialConfigurationIDs(rawIDs []string) []string {
	return normalizeCredentialConfigurationIDs(rawIDs, p.credentialConfigurations)
}

func (p *Plugin) consumeCredentialNonce(grant *accessGrant, nonce string, now time.Time) bool {
	if grant == nil || strings.TrimSpace(nonce) == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if expiry, ok := p.credentialNonces[nonce]; ok {
		delete(p.credentialNonces, nonce)
		return !now.After(expiry)
	}
	if grant.CNonceUsed ||
		nonce != grant.CNonce.Value ||
		now.After(grant.CNonce.ExpiresAt) {
		return false
	}
	grant.CNonceUsed = true
	return true
}

func (p *Plugin) collectProofs(req credentialRequest) ([]credentialProof, error) {
	if len(req.Proofs) == 0 {
		return nil, nil
	}
	var proofSets map[string][]string
	if err := json.Unmarshal(req.Proofs, &proofSets); err != nil || proofSets == nil {
		return nil, fmt.Errorf("proofs must be an object keyed by proof type")
	}
	if len(proofSets) != 1 {
		return nil, fmt.Errorf("proofs must contain exactly one proof type")
	}
	for proofType, values := range proofSets {
		if strings.TrimSpace(proofType) != "jwt" {
			return nil, fmt.Errorf("unsupported proof type %q", proofType)
		}
		if len(values) == 0 {
			return nil, fmt.Errorf("proofs.jwt must be a non-empty array")
		}
		// OID4VCI 1.0 ?11.2.3: when batch_credential_issuance is advertised,
		// batch_size is the maximum proofs array length in one request.
		if len(values) > batchCredentialIssuanceBatchSize {
			return nil, fmt.Errorf(
				"proofs.jwt length %d exceeds batch_credential_issuance.batch_size %d",
				len(values),
				batchCredentialIssuanceBatchSize,
			)
		}
		proofs := make([]credentialProof, 0, len(values))
		for _, value := range values {
			proofs = append(proofs, credentialProof{
				ProofType: "jwt",
				JWT:       value,
			})
		}
		return proofs, nil
	}
	return nil, nil
}

// validateProofJWT validates an OID4VCI 1.0 ?7 proof JWT and returns its
// nonce, optional issuer subject, JOSE-header holder key, and (if present) the raw
// key_attestation JOSE header value (Appendix F.1) for the caller to validate
// separately against a credential configuration's key_attestations_required
// (registry.go, key_attestation.go).
func (p *Plugin) validateProofJWT(proof credentialProof, expectedAudience string, expectedSubject string, supportedAlgorithms []string) (nonce string, subject string, holderJWK crypto.JWK, keyAttestationJWT string, err error) {
	emptyJWK := crypto.JWK{}
	if strings.TrimSpace(proof.JWT) == "" {
		return "", "", emptyJWK, "", fmt.Errorf("proof jwt is required")
	}
	if strings.TrimSpace(strings.ToLower(proof.ProofType)) != "jwt" {
		return "", "", emptyJWK, "", fmt.Errorf("unsupported proof_type %q", proof.ProofType)
	}

	decodedToken, err := crypto.DecodeTokenWithoutValidation(proof.JWT)
	if err != nil {
		return "", "", emptyJWK, "", fmt.Errorf("proof jwt decode failed: %w", err)
	}
	if err := ValidateOID4VCIProofType(fmt.Sprint(decodedToken.Header["typ"])); err != nil {
		return "", "", emptyJWK, "", err
	}
	keyAttestationHeader, _ := decodedToken.Header["key_attestation"].(string)
	iss, _ := decodedToken.Payload["iss"].(string)
	proofSubject := strings.TrimSpace(iss)

	if strings.HasPrefix(expectedSubject, "did:example:") &&
		strings.HasPrefix(proofSubject, "did:example:") &&
		proofSubject != expectedSubject {
		return "", "", emptyJWK, "", fmt.Errorf("proof subject %q does not match grant subject %q", proofSubject, expectedSubject)
	}

	verificationKey, expectedAlgPrefix, proofJWK, err := proofVerificationKeyFromHeader(decodedToken.Header)
	if err != nil {
		return "", "", emptyJWK, "", err
	}
	parsed, err := jwt.Parse(proof.JWT, func(token *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(token.Method.Alg(), expectedAlgPrefix) {
			return nil, fmt.Errorf("proof jwt uses unexpected algorithm")
		}
		if !stringSliceContains(supportedAlgorithms, token.Method.Alg()) {
			return nil, fmt.Errorf("proof jwt algorithm %q is not supported for this Credential Configuration", token.Method.Alg())
		}
		if jwkAlg := strings.TrimSpace(proofJWK.Alg); jwkAlg != "" && jwkAlg != token.Method.Alg() {
			return nil, fmt.Errorf("proof jwk alg does not match proof jwt alg")
		}
		kid, _ := token.Header["kid"].(string)
		if strings.TrimSpace(proofJWK.Kid) != "" && strings.TrimSpace(kid) != "" && strings.TrimSpace(proofJWK.Kid) != strings.TrimSpace(kid) {
			return nil, fmt.Errorf("proof kid does not match jwk kid")
		}
		return verificationKey, nil
	})
	if err != nil {
		return "", "", emptyJWK, "", fmt.Errorf("invalid proof jwt: %w", err)
	}
	if !parsed.Valid {
		return "", "", emptyJWK, "", fmt.Errorf("proof jwt failed signature validation")
	}
	if err := ValidateOID4VCIProofType(fmt.Sprint(parsed.Header["typ"])); err != nil {
		return "", "", emptyJWK, "", err
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", emptyJWK, "", fmt.Errorf("proof claims are invalid")
	}
	if err := validateAudienceClaim(claims["aud"], expectedAudience); err != nil {
		return "", "", emptyJWK, "", err
	}
	iatUnix, err := numericDateToInt64(claims["iat"])
	if err != nil {
		return "", "", emptyJWK, "", fmt.Errorf("proof iat claim is invalid")
	}
	now := time.Now().UTC().Unix()
	if rawExp, exists := claims["exp"]; exists {
		expUnix, expErr := numericDateToInt64(rawExp)
		if expErr != nil {
			return "", "", emptyJWK, "", fmt.Errorf("proof exp claim is invalid")
		}
		if now >= expUnix {
			return "", "", emptyJWK, "", fmt.Errorf("proof is expired")
		}
	}
	if iatUnix > now+60 {
		return "", "", emptyJWK, "", fmt.Errorf("proof iat is in the future")
	}
	nonceValue, _ := claims["nonce"].(string)
	if strings.TrimSpace(nonceValue) == "" {
		return "", "", emptyJWK, "", fmt.Errorf("proof nonce is required")
	}
	return nonceValue, proofSubject, proofJWK, strings.TrimSpace(keyAttestationHeader), nil
}

func proofVerificationKeyFromHeader(header map[string]interface{}) (interface{}, string, crypto.JWK, error) {
	_, hasKID := header["kid"]
	jwkRaw, hasJWK := header["jwk"]
	_, hasX5C := header["x5c"]
	keyReferences := 0
	for _, present := range []bool{hasKID, hasJWK, hasX5C} {
		if present {
			keyReferences++
		}
	}
	if keyReferences != 1 {
		return nil, "", crypto.JWK{}, fmt.Errorf("proof JOSE header must contain exactly one of kid, jwk, or x5c")
	}
	if !hasJWK {
		return nil, "", crypto.JWK{}, fmt.Errorf("proof JOSE key reference is not supported; use jwk")
	}
	jwk, err := parseProofJWK(jwkRaw)
	if err != nil {
		return nil, "", crypto.JWK{}, err
	}
	key, algPrefix, err := verificationKeyFromJWK(jwk)
	if err != nil {
		return nil, "", crypto.JWK{}, fmt.Errorf("proof jwk: %w", err)
	}
	return key, algPrefix, jwk, nil
}

func parseProofJWK(raw interface{}) (crypto.JWK, error) {
	jwkBytes, err := json.Marshal(raw)
	if err != nil {
		return crypto.JWK{}, fmt.Errorf("proof jwk is invalid JSON: %w", err)
	}
	var jwk crypto.JWK
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return crypto.JWK{}, fmt.Errorf("proof jwk parse failed: %w", err)
	}
	if strings.TrimSpace(jwk.Kty) == "" {
		return crypto.JWK{}, fmt.Errorf("proof jwk kty is required")
	}
	if strings.TrimSpace(jwk.D) != "" ||
		strings.TrimSpace(jwk.P) != "" ||
		strings.TrimSpace(jwk.Q) != "" ||
		strings.TrimSpace(jwk.DP) != "" ||
		strings.TrimSpace(jwk.DQ) != "" ||
		strings.TrimSpace(jwk.QI) != "" ||
		len(jwk.Oth) != 0 ||
		strings.TrimSpace(jwk.K) != "" {
		return crypto.JWK{}, fmt.Errorf("proof jwk must not contain private key material")
	}
	if use := strings.TrimSpace(jwk.Use); use != "" && use != "sig" {
		return crypto.JWK{}, fmt.Errorf("proof jwk use must be sig when present")
	}
	for _, operation := range jwk.KeyOps {
		if strings.TrimSpace(operation) != "verify" {
			return crypto.JWK{}, fmt.Errorf("proof jwk key_ops must contain only verify")
		}
	}
	return jwk, nil
}

func notificationTransitionAllowed(currentState, nextEvent string) bool {
	switch currentState {
	case "":
		return true
	case "credential_accepted":
		return nextEvent == "credential_accepted" || nextEvent == "credential_deleted"
	case "credential_failure":
		return nextEvent == "credential_failure"
	case "credential_deleted":
		return nextEvent == "credential_deleted"
	default:
		return false
	}
}

func stringSliceContains(values []string, expected string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == expected {
			return true
		}
	}
	return false
}

func requestHasMediaType(r *http.Request, expected string) bool {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, expected)
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
	return decodeJSONValue(decoder, target)
}

func decodeJSONValue(decoder *json.Decoder, target interface{}) error {
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
