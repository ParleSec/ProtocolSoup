package main

import (
	"fmt"
	"net/http"
	"strings"
)

// Credential refresh (OpenID4VCI 1.0 Section 14.5): "If the Credential Issuer
// issued a Refresh Token to the Wallet, the Wallet would obtain a fresh Access
// Token by making a request to the Token Endpoint, as defined in Section 6 of
// [RFC6749]", and receive an updated Credential "from a Credential Endpoint
// using a valid Access Token. This does not involve interaction with the
// End-User."

// credentialRefresh is what the wallet keeps from an issuance whose Token
// Response carried a refresh_token, so it can later request the Credential
// again without the End-User.
type credentialRefresh struct {
	RefreshToken string
	// ClientID and ClientSecret repeat the client authentication of the
	// original grant: RFC 6749 Section 6 requires a client that authenticated
	// to authenticate again on refresh.
	ClientID                    string
	ClientSecret                string
	IssuerMetadata              *resolvedExternalIssuerMetadata
	AuthorizationServerMetadata *resolvedAuthorizationServerMetadata
	ConfigurationID             string
	CredentialFormat            string
	JWTProofRequired            bool
	// HAIPSession holds the DPoP key a DPoP-bound refresh_token must be
	// presented with (RFC 9449 Section 5) and the client attestation instance
	// key, so refresh repeats the original attested, DPoP-bound client.
	HAIPSession   *haipIssuanceSession
	WalletBaseURL string
}

// newCredentialRefresh keeps the refresh context of an issuance whose Token
// Response carried a refresh_token; it returns nil when there was none.
func (s *walletHarnessServer) newCredentialRefresh(
	tokenPayload map[string]interface{},
	issuerMetadata *resolvedExternalIssuerMetadata,
	authorizationServerMetadata *resolvedAuthorizationServerMetadata,
	configurationID string,
	credentialFormat string,
	jwtProofRequired bool,
	haipSession *haipIssuanceSession,
	walletBaseURL string,
) *credentialRefresh {
	refreshToken, _ := tokenPayload["refresh_token"].(string)
	if strings.TrimSpace(refreshToken) == "" || authorizationServerMetadata == nil {
		return nil
	}
	refresh := &credentialRefresh{
		RefreshToken:                refreshToken,
		IssuerMetadata:              issuerMetadata,
		AuthorizationServerMetadata: authorizationServerMetadata,
		ConfigurationID:             configurationID,
		CredentialFormat:            credentialFormat,
		JWTProofRequired:            jwtProofRequired,
		HAIPSession:                 haipSession,
		WalletBaseURL:               walletBaseURL,
	}
	if haipSession != nil {
		refresh.ClientID = strings.TrimSpace(s.haipAttestedClientID)
	}
	return refresh
}

// rememberCredentialRefresh files refresh under the wallet's active
// credential, which the import that produced it has just bound.
func rememberCredentialRefresh(wallet *walletMaterial, refresh *credentialRefresh) {
	if wallet == nil || refresh == nil || strings.TrimSpace(wallet.CredentialID) == "" {
		return
	}
	if wallet.Refresh == nil {
		wallet.Refresh = make(map[string]*credentialRefresh)
	}
	wallet.Refresh[wallet.CredentialID] = refresh
}

type apiRefreshRequest struct {
	WalletSubject         string `json:"wallet_subject,omitempty"`
	CredentialID          string `json:"credential_id,omitempty"`
	LookingGlassSessionID string `json:"looking_glass_session_id,omitempty"`
}

// handleAPIRefresh refreshes a held Credential with its Refresh Token: a
// refresh_token grant at the Token Endpoint, then a Credential Request with
// the fresh Access Token. The updated Credential replaces the old one, so the
// wallet does not keep two of the same type without knowing which is latest.
func (s *walletHarnessServer) handleAPIRefresh(w http.ResponseWriter, r *http.Request) {
	r, respond := recordProtocolExchanges(w, r)
	if r.Method != http.MethodPost {
		respond(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req apiRefreshRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respond(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	scopeKey, _, err := s.resolveAPIScopeKey(w, r)
	if err != nil {
		respond(http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	subject := firstNonEmpty(req.WalletSubject, scopedWalletSubject(s.defaultWalletSubject, scopeKey))
	wallet, err := s.getOrCreateWallet(scopeKey, subject, requestBaseURL(r))
	if err != nil {
		respond(http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": err.Error()})
		return
	}
	previousCredentialID := firstNonEmpty(req.CredentialID, wallet.CredentialID)
	refresh := wallet.Refresh[previousCredentialID]
	if refresh == nil {
		respond(http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
			"error_description": fmt.Sprintf(
				"the wallet holds no Refresh Token for credential %q; OpenID4VCI 1.0 Section 14.5: without one the Credential is reissued by starting issuance from the beginning",
				previousCredentialID,
			),
		})
		return
	}

	tokenPayload, err := s.exchangeRefreshToken(r.Context(), refresh, req.LookingGlassSessionID)
	if err != nil {
		respond(http.StatusBadRequest, map[string]string{"error": "wallet_refresh_failed", "error_description": err.Error()})
		return
	}
	// RFC 6749 Section 6: when a new refresh token is issued, "the client
	// MUST discard the old refresh token and replace it with the new refresh
	// token".
	rotated := false
	if next, _ := tokenPayload["refresh_token"].(string); next != "" && next != refresh.RefreshToken {
		refresh.RefreshToken = next
		rotated = true
	}

	importResult, err := s.completeExternalCredentialImport(
		r.Context(),
		wallet,
		externalIssuerImportRequest{
			CredentialFormat:      refresh.CredentialFormat,
			CredentialConfigID:    refresh.ConfigurationID,
			LookingGlassSessionID: req.LookingGlassSessionID,
			WalletBaseURL:         refresh.WalletBaseURL,
		},
		nil,
		refresh.IssuerMetadata,
		refresh.AuthorizationServerMetadata,
		refresh.ConfigurationID,
		refresh.CredentialFormat,
		refresh.JWTProofRequired,
		tokenPayload,
		nil,
		refresh.HAIPSession,
	)
	if err != nil {
		respond(http.StatusBadRequest, map[string]string{"error": "wallet_refresh_failed", "error_description": err.Error()})
		return
	}
	if importResult == nil || importResult.IssuedCredential == nil {
		respond(http.StatusBadRequest, map[string]string{"error": "wallet_refresh_failed", "error_description": "credential issuer did not return a credential"})
		return
	}
	if err := s.bindCredential(
		wallet,
		importResult.IssuedCredential.CredentialJWT,
		importResult.IssuedCredential.CredentialConfigID,
		importResult.IssuedCredential.CredentialFormat,
	); err != nil {
		respond(http.StatusBadRequest, map[string]string{"error": "invalid_credential", "error_description": err.Error()})
		return
	}
	if wallet.CredentialID != previousCredentialID {
		delete(wallet.Credentials, previousCredentialID)
		delete(wallet.Refresh, previousCredentialID)
	}
	rememberCredentialRefresh(wallet, refresh)
	notificationErr := s.notifyCredentialAccepted(r.Context(), importResult.IssuedCredential, req.LookingGlassSessionID)
	response := map[string]interface{}{
		"wallet_subject":              wallet.Subject,
		"wallet_scope":                wallet.ScopeKey,
		"previous_credential_id":      previousCredentialID,
		"credential_id":               wallet.CredentialID,
		"credential_format":           wallet.CredentialFormat,
		"credential_configuration_id": wallet.CredentialConfigurationID,
		"credential_jwt":              wallet.CredentialJWT,
		"credential_summary":          summarizeCredential(wallet.CredentialJWT),
		"refresh_token_rotated":       rotated,
	}
	if notificationErr != nil {
		response["notification_error"] = notificationErr.Error()
	}
	respond(http.StatusOK, response)
}
