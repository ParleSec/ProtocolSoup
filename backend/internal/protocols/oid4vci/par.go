package oid4vci

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

const pushedAuthorizationRequestTTL = 90 * time.Second

func (p *Plugin) pushedAuthorizationRequestEndpointURL() string {
	return p.issuerID() + "/par"
}

// handlePushedAuthorizationRequest implements the HAIP authorization server's
// RFC 9126 PAR endpoint. Requests are authenticated with OAuth client
// attestation. Authorization-code DPoP binding may be established via a DPoP
// proof header, the dpop_jkt form parameter (RFC 9449 Section 10.1), or both
// when the thumbprints agree. HAIP wallets that introduce DPoP only at the
// token endpoint remain supported.
func (p *Plugin) handlePushedAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "PAR requests must use application/x-www-form-urlencoded")
		return
	}
	if p.mockIDP == nil {
		writeOID4VCIError(w, http.StatusServiceUnavailable, "server_error", "authorization server state is unavailable")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}

	attestation, attempted, err := p.authenticateClientAttestation(r)
	if err != nil || !attempted {
		if err == nil {
			err = errors.New("OAuth client attestation is required")
		}
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	if clientID == "" || clientID != attestation.ClientID {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "client_id must match the client attestation subject")
		return
	}

	// RFC 9126 Section 2.1: after client authentication, reject the request if
	// the request_uri authorization request parameter is provided. PAR creates
	// request_uri values; it must not accept them as input.
	if strings.TrimSpace(r.Form.Get("request_uri")) != "" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "request_uri must not be provided to the PAR endpoint (RFC 9126 Section 2.1)")
		return
	}

	dpopResult, err := p.validateAuthorizationServerDPoP(r, p.pushedAuthorizationRequestEndpointURL())
	if err != nil {
		var nonceErr *dpop.NonceRequiredError
		if errors.As(err, &nonceErr) {
			w.Header().Set(dpop.NonceHeaderName, nonceErr.Nonce)
			writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorUseDPoPNonce, "a fresh DPoP proof nonce is required")
			return
		}
		var infrastructureErr *dpop.InfrastructureError
		if errors.As(err, &infrastructureErr) {
			writeOID4VCIError(w, http.StatusInternalServerError, "server_error", "DPoP validation is temporarily unavailable")
			return
		}
		writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorInvalidDPoPProof, err.Error())
		return
	}
	if commitErr := p.commitClientAttestationPoP(attestation); commitErr != nil {
		writeOID4VCIError(w, http.StatusUnauthorized, "invalid_client", commitErr.Error())
		return
	}
	// RFC 9449 Section 10.1: PAR may bind via dpop_jkt, the DPoP header, or
	// both. When both are present the thumbprints MUST agree; otherwise the
	// request is rejected. Either mechanism alone is sufficient to bind the
	// authorization code to that key.
	submittedDPoPJKT := strings.TrimSpace(r.Form.Get("dpop_jkt"))
	boundDPoPJKT := dpopResult.JKT
	if dpopResult.Present && submittedDPoPJKT != "" && submittedDPoPJKT != dpopResult.JKT {
		writeOID4VCIError(w, http.StatusBadRequest, dpop.ErrorInvalidDPoPProof, "dpop_jkt does not match the DPoP proof JWK thumbprint")
		return
	}
	if boundDPoPJKT == "" {
		boundDPoPJKT = submittedDPoPJKT
	}
	if r.Form.Get("response_type") != "code" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "response_type must be code")
		return
	}
	redirectURI := strings.TrimSpace(r.Form.Get("redirect_uri"))
	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil || parsedRedirect.Scheme != "https" || parsedRedirect.Host == "" || parsedRedirect.User != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "redirect_uri must be an absolute HTTPS URI without userinfo")
		return
	}
	codeChallenge := strings.TrimSpace(r.Form.Get("code_challenge"))
	if codeChallenge == "" || r.Form.Get("code_challenge_method") != "S256" {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "PKCE S256 code_challenge is required")
		return
	}

	configurationIDs, usedAuthorizationDetails, err := p.parseAuthorizationDetails(r.Form.Get("authorization_details"))
	if err != nil {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if !usedAuthorizationDetails {
		configurationIDs = p.credentialConfigurationIDsForScope(r.Form.Get("scope"))
	}
	if len(configurationIDs) == 0 {
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "authorization_details or a supported credential scope is required")
		return
	}
	issuerState := strings.TrimSpace(r.Form.Get("issuer_state"))
	// Multiple credential configurations can share one scope value (for
	// example both the educational and HAIP mDL configs use vc:mdl). When
	// the wallet returns an issuer_state from an issuer-initiated offer and
	// selected credentials by scope only, bind the authorization to the
	// intersection with the configurations that offer actually authorized.
	if issuerState != "" && !usedAuthorizationDetails {
		offeredIDs := p.issuerInitiatedOfferedConfigurationIDs(issuerState)
		if len(offeredIDs) == 0 {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "issuer_state is unknown or expired")
			return
		}
		configurationIDs = intersectCredentialConfigurationIDs(configurationIDs, offeredIDs)
		if len(configurationIDs) == 0 {
			writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", "scope does not authorize any credential_configuration_id from the issuer-initiated offer")
			return
		}
	}
	issuerTransaction, err := p.acceptIssuerInitiatedAuthorizationRequest(issuerState, clientID, configurationIDs)
	if err != nil {
		// OpenID4VCI 1.0 Section 5.1.3: issuer_state is not guaranteed to
		// originate from this Credential Issuer and can be attacker-injected.
		// A supplied value therefore has to resolve to a live issuer-created
		// context and remain bound to the Credential Configurations it offered.
		// The value is not single-use: consecutive clients may redeem the same
		// offer until it expires.
		writeOID4VCIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	// The attestation subject is the client registration identity for this
	// authorization interaction. Persist only the redirect and protocol
	// capabilities proven in this PAR request; no client secret is created.
	p.mockIDP.RegisterClient(&models.Client{
		ID:                      clientID,
		Name:                    "Attested OID4VCI Wallet",
		RedirectURIs:            []string{redirectURI},
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		Scopes:                  strings.Fields(r.Form.Get("scope")),
		Public:                  true,
		TokenEndpointAuthMethod: "attest_jwt_client_auth",
		CreatedAt:               time.Now(),
	})

	requestURI := p.mockIDP.StorePushedAuthorizationRequest(mockidp.PushedAuthorizationRequest{
		ClientID:                   clientID,
		RedirectURI:                redirectURI,
		ResponseType:               "code",
		Scope:                      strings.TrimSpace(r.Form.Get("scope")),
		State:                      r.Form.Get("state"),
		Nonce:                      r.Form.Get("nonce"),
		CodeChallenge:              codeChallenge,
		CodeChallengeMethod:        "S256",
		CredentialConfigurationIDs: configurationIDs,
		AuthorizationDetailsUsed:   usedAuthorizationDetails,
		DPoPJKT:                    boundDPoPJKT,
		IssuerState:                issuerState,
		ExpiresAt:                  time.Now().Add(pushedAuthorizationRequestTTL),
	})
	if issuerTransaction != nil {
		p.emitEvent(
			issuerTransaction.SessionID,
			lookingglass.EventTypeFlowStep,
			"Issuer-Initiated Authorization Request Received",
			map[string]interface{}{
				"client_id":                    clientID,
				"credential_configuration_ids": configurationIDs,
				"issuer_state_validated":       true,
				"request_uri":                  requestURI,
			},
			lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeRFCReference,
				Title:       "Issuer State Returned",
				Description: "The wallet returned the opaque issuer_state from the Credential Offer in its pushed Authorization Request. The issuer validated the state and its Credential Configuration binding.",
				Reference:   "OpenID4VCI 1.0 Section 5.1.3",
			},
		)
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"request_uri": requestURI,
		"expires_in":  int(pushedAuthorizationRequestTTL.Seconds()),
	})
}

func (p *Plugin) credentialConfigurationIDsForScope(scope string) []string {
	requestedScopes := make(map[string]struct{})
	for _, value := range strings.Fields(scope) {
		requestedScopes[value] = struct{}{}
	}
	ids := make([]string, 0)
	for id, configuration := range p.credentialConfigurations {
		if _, requested := requestedScopes[configuration.Scope]; requested {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func (p *Plugin) issuerInitiatedOfferedConfigurationIDs(issuerState string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	transaction := p.issuerInitiatedOffers[strings.TrimSpace(issuerState)]
	if transaction == nil || time.Now().UTC().After(transaction.ExpiresAt) {
		return nil
	}
	return append([]string(nil), transaction.CredentialConfigurationIDs...)
}

func intersectCredentialConfigurationIDs(requested, offered []string) []string {
	allowed := make(map[string]struct{}, len(offered))
	for _, id := range offered {
		allowed[id] = struct{}{}
	}
	intersection := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, id := range requested {
		if _, ok := allowed[id]; !ok {
			continue
		}
		if _, already := seen[id]; already {
			continue
		}
		seen[id] = struct{}{}
		intersection = append(intersection, id)
	}
	sort.Strings(intersection)
	return intersection
}
