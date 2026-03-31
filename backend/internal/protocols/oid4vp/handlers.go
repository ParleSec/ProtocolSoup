package oid4vp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	credentialFormatDCSdJWT    = "dc+sd-jwt"
	credentialFormatJWTVCJSON  = "jwt_vc_json"
	credentialFormatJWTVCJSONL = "jwt_vc_json-ld"
	credentialFormatLDPVC      = "ldp_vc"
)

type createAuthorizationRequest struct {
	ClientID       string                 `json:"client_id"`
	ClientIDScheme string                 `json:"client_id_scheme,omitempty"`
	ResponseMode   string                 `json:"response_mode"`
	ResponseURI    string                 `json:"response_uri"`
	RedirectURI    string                 `json:"redirect_uri,omitempty"`
	Scope          string                 `json:"scope,omitempty"`
	DCQLQuery      json.RawMessage        `json:"dcql_query,omitempty"`
	ClientMetadata map[string]interface{} `json:"client_metadata,omitempty"`
}

type walletResponsePayload struct {
	State    string `json:"state"`
	VPToken  string `json:"vp_token,omitempty"`
	Response string `json:"response,omitempty"`
}

func (p *Plugin) handleCreateAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	if strings.TrimSpace(p.requestDataPath) != "" {
		if err := p.loadRequestState(p.requestDataPath); err != nil {
			writeServerError(w, "load request state", err)
			return
		}
	}

	if p.keySet == nil {
		writeOID4VPError(w, http.StatusServiceUnavailable, "server_error", "keyset is unavailable")
		return
	}

	var req createAuthorizationRequest
	if err := jsonDecode(r, &req); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	req.ResponseMode = strings.TrimSpace(req.ResponseMode)
	if req.ResponseMode == "" {
		req.ResponseMode = "direct_post"
	}
	req.ResponseURI = strings.TrimSpace(req.ResponseURI)
	if req.ResponseURI == "" {
		req.ResponseURI = p.verifierBaseURL() + "/response"
	}

	req.ClientID = strings.TrimSpace(req.ClientID)
	req.ClientIDScheme = strings.TrimSpace(req.ClientIDScheme)
	requestedClientIDScheme := ClientIDSchemeUnknown
	if req.ClientIDScheme != "" {
		scheme, err := ParseClientIDSchemeName(req.ClientIDScheme)
		if err != nil {
			writeOID4VPError(w, http.StatusBadRequest, "invalid_client", err.Error())
			return
		}
		requestedClientIDScheme = scheme
		if req.ClientID == "" {
			req.ClientID = p.defaultClientIDForScheme(scheme, req.ResponseURI)
			if req.ClientID == "" {
				writeOID4VPError(
					w,
					http.StatusBadRequest,
					"invalid_client",
					fmt.Sprintf("client_id scheme %q is not configured for this verifier", req.ClientIDScheme),
				)
				return
			}
		}
	}
	if req.ClientID == "" {
		req.ClientID = p.defaultClientIDForScheme(ClientIDSchemeRedirectURI, req.ResponseURI)
	}

	dcqlQuery := strings.TrimSpace(string(req.DCQLQuery))
	if dcqlQuery == "" && strings.TrimSpace(req.Scope) == "" {
		defaultDCQLBytes, _ := json.Marshal(defaultDCQLQuery)
		req.DCQLQuery = defaultDCQLBytes
		dcqlQuery = strings.TrimSpace(string(defaultDCQLBytes))
	}

	if err := ValidateDCQLQueryContract(dcqlQuery, req.Scope); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := ValidateDirectPostContract(req.ResponseMode, req.ResponseURI, req.RedirectURI); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	clientIDScheme, err := ParseClientIDScheme(req.ClientID)
	if err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	if requestedClientIDScheme != ClientIDSchemeUnknown && clientIDScheme != requestedClientIDScheme {
		writeOID4VPError(
			w,
			http.StatusBadRequest,
			"invalid_client",
			fmt.Sprintf("client_id %q does not match client_id_scheme %q", req.ClientID, req.ClientIDScheme),
		)
		return
	}
	if err := ValidateSupportedClientIDScheme(req.ClientID, p.supportedClientIDSchemes); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	if err := p.validateVerifierIdentityRequest(clientIDScheme, req.ClientID, req.ResponseURI); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}
	if clientIDScheme == ClientIDSchemeDecentralizedIdentifier && p.trustResolver != nil {
		if _, err := p.trustResolver.ResolveVerifier(r.Context(), req.ClientID); err != nil {
			writeOID4VPError(w, http.StatusBadRequest, "invalid_client", err.Error())
			return
		}
	}

	nonce := p.randomValue(24)
	state := p.randomValue(24)
	if err := ValidateNoncePresence(nonce); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	now := time.Now().UTC()
	requestID := p.randomValue(24)
	requestClaims := jwt.MapClaims{
		"iss":              req.ClientID,
		"aud":              "wallet",
		"client_id":        req.ClientID,
		"client_id_scheme": string(clientIDScheme),
		"response_type":    "vp_token",
		"response_mode":    req.ResponseMode,
		"response_uri":     req.ResponseURI,
		"nonce":            nonce,
		"state":            state,
		"iat":              now.Unix(),
		"exp":              now.Add(requestObjectTTL).Unix(),
		"jti":              requestID,
	}
	if req.Scope != "" {
		requestClaims["scope"] = req.Scope
	}
	if dcqlQuery != "" {
		var dcqlObject interface{}
		if err := json.Unmarshal(req.DCQLQuery, &dcqlObject); err != nil {
			writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "dcql_query must be valid JSON")
			return
		}
		requestClaims["dcql_query"] = dcqlObject
	}

	// OID4VP Section 5.1/11.1: include client_metadata with vp_formats_supported
	clientMetadata := req.ClientMetadata
	if clientMetadata == nil {
		clientMetadata = make(map[string]interface{})
	}
	if _, hasFormats := clientMetadata["vp_formats_supported"]; !hasFormats {
		clientMetadata["vp_formats_supported"] = defaultVPFormatsSupported()
	}
	requestClaims["client_metadata"] = clientMetadata

	requestJWT, err := p.signAuthorizationRequestObject(clientIDScheme, req.ClientID, requestClaims, req.ResponseURI)
	if err != nil {
		writeServerError(w, "sign request object", err)
		return
	}

	session := &requestSession{
		ID:             requestID,
		ClientID:       req.ClientID,
		ClientIDScheme: clientIDScheme,
		Nonce:          nonce,
		State:          state,
		ResponseMode:   req.ResponseMode,
		ResponseURI:    req.ResponseURI,
		RedirectURI:    req.RedirectURI,
		ScopeAlias:     req.Scope,
		DCQLQuery:      dcqlQuery,
		RequestJWT:     requestJWT,
		CreatedAt:      now,
		ExpiresAt:      now.Add(requestObjectTTL),
	}

	p.mu.Lock()
	p.requests[requestID] = session
	p.requestsByState[state] = requestID
	if err := p.persistRequestStateLocked(); err != nil {
		p.mu.Unlock()
		writeServerError(w, "persist request session", err)
		return
	}
	p.mu.Unlock()

	eventData := map[string]interface{}{
		"request_id":            requestID,
		"client_id":             req.ClientID,
		"client_id_scheme":      string(clientIDScheme),
		"response_mode":         req.ResponseMode,
		"response_uri":          req.ResponseURI,
		"has_dcql_query":        dcqlQuery != "",
		"scope_alias":           req.Scope,
		"nonce":                 nonce,
		"state":                 state,
		"trust_mode":            p.trustMode(),
		"did_web_allowed_hosts": p.didWebAllowedHosts,
	}
	if clientIDScheme == ClientIDSchemeX509SANDNS && p.x509SANDNSSigner != nil {
		eventData["x509_chain"] = p.describeX509Chain()
	}

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"OID4VP Authorization Request Created",
		eventData,
		append(
			append(
				append(
					p.vpAnnotation("dcql_contract"),
					p.vpAnnotation("direct_post")...,
				),
				p.vpAnnotation("request_object_typ")...,
			),
			p.vpAnnotation("client_id_scheme")...,
		)...,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"request_id":            requestID,
		"request_uri":           p.verifierBaseURL() + "/request/" + requestID,
		"request_uri_method":    "get",
		"request":               requestJWT,
		"response_mode":         req.ResponseMode,
		"response_uri":          req.ResponseURI,
		"state":                 state,
		"nonce":                 nonce,
		"client_id":             req.ClientID,
		"client_id_scheme":      string(clientIDScheme),
		"expires_in_seconds":    int(requestObjectTTL.Seconds()),
		"dcql_query_supplied":   dcqlQuery != "",
		"trust_mode":            p.trustMode(),
		"did_web_allowed_hosts": p.didWebAllowedHosts,
	})
}

func (p *Plugin) handleGetAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(p.requestDataPath) != "" {
		if err := p.loadRequestState(p.requestDataPath); err != nil {
			writeServerError(w, "load request state", err)
			return
		}
	}
	requestID := strings.TrimSpace(chi.URLParam(r, "requestID"))
	if requestID == "" {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "requestID is required")
		return
	}

	p.mu.RLock()
	session, ok := p.requests[requestID]
	p.mu.RUnlock()
	if !ok {
		writeOID4VPError(w, http.StatusNotFound, "invalid_request_uri", "request object not found")
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request_uri", "request object expired")
		return
	}
	if err := validateRequestObjectTyp(session.RequestJWT); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request_object", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request":    session.RequestJWT,
		"request_id": requestID,
		"expires_at": session.ExpiresAt.Format(time.RFC3339),
	})
}

func (p *Plugin) handlePostAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(p.requestDataPath) != "" {
		if err := p.loadRequestState(p.requestDataPath); err != nil {
			writeServerError(w, "load request state", err)
			return
		}
	}
	requestID := strings.TrimSpace(chi.URLParam(r, "requestID"))
	if requestID == "" {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "requestID is required")
		return
	}

	p.mu.RLock()
	session, ok := p.requests[requestID]
	p.mu.RUnlock()
	if !ok {
		writeOID4VPError(w, http.StatusNotFound, "invalid_request_uri", "request object not found")
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request_uri", "request object expired")
		return
	}
	if err := validateRequestObjectTyp(session.RequestJWT); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request_object", err.Error())
		return
	}

	// OID4VP Section 5.10: parse wallet_nonce from POST body if present
	walletNonce := strings.TrimSpace(r.FormValue("wallet_nonce"))
	walletMetadata := strings.TrimSpace(r.FormValue("wallet_metadata"))

	response := map[string]interface{}{
		"request":             session.RequestJWT,
		"request_id":          requestID,
		"request_uri_method":  "post",
		"dcql_query_supplied": session.DCQLQuery != "",
	}
	if walletNonce != "" {
		response["wallet_nonce"] = walletNonce
	}
	if walletMetadata != "" {
		response["wallet_metadata"] = walletMetadata
	}
	writeJSON(w, http.StatusOK, response)
}

func (p *Plugin) handleWalletResponse(w http.ResponseWriter, r *http.Request) {
	sessionID := p.getSessionFromRequest(r)
	if strings.TrimSpace(p.requestDataPath) != "" {
		if err := p.loadRequestState(p.requestDataPath); err != nil {
			writeServerError(w, "load request state", err)
			return
		}
	}

	payload, err := parseWalletResponsePayload(r)
	if err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(payload.State) == "" {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "state is required")
		return
	}

	p.mu.RLock()
	requestID, ok := p.requestsByState[payload.State]
	session := p.requests[requestID]
	p.mu.RUnlock()
	if !ok || session == nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "state does not map to active request")
		return
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "request session expired")
		return
	}

	vpToken := payload.VPToken
	if session.ResponseMode == "direct_post.jwt" {
		if strings.TrimSpace(payload.Response) == "" {
			writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "response is required for direct_post.jwt")
			return
		}
		extractedVPToken, extractedState, err := p.decryptAndExtractDirectPostJWT(payload.Response, session)
		if err != nil {
			writeOID4VPError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if extractedState != payload.State {
			writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "state mismatch in direct_post.jwt payload")
			return
		}
		vpToken = extractedVPToken
	}
	if strings.TrimSpace(vpToken) == "" {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "vp_token is required")
		return
	}

	result := p.evaluateVPToken(session, vpToken)
	p.mu.Lock()
	if session.Result != nil {
		p.mu.Unlock()
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "request session already completed")
		return
	}
	session.Result = result
	if err := p.persistRequestStateLocked(); err != nil {
		p.mu.Unlock()
		writeServerError(w, "persist request result", err)
		return
	}
	p.mu.Unlock()

	eventType := lookingglass.EventTypeFlowStep
	eventTitle := "OID4VP Response Evaluated"
	if !result.Policy.Allowed {
		eventType = lookingglass.EventTypeSecurityWarning
		eventTitle = "OID4VP Policy Denied"
	}

	p.emitEvent(
		sessionID,
		eventType,
		eventTitle,
		map[string]interface{}{
			"request_id":                session.ID,
			"response_mode":             session.ResponseMode,
			"nonce_validated":           result.NonceValidated,
			"audience_validated":        result.AudienceValidated,
			"expiry_validated":          result.ExpiryValidated,
			"holder_binding_verified":   result.HolderBindingVerified,
			"policy_allowed":            result.Policy.Allowed,
			"policy_code":               result.Policy.Code,
			"policy_reasons":            result.Policy.Reasons,
			"policy_reason_codes":       result.Policy.ReasonCodes,
			"vp_token_present":          vpToken != "",
			"direct_post_jwt_encrypted": session.ResponseMode == "direct_post.jwt",
		},
		append(
			p.vpAnnotation("nonce_binding"),
			p.vpAnnotation("direct_post")...,
		)...,
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": requestID,
		"policy":     result.Policy,
		"result":     result,
	})
}

func (p *Plugin) handleGetVerificationResult(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(p.requestDataPath) != "" {
		if err := p.loadRequestState(p.requestDataPath); err != nil {
			writeServerError(w, "load request state", err)
			return
		}
	}
	requestID := strings.TrimSpace(chi.URLParam(r, "requestID"))
	if requestID == "" {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request", "requestID is required")
		return
	}

	p.mu.RLock()
	session, ok := p.requests[requestID]
	p.mu.RUnlock()
	if !ok {
		writeOID4VPError(w, http.StatusNotFound, "invalid_request", "request not found")
		return
	}
	if session.Result == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"request_id": requestID,
			"status":     "pending",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request_id": requestID,
		"status":     "completed",
		"result":     session.Result,
	})
}

func (p *Plugin) evaluateVPToken(session *requestSession, vpToken string) *models.OID4VPVerificationResult {
	result := &models.OID4VPVerificationResult{
		NonceValidated:        false,
		AudienceValidated:     false,
		ExpiryValidated:       false,
		HolderBindingVerified: false,
		Policy: models.OID4VPPolicyDecision{
			Allowed:     false,
			Code:        "verification_failed",
			Message:     "Presentation failed verifier policy checks",
			Reasons:     []string{},
			ReasonCodes: []string{},
			EvaluatedAt: time.Now().UTC(),
		},
	}

	if strings.Contains(vpToken, "~") {
		return p.evaluateSDJWTPresentation(session, vpToken, result)
	}
	if strings.HasPrefix(strings.TrimSpace(vpToken), "{") {
		return p.evaluateJSONLDPresentation(session, vpToken, result)
	}

	walletContext, err := p.resolvePresentedWalletContext(vpToken, "")
	if err != nil {
		addPolicyReason(result, "vp_token_invalid", err.Error())
		finalizePolicyDecision(result)
		return result
	}

	parsed, err := jwt.Parse(vpToken, func(token *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(token.Method.Alg(), walletContext.VerificationAlgPrefix) {
			return nil, fmt.Errorf("vp_token uses unexpected algorithm")
		}
		if strings.TrimSpace(walletContext.JWK.Kid) != "" {
			kid, _ := token.Header["kid"].(string)
			if strings.TrimSpace(kid) != "" && strings.TrimSpace(kid) != strings.TrimSpace(walletContext.JWK.Kid) {
				return nil, fmt.Errorf("vp_token kid does not match wallet cnf.jwk kid")
			}
		}
		return walletContext.VerificationKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !parsed.Valid {
		addPolicyReason(result, "vp_token_signature_invalid", "vp_token signature validation failed")
		finalizePolicyDecision(result)
		return result
	}
	if err := ValidateVPTokenType(fmt.Sprint(parsed.Header["typ"])); err != nil {
		addPolicyReason(result, "vp_token_type_invalid", err.Error())
		finalizePolicyDecision(result)
		return result
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		addPolicyReason(result, "vp_token_claims_invalid", "vp_token claims are invalid")
		finalizePolicyDecision(result)
		return result
	}

	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	cnfMap, _ := claims["cnf"].(map[string]interface{})
	cnfJKT, _ := cnfMap["jkt"].(string)
	if strings.TrimSpace(issuer) != walletContext.Subject || strings.TrimSpace(subject) != walletContext.Subject {
		addPolicyReason(result, "holder_binding_mismatch", "holder subject does not match wallet identity")
	}
	if strings.TrimSpace(cnfJKT) != walletContext.BindingThumbprint {
		addPolicyReason(result, "holder_binding_mismatch", "holder key thumbprint mismatch")
	}
	if strings.TrimSpace(issuer) == walletContext.Subject && strings.TrimSpace(subject) == walletContext.Subject && strings.TrimSpace(cnfJKT) == walletContext.BindingThumbprint {
		result.HolderBindingVerified = true
	}

	if nonceClaim, _ := claims["nonce"].(string); nonceClaim == session.Nonce {
		result.NonceValidated = true
	} else {
		addPolicyReason(result, "nonce_mismatch", "nonce mismatch")
	}

	if audienceIncludes(claims["aud"], session.ClientID) {
		result.AudienceValidated = true
	} else {
		addPolicyReason(result, "audience_mismatch", "audience mismatch")
	}

	expiryValid := claimExpiryIsValid(claims["exp"])
	result.ExpiryValidated = expiryValid
	if !expiryValid {
		addPolicyReason(result, "vp_token_expired", "vp_token expired")
	}

	credentialEvidenceSet, credentialErr := p.validatePresentedCredentials(claims, walletContext.Subject, session)
	if credentialErr != nil {
		if policyErr, ok := asVerifierPolicyError(credentialErr); ok {
			addPolicyReason(result, policyErr.Code, policyErr.Message)
		} else {
			addPolicyReason(result, "credential_validation_failed", credentialErr.Error())
		}
		result.HolderBindingVerified = false
	} else {
		if len(credentialEvidenceSet) > 0 {
			result.CredentialEvidence = &credentialEvidenceSet[0]
			result.CredentialEvidenceSet = credentialEvidenceSet
		}
	}

	result.Policy.Allowed = result.NonceValidated &&
		result.AudienceValidated &&
		result.ExpiryValidated &&
		result.HolderBindingVerified &&
		len(result.Policy.ReasonCodes) == 0
	if result.Policy.Allowed {
		result.Policy.Code = "allowed"
		result.Policy.Message = "Presentation accepted"
		result.Policy.Reasons = nil
		result.Policy.ReasonCodes = nil
		return result
	}
	finalizePolicyDecision(result)
	return result
}

func (p *Plugin) evaluateSDJWTPresentation(session *requestSession, vpToken string, result *models.OID4VPVerificationResult) *models.OID4VPVerificationResult {
	envelope, err := vc.ParseSDJWTEnvelope(vpToken)
	if err != nil {
		addPolicyReason(result, "vp_token_invalid", fmt.Sprintf("sd-jwt parse: %v", err))
		finalizePolicyDecision(result)
		return result
	}

	issuerToken, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
	if err != nil {
		addPolicyReason(result, "vp_token_invalid", fmt.Sprintf("issuer jwt decode: %v", err))
		finalizePolicyDecision(result)
		return result
	}

	credSubject := ""
	if sub, ok := issuerToken.Payload["sub"].(string); ok {
		credSubject = strings.TrimSpace(sub)
	}
	if credSubject == "" {
		if iss, ok := issuerToken.Payload["iss"].(string); ok {
			credSubject = strings.TrimSpace(iss)
		}
	}

	cnfMap, _ := issuerToken.Payload["cnf"].(map[string]interface{})
	if cnfMap == nil {
		vcObj, _ := issuerToken.Payload["vc"].(map[string]interface{})
		if vcObj != nil {
			if csObj, _ := vcObj["credentialSubject"].(map[string]interface{}); csObj != nil {
				cnfMap, _ = csObj["cnf"].(map[string]interface{})
			}
		}
	}

	var holderJWK crypto.JWK
	var holderKey interface{}
	var holderAlgPrefix string

	if cnfMap != nil {
		if jwkRaw, ok := cnfMap["jwk"]; ok {
			jwkBytes, _ := json.Marshal(jwkRaw)
			if err := json.Unmarshal(jwkBytes, &holderJWK); err == nil {
				holderKey, holderAlgPrefix, _ = credentialVerificationKeyFromJWK(holderJWK)
			}
		}
	}

	if !envelope.HasKeyBindingJWT() {
		addPolicyReason(result, "kb_jwt_missing", "sd-jwt presentation requires key binding jwt")
		finalizePolicyDecision(result)
		return result
	}

	// Validate KB-JWT
	if holderKey != nil {
		kbParsed, kbErr := jwt.Parse(envelope.KeyBindingJWT, func(token *jwt.Token) (interface{}, error) {
			if !strings.HasPrefix(token.Method.Alg(), holderAlgPrefix) {
				return nil, fmt.Errorf("kb-jwt uses unexpected algorithm")
			}
			return holderKey, nil
		})
		if kbErr != nil {
			addPolicyReason(result, "kb_jwt_invalid", fmt.Sprintf("kb-jwt signature: %v", kbErr))
		} else if kbParsed.Valid {
			kbClaims, _ := kbParsed.Claims.(jwt.MapClaims)
			if kbClaims != nil {
				kbTyp, _ := kbParsed.Header["typ"].(string)
				if strings.TrimSpace(kbTyp) != "kb+jwt" {
					addPolicyReason(result, "kb_jwt_invalid", "kb-jwt typ must be kb+jwt")
				}
				if kbAud, _ := kbClaims["aud"].(string); strings.TrimSpace(kbAud) != session.ClientID {
					addPolicyReason(result, "audience_mismatch", "kb-jwt audience mismatch")
				} else {
					result.AudienceValidated = true
				}
				if kbNonce, _ := kbClaims["nonce"].(string); strings.TrimSpace(kbNonce) != session.Nonce {
					addPolicyReason(result, "nonce_mismatch", "kb-jwt nonce mismatch")
				} else {
					result.NonceValidated = true
				}
				if _, hasIAT := kbClaims["iat"]; !hasIAT {
					addPolicyReason(result, "kb_jwt_invalid", "kb-jwt missing iat")
				}
				// Verify sd_hash
				sdJWTWithoutKB := vc.BuildSDJWTSerialization(envelope.IssuerSignedJWT, envelope.Disclosures, "")
				if !strings.HasSuffix(sdJWTWithoutKB, "~") {
					sdJWTWithoutKB += "~"
				}
				expectedHash := sha256.Sum256([]byte(sdJWTWithoutKB))
				expectedSDHash := base64.RawURLEncoding.EncodeToString(expectedHash[:])
				if sdHash, _ := kbClaims["sd_hash"].(string); strings.TrimSpace(sdHash) != expectedSDHash {
					addPolicyReason(result, "kb_jwt_invalid", "kb-jwt sd_hash mismatch")
				}
				result.HolderBindingVerified = len(result.Policy.ReasonCodes) == 0
			}
		}
	} else {
		addPolicyReason(result, "holder_binding_missing", "credential cnf.jwk not found for kb-jwt verification")
	}

	result.ExpiryValidated = true
	if expRaw, ok := issuerToken.Payload["exp"]; ok {
		result.ExpiryValidated = claimExpiryIsValid(expRaw)
		if !result.ExpiryValidated {
			addPolicyReason(result, "credential_expired", "issuer credential expired")
		}
	}

	// Build credential evidence from issuer JWT + disclosed claims
	decodedDisclosures, discErr := vc.DecodeAndVerifyDisclosures(envelope.Disclosures, nil)
	if discErr != nil {
		addPolicyReason(result, "disclosure_invalid", discErr.Error())
	}
	disclosedClaims := vc.DisclosedClaimMap(decodedDisclosures)
	fullClaims := make(map[string]interface{})
	for k, v := range issuerToken.Payload {
		fullClaims[k] = v
	}
	for k, v := range disclosedClaims {
		fullClaims[k] = v
	}

	evidence := models.OID4VPCredentialEvidence{
		Format:          credentialFormatDCSdJWT,
		VCT:             strings.TrimSpace(asString(issuerToken.Payload["vct"])),
		Subject:         credSubject,
		Issuer:          strings.TrimSpace(asString(issuerToken.Payload["iss"])),
		FullClaims:      fullClaims,
		DisclosedClaims: disclosedClaims,
	}
	result.CredentialEvidence = &evidence
	result.CredentialEvidenceSet = []models.OID4VPCredentialEvidence{evidence}

	result.Policy.Allowed = result.NonceValidated &&
		result.AudienceValidated &&
		result.ExpiryValidated &&
		result.HolderBindingVerified &&
		len(result.Policy.ReasonCodes) == 0
	if result.Policy.Allowed {
		result.Policy.Code = "allowed"
		result.Policy.Message = "Presentation accepted"
		result.Policy.Reasons = nil
		result.Policy.ReasonCodes = nil
		return result
	}
	finalizePolicyDecision(result)
	return result
}

func (p *Plugin) evaluateJSONLDPresentation(session *requestSession, vpToken string, result *models.OID4VPVerificationResult) *models.OID4VPVerificationResult {
	trimmedToken := strings.TrimSpace(vpToken)
	var vpObject map[string]interface{}
	if err := json.Unmarshal([]byte(trimmedToken), &vpObject); err != nil {
		addPolicyReason(result, "vp_token_invalid", fmt.Sprintf("json-ld parse: %v", err))
		finalizePolicyDecision(result)
		return result
	}
	if err := vc.VerifyDataIntegrityPresentation(vpObject, nil); err != nil {
		addPolicyReason(result, "vp_token_signature_invalid", err.Error())
		finalizePolicyDecision(result)
		return result
	}

	walletContext, err := p.resolvePresentedWalletContext(trimmedToken, "")
	if err != nil {
		addPolicyReason(result, "holder_binding_mismatch", err.Error())
		finalizePolicyDecision(result)
		return result
	}
	holder := strings.TrimSpace(asString(vpObject["holder"]))
	if holder == "" {
		addPolicyReason(result, "holder_binding_mismatch", "presentation holder is missing")
	} else if holder != walletContext.Subject {
		addPolicyReason(result, "holder_binding_mismatch", "presentation holder does not match wallet identity")
	}

	proofs, err := extractProofObjectsOID4VP(vpObject["proof"])
	if err != nil || len(proofs) == 0 {
		addPolicyReason(result, "vp_token_invalid", "presentation proof is missing")
		finalizePolicyDecision(result)
		return result
	}
	for _, proof := range proofs {
		if challenge := strings.TrimSpace(asString(proof["challenge"])); challenge == session.Nonce {
			result.NonceValidated = true
		}
		if audienceIncludes(proof["domain"], session.ClientID) {
			result.AudienceValidated = true
		}
		if expiresAt, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(asString(proof["expires"]))); parseErr == nil && !expiresAt.IsZero() {
			if expiresAt.Before(time.Now().UTC()) {
				addPolicyReason(result, "vp_token_expired", "presentation proof expired")
			}
		}
		verificationMethodID := proofVerificationMethodID(proof["verificationMethod"])
		if verificationMethodBoundToHolder(verificationMethodID, walletContext.Subject) {
			result.HolderBindingVerified = true
		}
	}
	if !result.NonceValidated {
		addPolicyReason(result, "nonce_mismatch", "no presentation proof matched the expected challenge")
	}
	if !result.AudienceValidated {
		addPolicyReason(result, "audience_mismatch", "no presentation proof matched the expected domain")
	}
	if !result.HolderBindingVerified {
		addPolicyReason(result, "holder_binding_mismatch", "no presentation proof verificationMethod is bound to the holder")
	}
	result.ExpiryValidated = !containsPolicyCode(result, "vp_token_expired")

	presentedCredentials, err := extractPresentedCredentialEnvelopes(vpObject)
	if err != nil {
		addPolicyReason(result, "credential_missing", err.Error())
		result.HolderBindingVerified = false
		finalizePolicyDecision(result)
		return result
	}
	credentialEvidenceSet, credentialErr := p.validatePresentedCredentialEnvelopes(presentedCredentials, walletContext.Subject, session)
	if credentialErr != nil {
		if policyErr, ok := asVerifierPolicyError(credentialErr); ok {
			addPolicyReason(result, policyErr.Code, policyErr.Message)
		} else {
			addPolicyReason(result, "credential_validation_failed", credentialErr.Error())
		}
		result.HolderBindingVerified = false
	} else if len(credentialEvidenceSet) > 0 {
		result.CredentialEvidence = &credentialEvidenceSet[0]
		result.CredentialEvidenceSet = credentialEvidenceSet
	}

	result.Policy.Allowed = result.NonceValidated &&
		result.AudienceValidated &&
		result.ExpiryValidated &&
		result.HolderBindingVerified &&
		len(result.Policy.ReasonCodes) == 0
	if result.Policy.Allowed {
		result.Policy.Code = "allowed"
		result.Policy.Message = "Presentation accepted"
		result.Policy.Reasons = nil
		result.Policy.ReasonCodes = nil
		return result
	}
	finalizePolicyDecision(result)
	return result
}

func (p *Plugin) decryptAndExtractDirectPostJWT(compactJWE string, session *requestSession) (string, string, error) {
	if p.keySet == nil {
		return "", "", fmt.Errorf("keyset is unavailable")
	}
	if session == nil {
		return "", "", fmt.Errorf("request session is required")
	}
	encrypted, err := jose.ParseEncrypted(compactJWE, []jose.KeyAlgorithm{jose.RSA_OAEP}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return "", "", fmt.Errorf("invalid JWE response: %w", err)
	}
	plaintext, err := encrypted.Decrypt(p.keySet.RSAPrivateKey())
	if err != nil {
		return "", "", fmt.Errorf("failed to decrypt direct_post.jwt payload: %w", err)
	}

	innerJWT := strings.TrimSpace(string(plaintext))
	if innerJWT == "" {
		return "", "", fmt.Errorf("decrypted response payload is empty")
	}

	decodedInner, err := crypto.DecodeTokenWithoutValidation(innerJWT)
	if err != nil {
		return "", "", fmt.Errorf("decode direct_post.jwt payload failed: %w", err)
	}
	if err := ValidateResponseJWTType(fmt.Sprint(decodedInner.Header["typ"])); err != nil {
		return "", "", err
	}
	vpTokenHint, _ := decodedInner.Payload["vp_token"].(string)
	if strings.TrimSpace(vpTokenHint) == "" {
		return "", "", fmt.Errorf("direct_post.jwt payload must contain vp_token")
	}
	subjectHint, _ := decodedInner.Payload["sub"].(string)
	if strings.TrimSpace(subjectHint) == "" {
		subjectHint, _ = decodedInner.Payload["iss"].(string)
	}
	walletContext, err := p.resolvePresentedWalletContext(vpTokenHint, subjectHint)
	if err != nil {
		return "", "", err
	}

	parsed, err := jwt.Parse(innerJWT, func(token *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(token.Method.Alg(), walletContext.VerificationAlgPrefix) {
			return nil, fmt.Errorf("response jwt uses unexpected algorithm")
		}
		if strings.TrimSpace(walletContext.JWK.Kid) != "" {
			kid, _ := token.Header["kid"].(string)
			if strings.TrimSpace(kid) != "" && strings.TrimSpace(kid) != strings.TrimSpace(walletContext.JWK.Kid) {
				return nil, fmt.Errorf("response jwt kid does not match wallet key")
			}
		}
		return walletContext.VerificationKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !parsed.Valid {
		return "", "", fmt.Errorf("invalid direct_post.jwt response signature")
	}
	if err := ValidateResponseJWTType(fmt.Sprint(parsed.Header["typ"])); err != nil {
		return "", "", err
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", fmt.Errorf("invalid direct_post.jwt claims")
	}
	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	if strings.TrimSpace(issuer) != walletContext.Subject || strings.TrimSpace(subject) != walletContext.Subject {
		return "", "", fmt.Errorf("direct_post.jwt subject is not bound to wallet identity")
	}

	if !audienceIncludes(claims["aud"], session.ResponseURI) {
		return "", "", fmt.Errorf("direct_post.jwt audience does not match response_uri")
	}
	expiryValid := claimExpiryIsValid(claims["exp"])
	if !expiryValid {
		return "", "", fmt.Errorf("direct_post.jwt response is expired")
	}

	vpToken, _ := claims["vp_token"].(string)
	state, _ := claims["state"].(string)
	if strings.TrimSpace(vpToken) == "" || strings.TrimSpace(state) == "" {
		return "", "", fmt.Errorf("direct_post.jwt payload must contain vp_token and state")
	}
	return vpToken, state, nil
}

func validateRequestObjectTyp(requestJWT string) error {
	decodedToken, err := crypto.DecodeTokenWithoutValidation(requestJWT)
	if err != nil {
		return fmt.Errorf("request object decode failed: %w", err)
	}
	typRaw, _ := decodedToken.Header["typ"].(string)
	return ValidateRequestObjectType(typRaw)
}

func defaultVPFormatsSupported() map[string]interface{} {
	return map[string]interface{}{
		credentialFormatDCSdJWT: map[string]interface{}{
			"sd-jwt_alg_values": []string{"ES256"},
			"kb-jwt_alg_values": []string{"ES256"},
		},
		credentialFormatJWTVCJSON: map[string]interface{}{
			"alg_values_supported": []string{"ES256", "RS256", "EdDSA"},
		},
		credentialFormatJWTVCJSONL: map[string]interface{}{
			"alg_values_supported": []string{"ES256", "RS256", "EdDSA"},
		},
		credentialFormatLDPVC: map[string]interface{}{
			"proof_type_values_supported": []string{
				"DataIntegrityProof",
			},
		},
	}
}

func claimExpiryIsValid(rawExp interface{}) bool {
	var unix int64
	switch value := rawExp.(type) {
	case float64:
		unix = int64(value)
	case int64:
		unix = value
	case int:
		unix = int64(value)
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return false
		}
		unix = parsed
	default:
		return false
	}
	return time.Unix(unix, 0).After(time.Now().UTC())
}

type presentedWalletContext struct {
	Subject               string
	JWK                   crypto.JWK
	VerificationKey       interface{}
	VerificationAlgPrefix string
	BindingThumbprint     string
}

func (p *Plugin) resolvePresentedWalletContext(token string, subjectHint string) (*presentedWalletContext, error) {
	trimmedToken := strings.TrimSpace(token)
	if trimmedToken == "" {
		return nil, fmt.Errorf("token is required")
	}
	if strings.HasPrefix(trimmedToken, "{") {
		return p.resolveJSONLDPresentedWalletContext(trimmedToken, subjectHint)
	}

	var payload map[string]interface{}

	if strings.Contains(trimmedToken, "~") {
		envelope, err := vc.ParseSDJWTEnvelope(trimmedToken)
		if err != nil {
			return nil, fmt.Errorf("sd-jwt envelope parse failed: %w", err)
		}
		decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
		if err != nil {
			return nil, fmt.Errorf("sd-jwt issuer jwt decode failed: %w", err)
		}
		payload = decoded.Payload
	} else {
		decoded, err := crypto.DecodeTokenWithoutValidation(trimmedToken)
		if err != nil {
			return nil, fmt.Errorf("token decode failed: %w", err)
		}
		payload = decoded.Payload
	}

	subject := ""
	if claimSub, ok := payload["sub"].(string); ok {
		subject = strings.TrimSpace(claimSub)
	}
	if subject == "" {
		if claimIss, ok := payload["iss"].(string); ok {
			subject = strings.TrimSpace(claimIss)
		}
	}
	hint := strings.TrimSpace(subjectHint)
	if subject == "" {
		subject = hint
	}
	if subject == "" {
		return nil, fmt.Errorf("wallet subject is missing from token")
	}
	if hint != "" && subject != hint {
		return nil, fmt.Errorf("token subject does not match expected wallet subject")
	}

	cnfMap, _ := payload["cnf"].(map[string]interface{})
	if cnfMap == nil {
		return nil, fmt.Errorf("token cnf claim is required")
	}
	jwkRaw, hasJWK := cnfMap["jwk"]
	if !hasJWK {
		return nil, fmt.Errorf("token cnf.jwk claim is required")
	}
	jwkBytes, err := json.Marshal(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("token cnf.jwk marshal failed: %w", err)
	}
	var walletJWK crypto.JWK
	if err := json.Unmarshal(jwkBytes, &walletJWK); err != nil {
		return nil, fmt.Errorf("token cnf.jwk parse failed: %w", err)
	}
	if strings.TrimSpace(walletJWK.Kty) == "" {
		return nil, fmt.Errorf("token cnf.jwk kty is required")
	}
	verificationKey, algPrefix, err := credentialVerificationKeyFromJWK(walletJWK)
	if err != nil {
		return nil, err
	}
	thumbprint := strings.TrimSpace(walletJWK.Thumbprint())
	if thumbprint == "" {
		return nil, fmt.Errorf("token cnf.jwk thumbprint could not be derived")
	}
	cnfJKT, _ := cnfMap["jkt"].(string)
	if strings.TrimSpace(cnfJKT) != "" && strings.TrimSpace(cnfJKT) != thumbprint {
		return nil, fmt.Errorf("token cnf.jkt does not match cnf.jwk thumbprint")
	}

	return &presentedWalletContext{
		Subject:               subject,
		JWK:                   walletJWK,
		VerificationKey:       verificationKey,
		VerificationAlgPrefix: algPrefix,
		BindingThumbprint:     thumbprint,
	}, nil
}

func (p *Plugin) resolveJSONLDPresentedWalletContext(token string, subjectHint string) (*presentedWalletContext, error) {
	var presentation map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(token)), &presentation); err != nil {
		return nil, fmt.Errorf("json-ld presentation parse failed: %w", err)
	}
	subject := strings.TrimSpace(asString(presentation["holder"]))
	hint := strings.TrimSpace(subjectHint)
	if subject == "" {
		subject = hint
	}
	if subject == "" {
		return nil, fmt.Errorf("wallet subject is missing from presentation")
	}
	if hint != "" && subject != hint {
		return nil, fmt.Errorf("presentation holder does not match expected wallet subject")
	}
	proofs, err := extractProofObjectsOID4VP(presentation["proof"])
	if err != nil || len(proofs) == 0 {
		return nil, fmt.Errorf("presentation proof is missing")
	}
	walletJWKs, err := vc.ResolveVerificationMethodJWKs(proofs[0]["verificationMethod"], nil)
	if err != nil {
		return nil, fmt.Errorf("resolve presentation verification method: %w", err)
	}
	walletJWK := walletJWKs[0]
	verificationKey, algPrefix, err := credentialVerificationKeyFromJWK(walletJWK)
	if err != nil {
		return nil, err
	}
	thumbprint := strings.TrimSpace(walletJWK.Thumbprint())
	if thumbprint == "" {
		return nil, fmt.Errorf("presentation verification key thumbprint could not be derived")
	}
	return &presentedWalletContext{
		Subject:               subject,
		JWK:                   walletJWK,
		VerificationKey:       verificationKey,
		VerificationAlgPrefix: algPrefix,
		BindingThumbprint:     thumbprint,
	}, nil
}

type presentedCredentialEnvelope struct {
	CredentialID string
	Format       string
	Credential   string
}

type dcqlCredentialRequirement = vc.DCQLCredentialRequirement

func (p *Plugin) validatePresentedCredentials(
	vpClaims jwt.MapClaims,
	walletSubject string,
	session *requestSession,
) ([]models.OID4VPCredentialEvidence, error) {
	vpObject, ok := vpClaims["vp"].(map[string]interface{})
	if !ok {
		return nil, newVerifierPolicyError("credential_missing", "vp claim is missing", nil)
	}
	presentedCredentials, err := extractPresentedCredentialEnvelopes(vpObject)
	if err != nil {
		return nil, newVerifierPolicyError("credential_missing", err.Error(), nil)
	}
	return p.validatePresentedCredentialEnvelopes(presentedCredentials, walletSubject, session)
}

func (p *Plugin) validatePresentedCredentialEnvelopes(
	presentedCredentials []presentedCredentialEnvelope,
	walletSubject string,
	session *requestSession,
) ([]models.OID4VPCredentialEvidence, error) {
	normalizedSubject := strings.TrimSpace(walletSubject)
	if normalizedSubject == "" {
		return nil, newVerifierPolicyError("holder_binding_mismatch", "wallet subject is missing", nil)
	}
	if p.walletStore == nil {
		return nil, newVerifierPolicyError("missing_lineage", "wallet credential lineage store is unavailable", nil)
	}
	storedCredentials := p.walletStore.List(normalizedSubject)
	if len(storedCredentials) == 0 {
		return nil, newVerifierPolicyError("missing_lineage", "presented credential lineage was not found", nil)
	}

	registry := vc.DefaultCredentialFormatRegistry()
	evidenceSet := make([]models.OID4VPCredentialEvidence, 0, len(presentedCredentials))
	for _, presented := range presentedCredentials {
		rawCredential := strings.TrimSpace(presented.Credential)
		if rawCredential == "" {
			continue
		}

		parsedCredential, err := registry.ParseAnyCredential(rawCredential)
		if err != nil {
			return nil, newVerifierPolicyError("credential_malformed", "presented credential parse failed", err)
		}
		credentialFormat := firstNonEmpty(strings.TrimSpace(presented.Format), strings.TrimSpace(parsedCredential.Format))
		if credentialFormat == "" {
			credentialFormat = strings.TrimSpace(parsedCredential.Format)
		}
		if strings.TrimSpace(presented.Format) != "" && strings.TrimSpace(parsedCredential.Format) != "" && strings.TrimSpace(presented.Format) != strings.TrimSpace(parsedCredential.Format) {
			return nil, newVerifierPolicyError("credential_format_mismatch", "presented credential format does not match actual credential format", nil)
		}
		if strings.TrimSpace(parsedCredential.Subject) != normalizedSubject {
			return nil, newVerifierPolicyError("credential_subject_mismatch", "presented credential subject mismatch", nil)
		}

		credentialEvidence, err := vc.BuildCredentialEvidence(rawCredential)
		if err != nil {
			return nil, newVerifierPolicyError("credential_malformed", "presented credential evidence could not be derived", err)
		}

		storedRecord, found := findStoredCredentialLineage(
			storedCredentials,
			presented,
			rawCredential,
			strings.TrimSpace(parsedCredential.IssuerSignedJWT),
			credentialFormat,
			strings.TrimSpace(parsedCredential.VCT),
			strings.TrimSpace(parsedCredential.Doctype),
		)
		if !found {
			return nil, newVerifierPolicyError("missing_lineage", "presented credential does not match stored issuance lineage", nil)
		}

		formatHandler, ok := registry.Lookup(credentialFormat)
		if !ok {
			return nil, newVerifierPolicyError("credential_format_mismatch", "presented credential format is unsupported", nil)
		}
		issuerKeys := []crypto.JWK{}
		if strings.TrimSpace(storedRecord.IssuerJWK.Kty) != "" {
			issuerKeys = append(issuerKeys, storedRecord.IssuerJWK)
		}
		if err := formatHandler.ValidateIssuerSignature(vc.CredentialValidationInput{
			Credential:       rawCredential,
			ParsedCredential: parsedCredential,
			IssuerKeys:       issuerKeys,
		}); err != nil {
			return nil, newVerifierPolicyError("credential_signature_invalid", "presented credential signature validation failed", err)
		}
		issuer := strings.TrimSpace(parsedCredential.Issuer)
		if strings.TrimSpace(storedRecord.Issuer) != "" && strings.TrimSpace(issuer) != strings.TrimSpace(storedRecord.Issuer) {
			return nil, newVerifierPolicyError("credential_issuer_mismatch", "presented credential issuer mismatch", nil)
		}
		if !parsedCredential.ExpiresAt.IsZero() && !parsedCredential.ExpiresAt.After(time.Now().UTC()) {
			return nil, newVerifierPolicyError("credential_expired", "presented credential expired", nil)
		}

		credentialTypes := append([]string{}, parsedCredential.CredentialTypes...)
		if len(credentialTypes) == 0 {
			credentialTypes = append(credentialTypes, storedRecord.CredentialTypes...)
		}

		evidence := models.OID4VPCredentialEvidence{
			Subject:                   normalizedSubject,
			Format:                    credentialFormat,
			CredentialConfigurationID: strings.TrimSpace(storedRecord.CredentialConfigurationID),
			VCT:                       firstNonEmpty(strings.TrimSpace(parsedCredential.VCT), strings.TrimSpace(storedRecord.VCT)),
			Doctype:                   firstNonEmpty(strings.TrimSpace(parsedCredential.Doctype), strings.TrimSpace(storedRecord.Doctype)),
			CredentialTypes:           dedupeStrings(credentialTypes),
			Issuer:                    firstNonEmpty(strings.TrimSpace(issuer), strings.TrimSpace(storedRecord.Issuer)),
			RequiredClaimPaths:        nil,
			DisclosedClaims:           credentialEvidence.DisclosedClaims,
			FullClaims:                credentialEvidence.FullClaims,
		}
		evidenceSet = append(evidenceSet, evidence)
	}
	if len(evidenceSet) == 0 {
		return nil, newVerifierPolicyError("credential_missing", "presented credential is missing", nil)
	}

	var requirements []dcqlCredentialRequirement
	if session != nil {
		requirements = parseDCQLCredentialRequirements(session.DCQLQuery)
	}
	for _, requirement := range requirements {
		matched := false
		failureCode := "dcql_format_mismatch"
		failureMessage := "presented credential does not satisfy requested dcql constraints"
		for idx := range evidenceSet {
			ok, code, message := requirementMatchesEvidence(requirement, evidenceSet[idx])
			if ok {
				evidenceSet[idx].RequiredClaimPaths = mergeClaimPaths(evidenceSet[idx].RequiredClaimPaths, requirement.RequiredClaimPaths)
				matched = true
				break
			}
			if strings.TrimSpace(code) != "" {
				failureCode = code
			}
			if strings.TrimSpace(message) != "" {
				failureMessage = message
			}
		}
		if !matched {
			return nil, newVerifierPolicyError(failureCode, failureMessage, nil)
		}
	}

	return evidenceSet, nil
}

func extractPresentedCredentialEnvelopes(vpObject map[string]interface{}) ([]presentedCredentialEnvelope, error) {
	result := make([]presentedCredentialEnvelope, 0, 2)
	rawCredentials, hasCredentials := vpObject["credentials"].([]interface{})
	if hasCredentials {
		for _, rawCredential := range rawCredentials {
			credentialObject, _ := rawCredential.(map[string]interface{})
			format, _ := credentialObject["format"].(string)
			credentialID, _ := credentialObject["credential_id"].(string)
			rawCredentialValue := strings.TrimSpace(asString(credentialObject["credential"]))
			if rawCredentialValue == "" {
				rawCredentialValue = strings.TrimSpace(asString(credentialObject["credential_jwt"]))
			}
			if rawCredentialValue == "" {
				continue
			}
			result = append(result, presentedCredentialEnvelope{
				CredentialID: strings.TrimSpace(credentialID),
				Format:       strings.TrimSpace(format),
				Credential:   rawCredentialValue,
			})
		}
	}
	if len(result) == 0 {
		if vcArray, ok := vpObject["verifiableCredential"].([]interface{}); ok {
			format, _ := vpObject["format"].(string)
			credentialID, _ := vpObject["credential_id"].(string)
			for _, rawVC := range vcArray {
				vcStr, err := normalizePresentedCredentialValueOID4VP(rawVC)
				if err != nil || vcStr == "" {
					continue
				}
				result = append(result, presentedCredentialEnvelope{
					CredentialID: strings.TrimSpace(asString(credentialID)),
					Format:       strings.TrimSpace(asString(format)),
					Credential:   vcStr,
				})
			}
		}
	}
	if len(result) == 0 {
		credentialJWT, _ := vpObject["credential_jwt"].(string)
		credentialJWT = strings.TrimSpace(credentialJWT)
		if credentialJWT == "" {
			return nil, fmt.Errorf("presented credential is missing")
		}
		format, _ := vpObject["format"].(string)
		result = append(result, presentedCredentialEnvelope{
			Format:     strings.TrimSpace(format),
			Credential: credentialJWT,
		})
	}
	return result, nil
}

func normalizePresentedCredentialValueOID4VP(raw interface{}) (string, error) {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed), nil
	case map[string]interface{}, []interface{}:
		serialized, err := json.Marshal(typed)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(serialized)), nil
	default:
		if raw == nil {
			return "", nil
		}
		serialized, err := json.Marshal(raw)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(serialized)), nil
	}
}

func extractProofObjectsOID4VP(raw interface{}) ([]map[string]interface{}, error) {
	switch typed := raw.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{typed}, nil
	case []interface{}:
		proofs := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			proofMap, ok := item.(map[string]interface{})
			if ok {
				proofs = append(proofs, proofMap)
			}
		}
		return proofs, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported proof type %T", raw)
	}
}

func proofVerificationMethodID(raw interface{}) string {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]interface{}:
		return strings.TrimSpace(asString(typed["id"]))
	default:
		return ""
	}
}

func verificationMethodBoundToHolder(methodID string, holder string) bool {
	normalizedMethodID := strings.TrimSpace(methodID)
	normalizedHolder := strings.TrimSpace(holder)
	if normalizedMethodID == "" || normalizedHolder == "" {
		return false
	}
	return normalizedMethodID == normalizedHolder || strings.HasPrefix(normalizedMethodID, normalizedHolder+"#")
}

func findStoredCredentialLineage(
	records []vc.WalletCredentialRecord,
	presented presentedCredentialEnvelope,
	rawCredential string,
	issuerSignedJWT string,
	credentialFormat string,
	credentialVCT string,
	doctype string,
) (vc.WalletCredentialRecord, bool) {
	normalizedCredentialID := strings.TrimSpace(presented.CredentialID)
	normalizedFormat := strings.TrimSpace(credentialFormat)
	normalizedVCT := strings.TrimSpace(credentialVCT)
	normalizedDoctype := strings.TrimSpace(doctype)
	for _, record := range records {
		if normalizedCredentialID != "" && strings.TrimSpace(record.CredentialID) == normalizedCredentialID {
			return record, true
		}
	}
	for _, record := range records {
		if strings.TrimSpace(record.CredentialJWT) == strings.TrimSpace(rawCredential) {
			return record, true
		}
		storedIssuerJWT := strings.TrimSpace(record.IssuerSignedJWT)
		if storedIssuerJWT == "" {
			if envelope, err := vc.ParseSDJWTEnvelope(strings.TrimSpace(record.CredentialJWT)); err == nil {
				storedIssuerJWT = strings.TrimSpace(envelope.IssuerSignedJWT)
			}
		}
		if storedIssuerJWT != "" && storedIssuerJWT == strings.TrimSpace(issuerSignedJWT) {
			return record, true
		}
	}
	for _, record := range records {
		recordFormat := strings.TrimSpace(record.Format)
		if normalizedFormat != "" && recordFormat != "" && normalizedFormat != recordFormat {
			continue
		}
		if normalizedVCT != "" && strings.TrimSpace(record.VCT) != "" && strings.TrimSpace(record.VCT) != normalizedVCT {
			continue
		}
		if normalizedDoctype != "" && strings.TrimSpace(record.Doctype) != "" && strings.TrimSpace(record.Doctype) != normalizedDoctype {
			continue
		}
		return record, true
	}
	return vc.WalletCredentialRecord{}, false
}

func parseDCQLCredentialRequirements(rawDCQLQuery string) []dcqlCredentialRequirement {
	return vc.ParseDCQLCredentialRequirements(rawDCQLQuery)
}

func requirementMatchesEvidence(requirement dcqlCredentialRequirement, evidence models.OID4VPCredentialEvidence) (bool, string, string) {
	return vc.RequirementMatchesEvidence(requirement, vc.DCQLCredentialEvidence{
		Format:          evidence.Format,
		VCT:             evidence.VCT,
		Doctype:         evidence.Doctype,
		CredentialTypes: evidence.CredentialTypes,
		FullClaims:      evidence.FullClaims,
	})
}

func mergeClaimPaths(existing []string, additions []string) []string {
	if len(additions) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing)+len(additions))
	merged := make([]string, 0, len(existing)+len(additions))
	for _, item := range existing {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		merged = append(merged, normalized)
	}
	for _, item := range additions {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		merged = append(merged, normalized)
	}
	sort.Strings(merged)
	return merged
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if normalized := strings.TrimSpace(value); normalized != "" {
			return normalized
		}
	}
	return ""
}

type verifierPolicyError struct {
	Code    string
	Message string
	Cause   error
}

func (e *verifierPolicyError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

func (e *verifierPolicyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func newVerifierPolicyError(code string, message string, cause error) error {
	return &verifierPolicyError{
		Code:    strings.TrimSpace(code),
		Message: strings.TrimSpace(message),
		Cause:   cause,
	}
}

func asVerifierPolicyError(err error) (*verifierPolicyError, bool) {
	var policyErr *verifierPolicyError
	if errors.As(err, &policyErr) {
		return policyErr, true
	}
	return nil, false
}

func addPolicyReason(result *models.OID4VPVerificationResult, code string, message string) {
	if result == nil {
		return
	}
	normalizedCode := strings.TrimSpace(code)
	normalizedMessage := strings.TrimSpace(message)
	if normalizedCode == "" || normalizedMessage == "" {
		return
	}
	for idx := range result.Policy.ReasonCodes {
		if result.Policy.ReasonCodes[idx] == normalizedCode {
			return
		}
	}
	result.Policy.ReasonCodes = append(result.Policy.ReasonCodes, normalizedCode)
	result.Policy.Reasons = append(result.Policy.Reasons, normalizedMessage)
}

func containsPolicyCode(result *models.OID4VPVerificationResult, code string) bool {
	if result == nil {
		return false
	}
	for _, rc := range result.Policy.ReasonCodes {
		if rc == code {
			return true
		}
	}
	return false
}

func finalizePolicyDecision(result *models.OID4VPVerificationResult) {
	if result == nil {
		return
	}
	if len(result.Policy.ReasonCodes) == 0 || len(result.Policy.Reasons) == 0 {
		result.Policy.Code = "verification_failed"
		result.Policy.Message = "Presentation failed verifier policy checks"
		return
	}
	result.Policy.Code = result.Policy.ReasonCodes[0]
	result.Policy.Message = "Presentation denied: " + result.Policy.Reasons[0]
}

func credentialVerificationKeyFromJWK(jwk crypto.JWK) (interface{}, string, error) {
	switch strings.ToUpper(strings.TrimSpace(jwk.Kty)) {
	case "RSA":
		key, err := crypto.ParseRSAPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, "", fmt.Errorf("parse issuer rsa jwk: %w", err)
		}
		return key, "RS", nil
	case "EC":
		key, err := crypto.ParseECPublicKeyFromJWK(jwk)
		if err != nil {
			return nil, "", fmt.Errorf("parse issuer ec jwk: %w", err)
		}
		return key, "ES", nil
	default:
		return nil, "", fmt.Errorf("unsupported issuer jwk kty %q", jwk.Kty)
	}
}

func parseWalletResponsePayload(r *http.Request) (*walletResponsePayload, error) {
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var payload walletResponsePayload
		if err := jsonDecode(r, &payload); err != nil {
			return nil, err
		}
		return &payload, nil
	}
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("invalid response payload")
	}
	return &walletResponsePayload{
		State:    strings.TrimSpace(r.FormValue("state")),
		VPToken:  strings.TrimSpace(r.FormValue("vp_token")),
		Response: strings.TrimSpace(r.FormValue("response")),
	}, nil
}

func audienceIncludes(rawAudience interface{}, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	switch value := rawAudience.(type) {
	case string:
		return strings.TrimSpace(value) == expected
	case []interface{}:
		for _, candidate := range value {
			if candidateString, ok := candidate.(string); ok && strings.TrimSpace(candidateString) == expected {
				return true
			}
		}
	}
	return false
}

func asString(raw interface{}) string {
	if raw == nil {
		return ""
	}
	switch typed := raw.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
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
