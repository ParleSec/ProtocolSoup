package oid4vp

import (
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
	credentialFormatMSOMDOC    = "mso_mdoc"
	credentialFormatJWTVCJSON  = "jwt_vc_json"
	credentialFormatJWTVCJSONL = "jwt_vc_json-ld"
	credentialFormatLDPVC      = "ldp_vc"
)

type createAuthorizationRequest struct {
	ClientID     string          `json:"client_id"`
	ResponseMode string          `json:"response_mode"`
	ResponseURI  string          `json:"response_uri"`
	RedirectURI  string          `json:"redirect_uri,omitempty"`
	Scope        string          `json:"scope,omitempty"`
	DCQLQuery    json.RawMessage `json:"dcql_query,omitempty"`
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

	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientID == "" {
		req.ClientID = defaultVerifierClientID
	}
	req.ResponseMode = strings.TrimSpace(req.ResponseMode)
	if req.ResponseMode == "" {
		req.ResponseMode = "direct_post"
	}
	req.ResponseURI = strings.TrimSpace(req.ResponseURI)
	if req.ResponseURI == "" {
		req.ResponseURI = p.verifierBaseURL() + "/response"
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
	if err := ValidateSupportedClientIDScheme(req.ClientID, p.supportedClientIDSchemes); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_client", err.Error())
		return
	}

	clientIDScheme, err := ParseClientIDScheme(req.ClientID)
	if err != nil {
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
		"iss":           req.ClientID,
		"aud":           "wallet",
		"client_id":     req.ClientID,
		"response_type": "vp_token",
		"response_mode": req.ResponseMode,
		"response_uri":  req.ResponseURI,
		"nonce":         nonce,
		"state":         state,
		"iat":           now.Unix(),
		"exp":           now.Add(requestObjectTTL).Unix(),
		"jti":           requestID,
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

	requestObject := jwt.NewWithClaims(jwt.SigningMethodRS256, requestClaims)
	requestObject.Header["typ"] = "oauth-authz-req+jwt"
	requestObject.Header["kid"] = p.keySet.RSAKeyID()
	if err := ValidateRequestObjectType(fmt.Sprint(requestObject.Header["typ"])); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request_object", err.Error())
		return
	}
	requestJWT, err := requestObject.SignedString(p.keySet.RSAPrivateKey())
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

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"OID4VP Authorization Request Created",
		map[string]interface{}{
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
		},
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
	if err := validateRequestObjectTyp(session.RequestJWT); err != nil {
		writeOID4VPError(w, http.StatusBadRequest, "invalid_request_object", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"request":             session.RequestJWT,
		"request_id":          requestID,
		"request_uri_method":  "post",
		"dcql_query_supplied": session.DCQLQuery != "",
	})
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

	decodedToken, err := crypto.DecodeTokenWithoutValidation(trimmedToken)
	if err != nil {
		return nil, fmt.Errorf("token decode failed: %w", err)
	}

	subject := ""
	if claimSub, ok := decodedToken.Payload["sub"].(string); ok {
		subject = strings.TrimSpace(claimSub)
	}
	if subject == "" {
		if claimIss, ok := decodedToken.Payload["iss"].(string); ok {
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

	cnfMap, _ := decodedToken.Payload["cnf"].(map[string]interface{})
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
	if strings.TrimSpace(cnfJKT) == "" {
		return nil, fmt.Errorf("token cnf.jkt is required")
	}
	if strings.TrimSpace(cnfJKT) != thumbprint {
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

type presentedCredentialEnvelope struct {
	CredentialID string
	Format       string
	Credential   string
}

type dcqlCredentialRequirement struct {
	ID                   string
	Format               string
	VCTValues            []string
	DoctypeValues        []string
	CredentialTypeValues []string
	RequiredClaimPaths   []string
}

func (p *Plugin) validatePresentedCredentials(
	vpClaims jwt.MapClaims,
	walletSubject string,
	session *requestSession,
) ([]models.OID4VPCredentialEvidence, error) {
	normalizedSubject := strings.TrimSpace(walletSubject)
	if normalizedSubject == "" {
		return nil, newVerifierPolicyError("holder_binding_mismatch", "wallet subject is missing", nil)
	}
	vpObject, ok := vpClaims["vp"].(map[string]interface{})
	if !ok {
		return nil, newVerifierPolicyError("credential_missing", "vp claim is missing", nil)
	}
	presentedCredentials, err := extractPresentedCredentialEnvelopes(vpObject)
	if err != nil {
		return nil, newVerifierPolicyError("credential_missing", err.Error(), nil)
	}
	if p.walletStore == nil {
		return nil, newVerifierPolicyError("missing_lineage", "wallet credential lineage store is unavailable", nil)
	}
	storedCredentials := p.walletStore.List(normalizedSubject)
	if len(storedCredentials) == 0 {
		return nil, newVerifierPolicyError("missing_lineage", "presented credential lineage was not found", nil)
	}

	evidenceSet := make([]models.OID4VPCredentialEvidence, 0, len(presentedCredentials))
	for _, presented := range presentedCredentials {
		rawCredential := strings.TrimSpace(presented.Credential)
		if rawCredential == "" {
			continue
		}

		credentialFormat := strings.TrimSpace(presented.Format)
		issuerSignedJWT := rawCredential
		disclosureClaims := make(map[string]interface{})
		var disclosures []string
		shouldParseSDJWTEnvelope := credentialFormat == credentialFormatDCSdJWT || strings.Contains(rawCredential, "~")
		if shouldParseSDJWTEnvelope {
			if parsedEnvelope, parseErr := vc.ParseSDJWTEnvelope(rawCredential); parseErr == nil {
				issuerSignedJWT = strings.TrimSpace(parsedEnvelope.IssuerSignedJWT)
				disclosures = append(disclosures, parsedEnvelope.Disclosures...)
				if credentialFormat == "" && len(parsedEnvelope.Disclosures) > 0 {
					credentialFormat = credentialFormatDCSdJWT
				}
			}
		}
		decodedCredential, err := crypto.DecodeTokenWithoutValidation(issuerSignedJWT)
		if err != nil {
			return nil, newVerifierPolicyError("credential_malformed", "presented credential decode failed", err)
		}

		credentialSub, _ := decodedCredential.Payload["sub"].(string)
		if strings.TrimSpace(credentialSub) != normalizedSubject {
			return nil, newVerifierPolicyError("credential_subject_mismatch", "presented credential subject mismatch", nil)
		}
		if credentialFormat == "" {
			credentialFormat = inferCredentialFormat(decodedCredential)
		}

		credentialVCT, _ := decodedCredential.Payload["vct"].(string)
		credentialVCT = strings.TrimSpace(credentialVCT)
		doctype, _ := decodedCredential.Payload["doctype"].(string)
		doctype = strings.TrimSpace(doctype)

		storedRecord, found := findStoredCredentialLineage(storedCredentials, presented, rawCredential, issuerSignedJWT, credentialFormat, credentialVCT, doctype)
		if !found {
			return nil, newVerifierPolicyError("missing_lineage", "presented credential does not match stored issuance lineage", nil)
		}

		verificationKey, expectedAlgPrefix, err := credentialVerificationKeyFromJWK(storedRecord.IssuerJWK)
		if err != nil {
			return nil, newVerifierPolicyError("credential_signature_invalid", "issuer verification key is invalid", err)
		}
		parsedCredential, err := jwt.Parse(issuerSignedJWT, func(token *jwt.Token) (interface{}, error) {
			if !strings.HasPrefix(token.Method.Alg(), expectedAlgPrefix) {
				return nil, fmt.Errorf("credential jwt uses unexpected algorithm")
			}
			kid, _ := token.Header["kid"].(string)
			if storedRecord.IssuerJWK.Kid != "" && kid != "" && storedRecord.IssuerJWK.Kid != kid {
				return nil, fmt.Errorf("credential kid mismatch")
			}
			return verificationKey, nil
		}, jwt.WithoutClaimsValidation())
		if err != nil || !parsedCredential.Valid {
			return nil, newVerifierPolicyError("credential_signature_invalid", "presented credential signature validation failed", err)
		}
		credentialClaims, ok := parsedCredential.Claims.(jwt.MapClaims)
		if !ok {
			return nil, newVerifierPolicyError("credential_malformed", "presented credential claims are invalid", nil)
		}
		issuer, _ := credentialClaims["iss"].(string)
		if strings.TrimSpace(storedRecord.Issuer) != "" && strings.TrimSpace(issuer) != strings.TrimSpace(storedRecord.Issuer) {
			return nil, newVerifierPolicyError("credential_issuer_mismatch", "presented credential issuer mismatch", nil)
		}
		if !claimExpiryIsValid(credentialClaims["exp"]) {
			return nil, newVerifierPolicyError("credential_expired", "presented credential expired", nil)
		}

		fullClaims := extractCredentialSubjectClaims(credentialClaims)
		if credentialFormat == credentialFormatMSOMDOC {
			if mdocObject, ok := credentialClaims["mdoc"].(map[string]interface{}); ok {
				if namespaces, hasNamespaces := mdocObject["namespaces"].(map[string]interface{}); hasNamespaces {
					for claimName, claimValue := range namespaces {
						if _, exists := fullClaims[claimName]; exists {
							continue
						}
						fullClaims[claimName] = claimValue
					}
				} else {
					for claimName, claimValue := range mdocObject {
						if _, exists := fullClaims[claimName]; exists {
							continue
						}
						fullClaims[claimName] = claimValue
					}
				}
			}
		}
		if credentialFormat == credentialFormatDCSdJWT {
			digestAllowList := credentialDigestAllowList(credentialClaims)
			decodedDisclosures, decodeErr := vc.DecodeAndVerifyDisclosures(disclosures, digestAllowList)
			if decodeErr != nil {
				return nil, newVerifierPolicyError("disclosure_invalid", "presented disclosures failed validation", decodeErr)
			}
			disclosureClaims = vc.DisclosedClaimMap(decodedDisclosures)
			for claimName, claimValue := range disclosureClaims {
				fullClaims[claimName] = claimValue
			}
		}
		credentialTypes := extractCredentialTypeValues(credentialClaims)
		if len(credentialTypes) == 0 {
			credentialTypes = append(credentialTypes, storedRecord.CredentialTypes...)
		}

		evidence := models.OID4VPCredentialEvidence{
			Subject:                   normalizedSubject,
			Format:                    credentialFormat,
			CredentialConfigurationID: strings.TrimSpace(storedRecord.CredentialConfigurationID),
			VCT:                       firstNonEmpty(credentialVCT, strings.TrimSpace(storedRecord.VCT)),
			Doctype:                   firstNonEmpty(doctype, strings.TrimSpace(storedRecord.Doctype)),
			CredentialTypes:           dedupeStrings(credentialTypes),
			Issuer:                    strings.TrimSpace(issuer),
			RequiredClaimPaths:        nil,
			DisclosedClaims:           disclosureClaims,
			FullClaims:                fullClaims,
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

func inferCredentialFormat(decodedCredential *crypto.DecodedToken) string {
	if decodedCredential == nil {
		return ""
	}
	if typ, ok := decodedCredential.Header["typ"].(string); ok {
		switch strings.TrimSpace(typ) {
		case "vc+sd-jwt":
			return credentialFormatDCSdJWT
		case "mdoc+jwt":
			return credentialFormatMSOMDOC
		case "vc+ldp-jwt":
			return credentialFormatLDPVC
		}
	}
	vcObject, _ := decodedCredential.Payload["vc"].(map[string]interface{})
	if credentialSubject, ok := vcObject["credentialSubject"].(map[string]interface{}); ok {
		if _, hasSD := credentialSubject["_sd"]; hasSD {
			return credentialFormatDCSdJWT
		}
	}
	if _, hasDoctype := decodedCredential.Payload["doctype"]; hasDoctype {
		return credentialFormatMSOMDOC
	}
	if _, hasContext := vcObject["@context"]; hasContext {
		return credentialFormatJWTVCJSONL
	}
	return credentialFormatJWTVCJSON
}

func extractCredentialTypeValues(credentialClaims jwt.MapClaims) []string {
	vcObject, _ := credentialClaims["vc"].(map[string]interface{})
	return normalizeStringSlice(vcObject["type"])
}

func normalizeStringSlice(raw interface{}) []string {
	values := make([]string, 0)
	switch typed := raw.(type) {
	case string:
		if normalized := strings.TrimSpace(typed); normalized != "" {
			values = append(values, normalized)
		}
	case []interface{}:
		for _, item := range typed {
			itemString, _ := item.(string)
			itemString = strings.TrimSpace(itemString)
			if itemString == "" {
				continue
			}
			values = append(values, itemString)
		}
	}
	return dedupeStrings(values)
}

func parseDCQLCredentialRequirements(rawDCQLQuery string) []dcqlCredentialRequirement {
	trimmed := strings.TrimSpace(rawDCQLQuery)
	if trimmed == "" {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return nil
	}
	rawCredentials, _ := payload["credentials"].([]interface{})
	requirements := make([]dcqlCredentialRequirement, 0, len(rawCredentials))
	for _, rawCredential := range rawCredentials {
		credentialObject, _ := rawCredential.(map[string]interface{})
		requirement := dcqlCredentialRequirement{
			ID:     strings.TrimSpace(asString(credentialObject["id"])),
			Format: strings.TrimSpace(asString(credentialObject["format"])),
		}
		if meta, ok := credentialObject["meta"].(map[string]interface{}); ok {
			requirement.VCTValues = normalizeStringSlice(meta["vct_values"])
			requirement.DoctypeValues = normalizeStringSlice(meta["doctype_values"])
			if len(requirement.DoctypeValues) == 0 {
				if singleDoctype := strings.TrimSpace(asString(meta["doctype"])); singleDoctype != "" {
					requirement.DoctypeValues = []string{singleDoctype}
				}
			}
			requirement.CredentialTypeValues = normalizeStringSlice(meta["type_values"])
		}
		rawClaims, _ := credentialObject["claims"].([]interface{})
		requiredPaths := make([]string, 0, len(rawClaims))
		for _, rawClaim := range rawClaims {
			claimObject, _ := rawClaim.(map[string]interface{})
			rawPath, _ := claimObject["path"].([]interface{})
			segments := make([]string, 0, len(rawPath))
			for _, rawSegment := range rawPath {
				segment := strings.TrimSpace(asString(rawSegment))
				if segment == "" {
					continue
				}
				segments = append(segments, segment)
			}
			if len(segments) == 0 {
				continue
			}
			requiredPaths = append(requiredPaths, strings.Join(segments, "."))
		}
		requirement.RequiredClaimPaths = dedupeStrings(requiredPaths)
		sort.Strings(requirement.RequiredClaimPaths)
		requirements = append(requirements, requirement)
	}
	return requirements
}

func requirementMatchesEvidence(requirement dcqlCredentialRequirement, evidence models.OID4VPCredentialEvidence) (bool, string, string) {
	if requirement.Format != "" && strings.TrimSpace(evidence.Format) != requirement.Format {
		return false, "dcql_format_mismatch", fmt.Sprintf("credential format %q does not satisfy requested format %q", evidence.Format, requirement.Format)
	}
	if len(requirement.VCTValues) > 0 && !containsString(requirement.VCTValues, strings.TrimSpace(evidence.VCT)) {
		return false, "dcql_meta_mismatch", "credential vct does not satisfy dcql vct_values"
	}
	if len(requirement.DoctypeValues) > 0 && !containsString(requirement.DoctypeValues, strings.TrimSpace(evidence.Doctype)) {
		return false, "dcql_meta_mismatch", "credential doctype does not satisfy dcql doctype_values"
	}
	if len(requirement.CredentialTypeValues) > 0 && !intersectsStringSlice(requirement.CredentialTypeValues, evidence.CredentialTypes) {
		return false, "dcql_meta_mismatch", "credential type does not satisfy dcql type_values"
	}
	for _, claimPath := range requirement.RequiredClaimPaths {
		if !hasClaimPath(evidence.FullClaims, claimPath) {
			return false, "missing_required_claim", fmt.Sprintf("required claim %q is missing from disclosed credential data", claimPath)
		}
	}
	return true, "", ""
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

func intersectsStringSlice(left []string, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	lookup := make(map[string]struct{}, len(right))
	for _, value := range right {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		lookup[normalized] = struct{}{}
	}
	for _, value := range left {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		if _, ok := lookup[normalized]; ok {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
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

func credentialDigestAllowList(credentialClaims jwt.MapClaims) []string {
	allowList := make([]string, 0)
	vcObject, _ := credentialClaims["vc"].(map[string]interface{})
	credentialSubject, _ := vcObject["credentialSubject"].(map[string]interface{})
	rawDigests, _ := credentialSubject["_sd"].([]interface{})
	for _, item := range rawDigests {
		if digest, ok := item.(string); ok {
			normalized := strings.TrimSpace(digest)
			if normalized != "" {
				allowList = append(allowList, normalized)
			}
		}
	}
	return allowList
}

func extractCredentialSubjectClaims(credentialClaims jwt.MapClaims) map[string]interface{} {
	claims := make(map[string]interface{})
	vcObject, _ := credentialClaims["vc"].(map[string]interface{})
	credentialSubject, _ := vcObject["credentialSubject"].(map[string]interface{})
	for claimName, claimValue := range credentialSubject {
		if claimName == "_sd" || claimName == "_sd_alg" {
			continue
		}
		claims[claimName] = claimValue
	}
	return claims
}

func hasClaimPath(claims map[string]interface{}, claimPath string) bool {
	segments := strings.Split(strings.TrimSpace(claimPath), ".")
	if len(segments) == 0 {
		return false
	}
	var current interface{} = claims
	for idx, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return false
		}
		object, ok := current.(map[string]interface{})
		if !ok {
			return false
		}
		value, exists := object[segment]
		if !exists {
			return false
		}
		if idx == len(segments)-1 {
			return true
		}
		current = value
	}
	return false
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
