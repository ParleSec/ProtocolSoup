package oid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
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
	p.mu.Unlock()

	p.emitEvent(
		sessionID,
		lookingglass.EventTypeFlowStep,
		"OID4VP Authorization Request Created",
		map[string]interface{}{
			"request_id":       requestID,
			"client_id":        req.ClientID,
			"client_id_scheme": string(clientIDScheme),
			"response_mode":    req.ResponseMode,
			"response_uri":     req.ResponseURI,
			"has_dcql_query":   dcqlQuery != "",
			"scope_alias":      req.Scope,
			"nonce":            nonce,
			"state":            state,
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
		"request_id":          requestID,
		"request_uri":         p.verifierBaseURL() + "/request/" + requestID,
		"request_uri_method":  "get",
		"request":             requestJWT,
		"response_mode":       req.ResponseMode,
		"response_uri":        req.ResponseURI,
		"state":               state,
		"nonce":               nonce,
		"client_id":           req.ClientID,
		"client_id_scheme":    string(clientIDScheme),
		"expires_in_seconds":  int(requestObjectTTL.Seconds()),
		"dcql_query_supplied": dcqlQuery != "",
	})
}

func (p *Plugin) handleGetAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
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
	session.Result = result
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
			EvaluatedAt: time.Now().UTC(),
		},
	}
	walletContext, err := p.resolvePresentedWalletContext(vpToken, "")
	if err != nil {
		result.Policy.Reasons = append(result.Policy.Reasons, err.Error())
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
	})
	if err != nil || !parsed.Valid {
		result.Policy.Reasons = append(result.Policy.Reasons, "vp_token signature validation failed")
		return result
	}
	if err := ValidateVPTokenType(fmt.Sprint(parsed.Header["typ"])); err != nil {
		result.Policy.Reasons = append(result.Policy.Reasons, err.Error())
		return result
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		result.Policy.Reasons = append(result.Policy.Reasons, "vp_token claims are invalid")
		return result
	}

	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	if strings.TrimSpace(issuer) != walletContext.Subject || strings.TrimSpace(subject) != walletContext.Subject {
		result.Policy.Reasons = append(result.Policy.Reasons, "holder subject does not match wallet identity")
	}
	cnfMap, _ := claims["cnf"].(map[string]interface{})
	cnfJKT, _ := cnfMap["jkt"].(string)
	if strings.TrimSpace(cnfJKT) != walletContext.BindingThumbprint {
		result.Policy.Reasons = append(result.Policy.Reasons, "holder key thumbprint mismatch")
	}
	if strings.TrimSpace(issuer) == walletContext.Subject && strings.TrimSpace(subject) == walletContext.Subject && strings.TrimSpace(cnfJKT) == walletContext.BindingThumbprint {
		result.HolderBindingVerified = true
	}

	if nonceClaim, _ := claims["nonce"].(string); nonceClaim == session.Nonce {
		result.NonceValidated = true
	} else {
		result.Policy.Reasons = append(result.Policy.Reasons, "nonce mismatch")
	}

	if audienceIncludes(claims["aud"], session.ClientID) {
		result.AudienceValidated = true
	} else {
		result.Policy.Reasons = append(result.Policy.Reasons, "audience mismatch")
	}

	expiryValid := claimExpiryIsValid(claims["exp"])
	result.ExpiryValidated = expiryValid
	if !expiryValid {
		result.Policy.Reasons = append(result.Policy.Reasons, "vp_token expired")
	}

	if err := p.validatePresentedCredential(claims, walletContext.Subject); err != nil {
		result.Policy.Reasons = append(result.Policy.Reasons, err.Error())
		result.HolderBindingVerified = false
	}

	result.Policy.Allowed = result.NonceValidated && result.AudienceValidated && result.ExpiryValidated && result.HolderBindingVerified
	if result.Policy.Allowed {
		result.Policy.Code = "allowed"
		result.Policy.Message = "Presentation accepted"
		result.Policy.Reasons = nil
	}
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
	})
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

func (p *Plugin) validatePresentedCredential(vpClaims jwt.MapClaims, walletSubject string) error {
	normalizedSubject := strings.TrimSpace(walletSubject)
	if normalizedSubject == "" {
		return fmt.Errorf("wallet subject is missing")
	}
	vpObject, ok := vpClaims["vp"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("vp claim is missing")
	}
	credentialJWT, _ := vpObject["credential_jwt"].(string)
	if strings.TrimSpace(credentialJWT) == "" {
		return fmt.Errorf("presented credential is missing")
	}

	decodedCredential, err := crypto.DecodeTokenWithoutValidation(credentialJWT)
	if err != nil {
		return fmt.Errorf("presented credential decode failed: %w", err)
	}
	credentialSub, _ := decodedCredential.Payload["sub"].(string)
	if strings.TrimSpace(credentialSub) != normalizedSubject {
		return fmt.Errorf("presented credential subject mismatch")
	}
	credentialVCT, _ := decodedCredential.Payload["vct"].(string)
	credentialVCT = strings.TrimSpace(credentialVCT)
	if credentialVCT == "" {
		return fmt.Errorf("presented credential vct is missing")
	}
	if p.walletStore == nil {
		return fmt.Errorf("wallet credential store is unavailable")
	}
	storedRecord, found := p.walletStore.Get(normalizedSubject, credentialVCT)
	if !found {
		return fmt.Errorf("presented credential is not available in wallet store")
	}
	if strings.TrimSpace(storedRecord.CredentialJWT) != strings.TrimSpace(credentialJWT) {
		return fmt.Errorf("presented credential does not match wallet store record")
	}

	verificationKey, expectedAlgPrefix, err := credentialVerificationKeyFromJWK(storedRecord.IssuerJWK)
	if err != nil {
		return err
	}

	parsedCredential, err := jwt.Parse(credentialJWT, func(token *jwt.Token) (interface{}, error) {
		if !strings.HasPrefix(token.Method.Alg(), expectedAlgPrefix) {
			return nil, fmt.Errorf("credential jwt uses unexpected algorithm")
		}
		kid, _ := token.Header["kid"].(string)
		if storedRecord.IssuerJWK.Kid != "" && kid != "" && storedRecord.IssuerJWK.Kid != kid {
			return nil, fmt.Errorf("credential kid mismatch")
		}
		return verificationKey, nil
	})
	if err != nil || !parsedCredential.Valid {
		return fmt.Errorf("presented credential signature validation failed")
	}

	credentialClaims, ok := parsedCredential.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("presented credential claims are invalid")
	}
	issuer, _ := credentialClaims["iss"].(string)
	if strings.TrimSpace(storedRecord.Issuer) != "" && strings.TrimSpace(issuer) != strings.TrimSpace(storedRecord.Issuer) {
		return fmt.Errorf("presented credential issuer mismatch")
	}
	if !claimExpiryIsValid(credentialClaims["exp"]) {
		return fmt.Errorf("presented credential expired")
	}
	return nil
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
