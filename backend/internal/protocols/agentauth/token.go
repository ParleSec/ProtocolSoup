package agentauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/golang-jwt/jwt/v5"
)

// handleToken is the authorization server's token endpoint. It accepts the JWT
// bearer authorization grant of RFC 7523 Section 2.1 and the auth.md claim
// grant an agent polls while a claim ceremony is outstanding.
func (p *Plugin) handleToken(w http.ResponseWriter, r *http.Request) {
	sessionID := p.sessionFromRequest(r)

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body")
		return
	}

	switch grantType := r.PostFormValue("grant_type"); grantType {
	case grantTypeJWTBearer:
		p.handleJWTBearerGrant(w, r, sessionID)
	case grantTypeClaim:
		p.handleClaimGrant(w, r, sessionID)
	case "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `"grant_type" is required`)
	default:
		// RFC 6749 Section 5.2: unsupported_grant_type is the defined error
		// when the grant is not supported by the authorization server.
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("Unsupported grant_type %q; this server supports %q and %q",
				grantType, grantTypeJWTBearer, grantTypeClaim))
	}
}

// handleJWTBearerGrant exchanges an identity assertion for an access token.
//
// RFC 7523 Section 2.1 fixes the request shape: grant_type is the jwt-bearer
// URN and the assertion parameter carries a single JWT. Section 3 lists what
// the authorization server must check before honouring it, and every one of
// those checks happens in validateIdentityAssertion below.
func (p *Plugin) handleJWTBearerGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	assertion := r.PostFormValue("assertion")
	if assertion == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			`"assertion" is required for the JWT bearer grant`)
		return
	}

	claims, err := p.validateIdentityAssertion(assertion)
	if err != nil {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Identity assertion rejected",
			map[string]interface{}{
				"reason":     err.Error(),
				"grant_type": grantTypeJWTBearer,
			},
			lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeExplanation,
				Title:       "A failed assertion is always invalid_grant",
				Description: "RFC 7523 collapses every assertion failure into a single error so a caller cannot distinguish a bad signature from an unknown subject or a replayed token, which would otherwise be an oracle.",
				Reference:   "RFC 7523 Section 3.1",
			})
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	agentID, _ := claims["sub"].(string)
	claimed, _ := claims["claimed"].(bool)

	scope := scopePreClaim
	if claimed {
		scope = scopePostClaim
	}

	accessToken, err := p.mintAccessToken(agentID, scope, claimed)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not sign the access token")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Access token issued to agent",
		map[string]interface{}{
			"agent_id":   agentID,
			"grant_type": grantTypeJWTBearer,
			"claimed":    claimed,
			"scope":      scope,
			"expires_in": int(accessTokenTTL.Seconds()),
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "Scope follows the agent's standing",
			Description: "An unclaimed agent receives the pre-claim scope. The same assertion presented after a claim ceremony has claimed=true and earns the wider scope, so authorization tracks ownership rather than the credential itself.",
			Reference:   "auth.md, Anonymous Registration with Claim Ceremony",
		})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"scope":        scope,
	})
}

// handleClaimGrant is polled by an agent while a person decides whether to
// approve it. The polling semantics are those of RFC 8628 Section 3.5:
// authorization_pending until approval, slow_down when the agent polls faster
// than the advertised interval, and expired_token once the code lapses.
func (p *Plugin) handleClaimGrant(w http.ResponseWriter, r *http.Request, sessionID string) {
	claimToken := r.PostFormValue("claim_token")
	if claimToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			`"claim_token" is required for the claim grant`)
		return
	}

	now := time.Now()

	p.mu.Lock()
	identity, ok := p.identities[claimToken]
	if !ok || now.After(identity.ExpiresAt) {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Unknown or expired claim_token")
		return
	}
	if identity.Revoked {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "This agent registration was revoked")
		return
	}

	var attempt *claimAttempt
	for _, candidate := range p.attempts {
		if candidate.ClaimToken == claimToken {
			attempt = candidate
			break
		}
	}
	if attempt == nil {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"No claim attempt is outstanding; start one at the claim endpoint first")
		return
	}

	// RFC 8628 Section 3.5: a client polling faster than the interval it was
	// given gets slow_down, and every slow_down raises the required interval
	// by five seconds.
	if !attempt.LastPolledAt.IsZero() && now.Sub(attempt.LastPolledAt) < pollInterval {
		attempt.LastPolledAt = now
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "slow_down",
			fmt.Sprintf("Poll no more than once every %d seconds", int(pollInterval.Seconds())))
		return
	}
	attempt.LastPolledAt = now

	if now.After(attempt.ExpiresAt) {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "expired_token",
			"The user_code expired; request a new one at the claim endpoint")
		return
	}
	if !attempt.Completed {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending",
			"The person has not approved this agent yet")
		return
	}

	// Approval has landed. Promote the agent and retire the attempt so the
	// same user_code cannot be redeemed twice.
	identity.Claimed = true
	identity.Email = attempt.Email
	identity.AssertionVersion++
	delete(p.attempts, attempt.UserCode)

	promoted := *identity
	p.mu.Unlock()

	assertion, _, err := p.mintIdentityAssertion(&promoted)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not sign the identity assertion")
		return
	}
	accessToken, err := p.mintAccessToken(promoted.AgentID, scopePostClaim, true)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Could not sign the access token")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Claim completed, agent promoted",
		map[string]interface{}{
			"agent_id":          promoted.AgentID,
			"grant_type":        grantTypeClaim,
			"owner_email":       promoted.Email,
			"assertion_version": promoted.AssertionVersion,
			"scope":             scopePostClaim,
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "A second assertion replaces the first",
			Description: "The agent is handed a new assertion carrying claimed=true and an incremented version rather than an edit of the old one. The pre-claim assertion keeps saying what was true when it was issued, which is what makes either one safe to audit.",
			Reference:   "auth.md, Anonymous Registration with Claim Ceremony",
		})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":       accessToken,
		"token_type":         "Bearer",
		"expires_in":         int(accessTokenTTL.Seconds()),
		"scope":              scopePostClaim,
		"identity_assertion": assertion,
		"claimed":            true,
		"owner_email":        promoted.Email,
	})
}

// validateIdentityAssertion applies the checks RFC 7523 Section 3 requires of
// an authorization server before it accepts a JWT as an authorization grant.
func (p *Plugin) validateIdentityAssertion(assertion string) (jwt.MapClaims, error) {
	if p.keySet == nil {
		return nil, errors.New("no verification key is available")
	}

	publicKey, ok := p.keySet.RSAPrivateKey().Public().(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("no verification key is available")
	}

	// The assertion MUST be digitally signed and the server MUST reject one
	// whose signature does not verify. Pinning the algorithm prevents an
	// attacker choosing "none" or substituting a symmetric algorithm.
	parsed, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("unexpected signing algorithm %v", token.Header["alg"])
		}
		return publicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
		// exp is REQUIRED and an expired assertion MUST be rejected; nbf is
		// honoured when present.
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(p.issuer()),
		jwt.WithAudience(p.issuer()),
	)
	if err != nil {
		return nil, fmt.Errorf("the assertion did not verify: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("the assertion carries no claim set")
	}

	// sub is REQUIRED and identifies the principal the grant speaks for.
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return nil, errors.New("the assertion has no sub claim")
	}

	// jti is what makes single use enforceable. RFC 7523 Section 3 allows the
	// server to reject a repeated identifier, and doing so turns a bearer
	// assertion into a one-shot credential.
	tokenID, _ := claims["jti"].(string)
	if tokenID == "" {
		return nil, errors.New("the assertion has no jti claim")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if _, replayed := p.seenAssertionIDs[tokenID]; replayed {
		return nil, errors.New("this assertion has already been redeemed")
	}

	// The agent must still be registered and not revoked.
	var live *agentIdentity
	for _, identity := range p.identities {
		if identity.AgentID == subject {
			live = identity
			break
		}
	}
	if live == nil {
		return nil, errors.New("the assertion names an agent that is no longer registered")
	}
	if live.Revoked {
		return nil, errors.New("this agent registration was revoked")
	}

	p.seenAssertionIDs[tokenID] = time.Now()

	// Report the agent's standing as it is now, not as the assertion recorded
	// it, so a pre-claim assertion redeemed after approval still reflects the
	// approval.
	claims["claimed"] = live.Claimed

	return claims, nil
}

// mintAccessToken signs the bearer token an agent presents to protected
// resources.
func (p *Plugin) mintAccessToken(agentID, scope string, claimed bool) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":      p.issuer(),
		"sub":      agentID,
		"aud":      p.origin(),
		"exp":      now.Add(accessTokenTTL).Unix(),
		"iat":      now.Unix(),
		"nbf":      now.Unix(),
		"jti":      randomToken(),
		"scope":    scope,
		"claimed":  claimed,
		"agent_id": agentID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keySet.RSAKeyID()

	return token.SignedString(p.keySet.RSAPrivateKey())
}
