package agentauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/golang-jwt/jwt/v5"
)

// identityRequest is the body an agent posts to the identity endpoint.
type identityRequest struct {
	Type      string `json:"type"`
	AgentName string `json:"agent_name"`

	// AssertionType names the kind of assertion carried in Assertion, when
	// Type is identityTypeAssertion. The only value defined by auth.md is the
	// ID-JAG (assertionTypeIDJAG); it is read here purely to give a caller
	// who tries one a precise reason rather than the generic rejection below.
	AssertionType string `json:"assertion_type"`
	Assertion     string `json:"assertion"`
}

// handleIdentity registers an agent and returns a service-signed identity
// assertion together with the claim_token that lets the agent later bind
// itself to a person.
//
// Only anonymous registration is offered. Accepting an ID-JAG would require
// verifying an assertion minted by an external agent provider against that
// provider's key set, and this deployment federates with no such provider, so
// identity_types_supported advertises anonymous alone.
func (p *Plugin) handleIdentity(w http.ResponseWriter, r *http.Request) {
	sessionID := p.sessionFromRequest(r)

	if p.keySet == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable",
			"The identity endpoint has no signing key available")
		return
	}

	var req identityRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			"Request body must be a JSON object")
		return
	}

	if req.Type == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request",
			`"type" is required and must be "anonymous"`)
		return
	}
	if req.Type != identityTypeAnonymous {
		detail := `Only "anonymous" registration is supported; see the agent_auth block in the authorization server metadata`
		title := "Only anonymous registration is offered"
		description := "This deployment federates with no agent provider, so it cannot verify an ID-JAG. Advertising an identity type it cannot check would let an agent believe an assertion had been validated when it had not."

		// A caller presenting an ID-JAG specifically gets told exactly why it
		// is refused, rather than a generic rejection that could as easily
		// mean the type name was misspelled.
		if req.Type == identityTypeAssertion && req.AssertionType == assertionTypeIDJAG {
			detail = fmt.Sprintf(
				`This deployment does not federate with an external agent provider, so it cannot verify an ID-JAG (%s); only "anonymous" registration is supported`,
				assertionTypeIDJAG)
			title = "ID-JAG verification requires a federated agent provider"
			description = "An ID-JAG is minted and signed by an external agent provider. Verifying it means fetching that provider's keys and trusting its issuer, which this deployment does not do for any provider, so the assertion is refused unread rather than accepted and left unverified."
		}

		p.emitEvent(sessionID, lookingglass.EventTypeSecurityWarning, "Unsupported identity type rejected",
			map[string]interface{}{
				"requested":                req.Type,
				"assertion_type":           req.AssertionType,
				"identity_types_supported": []string{identityTypeAnonymous},
			},
			lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeExplanation,
				Title:       title,
				Description: description,
				Reference:   "auth.md, Identity Assertion (ID-JAG)",
			})
		writeOAuthError(w, http.StatusBadRequest, "unsupported_identity_type", detail)
		return
	}

	now := time.Now()
	identity := &agentIdentity{
		AgentID:          newAgentID(),
		IdentityType:     identityTypeAnonymous,
		AssertionVersion: 1,
		ClaimToken:       randomToken(),
		CreatedAt:        now,
		ExpiresAt:        now.Add(claimTokenTTL),
	}

	p.mu.Lock()
	p.identities[identity.ClaimToken] = identity
	p.mu.Unlock()

	assertion, expiresAt, err := p.mintIdentityAssertion(identity)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error",
			"Could not sign the identity assertion")
		return
	}

	p.emitEvent(sessionID, lookingglass.EventTypeTokenIssued, "Anonymous agent registered",
		map[string]interface{}{
			"agent_id":          identity.AgentID,
			"identity_type":     identityTypeAnonymous,
			"assertion_version": identity.AssertionVersion,
			"claimed":           false,
			"expires_in":        int(time.Until(expiresAt).Seconds()),
			"granted_scope":     scopePreClaim,
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "The agent has an identity but no owner",
			Description: "Anonymous registration proves nothing about who runs the agent, so the assertion carries claimed=false and only earns the pre-claim scope. A claim ceremony is what binds the agent to a person and widens that scope.",
			Reference:   "auth.md, Anonymous Registration with Claim Ceremony",
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "The assertion is a bearer credential",
			Description: "Anyone holding this assertion can exchange it for an access token until it expires, so it travels over TLS only and is accepted exactly once.",
			Reference:   "RFC 7523 Section 3",
		})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"identity_assertion":      assertion,
		"identity_assertion_type": credentialTypeJWT,
		"identity_type":           identityTypeAnonymous,
		"agent_id":                identity.AgentID,
		"claimed":                 false,
		"expires_in":              int(time.Until(expiresAt).Round(time.Second).Seconds()),
		"claim_token":             identity.ClaimToken,
		"claim_uri":               p.issuer() + "/identity/claim",
		"token_endpoint":          p.issuer() + "/token",
		"grant_type":              grantTypeJWTBearer,
	})
}

// mintIdentityAssertion signs the assertion an agent presents at the token
// endpoint. The claim set follows RFC 7523 Section 3: iss, sub, aud and exp are
// all present, iat and nbf bound the validity window, and jti gives the
// authorization server a handle for replay detection.
func (p *Plugin) mintIdentityAssertion(identity *agentIdentity) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(identityAssertionTTL)

	claims := jwt.MapClaims{
		// The service both mints and consumes this assertion, so it is its
		// own issuer and its own audience. RFC 7523 Section 3 requires the
		// audience to identify the authorization server that will accept it.
		"iss": p.issuer(),
		"sub": identity.AgentID,
		"aud": p.issuer(),
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": randomToken(),

		// auth.md profile claims describing the agent's standing.
		"identity_type":     identity.IdentityType,
		"claimed":           identity.Claimed,
		"assertion_version": identity.AssertionVersion,
	}
	if identity.Email != "" {
		claims["owner_email"] = identity.Email
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keySet.RSAKeyID()

	signed, err := token.SignedString(p.keySet.RSAPrivateKey())
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

// handleRevoke revokes an agent registration and every assertion issued
// against it. The request shape follows RFC 7009 Section 2.1, and as
// Section 2.2 requires, an unrecognised token is answered with 200 so a caller
// cannot use the endpoint to test whether a token exists.
func (p *Plugin) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sessionID := p.sessionFromRequest(r)

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body")
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `"token" is required`)
		return
	}

	p.mu.Lock()
	identity, found := p.identities[token]
	if found {
		identity.Revoked = true
	}
	p.mu.Unlock()

	if found {
		p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Agent registration revoked",
			map[string]interface{}{
				"agent_id": identity.AgentID,
				"event":    eventAssertionRevoked,
			},
			lookingglass.Annotation{
				Type:        lookingglass.AnnotationTypeExplanation,
				Title:       "Revocation ends the agent's standing",
				Description: "Assertions already minted for this agent stop being redeemable immediately. Access tokens already issued remain valid until they expire, which is why their lifetime is short.",
				Reference:   "RFC 7009 Section 2.1",
			})
	}

	w.WriteHeader(http.StatusOK)
}
