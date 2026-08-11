package oid4vci

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
)

// dpopValidation is the outcome of inspecting an incoming token request for
// an optional DPoP proof (RFC 9449). Absent a DPoP header, both fields are
// zero and every existing bearer-only code path continues unmodified.
// Deliberately duplicated from the equivalent type in
// internal/protocols/oauth2/dpop.go rather than shared: internal/dpop must
// not import internal/protocols/* (Phase 1), and oauth2 and oid4vci must not
// import each other -- oid4vci mints and validates its own access tokens
// independently of the oauth2 plugin's token endpoint.
type dpopValidation struct {
	Present bool
	JKT     string
}

// tokenEndpointURL is the htu comparison target for proofs presented at
// this plugin's own token endpoint (RFC 9449 Section 4.3 step 9).
func (p *Plugin) tokenEndpointURL() string {
	return p.baseURL + "/oid4vci/token"
}

// validateTokenEndpointDPoP mirrors oauth2's Plugin.validateTokenEndpointDPoP:
// oid4vci acts as its own authorization server for the tokens that protect
// its credential endpoints (it does not delegate to the oauth2 plugin), so
// it needs the identical AS-side validation, scoped to its own token
// endpoint and its own replay store.
func (p *Plugin) validateTokenEndpointDPoP(r *http.Request) (dpopValidation, error) {
	return p.validateAuthorizationServerDPoP(r, p.tokenEndpointURL())
}

func (p *Plugin) validateAuthorizationServerDPoP(r *http.Request, endpointURL string) (dpopValidation, error) {
	header, err := dpop.ExtractHeader(r.Header.Values(dpop.HeaderName))
	if err != nil {
		return dpopValidation{}, err
	}
	if header == "" {
		return dpopValidation{}, nil
	}

	proof, err := dpop.ValidateProof(header, dpop.ValidateOptions{
		Method: http.MethodPost,
		URI:    endpointURL,
	})
	if err != nil {
		return dpopValidation{}, err
	}

	// RFC 9449 Section 8: checked after full proof validation (so nonce
	// enforcement never changes the outcome of any other check) and before
	// the replay reservation (so a challenged proof's jti is not consumed;
	// the client mints an entirely new proof on retry). This is this
	// plugin's AS-role nonce space -- independent of dpopRSNonceIssuer per
	// Section 8.2.
	if p.dpopASNonceIssuer != nil {
		valid, nonceErr := p.dpopASNonceIssuer.Valid(proof.Nonce)
		if nonceErr != nil {
			return dpopValidation{}, dpop.NewInfrastructureError(nonceErr)
		}
		if !valid {
			nonce, issueErr := p.dpopASNonceIssuer.Issue()
			if issueErr != nil {
				return dpopValidation{}, dpop.NewInfrastructureError(issueErr)
			}
			return dpopValidation{}, &dpop.NonceRequiredError{Nonce: nonce}
		}
	}

	now := time.Now().UTC()
	reserved, reserveErr := p.dpopReplay.Reserve(
		r.Context(),
		proof.JKT,
		proof.JTI,
		proof.IAT.Add(dpop.IatFreshnessWindow),
		now,
	)
	if reserveErr != nil {
		return dpopValidation{}, dpop.NewInfrastructureError(reserveErr)
	}
	if !reserved {
		return dpopValidation{}, errDPoPProofReplayed
	}

	return dpopValidation{Present: true, JKT: proof.JKT}, nil
}

var errDPoPProofReplayed = errors.New("DPoP proof jti has already been used")

// parseAuthorizedToken extracts the access token from the Authorization
// header, accepting both the Bearer and DPoP presentation schemes (RFC 9449
// Section 7.1 reuses the proof header's name as the auth scheme too). The
// Bearer branch delegates to parseBearerToken so that function's original
// semantics and error message stay the single source of truth for the
// bearer-only path.
func parseAuthorizedToken(r *http.Request) (scheme string, token string, err error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], dpop.HeaderName) {
		token = strings.TrimSpace(parts[1])
		if token == "" {
			return "", "", errors.New("missing access token")
		}
		return "DPoP", token, nil
	}
	token, err = parseBearerToken(r)
	if err != nil {
		return "", "", err
	}
	return "Bearer", token, nil
}

// resourceAuthError carries enough information to write an RFC 6750/RFC 9449
// compliant WWW-Authenticate header alongside the OID4VCI error body: the
// scheme depends on whether the rejected token was DPoP-bound, since a
// bound token must never be told "Bearer" is an acceptable presentation.
type resourceAuthError struct {
	status      int
	code        string
	description string
	dpopBound   bool
	// nonce, when set, is a freshly issued RFC 9449 Section 8 nonce that
	// must accompany the response in a DPoP-Nonce header -- used only for
	// the use_dpop_nonce challenge, never for a hard rejection.
	nonce string
}

func (e *resourceAuthError) Error() string { return e.description }

func (e *resourceAuthError) respond(w http.ResponseWriter) {
	scheme := "Bearer"
	if e.dpopBound {
		scheme = dpop.HeaderName
	}
	if e.nonce != "" {
		w.Header().Set(dpop.NonceHeaderName, e.nonce)
	}
	if e.code != "" {
		challenge := fmt.Sprintf(`%s error="%s"`, scheme, e.code)
		if scheme == dpop.HeaderName {
			challenge += fmt.Sprintf(`, algs="%s"`, strings.Join(dpop.AllowedAlgorithmsList, " "))
		}
		w.Header().Set("WWW-Authenticate", challenge)
	} else {
		w.Header().Set("WWW-Authenticate", scheme)
	}
	writeOID4VCIError(w, e.status, e.code, e.description)
}

// authorizeResourceRequest extracts and authorizes the access token
// presented to a DPoP-aware OID4VCI resource endpoint (the credential,
// nonce, deferred_credential, and notification endpoints; RFC 9449 Section 7). A token
// whose accessGrant carries a jkt was issued DPoP-bound and MUST be
// presented with a valid, matching DPoP proof -- presenting it as a bare
// bearer token is rejected outright, never silently downgraded. A token
// with no jkt continues to work exactly as it did before DPoP existed.
func (p *Plugin) authorizeResourceRequest(r *http.Request) (string, *accessGrant, *resourceAuthError) {
	scheme, token, err := parseAuthorizedToken(r)
	if err != nil {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: err.Error()}
	}

	p.mu.RLock()
	grant, ok := p.accessGrants[token]
	p.mu.RUnlock()
	if !ok {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "unknown access token"}
	}

	// RFC 6749 Section 4.1.2: when an authorization code is replayed the AS
	// SHOULD revoke previously issued tokens. MockIdP records those JTIs on
	// redemption and marks them revoked on replay; enforce that here so the
	// credential/nonce/deferred/notification resource endpoints reject the
	// token with HTTP 4xx (RFC 6750 Section 3.1) instead of serving it from
	// the still-cached access grant.
	if p.mockIDP != nil && p.mockIDP.IsTokenRevoked(token) {
		p.mu.Lock()
		delete(p.accessGrants, token)
		p.mu.Unlock()
		return "", nil, &resourceAuthError{
			status:      http.StatusUnauthorized,
			code:        "invalid_token",
			description: "the access token has been revoked",
			dpopBound:   grant.JKT != "",
		}
	}

	dpopBound := grant.JKT != ""
	if time.Now().UTC().After(grant.ExpiresAt) {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "access token expired", dpopBound: dpopBound}
	}
	if !dpopBound {
		if scheme == "DPoP" {
			return "", nil, &resourceAuthError{
				status:      http.StatusUnauthorized,
				code:        "invalid_token",
				description: "an access token presented with the DPoP authorization scheme must be DPoP-bound",
				dpopBound:   true,
			}
		}
		return token, grant, nil
	}

	if scheme != "DPoP" {
		return "", nil, &resourceAuthError{
			status:      http.StatusUnauthorized,
			code:        "invalid_token",
			description: "this access token is bound to a DPoP key and must be presented with a DPoP proof (RFC 9449 Section 7)",
			dpopBound:   true,
		}
	}
	proofHeader, err := dpop.ExtractHeader(r.Header.Values(dpop.HeaderName))
	if err != nil {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_dpop_proof", description: err.Error(), dpopBound: true}
	}
	if proofHeader == "" {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_dpop_proof", description: "missing DPoP proof", dpopBound: true}
	}

	proof, proofErr := dpop.ValidateProof(proofHeader, dpop.ValidateOptions{
		Method:      r.Method,
		URI:         p.baseURL + r.URL.Path,
		AccessToken: token,
	})
	if proofErr != nil {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_dpop_proof", description: "invalid DPoP proof: " + proofErr.Error(), dpopBound: true}
	}
	if proof.JKT != grant.JKT {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_dpop_proof", description: "DPoP proof key does not match the token's bound key", dpopBound: true}
	}

	// RFC 9449 Section 8, RS role: this plugin's resource-endpoint nonce
	// space, independent of dpopASNonceIssuer's AS-role space (Section
	// 8.2) even though both live on this same plugin instance.
	if p.dpopRSNonceIssuer != nil {
		valid, nonceErr := p.dpopRSNonceIssuer.Valid(proof.Nonce)
		if nonceErr != nil {
			return "", nil, &resourceAuthError{status: http.StatusInternalServerError, code: "server_error", description: "DPoP nonce validation is temporarily unavailable", dpopBound: true}
		}
		if !valid {
			nonce, issueErr := p.dpopRSNonceIssuer.Issue()
			if issueErr != nil {
				return "", nil, &resourceAuthError{status: http.StatusInternalServerError, code: "server_error", description: "DPoP nonce generation is temporarily unavailable", dpopBound: true}
			}
			return "", nil, &resourceAuthError{
				status:      http.StatusUnauthorized,
				code:        dpop.ErrorUseDPoPNonce,
				description: "a fresh DPoP proof nonce is required; retry with the nonce from the DPoP-Nonce response header",
				dpopBound:   true,
				nonce:       nonce,
			}
		}
	}

	reserved, reserveErr := p.dpopReplay.Reserve(
		r.Context(),
		proof.JKT,
		proof.JTI,
		proof.IAT.Add(dpop.IatFreshnessWindow),
		time.Now().UTC(),
	)
	if reserveErr != nil {
		return "", nil, &resourceAuthError{status: http.StatusInternalServerError, code: "server_error", description: "DPoP validation is temporarily unavailable", dpopBound: true}
	}
	if !reserved {
		return "", nil, &resourceAuthError{status: http.StatusUnauthorized, code: "invalid_token", description: "DPoP proof jti has already been used", dpopBound: true}
	}

	return token, grant, nil
}
