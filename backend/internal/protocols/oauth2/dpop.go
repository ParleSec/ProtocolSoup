package oauth2

import (
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
)

// dpopValidation is the outcome of inspecting an incoming token request for
// an optional DPoP proof (RFC 9449). Absent a DPoP header, both fields are
// zero and every existing bearer-only code path continues unmodified --
// DPoP is opt-in per RFC 9449, never mandatory for an existing endpoint.
type dpopValidation struct {
	// Present is true only when the client sent a DPoP header and it
	// validated successfully.
	Present bool
	// JKT is the RFC 7638 thumbprint of the proof's public key, set only
	// when Present is true. This is the value bound into an issued access
	// token's cnf.jkt claim.
	JKT string
}

// tokenEndpointURL returns the exact token endpoint URL used as the htu
// comparison target (RFC 9449 Section 4.3 step 9), matching the audience
// convention already used for private_key_jwt client assertions
// (see clientauth_jwt.go) against this same endpoint.
func (p *Plugin) tokenEndpointURL() string {
	return p.baseURL + "/oauth2/token"
}

// validateTokenEndpointDPoP validates an optional DPoP proof on a token
// request. It returns a zero-value dpopValidation and a nil error when no
// DPoP header is present at all -- the caller must not treat that as a
// failure. A non-nil error is either an *dpop.InfrastructureError (replay
// store outage; the caller must fail closed with 500 server_error) or a
// proof validation failure (RFC 9449 Section 5 invalid_dpop_proof, 400).
func (p *Plugin) validateTokenEndpointDPoP(r *http.Request) (dpopValidation, error) {
	header, err := dpop.ExtractHeader(r.Header.Values(dpop.HeaderName))
	if err != nil {
		return dpopValidation{}, err
	}
	if header == "" {
		return dpopValidation{}, nil
	}

	proof, err := dpop.ValidateProof(header, dpop.ValidateOptions{
		Method: http.MethodPost,
		URI:    p.tokenEndpointURL(),
		Now:    p.now(),
	})
	if err != nil {
		return dpopValidation{}, err
	}

	// RFC 9449 Section 8: when a nonce is in force at this endpoint, a
	// proof that is otherwise fully valid but carries a stale, foreign, or
	// absent nonce is not a hard failure -- it is a challenge. Checked
	// after full proof validation so nonce enforcement never changes the
	// outcome of any other check, and before the replay reservation so a
	// challenged proof's jti is not consumed (the client mints an entirely
	// new proof, with a new jti, on retry).
	if p.dpopNonceIssuer != nil && !p.dpopNonceIssuer.Valid(proof.Nonce) {
		return dpopValidation{}, &dpop.NonceRequiredError{Nonce: p.dpopNonceIssuer.Issue()}
	}

	now := p.now()
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

var errDPoPProofReplayed = dpopProofError("DPoP proof jti has already been used")

// dpopProofError is a plain string error for DPoP proof rejections that
// carry no wrapped cause, distinct from *dpop.InfrastructureError so
// callers can tell a replay-store outage apart from a genuine replay.
type dpopProofError string

func (e dpopProofError) Error() string { return string(e) }
