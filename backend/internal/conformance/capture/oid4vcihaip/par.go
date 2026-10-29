package oid4vcihaip

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// parClientID and parRedirectURI name the conformance client in its pushed
// authorization request. The redirect URI uses the reserved .invalid domain
// (RFC 6761) because no authorization response is ever delivered to it.
const (
	parClientID    = "protocolsoup-conformance-client"
	parRedirectURI = "https://conformance-client.invalid/callback"
)

func init() {
	capture.Register("CI-019", capture.Entry{
		Failing: &capture.Scenario{
			Name: "par-without-client-attestation",
			Description: "The conformance client pushes an authorization request to the pushed_authorization_request_endpoint the issuer's Authorization Server Metadata names, with response_type code, an HTTPS redirect_uri, " +
				"an S256 code_challenge and authorization_details for the " + haipSDJWTConfigurationID + " configuration, but without the OAuth-Client-Attestation and OAuth-Client-Attestation-PoP headers.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeRejected,
			Run:      parWithoutAttestation,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "The conformance client holds no client attestation signed by an attester the issuer trusts, so it cannot send an authenticated pushed authorization request.",
		},
	})
}

// parWithoutAttestation sends a PAR request that is complete apart from
// client authentication. HAIP 1.0 Section 4.3 says "Wallets MUST
// authenticate themselves at the PAR endpoint"; ProtocolSoup answers a
// missing attestation with 401 invalid_client.
func parWithoutAttestation(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	req, err := http.NewRequest(http.MethodGet, env.BaseURL+"/.well-known/oauth-authorization-server/oid4vci", nil)
	if err != nil {
		return "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("authorization server metadata answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	asMetadata, err := resp.JSON()
	if err != nil {
		return "", err
	}
	parEndpoint, _ := asMetadata["pushed_authorization_request_endpoint"].(string)
	issuer, _ := asMetadata["issuer"].(string)
	if parEndpoint == "" || issuer == "" {
		return "", fmt.Errorf("authorization server metadata has no issuer or pushed_authorization_request_endpoint")
	}

	verifier := make([]byte, 32)
	if _, err := rand.Read(verifier); err != nil {
		return "", err
	}
	challenge := sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(verifier)))
	details, err := json.Marshal([]map[string]any{{
		"type":                        "openid_credential",
		"credential_configuration_id": haipSDJWTConfigurationID,
		"locations":                   []string{issuer},
	}})
	if err != nil {
		return "", err
	}
	req, err = capture.NewForm(parEndpoint, url.Values{
		"client_id":             {parClientID},
		"response_type":         {"code"},
		"redirect_uri":          {parRedirectURI},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
		"authorization_details": {string(details)},
	})
	if err != nil {
		return "", err
	}
	resp, err = env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusCreated:
		// A request_uri was issued for an unauthenticated client.
		env.NoteExpiry(pushedRequestLifetime(resp))
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusUnauthorized && resp.Error() == "invalid_client":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("PAR endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// pushedRequestLifetime reads expires_in from a PAR response (RFC 9126
// Section 2.2), defaulting to an hour when it is missing.
func pushedRequestLifetime(resp *capture.Response) time.Duration {
	body, err := resp.JSON()
	if err == nil {
		if seconds, ok := body["expires_in"].(float64); ok && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}
	}
	return time.Hour
}
