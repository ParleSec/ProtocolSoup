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
	"slices"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture/haipwallet"
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
		Passing: &capture.Scenario{
			Name: "attested-par-redeemed",
			Description: "The conformance client has the issuer create an authorization_code offer for the " + haipSDJWTConfigurationID + " configuration and asks the hosted wallet to import it. " +
				"The wallet's pushed authorization request carries OAuth-Client-Attestation and OAuth-Client-Attestation-PoP headers, an S256 code_challenge and the exact redirect_uri, and the issuer answers 201 with a request_uri and its expires_in. " +
				"The conformance client then signs in at the Mock IdP as the End-User: the authorization server honours the request_uri for that client_id, delivers the Authorization Response to that redirect_uri, " +
				"and the wallet redeems the code. The Authorization Server Metadata the wallet fetched advertises attest_jwt_client_auth and the attestation signing algorithm.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      attestedPARRedeemed,
		},
		Failing: []*capture.Scenario{{
			Name: "par-without-client-attestation",
			Description: "The conformance client pushes an authorization request to the pushed_authorization_request_endpoint the issuer's Authorization Server Metadata names, with response_type code, an HTTPS redirect_uri, " +
				"an S256 code_challenge and authorization_details for the " + haipSDJWTConfigurationID + " configuration, but without the OAuth-Client-Attestation and OAuth-Client-Attestation-PoP headers.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeRejected,
			Run:      parWithoutAttestation,
		}},
	})
}

// attestedPARRedeemed runs the hosted wallet's attested pushed authorization
// request and checks what the requirement names on it: client attestation,
// PKCE S256, the redirect_uri, the short-lived request_uri, the metadata
// that advertises the authentication, and that the authorization server
// then redeems the request_uri for exactly that client and redirect URI.
func attestedPARRedeemed(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	authorization, err := haipwallet.PushedAuthorization(ctx, env)
	if err != nil {
		return "", err
	}
	par := authorization.PAR
	for _, header := range []string{"OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP"} {
		if par.RequestHeader(header) == "" {
			return "", fmt.Errorf("the PAR request carries no %s header", header)
		}
	}
	form, err := url.ParseQuery(par.RequestBody)
	if err != nil {
		return "", fmt.Errorf("parse the PAR form: %w", err)
	}
	if form.Get("code_challenge_method") != "S256" || len(form.Get("code_challenge")) != 43 {
		return "", fmt.Errorf("the PAR request is not S256 PKCE-bound: code_challenge_method %q, code_challenge %q", form.Get("code_challenge_method"), form.Get("code_challenge"))
	}
	redirectURI := form.Get("redirect_uri")
	if !strings.HasPrefix(redirectURI, env.WalletURL+"/") {
		return "", fmt.Errorf("the PAR request's redirect_uri %q is not at the wallet", redirectURI)
	}
	if par.ResponseStatus != http.StatusCreated {
		return "", fmt.Errorf("the PAR endpoint answered %d, not 201", par.ResponseStatus)
	}
	var parResponse struct {
		RequestURI string  `json:"request_uri"`
		ExpiresIn  float64 `json:"expires_in"`
	}
	if err := json.Unmarshal([]byte(par.ResponseBody), &parResponse); err != nil || parResponse.RequestURI == "" || parResponse.ExpiresIn <= 0 {
		return "", fmt.Errorf("the PAR response carries no request_uri with a positive expires_in: %s", capture.Truncate([]byte(par.ResponseBody)))
	}
	asMetadata, _ := authorization.Import.Body["authorization_server_metadata"].(map[string]any)
	methods, _ := asMetadata["token_endpoint_auth_methods_supported"].([]any)
	algorithms, _ := asMetadata["client_attestation_signing_alg_values_supported"].([]any)
	if !slices.Contains(methods, any("attest_jwt_client_auth")) || len(algorithms) == 0 {
		return "", fmt.Errorf("the Authorization Server Metadata does not advertise attest_jwt_client_auth with its signing algorithms: %v", asMetadata)
	}
	// Completing the authorization proves the request_uri was redeemed for
	// the pushed client_id and delivered to the pushed redirect_uri.
	_, response, err := authorization.Complete(ctx, env)
	if err != nil {
		return "", err
	}
	if response.Get("code") == "" {
		return "", fmt.Errorf("the Authorization Response delivered to %s carries no code", redirectURI)
	}
	return conformance.OutcomeAccepted, nil
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
