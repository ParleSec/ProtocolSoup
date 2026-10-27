package capture

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
)

func init() {
	register("DP-001", Entry{
		Passing: &Scenario{
			Name:        "one-dpop-header",
			Description: "The conformance client requests a client_credentials token from /oauth2/token with exactly one DPoP header field, answering a use_dpop_nonce challenge if the server issues one.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error) {
				return dpopTokenRequest(ctx, env, 1)
			},
		},
		Failing: &Scenario{
			Name:        "two-dpop-headers",
			Description: "The conformance client sends the same token request with two DPoP header fields, each carrying a valid proof.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error) {
				return dpopTokenRequest(ctx, env, 2)
			},
		},
	})
}

// machineClient reads the demo machine-client's credentials and token
// endpoint from /oauth2/demo/clients, the public listing Looking Glass's
// client-credentials flow uses.
func machineClient(ctx context.Context, env *Env) (clientID, secret, tokenEndpoint string, err error) {
	req, err := http.NewRequest(http.MethodGet, env.BaseURL+"/oauth2/demo/clients", nil)
	if err != nil {
		return "", "", "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", "", "", err
	}
	body, err := resp.JSON()
	if err != nil {
		return "", "", "", err
	}
	tokenEndpoint, _ = body["token_endpoint"].(string)
	clients, _ := body["clients"].([]any)
	for _, raw := range clients {
		client, _ := raw.(map[string]any)
		if client["id"] == "machine-client" {
			secret, _ = client["secret"].(string)
			return "machine-client", secret, tokenEndpoint, nil
		}
	}
	return "", "", "", fmt.Errorf("machine-client is not listed by /oauth2/demo/clients")
}

// dpopTokenRequest sends a client_credentials token request carrying proofs
// DPoP header fields. RFC 9449 Section 4.3 check 1 is "There is not more
// than one DPoP HTTP request header field."
func dpopTokenRequest(ctx context.Context, env *Env, proofs int) (conformance.ArtefactOutcome, error) {
	clientID, secret, tokenEndpoint, err := machineClient(ctx, env)
	if err != nil {
		return "", err
	}
	key, err := NewDPoPKey()
	if err != nil {
		return "", err
	}
	send := func(nonce string) (*Response, error) {
		req, err := NewForm(tokenEndpoint, url.Values{"grant_type": {"client_credentials"}})
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(clientID, secret)
		values := make([]string, 0, proofs)
		for i := 0; i < proofs; i++ {
			proof, err := key.Proof(ProofOptions{Method: http.MethodPost, URL: tokenEndpoint, Nonce: nonce})
			if err != nil {
				return nil, err
			}
			values = append(values, proof)
		}
		req.Header["DPoP"] = values
		return env.Do(ctx, req)
	}

	resp, err := send("")
	if err != nil {
		return "", err
	}
	// RFC 9449 Section 8: a server requiring a nonce answers use_dpop_nonce
	// with a DPoP-Nonce header, and the client retries with it.
	if resp.Status == http.StatusBadRequest && resp.Error() == "use_dpop_nonce" {
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce == "" {
			return "", fmt.Errorf("use_dpop_nonce without a DPoP-Nonce header")
		}
		if resp, err = send(nonce); err != nil {
			return "", err
		}
	}

	switch {
	case resp.Status == http.StatusOK:
		body, err := resp.JSON()
		if err != nil {
			return "", err
		}
		if body["token_type"] != "DPoP" {
			return "", fmt.Errorf("token_type %v, want DPoP", body["token_type"])
		}
		accessToken, _ := body["access_token"].(string)
		if err := revokeAccessToken(ctx, env, clientID, secret, accessToken); err != nil {
			// The token stays usable until it expires, so publication waits.
			expiresIn, _ := body["expires_in"].(float64)
			env.NoteExpiry(time.Duration(expiresIn) * time.Second)
		}
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_dpop_proof":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("token endpoint answered %d %s", resp.Status, truncate(resp.Body))
	}
}

// revokeAccessToken revokes a token the run obtained (RFC 7009), so the
// artefact never publishes a usable token.
func revokeAccessToken(ctx context.Context, env *Env, clientID, secret, token string) error {
	if token == "" {
		return fmt.Errorf("no access_token to revoke")
	}
	req, err := NewForm(env.BaseURL+"/oauth2/revoke", url.Values{"token": {token}, "token_type_hint": {"access_token"}})
	if err != nil {
		return err
	}
	req.SetBasicAuth(clientID, secret)
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status != http.StatusOK {
		return fmt.Errorf("revocation answered %d", resp.Status)
	}
	return nil
}
