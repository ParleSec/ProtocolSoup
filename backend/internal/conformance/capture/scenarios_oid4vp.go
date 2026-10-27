package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/google/uuid"
)

// requestObjectLifetime is how long the verifier keeps a request session.
const requestObjectLifetime = 5 * time.Minute

func init() {
	register("VP-008", Entry{
		Passing: &Scenario{
			Name:        "bind-and-repeat",
			Description: "The conformance client POSTs a wallet_nonce to a request_uri_method=post request_uri, then repeats the same POST. The first response must carry the nonce in the signed request object; the second must be byte-identical.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error) {
				return walletNonceBinding(ctx, env, false)
			},
		},
		Failing: &Scenario{
			Name:        "change-nonce",
			Description: "The conformance client binds one wallet_nonce, then POSTs a different wallet_nonce to the same request_uri.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error) {
				return walletNonceBinding(ctx, env, true)
			},
		},
	})
}

// postRequestURI creates a request_uri_method=post Authorization Request and
// returns its request_uri.
func postRequestURI(ctx context.Context, env *Env) (string, error) {
	req, err := NewJSON(env.BaseURL+"/oid4vp/request/create", map[string]any{
		"response_mode":      "direct_post",
		"response_uri":       env.BaseURL + "/oid4vp/response",
		"request_uri_method": "post",
		"dcql_query": map[string]any{
			"credentials": []map[string]any{{
				"id":     "degree",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []string{env.BaseURL + "/credentials/university_degree"}},
			}},
		},
	})
	if err != nil {
		return "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusCreated {
		return "", fmt.Errorf("request creation answered %d %s", resp.Status, truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return "", err
	}
	requestURI, _ := body["request_uri"].(string)
	if requestURI == "" {
		return "", fmt.Errorf("request creation returned no request_uri")
	}
	env.NoteExpiry(requestObjectLifetime)
	return requestURI, nil
}

// walletNonceBinding exercises OID4VP 1.0 Section 5.10: "When received, the
// Verifier MUST use it as the wallet_nonce value in the signed authorization
// request object."
func walletNonceBinding(ctx context.Context, env *Env, changeNonce bool) (conformance.ArtefactOutcome, error) {
	requestURI, err := postRequestURI(ctx, env)
	if err != nil {
		return "", err
	}
	first := uuid.NewString()
	fetch := func(nonce string) (*Response, error) {
		req, err := NewForm(requestURI, url.Values{"wallet_nonce": {nonce}})
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/oauth-authz-req+jwt")
		return env.Do(ctx, req)
	}

	bound, err := fetch(first)
	if err != nil {
		return "", err
	}
	if bound.Status != http.StatusOK {
		return conformance.OutcomeRejected, nil
	}
	claim, err := jwtClaim(string(bound.Body), "wallet_nonce")
	if err != nil {
		return "", err
	}
	if claim != first {
		return "", fmt.Errorf("request object wallet_nonce is %q, want %q", claim, first)
	}

	second := first
	if changeNonce {
		second = uuid.NewString()
	}
	again, err := fetch(second)
	if err != nil {
		return "", err
	}
	switch {
	case again.Status == http.StatusOK && !changeNonce:
		if string(again.Body) != string(bound.Body) {
			return "", fmt.Errorf("repeated retrieval with the same wallet_nonce returned a different request object")
		}
		return conformance.OutcomeAccepted, nil
	case again.Status == http.StatusOK:
		return conformance.OutcomeAccepted, nil
	case again.Status == http.StatusBadRequest && again.Error() == "invalid_request":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("request_uri answered %d %s", again.Status, truncate(again.Body))
	}
}

// jwtClaim reads one string claim from a compact JWS payload without
// verifying it; the scenario only checks what the verifier put there.
func jwtClaim(compact, name string) (string, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("request object is not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode request object payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse request object payload: %w", err)
	}
	value, _ := claims[name].(string)
	return value, nil
}
