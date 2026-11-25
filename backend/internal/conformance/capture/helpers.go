package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// Helpers shared by the scenario packages. They only prepare or tidy up
// around the exchange a scenario is about; the scenario records that
// exchange itself through Env.Do.

// MachineClient reads the demo machine-client's credentials and token
// endpoint from /oauth2/demo/clients, the public listing Looking Glass's
// client-credentials flow uses.
func MachineClient(ctx context.Context, env *Env) (clientID, secret, tokenEndpoint string, err error) {
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

// RevokeAccessToken revokes a token the run obtained (RFC 7009), so the
// artefact never publishes a usable token.
func RevokeAccessToken(ctx context.Context, env *Env, clientID, secret, token string) error {
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

// JWTParts decodes a compact JWS header and payload without verifying them.
func JWTParts(compact string) (header, payload map[string]any, err error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("value is not a compact JWS")
	}
	decode := func(segment string) (map[string]any, error) {
		raw, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if header, err = decode(parts[0]); err != nil {
		return nil, nil, fmt.Errorf("decode JWS header: %w", err)
	}
	if payload, err = decode(parts[1]); err != nil {
		return nil, nil, fmt.Errorf("decode JWS payload: %w", err)
	}
	return header, payload, nil
}

// JWTClaim reads one string claim from a compact JWS payload without
// verifying it; the scenario only checks what the sender put there.
func JWTClaim(compact, name string) (string, error) {
	_, claims, err := JWTParts(compact)
	if err != nil {
		return "", err
	}
	value, _ := claims[name].(string)
	return value, nil
}

// FetchMetadata records a GET for a metadata document and requires the
// response a client may use: 200 with the application/json media type. It
// names that media type in an Accept header, which OpenID4VCI 1.0 Section
// 12.2.2 recommends: "The Wallet is RECOMMENDED to send an Accept header in
// the HTTP GET request to indicate the Content Type(s) it supports".
func FetchMetadata(ctx context.Context, env *Env, target string) (*Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := env.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("%s was answered %d %s", target, resp.Status, Truncate(resp.Body))
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%s was answered with content type %q, not application/json", target, resp.Header.Get("Content-Type"))
	}
	return resp, nil
}
