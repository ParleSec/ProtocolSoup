package oidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// authenticateOIDCClient authenticates the client at the OIDC token endpoint.
// It supports client_secret_basic, client_secret_post, private_key_jwt, and none
// according to the client's registered token_endpoint_auth_method when set.
func (p *Plugin) authenticateOIDCClient(r *http.Request) (*models.Client, string, error) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	assertionType := r.FormValue("client_assertion_type")
	assertion := r.FormValue("client_assertion")
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if clientID == "" && hasBasic {
		clientID = basicID
		clientSecret = basicSecret
	}

	hasSecretPost := r.FormValue("client_secret") != ""
	hasAssertion := assertionType != "" || assertion != ""
	authMethods := 0
	if hasBasic {
		authMethods++
	}
	if hasSecretPost && !hasBasic {
		authMethods++
	}
	if hasAssertion {
		authMethods++
	}
	if authMethods > 1 {
		return nil, "invalid_client", errAuth("The client MUST NOT use more than one authentication method in each request (RFC 6749 Section 2.3.1)")
	}

	if hasAssertion {
		if assertionType != "" && assertion == "" || assertionType == "" && assertion != "" {
			return nil, "invalid_request", errAuth("client_assertion_type and client_assertion must be provided together")
		}
		if assertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return nil, "invalid_client", errAuth("unsupported client_assertion_type")
		}
		if p.oauth2Plugin == nil {
			return nil, "invalid_client", errAuth("private_key_jwt is unavailable")
		}
		issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
		audiences := []string{
			issuer + "/oidc/token",
			issuer,
		}
		client, _, err := p.oauth2Plugin.AuthenticatePrivateKeyJWTWithAudiences(
			context.Background(),
			clientID,
			assertion,
			audiences,
		)
		if err != nil {
			return nil, "invalid_client", err
		}
		return client, "private_key_jwt", nil
	}

	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		return nil, "invalid_client", errAuth("Unknown client")
	}

	method := client.TokenEndpointAuthMethod
	if method == "" {
		if client.Public {
			method = "none"
		} else if hasBasic {
			method = "client_secret_basic"
		} else {
			method = "client_secret_post"
		}
	}

	switch method {
	case "none":
		if hasBasic || hasSecretPost || hasAssertion {
			return nil, "invalid_client", errAuth("public clients must not present a client secret")
		}
		return client, "none", nil
	case "private_key_jwt":
		return nil, "invalid_client", errAuth("private_key_jwt requires client_assertion")
	case "client_secret_basic":
		if !hasBasic {
			return nil, "invalid_client", errAuth("client_secret_basic authentication required")
		}
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			return nil, "invalid_client", errAuth("Client authentication failed")
		}
		return client, "basic", nil
	case "client_secret_post":
		if hasBasic || !hasSecretPost {
			return nil, "invalid_client", errAuth("client_secret_post authentication required")
		}
		if _, err := p.mockIdP.ValidateClient(clientID, clientSecret); err != nil {
			return nil, "invalid_client", errAuth("Client authentication failed")
		}
		return client, "post", nil
	default:
		return nil, "invalid_client", errAuth("unsupported token_endpoint_auth_method")
	}
}

type authFailure string

func (e authFailure) Error() string { return string(e) }

func errAuth(msg string) error { return authFailure(msg) }
