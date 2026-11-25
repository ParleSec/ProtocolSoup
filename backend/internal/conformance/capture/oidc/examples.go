// Package oidc captures OpenID Connect example messages as a Relying Party
// would obtain them: the conformance client discovers the OpenID Provider,
// sends an Authentication Request, and redeems the authorization code.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.RegisterExample("oidc-id-token", capture.ExampleScenario{
		Description: "The conformance client acts as " + clientID + ", a public client registered at the OpenID Provider, and as the End-User's user agent. " +
			"It reads the OpenID Provider's discovery document, sends an Authentication Request to the authorization endpoint with scope openid, a nonce and a PKCE code_challenge, " +
			"signs in at the Mock IdP as a demo user, and redeems the authorization code at the token endpoint with the code_verifier. The Token Response carries the ID Token. " +
			"The client then fetches the JWK Set at the discovery document's jwks_uri, which holds the key that verifies the ID Token's signature. " +
			"The sign-in is not recorded: how the End-User authenticates is the OpenID Provider's own business, not an OpenID Connect message. " +
			"The Authorization Response it produced is a redirect to the client's redirect_uri carrying the code that the Token Request redeems.",
		Actor: conformance.ActorConformanceClient,
		Run:   idTokenExample,
	})
	capture.RegisterExample("openid-configuration", capture.ExampleScenario{
		Description: "The conformance client requests the OpenID Provider's configuration the way a Relying Party does: " +
			"it appends " + providerConfigurationPath + " to the Issuer and sends a GET (OpenID Connect Discovery 1.0 Section 4.1). The body of the response is the document.",
		Actor: conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
			return metadataExample(ctx, env, providerConfigurationPath)
		},
	})
	capture.RegisterExample("oauth-authorization-server", capture.ExampleScenario{
		Description: "The conformance client requests the authorization server's metadata the way an OAuth 2.0 client does: " +
			"it inserts " + authorizationServerMetadataPath + " after the host of the issuer identifier and sends a GET (RFC 8414 Section 3.1). The body of the response is the document.",
		Actor: conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
			return metadataExample(ctx, env, authorizationServerMetadataPath)
		},
	})
}

// The well-known locations of the two metadata documents this issuer
// publishes. The issuer has no path component, so appending the suffix
// (OpenID Connect Discovery 1.0 Section 4) and inserting it after the host
// (RFC 8414 Section 3) both put it directly after the origin.
const (
	providerConfigurationPath       = "/.well-known/openid-configuration"
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
)

// metadataExample captures the metadata document at wellKnownPath of the
// issuer under capture. RFC 8414 Section 3.2: "A successful response MUST use
// the 200 OK HTTP status code and return a JSON object using the
// "application/json" content type". OpenID Connect Discovery 1.0 Section 4.2
// requires the same. The capture run then checks the document's issuer
// against the Issuer the URL was built from.
func metadataExample(ctx context.Context, env *capture.Env, wellKnownPath string) (capture.ExampleResult, error) {
	issuer := env.BaseURL
	resp, err := fetchMetadata(ctx, env, issuer+wellKnownPath)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	return capture.ExampleResult{
		Value: string(resp.Body),
		Source: conformance.ExampleSource{
			Exchange: 0,
			Message:  conformance.ExampleInResponse,
			Location: "the body",
		},
		IssuerMember: "issuer",
		Issuer:       issuer,
	}, nil
}

// fetchMetadata records a GET for a metadata document and requires the
// response a client may use: 200 with a JSON content type.
func fetchMetadata(ctx context.Context, env *capture.Env, target string) (*capture.Response, error) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("%s was answered %d %s", target, resp.Status, capture.Truncate(resp.Body))
	}
	if mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return nil, fmt.Errorf("%s was answered with content type %q, not application/json", target, resp.Header.Get("Content-Type"))
	}
	return resp, nil
}

// clientID is the Mock IdP's seeded public client. A public client has no
// secret, so the capture holds no credential for it.
const clientID = "public-app"

// redirectURI is the redirect_uri the client has registered for the app
// under capture, the Looking Glass callback. The conformance client is the
// user agent and reads the Authorization Response from the redirect itself,
// so nothing is sent to that URL.
func redirectURI(env *capture.Env) string {
	if env.BaseURL == capture.ProductionBaseURL {
		return env.BaseURL + "/callback"
	}
	return "http://localhost:3000/callback"
}

// provider is the part of the OpenID Provider's configuration the client
// uses.
type provider struct {
	issuer                string
	authorizationEndpoint string
	tokenEndpoint         string
	revocationEndpoint    string
	jwksURI               string
}

// discover records a request for the OpenID Provider's configuration.
// OpenID Connect Discovery 1.0 Section 4 puts it "at the path formed by
// concatenating the string /.well-known/openid-configuration to the Issuer",
// and Section 4.3 says "The issuer value returned MUST be identical to the
// Issuer URL that was used as the prefix to /.well-known/openid-configuration
// to retrieve the configuration information." Every endpoint must be on the
// app under capture: a run never follows a URL to another host.
func discover(ctx context.Context, env *capture.Env) (*provider, error) {
	issuer := env.BaseURL
	resp, err := fetchMetadata(ctx, env, issuer+providerConfigurationPath)
	if err != nil {
		return nil, err
	}
	configuration, err := resp.JSON()
	if err != nil {
		return nil, err
	}
	if configuration["issuer"] != issuer {
		return nil, fmt.Errorf("the discovery document's issuer %v is not %q", configuration["issuer"], issuer)
	}
	found := &provider{issuer: issuer}
	for name, target := range map[string]*string{
		"authorization_endpoint": &found.authorizationEndpoint,
		"token_endpoint":         &found.tokenEndpoint,
		"revocation_endpoint":    &found.revocationEndpoint,
		"jwks_uri":               &found.jwksURI,
	} {
		value, _ := configuration[name].(string)
		if !strings.HasPrefix(value, env.BaseURL+"/") {
			return nil, fmt.Errorf("the discovery document's %s %q is not on %s", name, value, env.BaseURL)
		}
		*target = value
	}
	return found, nil
}

// randomValue returns 32 random bytes, base64url-encoded: 43 characters,
// the minimum length RFC 7636 Section 4.1 allows for a code_verifier.
func randomValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// revoke asks the authorization server to revoke a token the client was
// issued. A public client identifies itself with client_id (RFC 7009
// Section 2.1). The request is not recorded: it is the capture cleaning up,
// not part of what the example shows.
func revoke(ctx context.Context, env *capture.Env, op *provider, token, hint string) error {
	req, err := capture.NewForm(op.revocationEndpoint, url.Values{
		"token":           {token},
		"token_type_hint": {hint},
		"client_id":       {clientID},
	})
	if err != nil {
		return err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return err
	}
	if resp.Status != http.StatusOK {
		return fmt.Errorf("revoking the %s was answered %d %s", hint, resp.Status, capture.Truncate(resp.Body))
	}
	return nil
}

// idTokenExample captures the ID Token of an authorization code flow from
// the Token Response that carried it. It checks what the registry's notes
// say about the token: iss is the discovered Issuer, aud is the client, and
// nonce is the value the Authentication Request sent.
func idTokenExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	op, err := discover(ctx, env)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	var state, nonce, verifier string
	for _, value := range []*string{&state, &nonce, &verifier} {
		if *value, err = randomValue(); err != nil {
			return capture.ExampleResult{}, err
		}
	}
	challenge := sha256.Sum256([]byte(verifier))
	redirect := redirectURI(env)

	authenticationRequest := op.authorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirect},
		"scope":                 {"openid"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}.Encode()
	location, err := capture.AuthenticateEndUser(ctx, env, authenticationRequest, true)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	if !strings.HasPrefix(location, redirect+"?") {
		return capture.ExampleResult{}, fmt.Errorf("the Authorization Response went to %q, not the client's redirect_uri", location)
	}
	response, err := url.ParseQuery(strings.TrimPrefix(location, redirect+"?"))
	if err != nil {
		return capture.ExampleResult{}, fmt.Errorf("parse the Authorization Response query: %w", err)
	}
	if response.Get("error") != "" {
		return capture.ExampleResult{}, fmt.Errorf("the Authorization Response is an error: %s %s", response.Get("error"), response.Get("error_description"))
	}
	if response.Get("state") != state {
		return capture.ExampleResult{}, fmt.Errorf("the Authorization Response's state is not the value the Authentication Request sent")
	}

	tokenRequest, err := capture.NewForm(op.tokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {response.Get("code")},
		"redirect_uri":  {redirect},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	if err != nil {
		return capture.ExampleResult{}, err
	}
	tokenResponse, err := env.Do(ctx, tokenRequest)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	if tokenResponse.Status != http.StatusOK {
		return capture.ExampleResult{}, fmt.Errorf("the token endpoint answered %d %s", tokenResponse.Status, capture.Truncate(tokenResponse.Body))
	}
	tokens, err := tokenResponse.JSON()
	if err != nil {
		return capture.ExampleResult{}, err
	}
	// The Token Response is published in full, so the tokens in it that can
	// be used at an endpoint are revoked before the run returns, each by
	// name.
	for _, issued := range []struct{ member, hint string }{
		{"refresh_token", "refresh_token"},
		{"access_token", "access_token"},
	} {
		token, _ := tokens[issued.member].(string)
		if token == "" {
			continue
		}
		if err := revoke(ctx, env, op, token, issued.hint); err != nil {
			return capture.ExampleResult{}, err
		}
	}

	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		return capture.ExampleResult{}, fmt.Errorf("the Token Response carries no id_token")
	}
	_, claims, err := capture.JWTParts(idToken)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	for name, want := range map[string]string{"iss": op.issuer, "aud": clientID, "nonce": nonce} {
		if got, _ := claims[name].(string); got != want {
			return capture.ExampleResult{}, fmt.Errorf("the ID Token's %s is %q, want %q", name, got, want)
		}
	}
	// An ID Token cannot be revoked. It stops being acceptable at exp, so
	// the example is published only after that.
	exp, ok := claims["exp"].(float64)
	if !ok {
		return capture.ExampleResult{}, fmt.Errorf("the ID Token has no numeric exp")
	}

	jwksRequest, err := http.NewRequest(http.MethodGet, op.jwksURI, nil)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	jwks, err := env.Do(ctx, jwksRequest)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	if jwks.Status != http.StatusOK {
		return capture.ExampleResult{}, fmt.Errorf("jwks_uri answered %d %s", jwks.Status, capture.Truncate(jwks.Body))
	}

	// Recorded, in order: discovery, the Authentication Request, the Token
	// Request, the JWK Set.
	const tokenExchange, jwksExchangeIndex = 2, 3
	jwksExchange := jwksExchangeIndex
	return capture.ExampleResult{
		Value: idToken,
		Source: conformance.ExampleSource{
			Exchange: tokenExchange,
			Message:  conformance.ExampleInResponse,
			Location: "the id_token member of the JSON body",
		},
		JWKSExchange: &jwksExchange,
		ValueExpires: time.Unix(int64(exp), 0),
	}, nil
}
