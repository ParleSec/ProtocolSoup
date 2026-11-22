package rfc9449

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.RegisterExample("dpop-proof", capture.ExampleScenario{
		Description: "The conformance client presents a DPoP-bound access token to GET /oauth2/resource with a DPoP proof it signed for that request. The proof carries ath, the hash of the token, and the nonce the resource issued in an earlier use_dpop_nonce challenge. The resource answered 200.",
		Actor:       conformance.ActorConformanceClient,
		Run:         dpopProofExample,
	})
	capture.RegisterExample("dpop-bound-access-token", capture.ExampleScenario{
		Description: "The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof, and the token endpoint issues an access token bound to the proof's key. The client presents the token to GET /oauth2/resource with a second proof, and the resource answers 200. The client then reads the token issuer's metadata and its JWK Set, which holds the key that verifies the token's signature.",
		Actor:       conformance.ActorConformanceClient,
		Run:         boundAccessTokenExample,
	})
}

// presentBoundToken sends token to the OAuth 2.0 protected resource with a
// DPoP proof signed by key, recording the request the resource accepts. It
// returns that proof and how many exchanges it recorded; the accepted one
// is the last. The resource's nonce is learned with an unrecorded request
// first, as resourceATH does.
func presentBoundToken(ctx context.Context, env *capture.Env, key *proofKey, token string) (proof string, recorded int, err error) {
	resource := env.BaseURL + "/oauth2/resource"
	send := func(nonce string, record bool) (*capture.Response, string, error) {
		spec, err := newProofSpec(key, http.MethodGet, resource, nonce, token)
		if err != nil {
			return nil, "", err
		}
		signed, err := spec.signES256(key)
		if err != nil {
			return nil, "", err
		}
		req, err := http.NewRequest(http.MethodGet, resource, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", signed)
		do := env.Setup
		if record {
			do = env.Do
		}
		resp, err := do(ctx, req)
		return resp, signed, err
	}
	challenge := func(resp *capture.Response) string {
		if resp.Status == http.StatusUnauthorized && resp.Error() == "use_dpop_nonce" {
			return resp.Header.Get("DPoP-Nonce")
		}
		return ""
	}

	probe, _, err := send("", false)
	if err != nil {
		return "", 0, err
	}
	nonce := challenge(probe)
	if nonce == "" && probe.Status != http.StatusOK {
		return "", 0, fmt.Errorf("protected resource answered %d %s", probe.Status, capture.Truncate(probe.Body))
	}

	resp, proof, err := send(nonce, true)
	if err != nil {
		return "", 0, err
	}
	recorded = 1
	// The nonce can rotate between the probe and this request.
	if rotated := challenge(resp); rotated != "" {
		if resp, proof, err = send(rotated, true); err != nil {
			return "", 0, err
		}
		recorded = 2
	}
	if resp.Status != http.StatusOK {
		return "", 0, fmt.Errorf("protected resource answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	return proof, recorded, nil
}

// dpopProofExample captures the DPoP proof of a protected resource request
// the resource accepted. That proof carries every claim RFC 9449 Section
// 4.2 defines: jti, htm, htu and iat, ath because it accompanies an access
// token, and nonce because the resource provided one.
func dpopProofExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	client, err := newTokenClient(ctx, env)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	key, err := newProofKey(elliptic.P256())
	if err != nil {
		return capture.ExampleResult{}, err
	}
	token, lifetime, err := client.boundToken(ctx, env, key)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	defer client.retireToken(ctx, env, token, lifetime)

	proof, recorded, err := presentBoundToken(ctx, env, key, token)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	return capture.ExampleResult{
		Value: proof,
		Source: conformance.ExampleSource{
			Exchange: recorded - 1,
			Message:  conformance.ExampleInRequest,
			Location: "the DPoP header",
		},
	}, nil
}

// boundAccessTokenExample captures a DPoP-bound access token from the token
// response that issued it, shows the protected resource accepting it, and
// fetches the JWK Set that verifies it the way a resource server finds it:
// from the metadata of the issuer the token names (RFC 8414 Section 3).
func boundAccessTokenExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	client, err := newTokenClient(ctx, env)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	key, err := newProofKey(elliptic.P256())
	if err != nil {
		return capture.ExampleResult{}, err
	}
	nonce, err := client.serverNonce(ctx, env, key)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	requestToken := func(nonce string) (*capture.Response, error) {
		proof, err := client.conformantProof(key, nonce)
		if err != nil {
			return nil, err
		}
		req, err := client.request(proof)
		if err != nil {
			return nil, err
		}
		return env.Do(ctx, req)
	}
	resp, err := requestToken(nonce)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	recorded := 1
	// The nonce can rotate between preparation and this request.
	if resp.Status == http.StatusBadRequest && resp.Error() == "use_dpop_nonce" && resp.Header.Get("DPoP-Nonce") != "" {
		if resp, err = requestToken(resp.Header.Get("DPoP-Nonce")); err != nil {
			return capture.ExampleResult{}, err
		}
		recorded++
	}
	if resp.Status != http.StatusOK {
		return capture.ExampleResult{}, fmt.Errorf("token endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	token, lifetime, err := dpopToken(resp)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	defer client.retireToken(ctx, env, token, lifetime)
	tokenExchange := recorded - 1

	_, presented, err := presentBoundToken(ctx, env, key, token)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	recorded += presented

	jwksURI, err := issuerJWKSURI(ctx, env, token)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	recorded++
	req, err := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	jwks, err := env.Do(ctx, req)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	if jwks.Status != http.StatusOK {
		return capture.ExampleResult{}, fmt.Errorf("jwks_uri answered %d %s", jwks.Status, capture.Truncate(jwks.Body))
	}
	jwksExchange := recorded
	return capture.ExampleResult{
		Value: token,
		Source: conformance.ExampleSource{
			Exchange: tokenExchange,
			Message:  conformance.ExampleInResponse,
			Location: "the access_token member of the JSON body",
		},
		JWKSExchange: &jwksExchange,
	}, nil
}

// issuerJWKSURI records a request for the authorization server metadata of
// the issuer the token names and returns its jwks_uri. RFC 8414 Section 3
// puts the metadata "at a path formed by inserting a well-known URI string
// into the authorization server's issuer identifier between the host
// component and the path component, if any", and Section 3.3 says "The
// "issuer" value returned MUST be identical to the authorization server's
// issuer identifier value into which the well-known URI string was inserted
// to create the URL used to retrieve the metadata. If these values are not
// identical, the data contained in the response MUST NOT be used." Both URLs
// must be on the app under capture: a run never follows a URL to another
// host.
func issuerJWKSURI(ctx context.Context, env *capture.Env, token string) (string, error) {
	issuer, err := capture.JWTClaim(token, "iss")
	if err != nil {
		return "", err
	}
	if issuer != env.BaseURL && !strings.HasPrefix(issuer, env.BaseURL+"/") {
		return "", fmt.Errorf("the token's iss %q is not on %s", issuer, env.BaseURL)
	}
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", err
	}
	parsed.Path = "/.well-known/oauth-authorization-server" + strings.TrimSuffix(parsed.Path, "/")
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("%s answered %d %s", parsed.String(), resp.Status, capture.Truncate(resp.Body))
	}
	metadata, err := resp.JSON()
	if err != nil {
		return "", err
	}
	if metadata["issuer"] != issuer {
		return "", fmt.Errorf("metadata issuer %v is not the token's iss %q", metadata["issuer"], issuer)
	}
	jwksURI, _ := metadata["jwks_uri"].(string)
	if !strings.HasPrefix(jwksURI, env.BaseURL+"/") {
		return "", fmt.Errorf("jwks_uri %q is not on %s", jwksURI, env.BaseURL)
	}
	return jwksURI, nil
}
