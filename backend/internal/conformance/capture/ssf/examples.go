// Package ssf captures Shared Signals Framework example messages as an Event
// Receiver obtains them: the conformance client creates a poll stream, asks
// the Transmitter to verify it, and polls for the Security Event Token.
package ssf

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.RegisterExample("security-event-token", capture.ExampleScenario{
		Description: "The conformance client acts as an Event Receiver. It reads the Transmitter Configuration Metadata, then, with an access token for the seeded stream client, creates a stream that uses poll delivery (RFC 8936); " +
			"the token request and the stream creation are not recorded here. It asks the Transmitter to verify the stream with a state value it chose, and polls. " +
			"The poll response carries the Verification Event as a Security Event Token, and the event repeats that state. " +
			"The client then fetches the JWK Set at the metadata's jwks_uri, which holds the key that verifies the token's signature. " +
			"Afterwards it acknowledges the token, deletes the stream and revokes the access token.",
		Actor: conformance.ActorConformanceClient,
		Run:   securityEventTokenExample,
	})
}

// streamClientID is the Mock IdP's seeded Event Receiver client.
const streamClientID = "ssf-stream-client"

// verificationEvent is the event type of a Verification Event (OpenID Shared
// Signals Framework 1.0 Section 8.1.4.1).
const verificationEvent = "https://schemas.openid.net/secevent/ssf/event-type/verification"

// randomValue returns 24 random bytes, base64url-encoded.
func randomValue() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// onTheApp requires a URL the Transmitter or the stream names to be on the
// app under capture: a run never follows a URL to another host.
func onTheApp(env *capture.Env, name, value string) error {
	if !strings.HasPrefix(value, env.BaseURL+"/") {
		return fmt.Errorf("%s %q is not on %s", name, value, env.BaseURL)
	}
	return nil
}

// securityEventTokenExample captures the Security Event Token of a
// Verification Event from the poll response that delivered it. A Transmitter
// accepts Bearer tokens only when it is configured with its authorization
// server's JWK Set location (SSF_AS_JWKS_URI), which production requires; a
// local server needs it set for this scenario.
func securityEventTokenExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	fail := func(err error) (capture.ExampleResult, error) { return capture.ExampleResult{}, err }

	// Recorded exchange 0: the Transmitter Configuration Metadata.
	configuration, err := capture.FetchMetadata(ctx, env, env.BaseURL+"/.well-known/ssf-configuration")
	if err != nil {
		return fail(err)
	}
	metadata, err := configuration.JSON()
	if err != nil {
		return fail(err)
	}
	if metadata["issuer"] != env.BaseURL {
		return fail(fmt.Errorf("the Transmitter's issuer %v is not %q", metadata["issuer"], env.BaseURL))
	}
	endpoints := map[string]string{}
	for _, name := range []string{"configuration_endpoint", "verification_endpoint", "jwks_uri"} {
		value, _ := metadata[name].(string)
		if err := onTheApp(env, name, value); err != nil {
			return fail(err)
		}
		endpoints[name] = value
	}

	secret, tokenEndpoint, err := capture.DemoClient(ctx, env, streamClientID)
	if err != nil {
		return fail(err)
	}
	tokenRequest, err := capture.NewForm(tokenEndpoint, url.Values{"grant_type": {"client_credentials"}, "scope": {"ssf.manage ssf.read"}})
	if err != nil {
		return fail(err)
	}
	tokenRequest.SetBasicAuth(streamClientID, secret)
	tokenResponse, err := env.Setup(ctx, tokenRequest)
	if err != nil {
		return fail(err)
	}
	tokens, err := tokenResponse.JSON()
	if err != nil {
		return fail(err)
	}
	accessToken, _ := tokens["access_token"].(string)
	if tokenResponse.Status != http.StatusOK || accessToken == "" {
		return fail(fmt.Errorf("the token endpoint answered %d %s", tokenResponse.Status, capture.Truncate(tokenResponse.Body)))
	}
	// The access token is in the recorded requests, so it is revoked before
	// the run returns. A token that cannot be revoked must expire first.
	defer func() {
		if err := capture.RevokeAccessToken(ctx, env, streamClientID, secret, accessToken); err != nil {
			env.NoteExpiry(capture.AccessTokenLifetime(tokens))
		}
	}()
	authorized := func(method, target string, body any, record bool) (*capture.Response, error) {
		var req *http.Request
		var err error
		if body == nil {
			req, err = http.NewRequest(method, target, nil)
		} else {
			req, err = capture.NewJSON(target, body)
		}
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		if record {
			return env.Do(ctx, req)
		}
		return env.Setup(ctx, req)
	}

	created, err := authorized(http.MethodPost, endpoints["configuration_endpoint"], map[string]any{
		"delivery":         map[string]any{"method": "urn:ietf:rfc:8936"},
		"events_requested": []string{verificationEvent},
		"description":      "ProtocolSoup conformance capture",
	}, false)
	if err != nil {
		return fail(err)
	}
	stream, err := created.JSON()
	if err != nil {
		return fail(err)
	}
	streamID, _ := stream["stream_id"].(string)
	delivery, _ := stream["delivery"].(map[string]any)
	pollEndpoint, _ := delivery["endpoint_url"].(string)
	if created.Status != http.StatusCreated || streamID == "" {
		return fail(fmt.Errorf("creating the stream was answered %d %s", created.Status, capture.Truncate(created.Body)))
	}
	defer func() {
		_, _ = authorized(http.MethodDelete, endpoints["configuration_endpoint"]+"?stream_id="+url.QueryEscape(streamID), nil, false)
	}()
	if err := onTheApp(env, "the stream's poll endpoint_url", pollEndpoint); err != nil {
		return fail(err)
	}

	// Recorded exchange 1: the Receiver asks for a Verification Event.
	state, err := randomValue()
	if err != nil {
		return fail(err)
	}
	verify, err := authorized(http.MethodPost, endpoints["verification_endpoint"], map[string]any{"stream_id": streamID, "state": state}, true)
	if err != nil {
		return fail(err)
	}
	if verify.Status != http.StatusNoContent {
		return fail(fmt.Errorf("the verification request was answered %d %s", verify.Status, capture.Truncate(verify.Body)))
	}

	// Recorded exchange 2: the poll that delivers the token.
	polled, err := authorized(http.MethodPost, pollEndpoint, map[string]any{"returnImmediately": true}, true)
	if err != nil {
		return fail(err)
	}
	delivered, err := polled.JSON()
	if err != nil {
		return fail(err)
	}
	sets, _ := delivered["sets"].(map[string]any)
	if polled.Status != http.StatusOK || len(sets) != 1 {
		return fail(fmt.Errorf("the poll was answered %d with %d SETs, want 1: %s", polled.Status, len(sets), capture.Truncate(polled.Body)))
	}
	var jti, set string
	for id, value := range sets {
		jti = id
		set, _ = value.(string)
	}
	// RFC 8936 Section 2.4: the Receiver acknowledges the SETs it received.
	if _, err := authorized(http.MethodPost, pollEndpoint, map[string]any{"ack": []string{jti}, "returnImmediately": true}, false); err != nil {
		return fail(err)
	}

	// The token must be what the page says it is: issued by this
	// Transmitter, keyed in the poll response by its own jti, and carrying
	// the Verification Event with the state the Receiver sent.
	_, claims, err := capture.JWTParts(set)
	if err != nil {
		return fail(err)
	}
	if claims["iss"] != env.BaseURL || claims["jti"] != jti {
		return fail(fmt.Errorf("the SET's iss %v and jti %v are not the Transmitter %q and the poll key %q", claims["iss"], claims["jti"], env.BaseURL, jti))
	}
	events, _ := claims["events"].(map[string]any)
	event, _ := events[verificationEvent].(map[string]any)
	if len(events) != 1 || event["state"] != state {
		return fail(fmt.Errorf("the SET does not carry one Verification Event with the state the Receiver sent"))
	}

	// Recorded exchange 3: the JWK Set that verifies the token.
	jwksRequest, err := http.NewRequest(http.MethodGet, endpoints["jwks_uri"], nil)
	if err != nil {
		return fail(err)
	}
	jwks, err := env.Do(ctx, jwksRequest)
	if err != nil {
		return fail(err)
	}
	if jwks.Status != http.StatusOK {
		return fail(fmt.Errorf("jwks_uri answered %d %s", jwks.Status, capture.Truncate(jwks.Body)))
	}

	const pollExchange, jwksExchangeIndex = 2, 3
	jwksExchange := jwksExchangeIndex
	return capture.ExampleResult{
		Value: set,
		Source: conformance.ExampleSource{
			Exchange: pollExchange,
			Message:  conformance.ExampleInResponse,
			Location: "the one member of sets, in the JSON body",
		},
		JWKSExchange: &jwksExchange,
	}, nil
}
