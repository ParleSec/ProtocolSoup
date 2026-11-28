// Package scim captures SCIM 2.0 example resources as a provisioning client
// obtains them: the conformance client creates a User at the service provider
// and retrieves it from the URI the service provider gave it.
package scim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.RegisterExample("scim-user", capture.ExampleScenario{
		Description: "The conformance client acts as a provisioning client. With an access token for the seeded SCIM client, which grants scim.read and scim.write, it creates a User with POST; " +
			"the token request is not recorded here. The service provider answers 201 (Created), issues the id and names the User's URI in the Location header and in meta.location. " +
			"The client then sends a GET to that URI, and the response body is the User on this page. " +
			"Afterwards the client deletes the User and revokes the access token.",
		Actor: conformance.ActorConformanceClient,
		Run:   userExample,
	})
}

// scimClientID is the Mock IdP's seeded SCIM client (mockidp.SCIMClientID).
const scimClientID = "scim-client"

// scimMediaType is the media type of SCIM requests and responses (RFC 7644
// Section 3.8).
const scimMediaType = "application/scim+json"

// userSchema is the core User schema URI (RFC 7643 Section 4.1).
const userSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// randomHex returns n random bytes in hexadecimal.
func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// userExample captures a User from the response to a GET of its location.
func userExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	fail := func(err error) (capture.ExampleResult, error) { return capture.ExampleResult{}, err }

	secret, tokenEndpoint, err := capture.DemoClient(ctx, env, scimClientID)
	if err != nil {
		return fail(err)
	}
	tokenRequest, err := capture.NewForm(tokenEndpoint, url.Values{"grant_type": {"client_credentials"}, "scope": {"scim.read scim.write"}})
	if err != nil {
		return fail(err)
	}
	tokenRequest.SetBasicAuth(scimClientID, secret)
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
		if err := capture.RevokeAccessToken(ctx, env, scimClientID, secret, accessToken); err != nil {
			env.NoteExpiry(capture.AccessTokenLifetime(tokens))
		}
	}()
	authorize := func(req *http.Request) {
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", scimMediaType)
	}

	// The User is made for this capture and stands for no person: its names
	// say what it is, and its address is under example.com (RFC 2606).
	suffix, err := randomHex(4)
	if err != nil {
		return fail(err)
	}
	externalID, err := randomHex(8)
	if err != nil {
		return fail(err)
	}
	address := "conformance.capture." + suffix + "@example.com"

	// Recorded exchange 0: the client creates the User (RFC 7644 Section 3.3).
	create, err := capture.NewJSON(env.BaseURL+"/scim/v2/Users", map[string]any{
		"schemas":     []string{userSchema},
		"externalId":  externalID,
		"userName":    address,
		"name":        map[string]any{"formatted": "Conformance Capture", "familyName": "Capture", "givenName": "Conformance"},
		"displayName": "Conformance Capture",
		"active":      true,
		"emails":      []map[string]any{{"value": address, "type": "work", "primary": true}},
	})
	if err != nil {
		return fail(err)
	}
	create.Header.Set("Content-Type", scimMediaType)
	authorize(create)
	created, err := env.Do(ctx, create)
	if err != nil {
		return fail(err)
	}
	if created.Status != http.StatusCreated {
		return fail(fmt.Errorf("creating the User was answered %d %s", created.Status, capture.Truncate(created.Body)))
	}
	location := created.Header.Get("Location")
	// A run never follows a URI to another host.
	if !strings.HasPrefix(location, env.BaseURL+"/scim/v2/Users/") {
		return fail(fmt.Errorf("the Location header %q is not a User of %s", location, env.BaseURL))
	}
	defer func() {
		remove, err := http.NewRequest(http.MethodDelete, location, nil)
		if err != nil {
			return
		}
		authorize(remove)
		_, _ = env.Setup(ctx, remove)
	}()

	// Recorded exchange 1: the client retrieves the User at the URI it was
	// given (RFC 7644 Section 3.4.1).
	retrieve, err := http.NewRequest(http.MethodGet, location, nil)
	if err != nil {
		return fail(err)
	}
	authorize(retrieve)
	retrieved, err := env.Do(ctx, retrieve)
	if err != nil {
		return fail(err)
	}
	if retrieved.Status != http.StatusOK {
		return fail(fmt.Errorf("retrieving the User was answered %d %s", retrieved.Status, capture.Truncate(retrieved.Body)))
	}

	// The User must be what the page says it is: the one this client asked
	// for, under the names it sent.
	user, err := retrieved.JSON()
	if err != nil {
		return fail(err)
	}
	if user["userName"] != address || user["externalId"] != externalID {
		return fail(fmt.Errorf("the retrieved User has userName %v and externalId %v, not the ones the client sent", user["userName"], user["externalId"]))
	}

	const createExchange, retrieveExchange = 0, 1
	createdExchange := createExchange
	return capture.ExampleResult{
		Value: string(retrieved.Body),
		Source: conformance.ExampleSource{
			Exchange: retrieveExchange,
			Message:  conformance.ExampleInResponse,
			Location: "the body",
		},
		CreatedExchange: &createdExchange,
	}, nil
}
