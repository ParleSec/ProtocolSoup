// Package saml captures SAML 2.0 example messages as a browser carries them
// in Web Browser SSO: the conformance client is the user agent between the
// service provider and the identity provider.
package saml

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.RegisterExample("saml-response", capture.ExampleScenario{
		Description: "The conformance client acts as the user agent in SP-initiated Web Browser SSO. It asks the service provider to sign in, and the service provider redirects it to the identity provider with an AuthnRequest. " +
			"The identity provider answers with its sign-in page. The client signs in as a demo user, which is not recorded: how the user authenticates is the identity provider's own business, not a SAML message. " +
			"The identity provider answers that sign-in with an HTML form holding the Response, and the client posts the form to the service provider's Assertion Consumer Service, as a browser would. That post is the Response's delivery. " +
			"The client then fetches the identity provider's metadata, whose certificate verifies the signatures.",
		Actor: conformance.ActorConformanceClient,
		Run:   responseExample,
	})
}

// assertionLifetime is how long the identity provider makes an Assertion
// valid. The Response is published in full, so the set is not published
// before the Assertion in it has expired.
const assertionLifetime = 5 * time.Minute

// The form the identity provider returns to deliver a message by HTTP POST.
var (
	formAction   = regexp.MustCompile(`<form[^>]*\saction="([^"]*)"`)
	formControls = regexp.MustCompile(`<input[^>]*\sname="([^"]+)"[^>]*\svalue="([^"]*)"`)
)

// onTheApp requires a URL a party names to be on the app under capture: a
// run never follows a URL to another host.
func onTheApp(env *capture.Env, name, value string) error {
	if !strings.HasPrefix(value, env.BaseURL+"/") {
		return fmt.Errorf("%s %q is not on %s", name, value, env.BaseURL)
	}
	return nil
}

// cookieOf returns the name=value pair of the first Set-Cookie header, to be
// sent back as a browser would. The identity provider marks its cookies
// Secure, and a browser still returns them to http://localhost.
func cookieOf(resp *capture.Response) string {
	pair, _, _ := strings.Cut(resp.Header.Get("Set-Cookie"), ";")
	return strings.TrimSpace(pair)
}

// responseExample captures a SAML Response from the request that delivers it
// to the service provider.
func responseExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	fail := func(err error) (capture.ExampleResult, error) { return capture.ExampleResult{}, err }
	get := func(target string) (*http.Request, error) {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err == nil {
			req.Header.Set("Accept", "text/html")
		}
		return req, err
	}

	// Recorded exchange 0: the service provider issues the AuthnRequest.
	req, err := get(env.BaseURL + "/saml/sp/login")
	if err != nil {
		return fail(err)
	}
	started, err := env.Do(ctx, req)
	if err != nil {
		return fail(err)
	}
	singleSignOn := started.Header.Get("Location")
	if started.Status != http.StatusFound && started.Status != http.StatusSeeOther {
		return fail(fmt.Errorf("the service provider answered %d, not a redirect to the identity provider: %s", started.Status, capture.Truncate(started.Body)))
	}
	if err := onTheApp(env, "the single sign-on location", singleSignOn); err != nil {
		return fail(err)
	}

	// Recorded exchange 1: the identity provider receives it and asks the
	// user to sign in.
	req, err = get(singleSignOn)
	if err != nil {
		return fail(err)
	}
	page, err := env.Do(ctx, req)
	if err != nil {
		return fail(err)
	}
	action := formAction.FindSubmatch(page.Body)
	if page.Status != http.StatusOK || action == nil {
		return fail(fmt.Errorf("the identity provider answered %d without a sign-in form: %s", page.Status, capture.Truncate(page.Body)))
	}
	signIn := html.UnescapeString(string(action[1]))
	if err := onTheApp(env, "the sign-in form's action", signIn); err != nil {
		return fail(err)
	}

	email, password, err := capture.DemoUser(ctx, env)
	if err != nil {
		return fail(err)
	}
	req, err = capture.NewForm(signIn, url.Values{"email": {email}, "password": {password}})
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Cookie", cookieOf(page))
	delivered, err := env.Setup(ctx, req)
	if err != nil {
		return fail(err)
	}
	action = formAction.FindSubmatch(delivered.Body)
	if delivered.Status != http.StatusOK || action == nil {
		return fail(fmt.Errorf("the sign-in was answered %d without a form to post: %s", delivered.Status, capture.Truncate(delivered.Body)))
	}
	consumer := html.UnescapeString(string(action[1]))
	if err := onTheApp(env, "the Assertion Consumer Service", consumer); err != nil {
		return fail(err)
	}
	form := url.Values{}
	for _, control := range formControls.FindAllSubmatch(delivered.Body, -1) {
		form.Set(string(control[1]), html.UnescapeString(string(control[2])))
	}
	response := form.Get("SAMLResponse")
	if response == "" {
		return fail(fmt.Errorf("the identity provider's form carries no SAMLResponse control"))
	}
	env.NoteExpiry(assertionLifetime)

	// Recorded exchange 2: the user agent delivers the Response.
	req, err = capture.NewForm(consumer, form)
	if err != nil {
		return fail(err)
	}
	consumed, err := env.Do(ctx, req)
	if err != nil {
		return fail(err)
	}
	if consumed.Status >= http.StatusBadRequest {
		return fail(fmt.Errorf("the service provider refused the Response with %d %s", consumed.Status, capture.Truncate(consumed.Body)))
	}

	// Recorded exchange 3: the identity provider's metadata, published at
	// its entityID, which is the Issuer the Response names.
	document, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		return fail(fmt.Errorf("the SAMLResponse control is not base64: %w", err))
	}
	issuer := responseIssuer.FindSubmatch(document)
	if issuer == nil {
		return fail(fmt.Errorf("the Response names no Issuer"))
	}
	entityID := html.UnescapeString(string(issuer[1]))
	if err := onTheApp(env, "the Response's Issuer", entityID); err != nil {
		return fail(err)
	}
	req, err = http.NewRequest(http.MethodGet, entityID, nil)
	if err != nil {
		return fail(err)
	}
	metadata, err := env.Do(ctx, req)
	if err != nil {
		return fail(err)
	}
	if metadata.Status != http.StatusOK {
		return fail(fmt.Errorf("the identity provider's metadata was answered %d %s", metadata.Status, capture.Truncate(metadata.Body)))
	}

	const deliveryExchange, metadataExchangeIndex = 2, 3
	metadataExchange := metadataExchangeIndex
	return capture.ExampleResult{
		Value: response,
		Source: conformance.ExampleSource{
			Exchange:  deliveryExchange,
			Message:   conformance.ExampleInRequest,
			Location:  "the SAMLResponse control of the form body",
			FormField: "SAMLResponse",
		},
		JWKSExchange: &metadataExchange,
	}, nil
}

// responseIssuer finds the first Issuer of a Response, which is the
// message's own: the schema puts it before the Assertion.
var responseIssuer = regexp.MustCompile(`<(?:[A-Za-z0-9]+:)?Issuer[^>]*>([^<]+)</`)
