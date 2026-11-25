package oid4vci

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.RegisterExample("openid-credential-issuer", capture.ExampleScenario{
		Description: "The conformance client requests the Credential Issuer Metadata the way a Wallet does: " +
			"it inserts /.well-known/openid-credential-issuer between the host and the path of the Credential Issuer Identifier and sends a GET with an Accept header naming application/json " +
			"(OpenID4VCI 1.0 Section 12.2.2). The body of the response is the document.",
		Actor: conformance.ActorConformanceClient,
		Run:   issuerMetadataExample,
	})
	capture.RegisterExample("sd-jwt-vc", capture.ExampleScenario{
		Description: "The conformance client acts as a Wallet in the Pre-Authorized Code Flow. It reads the Credential Issuer Metadata, redeems a Credential Offer at the Token Endpoint and fetches a c_nonce, " +
			"none of which is recorded here. It then sends the Credential Request, with a jwt proof signed by a holder key it has just made, and the Credential Response carries the SD-JWT VC. " +
			"To check the signature it builds the JWT VC Issuer Metadata location from the credential's iss and fetches it: the kid in the credential's header selects the key. " +
			"The credential is bound to the holder key through cnf, and the capture discards that key's private half, so no Key Binding JWT can be made for this credential.",
		Actor: conformance.ActorConformanceClient,
		Run:   sdJWTVCExample,
	})
}

// sdJWTVCExample captures an SD-JWT VC from the Credential Response that
// issued it and the JWT VC Issuer Metadata that holds its verification key.
// SD-JWT VC draft 11 Section 5 puts that document "at the location formed by
// inserting the well-known string /.well-known/jwt-vc-issuer between the host
// component and the path component (if any) of the iss claim value in the
// JWT". The location must be on the app under capture: a run never follows a
// URL to another host.
func sdJWTVCExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{OfferOptions: capture.OfferOptions{TxCode: true}})
	if err != nil {
		return capture.ExampleResult{}, err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return capture.ExampleResult{}, err
	}
	nonce, err := capture.FreshNonce(ctx, env, issuer)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	proof, err := key.Proof(issuer.ID, nonce)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	req, err := capture.BearerJSON(issuer.Credential, grant.AccessToken, grant.CredentialRequest(proof))
	if err != nil {
		return capture.ExampleResult{}, err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	if resp.Status != http.StatusOK {
		return capture.ExampleResult{}, fmt.Errorf("the Credential Request was answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return capture.ExampleResult{}, err
	}
	credentials, err := capture.IssuedCredentials(body)
	if err != nil {
		return capture.ExampleResult{}, err
	}
	if len(credentials) != 1 {
		return capture.ExampleResult{}, fmt.Errorf("the Credential Response carries %d credentials, want 1", len(credentials))
	}
	credential := credentials[0]

	iss, err := capture.SDJWTClaim(credential, "iss")
	if err != nil {
		return capture.ExampleResult{}, err
	}
	location, err := url.Parse(iss)
	if err != nil {
		return capture.ExampleResult{}, fmt.Errorf("parse the credential's iss: %w", err)
	}
	if origin := location.Scheme + "://" + location.Host; origin != env.BaseURL {
		return capture.ExampleResult{}, fmt.Errorf("the credential's iss %q is not on %s", iss, env.BaseURL)
	}
	location.Path = "/.well-known/jwt-vc-issuer" + strings.TrimSuffix(location.Path, "/")
	if _, err := capture.FetchMetadata(ctx, env, location.String()); err != nil {
		return capture.ExampleResult{}, err
	}

	// Recorded, in order: the Credential Request, the JWT VC Issuer Metadata.
	metadataExchange := 1
	return capture.ExampleResult{
		Value: credential,
		Source: conformance.ExampleSource{
			Exchange: 0,
			Message:  conformance.ExampleInResponse,
			Location: "the credential member of the one entry in credentials, in the JSON body",
		},
		JWKSExchange: &metadataExchange,
	}, nil
}

// issuerMetadataExample captures the Credential Issuer Metadata. OpenID4VCI
// 1.0 Section 12.2.2: "The Credential Issuer MUST respond with HTTP Status
// Code 200 and return the Credential Issuer Metadata containing the
// parameters defined in Section 12.2.4 as either an unsigned JSON document
// using the media type application/json, or a signed JSON Web Token (JWT)".
// The capture run then checks credential_issuer against the Credential
// Issuer Identifier the URL was built from, which Section 12.2.4 requires of
// a Wallet before it uses the document.
func issuerMetadataExample(ctx context.Context, env *capture.Env) (capture.ExampleResult, error) {
	resp, err := capture.FetchMetadata(ctx, env, capture.IssuerMetadataURL(env))
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
		IssuerMember: "credential_issuer",
		Issuer:       env.BaseURL + "/oid4vci",
	}, nil
}
