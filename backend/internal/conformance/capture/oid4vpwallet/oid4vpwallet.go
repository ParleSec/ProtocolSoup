// Package oid4vpwallet captures the OpenID4VP requirements the hosted wallet
// meets as the receiver of an Authorization Request: Client Identifier
// Prefix handling, unrecognised parameters, request_uri retrieval,
// transaction_data, the wallet_nonce check after POST retrieval, and the
// HAIP floor of validating ES256-signed requests. The conformance client
// calls the wallet's API; the wallet's own hops join each artefact.
package oid4vpwallet

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// Hop steps as cmd/walletharness labels them.
const (
	stepFetchRequestObject    = "Fetch Request Object"
	stepAuthorizationResponse = "Authorization Response"
	stepResolveDIDDocument    = "Resolve Verifier DID Document"
)

// requestObjectMediaType is the media type RFC 9101 registers for a Request
// Object and OpenID4VP 1.0 Section 5.10.1 requires of a request_uri response.
const requestObjectMediaType = "application/oauth-authz-req+jwt"

func init() {
	capture.Register("VP-001", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "prefixed-client-id",
			Description: "The conformance client has the production verifier create a HAIP request, whose client_id carries the x509_hash Client Identifier Prefix, and asks the hosted wallet to resolve its request_uri. The wallet reads the prefix from the text before the first colon and verifies the request object by that prefix's rules.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, object, err := resolveHAIPRequest(ctx, env)
				if err != nil || result.Status != http.StatusOK {
					return outcomeOf(result, err)
				}
				clientID := object.Claim("client_id")
				if !strings.HasPrefix(clientID, "x509_hash:") {
					return "", fmt.Errorf("the request object client_id is %q, want an x509_hash: prefix", clientID)
				}
				trust := trustOf(result)
				if trust.scheme != "x509_hash" || !trust.verified {
					return "", fmt.Errorf("the wallet classified client_id %q as %q (verified %t), want x509_hash verified", clientID, trust.scheme, trust.verified)
				}
				return conformance.OutcomeAccepted, nil
			},
		},
		Failing: &capture.Scenario{
			Name:        "undefined-prefix",
			Description: "The conformance client asks the hosted wallet to resolve a counterparty request_uri whose signed request object carries client_id entity_id:..., a prefix OpenID4VP 1.0 does not define, beside the removed client_id_scheme parameter claiming pre-registration. The wallet decides from the text before the colon alone and refuses.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, err := resolveCounterpartyRequest(ctx, env, "vp-001", nil)
				if err != nil {
					return "", err
				}
				return refusal(result, "invalid_request", `unsupported client_id scheme prefix in "entity_id:`, stepFetchRequestObject)
			},
		},
	})

	capture.Register("VP-002", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "The hosted wallet takes the refusal option Section 5.9.2 allows, so it accepts no request whose client_id carries an unrecognised Client Identifier Prefix.",
		},
		Failing: &capture.Scenario{
			Name:        "unrecognised-prefix",
			Description: "The conformance client asks the hosted wallet to resolve a counterparty request_uri whose signed request object carries client_id unregistered_prefix:..., a Client Identifier Prefix the wallet does not recognise. The wallet refuses the request rather than treating the identifier as pre-registered.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, err := resolveCounterpartyRequest(ctx, env, "vp-002", nil)
				if err != nil {
					return "", err
				}
				return refusal(result, "invalid_request", `unsupported client_id scheme prefix in "unregistered_prefix:`, stepFetchRequestObject)
			},
		},
	})

	capture.Register("VP-003", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "extra-parameters-presented",
			Description: "The conformance client asks the hosted wallet to present to a counterparty request_uri whose valid, ES256-signed request object also carries an unregistered x_protocolsoup_extension parameter, the removed client_id_scheme parameter naming redirect_uri, and the removed presentation_definition parameter. The wallet verifies the request by its decentralized_identifier prefix, presents a University Degree Credential chosen by dcql_query, and posts an Authorization Response without a presentation_submission.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         presentWithUnrecognisedParameters,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "A wallet that ignores unrecognised parameters has nothing to refuse; the one parameter it must not ignore, transaction_data, is shown refused under VP-011.",
		},
	})

	capture.Register("VP-004", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "get-request-object",
			Description: "The conformance client has the production verifier create a direct_post request and asks the hosted wallet to resolve its request_uri. The wallet sends GET with Accept: application/oauth-authz-req+jwt and receives the compact signed request object itself, served with that media type.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         resolveByGET,
		},
		Failing: &capture.Scenario{
			Name:        "json-wrapped-request-object",
			Description: "The conformance client asks the hosted wallet to resolve a counterparty request_uri that answers GET with Content-Type: application/json and the signed request object wrapped in a JSON object. The wallet refuses the response for its media type before decoding anything.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, err := resolveCounterpartyRequest(ctx, env, "vp-004", nil)
				if err != nil {
					return "", err
				}
				return refusal(result, "invalid_request", `request_uri GET returned unsupported Content-Type "application/json`, stepFetchRequestObject)
			},
		},
	})

	capture.Register("VP-011", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "The hosted wallet supports no transaction data type, so it refuses every request carrying transaction_data; there is no request with transaction_data it accepts.",
		},
		Failing: &capture.Scenario{
			Name:        "unsupported-transaction-data",
			Description: "The conformance client asks the hosted wallet to resolve a counterparty request_uri whose signed request object carries a transaction_data entry of a type no wallet implements. The wallet, which supports no transaction data type, returns invalid_transaction_data instead of ignoring the parameter.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, err := resolveCounterpartyRequest(ctx, env, "vp-011", nil)
				if err != nil {
					return "", err
				}
				check := `transaction data type "` + env.CounterpartyURL + `/scenarios/vp-011/transaction-type" is not supported`
				return refusal(result, "invalid_transaction_data", check, stepFetchRequestObject)
			},
		},
	})

	capture.Register("VP-012", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "post-wallet-nonce",
			Description: "The conformance client has the production verifier create a request_uri_method=post request and asks the hosted wallet to resolve it. The wallet POSTs a fresh wallet_nonce to the request_uri and accepts the signed request object because its wallet_nonce claim is the value it sent.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         resolveByPOST,
		},
		Failing: &capture.Scenario{
			Name:        "mismatched-wallet-nonce",
			Description: "The conformance client asks the hosted wallet to resolve a counterparty request_uri with request_uri_method=post. The counterparty answers the wallet's POSTed wallet_nonce with a signed request object whose wallet_nonce claim is a different value, and the wallet terminates request processing.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, err := resolveCounterpartyRequest(ctx, env, "vp-012", map[string]any{"request_uri_method": "post"})
				if err != nil {
					return "", err
				}
				return refusal(result, "invalid_request", "request object does not contain the wallet_nonce sent in the request_uri POST", stepFetchRequestObject)
			},
		},
	})

	capture.Register("CW-H017", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "es256-request-verified",
			Description: "The conformance client has the production verifier create a HAIP request, signed ES256 with a P-256 key, and asks the hosted wallet to resolve its request_uri. The wallet validates the x5c chain named by the x509_hash client_id and verifies the ES256 signature with the leaf's EC key.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				result, object, err := resolveHAIPRequest(ctx, env)
				if err != nil || result.Status != http.StatusOK {
					return outcomeOf(result, err)
				}
				if alg := object.Header["alg"]; alg != "ES256" {
					return "", fmt.Errorf("the request object alg is %v, want ES256", alg)
				}
				trust := trustOf(result)
				if !trust.verified || trust.keyType != "EC" {
					return "", fmt.Errorf("the wallet reported request object verification verified=%t key_type=%q, want verified with an EC key", trust.verified, trust.keyType)
				}
				return conformance.OutcomeAccepted, nil
			},
		},
		Failing: &capture.Scenario{
			Name:        "broken-es256-signature",
			Description: "The conformance client asks the hosted wallet to preview a counterparty request_uri whose request object is signed ES256 under a decentralized_identifier client_id, with one claim changed after signing. The wallet resolves the did:web DID Document, checks the ES256 signature with the published P-256 key, and refuses because it does not verify.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				requestURI, err := counterpartyRequestURI(env, "cw-h017")
				if err != nil {
					return "", err
				}
				result, err := callWallet(ctx, env, "/api/preview", map[string]any{"request_uri": requestURI})
				if err != nil {
					return "", err
				}
				if result.Status == http.StatusBadRequest {
					hop, err := requireHop(result, stepFetchRequestObject)
					if err != nil {
						return "", err
					}
					if header, _, err := capture.JWTParts(hopBody(hop.ResponseBody, hop.ResponseBodyEncoding)); err != nil {
						return "", fmt.Errorf("the counterparty request object: %w", err)
					} else if header["alg"] != "ES256" {
						return "", fmt.Errorf("the counterparty request object alg is %v, want ES256", header["alg"])
					}
				}
				return refusal(result, "invalid_request", "request object signature verification failed", stepResolveDIDDocument)
			},
		},
	})
}

// resolveHAIPRequest has the production verifier create a HAIP request and
// the wallet resolve it, returning the wallet's answer and the request object
// the wallet fetched. The HAIP profile signs ES256 under an x509_hash
// client_id.
func resolveHAIPRequest(ctx context.Context, env *capture.Env) (*capture.WalletResult, *capture.RequestObject, error) {
	_, requestURI, err := capture.CreateRequest(ctx, env, capture.RequestOptions{
		HAIP:         true,
		ResponseMode: "direct_post.jwt",
		Credential:   capture.SDJWTQuery(capture.UniversityDegreeVCT),
	})
	if err != nil {
		return nil, nil, err
	}
	result, err := callWallet(ctx, env, "/api/resolve", map[string]any{"request_uri": requestURI})
	if err != nil {
		return nil, nil, err
	}
	if result.Status != http.StatusOK {
		return result, nil, nil
	}
	hop, err := requireHop(result, stepFetchRequestObject)
	if err != nil {
		return nil, nil, err
	}
	object, err := hopRequestObject(hop)
	if err != nil {
		return nil, nil, err
	}
	return result, object, nil
}

// resolveByGET is VP-004's passing scenario: the wallet retrieves a
// production request_uri with GET and receives the compact signed request
// object as application/oauth-authz-req+jwt.
func resolveByGET(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	_, requestURI, err := capture.CreateRequest(ctx, env, capture.RequestOptions{
		ResponseMode: "direct_post",
		Credential:   capture.SDJWTQuery(capture.UniversityDegreeVCT),
	})
	if err != nil {
		return "", err
	}
	result, err := callWallet(ctx, env, "/api/resolve", map[string]any{"request_uri": requestURI})
	if err != nil || result.Status != http.StatusOK {
		return outcomeOf(result, err)
	}
	hop, err := requireHop(result, stepFetchRequestObject)
	if err != nil {
		return "", err
	}
	if hop.Method != http.MethodGet {
		return "", fmt.Errorf("the wallet retrieved the request_uri with %s, want GET", hop.Method)
	}
	if accept := headerValue(hop.RequestHeaders, "Accept"); accept != requestObjectMediaType {
		return "", fmt.Errorf("the wallet sent Accept %q, want %q", accept, requestObjectMediaType)
	}
	if contentType := mediaType(headerValue(hop.ResponseHeaders, "Content-Type")); contentType != requestObjectMediaType {
		return "", fmt.Errorf("the request_uri answered Content-Type %q, want %q", contentType, requestObjectMediaType)
	}
	object, err := hopRequestObject(hop)
	if err != nil {
		return "", err
	}
	if resolved, _ := result.Body["request"].(string); resolved != object.Compact {
		return "", fmt.Errorf("the wallet resolved a request object other than the one the request_uri returned")
	}
	return conformance.OutcomeAccepted, nil
}

// resolveByPOST is VP-012's passing scenario: the wallet POSTs a wallet_nonce
// to a production request_uri_method=post request_uri and accepts the request
// object because its wallet_nonce claim is the value it sent.
func resolveByPOST(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	requestURI, err := createPOSTRequestURI(ctx, env)
	if err != nil {
		return "", err
	}
	result, err := callWallet(ctx, env, "/api/resolve", map[string]any{"request_uri": requestURI, "request_uri_method": "post"})
	if err != nil || result.Status != http.StatusOK {
		return outcomeOf(result, err)
	}
	hop, err := requireHop(result, stepFetchRequestObject)
	if err != nil {
		return "", err
	}
	if hop.Method != http.MethodPost {
		return "", fmt.Errorf("the wallet retrieved the request_uri with %s, want POST", hop.Method)
	}
	form, err := url.ParseQuery(hopBody(hop.RequestBody, hop.RequestBodyEncoding))
	if err != nil {
		return "", fmt.Errorf("the wallet's request_uri POST body is not a form: %w", err)
	}
	sent := form.Get("wallet_nonce")
	if sent == "" {
		return "", fmt.Errorf("the wallet's request_uri POST carries no wallet_nonce")
	}
	object, err := hopRequestObject(hop)
	if err != nil {
		return "", err
	}
	if bound := object.Claim("wallet_nonce"); bound != sent {
		return "", fmt.Errorf("the request object wallet_nonce is %q, the wallet sent %q", bound, sent)
	}
	return conformance.OutcomeAccepted, nil
}

// createPOSTRequestURI has the production verifier create a
// request_uri_method=post Authorization Request and returns its request_uri.
// capture.CreateRequest has no request_uri_method option, so this is
// package-local preparation.
func createPOSTRequestURI(ctx context.Context, env *capture.Env) (string, error) {
	req, err := capture.NewJSON(env.BaseURL+"/oid4vp/request/create", map[string]any{
		"response_mode":      "direct_post",
		"request_uri_method": "post",
		"dcql_query":         map[string]any{"credentials": []map[string]any{capture.SDJWTQuery(capture.UniversityDegreeVCT)}},
	})
	if err != nil {
		return "", err
	}
	created, err := capture.SetupJSON(ctx, env, req, http.StatusCreated, "request creation")
	if err != nil {
		return "", err
	}
	requestURI, _ := created["request_uri"].(string)
	if requestURI == "" {
		return "", fmt.Errorf("request creation returned no request_uri")
	}
	env.NoteExpiry(capture.RequestObjectLifetime)
	return requestURI, nil
}

// presentWithUnrecognisedParameters is VP-003's passing scenario. The
// production verifier cannot put an unrecognised top-level parameter into a
// request object, so this is the one passing exchange against the
// counterparty: a valid, verifiably signed request that also carries
// parameters the wallet does not recognise, which the wallet presents to.
func presentWithUnrecognisedParameters(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	requestURI, err := counterpartyRequestURI(env, "vp-003")
	if err != nil {
		return "", err
	}
	result, err := callWallet(ctx, env, "/api/present", map[string]any{"request_uri": requestURI, "approve_external_trust": true})
	if err != nil || result.Status != http.StatusOK {
		return outcomeOf(result, err)
	}
	fetch, err := requireHop(result, stepFetchRequestObject)
	if err != nil {
		return "", err
	}
	object, err := hopRequestObject(fetch)
	if err != nil {
		return "", err
	}
	for _, parameter := range []string{"x_protocolsoup_extension", "client_id_scheme", "presentation_definition"} {
		if _, present := object.Claims[parameter]; !present {
			return "", fmt.Errorf("the counterparty request object carries no %s parameter", parameter)
		}
	}
	if trust := trustOf(result); trust.scheme != "decentralized_identifier" || !trust.verified {
		return "", fmt.Errorf("the wallet classified the request as %q (verified %t), want decentralized_identifier verified", trust.scheme, trust.verified)
	}
	response, err := requireHop(result, stepAuthorizationResponse)
	if err != nil {
		return "", err
	}
	if response.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("the counterparty answered the Authorization Response %d %s", response.ResponseStatus, capture.Truncate([]byte(response.ResponseBody)))
	}
	form, err := url.ParseQuery(hopBody(response.RequestBody, response.RequestBodyEncoding))
	if err != nil {
		return "", fmt.Errorf("the Authorization Response body is not a form: %w", err)
	}
	if form.Get("vp_token") == "" {
		return "", fmt.Errorf("the Authorization Response carries no vp_token")
	}
	if form.Has("presentation_submission") {
		return "", fmt.Errorf("the Authorization Response carries presentation_submission, so the wallet acted on the removed presentation_definition parameter")
	}
	return conformance.OutcomeAccepted, nil
}

// resolveCounterpartyRequest asks the wallet to resolve the counterparty's
// request_uri for scenario, with any extra request members.
func resolveCounterpartyRequest(ctx context.Context, env *capture.Env, scenario string, extra map[string]any) (*capture.WalletResult, error) {
	requestURI, err := counterpartyRequestURI(env, scenario)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"request_uri": requestURI}
	for key, value := range extra {
		body[key] = value
	}
	return callWallet(ctx, env, "/api/resolve", body)
}

// counterpartyRequestURI is the counterparty's request_uri for scenario.
func counterpartyRequestURI(env *capture.Env, scenario string) (string, error) {
	if env.CounterpartyURL == "" {
		return "", fmt.Errorf("this run has no counterparty")
	}
	return env.CounterpartyURL + "/scenarios/" + scenario + "/request", nil
}

// callWallet calls the hosted wallet's API in a fresh session, so the
// Credentials one scenario leaves behind never change another's hops.
func callWallet(ctx context.Context, env *capture.Env, path string, body map[string]any) (*capture.WalletResult, error) {
	return capture.CallWallet(ctx, env, capture.WalletCall{Path: path, Body: body, Session: capture.NewWalletSession()})
}

// refusal decides a counterparty scenario from the wallet's answer. It is
// rejected only when the wallet answered 400 with errorCode and an
// error_description naming this row's check, and recorded the hop that
// carried the counterparty's message. A 200 is the wallet accepting what it
// must refuse, recorded truthfully; any other answer is an error.
func refusal(result *capture.WalletResult, errorCode, check, step string) (conformance.ArtefactOutcome, error) {
	switch {
	case result.Status == http.StatusOK:
		return conformance.OutcomeAccepted, nil
	case result.Status != http.StatusBadRequest:
		return "", fmt.Errorf("the wallet answered %s %s", capture.WalletStatusText(result.Status), describe(result))
	case result.Error() != errorCode:
		return "", fmt.Errorf("the wallet refused with error %q, want %q: %s", result.Error(), errorCode, describe(result))
	case !strings.Contains(result.ErrorDescription(), check):
		return "", fmt.Errorf("the wallet refused for another reason than %q: %s", check, describe(result))
	}
	if _, err := requireHop(result, step); err != nil {
		return "", err
	}
	return conformance.OutcomeRejected, nil
}

// outcomeOf decides a passing scenario whose wallet call failed or did not
// answer 200: a 400 is the wallet refusing what it should accept, recorded
// truthfully; anything else is an error.
func outcomeOf(result *capture.WalletResult, err error) (conformance.ArtefactOutcome, error) {
	if err != nil {
		return "", err
	}
	if result.Status == http.StatusBadRequest {
		return conformance.OutcomeRejected, nil
	}
	return "", fmt.Errorf("the wallet answered %s %s", capture.WalletStatusText(result.Status), describe(result))
}

func describe(result *capture.WalletResult) string {
	if result.Error() == "" && result.ErrorDescription() == "" {
		return ""
	}
	return result.Error() + ": " + result.ErrorDescription()
}

// requireHop returns the wallet's recorded hop for step, or an error naming
// the missing evidence.
func requireHop(result *capture.WalletResult, step string) (*capture.WalletHop, error) {
	hop := result.Hop(step)
	if hop == nil {
		return nil, fmt.Errorf("the wallet recorded no %q hop", step)
	}
	return hop, nil
}

// hopRequestObject decodes the compact signed request object a request_uri
// hop returned.
func hopRequestObject(hop *capture.WalletHop) (*capture.RequestObject, error) {
	if hop.ResponseStatus != http.StatusOK {
		return nil, fmt.Errorf("the request_uri answered %d %s", hop.ResponseStatus, capture.Truncate([]byte(hop.ResponseBody)))
	}
	compact := strings.TrimSpace(hopBody(hop.ResponseBody, hop.ResponseBodyEncoding))
	header, claims, err := capture.JWTParts(compact)
	if err != nil {
		return nil, fmt.Errorf("the request_uri response: %w", err)
	}
	return &capture.RequestObject{Compact: compact, Header: header, Claims: claims}, nil
}

// hopBody returns a recorded hop body as text; the wallet records non-UTF-8
// bodies base64 encoded.
func hopBody(body, encoding string) string {
	if encoding != "base64" {
		return body
	}
	decoded, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return body
	}
	return string(decoded)
}

// headerValue reads a recorded header regardless of case.
func headerValue(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// mediaType strips the parameters from a Content-Type value.
func mediaType(contentType string) string {
	value, _, _ := strings.Cut(contentType, ";")
	return strings.ToLower(strings.TrimSpace(value))
}

// trustEvidence is what the wallet reported under "trust".
type trustEvidence struct {
	scheme   string
	verified bool
	keyType  string
}

func trustOf(result *capture.WalletResult) trustEvidence {
	trust, _ := result.Body["trust"].(map[string]any)
	verification, _ := trust["request_object_verification"].(map[string]any)
	scheme, _ := trust["client_id_scheme"].(string)
	verified, _ := verification["verified"].(bool)
	keyType, _ := verification["key_type"].(string)
	return trustEvidence{scheme: scheme, verified: verified, keyType: keyType}
}
