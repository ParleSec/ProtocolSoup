package oid4vp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.Register("VP-006", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "encrypted-response-selected-by-kid",
			Description: "The conformance client, holding an SD-JWT VC that the issuer issued to it, fetches a direct_post.jwt request object from the request_uri. It encrypts vp_token and the request's state to the verifier's ephemeral ECDH-ES key, with that key's kid in the JWE header, and POSTs only the response parameter to /oid4vp/response. The verifier must select the request by the kid, find the decrypted state equal to the one it issued, and evaluate the presentation, whose result it reports at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         encryptedResponseSelectedByKid,
		},
		Failing: &capture.Scenario{
			Name:        "request-id-without-state",
			Description: "The conformance client fetches a direct_post request object from the request_uri, then POSTs a valid presentation to /oid4vp/response with the verifier's request_id in place of the state the request object carried. A request_id must not stand in for state on a redirect-invoked request.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         requestIDWithoutState,
		},
	})
}

// encryptedResponseSelectedByKid answers a direct_post.jwt request with an
// encrypted response that carries no outer state (OID4VP 1.0 Section 8.3).
func encryptedResponseSelectedByKid(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	h, err := capture.IssueSDJWTHolder(ctx, env)
	if err != nil {
		return "", err
	}
	requestID, requestURI, err := capture.CreateRequest(ctx, env, capture.RequestOptions{ResponseMode: "direct_post.jwt", Credential: capture.SDJWTQuery(h.VCT)})
	if err != nil {
		return "", err
	}
	object, err := capture.FetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return "", err
	}
	state := object.Claim("state")
	if state == "" {
		return "", fmt.Errorf("request object carries no state")
	}
	vpToken, err := h.Present(object.Claim("client_id"), object.Claim("nonce"))
	if err != nil {
		return "", err
	}
	response, err := capture.EncryptResponse(object, map[string]any{"vp_token": json.RawMessage(vpToken), "state": state})
	if err != nil {
		return "", err
	}
	resp, err := capture.PostResponse(ctx, env, object, url.Values{"response": {response}})
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusOK:
	case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_request":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("response_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	decision, err := capture.FetchResult(ctx, env, requestID)
	if err != nil {
		return "", err
	}
	if !decision.Allowed {
		return "", fmt.Errorf("verifier correlated the response but denied the presentation: %s", strings.Join(decision.ReasonCodes, ", "))
	}
	return conformance.OutcomeAccepted, nil
}

// requestIDWithoutState posts a presentation correlated only by request_id
// to a redirect-invoked direct_post request.
func requestIDWithoutState(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	h, err := capture.IssueSDJWTHolder(ctx, env)
	if err != nil {
		return "", err
	}
	requestID, requestURI, err := capture.CreateRequest(ctx, env, capture.RequestOptions{ResponseMode: "direct_post", Credential: capture.SDJWTQuery(h.VCT)})
	if err != nil {
		return "", err
	}
	object, err := capture.FetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return "", err
	}
	if object.Claim("state") == "" {
		return "", fmt.Errorf("request object carries no state")
	}
	vpToken, err := h.Present(object.Claim("client_id"), object.Claim("nonce"))
	if err != nil {
		return "", err
	}
	responseURI := object.Claim("response_uri")
	if responseURI == "" {
		return "", fmt.Errorf("request object has no response_uri")
	}
	req, err := capture.NewJSON(responseURI, map[string]any{"request_id": requestID, "vp_token": vpToken})
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusOK:
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_request":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("response_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}
