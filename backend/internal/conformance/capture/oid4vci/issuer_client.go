package oid4vci

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// The parts of the conformance client's anonymous Pre-Authorized Code
// issuance that only these scenarios use, on top of the shared Wallet side in
// the capture package. Everything here is preparation sent through Env.Setup.

// boundProof is a fresh holder key's proof over a fresh c_nonce.
func boundProof(ctx context.Context, env *capture.Env, issuer *capture.Issuer) (string, error) {
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	nonce, err := capture.FreshNonce(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	return key.Proof(issuer.ID, nonce)
}

// credentialOutcome classifies a Credential or Deferred Credential Response.
// HTTP 200 with a non-empty credentials array is acceptance. HTTP 400 is
// rejection when its error is one of rejectedWith, or carries any error code
// when rejectedWith is empty (a passing scenario that is refused for any
// reason is a rejection the runner flags). Anything else fits neither.
func credentialOutcome(endpoint string, resp *capture.Response, rejectedWith ...string) (conformance.ArtefactOutcome, error) {
	switch resp.Status {
	case http.StatusOK:
		body, err := resp.JSON()
		if err != nil {
			return "", err
		}
		if credentials, _ := body["credentials"].([]any); len(credentials) == 0 {
			return "", fmt.Errorf("%s answered 200 without credentials: %s", endpoint, capture.Truncate(resp.Body))
		}
		return conformance.OutcomeAccepted, nil
	case http.StatusBadRequest:
		code := resp.Error()
		if code != "" && len(rejectedWith) == 0 {
			return conformance.OutcomeRejected, nil
		}
		for _, want := range rejectedWith {
			if code == want {
				return conformance.OutcomeRejected, nil
			}
		}
	}
	return "", fmt.Errorf("%s answered %d %s", endpoint, resp.Status, capture.Truncate(resp.Body))
}

// issueCredential redeems grant for one Credential and returns the Credential
// Response's notification_id (Section 8.3).
func issueCredential(ctx context.Context, env *capture.Env, issuer *capture.Issuer, grant *capture.Grant) (string, error) {
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	body, err := capture.RequestCredential(ctx, env, issuer, grant, key, http.StatusOK)
	if err != nil {
		return "", err
	}
	notificationID, _ := body["notification_id"].(string)
	if notificationID == "" {
		return "", fmt.Errorf("credential response has no notification_id")
	}
	return notificationID, nil
}

// deferredTransaction makes a Credential Request on a deferred offer's
// Access Token, which the issuer answers with HTTP 202 and a transaction_id
// (Section 8.3), and waits out the interval the response names.
func deferredTransaction(ctx context.Context, env *capture.Env, issuer *capture.Issuer) (grant *capture.Grant, transactionID string, err error) {
	if issuer.DeferredCredential == "" {
		return nil, "", fmt.Errorf("credential issuer metadata has no deferred_credential_endpoint")
	}
	grant, err = capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{OfferOptions: capture.OfferOptions{Deferred: true}})
	if err != nil {
		return nil, "", err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return nil, "", err
	}
	body, err := capture.RequestCredential(ctx, env, issuer, grant, key, http.StatusAccepted)
	if err != nil {
		return nil, "", err
	}
	transactionID, _ = body["transaction_id"].(string)
	if transactionID == "" {
		return nil, "", fmt.Errorf("deferred credential response has no transaction_id")
	}
	interval, _ := body["interval"].(float64)
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	// One second beyond the interval, so the first poll finds the
	// Credential ready rather than pending.
	case <-time.After(time.Duration(interval)*time.Second + time.Second):
	}
	return grant, transactionID, nil
}
