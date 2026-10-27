package oid4vci

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// Notification Endpoint and Deferred Credential Endpoint requirements
// (OID4VCI 1.0 Sections 9 and 11).

func init() {
	capture.Register("CI-008", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "identical-notification-retry",
			Description: "The conformance client sends /oid4vci/notification a credential_accepted event for the notification_id its Credential Response returned, with the Access Token that obtained the Credential, then sends the identical request again as a Wallet retrying after a network error would.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return notificationRequest(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "notification-id-from-another-token",
			Description: "The conformance client sends /oid4vci/notification a credential_accepted event for a notification_id that the issuer returned to a different Access Token, presented with a second, valid Access Token.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return notificationRequest(ctx, env, true)
			},
		},
	})

	capture.Register("CI-016", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "deferred-transaction-redeemed",
			Description: "The conformance client sends /oid4vci/deferred_credential the transaction_id from an HTTP 202 Credential Response, after the interval it named, with the Access Token that made the Credential Request.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return deferredRedemption(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "deferred-transaction-redeemed-twice",
			Description: "The conformance client obtains the Credentials for a transaction_id from /oid4vci/deferred_credential, then sends the same Deferred Credential Request again with the same Access Token.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return deferredRedemption(ctx, env, true)
			},
		},
	})
}

// notificationRequest exercises Section 11: "When the Credential Issuer
// receives multiple identical calls from the Wallet for the same
// notification_id, it returns success" (HTTP 204, Section 11.2). With
// crossToken the notification_id belongs to another Access Token, which
// ProtocolSoup treats as invalid: HTTP 400 invalid_notification_id (Section
// 11.3).
func notificationRequest(ctx context.Context, env *capture.Env, crossToken bool) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{AuthorizationDetails: true})
	if err != nil {
		return "", err
	}
	if issuer.Notification == "" {
		return "", fmt.Errorf("credential issuer metadata has no notification_endpoint")
	}
	notificationID, err := issueCredential(ctx, env, issuer, grant)
	if err != nil {
		return "", err
	}
	accessToken := grant.AccessToken
	if crossToken {
		other, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{AuthorizationDetails: true})
		if err != nil {
			return "", err
		}
		accessToken = other.AccessToken
	}
	send := func() (*capture.Response, error) {
		req, err := capture.BearerJSON(issuer.Notification, accessToken, map[string]any{
			"notification_id": notificationID,
			"event":           "credential_accepted",
		})
		if err != nil {
			return nil, err
		}
		return env.Do(ctx, req)
	}
	attempts := 2
	if crossToken {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		resp, err := send()
		if err != nil {
			return "", err
		}
		switch {
		case resp.Status == http.StatusNoContent:
			continue
		case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_notification_id":
			return conformance.OutcomeRejected, nil
		// A retry recorded as a second, conflicting event would surface here.
		case !crossToken && resp.Status == http.StatusBadRequest && resp.Error() == "invalid_notification_request":
			return conformance.OutcomeRejected, nil
		default:
			return "", fmt.Errorf("notification endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
		}
	}
	return conformance.OutcomeAccepted, nil
}

// deferredRedemption exercises Section 9.1, "The Credential Issuer MUST
// invalidate the transaction_id after the Credential for which it was meant
// has been obtained by the Wallet." A second Deferred Credential Request for
// a spent transaction_id gets invalid_transaction_id (Section 9.3).
func deferredRedemption(ctx context.Context, env *capture.Env, twice bool) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, transactionID, err := deferredTransaction(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	send := func() (*capture.Response, error) {
		req, err := capture.BearerJSON(issuer.DeferredCredential, grant.AccessToken, map[string]any{
			"transaction_id": transactionID,
		})
		if err != nil {
			return nil, err
		}
		return env.Do(ctx, req)
	}
	resp, err := send()
	if err != nil {
		return "", err
	}
	if !twice {
		return credentialOutcome("deferred credential endpoint", resp)
	}
	first, err := credentialOutcome("deferred credential endpoint", resp)
	if err != nil {
		return "", err
	}
	if first != conformance.OutcomeAccepted {
		return "", fmt.Errorf("the first Deferred Credential Request was refused: %s", capture.Truncate(resp.Body))
	}
	if resp, err = send(); err != nil {
		return "", err
	}
	return credentialOutcome("deferred credential endpoint", resp, "invalid_transaction_id")
}
