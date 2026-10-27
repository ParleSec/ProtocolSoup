package oid4vci

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.Register("CI-014", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "correct-tx-code",
			Description: "The conformance client redeems a fresh pre-authorized code at /oid4vci/token with the tx_code the issuer delivered out of band.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return preAuthorizedTokenRequest(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "wrong-tx-code",
			Description: "The conformance client redeems a fresh pre-authorized code with a tx_code that is not the one the issuer delivered.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return preAuthorizedTokenRequest(ctx, env, true)
			},
		},
	})
}

// preAuthorizedTokenRequest redeems a pre-authorized code with the right or
// a wrong tx_code. OID4VCI 1.0 Section 6.3 maps a wrong tx_code to
// invalid_grant.
func preAuthorizedTokenRequest(ctx context.Context, env *capture.Env, wrongTxCode bool) (conformance.ArtefactOutcome, error) {
	offer, err := capture.CreatePreAuthorizedOffer(ctx, env, capture.OfferOptions{TxCode: true})
	if err != nil {
		return "", err
	}
	txCode := offer.TxCode
	if wrongTxCode {
		txCode = differentDigits(txCode)
	}
	req, err := capture.NewForm(env.BaseURL+"/oid4vci/token", capture.PreAuthorizedTokenForm(offer.Code, txCode))
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusOK:
		body, err := resp.JSON()
		if err != nil {
			return "", err
		}
		expiresIn, _ := body["expires_in"].(float64)
		env.NoteExpiry(time.Duration(expiresIn) * time.Second)
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_grant":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("token endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// differentDigits returns a same-length numeric code that differs from code.
func differentDigits(code string) string {
	out := []byte(code)
	for i, c := range out {
		if c >= '0' && c <= '9' {
			out[i] = '0' + (c-'0'+1)%10
		}
	}
	if string(out) == code {
		return code + "0"
	}
	return string(out)
}
