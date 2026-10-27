package capture

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
)

// preAuthorizedOfferLifetime is how long the issuer keeps an offer's
// pre-authorized code redeemable.
const preAuthorizedOfferLifetime = 15 * time.Minute

func init() {
	register("CI-014", Entry{
		Passing: &Scenario{
			Name:        "correct-tx-code",
			Description: "The conformance client redeems a fresh pre-authorized code at /oid4vci/token with the tx_code the issuer delivered out of band.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error) {
				return preAuthorizedTokenRequest(ctx, env, false)
			},
		},
		Failing: &Scenario{
			Name:        "wrong-tx-code",
			Description: "The conformance client redeems a fresh pre-authorized code with a tx_code that is not the one the issuer delivered.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *Env) (conformance.ArtefactOutcome, error) {
				return preAuthorizedTokenRequest(ctx, env, true)
			},
		},
	})
}

// preAuthorizedOffer creates a tx_code-protected offer and returns its code
// and the out-of-band tx_code value the issuer hands to the End-User.
func preAuthorizedOffer(ctx context.Context, env *Env) (code, txCode string, err error) {
	req, err := NewJSON(env.BaseURL+"/oid4vci/offers/pre-authorized", map[string]any{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
		"tx_code_required":             true,
	})
	if err != nil {
		return "", "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", "", err
	}
	if resp.Status != http.StatusCreated {
		return "", "", fmt.Errorf("offer creation answered %d %s", resp.Status, truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return "", "", err
	}
	code, _ = body["pre_authorized_code"].(string)
	txCode, _ = body["tx_code_oob_value"].(string)
	if code == "" || txCode == "" {
		return "", "", fmt.Errorf("offer response has no pre_authorized_code or tx_code_oob_value")
	}
	// Until it is redeemed, the code is usable by anyone holding the tx_code.
	env.NoteExpiry(preAuthorizedOfferLifetime)
	return code, txCode, nil
}

// preAuthorizedTokenRequest redeems a pre-authorized code with the right or
// a wrong tx_code. OID4VCI 1.0 Section 6.3 maps a wrong tx_code to
// invalid_grant.
func preAuthorizedTokenRequest(ctx context.Context, env *Env, wrongTxCode bool) (conformance.ArtefactOutcome, error) {
	code, txCode, err := preAuthorizedOffer(ctx, env)
	if err != nil {
		return "", err
	}
	if wrongTxCode {
		txCode = differentDigits(txCode)
	}
	req, err := NewForm(env.BaseURL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
		"tx_code":             {txCode},
	})
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
		return "", fmt.Errorf("token endpoint answered %d %s", resp.Status, truncate(resp.Body))
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
