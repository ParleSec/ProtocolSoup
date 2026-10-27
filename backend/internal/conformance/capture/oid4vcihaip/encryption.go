package oid4vcihaip

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// unsupportedResponseEnc is a JWE enc value ProtocolSoup does not advertise
// in credential_response_encryption.enc_values_supported.
const unsupportedResponseEnc = "A192GCM"

func init() {
	capture.Register("CI-021", capture.Entry{
		Passing: &capture.Scenario{
			Name: "encrypted-credential-request",
			Description: "The conformance client encrypts a Credential Request to the key the issuer advertises in credential_request_encryption.jwks, using that key's alg and kid and the first advertised enc value, " +
				"and posts the JWE as application/jwt to /oid4vci/credential with a bearer access token from a pre-authorized code. The encrypted request carries one jwt proof over a fresh c_nonce.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return encryptedCredentialRequest(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name: "encrypted-request-with-unissued-c-nonce",
			Description: "The conformance client sends the same encrypted Credential Request, but its jwt proof carries a c_nonce the issuer never issued. " +
				"Once decrypted, the request has to pass the same proof checks as an application/json request.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return encryptedCredentialRequest(ctx, env, true)
			},
		},
	})
	capture.Register("CI-022", capture.Entry{
		Passing: &capture.Scenario{
			Name: "encrypted-request-asks-for-encrypted-response",
			Description: "The conformance client sends a Credential Request carrying credential_response_encryption, with a fresh ECDH-ES P-256 key and an advertised enc value, " +
				"encrypted to the issuer's advertised credential_request_encryption key and posted as application/jwt to /oid4vci/credential. " +
				"The capture decrypts the application/jwt response with that key and checks it holds a Credential.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return responseEncryptionRequest(ctx, env, true)
			},
		},
		Failing: &capture.Scenario{
			Name:        "plaintext-request-asks-for-encrypted-response",
			Description: "The conformance client sends the same Credential Request, credential_response_encryption included, as plaintext application/json, so the response key in it is open to substitution.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return responseEncryptionRequest(ctx, env, false)
			},
		},
	})
	capture.Register("CI-023", capture.Entry{
		Passing: &capture.Scenario{
			Name: "encrypted-pending-deferred-response",
			Description: "The conformance client starts a deferred issuance with a pre-authorized code and a Credential Request, then, before the Credential is ready, sends an encrypted Deferred Credential Request to /oid4vci/deferred_credential " +
				"with the transaction_id and a credential_response_encryption object holding a fresh ECDH-ES P-256 key. " +
				"The capture checks that the still-pending answer is an application/jwt JWE that decrypts with that key to the same transaction_id and an interval.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return deferredEncryptedPoll(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name: "deferred-request-with-unsupported-enc",
			Description: "The conformance client sends the same encrypted Deferred Credential Request, but its credential_response_encryption asks for enc " + unsupportedResponseEnc +
				", which the issuer does not advertise, so the issuer cannot encode the Deferred Credential Response with the parameters it was given.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return deferredEncryptedPoll(ctx, env, true)
			},
		},
	})
}

// encryptedCredentialRequest sends an encrypted Credential Request (OID4VCI
// 1.0 Sections 8.2 and 10). With unissuedNonce the proof's nonce is a random
// value, which the issuer rejects with invalid_nonce (Section 8.3.1.2).
func encryptedCredentialRequest(ctx context.Context, env *capture.Env, unissuedNonce bool) (conformance.ArtefactOutcome, error) {
	meta, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	enc, err := meta.FirstRequestEnc()
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, meta, txCodeGrant)
	if err != nil {
		return "", err
	}
	nonce, err := capture.FreshNonce(ctx, env, meta)
	if err != nil {
		return "", err
	}
	if unissuedNonce {
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return "", err
		}
		nonce = base64.RawURLEncoding.EncodeToString(random)
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	proof, err := key.Proof(meta.ID, nonce)
	if err != nil {
		return "", err
	}
	req, err := newEncryptedRequest(meta.Credential, grant.AccessToken, meta, enc, grant.CredentialRequest(proof))
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
		if _, err := capture.IssuedCredentials(body); err != nil {
			return "", err
		}
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && unissuedNonce && resp.Error() == "invalid_nonce":
		return conformance.OutcomeRejected, nil
	case resp.Status == http.StatusBadRequest && !unissuedNonce && resp.Error() != "":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("credential endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// responseEncryptionRequest sends a Credential Request carrying
// credential_response_encryption, encrypted or as plaintext JSON. Section 8.2:
// "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included"; ProtocolSoup
// rejects the plaintext form with invalid_encryption_parameters.
func responseEncryptionRequest(ctx context.Context, env *capture.Env, encrypted bool) (conformance.ArtefactOutcome, error) {
	meta, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	requestEnc, err := meta.FirstRequestEnc()
	if err != nil {
		return "", err
	}
	if len(meta.ResponseEnc) == 0 {
		return "", fmt.Errorf("credential_response_encryption advertises no enc_values_supported")
	}
	responder, err := newResponseKey(meta, meta.ResponseEnc[0])
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, meta, txCodeGrant)
	if err != nil {
		return "", err
	}
	nonce, err := capture.FreshNonce(ctx, env, meta)
	if err != nil {
		return "", err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	proof, err := key.Proof(meta.ID, nonce)
	if err != nil {
		return "", err
	}
	body := grant.CredentialRequest(proof)
	body["credential_response_encryption"] = responder.parameters()
	var req *http.Request
	if encrypted {
		req, err = newEncryptedRequest(meta.Credential, grant.AccessToken, meta, requestEnc, body)
	} else {
		req, err = capture.BearerJSON(meta.Credential, grant.AccessToken, body)
	}
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusOK:
		if !encrypted {
			return conformance.OutcomeAccepted, nil
		}
		if mediaType(resp) != "application/jwt" {
			return "", fmt.Errorf("encrypted response was requested but the issuer answered %s", resp.Header.Get("Content-Type"))
		}
		decrypted, err := responder.decrypt(resp.Body)
		if err != nil {
			return "", err
		}
		if _, err := capture.IssuedCredentials(decrypted); err != nil {
			return "", err
		}
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && !encrypted && resp.Error() == "invalid_encryption_parameters":
		return conformance.OutcomeRejected, nil
	case resp.Status == http.StatusBadRequest && encrypted && resp.Error() != "":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("credential endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// deferredEncryptedPoll starts a deferred issuance and polls before the
// Credential is ready with an encrypted Deferred Credential Request. Section
// 9.2 encrypts the Deferred Credential Response "regardless of the content".
// With unsupportedEnc the request asks for an enc value the issuer does not
// advertise, which ProtocolSoup rejects with invalid_encryption_parameters.
func deferredEncryptedPoll(ctx context.Context, env *capture.Env, unsupportedEnc bool) (conformance.ArtefactOutcome, error) {
	meta, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	if meta.DeferredCredential == "" {
		return "", fmt.Errorf("credential issuer metadata has no deferred_credential_endpoint")
	}
	requestEnc, err := meta.FirstRequestEnc()
	if err != nil {
		return "", err
	}
	responseEnc := ""
	if unsupportedEnc {
		if slices.Contains(meta.ResponseEnc, unsupportedResponseEnc) {
			return "", fmt.Errorf("credential_response_encryption now advertises %s", unsupportedResponseEnc)
		}
		responseEnc = unsupportedResponseEnc
	} else {
		if len(meta.ResponseEnc) == 0 {
			return "", fmt.Errorf("credential_response_encryption advertises no enc_values_supported")
		}
		responseEnc = meta.ResponseEnc[0]
	}
	responder, err := newResponseKey(meta, responseEnc)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, meta, deferredGrant)
	if err != nil {
		return "", err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	started, err := capture.RequestCredential(ctx, env, meta, grant, key, http.StatusAccepted)
	if err != nil {
		return "", err
	}
	transactionID, _ := started["transaction_id"].(string)
	if transactionID == "" {
		return "", fmt.Errorf("deferred credential response has no transaction_id")
	}

	req, err := newEncryptedRequest(meta.DeferredCredential, grant.AccessToken, meta, requestEnc, map[string]any{
		"transaction_id":                 transactionID,
		"credential_response_encryption": responder.parameters(),
	})
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case unsupportedEnc && (resp.Status == http.StatusAccepted || resp.Status == http.StatusOK):
		// The issuer answered a request it cannot honour as asked.
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusAccepted:
		if mediaType(resp) != "application/jwt" {
			return "", fmt.Errorf("encrypted response was requested but the pending answer is %s: %s", resp.Header.Get("Content-Type"), capture.Truncate(resp.Body))
		}
		if strings.TrimSpace(resp.Header.Get("Retry-After")) == "" {
			return "", fmt.Errorf("pending answer has no Retry-After header")
		}
		pending, err := responder.decrypt(resp.Body)
		if err != nil {
			return "", err
		}
		if pending["transaction_id"] != transactionID {
			return "", fmt.Errorf("decrypted transaction_id is %v, want %s", pending["transaction_id"], transactionID)
		}
		if interval, ok := pending["interval"].(float64); !ok || interval < 1 {
			return "", fmt.Errorf("decrypted interval is %v, want at least 1", pending["interval"])
		}
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusOK:
		// The Credential was ready before the poll, so this is not the
		// pending answer the scenario describes.
		return "", fmt.Errorf("deferred credential was already issued when the poll arrived")
	case resp.Status == http.StatusBadRequest && unsupportedEnc && resp.Error() == "invalid_encryption_parameters":
		return conformance.OutcomeRejected, nil
	case resp.Status == http.StatusBadRequest && !unsupportedEnc && resp.Error() != "":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("deferred credential endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}
