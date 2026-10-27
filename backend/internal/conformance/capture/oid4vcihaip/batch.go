package oid4vcihaip

import (
	"context"
	stdcrypto "crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	jose "github.com/go-jose/go-jose/v4"
)

func init() {
	capture.Register("CI-017", capture.Entry{
		Passing: &capture.Scenario{
			Name: "batch-with-distinct-proof-keys",
			Description: "The conformance client sends a Credential Request to /oid4vci/credential with a bearer access token from a pre-authorized code and two jwt proofs over the same fresh c_nonce, " +
				"each signed by a different ES256 key. The capture checks that the two Credentials returned are bound by cnf.jwk to the two proof keys, one each.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return batchRequest(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "batch-repeating-one-proof-key",
			Description: "The conformance client sends the same kind of batch Credential Request, but both entries in proofs.jwt are the same proof, so both Credentials would be bound to one key.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return batchRequest(ctx, env, true)
			},
		},
	})
}

// batchRequest sends a two-proof batch Credential Request. With repeatKey
// the second proof is the first one again; ProtocolSoup rejects a repeated
// proof key with invalid_proof (OID4VCI 1.0 Section 8.3.1.2).
func batchRequest(ctx context.Context, env *capture.Env, repeatKey bool) (conformance.ArtefactOutcome, error) {
	meta, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	batch, _ := meta.Metadata["batch_credential_issuance"].(map[string]any)
	if size, _ := batch["batch_size"].(float64); size < 2 {
		return "", fmt.Errorf("credential issuer metadata does not advertise batch_credential_issuance with batch_size of at least 2")
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, meta, txCodeGrant)
	if err != nil {
		return "", err
	}
	nonce, err := capture.FreshNonce(ctx, env, meta)
	if err != nil {
		return "", err
	}
	keys := make([]*capture.HolderKey, 0, 2)
	proofs := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		if repeatKey && i == 1 {
			proofs = append(proofs, proofs[0])
			break
		}
		key, err := capture.NewHolderKey()
		if err != nil {
			return "", err
		}
		proof, err := key.Proof(meta.ID, nonce)
		if err != nil {
			return "", err
		}
		keys = append(keys, key)
		proofs = append(proofs, proof)
	}
	req, err := capture.BearerJSON(meta.Credential, grant.AccessToken, grant.CredentialRequest(proofs...))
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusOK && !repeatKey:
		body, err := resp.JSON()
		if err != nil {
			return "", err
		}
		issued, err := capture.IssuedCredentials(body)
		if err != nil {
			return "", err
		}
		if err := boundToDistinctKeys(issued, keys); err != nil {
			return "", err
		}
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusOK:
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_proof":
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("credential endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// boundToDistinctKeys checks that the issued SD-JWT VCs are bound, one each,
// to the proof keys: each cnf.jwk thumbprint matches a different key.
func boundToDistinctKeys(issued []string, keys []*capture.HolderKey) error {
	if len(issued) != len(keys) {
		return fmt.Errorf("issuer returned %d credentials for %d proofs", len(issued), len(keys))
	}
	want := map[string]bool{}
	for _, key := range keys {
		public := jose.JSONWebKey{Key: &key.PublicKey}
		thumbprint, err := public.Thumbprint(stdcrypto.SHA256)
		if err != nil {
			return err
		}
		want[base64.RawURLEncoding.EncodeToString(thumbprint)] = true
	}
	for _, credential := range issued {
		issuerSigned, _, _ := strings.Cut(credential, "~")
		_, payload, err := capture.JWTParts(issuerSigned)
		if err != nil {
			return fmt.Errorf("issued credential: %w", err)
		}
		cnf, _ := payload["cnf"].(map[string]any)
		encoded, err := json.Marshal(cnf["jwk"])
		if err != nil {
			return err
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(encoded, &jwk); err != nil {
			return fmt.Errorf("issued credential cnf.jwk: %w", err)
		}
		thumbprint, err := jwk.Thumbprint(stdcrypto.SHA256)
		if err != nil {
			return err
		}
		key := base64.RawURLEncoding.EncodeToString(thumbprint)
		if !want[key] {
			return fmt.Errorf("issued credential cnf.jwk is not an unused proof key")
		}
		delete(want, key)
	}
	return nil
}
