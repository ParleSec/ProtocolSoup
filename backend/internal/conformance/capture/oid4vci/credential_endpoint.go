package oid4vci

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// Nonce Endpoint and Credential Endpoint requirements (OID4VCI 1.0 Sections
// 7 and 8).

func init() {
	capture.Register("CI-006", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "unrecognised-member-ignored",
			Description: "The conformance client sends /oid4vci/credential a Credential Request with a valid proofs.jwt array and an extra singular proof member from pre-Final drafts, whose jwt value is not a JWT.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return unrecognisedProofMember(ctx, env, true)
			},
		},
		Failing: &capture.Scenario{
			Name:        "proof-only-in-unrecognised-member",
			Description: "The conformance client sends /oid4vci/credential a Credential Request whose only key proof is a valid jwt proof inside the singular proof member, which OID4VCI 1.0 Final does not define, and no proofs member.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return unrecognisedProofMember(ctx, env, false)
			},
		},
	})

	capture.Register("CI-007", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "token-bound-credential-identifier",
			Description: "The conformance client sends /oid4vci/credential the credential_identifier that the Token Response returned in authorization_details, with the Access Token from that same response.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return credentialIdentifierRequest(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "credential-identifier-from-another-token",
			Description: "The conformance client sends /oid4vci/credential a credential_identifier that the issuer returned with a second Access Token, presented with the first Access Token.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return credentialIdentifierRequest(ctx, env, true)
			},
		},
	})

	capture.Register("CI-009", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "advertised-nonce-endpoint",
			Description: "The conformance client reads the Credential Issuer Metadata from /.well-known/openid-credential-issuer/oid4vci and sends a POST to the nonce_endpoint it advertises.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         advertisedNonceEndpoint,
		},
		Failing: &capture.Scenario{
			Name:        "proof-without-c-nonce",
			Description: "The conformance client sends /oid4vci/credential a Credential Request whose jwt proof is correctly signed and addressed but carries no nonce claim.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         proofWithoutNonce,
		},
	})

	capture.Register("CI-012", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "unauthenticated-nonce-requests",
			Description: "The conformance client sends two POST requests to /oid4vci/nonce with no Authorization header, no DPoP header and no body, and checks that each answer carries a different c_nonce and Cache-Control: no-store.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         unauthenticatedNonceRequests,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "A conformant Nonce Endpoint answers every POST without authorization, so there is no request it must reject under this requirement.",
		},
	})

	capture.Register("CI-015", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "fresh-c-nonce",
			Description: "The conformance client obtains a c_nonce from /oid4vci/nonce and sends /oid4vci/credential a Credential Request whose jwt proof carries it.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return reusedNonce(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "consumed-c-nonce-reused",
			Description: "The conformance client spends a c_nonce on one Credential Request, then sends a second Credential Request on the same Access Token with a newly signed jwt proof that carries the same c_nonce.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return reusedNonce(ctx, env, true)
			},
		},
	})
}

// unrecognisedProofMember exercises Section 8.2, "The Credential Issuer MUST
// ignore any unrecognized parameters." With proofsPresent the singular proof
// member sits beside a valid proofs array and must not be validated; without
// it the valid proof travels only in proof, which must not be acted on, so the
// request has no key proof and Section 8.3.1.2 gives invalid_proof.
func unrecognisedProofMember(ctx context.Context, env *capture.Env, proofsPresent bool) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{})
	if err != nil {
		return "", err
	}
	proof, err := boundProof(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	var body map[string]any
	if proofsPresent {
		body = grant.CredentialRequest(proof)
		body["proof"] = map[string]any{"proof_type": "jwt", "jwt": "not-a-jwt"}
	} else {
		body = map[string]any{
			"credential_configuration_id": grant.ConfigurationID,
			"proof":                       map[string]any{"proof_type": "jwt", "jwt": proof},
		}
	}
	req, err := capture.BearerJSON(issuer.Credential, grant.AccessToken, body)
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if proofsPresent {
		return credentialOutcome("credential endpoint", resp)
	}
	return credentialOutcome("credential endpoint", resp, "invalid_proof")
}

// credentialIdentifierRequest exercises Sections 6.2 and 8.2: a
// credential_identifier names a Credential Dataset authorised for the Access
// Token whose Token Response returned it. One from another token is unknown
// to this one, which Section 8.3.1.2 reports as unknown_credential_identifier.
func credentialIdentifierRequest(ctx context.Context, env *capture.Env, crossToken bool) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{AuthorizationDetails: true})
	if err != nil {
		return "", err
	}
	identifier := grant.CredentialIdentifier
	if crossToken {
		other, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{AuthorizationDetails: true})
		if err != nil {
			return "", err
		}
		identifier = other.CredentialIdentifier
	}
	proof, err := boundProof(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	body := grant.CredentialRequest(proof)
	body["credential_identifier"] = identifier
	req, err := capture.BearerJSON(issuer.Credential, grant.AccessToken, body)
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if !crossToken {
		return credentialOutcome("credential endpoint", resp)
	}
	return credentialOutcome("credential endpoint", resp, "unknown_credential_identifier")
}

// advertisedNonceEndpoint exercises Section 7: an issuer that requires a
// c_nonce in proofs publishes nonce_endpoint (Section 12.2.4), and that URL
// issues one.
func advertisedNonceEndpoint(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	req, err := http.NewRequest(http.MethodGet, capture.IssuerMetadataURL(env), nil)
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("issuer metadata answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	metadata, err := resp.JSON()
	if err != nil {
		return "", err
	}
	nonceEndpoint, _ := metadata["nonce_endpoint"].(string)
	if nonceEndpoint == "" {
		return "", fmt.Errorf("issuer metadata has no nonce_endpoint")
	}
	if req, err = http.NewRequest(http.MethodPost, nonceEndpoint, nil); err != nil {
		return "", err
	}
	if resp, err = env.Do(ctx, req); err != nil {
		return "", err
	}
	return nonceOutcome(resp)
}

// proofWithoutNonce shows the issuer does require a c_nonce: a proof without
// one is refused with invalid_proof, which Section 8.3.1.2 uses when "at
// least one of the key proofs does not contain a c_nonce value".
func proofWithoutNonce(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{})
	if err != nil {
		return "", err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	proof, err := key.Proof(issuer.ID, "")
	if err != nil {
		return "", err
	}
	req, err := capture.BearerJSON(issuer.Credential, grant.AccessToken, grant.CredentialRequest(proof))
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	return credentialOutcome("credential endpoint", resp, "invalid_proof")
}

// unauthenticatedNonceRequests exercises Section 7: the Nonce Endpoint is not
// a protected resource, and Section 7.2 requires "New challenge values MUST
// be unpredictable" and an uncacheable response carrying no-store.
func unauthenticatedNonceRequests(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	nonces := make([]string, 0, 2)
	for range 2 {
		req, err := http.NewRequest(http.MethodPost, env.BaseURL+"/oid4vci/nonce", nil)
		if err != nil {
			return "", err
		}
		resp, err := env.Do(ctx, req)
		if err != nil {
			return "", err
		}
		outcome, err := nonceOutcome(resp)
		if err != nil || outcome != conformance.OutcomeAccepted {
			return outcome, err
		}
		body, err := resp.JSON()
		if err != nil {
			return "", err
		}
		nonce, _ := body["c_nonce"].(string)
		nonces = append(nonces, nonce)
	}
	if nonces[0] == nonces[1] {
		return "", fmt.Errorf("nonce endpoint returned the same c_nonce twice")
	}
	return conformance.OutcomeAccepted, nil
}

// nonceOutcome classifies a Nonce Response (Section 7.2): HTTP 200 with a
// c_nonce and Cache-Control no-store is acceptance; HTTP 401, which a
// protected resource answers without a token, is rejection.
func nonceOutcome(resp *capture.Response) (conformance.ArtefactOutcome, error) {
	switch resp.Status {
	case http.StatusOK:
		body, err := resp.JSON()
		if err != nil {
			return "", err
		}
		if nonce, _ := body["c_nonce"].(string); nonce == "" {
			return "", fmt.Errorf("nonce response has no c_nonce: %s", capture.Truncate(resp.Body))
		}
		if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
			return "", fmt.Errorf("nonce response Cache-Control is %q, want no-store", resp.Header.Get("Cache-Control"))
		}
		return conformance.OutcomeAccepted, nil
	case http.StatusUnauthorized:
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("nonce endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// reusedNonce exercises the single-use half of CI-015: once a Credential
// Request has consumed a c_nonce, a second proof carrying it is answered with
// invalid_nonce (Section 8.3.1.2). The five-minute lifetime is not waited out.
func reusedNonce(ctx context.Context, env *capture.Env, reuse bool) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{})
	if err != nil {
		return "", err
	}
	nonce, err := capture.FreshNonce(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	send := func() (*capture.Response, error) {
		proof, err := key.Proof(issuer.ID, nonce)
		if err != nil {
			return nil, err
		}
		req, err := capture.BearerJSON(issuer.Credential, grant.AccessToken, grant.CredentialRequest(proof))
		if err != nil {
			return nil, err
		}
		return env.Do(ctx, req)
	}
	resp, err := send()
	if err != nil {
		return "", err
	}
	if !reuse {
		return credentialOutcome("credential endpoint", resp)
	}
	first, err := credentialOutcome("credential endpoint", resp)
	if err != nil {
		return "", err
	}
	if first != conformance.OutcomeAccepted {
		return "", fmt.Errorf("the first Credential Request with the fresh c_nonce was refused: %s", capture.Truncate(resp.Body))
	}
	if resp, err = send(); err != nil {
		return "", err
	}
	return credentialOutcome("credential endpoint", resp, "invalid_nonce")
}
