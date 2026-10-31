// Package rfc9901 captures the SD-JWT format rules of RFC 9901 against the
// OID4VCI issuer and the OID4VP verifier. The conformance client obtains an
// SD-JWT VC from the issuer, changes it where a row needs it, and presents
// it; the verifier's decision at /oid4vp/result is the evidence.
package rfc9901

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
	capture.Register("SDJWT-000", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "issued-sd-jwt-ends-in-tilde",
			Description: "The conformance client redeems a pre-authorized code and sends a Credential Request, with a jwt proof of its own key, to the issuer's Credential Endpoint. The SD-JWT VC in the Credential Response carries no Key Binding JWT, so it must be the Issuer-signed JWT followed by a tilde and each Disclosure followed by a tilde, ending in the tilde before an empty last element.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         issuedSDJWTEndsInTilde,
		},
		Failing: &capture.Scenario{
			Name:        "final-tilde-omitted",
			Description: "The conformance client removes the final tilde from an SD-JWT VC the issuer issued to it, so the value ends with its last Disclosure, and POSTs it as the vp_token of a direct_post response to /oid4vp/response, with no Key Binding JWT. The verifier parses the serialization before anything else, must find that the last element is neither empty nor a Key Binding JWT, and reports the failure in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         finalTildeOmitted,
		},
	})

	capture.Register("SDJWT-001", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "issued-digests-unique",
			Description: "The conformance client obtains an SD-JWT VC from the issuer, checks that no digest repeats in the _sd array of its Issuer-signed JWT, and presents it with a Key Binding JWT in a direct_post response to /oid4vp/response. The verifier must allow the presentation in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         issuedDigestsUnique,
		},
		Failing: &capture.Scenario{
			Name:        "repeated-sd-digest",
			Description: "The conformance client appends a second copy of the first digest to the _sd array in the payload of an SD-JWT VC the issuer issued to it. This changes signed content, so the issuer's signature no longer verifies either. It presents the result with a Key Binding JWT in a direct_post response to /oid4vp/response, and the verifier must report the repeated digest in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         repeatedSDDigest,
		},
	})

	capture.Register("SDJWT-002", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "The issuer writes _sd_alg into the payload it signs for every SD-JWT VC, and removing the claim breaks that signature, so no presentation the verifier allows relies on the default.",
		},
		Failing: &capture.Scenario{
			Name:        "no-sd-alg-with-sha-384-digests",
			Description: "The conformance client removes _sd_alg from the payload of an SD-JWT VC the issuer issued to it and replaces each _sd digest with the sha-384 digest of the same Disclosure. This changes signed content, so the issuer's signature no longer verifies either. It presents the result with a Key Binding JWT in a direct_post response to /oid4vp/response. A verifier that applies the sha-256 default finds none of the Disclosures referenced by a digest, and must report that in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         noSDAlgWithSHA384Digests,
		},
	})

	capture.Register("SDJWT-003", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "ordinary-claim-names",
			Description: "The conformance client obtains an SD-JWT VC from the issuer, checks that none of its Disclosures uses the claim name _sd or ..., and presents it with a Key Binding JWT in a direct_post response to /oid4vp/response. The verifier must allow the presentation in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         ordinaryClaimNames,
		},
		Failing: &capture.Scenario{
			Name:        "disclosure-named-sd",
			Description: "The conformance client appends its own Disclosure with the claim name _sd and an array of one digest as its value to an SD-JWT VC the issuer issued to it, and presents the result with a Key Binding JWT in a direct_post response to /oid4vp/response. No digest in the Issuer-signed JWT references the new Disclosure, because the issuer's signature covers the digests; the verifier decodes every presented Disclosure before matching digests and must reject this one for its claim name in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         disclosureNamedSD,
		},
	})

	capture.Register("SDJWT-004", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "every-disclosure-referenced",
			Description: "The conformance client presents an SD-JWT VC the issuer issued to it, with every Disclosure the issuer gave it and a Key Binding JWT, in a direct_post response to /oid4vp/response. Each Disclosure's digest is in the _sd array of the Issuer-signed JWT, so the verifier must allow the presentation in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         everyDisclosureReferenced,
		},
		Failing: &capture.Scenario{
			Name:        "appended-uncommitted-disclosure",
			Description: "The conformance client appends its own Disclosure, age_over_21 set to true, to an SD-JWT VC the issuer issued to it, and presents the result with a Key Binding JWT over the whole altered SD-JWT in a direct_post response to /oid4vp/response. The Issuer-signed JWT is unchanged and carries no digest for the new Disclosure, so the verifier must reject the SD-JWT in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         appendedUncommittedDisclosure,
		},
	})

	capture.Register("SDJWT-005", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "disclosures-at-committed-level",
			Description: "The conformance client presents an SD-JWT VC the issuer issued to it, with a Key Binding JWT, in a direct_post response to /oid4vp/response. Every Disclosure is an object property whose digest sits in the top-level _sd array, and no claim name is also a plaintext claim, so the verifier must insert each at the top level and allow the presentation in the result at /oid4vp/result. The issuer issues no nested or array-element Disclosures, so this exchange does not exercise recursive processing.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         disclosuresAtCommittedLevel,
		},
		Failing: &capture.Scenario{
			Name:        "disclosure-collides-with-plaintext-claim",
			Description: "The conformance client adds a plaintext claim to the payload of an SD-JWT VC the issuer issued to it, with the same name and value as one of its Disclosures. This changes signed content, so the issuer's signature no longer verifies either. It presents the result with a Key Binding JWT in a direct_post response to /oid4vp/response. The Disclosure's claim name already exists at the level of the _sd key, so the verifier must reject the SD-JWT in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         disclosureCollidesWithPlaintextClaim,
		},
	})
}

// issuedSDJWTEndsInTilde records the Credential Request whose response
// carries the SD-JWT VC (RFC 9901 Section 4).
func issuedSDJWTEndsInTilde(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return "", err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{OfferOptions: capture.OfferOptions{TxCode: true}})
	if err != nil {
		return "", err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return "", err
	}
	nonce, err := capture.FreshNonce(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	proof, err := key.Proof(issuer.ID, nonce)
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
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("credential request answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return "", err
	}
	credentials, err := capture.IssuedCredentials(body)
	if err != nil {
		return "", err
	}
	for _, credential := range credentials {
		parsed, err := splitSDJWT(credential)
		if err != nil {
			return "", err
		}
		for _, disclosure := range parsed.Disclosures {
			if disclosure == "" {
				return "", fmt.Errorf("issued SD-JWT VC carries an empty element before its last tilde")
			}
		}
	}
	return conformance.OutcomeAccepted, nil
}

func finalTildeOmitted(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{omitFinalTilde: true})
	if err != nil {
		return "", err
	}
	return refused(policy, "vp_token_invalid", "sd-jwt compact serialization without a key binding jwt must end with a tilde")
}

func issuedDigestsUnique(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		payload, err := credential.payload()
		if err != nil {
			return err
		}
		digests, err := sdDigests(payload)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, digest := range digests {
			if seen[digest] {
				return fmt.Errorf("issued SD-JWT VC repeats the digest %q", digest)
			}
			seen[digest] = true
		}
		return nil
	}})
	if err != nil {
		return "", err
	}
	return allowed(policy)
}

func repeatedSDDigest(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	var repeated string
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		return credential.replacePayload(func(payload map[string]any) error {
			digests, err := sdDigests(payload)
			if err != nil {
				return err
			}
			repeated = digests[0]
			payload["_sd"] = append(payload["_sd"].([]any), repeated)
			return nil
		})
	}})
	if err != nil {
		return "", err
	}
	return refused(policy, "disclosure_invalid", fmt.Sprintf("duplicate sd-jwt digest %q", repeated))
}

func noSDAlgWithSHA384Digests(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		if len(credential.Disclosures) == 0 {
			return fmt.Errorf("issued SD-JWT VC carries no Disclosures")
		}
		return credential.replacePayload(func(payload map[string]any) error {
			if _, err := sdDigests(payload); err != nil {
				return err
			}
			digests := make([]any, 0, len(credential.Disclosures))
			for _, disclosure := range credential.Disclosures {
				digests = append(digests, sha384Digest(disclosure))
			}
			delete(payload, "_sd_alg")
			payload["_sd"] = digests
			return nil
		})
	}})
	if err != nil {
		return "", err
	}
	for _, reason := range policy.Reasons {
		if strings.Contains(reason, "_sd_alg") {
			return "", fmt.Errorf("verifier rejected the missing _sd_alg instead of applying the sha-256 default: %s", reason)
		}
	}
	return refused(policy, "disclosure_invalid", "is not referenced by the issuer payload")
}

func ordinaryClaimNames(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		for _, encoded := range credential.Disclosures {
			disclosure, err := decodeObjectDisclosure(encoded)
			if err != nil {
				return err
			}
			if disclosure.ClaimName == "_sd" || disclosure.ClaimName == "..." {
				return fmt.Errorf("issued SD-JWT VC carries a Disclosure named %q", disclosure.ClaimName)
			}
		}
		return nil
	}})
	if err != nil {
		return "", err
	}
	return allowed(policy)
}

func disclosureNamedSD(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		if len(credential.Disclosures) == 0 {
			return fmt.Errorf("issued SD-JWT VC carries no Disclosures")
		}
		reserved, err := newObjectDisclosure("_sd", []any{sha256Digest(credential.Disclosures[0])})
		if err != nil {
			return err
		}
		credential.Disclosures = append(credential.Disclosures, reserved)
		return nil
	}})
	if err != nil {
		return "", err
	}
	return refused(policy, "disclosure_invalid", `disclosure claim_name "_sd" is reserved`)
}

func everyDisclosureReferenced(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		payload, err := credential.payload()
		if err != nil {
			return err
		}
		digests, err := sdDigests(payload)
		if err != nil {
			return err
		}
		committed := map[string]bool{}
		for _, digest := range digests {
			committed[digest] = true
		}
		for _, disclosure := range credential.Disclosures {
			if !committed[sha256Digest(disclosure)] {
				return fmt.Errorf("issued SD-JWT VC carries a Disclosure its _sd array does not reference")
			}
		}
		return nil
	}})
	if err != nil {
		return "", err
	}
	return allowed(policy)
}

func appendedUncommittedDisclosure(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		uncommitted, err := newObjectDisclosure("age_over_21", true)
		if err != nil {
			return err
		}
		credential.Disclosures = append(credential.Disclosures, uncommitted)
		return nil
	}})
	if err != nil {
		return "", err
	}
	return refused(policy, "disclosure_invalid", `disclosure digest for claim "age_over_21" is not referenced by the issuer payload`)
}

func disclosuresAtCommittedLevel(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		payload, err := credential.payload()
		if err != nil {
			return err
		}
		for _, encoded := range credential.Disclosures {
			disclosure, err := decodeObjectDisclosure(encoded)
			if err != nil {
				return err
			}
			if _, plaintext := payload[disclosure.ClaimName]; plaintext {
				return fmt.Errorf("issued SD-JWT VC discloses %q, which is also a plaintext claim", disclosure.ClaimName)
			}
		}
		return nil
	}})
	if err != nil {
		return "", err
	}
	return allowed(policy)
}

func disclosureCollidesWithPlaintextClaim(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	var claimName string
	policy, err := present(ctx, env, presentation{prepare: func(credential *sdJWT) error {
		if len(credential.Disclosures) == 0 {
			return fmt.Errorf("issued SD-JWT VC carries no Disclosures")
		}
		disclosure, err := decodeObjectDisclosure(credential.Disclosures[0])
		if err != nil {
			return err
		}
		claimName = disclosure.ClaimName
		return credential.replacePayload(func(payload map[string]any) error {
			if _, exists := payload[claimName]; exists {
				return fmt.Errorf("issued SD-JWT VC already carries %q in plaintext", claimName)
			}
			payload[claimName] = disclosure.ClaimValue
			return nil
		})
	}})
	if err != nil {
		return "", err
	}
	return refused(policy, "disclosure_invalid", fmt.Sprintf("disclosed claim %q collides with a permanently disclosed claim", claimName))
}

// presentation says how the conformance client changes and sends the SD-JWT
// VC the issuer issued to it.
type presentation struct {
	// prepare inspects or changes the issued SD-JWT before it is presented.
	prepare func(credential *sdJWT) error
	// omitFinalTilde sends the SD-JWT without its final tilde and without a
	// Key Binding JWT; otherwise a Key Binding JWT is appended.
	omitFinalTilde bool
}

// present obtains an SD-JWT VC from the issuer, applies p, and sends it as
// the vp_token of a direct_post response (OID4VP 1.0 Section 8.2) to a
// request the verifier created for it, returning the verifier's decision.
func present(ctx context.Context, env *capture.Env, p presentation) (*capture.Policy, error) {
	holder, err := capture.IssueSDJWTHolder(ctx, env)
	if err != nil {
		return nil, err
	}
	credential, err := splitSDJWT(holder.Credential)
	if err != nil {
		return nil, err
	}
	if p.prepare != nil {
		if err := p.prepare(credential); err != nil {
			return nil, err
		}
	}
	requestID, requestURI, err := capture.CreateRequest(ctx, env, capture.RequestOptions{ResponseMode: "direct_post", Credential: capture.SDJWTQuery(holder.VCT)})
	if err != nil {
		return nil, err
	}
	object, err := capture.FetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return nil, err
	}
	state := object.Claim("state")
	if state == "" {
		return nil, fmt.Errorf("request object carries no state")
	}
	var vpToken string
	if p.omitFinalTilde {
		if len(credential.Disclosures) == 0 {
			return nil, fmt.Errorf("issued SD-JWT VC carries no Disclosures, so without its final tilde it is a bare JWT")
		}
		vpToken, err = capture.VPToken(strings.TrimSuffix(credential.serialize(), "~"))
	} else {
		vpToken, err = holder.PresentSerialized(credential.serialize(), object.Claim("client_id"), object.Claim("nonce"))
	}
	if err != nil {
		return nil, err
	}
	resp, err := capture.PostResponse(ctx, env, object, url.Values{"vp_token": {vpToken}, "state": {state}})
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("response_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	return capture.FetchResult(ctx, env, requestID)
}

// allowed is the outcome of presenting conformant material: the verifier
// must allow it.
func allowed(policy *capture.Policy) (conformance.ArtefactOutcome, error) {
	if !policy.Allowed {
		return "", fmt.Errorf("verifier denied the issued credential: %s (%s)",
			strings.Join(policy.ReasonCodes, ", "), strings.Join(policy.Reasons, "; "))
	}
	return conformance.OutcomeAccepted, nil
}

// refused is the outcome of presenting altered material: rejected only when
// the verifier reports this requirement's check by code and message.
func refused(policy *capture.Policy, code, detail string) (conformance.ArtefactOutcome, error) {
	if policy.Allowed {
		return conformance.OutcomeAccepted, nil
	}
	if !policy.HasReason(code, detail) {
		return "", fmt.Errorf("verifier denied the presentation without reporting %s with %q: %s (%s)",
			code, detail, strings.Join(policy.ReasonCodes, ", "), strings.Join(policy.Reasons, "; "))
	}
	return conformance.OutcomeRejected, nil
}
