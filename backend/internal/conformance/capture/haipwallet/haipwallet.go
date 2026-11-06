// Package haipwallet captures the hosted wallet's HAIP issuance
// requirements (HAIP 1.0 Section 4 and OpenID4VCI 1.0 Sections 8.2 and 10):
// PKCE S256 with PAR, DPoP with DPoP-Nonce handling, client attestation at
// the PAR and Token Endpoints, the Wallet Attestation itself, key
// attestations without unproven assurance levels, and encrypted Credential
// Responses. Passing cases run the wallet's HAIP path against the issuer;
// failing cases point it at the conformance counterparty, which it refuses
// before any attested request.
package haipwallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// haipConfigurationID is the issuer's HAIP SD-JWT VC Credential
// Configuration; its name puts the hosted wallet on the HAIP issuance path.
const haipConfigurationID = "UniversityDegreeCredentialSDJWTHAIP"

// counterpartyConfigurationID is the one Credential Configuration every
// counterparty issuer scenario advertises.
const counterpartyConfigurationID = "ConformanceCounterpartySDJWT"

// noHAIPMaterial is how the wallet reports that it holds no client or key
// attestation material, without which it cannot run the HAIP path at all.
const noHAIPMaterial = "requires haip attestation material"

func init() {
	capture.Register("CW-072", capture.Entry{
		Passing: &capture.Scenario{
			Name: "haip-encrypted-credential-response",
			Description: "The conformance client has the issuer create a pre-authorized offer for the " + haipConfigurationID + " configuration and asks the hosted wallet to import it. " +
				"The issuer's metadata advertises ECDH-ES response encryption and a request-encryption key, so the wallet sends its Credential Request as an application/jwt JWE carrying its response key, " +
				"and the issuer answers with an application/jwt JWE. The capture checks that the response JWE uses an alg and enc the metadata advertised and that the wallet decrypted it and stored the Credential.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      encryptedCredentialResponse,
		},
		Failing: &capture.Scenario{
			Name: "counterparty-response-encrypted-with-unnegotiated-alg",
			Description: "The conformance client asks the hosted wallet to import the counterparty's cw-072 offer. The counterparty advertises ECDH-ES and A256GCM, decrypts the wallet's encrypted Credential Request, " +
				"and answers with an application/jwt JWE encrypted to the wallet's response key with ECDH-ES+A256KW, which is not the negotiated algorithm. The wallet refuses to decrypt it.",
			Actor:    conformance.ActorCounterparty,
			Expected: conformance.OutcomeRejected,
			Run:      counterpartyUnnegotiatedAlgorithm,
		},
	})
	capture.Register("CW-H003", capture.Entry{
		Passing: &capture.Scenario{
			Name: "haip-par-with-pkce-s256",
			Description: "The conformance client has the issuer create an authorization_code offer for the " + haipConfigurationID + " configuration and asks the hosted wallet to import it. " +
				"The wallet pushes its Authorization Request to the issuer's PAR endpoint with code_challenge_method=S256 and returns an authorization URL carrying only client_id and request_uri. " +
				"The iss check on the Authorization Response happens on the wallet's browser callback, which this capture does not drive.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      parWithPKCES256,
		},
		Failing: &capture.Scenario{
			Name: "counterparty-par-without-pkce-s256",
			Description: "The conformance client asks the hosted wallet to start wallet-initiated issuance from the counterparty's cw-h003 issuer. Its authorization server metadata requires PAR but lists only plain in code_challenge_methods_supported. " +
				"The wallet refuses before pushing any Authorization Request.",
			Actor:    conformance.ActorCounterparty,
			Expected: conformance.OutcomeRejected,
			Run:      counterpartyWithoutS256,
		},
	})
	capture.Register("CW-H004", capture.Entry{
		Passing: &capture.Scenario{
			Name: "haip-dpop-nonce-challenge-handled",
			Description: "The conformance client has the issuer create a pre-authorized offer for the " + haipConfigurationID + " configuration and asks the hosted wallet to import it. " +
				"The issuer requires a DPoP nonce: its Token Endpoint answers the wallet's first DPoP proof with 400 use_dpop_nonce and a DPoP-Nonce header, and the wallet repeats the request with that value in the proof's nonce claim. " +
				"The capture checks the same for the Credential Endpoint's 401 challenge when one is issued, and that every Token and Credential Request carried a DPoP proof.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      dpopNonceHandled,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The conformance counterparty serves no use_dpop_nonce challenge, so no exchange can show the hosted wallet refusing a challenge that lacks the DPoP-Nonce header.",
		},
	})
	capture.Register("CW-H010", capture.Entry{
		Passing: &capture.Scenario{
			Name: "haip-same-client-authentication-at-par-and-token",
			Description: "The conformance client asks the hosted wallet to import an authorization_code offer for the " + haipConfigurationID + " configuration, which records the wallet's PAR request, " +
				"then to import a pre-authorized offer for the same configuration, which records its Token Request. The capture checks that both carry OAuth-Client-Attestation, OAuth-Client-Attestation-PoP and DPoP headers, " +
				"that the attestations share one sub, that client_id equals that sub in both, and that neither adds a second authentication method. " +
				"The Token Request of the authorization_code flow itself runs on the wallet's browser callback, which records no hops, so the pre-authorized Token Request stands in for it.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      sameClientAuthentication,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet refuses to push an authorization request without client attestation and builds the attestation, its proof of possession and the DPoP proof the same way for the PAR and Token Endpoints, so it never authenticates at one differently from the other.",
		},
	})
	capture.Register("CW-H013", capture.Entry{
		Passing: &capture.Scenario{
			Name: "haip-wallet-attestation-x5c-and-sub",
			Description: "The conformance client asks the hosted wallet to import two authorization_code offers for the " + haipConfigurationID + " configuration, in two wallet sessions, and reads the OAuth-Client-Attestation header of each PAR request. " +
				"The capture checks that each attestation is an ES256 oauth-client-attestation+jwt whose signature verifies under the leaf of an x5c chain that contains no self-signed certificate, " +
				"that the PAR client_id equals the attestation sub, that both attestations carry the same sub, and that the wallet minted a different attestation with a different cnf key for each request.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      walletAttestation,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet mints a fresh attestation for every request with a deployment-wide sub and sends that sub as the PAR client_id, so it never sends an attestation that breaks these rules.",
		},
	})
	capture.Register("CW-H014", capture.Entry{
		Passing: &capture.Scenario{
			Name: "haip-key-attestation-without-assurance-levels",
			Description: "The conformance client has the issuer create a pre-authorized offer for the " + haipConfigurationID + " configuration and asks the hosted wallet to import it. " +
				"The wallet encrypts its Credential Request, so the capture reads the proof from the wallet's own Build Credential Proof JWT record and checks that its key_attestation header is a key-attestation+jwt " +
				"whose attested_keys include the proof key and which carries neither key_storage nor user_authentication.",
			Actor:    conformance.ActorHostedWallet,
			Expected: conformance.OutcomeAccepted,
			Run:      keyAttestationWithoutLevels,
		},
		Failing: &capture.Scenario{
			Name: "counterparty-demands-iso-18045-levels",
			Description: "The conformance client asks the hosted wallet to import the counterparty's cw-h014 offer. The configuration's key_attestations_required demands iso_18045_high for key_storage and user_authentication. " +
				"The wallet holds software keys that can back no such level, so it refuses before sending a Token Request rather than claim one.",
			Actor:    conformance.ActorCounterparty,
			Expected: conformance.OutcomeRejected,
			Run:      counterpartyDemandsLevels,
		},
	})
}

// importCredential makes one /api/import call to the hosted wallet in a
// fresh session. A wallet without HAIP attestation material cannot run the
// HAIP path, which is an error for this package's scenarios, not an outcome.
func importCredential(ctx context.Context, env *capture.Env, body map[string]any) (*capture.WalletResult, error) {
	result, err := capture.CallWallet(ctx, env, capture.WalletCall{
		Path:    "/api/import",
		Body:    body,
		Session: capture.NewWalletSession(),
	})
	if err != nil {
		return nil, err
	}
	if strings.Contains(result.ErrorDescription(), noHAIPMaterial) {
		return nil, fmt.Errorf("the hosted wallet holds no HAIP attestation material (WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON and WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON), so it cannot run the HAIP issuance path: %s", result.ErrorDescription())
	}
	return result, nil
}

// issued checks that the wallet completed the import and stored a Credential.
func issued(result *capture.WalletResult) error {
	if result.Status != http.StatusOK {
		return fmt.Errorf("wallet /api/import answered %s: %s", capture.WalletStatusText(result.Status), walletError(result))
	}
	if credential, _ := result.Body["credential_jwt"].(string); credential == "" {
		return fmt.Errorf("wallet /api/import answered 200 OK without a credential_jwt")
	}
	return nil
}

// refused returns rejected when the wallet answered a 4xx whose
// error_description names this row's check, given as every string it must
// contain. Any other answer is an error: the wallet accepted, failed for a
// different reason, or did not answer at all.
func refused(result *capture.WalletResult, wantText ...string) (conformance.ArtefactOutcome, error) {
	if result.Status < http.StatusBadRequest || result.Status >= http.StatusInternalServerError {
		return "", fmt.Errorf("wallet /api/import answered %s: %s", capture.WalletStatusText(result.Status), walletError(result))
	}
	description := result.ErrorDescription()
	for _, want := range wantText {
		if !strings.Contains(description, want) {
			return "", fmt.Errorf("wallet refused for another reason: %s", walletError(result))
		}
	}
	return conformance.OutcomeRejected, nil
}

// walletError names what the wallet answered, for a scenario error.
func walletError(result *capture.WalletResult) string {
	if result.Error() == "" && result.ErrorDescription() == "" {
		if credential, _ := result.Body["credential_jwt"].(string); credential != "" {
			return "the import succeeded and a Credential was stored"
		}
		if result.Body["authorization_required"] == true {
			return "the import returned an authorization_url"
		}
		return "the body carries no error"
	}
	return result.Error() + ": " + result.ErrorDescription()
}

// preAuthorizedOfferLink has the issuer create a pre-authorized offer for
// configurationID and returns the openid-credential-offer:// link carrying
// its credential_offer_uri, which the wallet dereferences itself.
func preAuthorizedOfferLink(ctx context.Context, env *capture.Env, configurationID string) (string, error) {
	req, err := capture.NewJSON(env.BaseURL+"/oid4vci/offers/pre-authorized", map[string]any{
		"credential_configuration_ids": []string{configurationID},
	})
	if err != nil {
		return "", err
	}
	body, err := capture.SetupJSON(ctx, env, req, http.StatusCreated, "offer creation")
	if err != nil {
		return "", err
	}
	offerURI, _ := body["credential_offer_uri"].(string)
	if offerURI == "" {
		return "", fmt.Errorf("offer response has no credential_offer_uri")
	}
	// Until the wallet redeems it, the code behind the URI is usable by
	// anyone who dereferences it.
	env.NoteExpiry(capture.PreAuthorizedOfferLifetime)
	return "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURI), nil
}

// authorizationCodeOfferLink has the issuer create an authorization_code
// offer for configurationID and returns the by-value
// openid-credential-offer:// link carrying the offer object, as the issuer
// hands it out.
func authorizationCodeOfferLink(ctx context.Context, env *capture.Env, configurationID string) (string, error) {
	req, err := capture.NewJSON(env.BaseURL+"/oid4vci/offers/authorization-code", map[string]any{
		"credential_configuration_ids": []string{configurationID},
	})
	if err != nil {
		return "", err
	}
	body, err := capture.SetupJSON(ctx, env, req, http.StatusCreated, "authorization_code offer creation")
	if err != nil {
		return "", err
	}
	offer, ok := body["credential_offer"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("offer response has no credential_offer object")
	}
	encoded, err := json.Marshal(offer)
	if err != nil {
		return "", err
	}
	// The issuer_state in the offer, and the request_uri the wallet obtains
	// with it, stay usable until the issuer's transaction expires.
	expiresIn, _ := body["expires_in"].(float64)
	if expiresIn <= 0 {
		return "", fmt.Errorf("offer response has no positive expires_in")
	}
	env.NoteExpiry(time.Duration(expiresIn) * time.Second)
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(encoded)), nil
}

// counterpartyOfferLink is the by-reference offer link for a counterparty
// issuer scenario.
func counterpartyOfferLink(env *capture.Env, scenario string) (string, error) {
	if env.CounterpartyURL == "" {
		return "", fmt.Errorf("this run has no counterparty")
	}
	return "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(env.CounterpartyURL+"/scenarios/"+scenario+"/credential-offer"), nil
}

// hopHeader reads a recorded hop header by name, whatever case the wallet
// recorded it in.
func hopHeader(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

// hopsOf returns every recorded hop of step, in order.
func hopsOf(result *capture.WalletResult, step string) []capture.WalletHop {
	var out []capture.WalletHop
	for _, hop := range result.Hops {
		if hop.Step == step {
			out = append(out, hop)
		}
	}
	return out
}

// completedHop returns the hop of step the server answered 2xx: the attempt
// that went through after any DPoP nonce challenge.
func completedHop(result *capture.WalletResult, step string) (*capture.WalletHop, error) {
	hops := hopsOf(result, step)
	if len(hops) == 0 {
		return nil, fmt.Errorf("the wallet recorded no %s hop", step)
	}
	for i := range hops {
		if hops[i].ResponseStatus >= 200 && hops[i].ResponseStatus < 300 {
			return &hops[i], nil
		}
	}
	return nil, fmt.Errorf("no %s hop was answered 2xx; the last answered %d", step, hops[len(hops)-1].ResponseStatus)
}

// hopJSON decodes a recorded hop body as a JSON object.
func hopJSON(body string) map[string]any {
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return nil
	}
	return out
}

// hopForm decodes a recorded form body.
func hopForm(hop *capture.WalletHop) (url.Values, error) {
	if !strings.HasPrefix(strings.ToLower(hopHeader(hop.RequestHeaders, "Content-Type")), "application/x-www-form-urlencoded") {
		return nil, fmt.Errorf("%s request is not form-encoded: Content-Type %q", hop.Step, hopHeader(hop.RequestHeaders, "Content-Type"))
	}
	form, err := url.ParseQuery(hop.RequestBody)
	if err != nil {
		return nil, fmt.Errorf("parse %s form: %w", hop.Step, err)
	}
	return form, nil
}

// lookingGlassEvent returns the wallet's own record titled title from the
// call's _looking_glass_events, or nil.
func lookingGlassEvent(result *capture.WalletResult, title string) map[string]any {
	events, _ := result.Body["_looking_glass_events"].([]any)
	for _, raw := range events {
		event, _ := raw.(map[string]any)
		if event["title"] == title {
			data, _ := event["data"].(map[string]any)
			return data
		}
	}
	return nil
}

// jweHeader decodes the protected header of a compact JWE.
func jweHeader(compact string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("value has %d segments, not the five of a compact JWE", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWE header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, fmt.Errorf("decode JWE header: %w", err)
	}
	return header, nil
}

func containsString(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
