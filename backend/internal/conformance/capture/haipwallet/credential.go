package haipwallet

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// The wallet's pre-authorized HAIP issuance: DPoP at the Token and
// Credential Endpoints (HAIP 1.0 Section 4), the key attestation in its
// proof (HAIP 1.0 Section 4.5.1) and the encrypted Credential Request and
// Response (OpenID4VCI 1.0 Sections 8.2 and 10).

const (
	stepCredential     = "Credential Request"
	stepIssuerMetadata = "Fetch Credential Issuer Metadata"
	stepProofBuilt     = "Build Credential Proof JWT"

	typKeyAttestation = "key-attestation+jwt"
	useDPoPNonce      = "use_dpop_nonce"
)

// preAuthorizedHAIPImport imports a pre-authorized offer for the HAIP
// configuration and checks the wallet stored the Credential.
func preAuthorizedHAIPImport(ctx context.Context, env *capture.Env) (*capture.WalletResult, error) {
	link, err := preAuthorizedOfferLink(ctx, env, haipConfigurationID)
	if err != nil {
		return nil, err
	}
	result, err := importCredential(ctx, env, map[string]any{"offer": link})
	if err != nil {
		return nil, err
	}
	if err := issued(result); err != nil {
		return nil, err
	}
	return result, nil
}

// encryptedCredentialResponse checks OpenID4VCI 1.0 Section 10 in both
// directions on the recorded Credential Request: an application/jwt JWE out,
// an application/jwt JWE back whose alg and enc the issuer's metadata
// advertised, and a stored Credential, so the wallet decrypted it.
func encryptedCredentialResponse(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, err := preAuthorizedHAIPImport(ctx, env)
	if err != nil {
		return "", err
	}
	credential, err := completedHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	if contentType := hopHeader(credential.RequestHeaders, "Content-Type"); !strings.HasPrefix(contentType, "application/jwt") {
		return "", fmt.Errorf("the Credential Request was sent as %q, not application/jwt", contentType)
	}
	if _, err := jweHeader(credential.RequestBody); err != nil {
		return "", fmt.Errorf("the Credential Request body: %w", err)
	}
	if contentType := hopHeader(credential.ResponseHeaders, "Content-Type"); !strings.HasPrefix(contentType, "application/jwt") {
		return "", fmt.Errorf("the Credential Response came back as %q, not application/jwt", contentType)
	}
	header, err := jweHeader(credential.ResponseBody)
	if err != nil {
		return "", fmt.Errorf("the Credential Response body: %w", err)
	}
	metadata, err := issuerMetadataHop(result)
	if err != nil {
		return "", err
	}
	encryption, _ := metadata["credential_response_encryption"].(map[string]any)
	algs, _ := encryption["alg_values_supported"].([]any)
	encs, _ := encryption["enc_values_supported"].([]any)
	alg, _ := header["alg"].(string)
	enc, _ := header["enc"].(string)
	if !containsString(algs, alg) || !containsString(encs, enc) {
		return "", fmt.Errorf("the Credential Response JWE uses alg %q and enc %q; the metadata advertised %v and %v", alg, enc, algs, encs)
	}
	return conformance.OutcomeAccepted, nil
}

// issuerMetadataHop returns the Credential Issuer Metadata the wallet fetched,
// whether it came as JSON or as signed metadata.
func issuerMetadataHop(result *capture.WalletResult) (map[string]any, error) {
	hop, err := completedHop(result, stepIssuerMetadata)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(hopHeader(hop.ResponseHeaders, "Content-Type"), "application/jwt") {
		_, claims, err := capture.JWTParts(hop.ResponseBody)
		if err != nil {
			return nil, fmt.Errorf("signed Credential Issuer Metadata: %w", err)
		}
		return claims, nil
	}
	metadata := hopJSON(hop.ResponseBody)
	if metadata == nil {
		return nil, fmt.Errorf("the Credential Issuer Metadata is not a JSON object: %s", capture.Truncate([]byte(hop.ResponseBody)))
	}
	return metadata, nil
}

// counterpartyUnnegotiatedAlgorithm imports the counterparty's cw-072 offer,
// whose Credential Response is encrypted with ECDH-ES+A256KW instead of the
// negotiated ECDH-ES.
func counterpartyUnnegotiatedAlgorithm(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	link, err := counterpartyOfferLink(env, "cw-072")
	if err != nil {
		return "", err
	}
	result, err := importCredential(ctx, env, map[string]any{"offer": link})
	if err != nil {
		return "", err
	}
	if result.Hop(stepCredential) == nil {
		return "", fmt.Errorf("the wallet sent no Credential Request: %s", walletError(result))
	}
	return refused(result, "parse encrypted credential response", `"ECDH-ES+A256KW"`)
}

// dpopNonceHandled checks that every Token and Credential Request carried a
// DPoP proof, and that each use_dpop_nonce challenge was answered by a
// repeat whose proof carries the DPoP-Nonce value (RFC 9449 Sections 8 and
// 9, HAIP 1.0 Section 4).
func dpopNonceHandled(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, err := preAuthorizedHAIPImport(ctx, env)
	if err != nil {
		return "", err
	}
	tokenChallenges, err := nonceChallengesHandled(hopsOf(result, stepToken), stepToken)
	if err != nil {
		return "", err
	}
	if tokenChallenges == 0 {
		return "", fmt.Errorf("the Token Endpoint issued no use_dpop_nonce challenge, so the exchange cannot show the wallet handling DPoP-Nonce")
	}
	if _, err := nonceChallengesHandled(hopsOf(result, stepCredential), stepCredential); err != nil {
		return "", err
	}
	credential, err := completedHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	if scheme, _, _ := strings.Cut(hopHeader(credential.RequestHeaders, "Authorization"), " "); scheme != "DPoP" {
		return "", fmt.Errorf("the Credential Request presents the Access Token with the %q scheme, not DPoP", scheme)
	}
	return conformance.OutcomeAccepted, nil
}

// nonceChallengesHandled walks the hops of one endpoint in order. Every hop
// must carry a DPoP proof. A 400 or 401 use_dpop_nonce challenge must carry
// a DPoP-Nonce header and be followed by a repeat whose proof nonce equals
// it. It returns how many challenges were handled.
func nonceChallengesHandled(hops []capture.WalletHop, step string) (int, error) {
	if len(hops) == 0 {
		return 0, fmt.Errorf("the wallet recorded no %s hop", step)
	}
	handled := 0
	for i := range hops {
		hop := &hops[i]
		if hopHeader(hop.RequestHeaders, "DPoP") == "" {
			return 0, fmt.Errorf("%s %d of %d carries no DPoP proof", step, i+1, len(hops))
		}
		if !isNonceChallenge(hop) {
			continue
		}
		nonce := hopHeader(hop.ResponseHeaders, "DPoP-Nonce")
		if nonce == "" {
			return 0, fmt.Errorf("%s was challenged with use_dpop_nonce but no DPoP-Nonce header", step)
		}
		if i+1 >= len(hops) {
			return 0, fmt.Errorf("%s was challenged with use_dpop_nonce and the wallet did not repeat it", step)
		}
		_, claims, err := capture.JWTParts(hopHeader(hops[i+1].RequestHeaders, "DPoP"))
		if err != nil {
			return 0, fmt.Errorf("%s repeat DPoP proof: %w", step, err)
		}
		if claims["nonce"] != nonce {
			return 0, fmt.Errorf("%s repeat DPoP proof carries nonce %v, not the DPoP-Nonce value %q", step, claims["nonce"], nonce)
		}
		handled++
	}
	return handled, nil
}

// isNonceChallenge reports whether a hop's response is an RFC 9449 nonce
// challenge: a 400 with error use_dpop_nonce (Section 8), or a 401 whose
// WWW-Authenticate or body names it, or that carries only a DPoP-Nonce
// header (Section 9).
func isNonceChallenge(hop *capture.WalletHop) bool {
	switch hop.ResponseStatus {
	case http.StatusBadRequest:
		return hopJSON(hop.ResponseBody)["error"] == useDPoPNonce
	case http.StatusUnauthorized:
		return strings.Contains(hopHeader(hop.ResponseHeaders, "WWW-Authenticate"), useDPoPNonce) ||
			hopJSON(hop.ResponseBody)["error"] == useDPoPNonce ||
			hopHeader(hop.ResponseHeaders, "DPoP-Nonce") != ""
	}
	return false
}

// keyAttestationWithoutLevels reads the proof the wallet built for its
// encrypted Credential Request and checks HAIP 1.0 Section 4.5.1: a key
// attestation covering the proof key, asserting no key_storage or
// user_authentication level.
func keyAttestationWithoutLevels(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, err := preAuthorizedHAIPImport(ctx, env)
	if err != nil {
		return "", err
	}
	event := lookingGlassEvent(result, stepProofBuilt)
	if event == nil {
		return "", fmt.Errorf("the wallet recorded no %q event, so the proof it sent cannot be read", stepProofBuilt)
	}
	proof, _ := event["proof"].(map[string]any)
	compact, _ := proof["raw"].(string)
	proofHeader, _, err := capture.JWTParts(compact)
	if err != nil {
		return "", fmt.Errorf("proof JWT: %w", err)
	}
	keyAttestation, _ := proofHeader["key_attestation"].(string)
	if keyAttestation == "" {
		return "", fmt.Errorf("the proof carries no key_attestation header")
	}
	header, claims, err := capture.JWTParts(keyAttestation)
	if err != nil {
		return "", fmt.Errorf("key attestation: %w", err)
	}
	if header["typ"] != typKeyAttestation {
		return "", fmt.Errorf("key attestation typ is %v, want %s", header["typ"], typKeyAttestation)
	}
	attestedKeys, _ := claims["attested_keys"].([]any)
	if len(attestedKeys) == 0 {
		return "", fmt.Errorf("key attestation has no attested_keys")
	}
	proofKey, _ := proofHeader["jwk"].(map[string]any)
	if !attestsKey(attestedKeys, proofKey) {
		return "", fmt.Errorf("key attestation attested_keys do not include the proof jwk")
	}
	for _, claim := range []string{"key_storage", "user_authentication"} {
		if _, present := claims[claim]; present {
			return "", fmt.Errorf("key attestation claims %s %v, which the hosted wallet's software keys cannot back", claim, claims[claim])
		}
	}
	return conformance.OutcomeAccepted, nil
}

// attestsKey reports whether one attested EC key has the proof key's
// curve point.
func attestsKey(attestedKeys []any, key map[string]any) bool {
	if key == nil {
		return false
	}
	for _, raw := range attestedKeys {
		attested, _ := raw.(map[string]any)
		if attested["kty"] == key["kty"] && attested["crv"] == key["crv"] && attested["x"] == key["x"] && attested["y"] == key["y"] {
			return true
		}
	}
	return false
}

// counterpartyDemandsLevels imports the counterparty's cw-h014 offer, whose
// configuration demands iso_18045_high key_storage and user_authentication.
func counterpartyDemandsLevels(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	link, err := counterpartyOfferLink(env, "cw-h014")
	if err != nil {
		return "", err
	}
	result, err := importCredential(ctx, env, map[string]any{"offer": link})
	if err != nil {
		return "", err
	}
	if result.Hop(stepToken) != nil {
		return "", fmt.Errorf("the wallet sent a Token Request for a configuration demanding levels it cannot back")
	}
	return refused(result, "iso_18045_high", "can back no Appendix D.2 level")
}
