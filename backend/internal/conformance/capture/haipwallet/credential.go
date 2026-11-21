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

// counterpartyPlaintextResponse imports the counterparty's cw-072-plaintext
// offer, whose Credential Endpoint answers the wallet's encrypted Credential
// Request, which asked for an encrypted response, in plaintext
// application/json. OpenID4VCI 1.0 Section 10: "When encryption of a message
// was required but the received message is unencrypted, it SHOULD be
// rejected."
func counterpartyPlaintextResponse(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	link, err := counterpartyOfferLink(env, "cw-072-plaintext")
	if err != nil {
		return "", err
	}
	result, err := importCredential(ctx, env, map[string]any{"offer": link})
	if err != nil {
		return "", err
	}
	credential, err := completedHop(result, stepCredential)
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, walletError(result))
	}
	if !strings.HasPrefix(strings.ToLower(hopHeader(credential.RequestHeaders, "Content-Type")), "application/jwt") {
		return "", fmt.Errorf("the wallet sent its Credential Request as %q, not an encrypted application/jwt", hopHeader(credential.RequestHeaders, "Content-Type"))
	}
	if !strings.HasPrefix(strings.ToLower(hopHeader(credential.ResponseHeaders, "Content-Type")), "application/json") {
		return "", fmt.Errorf("the counterparty answered with %q rather than plaintext application/json", hopHeader(credential.ResponseHeaders, "Content-Type"))
	}
	return refused(result, "unencrypted application/json")
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

// counterpartyChallengeWithoutNonce imports the counterparty's cw-h004 offer,
// whose Token Endpoint answers the wallet's DPoP-bound Token Request with
// use_dpop_nonce and no DPoP-Nonce header. The wallet must send exactly one
// Token Request, carrying a DPoP proof, and stop: a repeat could carry no
// nonce the server supplied (RFC 9449 Section 8).
func counterpartyChallengeWithoutNonce(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	link, err := counterpartyOfferLink(env, "cw-h004")
	if err != nil {
		return "", err
	}
	result, err := importCredential(ctx, env, map[string]any{"offer": link})
	if err != nil {
		return "", err
	}
	tokens := hopsOf(result, stepToken)
	if len(tokens) == 0 {
		return "", fmt.Errorf("the wallet sent no Token Request: %s", walletError(result))
	}
	if len(tokens) > 1 {
		return "", fmt.Errorf("the wallet sent %d Token Requests after a use_dpop_nonce challenge that supplied no DPoP-Nonce to retry with", len(tokens))
	}
	token := &tokens[0]
	if hopHeader(token.RequestHeaders, "DPoP") == "" {
		return "", fmt.Errorf("the Token Request carries no DPoP proof, so the counterparty issued no nonce challenge: %s", walletError(result))
	}
	if !isNonceChallenge(token) || hopHeader(token.ResponseHeaders, "DPoP-Nonce") != "" {
		return "", fmt.Errorf("the counterparty answered the Token Request with %d rather than use_dpop_nonce without a DPoP-Nonce header", token.ResponseStatus)
	}
	return refused(result, "use_dpop_nonce without DPoP-Nonce header")
}

// walletKeyAttestation is the key attestation the wallet sent with the proof
// of an encrypted Credential Request, read from the wallet's own Build
// Credential Proof JWT record, with the proof's header.
type walletKeyAttestation struct {
	Compact     string
	Header      map[string]any
	Claims      map[string]any
	ProofHeader map[string]any
}

// importedKeyAttestation runs a HAIP pre-authorized import and returns the
// key attestation its proof carried, checked to be a key-attestation+jwt
// whose attested_keys include the proof key.
func importedKeyAttestation(ctx context.Context, env *capture.Env) (*walletKeyAttestation, error) {
	result, err := preAuthorizedHAIPImport(ctx, env)
	if err != nil {
		return nil, err
	}
	event := lookingGlassEvent(result, stepProofBuilt)
	if event == nil {
		return nil, fmt.Errorf("the wallet recorded no %q event, so the proof it sent cannot be read", stepProofBuilt)
	}
	proof, _ := event["proof"].(map[string]any)
	compact, _ := proof["raw"].(string)
	proofHeader, _, err := capture.JWTParts(compact)
	if err != nil {
		return nil, fmt.Errorf("proof JWT: %w", err)
	}
	keyAttestation, _ := proofHeader["key_attestation"].(string)
	if keyAttestation == "" {
		return nil, fmt.Errorf("the proof carries no key_attestation header")
	}
	header, claims, err := capture.JWTParts(keyAttestation)
	if err != nil {
		return nil, fmt.Errorf("key attestation: %w", err)
	}
	if header["typ"] != typKeyAttestation {
		return nil, fmt.Errorf("key attestation typ is %v, want %s", header["typ"], typKeyAttestation)
	}
	attestedKeys, _ := claims["attested_keys"].([]any)
	if len(attestedKeys) == 0 {
		return nil, fmt.Errorf("key attestation has no attested_keys")
	}
	proofKey, _ := proofHeader["jwk"].(map[string]any)
	if !attestsKey(attestedKeys, proofKey) {
		return nil, fmt.Errorf("key attestation attested_keys do not include the proof jwk")
	}
	return &walletKeyAttestation{Compact: keyAttestation, Header: header, Claims: claims, ProofHeader: proofHeader}, nil
}

// keyAttestationChain checks HAIP 1.0 Section 4.5.1 on the wallet's key
// attestation: the wallet supports key attestations, and the attestation's
// x5c holds the key that verifies its signature, excludes the trust anchor
// and is not self-signed.
func keyAttestationChain(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	attestation, err := importedKeyAttestation(ctx, env)
	if err != nil {
		return "", err
	}
	if err := verifySignedUnderX5C("the key attestation", attestation.Header, attestation.Compact); err != nil {
		return "", err
	}
	return conformance.OutcomeAccepted, nil
}

// keyAttestationWithoutLevels checks OpenID4VCI 1.0 Appendix D.2 on the
// wallet's key attestation: each key_storage and user_authentication value is
// an assertion of ISO/IEC 18045 attack-potential resistance, and the hosted
// wallet's software keys can back none, so the attestation carries neither.
func keyAttestationWithoutLevels(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	attestation, err := importedKeyAttestation(ctx, env)
	if err != nil {
		return "", err
	}
	for _, claim := range []string{"key_storage", "user_authentication"} {
		if _, present := attestation.Claims[claim]; present {
			return "", fmt.Errorf("key attestation claims %s %v, which the hosted wallet's software keys cannot back", claim, attestation.Claims[claim])
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

// counterpartyDemandsLevels imports the counterparty's cw-101 offer, whose
// configuration demands iso_18045_high key_storage and user_authentication.
func counterpartyDemandsLevels(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	link, err := counterpartyOfferLink(env, "cw-101")
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
