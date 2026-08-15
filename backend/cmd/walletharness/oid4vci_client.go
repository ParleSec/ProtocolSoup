package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

type credentialResponseEncryptionSupport struct {
	AlgValuesSupported []string
	EncValuesSupported []string
	EncryptionRequired bool
}

// credentialRequestEncryptionSupport is Credential Issuer Metadata
// credential_request_encryption (OID4VCI 1.0 §12.2.4 / §8.2 / §10).
type credentialRequestEncryptionSupport struct {
	EncValuesSupported []string
	EncryptionRequired bool
	Keys               []intcrypto.JWK
}

type credentialRequestBuildInput struct {
	CredentialConfigurationID string
	CredentialIdentifiers     []string
	ProofJWT                  string
	ProofJWTs                 []string
	Encryption                *credentialResponseEncryptionSupport
	RequestEncryption         *credentialRequestEncryptionSupport
	RequireEncryption         bool
}

type credentialRequestBuildResult struct {
	Body                map[string]interface{}
	ResponsePrivateKey  *ecdsa.PrivateKey
	EncryptionRequested bool
}

// walletBatchCredentialProofCount is how many distinct proof keys the wallet
// requests when the issuer advertises batch_credential_issuance. Cap by
// batch_size. Two satisfies OID4VCI 1.0 §11.2.3 (batch_size MUST be >= 2)
// without minting the full advertised batch.
const walletBatchCredentialProofCount = 2

func batchCredentialProofCount(batchSize int, batchAdvertised bool, _ string) int {
	if !batchAdvertised {
		return 1
	}
	// OID4VCI 1.0 §11.2.3: when batch_credential_issuance is present, batch_size
	// MUST be >= 2. If metadata omits or understates the integer, still request
	// a multi-proof batch. Distinct keys are required for SD-JWT unlinkability
	// and recommended for mdoc.
	if batchSize < 2 {
		return walletBatchCredentialProofCount
	}
	if batchSize < walletBatchCredentialProofCount {
		return batchSize
	}
	return walletBatchCredentialProofCount
}

func proofJWTsFromBuildInput(input credentialRequestBuildInput) []string {
	proofs := make([]string, 0, len(input.ProofJWTs)+1)
	for _, proof := range input.ProofJWTs {
		if trimmed := strings.TrimSpace(proof); trimmed != "" {
			proofs = append(proofs, trimmed)
		}
	}
	if len(proofs) == 0 {
		if trimmed := strings.TrimSpace(input.ProofJWT); trimmed != "" {
			proofs = append(proofs, trimmed)
		}
	}
	return proofs
}

type dpopAuthenticatedRequestInput struct {
	Method                string
	URL                   string
	BodyBytes             []byte
	ContentType           string
	Accept                string
	AccessToken           string
	TokenType             string
	Session               *haipIssuanceSession
	LookingGlassSessionID string
	AttestationJWT        string
	PoPJWT                string
	PopAudience           string
	ChallengeEndpoint     string
	IncludeDPoP           bool
	Ath                   bool
	ExtraHeaders          map[string]string
}

func parseCredentialResponseEncryptionSupport(raw interface{}) credentialResponseEncryptionSupport {
	support := credentialResponseEncryptionSupport{}
	typed, ok := raw.(map[string]interface{})
	if !ok || typed == nil {
		return support
	}
	support.AlgValuesSupported = stringSliceFromValue(typed["alg_values_supported"])
	support.EncValuesSupported = stringSliceFromValue(typed["enc_values_supported"])
	if required, ok := typed["encryption_required"].(bool); ok {
		support.EncryptionRequired = required
	}
	return support
}

func parseCredentialRequestEncryptionSupport(raw interface{}) credentialRequestEncryptionSupport {
	support := credentialRequestEncryptionSupport{}
	typed, ok := raw.(map[string]interface{})
	if !ok || typed == nil {
		return support
	}
	support.EncValuesSupported = stringSliceFromValue(typed["enc_values_supported"])
	if required, ok := typed["encryption_required"].(bool); ok {
		support.EncryptionRequired = required
	}
	support.Keys = parseCredentialRequestEncryptionJWKs(typed["jwks"])
	return support
}

func parseCredentialRequestEncryptionJWKs(raw interface{}) []intcrypto.JWK {
	switch typed := raw.(type) {
	case map[string]interface{}:
		keysRaw, ok := typed["keys"].([]interface{})
		if !ok {
			return nil
		}
		return decodeJWKList(keysRaw)
	case []interface{}:
		return decodeJWKList(typed)
	default:
		return nil
	}
}

func decodeJWKList(keysRaw []interface{}) []intcrypto.JWK {
	keys := make([]intcrypto.JWK, 0, len(keysRaw))
	for _, entry := range keysRaw {
		raw, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		var jwk intcrypto.JWK
		if err := json.Unmarshal(raw, &jwk); err != nil {
			continue
		}
		if strings.TrimSpace(jwk.Kty) == "" {
			continue
		}
		keys = append(keys, jwk)
	}
	return keys
}

func (s credentialRequestEncryptionSupport) advertised() bool {
	return len(s.Keys) > 0
}

func parseBatchCredentialIssuance(raw interface{}) (batchSize int, advertised bool) {
	typed, ok := raw.(map[string]interface{})
	if !ok || typed == nil {
		return 0, false
	}
	switch value := typed["batch_size"].(type) {
	case float64:
		return int(value), true
	case float32:
		return int(value), true
	case int:
		return value, true
	case int64:
		return int(value), true
	case json.Number:
		parsed, err := value.Int64()
		if err != nil {
			return 0, true
		}
		return int(parsed), true
	case string:
		parsed, err := parsePositiveInt(strings.TrimSpace(value))
		if err != nil {
			return 0, true
		}
		return parsed, true
	default:
		return 0, true
	}
}

func configurationRequiresKeyAttestation(configuration map[string]interface{}) bool {
	if configuration == nil {
		return false
	}
	proofTypes, _ := configuration["proof_types_supported"].(map[string]interface{})
	jwtProof, _ := proofTypes["jwt"].(map[string]interface{})
	if jwtProof == nil {
		return false
	}
	_, present := jwtProof["key_attestations_required"]
	return present
}

func (s *walletHarnessServer) shouldUseHAIPIssuancePath(
	configurationID string,
	configuration map[string]interface{},
	asMetadata *resolvedAuthorizationServerMetadata,
) bool {
	if configurationRequiresKeyAttestation(configuration) {
		return true
	}
	if asMetadata != nil {
		attestedAuth := containsStringFold(asMetadata.TokenEndpointAuthMethodsSupported, "attest_jwt_client_auth")
		dpopAdvertised := len(asMetadata.DPoPSigningAlgValuesSupported) > 0
		// HAIP / external AS metadata advertises attest_jwt_client_auth
		// without a "*HAIP*" configuration ID. When the AS expects that
		// method and requires PAR or advertises DPoP, use the attested
		// issuance path for any configuration.
		if attestedAuth && (asMetadata.RequirePushedAuthorizationRequests || dpopAdvertised) {
			return true
		}
	}
	// Temporary bootstrap hint until all HAIP configs advertise key_attestations_required.
	return isHAIPCredentialConfigurationID(configurationID)
}

func (s *walletHarnessServer) shouldUsePAR(
	asMetadata *resolvedAuthorizationServerMetadata,
	configurationID string,
	configuration map[string]interface{},
) bool {
	if asMetadata == nil {
		return false
	}
	if asMetadata.RequirePushedAuthorizationRequests {
		return true
	}
	if strings.TrimSpace(asMetadata.PushedAuthorizationRequestEndpoint) == "" {
		return false
	}
	return s.haipIssuanceEnabled() && s.shouldUseHAIPIssuancePath(configurationID, configuration, asMetadata)
}

func clientAttestationIssuer() string {
	if value := strings.TrimSpace(os.Getenv("WALLET_CLIENT_ATTESTATION_ISSUER")); value != "" {
		return value
	}
	return "https://wallet.protocolsoup.com/attester"
}

func keyAttestationClaimsFromEnv() (keyStorage []string, userAuthentication []string) {
	if raw := strings.TrimSpace(os.Getenv("WALLET_KEY_ATTESTATION_KEY_STORAGE")); raw != "" {
		keyStorage = splitCommaSeparated(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("WALLET_KEY_ATTESTATION_USER_AUTHENTICATION")); raw != "" {
		userAuthentication = splitCommaSeparated(raw)
	}
	return keyStorage, userAuthentication
}

func splitCommaSeparated(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}

func authorizationServerIssuer(asMetadata *resolvedAuthorizationServerMetadata, fallback string) string {
	if asMetadata != nil {
		if issuer := strings.TrimSpace(asMetadata.Issuer); issuer != "" {
			return issuer
		}
	}
	return strings.TrimSpace(fallback)
}

func popAudienceForAS(asMetadata *resolvedAuthorizationServerMetadata, fallback string) string {
	// Issuer Client Attestation PoP aud MUST equal the AS issuer identifier
	// (client_attestation.go / draft-09 §7.2).
	return authorizationServerIssuer(asMetadata, fallback)
}

func generatePKCES256Challenge(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func buildPKCES256Pair(supportedMethods []string, requireS256 bool) (verifier string, challenge string, method string, err error) {
	verifier, challenge = mockidp.GeneratePKCE()
	if len(supportedMethods) == 0 || containsStringFold(supportedMethods, "S256") {
		return verifier, challenge, "S256", nil
	}
	if requireS256 {
		return "", "", "", fmt.Errorf("authorization server does not advertise PKCE S256 and PAR/HAIP requires it")
	}
	if containsStringFold(supportedMethods, "plain") {
		return verifier, verifier, "plain", nil
	}
	return "", "", "", fmt.Errorf("authorization server does not advertise a supported PKCE code_challenge_method")
}

func validateCredentialRequestSelectorExclusivity(configurationID string, credentialIdentifier string) error {
	if strings.TrimSpace(configurationID) != "" && strings.TrimSpace(credentialIdentifier) != "" {
		return fmt.Errorf("credential_identifier and credential_configuration_id are mutually exclusive")
	}
	if strings.TrimSpace(configurationID) == "" && strings.TrimSpace(credentialIdentifier) == "" {
		return fmt.Errorf("credential_configuration_id or credential_identifier is required")
	}
	return nil
}

func credentialIdentifiersFromTokenResponse(tokenPayload map[string]interface{}) []string {
	if tokenPayload == nil {
		return nil
	}
	rawDetails, ok := tokenPayload["authorization_details"].([]interface{})
	if !ok || len(rawDetails) == 0 {
		return nil
	}
	identifiers := make([]string, 0)
	for _, rawDetail := range rawDetails {
		detail, ok := rawDetail.(map[string]interface{})
		if !ok {
			continue
		}
		identifiers = append(identifiers, stringSliceFromValue(detail["credential_identifiers"])...)
	}
	return dedupeStringList(identifiers)
}

func buildCredentialRequestBody(input credentialRequestBuildInput) (*credentialRequestBuildResult, error) {
	body := map[string]interface{}{}
	identifiers := dedupeStringList(input.CredentialIdentifiers)
	configurationID := strings.TrimSpace(input.CredentialConfigurationID)
	// CW-044/070: when the token response returned credential_identifiers,
	// request with credential_identifier and omit credential_configuration_id.
	if len(identifiers) > 0 {
		body["credential_identifier"] = identifiers[0]
	} else if configurationID != "" {
		body["credential_configuration_id"] = configurationID
	} else {
		return nil, fmt.Errorf("credential_configuration_id or credential_identifier is required")
	}
	if proofs := proofJWTsFromBuildInput(input); len(proofs) > 0 {
		body["proofs"] = map[string]interface{}{
			"jwt": proofs,
		}
	}

	result := &credentialRequestBuildResult{Body: body}
	encryption := input.Encryption
	wantEncryption := input.RequireEncryption
	if encryption != nil && encryption.EncryptionRequired {
		wantEncryption = true
	}
	if wantEncryption {
		encObject, privateKey, encErr := buildCredentialResponseEncryptionObject(encryption, true)
		if encErr != nil {
			return nil, encErr
		}
		body["credential_response_encryption"] = encObject
		result.ResponsePrivateKey = privateKey
		result.EncryptionRequested = true
	}
	return result, nil
}

func buildCredentialResponseEncryptionObject(
	encryption *credentialResponseEncryptionSupport,
	required bool,
) (map[string]interface{}, *ecdsa.PrivateKey, error) {
	if !required && (encryption == nil || (!encryption.EncryptionRequired && len(encryption.AlgValuesSupported) == 0)) {
		return nil, nil, nil
	}
	if encryption == nil || len(encryption.AlgValuesSupported) == 0 || len(encryption.EncValuesSupported) == 0 {
		return nil, nil, fmt.Errorf("credential response encryption is required but issuer metadata does not advertise supported alg/enc values")
	}
	if !containsStringFold(encryption.AlgValuesSupported, "ECDH-ES") {
		return nil, nil, fmt.Errorf("issuer does not advertise ECDH-ES for credential_response_encryption")
	}
	enc := "A256GCM"
	if !containsStringFold(encryption.EncValuesSupported, enc) {
		if containsStringFold(encryption.EncValuesSupported, "A128GCM") {
			enc = "A128GCM"
		} else {
			return nil, nil, fmt.Errorf("issuer does not advertise A256GCM or A128GCM for credential_response_encryption")
		}
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate credential response encryption key: %w", err)
	}
	jwk := intcrypto.JWKFromECPublicKey(&privateKey.PublicKey, "wallet-cred-response-enc")
	jwk.Alg = "ECDH-ES"
	jwk.Use = "enc"
	return map[string]interface{}{
		"jwk": jwk,
		"enc": enc,
	}, privateKey, nil
}

func decryptCredentialResponseJWT(compact string, privateKey *ecdsa.PrivateKey) (map[string]interface{}, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("credential response encryption private key is required")
	}
	normalized := strings.TrimSpace(compact)
	if normalized == "" {
		return nil, fmt.Errorf("encrypted credential response is empty")
	}
	object, err := jose.ParseEncrypted(
		normalized,
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A128GCM, jose.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("parse encrypted credential response: %w", err)
	}
	plaintext, err := object.Decrypt(privateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt credential response: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("decode decrypted credential response: %w", err)
	}
	return payload, nil
}

// shouldEncryptCredentialRequest reports whether the Credential / Deferred
// Credential Request body must be sent as an application/jwt JWE. OID4VCI 1.0
// §8.2: encrypt when encryption_required, and MUST encrypt when the request
// includes credential_response_encryption. When the issuer advertises request
// encryption keys, the wallet also encrypts even if encryption_required is
// false (OID4VCI 1.0 §8.2).
func shouldEncryptCredentialRequest(requestEnc *credentialRequestEncryptionSupport, responseEncryptionRequested bool) bool {
	if requestEnc == nil || !requestEnc.advertised() {
		return false
	}
	return requestEnc.EncryptionRequired || responseEncryptionRequested || requestEnc.advertised()
}

func encryptCredentialRequestBody(plaintext []byte, support *credentialRequestEncryptionSupport) (string, error) {
	if support == nil || !support.advertised() {
		return "", fmt.Errorf("credential request encryption jwks are unavailable")
	}
	jwk, enc, err := selectCredentialRequestEncryptionKey(support)
	if err != nil {
		return "", err
	}
	pub, err := intcrypto.ParseECPublicKeyFromJWK(jwk)
	if err != nil {
		return "", fmt.Errorf("parse credential request encryption jwk: %w", err)
	}
	opts := &jose.EncrypterOptions{}
	if kid := strings.TrimSpace(jwk.Kid); kid != "" {
		opts.WithHeader("kid", kid)
	}
	encrypter, err := jose.NewEncrypter(
		enc,
		jose.Recipient{
			Algorithm: jose.ECDH_ES,
			Key:       pub,
			KeyID:     strings.TrimSpace(jwk.Kid),
		},
		opts,
	)
	if err != nil {
		return "", fmt.Errorf("create credential request encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt credential request: %w", err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serialize encrypted credential request: %w", err)
	}
	return compact, nil
}

func selectCredentialRequestEncryptionKey(support *credentialRequestEncryptionSupport) (intcrypto.JWK, jose.ContentEncryption, error) {
	enc := jose.A256GCM
	if support != nil && len(support.EncValuesSupported) > 0 {
		if containsStringFold(support.EncValuesSupported, string(jose.A256GCM)) {
			enc = jose.A256GCM
		} else if containsStringFold(support.EncValuesSupported, string(jose.A128GCM)) {
			enc = jose.A128GCM
		} else {
			return intcrypto.JWK{}, "", fmt.Errorf("issuer does not advertise A256GCM or A128GCM for credential_request_encryption")
		}
	}
	for _, key := range support.Keys {
		if !strings.EqualFold(strings.TrimSpace(key.Kty), "EC") {
			continue
		}
		if crv := strings.TrimSpace(key.Crv); crv != "" && !strings.EqualFold(crv, "P-256") {
			continue
		}
		if use := strings.TrimSpace(key.Use); use != "" && !strings.EqualFold(use, "enc") {
			continue
		}
		if alg := strings.TrimSpace(key.Alg); alg != "" && !strings.EqualFold(alg, string(jose.ECDH_ES)) {
			continue
		}
		return key, enc, nil
	}
	return intcrypto.JWK{}, "", fmt.Errorf("no suitable ECDH-ES P-256 encryption key in credential_request_encryption.jwks")
}

func validateAuthorizationResponseIss(expectedIss string, responseIss string, requireIss bool) error {
	normalizedExpected := strings.TrimSpace(expectedIss)
	normalizedResponse := strings.TrimSpace(responseIss)
	if !requireIss && normalizedResponse == "" {
		return nil
	}
	if normalizedExpected == "" {
		return fmt.Errorf("authorization server issuer is unavailable for RFC 9207 iss validation")
	}
	if normalizedResponse == "" {
		return fmt.Errorf("authorization response missing iss (RFC 9207)")
	}
	if !sameURLIdentifier(normalizedExpected, normalizedResponse) {
		return fmt.Errorf("authorization response iss %q does not match authorization server issuer %q", normalizedResponse, normalizedExpected)
	}
	return nil
}

func consumePendingOID4VCIAuthState(
	states map[string]*pendingOID4VCIAuthState,
	state string,
	now time.Time,
) (*pendingOID4VCIAuthState, error) {
	normalizedState := strings.TrimSpace(state)
	if normalizedState == "" {
		return nil, fmt.Errorf("authorization state is missing or expired")
	}
	pending := states[normalizedState]
	delete(states, normalizedState)
	if pending == nil || now.After(pending.ExpiresAt) {
		return nil, fmt.Errorf("authorization state is missing or expired")
	}
	return pending, nil
}

func validateExactRedirectURI(expected string, actual string) error {
	if strings.TrimSpace(expected) == "" {
		return fmt.Errorf("expected redirect_uri is required")
	}
	if strings.TrimSpace(actual) != "" && strings.TrimSpace(expected) != strings.TrimSpace(actual) {
		return fmt.Errorf("redirect_uri mismatch")
	}
	return nil
}

func scopeFromCredentialConfiguration(configuration map[string]interface{}, asMetadata *resolvedAuthorizationServerMetadata) string {
	if scope := strings.TrimSpace(asString(configuration["scope"])); scope != "" {
		return scope
	}
	if asMetadata != nil {
		scopesSupported := stringSliceFromValue(asMetadata.Raw["scopes_supported"])
		if containsStringFold(scopesSupported, "openid") {
			return "openid"
		}
	}
	return ""
}

func buildAuthorizationURLFromPAR(
	authorizationEndpoint string,
	clientID string,
	requestURI string,
) (string, error) {
	authorizationURL, err := url.Parse(strings.TrimSpace(authorizationEndpoint))
	if err != nil {
		return "", fmt.Errorf("parse authorization endpoint: %w", err)
	}
	// FAPI2 SP Final §5.3.3.2 / PAR-4: when using PAR, the authorization
	// endpoint request MUST contain only client_id and request_uri.
	query := authorizationURL.Query()
	query.Set("client_id", strings.TrimSpace(clientID))
	query.Set("request_uri", strings.TrimSpace(requestURI))
	authorizationURL.RawQuery = query.Encode()
	return authorizationURL.String(), nil
}

type pushAuthorizationRequestInput struct {
	PAREndpoint           string
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	State                 string
	CodeChallenge         string
	Scope                 string
	IssuerState           string
	ConfigurationID       string
	LookingGlassSessionID string
	Session               *haipIssuanceSession
	PopAudience           string
	ChallengeEndpoint     string
}

func (s *walletHarnessServer) pushAuthorizationRequest(
	ctx context.Context,
	input pushAuthorizationRequestInput,
) (requestURI string, err error) {
	if !s.haipIssuanceEnabled() {
		return "", fmt.Errorf("haip attestation material is not configured for PAR")
	}
	if input.Session == nil {
		return "", fmt.Errorf("haip issuance session is required for PAR")
	}
	parEndpoint := strings.TrimSpace(input.PAREndpoint)
	if parEndpoint == "" {
		return "", fmt.Errorf("pushed_authorization_request_endpoint is required")
	}
	validatedEndpoint, err := s.validateExternalURL(parEndpoint)
	if err != nil {
		return "", fmt.Errorf("validate PAR endpoint: %w", err)
	}
	parEndpoint = validatedEndpoint

	attestationJWT, popJWT, err := s.buildClientAttestationHeaderPair(
		ctx,
		input.Session,
		input.PopAudience,
		input.ChallengeEndpoint,
		input.LookingGlassSessionID,
	)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("response_type", "code")
	form.Set("client_id", strings.TrimSpace(input.ClientID))
	form.Set("redirect_uri", strings.TrimSpace(input.RedirectURI))
	form.Set("state", strings.TrimSpace(input.State))
	form.Set("code_challenge", strings.TrimSpace(input.CodeChallenge))
	form.Set("code_challenge_method", "S256")
	form.Set("nonce", randomValue(16))
	if scope := strings.TrimSpace(input.Scope); scope != "" {
		form.Set("scope", scope)
	}
	if issuerState := strings.TrimSpace(input.IssuerState); issuerState != "" {
		form.Set("issuer_state", issuerState)
	}
	if configurationID := strings.TrimSpace(input.ConfigurationID); configurationID != "" {
		authorizationDetails := []map[string]interface{}{
			{
				"type":                        "openid_credential",
				"credential_configuration_id": configurationID,
			},
		}
		if rawAuthorizationDetails, marshalErr := json.Marshal(authorizationDetails); marshalErr == nil {
			form.Set("authorization_details", string(rawAuthorizationDetails))
		}
	}
	form.Set("dpop_jkt", input.Session.dpopPublicJWK.Thumbprint())

	payload, err := s.postHAIPFormWithDPoP(
		ctx,
		parEndpoint,
		form,
		input.Session,
		attestationJWT,
		popJWT,
		input.PopAudience,
		input.ChallengeEndpoint,
		input.LookingGlassSessionID,
		false,
	)
	if err != nil {
		return "", err
	}
	requestURI = strings.TrimSpace(asString(payload["request_uri"]))
	if requestURI == "" {
		return "", fmt.Errorf("PAR response missing request_uri")
	}
	return requestURI, nil
}

func (s *walletHarnessServer) buildClientAttestationHeaderPair(
	ctx context.Context,
	session *haipIssuanceSession,
	popAudience string,
	challengeEndpoint string,
	lookingGlassSessionID string,
) (attestationJWT string, popJWT string, err error) {
	if session == nil || session.clientInstanceKey == nil {
		return "", "", fmt.Errorf("haip issuance session is required")
	}
	attestationJWT, err = buildClientAttestationJWT(
		s.haipClientAttestation.PrivateKey,
		s.haipClientAttestation.X5C,
		s.haipAttestedClientID,
		intcrypto.JWKFromECPublicKey(&session.clientInstanceKey.PublicKey, "wallet-client-instance"),
		time.Now().UTC().Add(5*time.Minute),
	)
	if err != nil {
		return "", "", fmt.Errorf("build client attestation jwt: %w", err)
	}
	audience := strings.TrimSpace(popAudience)
	if audience == "" {
		audience = s.oid4vciIssuerAudience()
	}
	challenge, err := s.resolveAttestationChallenge(ctx, challengeEndpoint, lookingGlassSessionID, "")
	if err != nil {
		return "", "", err
	}
	popJWT, err = s.buildFreshClientAttestationPoP(session, audience, challenge)
	if err != nil {
		return "", "", err
	}
	return attestationJWT, popJWT, nil
}

// buildFreshClientAttestationPoP mints a new PoP JWT with a unique jti.
// OAuth2-ATCA requires a fresh PoP on every authenticated HTTP attempt,
// including DPoP-nonce retries.
func (s *walletHarnessServer) buildFreshClientAttestationPoP(
	session *haipIssuanceSession,
	popAudience string,
	challenge string,
) (string, error) {
	if session == nil || session.clientInstanceKey == nil {
		return "", fmt.Errorf("haip issuance session is required")
	}
	audience := strings.TrimSpace(popAudience)
	if audience == "" {
		audience = s.oid4vciIssuerAudience()
	}
	popJWT, err := buildClientAttestationPoPJWT(
		session.clientInstanceKey,
		s.haipAttestedClientID,
		audience,
		"wallet-attestation-pop-"+randomValue(12),
		time.Now().UTC(),
		challenge,
	)
	if err != nil {
		return "", fmt.Errorf("build client attestation pop jwt: %w", err)
	}
	return popJWT, nil
}

// resolveAttestationChallenge returns a preferred challenge when provided
// (for example from OAuth-Client-Attestation-Challenge). Otherwise, when the
// AS advertises challenge_endpoint, it MUST be fetched (OAuth2-ATCA §6.1).
func (s *walletHarnessServer) resolveAttestationChallenge(
	ctx context.Context,
	challengeEndpoint string,
	lookingGlassSessionID string,
	preferredChallenge string,
) (string, error) {
	if challenge := strings.TrimSpace(preferredChallenge); challenge != "" {
		return challenge, nil
	}
	endpoint := strings.TrimSpace(challengeEndpoint)
	if endpoint == "" {
		return "", nil
	}
	return s.fetchAttestationChallenge(ctx, endpoint, lookingGlassSessionID)
}

func (s *walletHarnessServer) fetchAttestationChallenge(
	ctx context.Context,
	challengeEndpoint string,
	lookingGlassSessionID string,
) (string, error) {
	validatedEndpoint, err := s.validateExternalURL(challengeEndpoint)
	if err != nil {
		return "", fmt.Errorf("validate challenge_endpoint: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, validatedEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("build challenge_endpoint request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}
	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return "", fmt.Errorf("challenge_endpoint request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("challenge_endpoint returned %d: %s", resp.StatusCode, oneLine(string(body)))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode challenge_endpoint response: %w", err)
	}
	challenge := firstNonEmpty(
		strings.TrimSpace(asString(payload["attestation_challenge"])),
		strings.TrimSpace(asString(payload["challenge"])),
	)
	if challenge == "" {
		return "", fmt.Errorf("challenge_endpoint response missing attestation_challenge")
	}
	return challenge, nil
}

func (s *walletHarnessServer) postHAIPFormWithDPoP(
	ctx context.Context,
	endpoint string,
	form url.Values,
	session *haipIssuanceSession,
	attestationJWT string,
	popJWT string,
	popAudience string,
	challengeEndpoint string,
	lookingGlassSessionID string,
	ath bool,
) (map[string]interface{}, error) {
	return s.doDPoPJSONRequest(ctx, dpopAuthenticatedRequestInput{
		Method:                http.MethodPost,
		URL:                   endpoint,
		BodyBytes:             []byte(form.Encode()),
		ContentType:           "application/x-www-form-urlencoded",
		Accept:                "application/json",
		Session:               session,
		LookingGlassSessionID: lookingGlassSessionID,
		AttestationJWT:        attestationJWT,
		PoPJWT:                popJWT,
		PopAudience:           popAudience,
		ChallengeEndpoint:     challengeEndpoint,
		IncludeDPoP:           true,
		Ath:                   ath,
	})
}

func (s *walletHarnessServer) doDPoPJSONRequest(
	ctx context.Context,
	input dpopAuthenticatedRequestInput,
) (map[string]interface{}, error) {
	payload, status, headers, body, err := s.doDPoPRequest(ctx, input, "")
	if err != nil {
		return nil, err
	}
	if isSuccessfulOID4VCIJSONStatus(status) {
		return payload, nil
	}
	if !isUseDPoPNonceChallenge(status, payload, headers, body) {
		return nil, fmt.Errorf("request to %s returned %d: %s", input.URL, status, oneLine(string(body)))
	}
	nonce := strings.TrimSpace(headers.Get(dpop.NonceHeaderName))
	if nonce == "" {
		return nil, fmt.Errorf("request returned use_dpop_nonce without %s header", dpop.NonceHeaderName)
	}
	// DPoP nonce retry is a new HTTP request. Client attestation PoP jti is
	// single-use (OAuth2-ATCA), so mint a fresh PoP while keeping the Client
	// Attestation JWT. Prefer a challenge from OAuth-Client-Attestation-Challenge;
	// otherwise re-fetch.
	if strings.TrimSpace(input.AttestationJWT) != "" && strings.TrimSpace(input.PoPJWT) != "" {
		challenge, challengeErr := s.resolveAttestationChallenge(
			ctx,
			input.ChallengeEndpoint,
			input.LookingGlassSessionID,
			headers.Get(headerOAuthClientAttestationChallenge),
		)
		if challengeErr != nil {
			return nil, fmt.Errorf("resolve attestation challenge for dpop nonce retry: %w", challengeErr)
		}
		freshPoP, refreshErr := s.buildFreshClientAttestationPoP(input.Session, input.PopAudience, challenge)
		if refreshErr != nil {
			return nil, fmt.Errorf("refresh client attestation pop for dpop nonce retry: %w", refreshErr)
		}
		input.PoPJWT = freshPoP
	}
	payload, status, _, body, err = s.doDPoPRequest(ctx, input, nonce)
	if err != nil {
		return nil, err
	}
	if !isSuccessfulOID4VCIJSONStatus(status) {
		return nil, fmt.Errorf("request retry to %s returned %d: %s", input.URL, status, oneLine(string(body)))
	}
	return payload, nil
}

// isSuccessfulOID4VCIJSONStatus accepts credential/token-style JSON success
// statuses: 200/201 for immediate responses and 202 Accepted for deferred
// issuance (OID4VCI 1.0 §7 / §9 transaction_id).
func isSuccessfulOID4VCIJSONStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted
}

// isUseDPoPNonceChallenge detects RFC 9449 nonce challenges from AS (HTTP 400
// JSON error) and RS (HTTP 401 + WWW-Authenticate / DPoP-Nonce) responses.
func isUseDPoPNonceChallenge(status int, payload map[string]interface{}, headers http.Header, body []byte) bool {
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		return false
	}
	if strings.TrimSpace(asString(payload["error"])) == dpop.ErrorUseDPoPNonce {
		return true
	}
	www := strings.ToLower(headers.Get("WWW-Authenticate"))
	if strings.Contains(www, dpop.ErrorUseDPoPNonce) {
		return true
	}
	if len(body) > 0 && strings.Contains(string(body), dpop.ErrorUseDPoPNonce) {
		return true
	}
	// RFC 9449 resource servers may send only DPoP-Nonce on HTTP 401.
	return strings.TrimSpace(headers.Get(dpop.NonceHeaderName)) != ""
}

func (s *walletHarnessServer) doDPoPRequest(
	ctx context.Context,
	input dpopAuthenticatedRequestInput,
	dpopNonce string,
) (map[string]interface{}, int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, input.Method, input.URL, strings.NewReader(string(input.BodyBytes)))
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("build request: %w", err)
	}
	if strings.TrimSpace(input.Accept) != "" {
		req.Header.Set("Accept", strings.TrimSpace(input.Accept))
	}
	if strings.TrimSpace(input.ContentType) != "" {
		req.Header.Set("Content-Type", strings.TrimSpace(input.ContentType))
	}
	if strings.TrimSpace(input.AttestationJWT) != "" {
		req.Header.Set(headerOAuthClientAttestation, input.AttestationJWT)
	}
	if strings.TrimSpace(input.PoPJWT) != "" {
		req.Header.Set(headerOAuthClientAttestationPoP, input.PoPJWT)
	}
	if strings.TrimSpace(input.AccessToken) != "" {
		req.Header.Set("Authorization", authorizationHeaderForAccessToken(input.TokenType, input.AccessToken))
	}
	if input.IncludeDPoP || isDPoPBoundTokenType(input.TokenType) {
		if input.Session == nil {
			return nil, 0, nil, nil, fmt.Errorf("dpop session is required")
		}
		extra := jwt.MapClaims{}
		if strings.TrimSpace(dpopNonce) != "" {
			extra["nonce"] = strings.TrimSpace(dpopNonce)
		}
		if input.Ath && strings.TrimSpace(input.AccessToken) != "" {
			extra["ath"] = computeAccessTokenHash(input.AccessToken)
		}
		dpopProof, err := input.Session.buildDPoPProof(req.Method, input.URL, extra)
		if err != nil {
			return nil, 0, nil, nil, err
		}
		req.Header.Set(dpop.HeaderName, dpopProof)
	}
	if strings.TrimSpace(input.LookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(input.LookingGlassSessionID))
	}
	for key, value := range input.ExtraHeaders {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		req.Header.Set(key, value)
	}

	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if strings.Contains(contentType, "application/jwt") {
		return map[string]interface{}{"__encrypted_jwt": strings.TrimSpace(string(body))}, resp.StatusCode, resp.Header, body, nil
	}

	var payload map[string]interface{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, resp.StatusCode, resp.Header, body, fmt.Errorf("decode response: %w", err)
		}
	}
	return payload, resp.StatusCode, resp.Header, body, nil
}

func (s *walletHarnessServer) requestCredentialWithLifecycle(
	ctx context.Context,
	credentialEndpoint string,
	input credentialRequestBuildInput,
	accessToken string,
	tokenType string,
	session *haipIssuanceSession,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	built, err := buildCredentialRequestBody(input)
	if err != nil {
		return nil, err
	}
	rawBody, err := json.Marshal(built.Body)
	if err != nil {
		return nil, fmt.Errorf("marshal credential request: %w", err)
	}
	contentType := "application/json"
	if shouldEncryptCredentialRequest(input.RequestEncryption, built.EncryptionRequested) {
		if input.RequestEncryption == nil || !input.RequestEncryption.advertised() {
			return nil, fmt.Errorf("credential response encryption requires credential request encryption (OID4VCI §8.2), but issuer metadata has no credential_request_encryption jwks")
		}
		compact, encErr := encryptCredentialRequestBody(rawBody, input.RequestEncryption)
		if encErr != nil {
			return nil, encErr
		}
		rawBody = []byte(compact)
		contentType = "application/jwt"
	} else if built.EncryptionRequested {
		return nil, fmt.Errorf("credential response encryption requires credential request encryption (OID4VCI §8.2), but issuer metadata has no credential_request_encryption jwks")
	}
	accept := "application/json"
	if built.EncryptionRequested {
		accept = "application/jwt, application/json"
	}
	// HAIP / RFC 9449: when a DPoP key session exists, always present a proof
	// at the credential endpoint (token_type may be DPoP, and RS nonce
	// challenges arrive as HTTP 401).
	includeDPoP := session != nil
	payload, err := s.doDPoPJSONRequest(ctx, dpopAuthenticatedRequestInput{
		Method:                http.MethodPost,
		URL:                   credentialEndpoint,
		BodyBytes:             rawBody,
		ContentType:           contentType,
		Accept:                accept,
		AccessToken:           accessToken,
		TokenType:             tokenType,
		Session:               session,
		LookingGlassSessionID: lookingGlassSessionID,
		IncludeDPoP:           includeDPoP,
		Ath:                   true,
	})
	if err != nil {
		return nil, fmt.Errorf("credential request: %w", err)
	}
	if encrypted := strings.TrimSpace(asString(payload["__encrypted_jwt"])); encrypted != "" {
		if built.ResponsePrivateKey == nil {
			return nil, fmt.Errorf("received encrypted credential response without a response decryption key")
		}
		return decryptCredentialResponseJWT(encrypted, built.ResponsePrivateKey)
	}
	return payload, nil
}

func (s *walletHarnessServer) pollDeferredCredentialAt(
	ctx context.Context,
	deferredURL string,
	accessToken string,
	tokenType string,
	transactionID string,
	lookingGlassSessionID string,
	haipSession *haipIssuanceSession,
	encryption *credentialResponseEncryptionSupport,
	requestEncryption *credentialRequestEncryptionSupport,
	requireEncryption bool,
) (map[string]interface{}, error) {
	validatedURL, err := s.validateExternalURL(deferredURL)
	if err != nil {
		return nil, fmt.Errorf("validate deferred credential endpoint: %w", err)
	}
	deferredURL = validatedURL

	for attempt := 0; attempt < deferredMaxRetries; attempt++ {
		backoff := deferredDefaultBackoff
		requestBody := map[string]interface{}{
			"transaction_id": transactionID,
		}
		var responseKey *ecdsa.PrivateKey
		responseEncryptionRequested := requireEncryption || (encryption != nil && encryption.EncryptionRequired)
		if responseEncryptionRequested {
			encParams, encKey, encErr := buildCredentialResponseEncryptionObject(encryption, true)
			if encErr != nil {
				return nil, encErr
			}
			if encParams != nil {
				requestBody["credential_response_encryption"] = encParams
				responseKey = encKey
			}
		}
		rawBody, _ := json.Marshal(requestBody)
		contentType := "application/json"
		if shouldEncryptCredentialRequest(requestEncryption, responseKey != nil) {
			if requestEncryption == nil || !requestEncryption.advertised() {
				return nil, fmt.Errorf("deferred credential response encryption requires credential request encryption (OID4VCI §8.2 / §9), but issuer metadata has no credential_request_encryption jwks")
			}
			compact, encErr := encryptCredentialRequestBody(rawBody, requestEncryption)
			if encErr != nil {
				return nil, encErr
			}
			rawBody = []byte(compact)
			contentType = "application/jwt"
		} else if responseKey != nil {
			return nil, fmt.Errorf("deferred credential response encryption requires credential request encryption (OID4VCI §8.2 / §9), but issuer metadata has no credential_request_encryption jwks")
		}
		accept := "application/json"
		if responseKey != nil {
			accept = "application/jwt, application/json"
		}
		// Use the same DPoP nonce-retry path as the credential endpoint:
		// deferred_credential may independently return HTTP 401 use_dpop_nonce.
		payload, reqErr := s.doDPoPJSONRequest(ctx, dpopAuthenticatedRequestInput{
			Method:                http.MethodPost,
			URL:                   deferredURL,
			BodyBytes:             rawBody,
			ContentType:           contentType,
			Accept:                accept,
			AccessToken:           accessToken,
			TokenType:             tokenType,
			Session:               haipSession,
			LookingGlassSessionID: lookingGlassSessionID,
			IncludeDPoP:           haipSession != nil || isDPoPBoundTokenType(tokenType),
			Ath:                   true,
		})
		if reqErr != nil {
			return nil, fmt.Errorf("deferred credential request: %w", reqErr)
		}
		if encrypted := strings.TrimSpace(asString(payload["__encrypted_jwt"])); encrypted != "" {
			if responseKey == nil {
				return nil, fmt.Errorf("received encrypted deferred response without a response decryption key")
			}
			return decryptCredentialResponseJWT(encrypted, responseKey)
		}
		if _, credErr := credentialResponseValues(payload); credErr == nil {
			return payload, nil
		}
		if seconds := positiveIntFromAny(payload["interval"]); seconds > 0 {
			backoff = time.Duration(seconds) * time.Second
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
			continue
		}
	}
	return nil, fmt.Errorf("deferred credential not ready after %d retries", deferredMaxRetries)
}

// exchangeRefreshToken redeems a refresh_token grant (RFC 6749 §6 / OID4VCI
// §14.5) at the Authorization Server token endpoint, preserving DPoP and
// client attestation when the original issuance used them.
func (s *walletHarnessServer) exchangeRefreshToken(
	ctx context.Context,
	tokenEndpoint string,
	refreshToken string,
	session *haipIssuanceSession,
	popAudience string,
	lookingGlassSessionID string,
) (map[string]interface{}, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	tokenEndpoint = strings.TrimSpace(tokenEndpoint)
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh_token is required")
	}
	if tokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint is required")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	if session != nil && s.haipIssuanceEnabled() {
		attestationJWT, popJWT, err := s.buildClientAttestationHeaderPair(ctx, session, popAudience, "", lookingGlassSessionID)
		if err != nil {
			return nil, err
		}
		if clientID := strings.TrimSpace(s.haipAttestedClientID); clientID != "" {
			form.Set("client_id", clientID)
		}
		return s.postHAIPFormWithDPoP(ctx, tokenEndpoint, form, session, attestationJWT, popJWT, popAudience, "", lookingGlassSessionID, false)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build refresh token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if strings.TrimSpace(lookingGlassSessionID) != "" {
		req.Header.Set("X-Looking-Glass-Session", strings.TrimSpace(lookingGlassSessionID))
	}
	resp, err := s.doHTTP(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("refresh token request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh token request returned %d: %s", resp.StatusCode, oneLine(string(body)))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode refresh token response: %w", err)
	}
	if strings.TrimSpace(asString(payload["access_token"])) == "" {
		return nil, fmt.Errorf("refresh token response missing access_token")
	}
	return payload, nil
}

func parsePositiveInt(raw string) (int, error) {
	var value int
	_, err := fmt.Sscanf(strings.TrimSpace(raw), "%d", &value)
	if err != nil {
		return 0, err
	}
	if value <= 0 {
		return 0, fmt.Errorf("non-positive")
	}
	return value, nil
}

// positiveIntFromAny coerces JSON-decoded numbers (float64) or numeric strings
// into a positive int. Used for OID4VCI deferred `interval` values.
func positiveIntFromAny(raw interface{}) int {
	switch v := raw.(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case json.Number:
		n, err := v.Int64()
		if err == nil && n > 0 {
			return int(n)
		}
	case int:
		if v > 0 {
			return v
		}
	case string:
		if n, err := parsePositiveInt(v); err == nil {
			return n
		}
	}
	return 0
}

func waitDeferredInterval(ctx context.Context, payload map[string]interface{}) error {
	seconds := positiveIntFromAny(payload["interval"])
	if seconds <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Duration(seconds) * time.Second):
		return nil
	}
}
