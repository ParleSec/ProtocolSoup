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
	"net/url"
	"os"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/dpop"
	"github.com/golang-jwt/jwt/v5"
)

const (
	headerOAuthClientAttestation          = "OAuth-Client-Attestation"
	headerOAuthClientAttestationPoP       = "OAuth-Client-Attestation-PoP"
	headerOAuthClientAttestationChallenge = "OAuth-Client-Attestation-Challenge"

	typOAuthClientAttestationJWT    = "oauth-client-attestation+jwt"
	typOAuthClientAttestationPoPJWT = "oauth-client-attestation-pop+jwt"
	typKeyAttestationJWT            = "key-attestation+jwt"
)

type attestationJWKMaterial struct {
	PrivateKey *ecdsa.PrivateKey
	X5C        []string
}

type haipIssuanceSession struct {
	dpopPrivateKey    *ecdsa.PrivateKey
	dpopPublicJWK     intcrypto.JWK
	clientInstanceKey *ecdsa.PrivateKey
}

func loadHAIPAttestationConfig() (clientAttestation *attestationJWKMaterial, keyAttestation *attestationJWKMaterial, attestedClientID string, err error) {
	clientAttestation, err = loadAttestationJWKMaterialFromEnv("WALLET_CLIENT_ATTESTATION_ATTESTER_JWK_JSON")
	if err != nil {
		return nil, nil, "", fmt.Errorf("load client attestation attester jwk: %w", err)
	}
	keyAttestation, err = loadAttestationJWKMaterialFromEnv("WALLET_CLIENT_ATTESTATION_KEY_ATTESTATION_JWK_JSON")
	if err != nil {
		return nil, nil, "", fmt.Errorf("load key attestation attester jwk: %w", err)
	}
	if clientAttestation == nil || keyAttestation == nil {
		return clientAttestation, keyAttestation, "", nil
	}
	attestedClientID = strings.TrimSpace(os.Getenv("WALLET_OID4VCI_ATTESTED_CLIENT_ID"))
	if attestedClientID == "" {
		attestedClientID = "protocolsoup-wallet"
	}
	return clientAttestation, keyAttestation, attestedClientID, nil
}

func loadAttestationJWKMaterialFromEnv(envName string) (*attestationJWKMaterial, error) {
	raw := strings.TrimSpace(os.Getenv(envName))
	if raw == "" {
		return nil, nil
	}
	jwk, x5c, err := parseAttestationJWKInput(raw)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecPrivateKeyFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("parse %s private key: %w", envName, err)
	}
	if len(x5c) == 0 {
		return nil, fmt.Errorf("%s must include an x5c certificate chain", envName)
	}
	return &attestationJWKMaterial{
		PrivateKey: privateKey,
		X5C:        x5c,
	}, nil
}

func parseAttestationJWKInput(raw string) (intcrypto.JWK, []string, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return intcrypto.JWK{}, nil, fmt.Errorf("decode attestation jwk json: %w", err)
	}
	if keysRaw, ok := envelope["keys"]; ok {
		var rawKeys []json.RawMessage
		if err := json.Unmarshal(keysRaw, &rawKeys); err != nil {
			return intcrypto.JWK{}, nil, fmt.Errorf("decode attestation jwks keys: %w", err)
		}
		if len(rawKeys) == 0 {
			return intcrypto.JWK{}, nil, fmt.Errorf("attestation jwks is empty")
		}
		var jwk intcrypto.JWK
		if err := json.Unmarshal(rawKeys[0], &jwk); err != nil {
			return intcrypto.JWK{}, nil, fmt.Errorf("decode attestation jwk: %w", err)
		}
		var firstKeyMap map[string]json.RawMessage
		if err := json.Unmarshal(rawKeys[0], &firstKeyMap); err != nil {
			return intcrypto.JWK{}, nil, err
		}
		return jwk, extractX5CFromRawMap(firstKeyMap), nil
	}
	var jwk intcrypto.JWK
	if err := json.Unmarshal([]byte(raw), &jwk); err != nil {
		return intcrypto.JWK{}, nil, fmt.Errorf("decode attestation jwk: %w", err)
	}
	return jwk, extractX5CFromRawMap(envelope), nil
}

func extractX5CFromRawMap(raw map[string]json.RawMessage) []string {
	x5cRaw, ok := raw["x5c"]
	if !ok {
		return nil
	}
	var encoded []string
	if err := json.Unmarshal(x5cRaw, &encoded); err != nil {
		return nil
	}
	return encoded
}

func ecPrivateKeyFromJWK(jwk intcrypto.JWK) (*ecdsa.PrivateKey, error) {
	pub, err := intcrypto.ParseECPublicKeyFromJWK(jwk)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(jwk.D) == "" {
		return nil, fmt.Errorf("EC JWK is missing the private d parameter")
	}
	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("decode EC private d: %w", err)
	}
	if crv := strings.TrimSpace(jwk.Crv); crv != "" && !strings.EqualFold(crv, "P-256") {
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), dBytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private d: %w", err)
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, fmt.Errorf("EC private d does not match the JWK public coordinates")
	}
	return priv, nil
}

func (s *walletHarnessServer) haipIssuanceEnabled() bool {
	return s != nil && s.haipClientAttestation != nil && s.haipKeyAttestation != nil
}

func (s *walletHarnessServer) oid4vciIssuerAudience() string {
	return strings.TrimRight(strings.TrimSpace(s.issuerBaseURL), "/") + "/oid4vci"
}

func isHAIPCredentialConfigurationID(configurationID string) bool {
	normalized := strings.TrimSpace(configurationID)
	if normalized == "" {
		return false
	}
	if strings.Contains(normalized, "HAIP") {
		return true
	}
	switch normalized {
	case "UniversityDegreeCredentialSDJWTHAIP", "MobileDrivingLicenceMsoMdocHAIP":
		return true
	default:
		return false
	}
}

func preferHAIPBootstrapConfigurationID(configurationID string, haipEnabled bool) string {
	normalized := strings.TrimSpace(configurationID)
	if !haipEnabled {
		return normalized
	}
	switch normalized {
	case "", "UniversityDegreeCredential", "UniversityDegreeCredentialSDJWT":
		return "UniversityDegreeCredentialSDJWTHAIP"
	default:
		return normalized
	}
}

// educationalCredentialConfigurationID maps a HAIP key-attested issuance
// configuration to the same-format educational configuration. HAIP 1.0
// Sections 4.4.1 / 4.5.1 require wallet and key attestation for issuance;
// HAIP 1.0 Section 5 presentation (x509_hash, DCQL, encrypted response) does
// not. Presentation bootstrap therefore issues the educational credential of
// the matching format when attestation material is not configured.
func educationalCredentialConfigurationID(configurationID string) string {
	switch strings.TrimSpace(configurationID) {
	case "MobileDrivingLicenceMsoMdocHAIP":
		return "MobileDrivingLicenceMsoMdoc"
	case "UniversityDegreeCredentialSDJWTHAIP":
		return "UniversityDegreeCredential"
	default:
		return strings.TrimSpace(configurationID)
	}
}

// presentationIssuanceConfigurationID is the credential configuration used to
// auto-issue during OID4VP /submit. HAIP issuance IDs are rewritten to the
// educational equivalent unless this wallet actually has attestation material.
func (s *walletHarnessServer) presentationIssuanceConfigurationID(configurationID string) string {
	normalized := strings.TrimSpace(configurationID)
	if !isHAIPCredentialConfigurationID(normalized) || s.haipIssuanceEnabled() {
		return normalized
	}
	return educationalCredentialConfigurationID(normalized)
}

func (s *walletHarnessServer) newHAIPIssuanceSession() (*haipIssuanceSession, error) {
	dpopPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dpop key: %w", err)
	}
	clientInstanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate client instance key: %w", err)
	}
	return &haipIssuanceSession{
		dpopPrivateKey:    dpopPrivateKey,
		dpopPublicJWK:     intcrypto.JWKFromECPublicKey(&dpopPrivateKey.PublicKey, "wallet-dpop-key"),
		clientInstanceKey: clientInstanceKey,
	}, nil
}

func buildClientAttestationJWT(
	attesterKey *ecdsa.PrivateKey,
	x5c []string,
	clientID string,
	cnfJWK intcrypto.JWK,
	exp time.Time,
) (string, error) {
	if attesterKey == nil {
		return "", fmt.Errorf("attester private key is required")
	}
	claims := jwt.MapClaims{
		"iss": clientAttestationIssuer(),
		"sub": strings.TrimSpace(clientID),
		"exp": exp.Unix(),
		"cnf": map[string]interface{}{"jwk": cnfJWK},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = typOAuthClientAttestationJWT
	token.Header["x5c"] = append([]string(nil), x5c...)
	return token.SignedString(attesterKey)
}

func buildClientAttestationPoPJWT(instanceKey *ecdsa.PrivateKey, clientID string, audience string, jti string, iat time.Time, challenge string) (string, error) {
	if instanceKey == nil {
		return "", fmt.Errorf("client instance private key is required")
	}
	normalizedClientID := strings.TrimSpace(clientID)
	if normalizedClientID == "" {
		return "", fmt.Errorf("client_id is required for client attestation PoP iss")
	}
	// OAuth 2.0 Attestation-Based Client Authentication draft-07 §5.2
	// requires PoP iss = client_id. Later drafts remove iss; including it
	// remains compatible with receivers that ignore unknown claims
	// (including ProtocolSoup's draft-09+ issuer validator).
	claims := jwt.MapClaims{
		"iss": normalizedClientID,
		"aud": strings.TrimSpace(audience),
		"jti": strings.TrimSpace(jti),
		"iat": iat.Unix(),
	}
	// OAuth 2.0 Attestation-Based Client Authentication §5 / §6.1:
	// when the AS provides a challenge (challenge_endpoint or header), the
	// Client Attestation PoP JWT MUST include it as the challenge claim.
	if normalizedChallenge := strings.TrimSpace(challenge); normalizedChallenge != "" {
		claims["challenge"] = normalizedChallenge
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = typOAuthClientAttestationPoPJWT
	return token.SignedString(instanceKey)
}

func buildKeyAttestationJWT(
	attesterKey *ecdsa.PrivateKey,
	x5c []string,
	attestedKeys []intcrypto.JWK,
	keyStorage []string,
	userAuthentication []string,
	nonce string,
) (string, error) {
	if attesterKey == nil {
		return "", fmt.Errorf("key attestation private key is required")
	}
	claims := jwt.MapClaims{
		"iat":           time.Now().UTC().Unix(),
		"attested_keys": attestedKeys,
	}
	if len(keyStorage) > 0 {
		claims["key_storage"] = keyStorage
	}
	if len(userAuthentication) > 0 {
		claims["user_authentication"] = userAuthentication
	}
	if strings.TrimSpace(nonce) != "" {
		claims["nonce"] = strings.TrimSpace(nonce)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = typKeyAttestationJWT
	token.Header["x5c"] = append([]string(nil), x5c...)
	return token.SignedString(attesterKey)
}

func createCredentialProofJWTWithKeyAttestation(
	holderKey *ecdsa.PrivateKey,
	holderJWK intcrypto.JWK,
	nonce string,
	subject string,
	audience string,
	keyAttestationJWT string,
) (string, error) {
	if holderKey == nil {
		return "", fmt.Errorf("holder private key is required")
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   strings.TrimSpace(subject),
		"sub":   strings.TrimSpace(subject),
		"aud":   strings.TrimSpace(audience),
		"nonce": strings.TrimSpace(nonce),
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   "proof-" + randomValue(16),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = holderJWK
	token.Header["key_attestation"] = strings.TrimSpace(keyAttestationJWT)
	return token.SignedString(holderKey)
}

func (session *haipIssuanceSession) buildDPoPProof(method string, targetURL string, extraClaims jwt.MapClaims) (string, error) {
	if session == nil || session.dpopPrivateKey == nil {
		return "", fmt.Errorf("haip issuance session is unavailable")
	}
	claims := jwt.MapClaims{
		"jti": randomValue(20),
		"htm": strings.ToUpper(strings.TrimSpace(method)),
		"htu": strings.TrimSpace(targetURL),
		"iat": time.Now().UTC().Unix(),
	}
	for key, value := range extraClaims {
		claims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = dpop.ProofTyp
	token.Header["jwk"] = map[string]interface{}{
		"kty": session.dpopPublicJWK.Kty,
		"crv": session.dpopPublicJWK.Crv,
		"x":   session.dpopPublicJWK.X,
		"y":   session.dpopPublicJWK.Y,
	}
	return token.SignedString(session.dpopPrivateKey)
}

func computeAccessTokenHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func authorizationHeaderForAccessToken(tokenType string, accessToken string) string {
	normalizedType := strings.TrimSpace(tokenType)
	if normalizedType == "" {
		normalizedType = "Bearer"
	}
	if strings.EqualFold(normalizedType, dpop.HeaderName) {
		return dpop.HeaderName + " " + strings.TrimSpace(accessToken)
	}
	return normalizedType + " " + strings.TrimSpace(accessToken)
}

func isDPoPBoundTokenType(tokenType string) bool {
	return strings.EqualFold(strings.TrimSpace(tokenType), dpop.HeaderName)
}

type haipTokenExchangeInput struct {
	TokenEndpoint         string
	Form                  url.Values
	LookingGlassSessionID string
	Session               *haipIssuanceSession
	PopAudience           string
	ChallengeEndpoint     string
}

func (s *walletHarnessServer) exchangeHAIPPreAuthorizedToken(
	ctx context.Context,
	input haipTokenExchangeInput,
) (map[string]interface{}, error) {
	if s == nil || !s.haipIssuanceEnabled() {
		return nil, fmt.Errorf("haip attestation material is not configured")
	}
	if input.Session == nil {
		return nil, fmt.Errorf("haip issuance session is required")
	}
	tokenEndpoint := strings.TrimSpace(input.TokenEndpoint)
	if tokenEndpoint == "" {
		return nil, fmt.Errorf("token endpoint is required")
	}

	attestationJWT, popJWT, err := s.buildClientAttestationHeaderPair(
		ctx,
		input.Session,
		input.PopAudience,
		input.ChallengeEndpoint,
		input.LookingGlassSessionID,
	)
	if err != nil {
		return nil, err
	}

	form := cloneURLValues(input.Form)
	if strings.TrimSpace(s.haipAttestedClientID) != "" {
		form.Set("client_id", strings.TrimSpace(s.haipAttestedClientID))
	}

	payload, err := s.postHAIPFormWithDPoP(
		ctx,
		tokenEndpoint,
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
		return nil, err
	}
	return payload, nil
}

func cloneURLValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func (s *walletHarnessServer) createHAIPCredentialProofJWT(
	wallet *walletMaterial,
	walletSubject string,
	cNonce string,
	audience string,
	credentialConfigID string,
	credentialFormat string,
) (string, error) {
	if !s.haipIssuanceEnabled() {
		return "", fmt.Errorf("haip attestation material is not configured")
	}
	if strings.EqualFold(strings.TrimSpace(credentialFormat), credentialFormatMsoMdoc) ||
		strings.EqualFold(strings.TrimSpace(credentialConfigID), "MobileDrivingLicenceMsoMdocHAIP") {
		return s.createMdocHAIPCredentialProofJWT(walletSubject, cNonce, audience, credentialConfigID)
	}
	return s.createSDJWTHAIPCredentialProofJWT(wallet, walletSubject, cNonce, audience)
}

func (s *walletHarnessServer) createSDJWTHAIPCredentialProofJWT(
	wallet *walletMaterial,
	walletSubject string,
	cNonce string,
	audience string,
) (string, error) {
	if wallet == nil || wallet.KeySet == nil {
		return "", fmt.Errorf("wallet key material is unavailable")
	}
	if err := selectWalletSigningAlgorithm(wallet, "ES256"); err != nil {
		return "", err
	}
	holderJWK, _, err := walletActiveJWK(wallet)
	if err != nil {
		return "", err
	}
	holderKey := wallet.KeySet.ECPrivateKey()
	if holderKey == nil {
		return "", fmt.Errorf("wallet has no ES256 holder key")
	}
	return s.createSDJWTHAIPCredentialProofJWTFromKey(holderKey, holderJWK, walletSubject, cNonce, audience)
}

func (s *walletHarnessServer) createSDJWTHAIPCredentialProofJWTFromKey(
	holderKey *ecdsa.PrivateKey,
	holderJWK intcrypto.JWK,
	walletSubject string,
	cNonce string,
	audience string,
) (string, error) {
	if holderKey == nil {
		return "", fmt.Errorf("holder private key is required")
	}
	keyAttestationJWT, err := buildKeyAttestationJWT(
		s.haipKeyAttestation.PrivateKey,
		s.haipKeyAttestation.X5C,
		[]intcrypto.JWK{holderJWK},
		nil,
		nil,
		cNonce,
	)
	if err != nil {
		return "", fmt.Errorf("build key attestation jwt: %w", err)
	}
	return createCredentialProofJWTWithKeyAttestation(holderKey, holderJWK, cNonce, walletSubject, audience, keyAttestationJWT)
}

func (s *walletHarnessServer) createMdocHAIPCredentialProofJWT(
	walletSubject string,
	cNonce string,
	audience string,
	_ string,
) (string, error) {
	if s.deviceKey == nil {
		return "", fmt.Errorf("wallet device key is unavailable")
	}
	deviceJWK := intcrypto.JWKFromECPublicKey(&s.deviceKey.PublicKey, s.deviceKeyID)
	keyStorage, userAuthentication := keyAttestationClaimsFromEnv()
	keyAttestationJWT, err := buildKeyAttestationJWT(
		s.haipKeyAttestation.PrivateKey,
		s.haipKeyAttestation.X5C,
		[]intcrypto.JWK{deviceJWK},
		keyStorage,
		userAuthentication,
		cNonce,
	)
	if err != nil {
		return "", fmt.Errorf("build mdoc key attestation jwt: %w", err)
	}
	return createCredentialProofJWTWithKeyAttestation(
		s.deviceKey,
		deviceJWK,
		cNonce,
		walletSubject,
		audience,
		keyAttestationJWT,
	)
}

func (s *walletHarnessServer) requestHAIPCredential(
	ctx context.Context,
	credentialEndpoint string,
	credentialConfigurationID string,
	accessToken string,
	tokenType string,
	proofJWTs []string,
	session *haipIssuanceSession,
	lookingGlassSessionID string,
	encryption *credentialResponseEncryptionSupport,
	requestEncryption *credentialRequestEncryptionSupport,
	credentialIdentifiers []string,
) (map[string]interface{}, error) {
	// Prefer encrypted responses on the HAIP path when the issuer advertises
	// algorithms, but only when request encryption keys are also available:
	// OID4VCI §8.2 requires encrypting the request whenever
	// credential_response_encryption is included.
	requireEncryption := encryption != nil && encryption.EncryptionRequired
	if encryption != nil && len(encryption.AlgValuesSupported) > 0 && requestEncryption != nil && requestEncryption.advertised() {
		requireEncryption = true
	}
	return s.requestCredentialWithLifecycle(ctx, credentialEndpoint, credentialRequestBuildInput{
		CredentialConfigurationID: credentialConfigurationID,
		CredentialIdentifiers:     credentialIdentifiers,
		ProofJWTs:                 proofJWTs,
		Encryption:                encryption,
		RequestEncryption:         requestEncryption,
		RequireEncryption:         requireEncryption,
	}, accessToken, tokenType, session, lookingGlassSessionID)
}
