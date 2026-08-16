package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	jose "github.com/go-jose/go-jose/v4"
)

// Encrypted OID4VP responses (OID4VP 1.0 Section 8.3 / Appendix B.2) use
// ECDH-ES key agreement with A128GCM content encryption by default. HAIP 1.0
// Section 5 additionally requires A256GCM; the verifier accepts both content
// encryption algorithms on decrypt and (in HAIP / DC API mode) advertises both.
const (
	mdocResponseEncAlg = "ECDH-ES"
	mdocResponseEncEnc = encA128GCM
)

// ecdhesContentEncryptions is the set of JWE content encryption algorithms the
// verifier accepts for ECDH-ES responses: A128GCM (online-profile default) and A256GCM
// (HAIP 1.0 Section 5). go-jose requires the decrypt allowlist to enumerate
// every algorithm a response might use.
var ecdhesContentEncryptions = []jose.ContentEncryption{jose.A128GCM, jose.A256GCM}

// mdocPresentation is one decoded mdoc presentation extracted from a vp_token:
// the DCQL credential query identifier it answers, the raw base64url-decoded
// DeviceResponse CBOR, and the decoded structure.
type mdocPresentation struct {
	DCQLID   string
	Raw      []byte
	Response mdoc.DeviceResponse
}

// newMdocResponseEncryptionKey generates an ephemeral EC P-256 ECDH-ES
// response-encryption key for an mdoc OID4VP request. It returns the private JWK
// (carrying d, retained by the verifier to decrypt the response) and the public
// JWK (published in client_metadata.jwks for the wallet to encrypt to). The kid
// ties the two together and is echoed in the JWE header per OID4VP 1.0 Section
// 8.3.
func newMdocResponseEncryptionKey(kid string) (private crypto.JWK, public crypto.JWK, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return crypto.JWK{}, crypto.JWK{}, fmt.Errorf("generate mdoc response encryption key: %w", err)
	}
	public = crypto.JWKFromECPublicKey(&priv.PublicKey, kid)
	public.Use = "enc"
	public.Alg = mdocResponseEncAlg
	private = public
	d, err := priv.Bytes()
	if err != nil {
		return crypto.JWK{}, crypto.JWK{}, fmt.Errorf("encode mdoc response encryption key: %w", err)
	}
	private.D = base64.RawURLEncoding.EncodeToString(d)
	return private, public, nil
}

// ecPrivateKeyFromJWK reconstructs an *ecdsa.PrivateKey from a JWK carrying the
// private d parameter, for JWE decryption.
func ecPrivateKeyFromJWK(jwk crypto.JWK) (*ecdsa.PrivateKey, error) {
	pub, err := crypto.ParseECPublicKeyFromJWK(jwk)
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
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), dBytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private d: %w", err)
	}
	if !priv.PublicKey.Equal(pub) {
		return nil, fmt.Errorf("EC private d does not match the JWK public coordinates")
	}
	return priv, nil
}

// encodeMdocVPToken builds the OID4VP 1.0 DCQL vp_token for an mdoc
// presentation: a JSON object keyed by the DCQL credential query id whose value
// is an array of base64url-encoded DeviceResponse CBOR strings (Appendix B.2).
func encodeMdocVPToken(dcqlID string, deviceResponse []byte) (string, error) {
	if strings.TrimSpace(dcqlID) == "" {
		return "", fmt.Errorf("mdoc vp_token requires a DCQL credential id")
	}
	if len(deviceResponse) == 0 {
		return "", fmt.Errorf("mdoc vp_token requires a DeviceResponse")
	}
	token := map[string][]string{
		dcqlID: {base64.RawURLEncoding.EncodeToString(deviceResponse)},
	}
	encoded, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("encode mdoc vp_token: %w", err)
	}
	return string(encoded), nil
}

// extractMdocPresentations parses a vp_token into mdoc presentations, accepting
// both the OID4VP 1.0 DCQL-keyed object form
// ({"<id>": ["<base64url DeviceResponse>", ...]}) and a bare base64url
// DeviceResponse string (the non-DCQL form). It returns ok=false when
// the token is not an mdoc presentation at all (e.g. an SD-JWT or JSON-LD VP),
// so it can be used as the dispatch discriminator without false positives: it
// only claims a token when a DeviceResponse actually decodes.
func extractMdocPresentations(vpToken string) ([]mdocPresentation, bool) {
	trimmed := strings.TrimSpace(vpToken)
	if trimmed == "" || strings.Contains(trimmed, "~") {
		return nil, false
	}

	// DCQL-keyed object form.
	if strings.HasPrefix(trimmed, "{") {
		var keyed map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &keyed); err != nil {
			return nil, false
		}
		presentations := make([]mdocPresentation, 0, len(keyed))
		for id, rawValue := range keyed {
			for _, encoded := range decodeVPTokenEntry(rawValue) {
				raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
				if err != nil {
					continue
				}
				response, err := mdoc.DecodeDeviceResponse(raw)
				if err != nil || len(response.Documents) == 0 {
					continue
				}
				presentations = append(presentations, mdocPresentation{DCQLID: id, Raw: raw, Response: response})
			}
		}
		if len(presentations) == 0 {
			return nil, false
		}
		return presentations, true
	}

	// Bare base64url DeviceResponse (no DCQL key).
	if strings.Contains(trimmed, ".") {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, false
	}
	response, err := mdoc.DecodeDeviceResponse(raw)
	if err != nil || len(response.Documents) == 0 {
		return nil, false
	}
	return []mdocPresentation{{DCQLID: "", Raw: raw, Response: response}}, true
}

// decodeVPTokenEntry normalizes a single DCQL vp_token value, which OID4VP
// allows as either a single string or an array of strings.
func decodeVPTokenEntry(rawValue json.RawMessage) []string {
	var single string
	if err := json.Unmarshal(rawValue, &single); err == nil {
		if strings.TrimSpace(single) == "" {
			return nil
		}
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(rawValue, &many); err == nil {
		return many
	}
	return nil
}

// encryptMdocResponse builds the OID4VP 1.0 Section 8.3 encrypted response for
// direct_post.jwt: an unsigned, encrypted JWT (JWE) whose payload is the JSON
// Authorization Response (vp_token + state) as top-level members, encrypted to
// the verifier's response-encryption public key via ECDH-ES + A128GCM. The kid
// of the verifier key is echoed in the JWE header. This is the wallet (and
// interop test) side; the verifier decrypts with decryptMdocResponse.
//
// The handover/JWE coupling required by OID4VP 1.0 Appendix B.2.6 is satisfied
// because the same verifier public key whose RFC 7638 thumbprint is bound into
// OpenID4VPHandoverInfo is the key used here to encrypt.
func encryptMdocResponse(verifierEncJWK crypto.JWK, vpToken string, state string) (string, error) {
	return encryptECDHESResponse(verifierEncJWK, vpToken, state, jose.A128GCM)
}

// encryptECDHESResponse builds the OID4VP 1.0 Section 8.3 encrypted response
// (ECDH-ES + AES-GCM) for either the mdoc direct_post.jwt online profile or the
// HAIP DC API path, with a caller-selected content encryption algorithm (HAIP
// 1.0 Section 5 allows A128GCM or A256GCM). This is the wallet / interop side;
// the verifier decrypts with decryptMdocResponse.
func encryptECDHESResponse(verifierEncJWK crypto.JWK, vpToken string, state string, enc jose.ContentEncryption) (string, error) {
	pub, err := crypto.ParseECPublicKeyFromJWK(verifierEncJWK)
	if err != nil {
		return "", fmt.Errorf("parse verifier encryption key: %w", err)
	}
	var vpTokenValue interface{}
	if err := json.Unmarshal([]byte(vpToken), &vpTokenValue); err != nil {
		// Not JSON (a bare base64url DeviceResponse); carry it as a string.
		vpTokenValue = vpToken
	}
	payload := map[string]interface{}{"vp_token": vpTokenValue}
	if strings.TrimSpace(state) != "" {
		payload["state"] = state
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal encrypted response payload: %w", err)
	}

	recipient := jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}
	if kid := strings.TrimSpace(verifierEncJWK.Kid); kid != "" {
		recipient.KeyID = kid
	}
	encrypter, err := jose.NewEncrypter(enc, recipient, (&jose.EncrypterOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("build mdoc response encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt mdoc response: %w", err)
	}
	return object.CompactSerialize()
}

// decryptMdocResponse decrypts an mdoc OID4VP direct_post.jwt encrypted response
// (ECDH-ES + A128GCM) using the verifier's response-encryption private key, and
// returns the vp_token (re-serialized to its JSON/string form) and state from
// the JWE payload. The verifier reconstructs the handover from its own enc key
// thumbprint, so an attacker re-encrypting to a different key is detectable via
// the device-authentication failure (OID4VP 1.0 Appendix B.2.6 anti-substitution).
func decryptMdocResponse(compactJWE string, encPrivJWK crypto.JWK) (vpToken string, state string, err error) {
	priv, err := ecPrivateKeyFromJWK(encPrivJWK)
	if err != nil {
		return "", "", fmt.Errorf("load response decryption key: %w", err)
	}
	object, err := jose.ParseEncrypted(
		strings.TrimSpace(compactJWE),
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		ecdhesContentEncryptions,
	)
	if err != nil {
		return "", "", fmt.Errorf("parse mdoc encrypted response: %w", err)
	}
	plaintext, err := object.Decrypt(priv)
	if err != nil {
		return "", "", fmt.Errorf("decrypt mdoc encrypted response: %w", err)
	}
	var payload struct {
		VPToken json.RawMessage `json:"vp_token"`
		State   string          `json:"state"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return "", "", fmt.Errorf("parse mdoc encrypted response payload: %w", err)
	}
	if len(payload.VPToken) == 0 {
		return "", "", fmt.Errorf("mdoc encrypted response is missing vp_token")
	}
	// vp_token may be a JSON object/array (DCQL-keyed) or a JSON string (bare
	// DeviceResponse). Re-serialize objects/arrays; unwrap a JSON string.
	vpToken = strings.TrimSpace(string(payload.VPToken))
	if strings.HasPrefix(vpToken, "\"") {
		var unwrapped string
		if err := json.Unmarshal(payload.VPToken, &unwrapped); err == nil {
			vpToken = unwrapped
		}
	}
	return vpToken, payload.State, nil
}

// dcqlRequestsMdoc reports whether a DCQL query asks for at least one mso_mdoc
// credential, which the request builder uses to decide whether to provision an
// ECDH-ES response-encryption key for the OID4VP online profile.
func dcqlRequestsMdoc(dcqlQuery string) bool {
	for _, requirement := range vc.ParseDCQLCredentialRequirements(dcqlQuery) {
		if strings.EqualFold(strings.TrimSpace(requirement.Format), credentialFormatMsoMdoc) {
			return true
		}
	}
	return false
}

// injectResponseEncryption mutates client_metadata to advertise the verifier's
// ephemeral ECDH-ES response-encryption public key (in jwks) and the supported
// content encryption algorithms, per OID4VP 1.0 Section 8.3, so the wallet can
// encrypt the response. It returns the private JWK to retain on the session for
// decryption.
//
// encValues is the advertised encrypted_response_enc_values_supported list:
// The general online profile advertises A128GCM, while HAIP 1.0 Section 5 requires verifiers
// to list both A128GCM and A256GCM. The ephemeral key is request-specific (HAIP
// 1.0 Section 5: "ephemeral encryption public keys specific to each
// Authorization Request").
func injectResponseEncryption(clientMetadata map[string]interface{}, kid string, encValues []string) (crypto.JWK, error) {
	private, public, err := newMdocResponseEncryptionKey(kid)
	if err != nil {
		return crypto.JWK{}, err
	}
	clientMetadata["jwks"] = map[string]interface{}{
		"keys": []interface{}{jwkToClientMetadataMap(public)},
	}
	if len(encValues) == 0 {
		encValues = []string{mdocResponseEncEnc}
	}
	clientMetadata["encrypted_response_enc_values_supported"] = encValues
	return private, nil
}

// jwkToClientMetadataMap renders a public EC JWK as the JSON object shape OID4VP
// client_metadata.jwks expects (kty, crv, x, y, use, alg, kid), omitting the
// private d.
func jwkToClientMetadataMap(jwk crypto.JWK) map[string]interface{} {
	m := map[string]interface{}{
		"kty": jwk.Kty,
		"crv": jwk.Crv,
		"x":   jwk.X,
		"y":   jwk.Y,
	}
	if jwk.Use != "" {
		m["use"] = jwk.Use
	}
	if jwk.Alg != "" {
		m["alg"] = jwk.Alg
	}
	if jwk.Kid != "" {
		m["kid"] = jwk.Kid
	}
	return m
}

// sessionResponseEncryptionThumbprint returns the RFC 7638 SHA-256 thumbprint
// (raw bytes) of the verifier's response-encryption key bound to this session,
// or nil when the response is unencrypted. This is the jwkThumbprint embedded in
// OpenID4VPHandoverInfo.
func sessionResponseEncryptionThumbprint(session *requestSession) ([]byte, error) {
	if session == nil || session.ResponseEncryptionJWK == nil {
		return nil, nil
	}
	return session.ResponseEncryptionJWK.ThumbprintBytes()
}

// reconstructSessionHandover builds the OID4VP 1.0 SessionTranscript Handover
// for a session, selecting the correct variant by invocation path. This is the
// single place the verifier reconstructs the handover; the wallet builds the
// identical handover from the same inputs, so the shared SessionTranscript
// cannot drift.
//
//   - Redirect / direct_post: OpenID4VPHandover over
//     [client_id, nonce, jwkThumbprint, response_uri] (Appendix B.2.6.1).
//   - W3C Digital Credentials API: OpenID4VPDCAPIHandover over
//     [origin, nonce, jwkThumbprint] (Appendix B.2.6.2). The Origin replaces
//     client_id and response_uri; the bare Origin (no "origin:" prefix) is bound.
func reconstructSessionHandover(session *requestSession) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("request session is required")
	}
	thumbprint, err := sessionResponseEncryptionThumbprint(session)
	if err != nil {
		return nil, fmt.Errorf("compute response encryption thumbprint: %w", err)
	}
	if session.isDCAPI() {
		origin := strings.TrimSpace(session.Origin)
		if origin == "" {
			return nil, fmt.Errorf("dc_api session is missing the verifier origin")
		}
		return mdoc.NewOpenID4VPDCAPIHandover(origin, session.Nonce, thumbprint)
	}
	responseURI := strings.TrimSpace(session.ResponseURI)
	if responseURI == "" {
		responseURI = strings.TrimSpace(session.RedirectURI)
	}
	return mdoc.NewOpenID4VPHandover(session.ClientID, session.Nonce, thumbprint, responseURI)
}
