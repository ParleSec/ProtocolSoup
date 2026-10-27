package oid4vcihaip

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	jose "github.com/go-jose/go-jose/v4"
)

// Request and response encryption (OID4VCI 1.0 Section 10), which only these
// scenarios use, on top of the shared Wallet side in the capture package.

// txCodeGrant is the tx_code-protected Pre-Authorized Code grant the
// scenarios redeem; deferredGrant is the same for a deferred offer.
var (
	txCodeGrant   = capture.GrantOptions{OfferOptions: capture.OfferOptions{TxCode: true}}
	deferredGrant = capture.GrantOptions{OfferOptions: capture.OfferOptions{TxCode: true, Deferred: true}}
)

// newEncryptedRequest encrypts body to the key the issuer advertises in
// credential_request_encryption (OID4VCI 1.0 Section 10: the JWE alg equals
// the JWK's alg and the JWE carries the JWK's kid) and posts it as
// application/jwt with a bearer token.
func newEncryptedRequest(target, accessToken string, meta *capture.Issuer, enc string, body any) (*http.Request, error) {
	if meta.RequestKey == nil {
		return nil, fmt.Errorf("credential issuer metadata advertises no credential_request_encryption key")
	}
	if meta.RequestKey.Algorithm == "" {
		return nil, fmt.Errorf("advertised credential_request_encryption key has no alg")
	}
	plaintext, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	encrypter, err := jose.NewEncrypter(
		jose.ContentEncryption(enc),
		jose.Recipient{
			Algorithm: jose.KeyAlgorithm(meta.RequestKey.Algorithm),
			Key:       meta.RequestKey.Key,
			KeyID:     meta.RequestKey.KeyID,
		},
		(&jose.EncrypterOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, fmt.Errorf("build request encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(compact))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/jwt")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return req, nil
}

// responseKey is the conformance client's ephemeral key for an encrypted
// Credential Response.
type responseKey struct {
	private *ecdsa.PrivateKey
	enc     string
}

const responseKeyID = "conformance-client-response-key"

// newResponseKey generates a P-256 key for the credential_response_encryption
// alg ECDH-ES and the given enc, after checking the issuer advertises both.
func newResponseKey(meta *capture.Issuer, enc string) (*responseKey, error) {
	if !slices.Contains(meta.ResponseAlg, string(jose.ECDH_ES)) {
		return nil, fmt.Errorf("credential_response_encryption does not advertise ECDH-ES")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &responseKey{private: key, enc: enc}, nil
}

// parameters is the credential_response_encryption request object.
func (k *responseKey) parameters() map[string]any {
	return map[string]any{
		"jwk": jose.JSONWebKey{
			Key:       &k.private.PublicKey,
			KeyID:     responseKeyID,
			Algorithm: string(jose.ECDH_ES),
			Use:       "enc",
		},
		"enc": k.enc,
	}
}

// decrypt opens an encrypted Credential or Deferred Credential Response. It
// checks the JWE carries the kid of the key it was encrypted to (Section 10).
func (k *responseKey) decrypt(body []byte) (map[string]any, error) {
	object, err := jose.ParseEncrypted(
		strings.TrimSpace(string(body)),
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.ContentEncryption(k.enc)},
	)
	if err != nil {
		return nil, fmt.Errorf("response is not a JWE for ECDH-ES and %s: %w", k.enc, err)
	}
	if object.Header.KeyID != responseKeyID {
		return nil, fmt.Errorf("response JWE kid is %q, want %q", object.Header.KeyID, responseKeyID)
	}
	plaintext, err := object.Decrypt(k.private)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return nil, fmt.Errorf("decrypted response is not a JSON object: %w", err)
	}
	return out, nil
}

func mediaType(resp *capture.Response) string {
	value, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	return strings.TrimSpace(strings.ToLower(value))
}
