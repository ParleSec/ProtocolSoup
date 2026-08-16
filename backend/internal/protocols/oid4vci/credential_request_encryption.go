package oid4vci

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	jose "github.com/go-jose/go-jose/v4"
)

const maxEncryptedCredentialRequestBytes = 64 * 1024

func (p *Plugin) credentialRequestEncryptionMetadata() (map[string]interface{}, error) {
	if p.mdocPKI == nil || p.mdocPKI.DocumentSignerKey() == nil {
		return nil, fmt.Errorf("credential request decryption key is unavailable")
	}
	jwk := crypto.JWKFromECPublicKey(
		&p.mdocPKI.DocumentSignerKey().PublicKey,
		"oid4vci-credential-request-encryption",
	)
	jwk.Alg = string(jose.ECDH_ES)
	jwk.Use = "enc"
	return map[string]interface{}{
		"enc_values_supported": []string{string(jose.A128GCM), string(jose.A256GCM)},
		"encryption_required":  false,
		"jwks": crypto.JWKS{
			Keys: []crypto.JWK{jwk},
		},
	}, nil
}

func (p *Plugin) decodeCredentialRequest(r *http.Request, destination *credentialRequest) error {
	return p.decodeJSONOrEncryptedJWTRequest(r, destination, "credential request")
}

// decodeJSONOrEncryptedJWTRequest accepts OID4VCI §8.2 / §9 bodies as
// application/json or as an encrypted application/jwt (when the issuer
// advertises credential_request_encryption). The deferred credential
// endpoint uses the same encodings as the credential endpoint.
func (p *Plugin) decodeJSONOrEncryptedJWTRequest(r *http.Request, destination interface{}, requestName string) error {
	if requestHasMediaType(r, "application/json") {
		return decodeRequestObject(r.Body, destination, requestName)
	}
	if !requestHasMediaType(r, "application/jwt") {
		return fmt.Errorf("Content-Type must be application/json or application/jwt")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxEncryptedCredentialRequestBytes+1))
	if err != nil {
		return fmt.Errorf("%s could not be read", requestName)
	}
	if len(raw) > maxEncryptedCredentialRequestBytes {
		return fmt.Errorf("%s exceeds %d bytes", requestName, maxEncryptedCredentialRequestBytes)
	}
	encrypted, err := jose.ParseEncrypted(
		strings.TrimSpace(string(raw)),
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A128GCM, jose.A256GCM},
	)
	if err != nil {
		return fmt.Errorf("encrypted %s is invalid: %w", requestName, err)
	}
	plaintext, err := encrypted.Decrypt(p.mdocPKI.DocumentSignerKey())
	if err != nil {
		return fmt.Errorf("encrypted %s decryption failed", requestName)
	}
	return decodeRequestObject(
		io.NopCloser(bytes.NewReader(plaintext)),
		destination,
		requestName,
	)
}
