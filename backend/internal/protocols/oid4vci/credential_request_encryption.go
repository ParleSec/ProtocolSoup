package oid4vci

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	jose "github.com/go-jose/go-jose/v4"
)

const maxEncryptedCredentialRequestBytes = 64 * 1024

// requestEncryptionKeyFile is where the Credential Request decryption key is
// kept, beside the mdoc PKI bundle when a store directory is configured.
const requestEncryptionKeyFile = "credential_request_encryption_key.pem"

// loadOrCreateRequestEncryptionKey returns the P-256 key the Credential Issuer
// decrypts Credential and Deferred Credential Requests with (OID4VCI 1.0
// Section 10). It is used for nothing else: the mdoc Document Signer key signs
// IssuerAuth, signed metadata and status lists, and a key that both signs and
// decrypts mixes two purposes RFC 7517 Section 4.2 keeps apart with "use". With
// a store directory the key is persisted so a restart keeps the key the
// published metadata advertises; without one it lives only in memory, like the
// mdoc PKI.
func loadOrCreateRequestEncryptionKey(dir string) (*ecdsa.PrivateKey, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create request encryption key dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, requestEncryptionKeyFile)
	if encoded, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(encoded)
		if block == nil {
			return nil, fmt.Errorf("request encryption key %q holds no PEM block", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse request encryption key %q: %w", path, err)
		}
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("request encryption key %q is not a P-256 key", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read request encryption key %q: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal request encryption key: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("write request encryption key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("store request encryption key: %w", err)
	}
	return key, nil
}

func (p *Plugin) credentialRequestEncryptionMetadata() (map[string]interface{}, error) {
	if p.requestEncryptionKey == nil {
		return nil, fmt.Errorf("credential request decryption key is unavailable")
	}
	jwk := crypto.JWKFromECPublicKey(
		&p.requestEncryptionKey.PublicKey,
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

func (p *Plugin) decodeCredentialRequest(r *http.Request, destination *credentialRequest) (bool, error) {
	return p.decodeJSONOrEncryptedJWTRequest(r, destination, "credential request")
}

// errResponseEncryptionNeedsEncryptedRequest is the invalid_encryption_parameters
// description for a plaintext request that asks for an encrypted response.
// OID4VCI 1.0 Section 8.2: "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it being
// substituted by an attacker." Section 9.1 says the same of the Deferred
// Credential Request.
const errResponseEncryptionNeedsEncryptedRequest = "credential_response_encryption is only accepted in an encrypted (application/jwt) request (OID4VCI 1.0 Sections 8.2 and 9.1)"

// decodeJSONOrEncryptedJWTRequest accepts OID4VCI §8.2 / §9 bodies as
// application/json or as an encrypted application/jwt (when the issuer
// advertises credential_request_encryption). The deferred credential
// endpoint uses the same encodings as the credential endpoint. It reports
// whether the body arrived encrypted, which decides whether
// credential_response_encryption may be honoured.
func (p *Plugin) decodeJSONOrEncryptedJWTRequest(r *http.Request, destination interface{}, requestName string) (bool, error) {
	if requestHasMediaType(r, "application/json") {
		return false, decodeRequestObject(r.Body, destination, requestName)
	}
	if !requestHasMediaType(r, "application/jwt") {
		return false, fmt.Errorf("Content-Type must be application/json or application/jwt")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxEncryptedCredentialRequestBytes+1))
	if err != nil {
		return true, fmt.Errorf("%s could not be read", requestName)
	}
	if len(raw) > maxEncryptedCredentialRequestBytes {
		return true, fmt.Errorf("%s exceeds %d bytes", requestName, maxEncryptedCredentialRequestBytes)
	}
	encrypted, err := jose.ParseEncrypted(
		strings.TrimSpace(string(raw)),
		[]jose.KeyAlgorithm{jose.ECDH_ES},
		[]jose.ContentEncryption{jose.A128GCM, jose.A256GCM},
	)
	if err != nil {
		return true, fmt.Errorf("encrypted %s is invalid: %w", requestName, err)
	}
	if p.requestEncryptionKey == nil {
		return true, fmt.Errorf("encrypted %s cannot be decrypted: no request encryption key", requestName)
	}
	plaintext, err := encrypted.Decrypt(p.requestEncryptionKey)
	if err != nil {
		return true, fmt.Errorf("encrypted %s decryption failed", requestName)
	}
	return true, decodeRequestObject(
		io.NopCloser(bytes.NewReader(plaintext)),
		destination,
		requestName,
	)
}
