package oid4vci

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	jose "github.com/go-jose/go-jose/v4"
)

// credentialResponseEncAlgsSupported / credentialResponseEncEncSupported are
// advertised in credential issuer metadata's credential_response_encryption
// (OID4VCI 1.0 §11.2.3) and enforced on the request's chosen values.
// ECDH-ES mirrors the mso_mdoc/HAIP encryption already implemented for
// OID4VP (oid4vp/mdoc_online.go); A128GCM/A256GCM mirrors HAIP 1.0 §5's
// mandated content-encryption pair.
var (
	credentialResponseEncAlgsSupported = []string{"ECDH-ES"}
	credentialResponseEncEncSupported  = []string{"A128GCM", "A256GCM"}
)

// credentialResponseEncryptionRequest is the OID4VCI 1.0 §8.2/§9.1
// credential_response_encryption request object: the wallet's ephemeral
// public key and chosen content-encryption algorithm for the response. The
// JWE key-management algorithm is the jwk's own alg member (§10: "The alg
// parameter MUST be present [on the JWK]. The JWE alg algorithm used MUST be
// equal to the alg value of the chosen JWK").
type credentialResponseEncryptionRequest struct {
	JWK crypto.JWK `json:"jwk"`
	Enc string     `json:"enc"`
}

// validate checks the request object against the issuer's advertised
// alg_values_supported / enc_values_supported. A malformed or unsupported
// request maps to the OID4VCI 1.0 §8.3.1.2 invalid_encryption_parameters
// error.
func (req *credentialResponseEncryptionRequest) validate() error {
	if req == nil {
		return fmt.Errorf("credential_response_encryption is required")
	}
	if strings.TrimSpace(req.JWK.Kty) == "" {
		return fmt.Errorf("credential_response_encryption.jwk is required")
	}
	alg := strings.TrimSpace(req.JWK.Alg)
	if alg == "" || !containsFold(credentialResponseEncAlgsSupported, alg) {
		return fmt.Errorf("credential_response_encryption.jwk.alg %q is not supported (supported: %v)", alg, credentialResponseEncAlgsSupported)
	}
	if !containsFold(credentialResponseEncEncSupported, strings.TrimSpace(req.Enc)) {
		return fmt.Errorf("credential_response_encryption.enc %q is not supported (supported: %v)", req.Enc, credentialResponseEncEncSupported)
	}
	return nil
}

func containsFold(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if strings.EqualFold(candidate, needle) {
			return true
		}
	}
	return false
}

// encryptCredentialResponse renders a Credential/Deferred Credential Response
// as an encrypted JWT per OID4VCI 1.0 §10: ECDH-ES key agreement to the
// wallet's ephemeral public key, then AEAD content encryption with the
// requested enc algorithm. The kid of the wallet's key (if present) is echoed
// in the JWE header per §10 ("the JWE MUST include the same value in the kid
// JWE Header Parameter").
func encryptCredentialResponse(payload map[string]interface{}, req credentialResponseEncryptionRequest) (string, error) {
	pub, err := crypto.ParseECPublicKeyFromJWK(req.JWK)
	if err != nil {
		return "", fmt.Errorf("parse credential_response_encryption.jwk: %w", err)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal credential response payload: %w", err)
	}
	recipient := jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}
	if kid := strings.TrimSpace(req.JWK.Kid); kid != "" {
		recipient.KeyID = kid
	}
	encrypter, err := jose.NewEncrypter(jose.ContentEncryption(strings.ToUpper(strings.TrimSpace(req.Enc))), recipient, (&jose.EncrypterOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("build credential response encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt credential response: %w", err)
	}
	return object.CompactSerialize()
}

// writeCredentialResponse writes a Credential/Deferred Credential Response,
// encrypting it as application/jwt when the wallet requested encryption
// (OID4VCI 1.0 §8.3/§9.2/§10), or as plain application/json otherwise.
func writeCredentialResponse(w http.ResponseWriter, status int, payload map[string]interface{}, encryption *credentialResponseEncryptionRequest) error {
	if encryption == nil {
		writeJSON(w, status, payload)
		return nil
	}
	compact, err := encryptCredentialResponse(payload, *encryption)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(compact))
	return nil
}

// credentialResponseEncryptionMetadata builds the credential issuer
// metadata's credential_response_encryption object (OID4VCI 1.0 §11.2.3).
// encryption_required stays false: the Final plan's unencrypted flow must
// keep working, while HAIP wallets that request encryption are now genuinely
// served a JWE response instead of the parameter being decorative.
func credentialResponseEncryptionMetadata() map[string]interface{} {
	return map[string]interface{}{
		"alg_values_supported": append([]string{}, credentialResponseEncAlgsSupported...),
		"enc_values_supported": append([]string{}, credentialResponseEncEncSupported...),
		"encryption_required":  false,
	}
}
