package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// DPoPKey is the conformance client's ES256 proof-of-possession key.
type DPoPKey struct {
	private *ecdsa.PrivateKey
}

// NewDPoPKey generates a fresh P-256 key.
func NewDPoPKey() (*DPoPKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DPoPKey{private: key}, nil
}

// PublicJWK is the public key as the jwk JOSE header carries it.
func (k *DPoPKey) PublicJWK() (map[string]any, error) {
	// The uncompressed SEC 1 encoding is 0x04 || X || Y, 32 bytes each for P-256.
	point, err := k.private.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	if len(point) != 65 || point[0] != 0x04 {
		return nil, fmt.Errorf("unexpected P-256 public key encoding")
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(point[33:]),
	}, nil
}

// ProofOptions are the RFC 9449 Section 4.2 inputs for one proof.
type ProofOptions struct {
	Method string
	URL    string
	// Nonce is the server-provided DPoP-Nonce, when one was issued.
	Nonce string
	// AccessToken, when set, adds ath (Section 4.2).
	AccessToken string
}

// Proof builds a dpop+jwt proof: typ dpop+jwt, alg ES256, the public jwk,
// and the jti, htm, htu and iat claims, plus nonce and ath when given.
func (k *DPoPKey) Proof(opts ProofOptions) (string, error) {
	claims := jwt.MapClaims{
		"jti": uuid.NewString(),
		"htm": opts.Method,
		"htu": opts.URL,
		"iat": time.Now().Unix(),
	}
	if opts.Nonce != "" {
		claims["nonce"] = opts.Nonce
	}
	if opts.AccessToken != "" {
		sum := sha256.Sum256([]byte(opts.AccessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	jwk, err := k.PublicJWK()
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk
	return token.SignedString(k.private)
}
