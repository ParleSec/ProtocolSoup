package rfc9449

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

// The conformance client's DPoP proofs. The failing scenarios need proofs
// that break one RFC 9449 Section 4.3 check each, so a proof is built from
// editable header and claim maps and signed only once a scenario has edited
// it.

// proofKey is a conformance-client EC key generated for one scenario.
type proofKey struct {
	private *ecdsa.PrivateKey
}

func newProofKey(curve elliptic.Curve) (*proofKey, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &proofKey{private: key}, nil
}

// publicJWK is the key's public members as a jwk JOSE header carries them.
func (k *proofKey) publicJWK() (map[string]any, error) {
	// The uncompressed SEC 1 encoding is 0x04 || X || Y.
	point, err := k.private.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	size := (len(point) - 1) / 2
	if point[0] != 0x04 || len(point) != 1+2*size {
		return nil, fmt.Errorf("unexpected EC public key encoding")
	}
	return map[string]any{
		"kty": "EC",
		"crv": k.private.Curve.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(point[1 : 1+size]),
		"y":   base64.RawURLEncoding.EncodeToString(point[1+size:]),
	}, nil
}

// privateJWK is publicJWK plus the private scalar d (RFC 7518 Section
// 6.2.2.1), for the scenario that puts a private key in the jwk header.
func (k *proofKey) privateJWK() (map[string]any, error) {
	jwk, err := k.publicJWK()
	if err != nil {
		return nil, err
	}
	d, err := k.private.Bytes()
	if err != nil {
		return nil, err
	}
	jwk["d"] = base64.RawURLEncoding.EncodeToString(d)
	return jwk, nil
}

// proofSpec is a DPoP proof before signing. A header member set to nil is
// removed from the signed header.
type proofSpec struct {
	header map[string]any
	claims jwt.MapClaims
}

// newProofSpec is a conformant RFC 9449 Section 4.2 proof for key: typ
// dpop+jwt, the public jwk, and jti, htm, htu and iat, plus nonce and ath
// when given. Scenarios edit it to break exactly one check.
func newProofSpec(key *proofKey, method, uri, nonce, accessToken string) (*proofSpec, error) {
	jwk, err := key.publicJWK()
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{
		"jti": uuid.NewString(),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		claims["ath"] = accessTokenHash(accessToken)
	}
	return &proofSpec{header: map[string]any{"typ": "dpop+jwt", "jwk": jwk}, claims: claims}, nil
}

// sign produces the compact JWS with method and signing key. alg comes
// from method; jwt.SigningMethodNone with jwt.UnsafeAllowNoneSignatureType
// produces an unsigned proof.
func (p *proofSpec) sign(method jwt.SigningMethod, key any) (string, error) {
	token := jwt.NewWithClaims(method, p.claims)
	for name, value := range p.header {
		if value == nil {
			delete(token.Header, name)
			continue
		}
		token.Header[name] = value
	}
	return token.SignedString(key)
}

// signES256 signs with signer, which is normally the key in the jwk header.
func (p *proofSpec) signES256(signer *proofKey) (string, error) {
	return p.sign(jwt.SigningMethodES256, signer.private)
}

// accessTokenHash is the RFC 9449 Section 4.2 ath value: the base64url
// encoding of the SHA-256 hash of the access token's ASCII value.
func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
