package capture

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The conformance client's SD-JWT VC holder: it obtains a credential from
// the issuer and presents it the way a wallet does. Everything it sends is
// built here, independently of the product's own credential libraries.

// UniversityDegreeVCT is the vct the issuer's University Degree SD-JWT VC
// carries.
const UniversityDegreeVCT = "https://protocolsoup.com/credentials/university_degree"

// SDJWTHolder is the conformance client's key-bound SD-JWT VC.
type SDJWTHolder struct {
	Key *HolderKey
	// Credential is the SD-JWT VC without a Key Binding JWT: the
	// issuer-signed JWT and its disclosures, ending in "~".
	Credential string
	VCT        string
}

// IssueSDJWTHolder obtains an SD-JWT VC from the issuer through the
// Pre-Authorized Code Flow: metadata, offer, token, nonce and a credential
// request with a jwt proof of the conformance client's own key. It is
// preparation, so every request goes through Setup.
func IssueSDJWTHolder(ctx context.Context, env *Env) (*SDJWTHolder, error) {
	issuer, err := DiscoverIssuer(ctx, env)
	if err != nil {
		return nil, err
	}
	grant, err := PreAuthorizedGrant(ctx, env, issuer, GrantOptions{OfferOptions: OfferOptions{TxCode: true}})
	if err != nil {
		return nil, err
	}
	key, err := NewHolderKey()
	if err != nil {
		return nil, err
	}
	issued, err := RequestCredential(ctx, env, issuer, grant, key, http.StatusOK)
	if err != nil {
		return nil, err
	}
	credentials, err := IssuedCredentials(issued)
	if err != nil {
		return nil, err
	}
	if len(credentials) != 1 {
		return nil, fmt.Errorf("credential response carries %d credentials, want 1", len(credentials))
	}
	credential := credentials[0]
	if !strings.Contains(credential, "~") {
		return nil, fmt.Errorf("credential response does not carry an SD-JWT VC")
	}
	vct, err := SDJWTClaim(credential, "vct")
	if err != nil {
		return nil, err
	}
	return &SDJWTHolder{Key: key, Credential: credential, VCT: vct}, nil
}

// SDJWTClaim reads a string claim from an SD-JWT's issuer-signed JWT.
func SDJWTClaim(sdJWT, name string) (string, error) {
	issuerJWT, _, _ := strings.Cut(sdJWT, "~")
	value, err := JWTClaim(issuerJWT, name)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("issuer-signed JWT has no %s claim", name)
	}
	return value, nil
}

// Present appends a Key Binding JWT (SD-JWT Section 4.3) for the verifier's
// client_id and nonce, and wraps the result in the DCQL-keyed vp_token
// object of OID4VP 1.0 Section 8.1.
func (h *SDJWTHolder) Present(audience, nonce string) (string, error) {
	return h.PresentSerialized(h.Credential, audience, nonce)
}

// PresentSerialized does what Present does for a caller-supplied SD-JWT
// without its Key Binding JWT, so a scenario can bind a serialization it
// altered. A missing trailing "~" is added, since the Key Binding JWT
// follows the last separator.
func (h *SDJWTHolder) PresentSerialized(withoutKB, audience, nonce string) (string, error) {
	if !strings.HasSuffix(withoutKB, "~") {
		withoutKB += "~"
	}
	sdHash := sha256.Sum256([]byte(withoutKB))
	kb := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"aud":     audience,
		"nonce":   nonce,
		"iat":     time.Now().Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(sdHash[:]),
	})
	kb.Header["typ"] = "kb+jwt"
	signed, err := kb.SignedString(h.Key.PrivateKey)
	if err != nil {
		return "", err
	}
	return VPToken(withoutKB + signed)
}

// VPToken wraps one presentation in the DCQL-keyed vp_token object of
// OID4VP 1.0 Section 8.1.
func VPToken(presentation string) (string, error) {
	vpToken, err := json.Marshal(map[string][]string{DCQLCredentialID: {presentation}})
	if err != nil {
		return "", err
	}
	return string(vpToken), nil
}
