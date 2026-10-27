package capture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// The conformance client's Wallet side of an anonymous Pre-Authorized Code
// issuance (OID4VCI 1.0 Sections 3.5, 6, 7 and 8), shared by the scenario
// packages. Everything here is preparation sent through Env.Setup; each
// scenario records its own subject exchange.

// IssuedConfiguration is the Credential Configuration the scenarios request
// unless one needs another. It is a non-HAIP SD-JWT VC configuration, so the
// Token Request needs neither client attestation nor DPoP and the Access
// Token is a plain Bearer token.
const IssuedConfiguration = "UniversityDegreeCredentialSDJWT"

// PreAuthorizedOfferLifetime is how long the issuer keeps an offer's
// pre-authorized code redeemable.
const PreAuthorizedOfferLifetime = 15 * time.Minute

// CNonceLifetime is how long the issuer keeps a c_nonce usable.
const CNonceLifetime = 5 * time.Minute

// Issuer is the part of the Credential Issuer Metadata (Section 12.2.4) the
// scenarios use, read from the live metadata endpoint.
type Issuer struct {
	// Metadata is the whole metadata object.
	Metadata           map[string]any
	ID                 string
	Credential         string
	Nonce              string
	DeferredCredential string
	Notification       string
	// RequestKey is the first encryption key in credential_request_encryption.jwks.
	RequestKey *jose.JSONWebKey
	// RequestEnc is credential_request_encryption.enc_values_supported.
	RequestEnc []string
	// ResponseAlg and ResponseEnc are credential_response_encryption's
	// alg_values_supported and enc_values_supported.
	ResponseAlg []string
	ResponseEnc []string
}

// IssuerMetadataURL is the Section 12.2.2 well-known location for the issuer
// identifier <base>/oid4vci.
func IssuerMetadataURL(env *Env) string {
	return env.BaseURL + "/.well-known/openid-credential-issuer/oid4vci"
}

// DiscoverIssuer reads the Credential Issuer Metadata, as a Wallet does
// before it builds proofs (aud is credential_issuer) or calls an endpoint.
func DiscoverIssuer(ctx context.Context, env *Env) (*Issuer, error) {
	req, err := http.NewRequest(http.MethodGet, IssuerMetadataURL(env), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("credential issuer metadata answered %d %s", resp.Status, Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return nil, err
	}
	return ParseIssuerMetadata(body)
}

// ParseIssuerMetadata reads Issuer from a metadata object, whether it came
// as JSON or as the claims of signed metadata.
func ParseIssuerMetadata(body map[string]any) (*Issuer, error) {
	issuer := &Issuer{Metadata: body}
	issuer.ID, _ = body["credential_issuer"].(string)
	issuer.Credential, _ = body["credential_endpoint"].(string)
	issuer.Nonce, _ = body["nonce_endpoint"].(string)
	issuer.DeferredCredential, _ = body["deferred_credential_endpoint"].(string)
	issuer.Notification, _ = body["notification_endpoint"].(string)
	if issuer.ID == "" || issuer.Credential == "" || issuer.Nonce == "" {
		return nil, fmt.Errorf("credential issuer metadata lacks credential_issuer, credential_endpoint or nonce_endpoint")
	}
	if requestEncryption, ok := body["credential_request_encryption"].(map[string]any); ok {
		issuer.RequestEnc = stringList(requestEncryption["enc_values_supported"])
		encoded, err := json.Marshal(requestEncryption["jwks"])
		if err != nil {
			return nil, err
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(encoded, &set); err != nil {
			return nil, fmt.Errorf("parse credential_request_encryption.jwks: %w", err)
		}
		for i := range set.Keys {
			if set.Keys[i].Use == "" || set.Keys[i].Use == "enc" {
				issuer.RequestKey = &set.Keys[i]
				break
			}
		}
	}
	if responseEncryption, ok := body["credential_response_encryption"].(map[string]any); ok {
		issuer.ResponseAlg = stringList(responseEncryption["alg_values_supported"])
		issuer.ResponseEnc = stringList(responseEncryption["enc_values_supported"])
	}
	return issuer, nil
}

func stringList(raw any) []string {
	values, _ := raw.([]any)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if s, ok := value.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// FirstRequestEnc is the first enc value credential_request_encryption advertises.
func (i *Issuer) FirstRequestEnc() (string, error) {
	if len(i.RequestEnc) == 0 {
		return "", fmt.Errorf("credential_request_encryption advertises no enc_values_supported")
	}
	return i.RequestEnc[0], nil
}

// OfferOptions select the pre-authorized offer the issuer creates.
type OfferOptions struct {
	// Deferred asks for an offer whose Credential Request is answered with
	// HTTP 202 and a transaction_id (Section 8.3).
	Deferred bool
	// ConfigurationID defaults to IssuedConfiguration.
	ConfigurationID string
	// TxCode asks for a tx_code-protected offer (Section 4.1.1).
	TxCode bool
}

// Offer is a pre-authorized code and, for a tx_code-protected offer, the
// out-of-band tx_code value the issuer hands to the End-User.
type Offer struct {
	Code            string
	TxCode          string
	ConfigurationID string
}

// CreatePreAuthorizedOffer has the issuer create a pre-authorized offer.
func CreatePreAuthorizedOffer(ctx context.Context, env *Env, opts OfferOptions) (*Offer, error) {
	path := "/oid4vci/offers/pre-authorized"
	if opts.Deferred {
		path += "/deferred"
	}
	offer := &Offer{ConfigurationID: opts.ConfigurationID}
	if offer.ConfigurationID == "" {
		offer.ConfigurationID = IssuedConfiguration
	}
	request := map[string]any{"credential_configuration_ids": []string{offer.ConfigurationID}}
	if opts.TxCode {
		request["tx_code_required"] = true
	}
	req, err := NewJSON(env.BaseURL+path, request)
	if err != nil {
		return nil, err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusCreated {
		return nil, fmt.Errorf("offer creation answered %d %s", resp.Status, Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return nil, err
	}
	offer.Code, _ = body["pre_authorized_code"].(string)
	if offer.Code == "" {
		return nil, fmt.Errorf("offer response has no pre_authorized_code")
	}
	if opts.TxCode {
		if offer.TxCode, _ = body["tx_code_oob_value"].(string); offer.TxCode == "" {
			return nil, fmt.Errorf("offer response has no tx_code_oob_value")
		}
	}
	// Until it is redeemed, the code is usable by anyone holding it (and
	// the tx_code, when there is one).
	env.NoteExpiry(PreAuthorizedOfferLifetime)
	return offer, nil
}

// PreAuthorizedTokenForm is the Section 6.1 Token Request for a
// pre-authorized code, with tx_code when one is given.
func PreAuthorizedTokenForm(code, txCode string) url.Values {
	form := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {code},
	}
	if txCode != "" {
		form.Set("tx_code", txCode)
	}
	return form
}

// GrantOptions select the offer and how its code is redeemed.
type GrantOptions struct {
	OfferOptions
	// AuthorizationDetails requests the configuration through
	// authorization_details (Section 5.1.1), so the Token Response returns a
	// credential_identifier.
	AuthorizationDetails bool
}

// Grant is an Access Token from a Pre-Authorized Code Token Request and,
// when authorization_details was used, the credential_identifier the Token
// Response bound to it (Section 6.2).
type Grant struct {
	AccessToken          string
	CredentialIdentifier string
	ConfigurationID      string
}

// PreAuthorizedGrant creates an offer and redeems its pre-authorized code
// anonymously at /oid4vci/token.
func PreAuthorizedGrant(ctx context.Context, env *Env, issuer *Issuer, opts GrantOptions) (*Grant, error) {
	offer, err := CreatePreAuthorizedOffer(ctx, env, opts.OfferOptions)
	if err != nil {
		return nil, err
	}
	form := PreAuthorizedTokenForm(offer.Code, offer.TxCode)
	if opts.AuthorizationDetails {
		details, err := json.Marshal([]map[string]any{{
			"type":                        "openid_credential",
			"credential_configuration_id": offer.ConfigurationID,
			"locations":                   []string{issuer.ID},
		}})
		if err != nil {
			return nil, err
		}
		form.Set("authorization_details", string(details))
	}
	req, err := NewForm(env.BaseURL+"/oid4vci/token", form)
	if err != nil {
		return nil, err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("token endpoint answered %d %s", resp.Status, Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return nil, err
	}
	grant := &Grant{ConfigurationID: offer.ConfigurationID}
	if grant.AccessToken, _ = body["access_token"].(string); grant.AccessToken == "" {
		return nil, fmt.Errorf("token response has no access_token")
	}
	// The issuer has no revocation endpoint for these tokens, so the run
	// waits out their lifetime before publishing.
	expiresIn, _ := body["expires_in"].(float64)
	if expiresIn <= 0 {
		return nil, fmt.Errorf("token response has no positive expires_in")
	}
	env.NoteExpiry(time.Duration(expiresIn) * time.Second)
	if opts.AuthorizationDetails {
		if grant.CredentialIdentifier, err = firstCredentialIdentifier(body); err != nil {
			return nil, err
		}
	}
	return grant, nil
}

func firstCredentialIdentifier(tokenResponse map[string]any) (string, error) {
	details, _ := tokenResponse["authorization_details"].([]any)
	for _, raw := range details {
		detail, _ := raw.(map[string]any)
		identifiers, _ := detail["credential_identifiers"].([]any)
		for _, identifier := range identifiers {
			if value, _ := identifier.(string); value != "" {
				return value, nil
			}
		}
	}
	return "", fmt.Errorf("token response has no authorization_details credential_identifiers")
}

// CredentialRequest is the Section 8.2 Credential Request for this grant
// carrying the given jwt proofs: credential_identifier when the Token
// Response returned one, which then excludes credential_configuration_id,
// otherwise credential_configuration_id.
func (g *Grant) CredentialRequest(proofs ...string) map[string]any {
	body := map[string]any{"proofs": map[string]any{"jwt": proofs}}
	if g.CredentialIdentifier != "" {
		body["credential_identifier"] = g.CredentialIdentifier
	} else {
		body["credential_configuration_id"] = g.ConfigurationID
	}
	return body
}

// FreshNonce obtains a c_nonce from the Nonce Endpoint (Section 7.1).
func FreshNonce(ctx context.Context, env *Env, issuer *Issuer) (string, error) {
	req, err := http.NewRequest(http.MethodPost, issuer.Nonce, nil)
	if err != nil {
		return "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("nonce endpoint answered %d %s", resp.Status, Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return "", err
	}
	nonce, _ := body["c_nonce"].(string)
	if nonce == "" {
		return "", fmt.Errorf("nonce response has no c_nonce")
	}
	env.NoteExpiry(CNonceLifetime)
	return nonce, nil
}

// HolderKey is a fresh P-256 key the conformance client proves possession
// of in a jwt key proof (Appendix F.1), and that issued Credentials are
// bound to.
type HolderKey struct {
	*ecdsa.PrivateKey
}

// NewHolderKey generates a fresh P-256 key.
func NewHolderKey() (*HolderKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &HolderKey{PrivateKey: key}, nil
}

// PublicJWK is the public key as a jwk JOSE header or cnf claim carries it.
func (k *HolderKey) PublicJWK() (map[string]any, error) {
	// The uncompressed SEC 1 encoding is 0x04 || X || Y, 32 bytes each for P-256.
	point, err := k.PublicKey.Bytes()
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

// Proof builds a jwt key proof (Appendix F.1): typ openid4vci-proof+jwt,
// alg ES256, the public jwk, aud set to the Credential Issuer Identifier,
// iat, and nonce when one is given. iss is omitted because the Access Token
// came from anonymous access to the Token Endpoint, for which Appendix F.1
// says the claim "MUST be omitted".
func (k *HolderKey) Proof(audience, nonce string) (string, error) {
	jwk, err := k.PublicJWK()
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"aud": audience,
		"iat": time.Now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = jwk
	return token.SignedString(k.PrivateKey)
}

// BearerJSON is a JSON POST carrying the Access Token as a Bearer token
// (RFC 6750 Section 2.1).
func BearerJSON(target, accessToken string, body any) (*http.Request, error) {
	req, err := NewJSON(target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	return req, nil
}

// RequestCredential obtains a fresh c_nonce, proves possession of key over
// it, and sends the grant's Credential Request through Setup. It returns the
// response body when the issuer answers with status want: HTTP 200 for an
// immediate Credential, HTTP 202 for a deferred one.
func RequestCredential(ctx context.Context, env *Env, issuer *Issuer, grant *Grant, key *HolderKey, want int) (map[string]any, error) {
	nonce, err := FreshNonce(ctx, env, issuer)
	if err != nil {
		return nil, err
	}
	proof, err := key.Proof(issuer.ID, nonce)
	if err != nil {
		return nil, err
	}
	req, err := BearerJSON(issuer.Credential, grant.AccessToken, grant.CredentialRequest(proof))
	if err != nil {
		return nil, err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != want {
		return nil, fmt.Errorf("credential request answered %d %s", resp.Status, Truncate(resp.Body))
	}
	return resp.JSON()
}

// IssuedCredentials returns the credential strings of a Credential Response's
// credentials array (Section 8.3).
func IssuedCredentials(body map[string]any) ([]string, error) {
	entries, _ := body["credentials"].([]any)
	out := make([]string, 0, len(entries))
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		credential, _ := entry["credential"].(string)
		if credential == "" {
			return nil, fmt.Errorf("credentials entry has no credential string")
		}
		out = append(out, credential)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("credential response has no credentials")
	}
	return out, nil
}
