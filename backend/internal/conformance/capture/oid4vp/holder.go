package oid4vp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// The conformance client's holder side: it obtains a credential from the
// issuer, reads the verifier's request object, and answers it the way a
// wallet does. Everything it sends is built here or in the capture
// package's shared Wallet side, independently of the product's own
// credential libraries.

// dcqlCredentialID names the single Credential Query in every request the
// conformance client creates.
const dcqlCredentialID = "degree"

// holder is the conformance client's key-bound credential.
type holder struct {
	key *capture.HolderKey
	// credential is the SD-JWT VC without a Key Binding JWT: the
	// issuer-signed JWT and its disclosures, ending in "~".
	credential string
	vct        string
}

// issuedHolder obtains an SD-JWT VC from the issuer through the
// Pre-Authorized Code Flow: metadata, offer, token, nonce and a credential
// request with a jwt proof of the conformance client's own key. It is
// preparation, so every request goes through Setup.
func issuedHolder(ctx context.Context, env *capture.Env) (*holder, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return nil, err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{OfferOptions: capture.OfferOptions{TxCode: true}})
	if err != nil {
		return nil, err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return nil, err
	}
	issued, err := capture.RequestCredential(ctx, env, issuer, grant, key, http.StatusOK)
	if err != nil {
		return nil, err
	}
	credentials, err := capture.IssuedCredentials(issued)
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
	vct, err := sdJWTClaim(credential, "vct")
	if err != nil {
		return nil, err
	}
	return &holder{key: key, credential: credential, vct: vct}, nil
}

func setupJSON(ctx context.Context, env *capture.Env, req *http.Request, want int, what string) (map[string]any, error) {
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != want {
		return nil, fmt.Errorf("%s answered %d %s", what, resp.Status, capture.Truncate(resp.Body))
	}
	return resp.JSON()
}

// sdJWTClaim reads a string claim from an SD-JWT's issuer-signed JWT.
func sdJWTClaim(sdJWT, name string) (string, error) {
	issuerJWT, _, _ := strings.Cut(sdJWT, "~")
	value, err := capture.JWTClaim(issuerJWT, name)
	if err != nil {
		return "", err
	}
	if value == "" {
		return "", fmt.Errorf("issuer-signed JWT has no %s claim", name)
	}
	return value, nil
}

// present appends a Key Binding JWT (SD-JWT Section 4.3) for the verifier's
// client_id and nonce, and wraps the result in the DCQL-keyed vp_token
// object of OID4VP 1.0 Section 8.1.
func (h *holder) present(audience, nonce string) (string, error) {
	withoutKB := h.credential
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
	signed, err := kb.SignedString(h.key.PrivateKey)
	if err != nil {
		return "", err
	}
	vpToken, err := json.Marshal(map[string][]string{dcqlCredentialID: {withoutKB + signed}})
	if err != nil {
		return "", err
	}
	return string(vpToken), nil
}

// requestOptions selects the verifier's request profile.
type requestOptions struct {
	haip         bool
	responseMode string
	vct          string
}

// createRequest has the verifier create an Authorization Request for one
// dc+sd-jwt credential and returns its request_id and request_uri. It is
// preparation; the wallet-facing exchange is the request_uri retrieval.
func createRequest(ctx context.Context, env *capture.Env, opts requestOptions) (requestID, requestURI string, err error) {
	body := map[string]any{
		"response_mode": opts.responseMode,
		"dcql_query": map[string]any{
			"credentials": []map[string]any{{
				"id":     dcqlCredentialID,
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []string{opts.vct}},
			}},
		},
	}
	if opts.haip {
		body["profile"] = "haip"
	}
	req, err := capture.NewJSON(env.BaseURL+"/oid4vp/request/create", body)
	if err != nil {
		return "", "", err
	}
	created, err := setupJSON(ctx, env, req, http.StatusCreated, "request creation")
	if err != nil {
		return "", "", err
	}
	requestID, _ = created["request_id"].(string)
	requestURI, _ = created["request_uri"].(string)
	if requestID == "" || requestURI == "" {
		return "", "", fmt.Errorf("request creation returned no request_id or request_uri")
	}
	env.NoteExpiry(requestObjectLifetime)
	return requestID, requestURI, nil
}

// requestObject is a request object as the wallet received it.
type requestObject struct {
	compact string
	header  map[string]any
	claims  map[string]any
}

func (r *requestObject) claim(name string) string {
	value, _ := r.claims[name].(string)
	return value
}

// fetchRequestObject retrieves the signed request object from request_uri
// (OID4VP 1.0 Section 5.10.1) as a wallet does, recording the exchange.
func fetchRequestObject(ctx context.Context, env *capture.Env, requestURI string) (*requestObject, error) {
	req, err := http.NewRequest(http.MethodGet, requestURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")
	resp, err := env.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("request_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	compact := strings.TrimSpace(string(resp.Body))
	header, claims, err := capture.JWTParts(compact)
	if err != nil {
		return nil, fmt.Errorf("request_uri: %w", err)
	}
	object := &requestObject{compact: compact, header: header, claims: claims}
	return object, nil
}

// encryptResponse encrypts the Authorization Response parameters to the
// verifier's client_metadata.jwks key with ECDH-ES (OID4VP 1.0 Section 8.3),
// copying the key's kid into the JWE protected header.
func encryptResponse(object *requestObject, parameters map[string]any) (string, error) {
	metadata, _ := object.claims["client_metadata"].(map[string]any)
	jwks, _ := metadata["jwks"].(map[string]any)
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		return "", fmt.Errorf("request object client_metadata.jwks carries %d keys, want 1", len(keys))
	}
	rawKey, err := json.Marshal(keys[0])
	if err != nil {
		return "", err
	}
	var recipientKey jose.JSONWebKey
	if err := recipientKey.UnmarshalJSON(rawKey); err != nil {
		return "", fmt.Errorf("parse client_metadata.jwks key: %w", err)
	}
	encValues, _ := metadata["encrypted_response_enc_values_supported"].([]any)
	enc, _ := firstOr(encValues, "A128GCM").(string)
	encrypter, err := jose.NewEncrypter(jose.ContentEncryption(enc), jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       recipientKey.Key,
		KeyID:     recipientKey.KeyID,
	}, nil)
	if err != nil {
		return "", err
	}
	plaintext, err := json.Marshal(parameters)
	if err != nil {
		return "", err
	}
	encrypted, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return encrypted.CompactSerialize()
}

func firstOr(values []any, fallback any) any {
	if len(values) == 0 {
		return fallback
	}
	return values[0]
}

// postResponse sends the Authorization Response to response_uri, recorded.
func postResponse(ctx context.Context, env *capture.Env, object *requestObject, form url.Values) (*capture.Response, error) {
	responseURI := object.claim("response_uri")
	if responseURI == "" {
		return nil, fmt.Errorf("request object has no response_uri")
	}
	req, err := capture.NewForm(responseURI, form)
	if err != nil {
		return nil, err
	}
	return env.Do(ctx, req)
}

// policy is the verifier's decision on a completed request.
type policy struct {
	Allowed     bool     `json:"allowed"`
	Code        string   `json:"code"`
	ReasonCodes []string `json:"reason_codes"`
	Reasons     []string `json:"reasons"`
}

// fetchResult reads the verifier's decision from /oid4vp/result/{id},
// recorded, since a direct_post acknowledgement does not carry it.
func fetchResult(ctx context.Context, env *capture.Env, requestID string) (*policy, error) {
	req, err := http.NewRequest(http.MethodGet, env.BaseURL+"/oid4vp/result/"+url.PathEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("result endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	var body struct {
		Status string `json:"status"`
		Result struct {
			Policy policy `json:"policy"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	if body.Status != "completed" {
		return nil, fmt.Errorf("result status is %q, want completed", body.Status)
	}
	return &body.Result.Policy, nil
}
