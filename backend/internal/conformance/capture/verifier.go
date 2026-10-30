package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The conformance client's side of an OID4VP verifier exchange: it has the
// verifier create a request, reads the request object as a wallet does, and
// answers it. Shared by every scenario package that presents to the
// verifier.

// RequestObjectLifetime is how long the verifier keeps a request session.
const RequestObjectLifetime = 5 * time.Minute

// DCQLCredentialID names the single Credential Query in every request the
// conformance client creates.
const DCQLCredentialID = "degree"

// SDJWTQuery is a DCQL Credential Query for one dc+sd-jwt credential of vct.
func SDJWTQuery(vct string) map[string]any {
	return map[string]any{
		"id":     DCQLCredentialID,
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []string{vct}},
	}
}

// RequestOptions selects the verifier's request profile and the one
// Credential Query it asks for.
type RequestOptions struct {
	HAIP         bool
	ResponseMode string
	Credential   map[string]any
}

// CreateRequest has the verifier create an Authorization Request and returns
// its request_id and request_uri. It is preparation; the wallet-facing
// exchange is the request_uri retrieval.
func CreateRequest(ctx context.Context, env *Env, opts RequestOptions) (requestID, requestURI string, err error) {
	body := map[string]any{
		"response_mode": opts.ResponseMode,
		"dcql_query":    map[string]any{"credentials": []map[string]any{opts.Credential}},
	}
	if opts.HAIP {
		body["profile"] = "haip"
	}
	req, err := NewJSON(env.BaseURL+"/oid4vp/request/create", body)
	if err != nil {
		return "", "", err
	}
	created, err := SetupJSON(ctx, env, req, http.StatusCreated, "request creation")
	if err != nil {
		return "", "", err
	}
	requestID, _ = created["request_id"].(string)
	requestURI, _ = created["request_uri"].(string)
	if requestID == "" || requestURI == "" {
		return "", "", fmt.Errorf("request creation returned no request_id or request_uri")
	}
	env.NoteExpiry(RequestObjectLifetime)
	return requestID, requestURI, nil
}

// SetupJSON sends a preparation request and decodes its JSON body, failing
// unless the status is want.
func SetupJSON(ctx context.Context, env *Env, req *http.Request, want int, what string) (map[string]any, error) {
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != want {
		return nil, fmt.Errorf("%s answered %d %s", what, resp.Status, Truncate(resp.Body))
	}
	return resp.JSON()
}

// RequestObject is a request object as the wallet received it.
type RequestObject struct {
	Compact string
	Header  map[string]any
	Claims  map[string]any
}

// Claim reads a string claim of the request object.
func (r *RequestObject) Claim(name string) string {
	value, _ := r.Claims[name].(string)
	return value
}

// FetchRequestObject retrieves the signed request object from request_uri
// (OID4VP 1.0 Section 5.10.1) as a wallet does, recording the exchange.
func FetchRequestObject(ctx context.Context, env *Env, requestURI string) (*RequestObject, error) {
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
		return nil, fmt.Errorf("request_uri answered %d %s", resp.Status, Truncate(resp.Body))
	}
	compact := strings.TrimSpace(string(resp.Body))
	header, claims, err := JWTParts(compact)
	if err != nil {
		return nil, fmt.Errorf("request_uri: %w", err)
	}
	return &RequestObject{Compact: compact, Header: header, Claims: claims}, nil
}

// EncryptResponse encrypts the Authorization Response parameters to the
// verifier's client_metadata.jwks key with ECDH-ES (OID4VP 1.0 Section 8.3),
// copying the key's kid into the JWE protected header.
func EncryptResponse(object *RequestObject, parameters map[string]any) (string, error) {
	metadata, _ := object.Claims["client_metadata"].(map[string]any)
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
	enc := "A128GCM"
	if encValues, _ := metadata["encrypted_response_enc_values_supported"].([]any); len(encValues) > 0 {
		if first, ok := encValues[0].(string); ok {
			enc = first
		}
	}
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

// PostResponse sends the Authorization Response to response_uri, recorded.
func PostResponse(ctx context.Context, env *Env, object *RequestObject, form url.Values) (*Response, error) {
	responseURI := object.Claim("response_uri")
	if responseURI == "" {
		return nil, fmt.Errorf("request object has no response_uri")
	}
	req, err := NewForm(responseURI, form)
	if err != nil {
		return nil, err
	}
	return env.Do(ctx, req)
}

// Policy is the verifier's decision on a completed request.
type Policy struct {
	Allowed     bool     `json:"allowed"`
	Code        string   `json:"code"`
	ReasonCodes []string `json:"reason_codes"`
	Reasons     []string `json:"reasons"`
}

// HasReason reports whether the decision carries reason code, with a reason
// message containing detail when detail is not empty.
func (p *Policy) HasReason(code, detail string) bool {
	for _, reasonCode := range p.ReasonCodes {
		if reasonCode != code {
			continue
		}
		if detail == "" {
			return true
		}
		for _, reason := range p.Reasons {
			if strings.Contains(reason, detail) {
				return true
			}
		}
	}
	return false
}

// FetchResult reads the verifier's decision from /oid4vp/result/{id},
// recorded, since a direct_post acknowledgement does not carry it.
func FetchResult(ctx context.Context, env *Env, requestID string) (*Policy, error) {
	req, err := http.NewRequest(http.MethodGet, env.BaseURL+"/oid4vp/result/"+url.PathEscape(requestID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := env.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("result endpoint answered %d %s", resp.Status, Truncate(resp.Body))
	}
	var body struct {
		Status string `json:"status"`
		Result struct {
			Policy Policy `json:"policy"`
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
