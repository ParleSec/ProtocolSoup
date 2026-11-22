package capture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/go-jose/go-jose/v4"
)

// exampleIssuer is a test server that issues an RS256 token on /token,
// publishes its JWK Set on /jwks, and accepts anything on /resource.
type exampleIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	// token, when set, replaces the token /token would sign.
	token string
	// jwksKeyID is the kid the JWK Set publishes the key under.
	jwksKeyID string
}

func newExampleIssuer(t *testing.T) *exampleIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &exampleIssuer{key: key, jwksKeyID: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		token := issuer.token
		if token == "" {
			token = issuer.sign(t, `{"sub":"client"}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": token})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: issuer.jwksKeyID, Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/resource", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	issuer.server = httptest.NewServer(mux)
	t.Cleanup(issuer.server.Close)
	return issuer
}

// sign returns an RS256 compact JWS over payload with kid k1.
func (i *exampleIssuer) sign(t *testing.T, payload string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: i.key, KeyID: "k1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func (i *exampleIssuer) env() (*Env, *Recorder) {
	recorder := NewRecorder(nil)
	return NewEnv(i.server.URL, "", "", recorder, 6000), recorder
}

// tokenScenario fetches /token and /jwks and returns the access_token from
// the first response, verified by the JWK Set in the second.
func tokenScenario() ExampleScenario {
	return ExampleScenario{
		Description: "A test client requests a token and reads the JWK Set.",
		Actor:       conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *Env) (ExampleResult, error) {
			get := func(path string) (*Response, error) {
				req, err := http.NewRequest(http.MethodGet, env.BaseURL+path, nil)
				if err != nil {
					return nil, err
				}
				return env.Do(ctx, req)
			}
			resp, err := get("/token")
			if err != nil {
				return ExampleResult{}, err
			}
			body, err := resp.JSON()
			if err != nil {
				return ExampleResult{}, err
			}
			if _, err := get("/jwks"); err != nil {
				return ExampleResult{}, err
			}
			jwksExchange := 1
			token, _ := body["access_token"].(string)
			return ExampleResult{
				Value:        token,
				Source:       conformance.ExampleSource{Exchange: 0, Message: conformance.ExampleInResponse, Location: "the access_token member"},
				JWKSExchange: &jwksExchange,
			}, nil
		},
	}
}

func tokenDefinition() conformance.Example {
	field := func(path string) conformance.ExampleField {
		return conformance.ExampleField{Path: path, Reference: "Test Section 1", URL: "https://example.test/spec", Statement: "s"}
	}
	return conformance.Example{
		ID:     "test-token",
		Format: conformance.ExampleFormatJWT,
		Fields: []conformance.ExampleField{field("header.alg"), field("header.kid"), field("payload.sub")},
	}
}

func TestCaptureExampleVerifiesAgainstTheFetchedJWKSet(t *testing.T) {
	issuer := newExampleIssuer(t)
	env, recorder := issuer.env()
	captured, err := captureExample(context.Background(), env, recorder, tokenDefinition(), tokenScenario())
	if err != nil {
		t.Fatal(err)
	}
	if captured.ID != "test-token" || len(captured.Exchanges) != 2 || captured.Actor != conformance.ActorConformanceClient {
		t.Fatalf("captured = %+v", captured)
	}
	verification := captured.Verification
	if verification.Method != conformance.VerifiedByJWKS || verification.Algorithm != "RS256" || verification.KeyID != "k1" ||
		verification.JWKSExchange == nil || *verification.JWKSExchange != 1 {
		t.Fatalf("verification = %+v", verification)
	}
	if !strings.Contains(captured.Exchanges[0].Response.Body.Data, captured.Value) {
		t.Fatal("the captured value must be the one the token response carried")
	}
}

func TestCaptureExampleVerifiesAProofUnderItsOwnJWK(t *testing.T) {
	issuer := newExampleIssuer(t)
	env, recorder := issuer.env()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &jose.SignerOptions{EmbedJWK: true})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(`{"htm":"GET"}`))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	scenario := ExampleScenario{
		Description: "A test client sends a proof.",
		Actor:       conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *Env) (ExampleResult, error) {
			req, err := http.NewRequest(http.MethodGet, env.BaseURL+"/resource", nil)
			if err != nil {
				return ExampleResult{}, err
			}
			req.Header.Set("DPoP", proof)
			if _, err := env.Do(ctx, req); err != nil {
				return ExampleResult{}, err
			}
			return ExampleResult{
				Value:  proof,
				Source: conformance.ExampleSource{Exchange: 0, Message: conformance.ExampleInRequest, Location: "the DPoP header"},
			}, nil
		},
	}
	definition := tokenDefinition()
	definition.Fields = []conformance.ExampleField{
		{Path: "header.alg", Reference: "r", URL: "https://example.test", Statement: "s"},
		{Path: "header.jwk", Reference: "r", URL: "https://example.test", Statement: "s"},
		{Path: "payload.htm", Reference: "r", URL: "https://example.test", Statement: "s"},
	}
	captured, err := captureExample(context.Background(), env, recorder, definition, scenario)
	if err != nil {
		t.Fatal(err)
	}
	if captured.Verification.Method != conformance.VerifiedByEmbeddedJWK || captured.Verification.Algorithm != "ES256" ||
		captured.Verification.JWKSExchange != nil || captured.Verification.KeyID != "" {
		t.Fatalf("verification = %+v", captured.Verification)
	}
}

func TestCaptureExampleRefusesAValueItCannotStandBehind(t *testing.T) {
	// forged swaps the payload of a signed token, keeping its signature.
	forged := func(t *testing.T, issuer *exampleIssuer) string {
		parts := strings.Split(issuer.sign(t, `{"sub":"client"}`), ".")
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"someone-else"}`))
		return strings.Join(parts, ".")
	}
	hmacToken := func(t *testing.T) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("a-shared-secret-of-32-bytes-long")}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign([]byte(`{"sub":"client"}`))
		if err != nil {
			t.Fatal(err)
		}
		compact, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return compact
	}

	cases := []struct {
		name    string
		prepare func(t *testing.T, issuer *exampleIssuer, definition *conformance.Example, scenario *ExampleScenario)
		want    string
	}{
		{
			name: "a value that no recorded message carried",
			prepare: func(t *testing.T, issuer *exampleIssuer, _ *conformance.Example, scenario *ExampleScenario) {
				run := scenario.Run
				other := issuer.sign(t, `{"sub":"never-sent"}`)
				scenario.Run = func(ctx context.Context, env *Env) (ExampleResult, error) {
					result, err := run(ctx, env)
					result.Value = other
					return result, err
				}
			},
			want: "the value is not in the recorded response of exchange 0",
		},
		{
			name: "a source exchange that was never recorded",
			prepare: func(_ *testing.T, _ *exampleIssuer, _ *conformance.Example, scenario *ExampleScenario) {
				run := scenario.Run
				scenario.Run = func(ctx context.Context, env *Env) (ExampleResult, error) {
					result, err := run(ctx, env)
					result.Source.Exchange = 7
					return result, err
				}
			},
			want: "source exchange 7 is not one of the 2 recorded",
		},
		{
			name: "a payload the signature does not cover",
			prepare: func(t *testing.T, issuer *exampleIssuer, _ *conformance.Example, _ *ExampleScenario) {
				issuer.token = forged(t, issuer)
			},
			want: "the value's signature does not verify",
		},
		{
			name: "a kid the JWK Set does not hold",
			prepare: func(_ *testing.T, issuer *exampleIssuer, _ *conformance.Example, _ *ExampleScenario) {
				issuer.jwksKeyID = "rotated-away"
			},
			want: `kid "k1" selects 0 keys in the JWK Set`,
		},
		{
			name: "a symmetric algorithm",
			prepare: func(t *testing.T, issuer *exampleIssuer, definition *conformance.Example, _ *ExampleScenario) {
				issuer.token = hmacToken(t)
				definition.Fields = definition.Fields[:1]
				definition.Fields = append(definition.Fields, conformance.ExampleField{Path: "payload.sub", Reference: "r", URL: "https://example.test", Statement: "s"})
			},
			want: "parse the value as a JWS",
		},
		{
			name: "a member the definition does not annotate",
			prepare: func(_ *testing.T, _ *exampleIssuer, definition *conformance.Example, _ *ExampleScenario) {
				definition.Fields = definition.Fields[:2]
			},
			want: "no field annotates payload.sub",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newExampleIssuer(t)
			env, recorder := issuer.env()
			definition, scenario := tokenDefinition(), tokenScenario()
			tc.prepare(t, issuer, &definition, &scenario)
			captured, err := captureExample(context.Background(), env, recorder, definition, scenario)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("captureExample = %+v, %v; want an error containing %q", captured, err, tc.want)
			}
			if captured != nil {
				t.Fatal("a refused value must not be returned")
			}
		})
	}
}
