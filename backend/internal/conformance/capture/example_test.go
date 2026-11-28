package capture

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
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
	if !captured.PublishAfter.IsZero() {
		t.Fatalf("a scenario that names no expiry sets no publish time, got %v", captured.PublishAfter)
	}
}

// documentScenario fetches a metadata document from wellKnownPath of a test
// server and reports issuer as the issuer its URL was built from.
func documentScenario(wellKnownPath, issuer string) ExampleScenario {
	return ExampleScenario{
		Description: "A test client reads a metadata document.",
		Actor:       conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *Env) (ExampleResult, error) {
			req, err := http.NewRequest(http.MethodGet, env.BaseURL+wellKnownPath, nil)
			if err != nil {
				return ExampleResult{}, err
			}
			resp, err := env.Do(ctx, req)
			if err != nil {
				return ExampleResult{}, err
			}
			if issuer == "" {
				issuer = env.BaseURL
			}
			return ExampleResult{
				Value:        string(resp.Body),
				Source:       conformance.ExampleSource{Exchange: 0, Message: conformance.ExampleInResponse, Location: "the body"},
				IssuerMember: "issuer",
				Issuer:       issuer,
			}, nil
		},
	}
}

func TestCaptureExampleChecksADocumentAgainstTheIssuerItsURLWasBuiltFrom(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/sample":
			_, _ = w.Write([]byte(`{"issuer":"` + server.URL + `","token_endpoint":"` + server.URL + `/token"}` + "\n"))
		case "/.well-known/other-issuer":
			_, _ = w.Write([]byte(`{"issuer":"https://someone-else.example","token_endpoint":"` + server.URL + `/token"}`))
		default:
			_, _ = w.Write([]byte(`{"issuer":"` + server.URL + `","token_endpoint":"` + server.URL + `/token"}`))
		}
	}))
	t.Cleanup(server.Close)
	field := func(path string) conformance.ExampleField {
		return conformance.ExampleField{Path: path, Reference: "Test Section 1", URL: "https://example.test/spec", Statement: "s"}
	}
	definition := conformance.Example{
		ID:     "test-document",
		Format: conformance.ExampleFormatJSON,
		Fields: []conformance.ExampleField{field("document.issuer"), field("document.token_endpoint")},
	}
	capture := func(scenario ExampleScenario) (*conformance.CapturedExample, error) {
		recorder := NewRecorder(nil)
		return captureExample(context.Background(), NewEnv(server.URL, "", "", recorder, 6000), recorder, definition, scenario)
	}

	captured, err := capture(documentScenario("/.well-known/sample", ""))
	if err != nil {
		t.Fatal(err)
	}
	want := conformance.ExampleVerification{Method: conformance.VerifiedByIssuer, IssuerMember: "issuer", Issuer: server.URL}
	if captured.Verification != want {
		t.Fatalf("verification = %+v, want %+v", captured.Verification, want)
	}
	if !strings.HasSuffix(captured.Value, "\n") || captured.Value != captured.Exchanges[0].Response.Body.Data {
		t.Fatal("the value must be the response body exactly as it was sent")
	}

	for name, scenario := range map[string]ExampleScenario{
		"a document that names another issuer":       documentScenario("/.well-known/other-issuer", ""),
		"a document not at a well-known location":    documentScenario("/metadata", ""),
		"a document fetched from another host":       documentScenario("/.well-known/sample", "https://someone-else.example"),
		"a scenario that names no issuer to compare": withoutIssuer(documentScenario("/.well-known/sample", "")),
	} {
		if _, err := capture(scenario); err == nil {
			t.Errorf("%s must not be captured", name)
		}
	}
}

// sdJWTIssuer is a test SD-JWT VC Issuer: it serves a Credential Response
// and its JWT VC Issuer Metadata, and signs with a certified ES256 key.
type sdJWTIssuer struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	leaf   []byte
	// Overrides a test sets to make the Issuer misbehave.
	metadataIssuer string
	metadataKey    *ecdsa.PublicKey
	extra          string
}

func newSDJWTIssuer(t *testing.T) *sdJWTIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leaf, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &sdJWTIssuer{key: key, leaf: leaf}
	issuer.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/credential" {
			_ = json.NewEncoder(w).Encode(map[string]any{"credentials": []map[string]string{{"credential": issuer.credential(t)}}})
			return
		}
		named, published := issuer.server.URL, &issuer.key.PublicKey
		if issuer.metadataIssuer != "" {
			named = issuer.metadataIssuer
		}
		if issuer.metadataKey != nil {
			published = issuer.metadataKey
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": named,
			"jwks":   jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: published, KeyID: "signer", Algorithm: "ES256"}}},
		})
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

// credential signs an SD-JWT VC with two Disclosures, then appends extra.
func (i *sdJWTIssuer) credential(t *testing.T) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	disclosures := []string{encode([]byte(`["c2FsdC0x","given_name","Alice"]`)), encode([]byte(`["c2FsdC0y","graduation_year",2018]`))}
	digests := make([]string, 0, len(disclosures))
	for _, disclosure := range disclosures {
		sum := sha256.Sum256([]byte(disclosure))
		digests = append(digests, encode(sum[:]))
	}
	payload, err := json.Marshal(map[string]any{"iss": i.server.URL, "vct": "https://example.test/degree", "_sd_alg": "sha-256", "_sd": digests})
	if err != nil {
		t.Fatal(err)
	}
	options := (&jose.SignerOptions{}).WithType("dc+sd-jwt").WithHeader("kid", "signer").
		WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(i.leaf)})
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: i.key}, options)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact + "~" + strings.Join(disclosures, "~") + "~" + i.extra
}

func sdJWTScenario() ExampleScenario {
	return ExampleScenario{
		Description: "A test wallet requests a credential and reads the Issuer's metadata.",
		Actor:       conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *Env) (ExampleResult, error) {
			get := func(path string) (*Response, error) {
				req, err := http.NewRequest(http.MethodGet, env.BaseURL+path, nil)
				if err != nil {
					return nil, err
				}
				return env.Do(ctx, req)
			}
			resp, err := get("/credential")
			if err != nil {
				return ExampleResult{}, err
			}
			body, err := resp.JSON()
			if err != nil {
				return ExampleResult{}, err
			}
			credentials, err := IssuedCredentials(body)
			if err != nil {
				return ExampleResult{}, err
			}
			if _, err := get("/.well-known/jwt-vc-issuer"); err != nil {
				return ExampleResult{}, err
			}
			metadataExchange := 1
			return ExampleResult{
				Value:        credentials[0],
				Source:       conformance.ExampleSource{Exchange: 0, Message: conformance.ExampleInResponse, Location: "the credential member"},
				JWKSExchange: &metadataExchange,
			}, nil
		},
	}
}

func TestCaptureExampleVerifiesAnSDJWTVCThroughItsIssuersMetadata(t *testing.T) {
	field := func(path string) conformance.ExampleField {
		return conformance.ExampleField{Path: path, Reference: "Test Section 1", URL: "https://example.test/spec", Statement: "s"}
	}
	definition := conformance.Example{
		ID:     "test-sd-jwt",
		Format: conformance.ExampleFormatSDJWT,
		Fields: []conformance.ExampleField{
			field("header.alg"), field("header.kid"), field("header.typ"), field("header.x5c"),
			field("payload._sd"), field("payload._sd_alg"), field("payload.iss"), field("payload.vct"),
			field("disclosure.salt"), field("disclosure.name"), field("disclosure.value"),
		},
	}
	capture := func(issuer *sdJWTIssuer) (*conformance.CapturedExample, error) {
		recorder := NewRecorder(nil)
		return captureExample(context.Background(), NewEnv(issuer.server.URL, "", "", recorder, 6000), recorder, definition, sdJWTScenario())
	}

	captured, err := capture(newSDJWTIssuer(t))
	if err != nil {
		t.Fatal(err)
	}
	verification := captured.Verification
	if verification.Method != conformance.VerifiedByIssuerMetadata || verification.Algorithm != "ES256" || verification.KeyID != "signer" ||
		verification.JWKSExchange == nil || *verification.JWKSExchange != 1 {
		t.Fatalf("verification = %+v", verification)
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uncommitted := base64.RawURLEncoding.EncodeToString([]byte(`["c2FsdC0z","degree","Forged"]`)) + "~"
	for name, misbehave := range map[string]func(*sdJWTIssuer){
		"metadata that names another issuer":             func(i *sdJWTIssuer) { i.metadataIssuer = "https://someone-else.example" },
		"metadata whose key did not sign the JWT":        func(i *sdJWTIssuer) { i.metadataKey = &other.PublicKey },
		"a Disclosure the signed JWT does not commit to": func(i *sdJWTIssuer) { i.extra = uncommitted },
	} {
		issuer := newSDJWTIssuer(t)
		misbehave(issuer)
		if _, err := capture(issuer); err == nil {
			t.Errorf("%s must not be captured", name)
		}
	}
}

// samlParties is a test identity provider and service provider: one server
// that accepts a posted Response and publishes the identity provider's
// metadata.
type samlParties struct {
	server      *httptest.Server
	credentials *xmldsig.Credentials
	// published is the certificate the metadata carries; a test swaps it to
	// make the metadata disagree with the signer.
	published *x509.Certificate
}

func newSAMLParties(t *testing.T) *samlParties {
	t.Helper()
	credentials, err := xmldsig.NewCredentials("https://idp.example")
	if err != nil {
		t.Fatal(err)
	}
	parties := &samlParties{credentials: credentials, published: credentials.Certificate()}
	parties.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acs" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = fmt.Fprintf(w, `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s"><IDPSSODescriptor><KeyDescriptor use="signing">`+
			`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>`+
			`</KeyDescriptor></IDPSSODescriptor></EntityDescriptor>`, parties.server.URL+"/metadata", base64.StdEncoding.EncodeToString(parties.published.Raw))
	}))
	t.Cleanup(parties.server.Close)
	return parties
}

// response builds a Response whose Assertion and whose own element are
// signed, naming issuer in both, and returns it base64-encoded. alter runs
// after signing.
func (p *samlParties) response(t *testing.T, issuer string, alter func(*etree.Element)) string {
	t.Helper()
	document := etree.NewDocument()
	root := document.CreateElement("samlp:Response")
	root.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	root.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	root.CreateAttr("ID", "_response")
	root.CreateAttr("Version", "2.0")
	root.CreateElement("saml:Issuer").SetText(issuer)
	assertion := root.CreateElement("saml:Assertion")
	assertion.CreateAttr("ID", "_assertion")
	assertion.CreateAttr("Version", "2.0")
	assertion.CreateElement("saml:Issuer").SetText(issuer)
	assertion.CreateElement("saml:Subject").CreateElement("saml:NameID").SetText("alice@example.com")
	for _, element := range []*etree.Element{assertion, root} {
		if err := xmldsig.SignEnveloped(element, p.credentials); err != nil {
			t.Fatal(err)
		}
	}
	if alter != nil {
		alter(root)
	}
	serialized, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(serialized)
}

func samlScenario(response string) ExampleScenario {
	return ExampleScenario{
		Description: "A test user agent delivers a Response and reads the identity provider's metadata.",
		Actor:       conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *Env) (ExampleResult, error) {
			post, err := NewForm(env.BaseURL+"/acs", url.Values{"SAMLResponse": {response}, "RelayState": {"r"}})
			if err != nil {
				return ExampleResult{}, err
			}
			if _, err := env.Do(ctx, post); err != nil {
				return ExampleResult{}, err
			}
			get, err := http.NewRequest(http.MethodGet, env.BaseURL+"/metadata", nil)
			if err != nil {
				return ExampleResult{}, err
			}
			if _, err := env.Do(ctx, get); err != nil {
				return ExampleResult{}, err
			}
			metadataExchange := 1
			return ExampleResult{
				Value:        response,
				Source:       conformance.ExampleSource{Exchange: 0, Message: conformance.ExampleInRequest, Location: "the SAMLResponse control", FormField: "SAMLResponse"},
				JWKSExchange: &metadataExchange,
			}, nil
		},
	}
}

func TestCaptureExampleVerifiesASAMLResponseAgainstItsIssuersMetadata(t *testing.T) {
	field := func(path string) conformance.ExampleField {
		return conformance.ExampleField{Path: path, Reference: "Test Section 1", URL: "https://example.test/spec", Statement: "s"}
	}
	definition := conformance.Example{
		ID:     "test-saml",
		Format: conformance.ExampleFormatSAML,
		Fields: []conformance.ExampleField{
			field("response.@ID"), field("response.@Version"), field("response.Issuer"), field("response.Signature"), field("response.Assertion"),
		},
	}
	capture := func(parties *samlParties, response string) (*conformance.CapturedExample, error) {
		recorder := NewRecorder(nil)
		return captureExample(context.Background(), NewEnv(parties.server.URL, "", "", recorder, 6000), recorder, definition, samlScenario(response))
	}

	parties := newSAMLParties(t)
	entityID := parties.server.URL + "/metadata"
	captured, err := capture(parties, parties.response(t, entityID, nil))
	if err != nil {
		t.Fatal(err)
	}
	verification := captured.Verification
	if verification.Method != conformance.VerifiedByXMLSignature || !strings.HasSuffix(verification.Algorithm, "rsa-sha256") ||
		verification.JWKSExchange == nil || *verification.JWKSExchange != 1 {
		t.Fatalf("verification = %+v", verification)
	}
	// A base64 value holds "+" and "/", which the form body percent-encodes:
	// the capture found it by decoding the form, not by searching the bytes.
	if strings.Contains(captured.Exchanges[0].Request.Body.Data, captured.Value) {
		t.Fatal("the test value is not percent-encoded in the body, so it does not exercise form decoding")
	}

	renamed := parties.response(t, entityID, func(root *etree.Element) {
		root.FindElement("./Assertion/Subject/NameID").SetText("mallory@example.com")
	})
	if _, err := capture(parties, renamed); err == nil {
		t.Error("a Response altered after signing must not be captured")
	}
	if _, err := capture(parties, parties.response(t, "https://someone-else.example", nil)); err == nil {
		t.Error("a Response whose Issuer is not the metadata's entityID must not be captured")
	}
	other, err := xmldsig.NewCredentials("https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	parties.published = other.Certificate()
	if _, err := capture(parties, parties.response(t, entityID, nil)); err == nil {
		t.Error("a Response signed with a key the metadata does not publish must not be captured")
	}
}

// withoutIssuer drops what a scenario said about the issuer.
func withoutIssuer(scenario ExampleScenario) ExampleScenario {
	run := scenario.Run
	scenario.Run = func(ctx context.Context, env *Env) (ExampleResult, error) {
		result, err := run(ctx, env)
		result.Issuer, result.IssuerMember = "", ""
		return result, err
	}
	return scenario
}

func TestCaptureExampleCarriesTheExpiryOfAValueThatCannotBeRevoked(t *testing.T) {
	issuer := newExampleIssuer(t)
	env, recorder := issuer.env()
	expires := time.Date(2026, 11, 24, 12, 0, 0, 0, time.FixedZone("AEDT", 11*60*60))
	scenario := tokenScenario()
	run := scenario.Run
	scenario.Run = func(ctx context.Context, env *Env) (ExampleResult, error) {
		result, err := run(ctx, env)
		result.ValueExpires = expires
		return result, err
	}
	captured, err := captureExample(context.Background(), env, recorder, tokenDefinition(), scenario)
	if err != nil {
		t.Fatal(err)
	}
	if !captured.PublishAfter.Equal(expires) || captured.PublishAfter.Location() != time.UTC {
		t.Fatalf("publish_after = %v, want %v in UTC", captured.PublishAfter, expires.UTC())
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

// resourceScenario creates a resource with POST to createPath of a test
// server and retrieves it with GET from the Location header it was given.
func resourceScenario(createPath string) ExampleScenario {
	return ExampleScenario{
		Description: "A test client creates a resource and retrieves it.",
		Actor:       conformance.ActorConformanceClient,
		Run: func(ctx context.Context, env *Env) (ExampleResult, error) {
			create, err := NewJSON(env.BaseURL+createPath, map[string]any{"userName": "test"})
			if err != nil {
				return ExampleResult{}, err
			}
			created, err := env.Do(ctx, create)
			if err != nil {
				return ExampleResult{}, err
			}
			retrieve, err := http.NewRequest(http.MethodGet, created.Header.Get("Location"), nil)
			if err != nil {
				return ExampleResult{}, err
			}
			retrieved, err := env.Do(ctx, retrieve)
			if err != nil {
				return ExampleResult{}, err
			}
			createdExchange := 0
			return ExampleResult{
				Value:           string(retrieved.Body),
				Source:          conformance.ExampleSource{Exchange: 1, Message: conformance.ExampleInResponse, Location: "the body"},
				CreatedExchange: &createdExchange,
			}, nil
		},
	}
}

func TestCaptureExampleChecksAResourceAgainstItsLocation(t *testing.T) {
	var server *httptest.Server
	resource := func(id string) string {
		return `{"id":"` + id + `","meta":{"location":"` + server.URL + `/Users/` + id + `","version":"W/\"1\""},"userName":"test"}` + "\n"
	}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		w.Header().Set("ETag", `W/"1"`)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/Users":
			w.Header().Set("Location", server.URL+"/Users/a1")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(resource("a1")))
		case r.Method == http.MethodGet && r.URL.Path == "/Users/a1":
			w.Header().Set("Content-Location", server.URL+"/Users/a1")
			_, _ = w.Write([]byte(resource("a1")))
		// A service provider that names another URI in Location than the
		// resource names in meta.location.
		case r.Method == http.MethodPost && r.URL.Path == "/elsewhere/Users":
			w.Header().Set("Location", server.URL+"/alias/a1")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(resource("a1")))
		case r.Method == http.MethodGet && r.URL.Path == "/alias/a1":
			w.Header().Set("Content-Location", server.URL+"/Users/a1")
			_, _ = w.Write([]byte(resource("a1")))
		// A service provider that sends no Content-Location header.
		case r.Method == http.MethodPost && r.URL.Path == "/bare/Users":
			w.Header().Set("Location", server.URL+"/Users/b2")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(resource("b2")))
		case r.Method == http.MethodGet && r.URL.Path == "/Users/b2":
			_, _ = w.Write([]byte(resource("b2")))
		// A creation that answers 200 instead of 201.
		case r.Method == http.MethodPost && r.URL.Path == "/ok/Users":
			w.Header().Set("Location", server.URL+"/Users/a1")
			_, _ = w.Write([]byte(resource("a1")))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	field := func(path string) conformance.ExampleField {
		return conformance.ExampleField{Path: path, Reference: "Test Section 1", URL: "https://example.test/spec", Statement: "s"}
	}
	definition := conformance.Example{
		ID:     "test-resource",
		Format: conformance.ExampleFormatJSON,
		Fields: []conformance.ExampleField{field("document.id"), field("document.meta"), field("document.meta.location"), field("document.userName")},
	}
	capture := func(scenario ExampleScenario) (*conformance.CapturedExample, error) {
		recorder := NewRecorder(nil)
		return captureExample(context.Background(), NewEnv(server.URL, "", "", recorder, 6000), recorder, definition, scenario)
	}

	captured, err := capture(resourceScenario("/Users"))
	if err != nil {
		t.Fatal(err)
	}
	verification := captured.Verification
	if verification.Method != conformance.VerifiedByLocation || verification.Location != server.URL+"/Users/a1" ||
		verification.CreatedExchange == nil || *verification.CreatedExchange != 0 {
		t.Fatalf("verification = %+v", verification)
	}
	if captured.Value != captured.Exchanges[1].Response.Body.Data {
		t.Fatal("the value must be the response body exactly as it was sent")
	}

	for name, scenario := range map[string]ExampleScenario{
		"a resource retrieved from another URI than its meta.location": resourceScenario("/elsewhere/Users"),
		"a response with no Content-Location header":                   resourceScenario("/bare/Users"),
		"a creation that was not answered 201":                         resourceScenario("/ok/Users"),
	} {
		if _, err := capture(scenario); err == nil {
			t.Errorf("%s was recorded as verified", name)
		}
	}
}
