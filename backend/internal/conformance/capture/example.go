package capture

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/go-jose/go-jose/v4"
)

// ExampleScenario captures the value of one registry example: it performs
// the real exchanges that issue or carry the message and says where in them
// the message was.
type ExampleScenario struct {
	Description string
	Actor       conformance.ArtefactActor
	Run         func(ctx context.Context, env *Env) (ExampleResult, error)
}

// ExampleResult is what an example scenario found.
type ExampleResult struct {
	// Value is the message as the source exchange carried it.
	Value string
	// Source locates Value in the exchanges the scenario recorded.
	Source conformance.ExampleSource
	// JWKSExchange indexes the recorded exchange that fetched the keys that
	// verify Value: a JWK Set, or for an SD-JWT VC the Issuer's JWT VC Issuer
	// Metadata. It is nil for a value that carries its own public key in a
	// jwk header parameter.
	JWKSExchange *int
	// ValueExpires is when Value stops being acceptable, for a value that
	// cannot be revoked and outlives the run, such as an ID Token. The
	// example is not published before then. It is zero for a value the
	// scenario revoked or that is good for one use only.
	ValueExpires time.Time
	// IssuerMember and Issuer are for a metadata document: the member that
	// names its issuer, and the issuer identifier the scenario built the
	// request URL from.
	IssuerMember string
	Issuer       string
	// CreatedExchange is for a SCIM resource: it indexes the recorded
	// exchange whose 201 response created the resource.
	CreatedExchange *int
}

// kindExample labels a Mismatch that concerns an example rather than a
// requirement's passing or failing artefact.
const kindExample conformance.ArtefactKind = "example"

// exampleScenarios maps a registry example ID to its scenario. Package
// scenarios checks every registry example is covered.
var exampleScenarios = map[string]ExampleScenario{}

// RegisterExample records how example id is captured. Scenario packages
// call it from init; registering an ID twice is a programming error.
func RegisterExample(id string, scenario ExampleScenario) {
	if _, exists := exampleScenarios[id]; exists {
		panic("capture: duplicate example scenario for " + id)
	}
	exampleScenarios[id] = scenario
}

// ExampleScenarios returns a copy of the registered example scenarios.
func ExampleScenarios() map[string]ExampleScenario {
	out := make(map[string]ExampleScenario, len(exampleScenarios))
	for id, scenario := range exampleScenarios {
		out[id] = scenario
	}
	return out
}

// captureExample runs one example scenario and returns its value only when
// the value is provably what it is shown as: it sits in the recorded
// exchange the scenario names, every member of it is annotated by the
// registry definition, and its signature verifies. Anything else is an
// error, so an example page never shows a value the run could not stand
// behind.
func captureExample(ctx context.Context, env *Env, recorder *Recorder, definition conformance.Example, scenario ExampleScenario) (*conformance.CapturedExample, error) {
	_ = recorder.Take()
	result, err := scenario.Run(ctx, env)
	exchanges := recorder.Take()
	if err != nil {
		return nil, err
	}
	if err := onTheWire(exchanges, result.Source, result.Value); err != nil {
		return nil, err
	}
	if err := definition.CheckExample(result.Value); err != nil {
		return nil, err
	}
	var verification conformance.ExampleVerification
	switch definition.Format {
	case conformance.ExampleFormatJSON:
		if result.CreatedExchange != nil {
			verification, err = verifyResource(result, exchanges)
		} else {
			verification, err = verifyDocument(result, exchanges)
		}
	case conformance.ExampleFormatSDJWT:
		verification, err = verifySDJWTVC(result.Value, exchanges, result.JWKSExchange)
	case conformance.ExampleFormatSAML:
		verification, err = verifySAMLMessage(result.Value, exchanges, result.JWKSExchange)
	default:
		verification, err = verifyExample(result.Value, exchanges, result.JWKSExchange)
	}
	if err != nil {
		return nil, err
	}
	return &conformance.CapturedExample{
		ID:           definition.ID,
		Actor:        scenario.Actor,
		Description:  scenario.Description,
		Value:        result.Value,
		Source:       result.Source,
		Verification: verification,
		Exchanges:    exchanges,
		PublishAfter: result.ValueExpires.UTC(),
	}, nil
}

// onTheWire confirms value appears in the message source names.
func onTheWire(exchanges []lookingglass.CapturedExchange, source conformance.ExampleSource, value string) error {
	if value == "" {
		return fmt.Errorf("the scenario returned no value")
	}
	if source.Exchange < 0 || source.Exchange >= len(exchanges) {
		return fmt.Errorf("source exchange %d is not one of the %d recorded", source.Exchange, len(exchanges))
	}
	var message lookingglass.CapturedMessage
	switch source.Message {
	case conformance.ExampleInRequest:
		message = exchanges[source.Exchange].Request
	case conformance.ExampleInResponse:
		message = exchanges[source.Exchange].Response
	default:
		return fmt.Errorf("source message %q is neither request nor response", source.Message)
	}
	if source.Location == "" {
		return fmt.Errorf("the scenario did not say where in the %s the value was", source.Message)
	}
	raw, err := payloadBytes(message.Raw)
	if err != nil {
		return err
	}
	if source.FormField != "" {
		// A form body carries the value percent-encoded, so it is compared
		// after form decoding: it must be the one value of that control.
		body, err := payloadBytes(message.Body)
		if err != nil {
			return err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return fmt.Errorf("parse the %s of exchange %d as a form: %w", source.Message, source.Exchange, err)
		}
		if controls := form[source.FormField]; len(controls) != 1 || controls[0] != value {
			return fmt.Errorf("the value is not the %s control of the recorded %s of exchange %d", source.FormField, source.Message, source.Exchange)
		}
		return nil
	}
	if !bytes.Contains(raw, []byte(value)) {
		return fmt.Errorf("the value is not in the recorded %s of exchange %d", source.Message, source.Exchange)
	}
	return nil
}

// payloadBytes returns the bytes a recorded payload holds.
func payloadBytes(payload *lookingglass.CapturedPayload) ([]byte, error) {
	if payload == nil {
		return nil, nil
	}
	if payload.Encoding == "base64" {
		return base64.StdEncoding.DecodeString(payload.Data)
	}
	return []byte(payload.Data), nil
}

// verifySDJWTVC checks an SD-JWT VC the way a recipient must before using
// it, with the key found through JWT VC Issuer Metadata (SD-JWT VC draft 11
// Section 3.5). Section 5.3: "The issuer value returned MUST be identical to
// the iss value of the JWT. If these values are not identical, the data
// contained in the response MUST NOT be used." It also holds the Issuer to
// what it claims by carrying x5c, that the end-entity certificate has the
// same key, and checks every Disclosure against the signed digests: RFC 9901
// Section 7.1 rejects an SD-JWT when a Disclosure's digest is not in the
// payload or is found more than once.
func verifySDJWTVC(value string, exchanges []lookingglass.CapturedExchange, metadataExchange *int) (conformance.ExampleVerification, error) {
	var none conformance.ExampleVerification
	if metadataExchange == nil || *metadataExchange < 0 || *metadataExchange >= len(exchanges) {
		return none, fmt.Errorf("the scenario did not name the exchange that fetched the JWT VC Issuer Metadata")
	}
	segments := strings.Split(value, "~")
	if len(segments) < 2 || segments[len(segments)-1] != "" {
		return none, fmt.Errorf("the value is not an SD-JWT without a Key Binding JWT: it does not end with ~")
	}
	issuerSigned := segments[0]
	signed, err := jose.ParseSigned(issuerSigned, exampleSignatureAlgorithms)
	if err != nil {
		return none, fmt.Errorf("parse the Issuer-signed JWT: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return none, fmt.Errorf("the Issuer-signed JWT carries %d signatures, want 1", len(signed.Signatures))
	}
	header := signed.Signatures[0].Header
	rawHeader, claims, err := JWTParts(issuerSigned)
	if err != nil {
		return none, err
	}

	body, err := payloadBytes(exchanges[*metadataExchange].Response.Body)
	if err != nil {
		return none, err
	}
	var metadata struct {
		Issuer string             `json:"issuer"`
		JWKS   jose.JSONWebKeySet `json:"jwks"`
	}
	if err := json.Unmarshal(body, &metadata); err != nil {
		return none, fmt.Errorf("parse the JWT VC Issuer Metadata from exchange %d: %w", *metadataExchange, err)
	}
	if iss, _ := claims["iss"].(string); iss == "" || iss != metadata.Issuer {
		return none, fmt.Errorf("the JWT VC Issuer Metadata issuer %q is not the credential's iss %q", metadata.Issuer, iss)
	}
	matches := metadata.JWKS.Key(header.KeyID)
	if header.KeyID == "" || len(matches) != 1 {
		return none, fmt.Errorf("kid %q selects %d keys in the JWT VC Issuer Metadata, want 1", header.KeyID, len(matches))
	}
	key := matches[0]
	if _, err := signed.Verify(&key); err != nil {
		return none, fmt.Errorf("the Issuer-signed JWT's signature does not verify: %w", err)
	}

	chain, _ := rawHeader["x5c"].([]any)
	if len(chain) == 0 {
		return none, fmt.Errorf("the Issuer-signed JWT carries no x5c")
	}
	leafText, _ := chain[0].(string)
	leafDER, err := base64.StdEncoding.DecodeString(leafText)
	if err != nil {
		return none, fmt.Errorf("decode the x5c end-entity certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return none, fmt.Errorf("parse the x5c end-entity certificate: %w", err)
	}
	certified, err := (&jose.JSONWebKey{Key: leaf.PublicKey}).Thumbprint(crypto.SHA256)
	if err != nil {
		return none, err
	}
	published, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return none, err
	}
	if !bytes.Equal(certified, published) {
		return none, fmt.Errorf("the x5c end-entity certificate does not carry the key the JWT VC Issuer Metadata publishes")
	}

	if alg, present := claims["_sd_alg"]; present && alg != "sha-256" {
		return none, fmt.Errorf("_sd_alg is %v; only sha-256 Disclosures can be checked", alg)
	}
	committed := map[string]int{}
	digests, _ := claims["_sd"].([]any)
	for _, digest := range digests {
		text, _ := digest.(string)
		committed[text]++
	}
	for _, disclosure := range segments[1 : len(segments)-1] {
		sum := sha256.Sum256([]byte(disclosure))
		digest := base64.RawURLEncoding.EncodeToString(sum[:])
		if committed[digest] != 1 {
			return none, fmt.Errorf("a Disclosure's digest %s appears %d times in _sd, want 1", digest, committed[digest])
		}
	}

	index := *metadataExchange
	return conformance.ExampleVerification{
		Method:       conformance.VerifiedByIssuerMetadata,
		Algorithm:    header.Algorithm,
		KeyID:        header.KeyID,
		JWKSExchange: &index,
	}, nil
}

// verifyDocument checks a metadata document the way its consumer must. The
// document is the whole body of the response that carried it, the request
// went to the issuer's own host at a well-known location, and the member
// that names the issuer equals the issuer identifier the URL was built from
// (RFC 8414 Section 3.3: "The "issuer" value returned MUST be identical to
// the authorization server's issuer identifier value into which the
// well-known URI string was inserted to create the URL used to retrieve the
// metadata.").
func verifyDocument(result ExampleResult, exchanges []lookingglass.CapturedExchange) (conformance.ExampleVerification, error) {
	var none conformance.ExampleVerification
	if result.Issuer == "" || result.IssuerMember == "" {
		return none, fmt.Errorf("a document example needs the issuer its URL was built from and the member that names it")
	}
	if result.Source.Message != conformance.ExampleInResponse {
		return none, fmt.Errorf("a document example is the body of a response, not of a %s", result.Source.Message)
	}
	exchange := exchanges[result.Source.Exchange]
	body, err := payloadBytes(exchange.Response.Body)
	if err != nil {
		return none, err
	}
	if string(body) != result.Value {
		return none, fmt.Errorf("the value is not the whole body of the response in exchange %d", result.Source.Exchange)
	}
	issuer, err := url.Parse(result.Issuer)
	if err != nil {
		return none, fmt.Errorf("parse the issuer: %w", err)
	}
	requested, err := url.Parse(exchange.Request.URL)
	if err != nil {
		return none, fmt.Errorf("parse the request URL: %w", err)
	}
	if requested.Scheme != issuer.Scheme || requested.Host != issuer.Host || !strings.Contains(requested.Path, "/.well-known/") {
		return none, fmt.Errorf("the document was fetched from %s, not from a well-known location of issuer %s", exchange.Request.URL, result.Issuer)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return none, fmt.Errorf("parse the document: %w", err)
	}
	var named string
	if err := json.Unmarshal(document[result.IssuerMember], &named); err != nil || named != result.Issuer {
		return none, fmt.Errorf("the document's %s is %s, not the issuer %q the URL was built from", result.IssuerMember, document[result.IssuerMember], result.Issuer)
	}
	return conformance.ExampleVerification{
		Method:       conformance.VerifiedByIssuer,
		IssuerMember: result.IssuerMember,
		Issuer:       result.Issuer,
	}, nil
}

// verifyResource checks a SCIM resource, which carries no signature, against
// the exchanges that created and retrieved it. RFC 7644 Section 3.3: "The URI
// of the created resource SHALL include, in the HTTP "Location" header and
// the HTTP body, a JSON representation [RFC7159] with the attribute
// "meta.location"." RFC 7643 Section 3.1 on meta.location: "This value MUST be
// the same as the "Content-Location" HTTP response header", and on
// meta.version: "This value must be the same as the entity-tag (ETag) HTTP
// response header".
func verifyResource(result ExampleResult, exchanges []lookingglass.CapturedExchange) (conformance.ExampleVerification, error) {
	var none conformance.ExampleVerification
	if result.Source.Message != conformance.ExampleInResponse {
		return none, fmt.Errorf("a resource example is the body of a response, not of a %s", result.Source.Message)
	}
	retrieved := exchanges[result.Source.Exchange]
	body, err := payloadBytes(retrieved.Response.Body)
	if err != nil {
		return none, err
	}
	if string(body) != result.Value {
		return none, fmt.Errorf("the value is not the whole body of the response in exchange %d", result.Source.Exchange)
	}
	var resource struct {
		ID   string `json:"id"`
		Meta struct {
			Location string `json:"location"`
			Version  string `json:"version"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &resource); err != nil {
		return none, fmt.Errorf("parse the resource: %w", err)
	}
	if resource.ID == "" || resource.Meta.Location == "" {
		return none, fmt.Errorf("the resource has no id or no meta.location")
	}
	if retrieved.Request.Method != http.MethodGet || retrieved.Request.URL != resource.Meta.Location || retrieved.Response.Status != http.StatusOK {
		return none, fmt.Errorf("the value was not retrieved with a GET of its meta.location %s: exchange %d is %s %s, answered %d",
			resource.Meta.Location, result.Source.Exchange, retrieved.Request.Method, retrieved.Request.URL, retrieved.Response.Status)
	}
	if got := headerValue(retrieved.Response.Headers, "Content-Location"); got != resource.Meta.Location {
		return none, fmt.Errorf("the Content-Location header %q is not meta.location %q", got, resource.Meta.Location)
	}
	if got := headerValue(retrieved.Response.Headers, "ETag"); got != resource.Meta.Version {
		return none, fmt.Errorf("the ETag header %q is not meta.version %q", got, resource.Meta.Version)
	}

	if result.CreatedExchange == nil || *result.CreatedExchange < 0 || *result.CreatedExchange >= len(exchanges) || *result.CreatedExchange == result.Source.Exchange {
		return none, fmt.Errorf("a resource example needs the recorded exchange that created the resource")
	}
	created := exchanges[*result.CreatedExchange]
	if created.Request.Method != http.MethodPost || created.Response.Status != http.StatusCreated {
		return none, fmt.Errorf("exchange %d is %s answered %d, not a POST answered 201 (Created)", *result.CreatedExchange, created.Request.Method, created.Response.Status)
	}
	if got := headerValue(created.Response.Headers, "Location"); got != resource.Meta.Location {
		return none, fmt.Errorf("the Location header %q of the 201 response is not meta.location %q", got, resource.Meta.Location)
	}
	createdBody, err := payloadBytes(created.Response.Body)
	if err != nil {
		return none, err
	}
	var createdResource struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createdBody, &createdResource); err != nil || createdResource.ID != resource.ID {
		return none, fmt.Errorf("the 201 response does not carry the resource whose id is %q", resource.ID)
	}
	return conformance.ExampleVerification{
		Method:          conformance.VerifiedByLocation,
		Location:        resource.Meta.Location,
		CreatedExchange: result.CreatedExchange,
	}, nil
}

// headerValue returns the one value of a recorded header field, or "".
func headerValue(headers map[string][]string, name string) string {
	for field, values := range headers {
		if strings.EqualFold(field, name) && len(values) == 1 {
			return values[0]
		}
	}
	return ""
}

// exampleSignatureAlgorithms are the asymmetric JWS algorithms an example
// value may be signed with.
var exampleSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// verifyExample checks value's JWS signature. With no JWK Set exchange the
// key is the public key in the value's jwk header parameter; otherwise it
// is the key the kid header parameter selects from the JWK Set that
// exchange fetched.
func verifyExample(value string, exchanges []lookingglass.CapturedExchange, jwksExchange *int) (conformance.ExampleVerification, error) {
	signed, err := jose.ParseSigned(value, exampleSignatureAlgorithms)
	if err != nil {
		return conformance.ExampleVerification{}, fmt.Errorf("parse the value as a JWS: %w", err)
	}
	if len(signed.Signatures) != 1 {
		return conformance.ExampleVerification{}, fmt.Errorf("the value carries %d signatures, want 1", len(signed.Signatures))
	}
	header := signed.Signatures[0].Header
	verification := conformance.ExampleVerification{Algorithm: header.Algorithm}

	var key *jose.JSONWebKey
	if jwksExchange == nil {
		key = header.JSONWebKey
		if key == nil {
			return verification, fmt.Errorf("the value has no jwk header parameter and the scenario fetched no JWK Set")
		}
		if !key.IsPublic() {
			return verification, fmt.Errorf("the value's jwk header parameter is not a public key")
		}
		verification.Method = conformance.VerifiedByEmbeddedJWK
	} else {
		index := *jwksExchange
		if index < 0 || index >= len(exchanges) {
			return verification, fmt.Errorf("JWK Set exchange %d is not one of the %d recorded", index, len(exchanges))
		}
		body, err := payloadBytes(exchanges[index].Response.Body)
		if err != nil {
			return verification, err
		}
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(body, &set); err != nil {
			return verification, fmt.Errorf("parse the JWK Set from exchange %d: %w", index, err)
		}
		matches := set.Key(header.KeyID)
		if header.KeyID == "" || len(matches) != 1 {
			return verification, fmt.Errorf("kid %q selects %d keys in the JWK Set, want 1", header.KeyID, len(matches))
		}
		key = &matches[0]
		verification.Method = conformance.VerifiedByJWKS
		verification.KeyID = header.KeyID
		verification.JWKSExchange = &index
	}
	if _, err := signed.Verify(key); err != nil {
		return verification, fmt.Errorf("the value's signature does not verify: %w", err)
	}
	return verification, nil
}
