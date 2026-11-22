package capture

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

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
	// JWKSExchange indexes the recorded exchange that fetched the JWK Set
	// holding the key that verifies Value. It is nil for a value that
	// carries its own public key in a jwk header parameter.
	JWKSExchange *int
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
	verification, err := verifyExample(result.Value, exchanges, result.JWKSExchange)
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
