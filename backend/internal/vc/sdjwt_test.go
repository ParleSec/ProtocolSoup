package vc

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSDJWTDisclosureDigestsExtractsNestedCommitments(t *testing.T) {
	digests, err := SDJWTDisclosureDigests(map[string]interface{}{
		"_sd_alg": "sha-256",
		"credentialSubject": map[string]interface{}{
			"_sd": []interface{}{"digest-one", "digest-two"},
		},
	})
	if err != nil {
		t.Fatalf("SDJWTDisclosureDigests: %v", err)
	}
	if len(digests) != 2 || digests[0] != "digest-one" || digests[1] != "digest-two" {
		t.Fatalf("unexpected digests: %v", digests)
	}
}

func TestSDJWTCompactSerializationRequiresTrailingTildeWithoutKBJWT(t *testing.T) {
	serialized := BuildSDJWTSerialization("issuer.jwt.value", []string{"disclosure"}, "")
	if serialized != "issuer.jwt.value~disclosure~" {
		t.Fatalf("unexpected compact serialization %q", serialized)
	}
	if _, err := ParseSDJWTEnvelope("issuer.jwt.value"); err == nil {
		t.Fatal("expected missing tilde separator to be rejected")
	}
	envelope, err := ParseSDJWTEnvelope(serialized)
	if err != nil {
		t.Fatalf("ParseSDJWTEnvelope: %v", err)
	}
	if envelope.IssuerSignedJWT != "issuer.jwt.value" || len(envelope.Disclosures) != 1 {
		t.Fatalf("unexpected parsed envelope: %#v", envelope)
	}
}

func TestSDJWTDisclosureDigestsRejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := SDJWTDisclosureDigests(map[string]interface{}{"_sd_alg": "sha-512"})
	if err == nil || !strings.Contains(err.Error(), "unsupported _sd_alg") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}

func TestSDJWTDisclosureDigestsRejectsDuplicateCommitment(t *testing.T) {
	_, err := SDJWTDisclosureDigests(map[string]interface{}{
		"_sd": []interface{}{"duplicate"},
		"nested": map[string]interface{}{
			"_sd": []interface{}{"duplicate"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate sd-jwt digest") {
		t.Fatalf("expected duplicate digest error, got %v", err)
	}
}

func TestDecodeAndVerifyDisclosuresRejectsUncommittedDisclosure(t *testing.T) {
	disclosure, err := CreateSDJWTDisclosure("given_name", "Alice", "test-salt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAndVerifyDisclosures([]string{disclosure.Encoded}, nil); err == nil {
		t.Fatal("expected uncommitted disclosure to be rejected")
	}
	if _, err := DecodeAndVerifyDisclosures([]string{disclosure.Encoded}, []string{disclosure.Digest}); err != nil {
		t.Fatalf("expected committed disclosure to pass: %v", err)
	}
}

func TestDecodeSDJWTDisclosureRejectsReservedClaimNames(t *testing.T) {
	for _, claimName := range []string{"_sd", "..."} {
		if _, err := CreateSDJWTDisclosure(claimName, "value", "test-salt"); err == nil {
			t.Fatalf("expected issuer to reject reserved claim %q", claimName)
		}
		raw, err := json.Marshal([]interface{}{"test-salt", claimName, "value"})
		if err != nil {
			t.Fatal(err)
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		if _, err := DecodeSDJWTDisclosure(encoded); err == nil {
			t.Fatalf("expected reserved claim %q to be rejected", claimName)
		}
	}
}

// RFC 9901 Sections 4.2.2, 4.2.4.2, and 7.1 require a two-element
// Disclosure for an array element, replacement at the digest marker's exact
// position, and removal of markers whose Disclosure was not presented.
func TestProcessSDJWTDisclosuresResolvesArrayElementsPositionally(t *testing.T) {
	fr, err := CreateSDJWTArrayDisclosure("FR", "salt-fr")
	if err != nil {
		t.Fatal(err)
	}
	hidden, err := CreateSDJWTArrayDisclosure("GB", "salt-gb")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]interface{}{
		"_sd_alg": "sha-256",
		"nationalities": []interface{}{
			"DE",
			map[string]interface{}{"...": fr.Digest},
			map[string]interface{}{"...": hidden.Digest},
			"US",
		},
	}

	processed, decoded, err := ProcessSDJWTDisclosures(payload, []string{fr.Encoded})
	if err != nil {
		t.Fatalf("ProcessSDJWTDisclosures: %v", err)
	}
	got, ok := processed["nationalities"].([]interface{})
	if !ok {
		t.Fatalf("processed nationalities has type %T", processed["nationalities"])
	}
	want := []interface{}{"DE", "FR", "US"}
	if !equalJSONValue(got, want) {
		t.Fatalf("processed nationalities = %#v, want %#v", got, want)
	}
	if len(decoded) != 1 || !decoded[0].IsArrayElement || decoded[0].ClaimName != "" {
		t.Fatalf("unexpected decoded array disclosure: %#v", decoded)
	}
	if _, exists := processed["_sd_alg"]; exists {
		t.Fatal("processed payload retained _sd_alg")
	}
}

// RFC 9901 Section 4.2.6 permits recursive disclosures, and Section 7.1
// requires recursive processing from the digest's position rather than
// globally flattening nested claim names into the payload root.
func TestProcessSDJWTDisclosuresResolvesRecursiveObjectAtDigestPosition(t *testing.T) {
	city, err := CreateSDJWTDisclosure("city", "Paris", "salt-city")
	if err != nil {
		t.Fatal(err)
	}
	address, err := CreateSDJWTDisclosure("address", map[string]interface{}{
		"country": "FR",
		"_sd":     []interface{}{city.Digest},
	}, "salt-address")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]interface{}{
		"_sd_alg": "sha-256",
		"profile": map[string]interface{}{
			"_sd": []interface{}{address.Digest},
		},
	}

	processed, _, err := ProcessSDJWTDisclosures(payload, []string{address.Encoded, city.Encoded})
	if err != nil {
		t.Fatalf("ProcessSDJWTDisclosures: %v", err)
	}
	profile := processed["profile"].(map[string]interface{})
	addressValue := profile["address"].(map[string]interface{})
	if addressValue["country"] != "FR" || addressValue["city"] != "Paris" {
		t.Fatalf("unexpected processed address %#v", addressValue)
	}
	if _, flattened := processed["city"]; flattened {
		t.Fatal("recursive city disclosure was flattened into the payload root")
	}
}

// RFC 9901 Section 4.1.1: "_sd_alg" MUST appear at the top level and MUST
// NOT be used in any object nested within the payload.
func TestProcessSDJWTDisclosuresRejectsNestedSDAlg(t *testing.T) {
	_, _, err := ProcessSDJWTDisclosures(map[string]interface{}{
		"_sd_alg": "sha-256",
		"nested":  map[string]interface{}{"_sd_alg": "sha-256"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "only at the top level") {
		t.Fatalf("expected nested _sd_alg rejection, got %v", err)
	}
}

// RFC 9901 Sections 4.2.1 and 7.1 require rejection when an object-property
// Disclosure collides with a permanently disclosed claim in that object.
func TestProcessSDJWTDisclosuresRejectsPermanentClaimCollision(t *testing.T) {
	disclosure, err := CreateSDJWTDisclosure("name", "attacker", "salt-name")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ProcessSDJWTDisclosures(map[string]interface{}{
		"name": "Alice",
		"_sd":  []interface{}{disclosure.Digest},
	}, []string{disclosure.Encoded})
	if err == nil || !strings.Contains(err.Error(), "collides with a permanently disclosed claim") {
		t.Fatalf("expected collision rejection, got %v", err)
	}
}

// SD-JWT VC draft-ietf-oauth-sd-jwt-vc Section 2.2.2.2 requires these
// validity, type, key-binding, and status claims to remain in the SD-JWT
// component and forbids placing them in Disclosures.
func TestProcessSDJWTDisclosuresRejectsSDJWTVCPermanentClaims(t *testing.T) {
	for _, claimName := range []string{"iss", "nbf", "exp", "cnf", "vct", "vct#integrity", "status"} {
		t.Run(claimName, func(t *testing.T) {
			disclosure, err := CreateSDJWTDisclosure(claimName, "value", "salt-"+claimName)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = ProcessSDJWTDisclosures(
				map[string]interface{}{"_sd": []interface{}{disclosure.Digest}},
				[]string{disclosure.Encoded},
			)
			if err == nil || !strings.Contains(err.Error(), "must not be selectively disclosed") {
				t.Fatalf("expected permanent claim rejection, got %v", err)
			}
		})
	}
}

// RFC 9901 Section 4.1 requires the compact SD-JWT without a KB-JWT to end
// in "~"; empty interior segments are not Disclosure encodings.
func TestParseSDJWTEnvelopeRejectsNonCanonicalSeparators(t *testing.T) {
	for _, raw := range []string{
		"issuer.jwt.value~disclosure",
		"issuer.jwt.value~~",
		" issuer.jwt.value~",
		"issuer.jwt.value~ ",
	} {
		if _, err := ParseSDJWTEnvelope(raw); err == nil {
			t.Fatalf("expected malformed compact serialization %q to be rejected", raw)
		}
	}
}

func equalJSONValue(left, right interface{}) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}
