package oid4vciwallet

import (
	"net/http"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// TestJWTProofsRequiresTheSectionEightTwoShape proves the proofs check only
// accepts an object with the single member jwt holding a non-empty array.
func TestJWTProofsRequiresTheSectionEightTwoShape(t *testing.T) {
	good := map[string]any{"proofs": map[string]any{"jwt": []any{"a.b.c"}}}
	if proofs, err := jwtProofs(good); err != nil || len(proofs) != 1 || proofs[0] != "a.b.c" {
		t.Fatalf("one jwt proof: %v %v", proofs, err)
	}
	for name, request := range map[string]map[string]any{
		"array":           {"proofs": []any{map[string]any{"proof_type": "jwt", "jwt": "a.b.c"}}},
		"empty jwt array": {"proofs": map[string]any{"jwt": []any{}}},
		"two proof types": {"proofs": map[string]any{"jwt": []any{"a.b.c"}, "di_vp": []any{"x"}}},
		"other type only": {"proofs": map[string]any{"attestation": []any{"a.b.c"}}},
		"no proofs":       {},
	} {
		if _, err := jwtProofs(request); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestRefusalReadsOnlyThisRowsCheck proves a counterparty scenario is
// rejected only on a 400 naming the check, accepted only on a completed
// import, and otherwise an error.
func TestRefusalReadsOnlyThisRowsCheck(t *testing.T) {
	outcome, err := refusal(&capture.WalletResult{Status: http.StatusBadRequest, Body: map[string]any{
		"error": "invalid_request", "error_description": "tx_code is required when tx_code object is present in credential offer",
	}}, "tx_code is required")
	if err != nil || outcome != conformance.OutcomeRejected {
		t.Fatalf("named refusal: %v %v", outcome, err)
	}
	outcome, err = refusal(&capture.WalletResult{Status: http.StatusOK, Body: map[string]any{"credential_id": "c"}}, "tx_code is required")
	if err != nil || outcome != conformance.OutcomeAccepted {
		t.Fatalf("completed import: %v %v", outcome, err)
	}
	if _, err := refusal(&capture.WalletResult{Status: http.StatusBadRequest, Body: map[string]any{
		"error": "wallet_import_failed", "error_description": "something else",
	}}, "tx_code is required"); err == nil {
		t.Fatal("another refusal must be an error")
	}
	if _, err := refusal(&capture.WalletResult{Status: http.StatusBadGateway, Body: map[string]any{}}, "x"); err == nil {
		t.Fatal("a 5xx must be an error")
	}
}

// TestWellKnownURLInsertsAfterTheHost proves the Section 12.2.2 insertion.
func TestWellKnownURLInsertsAfterTheHost(t *testing.T) {
	got, err := wellKnownURL("https://issuer.example/tenant", "openid-credential-issuer")
	if err != nil || got != "https://issuer.example/.well-known/openid-credential-issuer/tenant" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := wellKnownURL("issuer.example/tenant", "openid-credential-issuer"); err == nil {
		t.Fatal("an identifier without a scheme must be an error")
	}
}

// TestEveryRowHasExactlyOneSourcePerKind proves each registered row has a
// scenario or an unavailable reason for each kind, never both or neither.
func TestEveryRowHasExactlyOneSourcePerKind(t *testing.T) {
	ids := []string{"CI-005", "CI-010", "CI-011", "CI-013", "CW-001", "CW-006", "CW-010", "CW-020", "CW-024", "CW-044", "CW-065", "CW-070", "CW-081", "CW-089", "CW-100"}
	entries := capture.Entries()
	for _, id := range ids {
		entry, ok := entries[id]
		if !ok {
			t.Errorf("%s is not registered", id)
			continue
		}
		for kind, scenario := range map[conformance.ArtefactKind]*capture.Scenario{conformance.KindPassing: entry.Passing, conformance.KindFailing: entry.Failing} {
			_, unavailable := entry.Unavailable[kind]
			if (scenario == nil) == !unavailable {
				t.Errorf("%s %s: want exactly one of a scenario or an unavailable reason", id, kind)
			}
			if scenario != nil && kind == conformance.KindPassing && scenario.Expected != conformance.OutcomeAccepted {
				t.Errorf("%s passing expects %s", id, scenario.Expected)
			}
			if scenario != nil && kind == conformance.KindFailing && scenario.Expected != conformance.OutcomeRejected {
				t.Errorf("%s failing expects %s", id, scenario.Expected)
			}
		}
	}
}

// TestEncryptedHopIsReadFromItsPlaintext proves a hop whose bodies are JWEs,
// as the hosted wallet's Credential Requests are, is read from the plaintext
// the wallet recorded, and a plain hop from its body.
func TestEncryptedHopIsReadFromItsPlaintext(t *testing.T) {
	encrypted := &capture.WalletHop{
		Step:              stepCredential,
		RequestBody:       "eyJhbGciOiJFQ0RILUVTIn0.a.b.c.d",
		RequestPlaintext:  `{"credential_configuration_id":"X","proofs":{"jwt":["p"]}}`,
		ResponseBody:      "eyJhbGciOiJFQ0RILUVTIn0.a.b.c.d",
		ResponsePlaintext: `{"credentials":[{"credential":"c"}],"notification_id":"n"}`,
	}
	request, err := requestJSON(encrypted)
	if err != nil || request["credential_configuration_id"] != "X" {
		t.Fatalf("request = %v, %v", request, err)
	}
	response, err := responseJSON(encrypted)
	if err != nil || response["notification_id"] != "n" {
		t.Fatalf("response = %v, %v", response, err)
	}
	plain := &capture.WalletHop{Step: stepCredential, RequestBody: `{"credential_configuration_id":"Y"}`}
	if request, err := requestJSON(plain); err != nil || request["credential_configuration_id"] != "Y" {
		t.Fatalf("plain request = %v, %v", request, err)
	}
	if _, err := requestJSON(&capture.WalletHop{Step: stepCredential, RequestBody: "eyJ.a.b.c.d"}); err == nil {
		t.Fatal("a JWE body with no recorded plaintext must be an error, not an empty object")
	}
}
