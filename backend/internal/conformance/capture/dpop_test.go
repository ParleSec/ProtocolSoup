package capture

import (
	"net/http"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/dpop"
)

// TestDPoPProofPassesServerValidation checks the conformance client's proofs
// against the validator the deployed endpoints use, so a passing scenario
// fails only if production disagrees, never because the client is wrong.
func TestDPoPProofPassesServerValidation(t *testing.T) {
	key, err := NewDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	const target = "https://protocolsoup.test/oauth2/resource"
	proof, err := key.Proof(ProofOptions{Method: http.MethodGet, URL: target, AccessToken: "access-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dpop.ValidateProof(proof, dpop.ValidateOptions{
		Method:      http.MethodGet,
		URI:         target,
		AccessToken: "access-token",
		Now:         time.Now(),
	}); err != nil {
		t.Fatalf("ValidateProof rejected the conformance client's proof: %v", err)
	}
}
