package mockidp

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

func TestPrivateKeyJWTClientExistsOnlyAfterSessionRegistration(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	if _, exists := idp.GetClient("machine-client-pkjwt"); exists {
		t.Fatal("unusable private_key_jwt client was seeded")
	}
	for _, preset := range idp.GetDemoClientPresets() {
		if preset.ID == "machine-client-pkjwt" {
			t.Fatal("unusable private_key_jwt preset was exposed")
		}
	}
}

func TestPairwiseSubjectIsDeterministicAndSectorBound(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	idp.SetPairwiseSubjectSalt("test-stable-pairwise-salt")

	first := &models.Client{
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://first.example/callback"},
	}
	second := &models.Client{
		SubjectType:  "pairwise",
		RedirectURIs: []string{"https://second.example/callback"},
	}
	firstSubject, err := idp.SubjectForClient(first, "alice")
	if err != nil {
		t.Fatalf("SubjectForClient first: %v", err)
	}
	repeatedSubject, err := idp.SubjectForClient(first, "alice")
	if err != nil {
		t.Fatalf("SubjectForClient repeated: %v", err)
	}
	secondSubject, err := idp.SubjectForClient(second, "alice")
	if err != nil {
		t.Fatalf("SubjectForClient second: %v", err)
	}
	if firstSubject != repeatedSubject {
		t.Fatal("pairwise subject changed for the same user and sector")
	}
	if firstSubject == secondSubject {
		t.Fatal("pairwise subjects matched across distinct sectors")
	}
}
