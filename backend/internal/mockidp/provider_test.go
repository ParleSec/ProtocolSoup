package mockidp

import (
	"testing"
	"time"

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

func TestAuthorizationCodeLifetimeIsAtMostSixtySeconds(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	idp.RegisterClient(&models.Client{
		ID:           "code-ttl-client",
		Public:       true,
		RedirectURIs: []string{"https://client.example/callback"},
		GrantTypes:   []string{"authorization_code"},
	})

	before := time.Now()
	authCode, err := idp.CreateAuthorizationCode(
		"code-ttl-client", "alice", "https://client.example/callback",
		"openid", "", "", "", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	after := time.Now()

	if authCode.ExpiresAt.After(before.Add(AuthorizationCodeTTL + time.Second)) {
		t.Fatalf("ExpiresAt = %s exceeds AuthorizationCodeTTL from %s", authCode.ExpiresAt, before)
	}
	if authCode.ExpiresAt.Before(after.Add(AuthorizationCodeTTL - 2*time.Second)) {
		t.Fatalf("ExpiresAt = %s is shorter than expected from %s", authCode.ExpiresAt, after)
	}
	if AuthorizationCodeTTL > 60*time.Second {
		t.Fatalf("AuthorizationCodeTTL = %s, FAPI2 SP Final §5.3.2.1-11 caps at 60s", AuthorizationCodeTTL)
	}
}

func TestValidateAuthorizationCodeRejectsExpiredCode(t *testing.T) {
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	idp := NewMockIdP(keySet)
	const clientID = "expired-code-client"
	const redirectURI = "https://client.example/callback"
	idp.RegisterClient(&models.Client{
		ID:           clientID,
		Public:       true,
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
	})

	authCode, err := idp.CreateAuthorizationCode(
		clientID, "alice", redirectURI, "openid", "", "", "", "", "", time.Now(),
	)
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}
	// FAPI2 waits 62s; simulate expiry without sleeping.
	authCode.ExpiresAt = time.Now().Add(-time.Second)

	_, err = idp.ValidateAuthorizationCode(authCode.Code, clientID, redirectURI, "")
	if err == nil || err.Error() != "authorization code expired" {
		t.Fatalf("ValidateAuthorizationCode = %v, want authorization code expired", err)
	}
}

