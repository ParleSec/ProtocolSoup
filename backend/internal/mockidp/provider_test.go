package mockidp

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
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
