package metadata

import (
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
)

func TestPublishedMetadataParsesBack(t *testing.T) {
	creds, err := xmldsig.NewCredentials("https://sp.example/metadata")
	if err != nil {
		t.Fatal(err)
	}
	descriptor := BuildSP(SPParams{
		Entity: Entity{
			EntityID:         "https://sp.example/metadata",
			Credentials:      creds,
			SingleLogout:     []Endpoint{{Binding: message.BindingHTTPRedirect, Location: "https://sp.example/slo"}},
			OrganizationName: "Example SP",
			OrganizationURL:  "https://sp.example",
		},
		ACSURL:               "https://sp.example/acs",
		AuthnRequestsSigned:  true,
		WantAssertionsSigned: true,
	})
	xmlBytes, err := message.Serialize(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Parse(xmlBytes, "https://sp.example/metadata", RoleSP, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !peer.AuthnRequestsSigned || !peer.WantAssertionsSigned || len(peer.SigningCerts) != 1 || !peer.SigningCerts[0].Equal(creds.Certificate()) {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	if acs, ok := peer.DefaultACS(); !ok || acs.Location != "https://sp.example/acs" {
		t.Fatalf("default ACS = %+v", acs)
	}
	if _, err := Parse(xmlBytes, "https://elsewhere.example/metadata", RoleSP, time.Now()); err == nil {
		t.Fatal("metadata accepted for a different entityID (SAML Metadata Section 4.1.1)")
	}
	if _, err := Parse(xmlBytes, "https://sp.example/metadata", RoleSP, time.Now().Add(72*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired metadata accepted: %v", err)
	}
}

func TestParseISODuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"PT1H": time.Hour, "P1DT30M": 24*time.Hour + 30*time.Minute, "PT90S": 90 * time.Second} {
		if got, err := parseISODuration(in); err != nil || got != want {
			t.Errorf("%s = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"P", "PT", "1H", "P1Y"} {
		if _, err := parseISODuration(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
