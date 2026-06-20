package core

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
)

// These tests pin the conformance-client provisioning rules. The OIDF OP
// Basic/Implicit/Hybrid profiles with static clients require two confidential
// clients registered with the suite callback as an exact redirect URI, and the
// provisioning must never create a secretless confidential client (which would
// authenticate anyone) when conformance is not deliberately enabled.

func newProvisioningIdP(t *testing.T) *mockidp.MockIdP {
	t.Helper()
	ks, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	return mockidp.NewMockIdP(ks)
}

func TestRegisterConformanceClientsRegistersTwoConfidentialClients(t *testing.T) {
	idp := newProvisioningIdP(t)
	uris := []string{
		"https://localhost.emobix.co.uk:8443/test/a/protocolsoup-basic/callback",
		"https://www.certification.openid.net/test/a/protocolsoup-basic/callback",
	}
	cfg := &Config{
		ConformanceRedirectURIs: uris,
		ConformanceClientID:     "conformance-client",
		ConformanceClientSecret: "s3cret-value",
		ConformanceClient2ID:    "conformance-client-2",
		// Client2 secret intentionally absent: it must fall back to client 1's.
	}

	registerConformanceClients(idp, cfg)

	for _, id := range []string{"conformance-client", "conformance-client-2"} {
		client, ok := idp.GetClient(id)
		if !ok {
			t.Fatalf("client %q was not registered", id)
		}
		if client.Public {
			t.Fatalf("client %q must be confidential, not public", id)
		}
		if client.Secret == "" {
			t.Fatalf("client %q must have a secret to authenticate at the token endpoint", id)
		}
		// Every supplied redirect URI must be registered verbatim: the OP does
		// exact-match comparison (RFC 6749 Section 3.1.2.3), so the suite
		// callback has to be present byte-for-byte.
		for _, want := range uris {
			if !idp.ValidateRedirectURI(id, want) {
				t.Fatalf("client %q is missing redirect URI %q", id, want)
			}
		}
	}

	// The second client reuses the first secret when none is given, but stays a
	// distinct registration so code-binding tests can authenticate as it.
	c1, _ := idp.GetClient("conformance-client")
	c2, _ := idp.GetClient("conformance-client-2")
	if c1.Secret != c2.Secret {
		t.Fatalf("client 2 secret = %q, want fallback to client 1 secret %q", c2.Secret, c1.Secret)
	}
}

func TestRegisterConformanceClientsHonoursDistinctSecondSecret(t *testing.T) {
	idp := newProvisioningIdP(t)
	cfg := &Config{
		ConformanceRedirectURIs:  []string{"https://localhost.emobix.co.uk:8443/test/a/x/callback"},
		ConformanceClientID:      "conformance-client",
		ConformanceClientSecret:  "first-secret",
		ConformanceClient2ID:     "conformance-client-2",
		ConformanceClient2Secret: "second-secret",
	}

	registerConformanceClients(idp, cfg)

	c2, ok := idp.GetClient("conformance-client-2")
	if !ok {
		t.Fatalf("second client was not registered")
	}
	if c2.Secret != "second-secret" {
		t.Fatalf("client 2 secret = %q, want the distinct value provided", c2.Secret)
	}
}

func TestRegisterConformanceClientsSkippedWithoutSecret(t *testing.T) {
	idp := newProvisioningIdP(t)
	cfg := &Config{
		ConformanceRedirectURIs: []string{"https://localhost.emobix.co.uk:8443/test/a/x/callback"},
		ConformanceClientID:     "conformance-client",
		ConformanceClient2ID:    "conformance-client-2",
		// No secret: registering would create a confidential client that accepts
		// anyone. Provisioning MUST refuse.
	}

	registerConformanceClients(idp, cfg)

	if _, ok := idp.GetClient("conformance-client"); ok {
		t.Fatalf("conformance client must NOT be registered without a secret")
	}
	if _, ok := idp.GetClient("conformance-client-2"); ok {
		t.Fatalf("conformance client 2 must NOT be registered without a secret")
	}
}

func TestRegisterConformanceClientsSkippedWithoutRedirectURIs(t *testing.T) {
	idp := newProvisioningIdP(t)
	cfg := &Config{
		ConformanceClientID:     "conformance-client",
		ConformanceClientSecret: "s3cret-value",
		ConformanceClient2ID:    "conformance-client-2",
		// No redirect URIs: conformance is not enabled, so nothing is registered.
	}

	registerConformanceClients(idp, cfg)

	if _, ok := idp.GetClient("conformance-client"); ok {
		t.Fatalf("conformance client must NOT be registered without redirect URIs")
	}
}

func TestRegisterConformanceClientsTrimsBlankEntries(t *testing.T) {
	idp := newProvisioningIdP(t)
	cfg := &Config{
		ConformanceRedirectURIs: []string{
			" https://localhost.emobix.co.uk:8443/test/a/protocolsoup-basic/callback ",
			"",
			"   ",
		},
		ConformanceClientID:     "conformance-client",
		ConformanceClientSecret: "s3cret-value",
		ConformanceClient2ID:    "conformance-client-2",
	}

	registerConformanceClients(idp, cfg)

	client, ok := idp.GetClient("conformance-client")
	if !ok {
		t.Fatalf("conformance client was not registered")
	}
	if len(client.RedirectURIs) != 1 {
		t.Fatalf("redirect URIs = %v, want exactly the one non-blank trimmed entry", client.RedirectURIs)
	}
	if !idp.ValidateRedirectURI("conformance-client", "https://localhost.emobix.co.uk:8443/test/a/protocolsoup-basic/callback") {
		t.Fatalf("trimmed redirect URI was not registered for exact match")
	}
}
