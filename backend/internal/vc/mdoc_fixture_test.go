package vc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
)

// testMdocFixture is a real, validly-signed ISO/IEC 18013-5 mso_mdoc
// IssuerSigned (base64url CBOR), built through the same exported
// internal/mdoc primitives production issuance uses -- mirroring
// walletharness's issueMdocBoundTo -- rather than a hand-crafted CBOR blob.
// It carries exactly two disclosed elements (family_name, age_over_18) in
// the org.iso.18013.5.1 namespace, so tests asserting selective-disclosure
// counts have a known-correct value to check against.
type testMdocFixture struct {
	credential   string
	trustAnchors *x509.CertPool
}

// buildTestMdocCredential issues a fresh mdoc fixture with its own
// single-use IACA root, so trustAnchors verifies this credential and no
// other. elementCount lets callers vary the disclosed-element count (for
// committed_count assertions) without duplicating this whole construction;
// pass 0 for the standard 2-element (family_name, age_over_18) fixture.
func buildTestMdocCredential(t *testing.T) testMdocFixture {
	t.Helper()
	return buildTestMdocCredentialBoundTo(t, nil)
}

// buildTestMdocCredentialBoundTo issues a fixture bound to a caller-supplied
// device key, or a freshly generated one if boundKey is nil. Device binding
// is irrelevant to format/evidence/trust-status tests, but BuildMSO requires
// a DeviceKeyInfo, so every fixture needs one regardless.
func buildTestMdocCredentialBoundTo(t *testing.T, boundKey *ecdsa.PublicKey) testMdocFixture {
	t.Helper()
	pki, err := mdoc.GenerateIssuerPKI(mdoc.DefaultPKIParams("https://issuer.example/oid4vci"))
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	if boundKey == nil {
		deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey(device): %v", err)
		}
		boundKey = &deviceKey.PublicKey
	}
	now := time.Now().Truncate(time.Second).UTC()
	family, err := mdoc.NewIssuerSignedItem(0, "family_name", "Citizen")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem(family_name): %v", err)
	}
	age, err := mdoc.NewIssuerSignedItem(1, "age_over_18", true)
	if err != nil {
		t.Fatalf("NewIssuerSignedItem(age_over_18): %v", err)
	}
	ns, err := mdoc.BuildIssuerNameSpaces(map[mdoc.NameSpace][]mdoc.IssuerSignedItem{mdoc.NameSpaceMDL: {family, age}})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}
	vd, err := mdoc.BuildValueDigests(ns, mdoc.DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}
	deviceCOSEKey, err := intcose.ECPublicKeyToCOSEKey(boundKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}
	mso := mdoc.BuildMSO(vd, deviceCOSEKey, mdoc.DocTypeMDL, mdoc.ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(48 * time.Hour)})
	msoBytes, err := mdoc.EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := mdoc.BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	encoded, err := mdoc.EncodeIssuerSigned(mdoc.IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth})
	if err != nil {
		t.Fatalf("EncodeIssuerSigned: %v", err)
	}
	return testMdocFixture{
		credential:   base64.RawURLEncoding.EncodeToString(encoded),
		trustAnchors: pki.TrustAnchors(),
	}
}
