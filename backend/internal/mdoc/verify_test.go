package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

func TestMSORoundTrip(t *testing.T) {
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, err := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}

	now := time.Now().Truncate(time.Second).UTC()
	mso := BuildMSO(
		ValueDigests{NameSpaceMDL: {0: []byte{0xaa, 0xbb}}},
		deviceCOSEKey,
		DocTypeMDL,
		ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
	)

	msoBytes, err := EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}

	decoded, err := DecodeMSOBytes(msoBytes)
	if err != nil {
		t.Fatalf("DecodeMSOBytes: %v", err)
	}

	if decoded.Version != MSOVersion {
		t.Errorf("Version = %q, want %q", decoded.Version, MSOVersion)
	}
	if decoded.DigestAlgorithm != DigestAlgorithmSHA256 {
		t.Errorf("DigestAlgorithm = %q, want %q", decoded.DigestAlgorithm, DigestAlgorithmSHA256)
	}
	if decoded.DocType != DocTypeMDL {
		t.Errorf("DocType = %q, want %q", decoded.DocType, DocTypeMDL)
	}
}

func TestIssuerAuthRoundTrip(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)

	now := time.Now().Truncate(time.Second).UTC()
	mso := BuildMSO(
		ValueDigests{NameSpaceMDL: {0: []byte{0xcc, 0xdd}}},
		deviceCOSEKey,
		DocTypeMDL,
		ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
	)
	msoBytes, err := EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}

	issuerAuth, err := BuildIssuerAuth(msoBytes, dsKey, nil)
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}

	// Parse it back.
	payload, _, err := ParseIssuerAuth(issuerAuth)
	if err != nil {
		t.Fatalf("ParseIssuerAuth: %v", err)
	}

	// Payload must be the same msoBytes we signed.
	// Note: some implementations embed the tag-24 bytes directly as payload.
	decoded, err := decodeMSOFromPayload(payload)
	if err != nil {
		t.Fatalf("decodeMSOFromPayload: %v", err)
	}
	if decoded.DocType != DocTypeMDL {
		t.Errorf("decoded MSO DocType = %q, want %q", decoded.DocType, DocTypeMDL)
	}

	// Verify signature.
	result, err := intcose.VerifySign1(issuerAuth, nil, &dsKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifySign1: %v", err)
	}
	if result.Payload == nil {
		t.Fatal("VerifySign1 returned nil payload")
	}
}

func TestVerifyIssuerSignedWithX5Chain(t *testing.T) {
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}

	// Device key.
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)

	now := time.Now().Truncate(time.Second)
	validity := ValidityInfo{
		Signed:     now.Add(-2 * time.Hour),
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: now.Add(24 * time.Hour),
	}

	items := makeVerifyTestItems(t)
	ns, _ := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: items})
	vd, _ := BuildValueDigests(ns, DigestAlgorithmSHA256)
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, validity)
	msoBytes, _ := EncodeMSOBytes(mso)

	issuerAuth, err := BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth with chain: %v", err)
	}

	cred := IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}

	verifiedMSO, err := VerifyIssuerSigned(cred, pki.TrustAnchors(), now)
	if err != nil {
		t.Fatalf("VerifyIssuerSigned with x5chain: %v", err)
	}
	if verifiedMSO.DocType != DocTypeMDL {
		t.Errorf("docType = %q, want %q", verifiedMSO.DocType, DocTypeMDL)
	}
}

func TestVerifyIssuerSignedRejectsNilRoots(t *testing.T) {
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credential, _ := issueTestCredential(t, deviceKey, validNow())
	if _, err := VerifyIssuerSigned(credential, nil, time.Now()); err == nil {
		t.Fatal("expected verification to fail closed when issuer roots are nil")
	}
}

func TestVerifyIssuerSignedRejectsBareMSOPayload(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&deviceKey.PublicKey)
	now := time.Now().Truncate(time.Second).UTC()
	mso := BuildMSO(
		ValueDigests{NameSpaceMDL: {0: make([]byte, 32)}},
		deviceCOSEKey,
		DocTypeMDL,
		ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour)},
	)
	bare, err := intcose.MarshalDeterministic(mso)
	if err != nil {
		t.Fatalf("encode bare MSO: %v", err)
	}
	issuerAuth, err := BuildIssuerAuth(bare, dsKey, nil)
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	if _, err := VerifyIssuerSignedWithKey(IssuerSigned{IssuerAuth: issuerAuth}, &dsKey.PublicKey, now); err == nil {
		t.Fatal("expected bare MobileSecurityObject payload to be rejected")
	}
}

func TestVerifyIssuerSignedRejectsInvalidMSOFields(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&deviceKey.PublicKey)
	now := time.Now().Truncate(time.Second).UTC()

	newValidMSO := func() MobileSecurityObject {
		return BuildMSO(
			ValueDigests{NameSpaceMDL: {0: make([]byte, 32)}},
			deviceCOSEKey,
			DocTypeMDL,
			ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(2 * time.Hour)},
		)
	}
	tests := []struct {
		name   string
		mutate func(*MobileSecurityObject)
	}{
		{"version", func(m *MobileSecurityObject) { m.Version = "2.0" }},
		{"digest algorithm", func(m *MobileSecurityObject) { m.DigestAlgorithm = "SHA-384" }},
		{"empty docType", func(m *MobileSecurityObject) { m.DocType = "" }},
		{"empty device key", func(m *MobileSecurityObject) { m.DeviceKeyInfo.DeviceKey = nil }},
		{"private device key material", func(m *MobileSecurityObject) {
			m.DeviceKeyInfo.DeviceKey, _ = intcose.ECPrivateKeyToCOSEKey(deviceKey)
		}},
		{"empty valueDigests", func(m *MobileSecurityObject) { m.ValueDigests = nil }},
		{"empty namespace", func(m *MobileSecurityObject) {
			m.ValueDigests = ValueDigests{"": {0: make([]byte, 32)}}
		}},
		{"empty namespace digests", func(m *MobileSecurityObject) {
			m.ValueDigests = ValueDigests{NameSpaceMDL: {}}
		}},
		{"wrong digest length", func(m *MobileSecurityObject) {
			m.ValueDigests = ValueDigests{NameSpaceMDL: {0: []byte{0x01}}}
		}},
		{"signed after validFrom", func(m *MobileSecurityObject) { m.ValidityInfo.Signed = now.Add(time.Second) }},
		{"validFrom equals validUntil", func(m *MobileSecurityObject) { m.ValidityInfo.ValidUntil = now }},
		{"expectedUpdate at signed", func(m *MobileSecurityObject) {
			update := now
			m.ValidityInfo.ExpectedUpdate = &update
		}},
		{"expectedUpdate at validUntil", func(m *MobileSecurityObject) {
			update := now.Add(2 * time.Hour)
			m.ValidityInfo.ExpectedUpdate = &update
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mso := newValidMSO()
			tt.mutate(&mso)
			msoBytes, err := EncodeMSOBytes(mso)
			if err != nil {
				t.Fatalf("EncodeMSOBytes: %v", err)
			}
			issuerAuth, err := BuildIssuerAuth(msoBytes, dsKey, nil)
			if err != nil {
				t.Fatalf("BuildIssuerAuth: %v", err)
			}
			if _, err := VerifyIssuerSignedWithKey(IssuerSigned{IssuerAuth: issuerAuth}, &dsKey.PublicKey, now); err == nil {
				t.Fatal("expected invalid MSO to be rejected")
			}
		})
	}
}

func TestDocumentSignerCertificateProfileRejectsInvalidFields(t *testing.T) {
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	valid := pki.DocumentSignerCertificate()
	tests := []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{"missing mDL DS EKU", func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil }},
		{"wrong key usage", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }},
		{"CA true", func(c *x509.Certificate) { c.IsCA = true }},
		{"missing basic constraints", func(c *x509.Certificate) { c.BasicConstraintsValid = false }},
		{"overlong validity", func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(dsMaxValidity + time.Second) }},
		{"missing country", func(c *x509.Certificate) { c.Subject.Country = nil }},
		{"missing organization", func(c *x509.Certificate) { c.Subject.Organization = nil }},
		{"missing subject key identifier", func(c *x509.Certificate) { c.SubjectKeyId = nil }},
		{"missing authority key identifier", func(c *x509.Certificate) { c.AuthorityKeyId = nil }},
		{"missing CRL distribution point", func(c *x509.Certificate) { c.CRLDistributionPoints = nil }},
		{"missing issuerAltName", func(c *x509.Certificate) {
			filtered := c.Extensions[:0]
			for _, ext := range c.Extensions {
				if !ext.Id.Equal(oidIssuerAltName) {
					filtered = append(filtered, ext)
				}
			}
			c.Extensions = filtered
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := *valid
			cert.Extensions = append([]pkix.Extension(nil), valid.Extensions...)
			tt.mutate(&cert)
			if err := validateDocumentSignerCertificate(&cert); err == nil {
				t.Fatal("expected invalid document-signer certificate profile to be rejected")
			}
		})
	}
}

func TestIssuerAuthSignatureBindsRFC9360X5ChainLeaf(t *testing.T) {
	signerPKI, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI signer: %v", err)
	}
	otherPKI, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI other: %v", err)
	}
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&deviceKey.PublicKey)
	now := time.Now().Truncate(time.Second).UTC()
	mso := BuildMSO(
		ValueDigests{NameSpaceMDL: {0: make([]byte, 32)}},
		deviceCOSEKey,
		DocTypeMDL,
		ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour)},
	)
	msoBytes, _ := EncodeMSOBytes(mso)
	issuerAuth, err := BuildIssuerAuth(msoBytes, signerPKI.DocumentSignerKey(), otherPKI.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	if _, err := VerifyIssuerSigned(
		IssuerSigned{IssuerAuth: issuerAuth},
		otherPKI.TrustAnchors(),
		now,
	); err == nil {
		t.Fatal("expected COSE signature verification to reject an x5chain leaf that does not own the signing key")
	}
}

func makeVerifyTestItems(t *testing.T) []IssuerSignedItem {
	t.Helper()
	elements := []struct {
		id    string
		value any
	}{
		{"family_name", "TestFamily"},
		{"given_name", "TestGiven"},
	}
	items := make([]IssuerSignedItem, len(elements))
	for i, e := range elements {
		item, err := NewIssuerSignedItem(DigestID(i), e.id, e.value)
		if err != nil {
			t.Fatalf("NewIssuerSignedItem %q: %v", e.id, err)
		}
		items[i] = item
	}
	return items
}
