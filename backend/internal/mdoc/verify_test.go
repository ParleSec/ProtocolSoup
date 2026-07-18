package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
	// Generate CA.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test mdoc CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Generate DS leaf signed by CA.
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test mdoc DS"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	dsDER, _ := x509.CreateCertificate(rand.Reader, dsTemplate, caCert, &dsKey.PublicKey, caKey)
	dsCert, _ := x509.ParseCertificate(dsDER)

	// Device key.
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)

	now := time.Now().Truncate(time.Second)
	validity := ValidityInfo{
		Signed:     now,
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: now.Add(24 * time.Hour),
	}

	items := makeVerifyTestItems(t)
	ns, _ := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: items})
	vd, _ := BuildValueDigests(ns, DigestAlgorithmSHA256)
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, validity)
	msoBytes, _ := EncodeMSOBytes(mso)

	issuerAuth, err := BuildIssuerAuth(msoBytes, dsKey, []*x509.Certificate{dsCert, caCert})
	if err != nil {
		t.Fatalf("BuildIssuerAuth with chain: %v", err)
	}

	cred := IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}

	// Build trusted roots pool.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	verifiedMSO, err := VerifyIssuerSigned(cred, roots, now)
	if err != nil {
		t.Fatalf("VerifyIssuerSigned with x5chain: %v", err)
	}
	if verifiedMSO.DocType != DocTypeMDL {
		t.Errorf("docType = %q, want %q", verifiedMSO.DocType, DocTypeMDL)
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
