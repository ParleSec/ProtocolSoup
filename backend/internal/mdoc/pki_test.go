package mdoc

import (
	"crypto/x509"
	"reflect"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

func testPKIParams() PKIParams {
	return DefaultPKIParams("https://issuer.test/oid4vci")
}

// TestIACAProfileConformsToAnnexB checks the IACA root against ISO/IEC 18013-5
// Table B.1: self-signed, keyCertSign+cRLSign only, CA with pathLen 0, a CRL
// distribution point, issuerAltName, and a validity inside the 15-year cap.
func TestIACAProfileConformsToAnnexB(t *testing.T) {
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	iaca := pki.IACACertificate()

	if !iaca.IsCA {
		t.Error("IACA must be a CA (Table B.1 Basic Constraints CA=TRUE)")
	}
	if iaca.MaxPathLen != 0 || !iaca.MaxPathLenZero {
		t.Errorf("IACA pathLenConstraint must be 0, got MaxPathLen=%d MaxPathLenZero=%v", iaca.MaxPathLen, iaca.MaxPathLenZero)
	}
	wantKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if iaca.KeyUsage != wantKU {
		t.Errorf("IACA keyUsage = %b, want %b (keyCertSign|cRLSign)", iaca.KeyUsage, wantKU)
	}
	if len(iaca.CRLDistributionPoints) == 0 {
		t.Error("IACA must carry a CRL distribution point (Table B.1)")
	}
	if !hasExtension(iaca, "2.5.29.18") {
		t.Error("IACA must carry issuerAltName (Table B.1)")
	}
	if len(iaca.Subject.Country) == 0 || len(iaca.Subject.Organization) == 0 {
		t.Error("IACA subject must include countryName and organizationName (Table B.1)")
	}
	// Self-signed: subject == issuer and it verifies its own signature.
	if !reflect.DeepEqual(iaca.RawSubject, iaca.RawIssuer) {
		t.Error("IACA subject must equal issuer (self-signed root)")
	}
	if err := iaca.CheckSignatureFrom(iaca); err != nil {
		t.Errorf("IACA must be self-signed: %v", err)
	}
	span := iaca.NotAfter.Sub(iaca.NotBefore)
	if span > iacaMaxValidity {
		t.Errorf("IACA validity %s exceeds Annex B 15-year cap", span)
	}
}

// TestDSProfileConformsToAnnexB checks the document signer against ISO/IEC
// 18013-5 Table B.3: digitalSignature only, the mDL DS EKU OID, CA=FALSE,
// authorityKeyId bound to the IACA, validity inside the 15-month cap, and a
// valid path to the IACA root.
func TestDSProfileConformsToAnnexB(t *testing.T) {
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	ds := pki.DocumentSignerCertificate()
	iaca := pki.IACACertificate()

	if ds.IsCA {
		t.Error("DS must not be a CA (Table B.3 Basic Constraints CA=FALSE)")
	}
	if ds.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("DS keyUsage = %b, want digitalSignature only", ds.KeyUsage)
	}
	if !hasExtKeyUsageOID(ds, OIDExtKeyUsageMDLDS) {
		t.Errorf("DS must carry the mDL DS extended key usage %s (Table B.3)", OIDExtKeyUsageMDLDS)
	}
	if len(ds.CRLDistributionPoints) == 0 {
		t.Error("DS must carry a CRL distribution point (Table B.3)")
	}
	if !hasExtension(ds, "2.5.29.18") {
		t.Error("DS must carry issuerAltName (Table B.3)")
	}
	if string(ds.AuthorityKeyId) != string(iaca.SubjectKeyId) {
		t.Error("DS authorityKeyId must match the IACA subjectKeyId (Table B.3)")
	}
	span := ds.NotAfter.Sub(ds.NotBefore)
	if span > dsMaxValidity {
		t.Errorf("DS validity %s exceeds Annex B 15-month cap", span)
	}
	if ds.NotAfter.After(iaca.NotAfter) {
		t.Error("DS must not outlive the IACA root")
	}
	// The DS must chain to the IACA root.
	roots := pki.TrustAnchors()
	if _, err := ds.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("DS must validate against the IACA root: %v", err)
	}
}

// TestDocumentSignerChainExcludesRoot confirms the x5chain carries only the DS
// leaf, not the IACA root (the root is the verifier's configured trust anchor).
func TestDocumentSignerChainExcludesRoot(t *testing.T) {
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	chain := pki.DocumentSignerChain()
	if len(chain) != 1 {
		t.Fatalf("expected x5chain length 1 (DS leaf only), got %d", len(chain))
	}
	if !reflect.DeepEqual(chain[0].Raw, pki.DocumentSignerCertificate().Raw) {
		t.Error("x5chain[0] must be the DS leaf certificate")
	}
}

// TestPKIParamsRejectOverlongValidity ensures the profile caps are enforced.
func TestPKIParamsRejectOverlongValidity(t *testing.T) {
	params := testPKIParams()
	params.DSValidity = 500 * 24 * time.Hour // > 15 months
	if _, err := GenerateIssuerPKI(params); err == nil {
		t.Fatal("expected error for DS validity beyond the Annex B cap")
	}

	params = testPKIParams()
	params.IACAValidity = 20 * 365 * 24 * time.Hour // > 15 years
	if _, err := GenerateIssuerPKI(params); err == nil {
		t.Fatal("expected error for IACA validity beyond the Annex B cap")
	}
}

// TestLoadOrCreateIssuerPKIPersists confirms the PKI is stable across reloads:
// the same IACA, DS certificate, and DS key are returned (no regeneration).
func TestLoadOrCreateIssuerPKIPersists(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateIssuerPKI(dir, testPKIParams())
	if err != nil {
		t.Fatalf("first LoadOrCreateIssuerPKI: %v", err)
	}
	second, err := LoadOrCreateIssuerPKI(dir, testPKIParams())
	if err != nil {
		t.Fatalf("second LoadOrCreateIssuerPKI: %v", err)
	}
	if !reflect.DeepEqual(first.IACACertificate().Raw, second.IACACertificate().Raw) {
		t.Error("IACA certificate must be stable across reloads")
	}
	if !reflect.DeepEqual(first.DocumentSignerCertificate().Raw, second.DocumentSignerCertificate().Raw) {
		t.Error("DS certificate must be stable across reloads")
	}
	firstDSKey, err := first.DocumentSignerKey().Bytes()
	if err != nil {
		t.Fatalf("encode first DS private key: %v", err)
	}
	secondDSKey, err := second.DocumentSignerKey().Bytes()
	if err != nil {
		t.Fatalf("encode second DS private key: %v", err)
	}
	if !reflect.DeepEqual(firstDSKey, secondDSKey) {
		t.Error("DS private key must be stable across reloads")
	}
}

// TestIssuerSignedRoundTripVerifiesAgainstTrustAnchor exercises the full
// issuance shape: build IssuerSigned signed by the DS key, encode to the wire,
// decode, and verify against the IACA trust anchor.
func TestIssuerSignedRoundTripVerifiesAgainstTrustAnchor(t *testing.T) {
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	now := time.Now().Truncate(time.Second).UTC()

	item, err := NewIssuerSignedItem(0, "family_name", "Citizen")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	dateItem, err := NewIssuerSignedItem(1, "birth_date", intcose.FullDate(now.AddDate(-30, 0, 0)))
	if err != nil {
		t.Fatalf("NewIssuerSignedItem date: %v", err)
	}
	ns, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: {item, dateItem}})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}
	vd, err := BuildValueDigests(ns, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}

	devKeyCOSE, err := intcose.ECPublicKeyToCOSEKey(&pki.DocumentSignerKey().PublicKey)
	if err != nil {
		t.Fatalf("device COSE key: %v", err)
	}
	mso := BuildMSO(vd, devKeyCOSE, DocTypeMDL, ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(48 * time.Hour)})
	msoBytes, err := EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}

	issuerSigned := IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}
	encoded, err := EncodeIssuerSigned(issuerSigned)
	if err != nil {
		t.Fatalf("EncodeIssuerSigned: %v", err)
	}

	decoded, err := DecodeIssuerSigned(encoded)
	if err != nil {
		t.Fatalf("DecodeIssuerSigned: %v", err)
	}
	if _, err := VerifyIssuerSigned(decoded, pki.TrustAnchors(), now.Add(time.Hour)); err != nil {
		t.Fatalf("VerifyIssuerSigned against IACA trust anchor: %v", err)
	}

	// An unrelated trust anchor must be rejected (the DS chains only to its IACA).
	other, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("second GenerateIssuerPKI: %v", err)
	}
	if _, err := VerifyIssuerSigned(decoded, other.TrustAnchors(), now.Add(time.Hour)); err == nil {
		t.Fatal("expected verification failure against an unrelated IACA root")
	}
}

func hasExtension(cert *x509.Certificate, oid string) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == oid {
			return true
		}
	}
	return false
}

func hasExtKeyUsageOID(cert *x509.Certificate, oid []int) bool {
	for _, got := range cert.UnknownExtKeyUsage {
		if got.Equal(oid) {
			return true
		}
	}
	return false
}
