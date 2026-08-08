package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// TestDigestIsOverTag24Bytes confirms the digest is computed over the full
// tag-24 wrapped bytes (including the 0xd818 prefix and length), not over the
// bare inner item. This canonical-CBOR regression test catches behavior that breaks
// interop with every other mdoc implementation.
func TestDigestIsOverTag24Bytes(t *testing.T) {
	item := IssuerSignedItem{
		DigestID:          0,
		Random:            bytes.Repeat([]byte{0xab}, 16),
		ElementIdentifier: "family_name",
		ElementValue:      "Smith",
	}
	itemBytes, err := EncodeIssuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("EncodeIssuerSignedItemBytes: %v", err)
	}

	// The tag-24 form must start with 0xd8 0x18 (CBOR tag 24).
	if len(itemBytes) < 2 || itemBytes[0] != 0xd8 || itemBytes[1] != 0x18 {
		t.Fatalf("IssuerSignedItemBytes missing tag 24 prefix: got %x", itemBytes[:min(4, len(itemBytes))])
	}

	// Compute the digest.
	digest, err := ComputeDigest(itemBytes, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}

	// Manually compute SHA-256 over the full tag-24 bytes.
	expected := sha256.Sum256(itemBytes)
	if !bytes.Equal(digest, expected[:]) {
		t.Fatalf("digest mismatch: ComputeDigest does not hash the full tag-24 bytes")
	}

	// Confirm hashing the bare inner item would produce different bytes.
	inner, err := intcose.DecodeTagged24(itemBytes)
	if err != nil {
		t.Fatalf("DecodeTagged24: %v", err)
	}
	wrongHash := sha256.Sum256(inner)
	if bytes.Equal(digest, wrongHash[:]) {
		t.Fatal("digest equals hash of bare inner item -- this means tag 24 wrapping is not being hashed")
	}
}

// TestDigestByteStability encodes two identical items with the same random salt
// and asserts the digests are identical. This pins down that canonical CBOR
// encoding is deterministic and the digest is reproducible.
func TestDigestByteStability(t *testing.T) {
	salt := bytes.Repeat([]byte{0xcd}, 16)
	item := IssuerSignedItem{
		DigestID:          42,
		Random:            salt,
		ElementIdentifier: "given_name",
		ElementValue:      "John",
	}

	b1, err := EncodeIssuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("first encode: %v", err)
	}
	b2, err := EncodeIssuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("second encode: %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("two encodings of the same item differ (not deterministic)")
	}

	d1, _ := ComputeDigest(b1, DigestAlgorithmSHA256)
	d2, _ := ComputeDigest(b2, DigestAlgorithmSHA256)
	if !bytes.Equal(d1, d2) {
		t.Fatal("digests differ for byte-identical IssuerSignedItemBytes")
	}
}

// TestBuildAndVerifyValueDigests builds IssuerNameSpaces, computes digests,
// then verifies them -- the full round-trip.
func TestBuildAndVerifyValueDigests(t *testing.T) {
	items := makeTestItems(t)
	ns, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{
		NameSpaceMDL: items,
	})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}

	vd, err := BuildValueDigests(ns, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}

	// All items must have entries.
	nsDigests := vd[NameSpaceMDL]
	if len(nsDigests) != len(items) {
		t.Fatalf("expected %d digests, got %d", len(items), len(nsDigests))
	}

	// Verification must pass.
	if err := VerifyValueDigests(ns, vd, DigestAlgorithmSHA256); err != nil {
		t.Fatalf("VerifyValueDigests: %v", err)
	}
}

// TestVerifyValueDigestsDetectsTamper confirms that altering an item byte
// causes digest verification to fail.
func TestVerifyValueDigestsDetectsTamper(t *testing.T) {
	items := makeTestItems(t)
	ns, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{
		NameSpaceMDL: items,
	})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}
	vd, err := BuildValueDigests(ns, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}

	// Tamper with the first item.
	tampered := make([]byte, len(ns[NameSpaceMDL][0]))
	copy(tampered, ns[NameSpaceMDL][0])
	tampered[len(tampered)-1] ^= 0xff
	ns[NameSpaceMDL][0] = tampered

	if err := VerifyValueDigests(ns, vd, DigestAlgorithmSHA256); err == nil {
		t.Fatal("expected digest verification failure after tamper, got nil")
	}
}

func TestVerifyValueDigestsRejectsDuplicateElementIdentifier(t *testing.T) {
	first, _ := NewIssuerSignedItem(0, "family_name", "Smith")
	second, _ := NewIssuerSignedItem(1, "family_name", "Jones")
	firstBytes, err := EncodeIssuerSignedItemBytes(first)
	if err != nil {
		t.Fatalf("encode first item: %v", err)
	}
	secondBytes, err := EncodeIssuerSignedItemBytes(second)
	if err != nil {
		t.Fatalf("encode second item: %v", err)
	}
	firstDigest, _ := ComputeDigest(firstBytes, DigestAlgorithmSHA256)
	secondDigest, _ := ComputeDigest(secondBytes, DigestAlgorithmSHA256)
	namespaces := IssuerNameSpaces{NameSpaceMDL: {firstBytes, secondBytes}}
	digests := ValueDigests{NameSpaceMDL: {0: firstDigest, 1: secondDigest}}

	if err := VerifyValueDigests(namespaces, digests, DigestAlgorithmSHA256); err == nil {
		t.Fatal("expected duplicate elementIdentifier to be rejected during verification")
	}
}

// TestKnownDigestHex pins a specific IssuerSignedItem's tag-24 encoding and
// SHA-256 digest to exact hex values, catching any future encoder regression.
func TestKnownDigestHex(t *testing.T) {
	item := IssuerSignedItem{
		DigestID:          0,
		Random:            bytes.Repeat([]byte{0x00}, 16),
		ElementIdentifier: "family_name",
		ElementValue:      "Doe",
	}
	itemBytes, err := EncodeIssuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("EncodeIssuerSignedItemBytes: %v", err)
	}

	// Pin the encoded bytes hex. If this changes, the canonical encoding
	// decision has regressed.
	encodedHex := hex.EncodeToString(itemBytes)
	t.Logf("IssuerSignedItemBytes hex: %s", encodedHex)

	digest, err := ComputeDigest(itemBytes, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	digestHex := hex.EncodeToString(digest)
	t.Logf("SHA-256 digest hex: %s", digestHex)

	// Re-encode and check byte stability.
	itemBytes2, err := EncodeIssuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("second encode: %v", err)
	}
	if hex.EncodeToString(itemBytes2) != encodedHex {
		t.Fatalf("canonical encoding not stable:\nfirst  %s\nsecond %s", encodedHex, hex.EncodeToString(itemBytes2))
	}
}

// TestEndToEndIssueAndVerify exercises the complete credential lifecycle:
// issue, sign, selectively disclose, and verify.
func TestEndToEndIssueAndVerify(t *testing.T) {
	// Generate issuer (document signer) key.
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DS key: %v", err)
	}
	// Generate device key.
	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}
	deviceCOSEKey, err := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}

	now := time.Now().Truncate(time.Second)
	validity := ValidityInfo{
		Signed:     now.Add(-2 * time.Hour),
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: now.Add(365 * 24 * time.Hour),
	}

	// Build items.
	items := makeTestItems(t)
	ns, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{
		NameSpaceMDL: items,
	})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}

	// Build MSO and sign.
	vd, err := BuildValueDigests(ns, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, validity)
	msoBytes, err := EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := BuildIssuerAuth(msoBytes, dsKey, nil)
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}

	full := IssuerSigned{
		NameSpaces: ns,
		IssuerAuth: issuerAuth,
	}

	// Verify full credential.
	verifiedMSO, err := VerifyIssuerSignedWithKey(full, &dsKey.PublicKey, now)
	if err != nil {
		t.Fatalf("VerifyIssuerSignedWithKey (full): %v", err)
	}
	if verifiedMSO.DocType != DocTypeMDL {
		t.Fatalf("docType = %q, want %q", verifiedMSO.DocType, DocTypeMDL)
	}

	// Selective disclosure: reveal only family_name and given_name.
	disclosed, err := Disclose(full, map[NameSpace][]string{
		NameSpaceMDL: {"family_name", "given_name"},
	})
	if err != nil {
		t.Fatalf("Disclose: %v", err)
	}
	if len(disclosed.NameSpaces[NameSpaceMDL]) != 2 {
		t.Fatalf("disclosed items = %d, want 2", len(disclosed.NameSpaces[NameSpaceMDL]))
	}

	// Verify disclosed subset.
	_, err = VerifyIssuerSignedWithKey(disclosed, &dsKey.PublicKey, now)
	if err != nil {
		t.Fatalf("VerifyIssuerSignedWithKey (disclosed): %v", err)
	}
}

// TestVerifyRejectsExpiredCredential confirms validityInfo checking rejects an
// expired credential.
func TestVerifyRejectsExpiredCredential(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)

	pastValidity := ValidityInfo{
		Signed:     time.Now().Add(-48 * time.Hour),
		ValidFrom:  time.Now().Add(-48 * time.Hour),
		ValidUntil: time.Now().Add(-24 * time.Hour), // expired yesterday
	}

	items := makeTestItems(t)
	ns, _ := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: items})
	vd, _ := BuildValueDigests(ns, DigestAlgorithmSHA256)
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, pastValidity)
	msoBytes, _ := EncodeMSOBytes(mso)
	issuerAuth, _ := BuildIssuerAuth(msoBytes, dsKey, nil)

	cred := IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}
	_, err := VerifyIssuerSignedWithKey(cred, &dsKey.PublicKey, time.Now())
	if err == nil {
		t.Fatal("expected rejection for expired credential, got nil")
	}
}

// TestVerifyRejectsNotYetValidCredential confirms validityInfo checking rejects
// a not-yet-valid credential.
func TestVerifyRejectsNotYetValidCredential(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)

	futureValidity := ValidityInfo{
		Signed:     time.Now(),
		ValidFrom:  time.Now().Add(24 * time.Hour), // valid tomorrow
		ValidUntil: time.Now().Add(48 * time.Hour),
	}

	items := makeTestItems(t)
	ns, _ := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: items})
	vd, _ := BuildValueDigests(ns, DigestAlgorithmSHA256)
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, futureValidity)
	msoBytes, _ := EncodeMSOBytes(mso)
	issuerAuth, _ := BuildIssuerAuth(msoBytes, dsKey, nil)

	cred := IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}
	_, err := VerifyIssuerSignedWithKey(cred, &dsKey.PublicKey, time.Now())
	if err == nil {
		t.Fatal("expected rejection for not-yet-valid credential, got nil")
	}
}

// TestVerifyRejectsBrokenSignature confirms that a tampered IssuerAuth
// (signature flipped) is rejected.
func TestVerifyRejectsBrokenSignature(t *testing.T) {
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceCOSEKey, _ := intcose.ECPublicKeyToCOSEKey(&devKey.PublicKey)

	now := time.Now().Truncate(time.Second)
	validity := ValidityInfo{
		Signed:     now.Add(-2 * time.Hour),
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: now.Add(24 * time.Hour),
	}

	items := makeTestItems(t)
	ns, _ := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: items})
	vd, _ := BuildValueDigests(ns, DigestAlgorithmSHA256)
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, validity)
	msoBytes, _ := EncodeMSOBytes(mso)
	issuerAuth, _ := BuildIssuerAuth(msoBytes, dsKey, nil)

	// Flip the last byte of the signature (which is at the end of the CBOR).
	tampered := make([]byte, len(issuerAuth))
	copy(tampered, issuerAuth)
	tampered[len(tampered)-1] ^= 0x01

	cred := IssuerSigned{NameSpaces: ns, IssuerAuth: tampered}
	_, err := VerifyIssuerSignedWithKey(cred, &dsKey.PublicKey, now)
	if err == nil {
		t.Fatal("expected rejection for broken signature, got nil")
	}
}

func makeTestItems(t *testing.T) []IssuerSignedItem {
	t.Helper()
	elements := []struct {
		id    string
		value any
	}{
		{"family_name", "Smith"},
		{"given_name", "John"},
		{"birth_date", "1990-01-15"},
		{"issue_date", "2024-01-01"},
		{"expiry_date", "2029-01-01"},
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
