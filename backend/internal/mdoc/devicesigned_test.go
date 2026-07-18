package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// testHolderCredential issues a real mDL IssuerSigned bound to deviceKey's
// public half (MSO deviceKeyInfo.deviceKey), signed by a freshly generated IACA
// document signer. It returns the IssuerSigned plus the trust anchors.
func testHolderCredential(t *testing.T, deviceKey *ecdsa.PrivateKey) (IssuerSigned, *MobileSecurityObject) {
	t.Helper()
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	now := time.Now().Truncate(time.Second).UTC()

	family, err := NewIssuerSignedItem(0, "family_name", "Citizen")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	given, err := NewIssuerSignedItem(1, "given_name", "Alex")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	age, err := NewIssuerSignedItem(2, "age_over_18", true)
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	ns, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: {family, given, age}})
	if err != nil {
		t.Fatalf("BuildIssuerNameSpaces: %v", err)
	}
	vd, err := BuildValueDigests(ns, DigestAlgorithmSHA256)
	if err != nil {
		t.Fatalf("BuildValueDigests: %v", err)
	}

	deviceCOSEKey, err := intcose.ECPublicKeyToCOSEKey(&deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("ECPublicKeyToCOSEKey: %v", err)
	}
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(48 * time.Hour)})
	msoBytes, err := EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	return IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}, &mso
}

// fixedTestHandover builds the deterministic test handover used to exercise the
// SessionTranscript construction independently of the OID4VP handover.
func fixedTestHandover(t *testing.T) []byte {
	t.Helper()
	handover, err := EncodeHandover([]any{"test-handover", "client-123", "nonce-abc"})
	if err != nil {
		t.Fatalf("EncodeHandover: %v", err)
	}
	return handover
}

func TestSessionTranscriptOID4VPShape(t *testing.T) {
	handover := fixedTestHandover(t)
	st, err := NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	encoded, err := st.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// [null, null, Handover]: 0x83 (array(3)), 0xf6 (null), 0xf6 (null), ...
	if len(encoded) < 3 {
		t.Fatalf("encoded SessionTranscript too short: %d bytes", len(encoded))
	}
	if encoded[0] != 0x83 {
		t.Fatalf("SessionTranscript must be a 3-element array (0x83), got 0x%02x", encoded[0])
	}
	if encoded[1] != 0xf6 || encoded[2] != 0xf6 {
		t.Fatalf("DeviceEngagementBytes and EReaderKeyBytes must be CBOR null, got 0x%02x 0x%02x", encoded[1], encoded[2])
	}
	if !bytes.HasSuffix(encoded, handover) {
		t.Fatal("SessionTranscript must end with the verbatim handover bytes")
	}

	if _, err := NewOID4VPSessionTranscript(nil); err == nil {
		t.Fatal("expected error for empty handover")
	}
}

func TestSessionTranscriptDeterministicAcrossSides(t *testing.T) {
	handover := fixedTestHandover(t)
	// The wallet and the verifier each build their own transcript from the same
	// inputs; the bytes must be identical or device authentication fails.
	walletSide, err := NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("wallet NewOID4VPSessionTranscript: %v", err)
	}
	verifierSide, err := NewOID4VPSessionTranscript(append([]byte(nil), handover...))
	if err != nil {
		t.Fatalf("verifier NewOID4VPSessionTranscript: %v", err)
	}
	a, err := walletSide.Encode()
	if err != nil {
		t.Fatalf("wallet Encode: %v", err)
	}
	b, err := verifierSide.Encode()
	if err != nil {
		t.Fatalf("verifier Encode: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("SessionTranscript bytes diverged between wallet and verifier sides")
	}
}

func TestEmptyDeviceNameSpacesIsTag24Wrapped(t *testing.T) {
	encoded, err := EncodeDeviceNameSpacesBytes(nil)
	if err != nil {
		t.Fatalf("EncodeDeviceNameSpacesBytes: %v", err)
	}
	// #6.24(bstr .cbor {}) => tag 24 (0xd8 0x18), bstr len 1 (0x41), empty map (0xa0).
	want := []byte{0xd8, 0x18, 0x41, 0xa0}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("empty DeviceNameSpacesBytes = % x, want % x", encoded, want)
	}
	inner, err := intcose.DecodeTagged24(encoded)
	if err != nil {
		t.Fatalf("DecodeTagged24: %v", err)
	}
	if !bytes.Equal(inner, []byte{0xa0}) {
		t.Fatalf("inner DeviceNameSpaces = % x, want empty map a0", inner)
	}
}

func TestDeviceSignatureVerifiesOverDeviceAuthenticationBytes(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	st, err := NewOID4VPSessionTranscript(fixedTestHandover(t))
	if err != nil {
		t.Fatalf("session transcript: %v", err)
	}
	transcript, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}

	deviceSigned, err := BuildDeviceSigned(deviceKey, transcript, DocTypeMDL, nil)
	if err != nil {
		t.Fatalf("BuildDeviceSigned: %v", err)
	}

	// The deviceSignature must be transmitted with a detached (nil) payload.
	parsed, err := intcose.ParseSign1(deviceSigned.DeviceSignature)
	if err != nil {
		t.Fatalf("ParseSign1: %v", err)
	}
	if parsed.Payload != nil {
		t.Fatalf("deviceSignature must carry a detached payload, got %d bytes", len(parsed.Payload))
	}

	if err := VerifyDeviceSignature(deviceSigned, transcript, DocTypeMDL, &deviceKey.PublicKey); err != nil {
		t.Fatalf("VerifyDeviceSignature: %v", err)
	}
}

func TestDeviceSignatureRejectsTamperedInputs(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	st, err := NewOID4VPSessionTranscript(fixedTestHandover(t))
	if err != nil {
		t.Fatalf("session transcript: %v", err)
	}
	transcript, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	deviceSigned, err := BuildDeviceSigned(deviceKey, transcript, DocTypeMDL, nil)
	if err != nil {
		t.Fatalf("BuildDeviceSigned: %v", err)
	}

	t.Run("wrong device key", func(t *testing.T) {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err := VerifyDeviceSignature(deviceSigned, transcript, DocTypeMDL, &other.PublicKey); err == nil {
			t.Fatal("expected verification failure against an unrelated device key")
		}
	})

	t.Run("different session transcript", func(t *testing.T) {
		otherSt, _ := NewOID4VPSessionTranscript([]byte{0x63, 'a', 'b', 'c'})
		otherTranscript, _ := otherSt.Encode()
		if err := VerifyDeviceSignature(deviceSigned, otherTranscript, DocTypeMDL, &deviceKey.PublicKey); err == nil {
			t.Fatal("expected verification failure with a different SessionTranscript")
		}
	})

	t.Run("different doctype", func(t *testing.T) {
		if err := VerifyDeviceSignature(deviceSigned, transcript, "org.iso.18013.5.1.other", &deviceKey.PublicKey); err == nil {
			t.Fatal("expected verification failure with a different docType")
		}
	})
}

func TestBuildAndDecodeDeviceResponse(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, mso := testHolderCredential(t, deviceKey)

	st, err := NewOID4VPSessionTranscript(fixedTestHandover(t))
	if err != nil {
		t.Fatalf("session transcript: %v", err)
	}
	transcript, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}

	requested := map[NameSpace][]string{NameSpaceMDL: {"family_name", "age_over_18"}}
	response, err := BuildDeviceResponse(deviceKey, issuerSigned, DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}
	if response.Version != "1.0" || response.Status != 0 {
		t.Fatalf("unexpected DeviceResponse envelope: version=%q status=%d", response.Version, response.Status)
	}

	encoded, err := EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse: %v", err)
	}
	decoded, err := DecodeDeviceResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse: %v", err)
	}
	if len(decoded.Documents) != 1 {
		t.Fatalf("expected 1 document, got %d", len(decoded.Documents))
	}
	doc := decoded.Documents[0]
	if doc.DocType != DocTypeMDL {
		t.Fatalf("docType = %q, want %q", doc.DocType, DocTypeMDL)
	}

	// Only the requested elements should be disclosed; the MSO is unchanged.
	disclosedItems := doc.IssuerSigned.NameSpaces[NameSpaceMDL]
	if len(disclosedItems) != 2 {
		t.Fatalf("expected 2 disclosed items, got %d", len(disclosedItems))
	}

	// The issuer signature and value digests still verify on the disclosed subset.
	verifiedMSO, err := VerifyIssuerSignedWithKey(doc.IssuerSigned, mustDocSignerPub(t, issuerSigned), time.Now())
	if err != nil {
		t.Fatalf("VerifyIssuerSigned on disclosed subset: %v", err)
	}

	// The device public key bound in the MSO verifies the deviceSignature over
	// the same SessionTranscript both sides reconstruct.
	boundDeviceKey, err := intcose.COSEKeyToECPublicKey(verifiedMSO.DeviceKeyInfo.DeviceKey)
	if err != nil {
		t.Fatalf("COSEKeyToECPublicKey: %v", err)
	}
	if err := VerifyDeviceSignature(doc.DeviceSigned, transcript, doc.DocType, boundDeviceKey); err != nil {
		t.Fatalf("VerifyDeviceSignature with MSO-bound key: %v", err)
	}

	// Sanity: the bound key is the holder device key, not the issuer.
	if !boundDeviceKey.Equal(&deviceKey.PublicKey) {
		t.Fatal("MSO-bound device key does not match the holder device key")
	}
	_ = mso
}

// mustDocSignerPub extracts the document-signer public key from the IssuerAuth
// x5chain so tests can verify the disclosed IssuerSigned without a trust pool.
func mustDocSignerPub(t *testing.T, is IssuerSigned) *ecdsa.PublicKey {
	t.Helper()
	_, msg, err := ParseIssuerAuth(is.IssuerAuth)
	if err != nil {
		t.Fatalf("ParseIssuerAuth: %v", err)
	}
	chain, err := intcose.GetX5Chain(msg.Headers.Unprotected)
	if err != nil {
		t.Fatalf("GetX5Chain: %v", err)
	}
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("document signer key is %T, want *ecdsa.PublicKey", chain[0].PublicKey)
	}
	return pub
}
