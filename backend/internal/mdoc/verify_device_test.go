package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// issueTestCredential issues a real mDL IssuerSigned bound to deviceKey's public
// half, signed by a freshly generated IACA document signer, with a caller-chosen
// validity window. It returns the IssuerSigned and the IssuerPKI (whose
// TrustAnchors are the IACA root the verifier chains to).
func issueTestCredential(t *testing.T, deviceKey *ecdsa.PrivateKey, validity ValidityInfo) (IssuerSigned, *IssuerPKI) {
	t.Helper()
	pki, err := GenerateIssuerPKI(testPKIParams())
	if err != nil {
		t.Fatalf("GenerateIssuerPKI: %v", err)
	}
	family, err := NewIssuerSignedItem(0, "family_name", "Citizen")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	given, err := NewIssuerSignedItem(1, "given_name", "Alex")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	docNumber, err := NewIssuerSignedItem(2, "document_number", "D-9007-2026")
	if err != nil {
		t.Fatalf("NewIssuerSignedItem: %v", err)
	}
	ns, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{NameSpaceMDL: {family, given, docNumber}})
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
	mso := BuildMSO(vd, deviceCOSEKey, DocTypeMDL, validity)
	msoBytes, err := EncodeMSOBytes(mso)
	if err != nil {
		t.Fatalf("EncodeMSOBytes: %v", err)
	}
	issuerAuth, err := BuildIssuerAuth(msoBytes, pki.DocumentSignerKey(), pki.DocumentSignerChain())
	if err != nil {
		t.Fatalf("BuildIssuerAuth: %v", err)
	}
	return IssuerSigned{NameSpaces: ns, IssuerAuth: issuerAuth}, pki
}

func validNow() ValidityInfo {
	now := time.Now().Truncate(time.Second).UTC()
	return ValidityInfo{Signed: now.Add(-2 * time.Hour), ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(48 * time.Hour)}
}

// TestVerifyDeviceResponseRoundTrip verifies that the wallet
// builds a DeviceResponse over the shared SessionTranscript, and the verifier
// reconstructs the identical SessionTranscript and accepts both the
// issuer signature (chaining the DS cert to the IACA root) and the holder
// deviceSignature, recovering the disclosed namespace/element values.
func TestVerifyDeviceResponseRoundTrip(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueTestCredential(t, deviceKey, validNow())

	handover, err := EncodeHandover([]any{"test-handover", "client-123", "nonce-abc"})
	if err != nil {
		t.Fatalf("EncodeHandover: %v", err)
	}
	st, err := NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("NewOID4VPSessionTranscript: %v", err)
	}
	transcript, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}

	requested := map[NameSpace][]string{NameSpaceMDL: {"family_name", "document_number"}}
	response, err := BuildDeviceResponse(deviceKey, issuerSigned, DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}
	wire, err := EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse: %v", err)
	}

	// The verifier decodes the wire bytes and reconstructs its own transcript.
	decoded, err := DecodeDeviceResponse(wire)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse: %v", err)
	}
	verifierSt, err := NewOID4VPSessionTranscript(handover)
	if err != nil {
		t.Fatalf("verifier NewOID4VPSessionTranscript: %v", err)
	}
	verifierTranscript, err := verifierSt.Encode()
	if err != nil {
		t.Fatalf("verifier encode transcript: %v", err)
	}

	verified, err := VerifyDeviceResponse(decoded, verifierTranscript, pki.TrustAnchors(), time.Now())
	if err != nil {
		t.Fatalf("VerifyDeviceResponse: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("expected 1 verified document, got %d", len(verified))
	}
	doc := verified[0]
	if doc.DocType != DocTypeMDL {
		t.Fatalf("docType = %q, want %q", doc.DocType, DocTypeMDL)
	}
	elements := doc.DisclosedClaims[NameSpaceMDL]
	if got, ok := elements["family_name"]; !ok || got != "Citizen" {
		t.Fatalf("family_name disclosed = %v (present=%v), want Citizen", got, ok)
	}
	if got, ok := elements["document_number"]; !ok || got != "D-9007-2026" {
		t.Fatalf("document_number disclosed = %v (present=%v), want D-9007-2026", got, ok)
	}
	if _, leaked := elements["given_name"]; leaked {
		t.Fatal("given_name was not requested and must not be disclosed")
	}
}

func TestDeviceResponseRejectsUnsupportedVersion(t *testing.T) {
	if _, err := EncodeDeviceResponse(DeviceResponse{Version: "2.0"}); err == nil {
		t.Fatal("expected encoding to reject unsupported DeviceResponse version")
	}
	wire, err := intcose.MarshalDeterministic(deviceResponseWire{Version: "2.0", Status: DeviceResponseStatusOK})
	if err != nil {
		t.Fatalf("encode test DeviceResponse: %v", err)
	}
	if _, err := DecodeDeviceResponse(wire); err == nil {
		t.Fatal("expected decoding to reject unsupported DeviceResponse version")
	}
	if _, err := VerifyDeviceResponse(DeviceResponse{Version: "2.0"}, nil, nil, time.Now()); err == nil {
		t.Fatal("expected verification to reject unsupported DeviceResponse version")
	}
}

// TestVerifyDeviceResponseRejectsTamperedDigest alters a disclosed
// IssuerSignedItem after issuance; the recomputed digest no longer matches the
// MSO valueDigests, so issuer verification must reject it (ISO/IEC 18013-5
// clause 9.3.1).
func TestVerifyDeviceResponseRejectsTamperedDigest(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueTestCredential(t, deviceKey, validNow())

	handover, _ := EncodeHandover([]any{"test-handover"})
	st, _ := NewOID4VPSessionTranscript(handover)
	transcript, _ := st.Encode()

	requested := map[NameSpace][]string{NameSpaceMDL: {"family_name"}}
	response, err := BuildDeviceResponse(deviceKey, issuerSigned, DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}

	// Tamper: re-encode the disclosed family_name item with a different value
	// (keeping its digestID and salt structure but mutating elementValue).
	items := response.Documents[0].IssuerSigned.NameSpaces[NameSpaceMDL]
	if len(items) != 1 {
		t.Fatalf("expected 1 disclosed item, got %d", len(items))
	}
	tamperedItem, err := DecodeIssuerSignedItemBytes(items[0])
	if err != nil {
		t.Fatalf("DecodeIssuerSignedItemBytes: %v", err)
	}
	tamperedItem.ElementValue = "Forged"
	tamperedBytes, err := EncodeIssuerSignedItemBytes(tamperedItem)
	if err != nil {
		t.Fatalf("EncodeIssuerSignedItemBytes: %v", err)
	}
	response.Documents[0].IssuerSigned.NameSpaces[NameSpaceMDL][0] = tamperedBytes

	if _, err := VerifyDeviceResponse(response, transcript, pki.TrustAnchors(), time.Now()); err == nil {
		t.Fatal("expected verification failure for a tampered disclosed item (digest mismatch)")
	}
}

// TestVerifyDeviceResponseRejectsWrongDeviceKey signs device authentication with
// a key other than the one bound in the MSO deviceKeyInfo. Issuer verification
// passes, but the deviceSignature must fail against the MSO-bound key.
func TestVerifyDeviceResponseRejectsWrongDeviceKey(t *testing.T) {
	boundKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("bound key: %v", err)
	}
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("attacker key: %v", err)
	}
	// MSO binds boundKey, but the DeviceResponse is signed by attackerKey.
	issuerSigned, pki := issueTestCredential(t, boundKey, validNow())

	handover, _ := EncodeHandover([]any{"test-handover"})
	st, _ := NewOID4VPSessionTranscript(handover)
	transcript, _ := st.Encode()

	requested := map[NameSpace][]string{NameSpaceMDL: {"family_name"}}
	response, err := BuildDeviceResponse(attackerKey, issuerSigned, DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}

	if _, err := VerifyDeviceResponse(response, transcript, pki.TrustAnchors(), time.Now()); err == nil {
		t.Fatal("expected device authentication failure when deviceSignature key != MSO deviceKey")
	}
}

// TestVerifyDeviceResponseRejectsExpired verifies a credential outside its
// validityInfo window; VerifyIssuerSigned must reject it (ISO/IEC 18013-5
// clause 9.1.2 validityInfo).
func TestVerifyDeviceResponseRejectsExpired(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	past := time.Now().Add(-72 * time.Hour).Truncate(time.Second).UTC()
	expired := ValidityInfo{Signed: past, ValidFrom: past, ValidUntil: past.Add(24 * time.Hour)}
	issuerSigned, pki := issueTestCredential(t, deviceKey, expired)

	handover, _ := EncodeHandover([]any{"test-handover"})
	st, _ := NewOID4VPSessionTranscript(handover)
	transcript, _ := st.Encode()

	requested := map[NameSpace][]string{NameSpaceMDL: {"family_name"}}
	response, err := BuildDeviceResponse(deviceKey, issuerSigned, DocTypeMDL, transcript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}

	if _, err := VerifyDeviceResponse(response, transcript, pki.TrustAnchors(), time.Now()); err == nil {
		t.Fatal("expected verification failure for a credential past its validUntil")
	}
}

// TestVerifyDeviceResponseRejectsSessionTranscriptMismatch proves the binding is
// genuine: the wallet signs over one handover, the verifier reconstructs a
// different handover, and device authentication must fail. A SessionTranscript
// mismatch is the dominant mdoc presentation failure mode, so this guards it.
func TestVerifyDeviceResponseRejectsSessionTranscriptMismatch(t *testing.T) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	issuerSigned, pki := issueTestCredential(t, deviceKey, validNow())

	walletHandover, _ := EncodeHandover([]any{"test-handover", "client-123", "nonce-abc"})
	walletSt, _ := NewOID4VPSessionTranscript(walletHandover)
	walletTranscript, _ := walletSt.Encode()

	requested := map[NameSpace][]string{NameSpaceMDL: {"family_name"}}
	response, err := BuildDeviceResponse(deviceKey, issuerSigned, DocTypeMDL, walletTranscript, requested, nil)
	if err != nil {
		t.Fatalf("BuildDeviceResponse: %v", err)
	}

	// The verifier reconstructs a different handover (e.g. a different nonce).
	verifierHandover, _ := EncodeHandover([]any{"test-handover", "client-123", "nonce-DIFFERENT"})
	verifierSt, _ := NewOID4VPSessionTranscript(verifierHandover)
	verifierTranscript, _ := verifierSt.Encode()

	if _, err := VerifyDeviceResponse(response, verifierTranscript, pki.TrustAnchors(), time.Now()); err == nil {
		t.Fatal("expected device authentication failure on SessionTranscript mismatch")
	}
}
