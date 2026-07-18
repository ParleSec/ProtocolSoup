package mdoc

import (
	"bytes"
	"testing"
)

func TestIssuerSignedItemRoundTrip(t *testing.T) {
	item := IssuerSignedItem{
		DigestID:          7,
		Random:            bytes.Repeat([]byte{0x42}, 16),
		ElementIdentifier: "document_number",
		ElementValue:      "DL12345678",
	}

	encoded, err := EncodeIssuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("EncodeIssuerSignedItemBytes: %v", err)
	}

	decoded, err := DecodeIssuerSignedItemBytes(encoded)
	if err != nil {
		t.Fatalf("DecodeIssuerSignedItemBytes: %v", err)
	}

	if decoded.DigestID != item.DigestID {
		t.Errorf("DigestID = %d, want %d", decoded.DigestID, item.DigestID)
	}
	if !bytes.Equal(decoded.Random, item.Random) {
		t.Errorf("Random mismatch")
	}
	if decoded.ElementIdentifier != item.ElementIdentifier {
		t.Errorf("ElementIdentifier = %q, want %q", decoded.ElementIdentifier, item.ElementIdentifier)
	}
	if decoded.ElementValue != item.ElementValue {
		t.Errorf("ElementValue = %v, want %v", decoded.ElementValue, item.ElementValue)
	}
}

func TestIssuerSignedItemRejectsShortRandom(t *testing.T) {
	item := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte{0x01, 0x02}, // too short
		ElementIdentifier: "test",
		ElementValue:      "value",
	}
	if _, err := EncodeIssuerSignedItemBytes(item); err == nil {
		t.Fatal("expected error for short random, got nil")
	}
}

func TestBuildIssuerNameSpacesRejectsDuplicateDigestID(t *testing.T) {
	item1, _ := NewIssuerSignedItem(0, "family_name", "Smith")
	item2, _ := NewIssuerSignedItem(0, "given_name", "John") // same digestID

	_, err := BuildIssuerNameSpaces(map[NameSpace][]IssuerSignedItem{
		NameSpaceMDL: {item1, item2},
	})
	if err == nil {
		t.Fatal("expected error for duplicate digestID, got nil")
	}
}
