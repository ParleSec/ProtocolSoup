package cose

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestCanonicalEncodingIsLengthFirst pins the ISO/IEC 18013-5 Section 8.1
// encoding to RFC 7049 Section 3.9 length-first map-key ordering. The same map
// under RFC 8949 Section 4.2.1 (bytewise-lexical) sorts differently, so this
// test would fail if the wrong encoder were wired in. Getting this wrong breaks
// MSO digest interop, so it is asserted byte-for-byte up front.
func TestCanonicalEncodingIsLengthFirst(t *testing.T) {
	// Keys: 10 -> 0x0a (1 byte), -1 -> 0x20 (1 byte), 100 -> 0x1864 (2 bytes).
	// Length-first: 1-byte keys first (0x0a then 0x20), then the 2-byte key.
	m := map[int]int{10: 0, -1: 2, 100: 1}

	got, err := MarshalDeterministic(m)
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}

	// A3                 map(3)
	//   0A 00            10: 0
	//   20 02            -1: 2
	//   18 64 01         100: 1
	want := mustDecodeHex(t, "a30a002002186401")
	if !bytes.Equal(got, want) {
		t.Fatalf("length-first canonical encoding mismatch:\n got %x\nwant %x", got, want)
	}
}

// TestCOSELayerEncodingIsBytewiseLexical confirms the COSE-layer encoder uses
// RFC 8949 Section 4.2.1 bytewise-lexical ordering, which differs from the mdoc
// data-model encoder above. This locks in the deliberate two-encoder split.
func TestCOSELayerEncodingIsBytewiseLexical(t *testing.T) {
	m := map[int]int{10: 0, -1: 2, 100: 1}

	got, err := coseEncMode.Marshal(m)
	if err != nil {
		t.Fatalf("coseEncMode.Marshal: %v", err)
	}

	// A3                 map(3)
	//   0A 00            10: 0
	//   18 64 01         100: 1   (bytewise: 0x1864 sorts before 0x20)
	//   20 02            -1: 2
	want := mustDecodeHex(t, "a30a001864012002")
	if !bytes.Equal(got, want) {
		t.Fatalf("bytewise-lexical COSE encoding mismatch:\n got %x\nwant %x", got, want)
	}

	// The two encoders MUST produce different bytes for this map, otherwise the
	// distinction the comment claims would be vacuous.
	canonical, err := MarshalDeterministic(m)
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}
	if bytes.Equal(canonical, got) {
		t.Fatal("expected length-first and bytewise-lexical encodings to differ")
	}
}

// TestMarshalDeterministicByteStable verifies encode -> decode -> re-encode is
// byte-identical, the property MSO digests rely on.
func TestMarshalDeterministicByteStable(t *testing.T) {
	original := map[int]any{
		1:  int64(2),
		-1: int64(1),
		-2: []byte{0x01, 0x02, 0x03},
		-3: []byte{0xaa, 0xbb},
	}

	first, err := MarshalDeterministic(original)
	if err != nil {
		t.Fatalf("first encode: %v", err)
	}

	var decoded map[int]any
	if err := Unmarshal(first, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}

	second, err := MarshalDeterministic(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatalf("encoding not byte-stable:\nfirst  %x\nsecond %x", first, second)
	}
}

// TestTag24RoundTrip verifies tag 24 wraps inner CBOR verbatim and unwraps to
// the exact bytes, which is what lets mdoc hash wrapped structures as received.
func TestTag24RoundTrip(t *testing.T) {
	value := map[int]any{1: int64(42), -2: []byte("device")}

	inner, err := MarshalDeterministic(value)
	if err != nil {
		t.Fatalf("encode inner: %v", err)
	}

	wrapped, err := EncodeTagged24(value)
	if err != nil {
		t.Fatalf("EncodeTagged24: %v", err)
	}

	// Wrapped form must begin with CBOR tag 24 (0xd8 0x18) followed by a byte
	// string holding the inner encoding.
	if len(wrapped) < 2 || wrapped[0] != 0xd8 || wrapped[1] != 0x18 {
		t.Fatalf("tag 24 prefix missing, got % x", wrapped[:min(2, len(wrapped))])
	}

	unwrapped, err := DecodeTagged24(wrapped)
	if err != nil {
		t.Fatalf("DecodeTagged24: %v", err)
	}
	if !bytes.Equal(unwrapped, inner) {
		t.Fatalf("tag 24 inner bytes not preserved:\n got %x\nwant %x", unwrapped, inner)
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
