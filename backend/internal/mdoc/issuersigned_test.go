package mdoc

import (
	"fmt"
	"testing"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/fxamacker/cbor/v2"
)

// nestedArrayValue builds a value nested `depth` levels deep in single-
// element CBOR arrays, bottoming out in a scalar leaf. measureUntrustedCBORDepth
// counts each array as one level and the leaf as zero, so this produces an
// exact, predictable depth for testing CheckUntrustedCBOR's limit.
func nestedArrayValue(depth int) any {
	if depth <= 0 {
		return "leaf"
	}
	return []any{nestedArrayValue(depth - 1)}
}

func TestCheckUntrustedCBORAcceptsNestingWithinLimit(t *testing.T) {
	// 8 mirrors the measured depth of a real issued mDL's deepest path (the
	// driving_privileges element) -- see the MaxNestedLevels derivation this
	// gate backs. A credential at that real-world depth must never be
	// rejected by the hardened path.
	const depth = 8
	data, err := intcose.MarshalDeterministic(nestedArrayValue(depth))
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}

	got, err := CheckUntrustedCBOR(data)
	if err != nil {
		t.Fatalf("CheckUntrustedCBOR rejected depth %d input, within the MaxNestedLevels=%d ceiling: %v", depth, maxUntrustedNestedLevels, err)
	}
	if got != depth {
		t.Fatalf("CheckUntrustedCBOR depth = %d, want %d", got, depth)
	}
	if margin := maxUntrustedNestedLevels - got; margin <= 0 {
		t.Fatalf("measured depth %d leaves no margin to MaxNestedLevels=%d", got, maxUntrustedNestedLevels)
	}
}

func TestCheckUntrustedCBORRejectsDeepNesting(t *testing.T) {
	data, err := intcose.MarshalDeterministic(nestedArrayValue(maxUntrustedNestedLevels + 4))
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}

	if _, err := CheckUntrustedCBOR(data); err == nil {
		t.Fatalf("CheckUntrustedCBOR accepted nesting %d levels deep, exceeding MaxNestedLevels=%d", maxUntrustedNestedLevels+4, maxUntrustedNestedLevels)
	}
}

// TestCheckUntrustedCBORRejectsNestingBombInsideTag24 is the specific bypass
// this gate exists to close. mdoc wraps IssuerSignedItemBytes and
// MobileSecurityObjectBytes in CBOR tag 24, so a generic outer decode sees
// each as an opaque byte string and never looks inside it. Here the outer
// shell (10 array levels plus the tag itself, 11 total) and the tag-24
// content (10 more array levels) are each, in isolation, comfortably under
// MaxNestedLevels -- an outer-only check, or a recursive check that resets
// the budget at the tag boundary instead of carrying it forward, would let
// this through. Only cumulative accounting across the tag-24 boundary
// (outer 11 + inner 10 = 21) catches it.
func TestCheckUntrustedCBORRejectsNestingBombInsideTag24(t *testing.T) {
	const outerDepth = 10
	const innerDepth = 10

	innerBytes, err := intcose.MarshalDeterministic(nestedArrayValue(innerDepth))
	if err != nil {
		t.Fatalf("MarshalDeterministic(inner): %v", err)
	}

	var value any = cbor.Tag{Number: intcose.TagEncodedCBOR, Content: innerBytes}
	for i := 0; i < outerDepth; i++ {
		value = []any{value}
	}

	// Sanity-check the test's own premise: the outer shell alone (treating
	// the tag's content as an opaque leaf, i.e. what an outer-only decode
	// would see) must stay under the limit, or this test would not be
	// distinguishing cumulative accounting from a trivial single-shell
	// rejection.
	if outerShellDepth := outerDepth + 1; outerShellDepth >= maxUntrustedNestedLevels {
		t.Fatalf("test setup invalid: outer shell alone (%d) must stay under MaxNestedLevels=%d for this test to prove anything", outerShellDepth, maxUntrustedNestedLevels)
	}
	if innerDepth >= maxUntrustedNestedLevels {
		t.Fatalf("test setup invalid: inner content alone (%d) must stay under MaxNestedLevels=%d for this test to prove anything", innerDepth, maxUntrustedNestedLevels)
	}

	data, err := intcose.MarshalDeterministic(value)
	if err != nil {
		t.Fatalf("MarshalDeterministic(outer): %v", err)
	}

	if _, err := CheckUntrustedCBOR(data); err == nil {
		t.Fatalf("CheckUntrustedCBOR accepted a nesting bomb hidden inside a tag-24 wrapper (outer %d + inner %d = %d, exceeding MaxNestedLevels=%d) -- the tag-24 recursion this gate exists to perform did not catch it", outerDepth, 1, innerDepth, maxUntrustedNestedLevels)
	}
}

func TestCheckUntrustedCBORRejectsOversizedArray(t *testing.T) {
	const oversized = 1025 // one past the 1024 MaxArrayElements ceiling
	elements := make([]any, oversized)
	for i := range elements {
		elements[i] = i
	}
	data, err := intcose.MarshalDeterministic(elements)
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}

	if _, err := CheckUntrustedCBOR(data); err == nil {
		t.Fatalf("CheckUntrustedCBOR accepted a %d-element array, exceeding MaxArrayElements=1024", oversized)
	}
}

func TestCheckUntrustedCBORRejectsOversizedMap(t *testing.T) {
	const oversized = 1025 // one past the 1024 MaxMapPairs ceiling
	m := make(map[string]any, oversized)
	for i := 0; i < oversized; i++ {
		m[fmt.Sprintf("k%d", i)] = i
	}
	data, err := intcose.MarshalDeterministic(m)
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}

	if _, err := CheckUntrustedCBOR(data); err == nil {
		t.Fatalf("CheckUntrustedCBOR accepted a %d-pair map, exceeding MaxMapPairs=1024", oversized)
	}
}

// TestCheckUntrustedCBORRejectsAtSizeCapNotTruncation is a narrow check that
// the gate itself makes no attempt to truncate or partially accept
// oversized input -- it must fail outright, with depth/decoding abandoned,
// rather than silently processing a truncated prefix. The HTTP-level byte
// cap (http.MaxBytesReader) is a separate, transport-level control; this
// only pins the decode gate's own behaviour on oversized collections.
func TestCheckUntrustedCBORRejectsAtSizeCapNotTruncation(t *testing.T) {
	const oversized = 2048
	elements := make([]any, oversized)
	for i := range elements {
		elements[i] = "x"
	}
	data, err := intcose.MarshalDeterministic(elements)
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}

	depth, err := CheckUntrustedCBOR(data)
	if err == nil {
		t.Fatalf("CheckUntrustedCBOR accepted a %d-element array outright instead of rejecting it", oversized)
	}
	// A truncating implementation would report a plausible depth (e.g. 1,
	// for "array of scalars") rather than failing before depth is
	// established at all. checkUntrustedCBORDepth returns outerDepth (0 at
	// the top level) on a decode error, which is the "abandoned, not
	// truncated" signal this test pins.
	if depth != 0 {
		t.Fatalf("CheckUntrustedCBOR returned depth %d alongside a decode error; want 0 (decode abandoned, not partially measured)", depth)
	}
}
