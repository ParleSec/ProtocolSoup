package oid4vci

import "testing"

func TestDifferentDigits(t *testing.T) {
	for _, code := range []string{"123456", "999999", "000000"} {
		if got := differentDigits(code); got == code || len(got) != len(code) {
			t.Fatalf("differentDigits(%q) = %q", code, got)
		}
	}
}
