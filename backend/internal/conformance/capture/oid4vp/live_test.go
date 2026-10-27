package oid4vp

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture/capturetest"
)

// TestLive captures this package's scenarios against CAPTURE_BASE; it skips
// when CAPTURE_BASE is unset.
func TestLive(t *testing.T) {
	capturetest.RunLive(t)
}
