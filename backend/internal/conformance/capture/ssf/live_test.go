package ssf

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture/capturetest"
)

// TestLive captures this package's scenarios against the local server on
// CAPTURE_PORT; it skips when CAPTURE_PORT is unset. The server must run with
// SSF_AS_JWKS_URI set, as production does.
func TestLive(t *testing.T) {
	capturetest.RunLive(t)
}
