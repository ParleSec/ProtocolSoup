package haipwallet

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture/capturetest"
)

// TestLive captures this package's scenarios against the local server on
// CAPTURE_PORT, the local wallet on CAPTURE_WALLET_PORT and the counterparty;
// it skips when CAPTURE_PORT is unset.
func TestLive(t *testing.T) {
	capturetest.RunLive(t)
}
