// Package scenarios gathers every capture scenario package, so the runner
// and the completeness test see the whole catalogue.
package scenarios

import (
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/haipwallet"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/iso18013"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vci"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vcihaip"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vciwallet"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vp"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vpwallet"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/rfc9449"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/rfc9901"
)
