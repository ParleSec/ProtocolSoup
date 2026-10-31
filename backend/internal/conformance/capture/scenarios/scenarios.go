// Package scenarios gathers every capture scenario package, so the runner
// and the completeness test see the whole catalogue.
package scenarios

import (
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/iso18013"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vci"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vcihaip"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/oid4vp"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/rfc9449"
	_ "github.com/ParleSec/ProtocolSoup/internal/conformance/capture/rfc9901"
)

// pending lists the requirements whose scenarios are not written yet. It
// shrinks as each stage lands and is deleted once every registry row has a
// scenario or an unavailable reason. One ID per line, so separate changes
// can remove their own rows.
var pending = []string{
	"VP-001",
	"VP-002",
	"VP-003",
	"VP-004",
	"VP-011",
	"VP-012",
	"CI-005",
	"CI-010",
	"CI-011",
	"CI-013",
	"CW-001",
	"CW-006",
	"CW-010",
	"CW-020",
	"CW-024",
	"CW-044",
	"CW-065",
	"CW-070",
	"CW-072",
	"CW-081",
	"CW-100",
	"CW-H003",
	"CW-H004",
	"CW-H010",
	"CW-H013",
	"CW-H014",
	"CW-H017",
	"CW-089",
}
