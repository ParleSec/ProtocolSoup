package capture

// pending lists the requirements whose scenarios are not written yet. It
// shrinks as each stage lands and is deleted, together with Entry.Pending,
// once every registry row has a scenario or an unavailable reason.
var pending = []string{
	"VP-001", "VP-002", "VP-003", "VP-004", "VP-006", "VP-007",
	"HAIP-VP-001", "HAIP-VP-002", "VP-011", "VP-012", "CI-005", "CI-009",
	"CI-006", "CI-007", "CI-008", "CI-010", "CI-011", "CI-012",
	"CI-013", "CI-015", "CI-016", "CI-017", "CI-018", "CI-019",
	"CI-020", "CI-021", "CI-022", "CI-023", "DP-002", "DP-003",
	"DP-004", "DP-005", "DP-006", "DP-007", "DP-008", "DP-009",
	"DP-010", "DP-011", "DP-012", "MDOC-001", "MDOC-002", "MDOC-003",
	"MDOC-004", "MDOC-005", "MDOC-006", "SDJWT-001", "SDJWT-000", "SDJWT-002",
	"SDJWT-003", "SDJWT-004", "SDJWT-005", "CW-001", "CW-006", "CW-010",
	"CW-020", "CW-024", "CW-044", "CW-065", "CW-070", "CW-072",
	"CW-081", "CW-100", "CW-H003", "CW-H004", "CW-H010", "CW-H013",
	"CW-H014", "CW-H017", "CW-089",
}

func init() {
	for _, id := range pending {
		register(id, Entry{Pending: true})
	}
}
