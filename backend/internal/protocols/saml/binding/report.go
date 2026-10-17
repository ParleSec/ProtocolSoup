package binding

import "github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"

// Check is one check a receiving entity actually ran, reported as-is to
// Looking Glass.
type Check struct {
	Name      string `json:"name"`
	Passed    bool   `json:"passed"`
	Detail    string `json:"detail"`
	Reference string `json:"reference"`
}

// Report lists every check an entity ran on a received message.
type Report struct {
	Signed    bool          `json:"signed"`
	Signature *xmldsig.Info `json:"signature,omitempty"`
	Checks    []Check       `json:"checks"`
}

// Add records a check.
func (r *Report) Add(name string, passed bool, detail, reference string) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: passed, Detail: detail, Reference: reference})
}

// Merge appends other's checks and signature details.
func (r *Report) Merge(other *Report) {
	if other == nil {
		return
	}
	r.Signed = r.Signed || other.Signed
	if r.Signature == nil {
		r.Signature = other.Signature
	}
	r.Checks = append(r.Checks, other.Checks...)
}
