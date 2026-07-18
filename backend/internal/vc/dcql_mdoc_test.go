package vc

import "testing"

// TestParseDCQLTrustedAuthorities confirms the DCQL Trusted Authorities Query
// (OID4VP 1.0 Section 6.1.1) is parsed per credential, including the HAIP "aki"
// type, while a credential with no trusted_authorities yields none.
func TestParseDCQLTrustedAuthorities(t *testing.T) {
	dcql := `{
		"credentials": [
			{
				"id": "mdl",
				"format": "mso_mdoc",
				"meta": {"doctype_values": ["org.iso.18013.5.1.mDL"]},
				"trusted_authorities": [
					{"type": "aki", "values": ["sBdpcyfYjLDg7e6_KdjQQX2v8jY", "anotherAki"]}
				]
			},
			{
				"id": "pid",
				"format": "dc+sd-jwt",
				"meta": {"vct_values": ["urn:eudi:pid:1"]}
			}
		]
	}`
	requirements := ParseDCQLCredentialRequirements(dcql)
	if len(requirements) != 2 {
		t.Fatalf("expected 2 requirements, got %d", len(requirements))
	}
	mdl := requirements[0]
	if len(mdl.TrustedAuthorities) != 1 {
		t.Fatalf("expected 1 trusted authority on the mdl credential, got %d", len(mdl.TrustedAuthorities))
	}
	authority := mdl.TrustedAuthorities[0]
	if authority.Type != "aki" {
		t.Fatalf("expected aki trusted-authority type, got %q", authority.Type)
	}
	if len(authority.Values) != 2 || authority.Values[0] != "sBdpcyfYjLDg7e6_KdjQQX2v8jY" || authority.Values[1] != "anotherAki" {
		t.Fatalf("trusted-authority values not preserved: %v", authority.Values)
	}
	if len(requirements[1].TrustedAuthorities) != 0 {
		t.Fatalf("expected no trusted authorities on the pid credential, got %d", len(requirements[1].TrustedAuthorities))
	}
}

func mdocEvidence() MdocCredentialEvidence {
	return MdocCredentialEvidence{
		Format:                       "mso_mdoc",
		Doctype:                      "org.iso.18013.5.1.mDL",
		IssuerAuthorityKeyIdentifier: "trusted-aki",
		NameSpaces: map[string]map[string]struct{}{
			"org.iso.18013.5.1": {
				"family_name":     {},
				"document_number": {},
			},
		},
	}
}

func TestRequirementMatchesMdocEnforcesAKITrustedAuthority(t *testing.T) {
	dcql := `{"credentials": [{"id": "mdl", "format": "mso_mdoc", "trusted_authorities": [{"type": "aki", "values": ["trusted-aki"]}]}]}`
	req := ParseDCQLCredentialRequirements(dcql)[0]
	if matched, code, message := RequirementMatchesMdoc(req, mdocEvidence()); !matched {
		t.Fatalf("expected AKI match, got code=%q message=%q", code, message)
	}

	evidence := mdocEvidence()
	evidence.IssuerAuthorityKeyIdentifier = "different-aki"
	if matched, code, _ := RequirementMatchesMdoc(req, evidence); matched || code != "dcql_trusted_authority_mismatch" {
		t.Fatalf("expected trusted-authority mismatch, got matched=%t code=%q", matched, code)
	}
}

func TestRequirementMatchesMdocByDoctypeAndNamespaceElementPaths(t *testing.T) {
	dcql := `{
		"credentials": [{
			"id": "mdl",
			"format": "mso_mdoc",
			"meta": {"doctype_values": ["org.iso.18013.5.1.mDL"]},
			"claims": [
				{"path": ["org.iso.18013.5.1", "family_name"]},
				{"path": ["org.iso.18013.5.1", "document_number"]}
			]
		}]
	}`
	reqs := ParseDCQLCredentialRequirements(dcql)
	if len(reqs) != 1 {
		t.Fatalf("expected 1 requirement, got %d", len(reqs))
	}
	req := reqs[0]
	if len(req.RequiredClaimPathSegments) != 2 {
		t.Fatalf("expected 2 path segment lists, got %d", len(req.RequiredClaimPathSegments))
	}
	// The namespace contains dots, so the raw segments must be preserved (the
	// dot-joined RequiredClaimPaths form is unusable for mdoc).
	if got := req.RequiredClaimPathSegments[0]; len(got) != 2 || got[0] != "org.iso.18013.5.1" || got[1] != "family_name" {
		t.Fatalf("unexpected first segment list: %v", got)
	}

	matched, code, msg := RequirementMatchesMdoc(req, mdocEvidence())
	if !matched {
		t.Fatalf("expected mdoc match, got code=%q msg=%q", code, msg)
	}
}

func TestRequirementMatchesMdocRejectsDoctypeMismatch(t *testing.T) {
	dcql := `{"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_values": ["org.iso.18013.5.1.mDL"]}, "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]}`
	req := ParseDCQLCredentialRequirements(dcql)[0]

	ev := mdocEvidence()
	ev.Doctype = "org.iso.18013.5.1.reservation"
	matched, code, _ := RequirementMatchesMdoc(req, ev)
	if matched {
		t.Fatal("expected doctype mismatch")
	}
	if code != "dcql_meta_mismatch" {
		t.Fatalf("expected dcql_meta_mismatch, got %q", code)
	}
}

func TestRequirementMatchesMdocRejectsMissingElement(t *testing.T) {
	dcql := `{"credentials": [{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_values": ["org.iso.18013.5.1.mDL"]}, "claims": [{"path": ["org.iso.18013.5.1", "birth_date"]}]}]}`
	req := ParseDCQLCredentialRequirements(dcql)[0]

	matched, code, _ := RequirementMatchesMdoc(req, mdocEvidence())
	if matched {
		t.Fatal("expected missing-element mismatch")
	}
	if code != "missing_required_claim" {
		t.Fatalf("expected missing_required_claim, got %q", code)
	}
}

func TestRequirementMatchesMdocRejectsFormatMismatch(t *testing.T) {
	dcql := `{"credentials": [{"id": "mdl", "format": "dc+sd-jwt", "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]}`
	req := ParseDCQLCredentialRequirements(dcql)[0]

	matched, code, _ := RequirementMatchesMdoc(req, mdocEvidence())
	if matched {
		t.Fatal("expected format mismatch")
	}
	if code != "dcql_format_mismatch" {
		t.Fatalf("expected dcql_format_mismatch, got %q", code)
	}
}

// TestSDJWTDCQLMatchingUnchanged guards that the existing SD-JWT VC matching path
// (dot-joined JSON-pointer claim paths against nested FullClaims) is intact after
// the mdoc additions.
func TestSDJWTDCQLMatchingUnchanged(t *testing.T) {
	dcql := `{
		"credentials": [{
			"id": "degree",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["https://protocolsoup.com/credentials/university_degree"]},
			"claims": [
				{"path": ["degree", "type"]},
				{"path": ["graduation_year"]}
			]
		}]
	}`
	req := ParseDCQLCredentialRequirements(dcql)[0]

	evidence := CredentialEvidence{
		Format: "dc+sd-jwt",
		VCT:    "https://protocolsoup.com/credentials/university_degree",
		FullClaims: map[string]interface{}{
			"degree":          map[string]interface{}{"type": "BachelorDegree"},
			"graduation_year": "2024",
		},
	}
	matched, code, msg := RequirementMatchesEvidence(req, evidence)
	if !matched {
		t.Fatalf("expected SD-JWT match, got code=%q msg=%q", code, msg)
	}

	// A missing nested claim must still fail via the dot-joined path matcher.
	evidence.FullClaims = map[string]interface{}{"graduation_year": "2024"}
	if matched, _, _ := RequirementMatchesEvidence(req, evidence); matched {
		t.Fatal("expected SD-JWT mismatch for missing nested degree.type claim")
	}
}
