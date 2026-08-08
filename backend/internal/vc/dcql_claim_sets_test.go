package vc

import "testing"

// TestParseDCQLClaimSets confirms claim_sets (OID4VP 1.0 Section 6.1) parses
// into DCQLCredentialRequirement.ClaimSets as an ordered list of id-lists, and
// that a query with no claim_sets leaves it empty.
func TestParseDCQLClaimSets(t *testing.T) {
	dcql := `{
		"credentials": [{
			"id": "pid",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["urn:eudi:pid:1"]},
			"claims": [
				{"id": "gn", "path": ["given_name"]},
				{"id": "fn", "path": ["family_name"]},
				{"id": "dob", "path": ["birth_date"]},
				{"id": "over18", "path": ["age_over_18"]}
			],
			"claim_sets": [
				["gn", "fn", "over18"],
				["gn", "fn", "dob"]
			]
		}]
	}`
	req := ParseDCQLCredentialRequirements(dcql)[0]
	if len(req.ClaimSets) != 2 {
		t.Fatalf("expected 2 claim_sets alternatives, got %d: %v", len(req.ClaimSets), req.ClaimSets)
	}
	if got := req.ClaimSets[0]; len(got) != 3 || got[0] != "gn" || got[1] != "fn" || got[2] != "over18" {
		t.Fatalf("unexpected first claim_sets alternative: %v", got)
	}
	if got := req.ClaimSets[1]; len(got) != 3 || got[2] != "dob" {
		t.Fatalf("unexpected second claim_sets alternative: %v", got)
	}
}

// TestParseDCQLNoClaimSetsLeavesFieldEmpty guards the zero-value backward
// compatibility bar: a query with no claim_sets key must not populate it.
func TestParseDCQLNoClaimSetsLeavesFieldEmpty(t *testing.T) {
	dcql := `{"credentials": [{"id": "degree", "format": "dc+sd-jwt", "claims": [{"path": ["degree"]}]}]}`
	req := ParseDCQLCredentialRequirements(dcql)[0]
	if len(req.ClaimSets) != 0 {
		t.Fatalf("expected no claim_sets, got %v", req.ClaimSets)
	}
}

func pidClaimSetDCQL() string {
	return `{
		"credentials": [{
			"id": "pid",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["urn:eudi:pid:1"]},
			"claims": [
				{"id": "gn", "path": ["given_name"]},
				{"id": "fn", "path": ["family_name"]},
				{"id": "dob", "path": ["birth_date"]},
				{"id": "over18", "path": ["age_over_18"]}
			],
			"claim_sets": [
				["gn", "fn", "over18"],
				["gn", "fn", "dob"]
			]
		}]
	}`
}

// TestRequirementMatchesEvidenceClaimSetFirstAlternativeSatisfied proves a
// credential disclosing exactly the first claim_sets alternative (and not the
// second) is accepted.
func TestRequirementMatchesEvidenceClaimSetFirstAlternativeSatisfied(t *testing.T) {
	req := ParseDCQLCredentialRequirements(pidClaimSetDCQL())[0]
	evidence := CredentialEvidence{
		Format: "dc+sd-jwt",
		VCT:    "urn:eudi:pid:1",
		FullClaims: map[string]interface{}{
			"given_name":  "Alice",
			"family_name": "Doe",
			"age_over_18": true,
			// birth_date deliberately absent: only the first alternative is disclosed.
		},
	}
	matched, code, msg := RequirementMatchesEvidence(req, evidence)
	if !matched {
		t.Fatalf("expected claim_sets first-alternative match, got code=%q msg=%q", code, msg)
	}
}

// TestRequirementMatchesEvidenceClaimSetSecondAlternativeSatisfied proves the
// second alternative alone (without the first) is also sufficient.
func TestRequirementMatchesEvidenceClaimSetSecondAlternativeSatisfied(t *testing.T) {
	req := ParseDCQLCredentialRequirements(pidClaimSetDCQL())[0]
	evidence := CredentialEvidence{
		Format: "dc+sd-jwt",
		VCT:    "urn:eudi:pid:1",
		FullClaims: map[string]interface{}{
			"given_name":  "Alice",
			"family_name": "Doe",
			"birth_date":  "2000-01-01",
			// age_over_18 deliberately absent: only the second alternative is disclosed.
		},
	}
	matched, code, msg := RequirementMatchesEvidence(req, evidence)
	if !matched {
		t.Fatalf("expected claim_sets second-alternative match, got code=%q msg=%q", code, msg)
	}
}

// TestRequirementMatchesEvidenceClaimSetNoAlternativeSatisfied proves that
// disclosing neither alternative in full fails with the new reason code.
func TestRequirementMatchesEvidenceClaimSetNoAlternativeSatisfied(t *testing.T) {
	req := ParseDCQLCredentialRequirements(pidClaimSetDCQL())[0]
	evidence := CredentialEvidence{
		Format: "dc+sd-jwt",
		VCT:    "urn:eudi:pid:1",
		FullClaims: map[string]interface{}{
			"given_name": "Alice",
			// family_name missing, so neither alternative (which both require
			// gn+fn) is fully disclosed.
		},
	}
	matched, code, _ := RequirementMatchesEvidence(req, evidence)
	if matched {
		t.Fatal("expected claim_sets denial when no alternative is fully disclosed")
	}
	if code != "missing_required_claim_set" {
		t.Fatalf("expected missing_required_claim_set, got %q", code)
	}
}

// TestRequirementMatchesEvidenceClaimSetUnclaimedClaimAlwaysRequired proves a
// claim with no id (so it cannot appear in any claim_sets alternative) stays
// unconditionally required even when claim_sets is present.
func TestRequirementMatchesEvidenceClaimSetUnclaimedClaimAlwaysRequired(t *testing.T) {
	dcql := `{
		"credentials": [{
			"id": "pid",
			"format": "dc+sd-jwt",
			"claims": [
				{"id": "gn", "path": ["given_name"]},
				{"id": "over18", "path": ["age_over_18"]},
				{"path": ["nationality"]}
			],
			"claim_sets": [
				["gn", "over18"]
			]
		}]
	}`
	req := ParseDCQLCredentialRequirements(dcql)[0]

	// The claim_sets alternative is satisfied, but the unclaimed "nationality"
	// claim is missing.
	evidence := CredentialEvidence{
		Format: "dc+sd-jwt",
		FullClaims: map[string]interface{}{
			"given_name":  "Alice",
			"age_over_18": true,
		},
	}
	matched, code, _ := RequirementMatchesEvidence(req, evidence)
	if matched {
		t.Fatal("expected denial when the unclaimed required claim is missing")
	}
	if code != "missing_required_claim" {
		t.Fatalf("expected missing_required_claim for the unclaimed claim, got %q", code)
	}

	evidence.FullClaims["nationality"] = "DE"
	matched, code, msg := RequirementMatchesEvidence(req, evidence)
	if !matched {
		t.Fatalf("expected match once both claim_sets and unclaimed claim are satisfied, got code=%q msg=%q", code, msg)
	}
}

// TestSDJWTDCQLMatchingUnchangedWithoutClaimSets is a regression guard for the
// non-goal: existing (no claim_sets) queries must match exactly as before.
func TestSDJWTDCQLMatchingUnchangedWithoutClaimSets(t *testing.T) {
	req := ParseDCQLCredentialRequirements(`{
		"credentials": [{
			"id": "degree",
			"format": "dc+sd-jwt",
			"claims": [{"path": ["degree"]}, {"path": ["graduation_year"]}]
		}]
	}`)[0]
	if len(req.ClaimSets) != 0 {
		t.Fatalf("expected no claim_sets, got %v", req.ClaimSets)
	}
	evidence := CredentialEvidence{
		Format: "dc+sd-jwt",
		FullClaims: map[string]interface{}{
			"degree": "BSc",
		},
	}
	matched, code, _ := RequirementMatchesEvidence(req, evidence)
	if matched {
		t.Fatal("expected denial for missing graduation_year, exactly as before claim_sets support")
	}
	if code != "missing_required_claim" {
		t.Fatalf("expected missing_required_claim, got %q", code)
	}
}

func mdocPIDClaimSetDCQL() string {
	return `{
		"credentials": [{
			"id": "mdl",
			"format": "mso_mdoc",
			"meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
			"claims": [
				{"id": "fname", "path": ["org.iso.18013.5.1", "family_name"]},
				{"id": "docnum", "path": ["org.iso.18013.5.1", "document_number"]},
				{"id": "portrait", "path": ["org.iso.18013.5.1", "portrait"]}
			],
			"claim_sets": [
				["fname", "docnum"],
				["fname", "portrait"]
			]
		}]
	}`
}

// TestRequirementMatchesMdocClaimSetFirstAlternativeSatisfied mirrors the
// SD-JWT VC claim_sets coverage above for the mdoc
// (RequiredClaimPathSegments/claimsByID) path.
func TestRequirementMatchesMdocClaimSetFirstAlternativeSatisfied(t *testing.T) {
	req := ParseDCQLCredentialRequirements(mdocPIDClaimSetDCQL())[0]
	evidence := MdocCredentialEvidence{
		Format:  "mso_mdoc",
		Doctype: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]struct{}{
			"org.iso.18013.5.1": {
				"family_name":     {},
				"document_number": {},
			},
		},
	}
	matched, code, msg := RequirementMatchesMdoc(req, evidence)
	if !matched {
		t.Fatalf("expected mdoc claim_sets first-alternative match, got code=%q msg=%q", code, msg)
	}
}

// TestRequirementMatchesMdocClaimSetSecondAlternativeSatisfied proves the
// second alternative alone also satisfies the mdoc requirement.
func TestRequirementMatchesMdocClaimSetSecondAlternativeSatisfied(t *testing.T) {
	req := ParseDCQLCredentialRequirements(mdocPIDClaimSetDCQL())[0]
	evidence := MdocCredentialEvidence{
		Format:  "mso_mdoc",
		Doctype: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]struct{}{
			"org.iso.18013.5.1": {
				"family_name": {},
				"portrait":    {},
			},
		},
	}
	matched, code, msg := RequirementMatchesMdoc(req, evidence)
	if !matched {
		t.Fatalf("expected mdoc claim_sets second-alternative match, got code=%q msg=%q", code, msg)
	}
}

// TestRequirementMatchesMdocClaimSetNoAlternativeSatisfied proves the mdoc
// path fails with the new reason code when no alternative is fully disclosed.
func TestRequirementMatchesMdocClaimSetNoAlternativeSatisfied(t *testing.T) {
	req := ParseDCQLCredentialRequirements(mdocPIDClaimSetDCQL())[0]
	evidence := MdocCredentialEvidence{
		Format:  "mso_mdoc",
		Doctype: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]struct{}{
			"org.iso.18013.5.1": {
				"family_name": {},
			},
		},
	}
	matched, code, _ := RequirementMatchesMdoc(req, evidence)
	if matched {
		t.Fatal("expected mdoc denial when no claim_sets alternative is fully disclosed")
	}
	if code != "missing_required_claim_set" {
		t.Fatalf("expected missing_required_claim_set, got %q", code)
	}
}

// TestRequirementMatchesMdocUnchangedWithoutClaimSets is a regression guard
// for the mdoc non-goal: existing (no claim_sets) mdoc queries must match
// exactly as before.
func TestRequirementMatchesMdocUnchangedWithoutClaimSets(t *testing.T) {
	req := ParseDCQLCredentialRequirements(`{
		"credentials": [{
			"id": "mdl",
			"format": "mso_mdoc",
			"meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
			"claims": [{"path": ["org.iso.18013.5.1", "family_name"]}, {"path": ["org.iso.18013.5.1", "document_number"]}]
		}]
	}`)[0]
	if len(req.ClaimSets) != 0 {
		t.Fatalf("expected no claim_sets, got %v", req.ClaimSets)
	}
	evidence := MdocCredentialEvidence{
		Format:  "mso_mdoc",
		Doctype: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]struct{}{
			"org.iso.18013.5.1": {"family_name": {}},
		},
	}
	matched, code, _ := RequirementMatchesMdoc(req, evidence)
	if matched {
		t.Fatal("expected denial for missing document_number, exactly as before claim_sets support")
	}
	if code != "missing_required_claim" {
		t.Fatalf("expected missing_required_claim, got %q", code)
	}
}
