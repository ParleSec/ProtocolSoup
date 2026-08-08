package vc

import "testing"

// TestParseDCQLQueryCredentialSets confirms the top-level credential_sets
// array (OID4VP 1.0 Section 6.2) parses into DCQLQuery.CredentialSets with
// Required defaulting to true when omitted, and honored when explicit.
func TestParseDCQLQueryCredentialSets(t *testing.T) {
	dcql := `{
		"credentials": [
			{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}},
			{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}},
			{"id": "photo_id", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.23220.photoid.1"}}
		],
		"credential_sets": [
			{"options": [["pid"], ["mdl"]]},
			{"options": [["photo_id"]], "required": false}
		]
	}`
	query := ParseDCQLQuery(dcql)
	if len(query.Credentials) != 3 {
		t.Fatalf("expected 3 credential requirements, got %d", len(query.Credentials))
	}
	if len(query.CredentialSets) != 2 {
		t.Fatalf("expected 2 credential_sets entries, got %d", len(query.CredentialSets))
	}
	first := query.CredentialSets[0]
	if !first.Required {
		t.Fatal("expected required to default to true when omitted")
	}
	if len(first.Options) != 2 || first.Options[0][0] != "pid" || first.Options[1][0] != "mdl" {
		t.Fatalf("unexpected first credential_sets options: %v", first.Options)
	}
	second := query.CredentialSets[1]
	if second.Required {
		t.Fatal("expected explicit required:false to be honored")
	}
	if len(second.Options) != 1 || second.Options[0][0] != "photo_id" {
		t.Fatalf("unexpected second credential_sets options: %v", second.Options)
	}
}

// TestParseDCQLQueryNoCredentialSets guards the zero-value backward
// compatibility bar for the new top-level parser.
func TestParseDCQLQueryNoCredentialSets(t *testing.T) {
	query := ParseDCQLQuery(`{"credentials": [{"id": "mdl", "format": "mso_mdoc"}]}`)
	if len(query.CredentialSets) != 0 {
		t.Fatalf("expected no credential_sets, got %v", query.CredentialSets)
	}
	if len(query.Credentials) != 1 || query.Credentials[0].ID != "mdl" {
		t.Fatalf("unexpected credentials: %+v", query.Credentials)
	}
}

// TestParseDCQLCredentialRequirementsUnaffectedByCredentialSets is a
// regression guard: the pre-existing entry point must return identical
// per-credential requirements regardless of a sibling credential_sets array.
func TestParseDCQLCredentialRequirementsUnaffectedByCredentialSets(t *testing.T) {
	withSets := `{
		"credentials": [{"id": "mdl", "format": "mso_mdoc", "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}],
		"credential_sets": [{"options": [["mdl"]]}]
	}`
	withoutSets := `{
		"credentials": [{"id": "mdl", "format": "mso_mdoc", "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]}]
	}`
	a := ParseDCQLCredentialRequirements(withSets)
	b := ParseDCQLCredentialRequirements(withoutSets)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 requirement each, got %d and %d", len(a), len(b))
	}
	if a[0].ID != b[0].ID || a[0].Format != b[0].Format {
		t.Fatalf("expected identical requirements, got %+v vs %+v", a[0], b[0])
	}
}

func threeCredentialQuery(t *testing.T, setsJSON string) DCQLQuery {
	t.Helper()
	dcql := `{
		"credentials": [
			{"id": "pid", "format": "dc+sd-jwt"},
			{"id": "mdl", "format": "mso_mdoc"},
			{"id": "photo_id", "format": "mso_mdoc"}
		]` + setsJSON + `
	}`
	return ParseDCQLQuery(dcql)
}

// TestEvaluateCredentialSetsNoSetsAlwaysSatisfied confirms the documented
// zero-value contract: no CredentialSets means EvaluateCredentialSets always
// reports satisfied, regardless of what was matched.
func TestEvaluateCredentialSetsNoSetsAlwaysSatisfied(t *testing.T) {
	query := threeCredentialQuery(t, "")
	satisfied, unsatisfied := EvaluateCredentialSets(query, map[string]bool{})
	if !satisfied || len(unsatisfied) != 0 {
		t.Fatalf("expected always-satisfied with no credential_sets, got satisfied=%v unsatisfied=%v", satisfied, unsatisfied)
	}
}

// TestEvaluateCredentialSetsRequiredOptionSatisfied proves a required set is
// satisfied when at least one of its options is fully matched.
func TestEvaluateCredentialSetsRequiredOptionSatisfied(t *testing.T) {
	query := threeCredentialQuery(t, `, "credential_sets": [{"options": [["pid"], ["mdl"]]}]`)
	satisfied, unsatisfied := EvaluateCredentialSets(query, map[string]bool{"mdl": true})
	if !satisfied || len(unsatisfied) != 0 {
		t.Fatalf("expected satisfied via the mdl option, got satisfied=%v unsatisfied=%v", satisfied, unsatisfied)
	}
}

// TestEvaluateCredentialSetsRequiredOptionUnsatisfied proves a required set
// fails, naming its index, when no option is fully matched.
func TestEvaluateCredentialSetsRequiredOptionUnsatisfied(t *testing.T) {
	query := threeCredentialQuery(t, `, "credential_sets": [{"options": [["pid"], ["mdl"]]}]`)
	satisfied, unsatisfied := EvaluateCredentialSets(query, map[string]bool{"photo_id": true})
	if satisfied {
		t.Fatal("expected denial when neither pid nor mdl was matched")
	}
	if len(unsatisfied) != 1 || unsatisfied[0] != 0 {
		t.Fatalf("expected unsatisfied index [0], got %v", unsatisfied)
	}
}

// TestEvaluateCredentialSetsOptionalSetUnsatisfiedStillSucceeds proves a
// required:false set does not fail the overall query even if none of its
// options are matched.
func TestEvaluateCredentialSetsOptionalSetUnsatisfiedStillSucceeds(t *testing.T) {
	query := threeCredentialQuery(t, `, "credential_sets": [{"options": [["photo_id"]], "required": false}]`)
	satisfied, unsatisfied := EvaluateCredentialSets(query, map[string]bool{})
	if !satisfied || len(unsatisfied) != 0 {
		t.Fatalf("expected optional set to not block satisfaction, got satisfied=%v unsatisfied=%v", satisfied, unsatisfied)
	}
}

// TestEvaluateCredentialSetsMultipleRequiredSetsNamesEachFailure proves every
// unsatisfied required set is named, not just the first.
func TestEvaluateCredentialSetsMultipleRequiredSetsNamesEachFailure(t *testing.T) {
	query := threeCredentialQuery(t, `, "credential_sets": [{"options": [["pid"]]}, {"options": [["mdl"]]}]`)
	satisfied, unsatisfied := EvaluateCredentialSets(query, map[string]bool{"photo_id": true})
	if satisfied {
		t.Fatal("expected denial when neither required set is satisfied")
	}
	if len(unsatisfied) != 2 || unsatisfied[0] != 0 || unsatisfied[1] != 1 {
		t.Fatalf("expected both set indexes [0 1], got %v", unsatisfied)
	}
}

// TestCredentialIDsReferencedByCredentialSets confirms the helper used to
// tell "unconditionally required" Credential Queries apart from ones only
// required via a credential_sets alternative.
func TestCredentialIDsReferencedByCredentialSets(t *testing.T) {
	query := threeCredentialQuery(t, `, "credential_sets": [{"options": [["pid"], ["mdl"]]}]`)
	referenced := CredentialIDsReferencedByCredentialSets(query)
	if !referenced["pid"] || !referenced["mdl"] {
		t.Fatalf("expected pid and mdl to be referenced, got %v", referenced)
	}
	if referenced["photo_id"] {
		t.Fatalf("expected photo_id to be unreferenced, got %v", referenced)
	}

	noSets := threeCredentialQuery(t, "")
	if got := CredentialIDsReferencedByCredentialSets(noSets); got != nil {
		t.Fatalf("expected nil for a query with no credential_sets, got %v", got)
	}
}
