package vc

import (
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/golang-jwt/jwt/v5"
)

// TestBuildCredentialEvidenceRejectsZeroValueLifecycleStage pins that
// lifecycleStage has no default: an empty CredentialLifecycleStage (Go's
// zero value for the type, e.g. from an uninitialized field at a new call
// site) must be rejected rather than silently accepted and rendered with
// the wrong "issued" vs "presented" wording downstream.
func TestBuildCredentialEvidenceRejectsZeroValueLifecycleStage(t *testing.T) {
	rawCredential := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"vc": map[string]interface{}{
			"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	})
	if _, err := BuildCredentialEvidence(rawCredential, ""); err == nil {
		t.Fatalf("BuildCredentialEvidence accepted a zero-value lifecycle stage")
	}
	if _, err := BuildCredentialEvidence(rawCredential, CredentialLifecycleStage("bogus")); err == nil {
		t.Fatalf("BuildCredentialEvidence accepted an unrecognized lifecycle stage")
	}
}

// TestBuildCredentialEvidenceForMdocReportsExactCommittedCount is the direct
// regression pin for the fabrication-constraint breach this workstream
// exists to fix: an issued mdoc must report a real, non-zero,
// exactly-committed element count sourced from the MSO valueDigests, never
// the old hasDisclosures:false/disclosureCount:0 SD-JWT-tilde-counting
// artifact that mdoc could never produce a true answer for.
func TestBuildCredentialEvidenceForMdocReportsExactCommittedCount(t *testing.T) {
	fixture := buildTestMdocCredential(t)

	evidence, err := BuildCredentialEvidence(fixture.credential, LifecycleStageIssued)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence(mso_mdoc): %v", err)
	}
	if evidence.Format != "mso_mdoc" {
		t.Fatalf("evidence.Format = %q, want mso_mdoc", evidence.Format)
	}
	if evidence.Doctype != mdoc.DocTypeMDL {
		t.Fatalf("evidence.Doctype = %q, want %q", evidence.Doctype, mdoc.DocTypeMDL)
	}
	if evidence.IssuedAt.IsZero() {
		t.Fatalf("evidence.IssuedAt is zero; MSO ValidityInfo.Signed should have populated it")
	}
	if evidence.ExpiresAt.IsZero() {
		t.Fatalf("evidence.ExpiresAt is zero; MSO ValidityInfo.ValidUntil should have populated it")
	}

	sd := evidence.SelectiveDisclosure
	if sd == nil {
		t.Fatalf("evidence.SelectiveDisclosure is nil for mso_mdoc; mdoc always has a selective-disclosure mechanism")
		return
	}
	if sd.Mechanism != "mso_valuedigests" {
		t.Fatalf("sd.Mechanism = %q, want mso_valuedigests", sd.Mechanism)
	}
	// The fixture commits exactly 2 elements (family_name, age_over_18).
	// Zero here, on a credential that genuinely committed to 2 elements,
	// is exactly the fabrication this evidence shape replaces.
	if sd.CommittedCount != 2 {
		t.Fatalf("sd.CommittedCount = %d, want 2 (family_name, age_over_18)", sd.CommittedCount)
	}
	if !sd.CommittedCountIsExact {
		t.Fatalf("sd.CommittedCountIsExact = false for mso_valuedigests; ISO/IEC 18013-5 has no decoy-digest mechanism, so this must always be true")
	}
	if sd.PresentCount != 2 {
		t.Fatalf("sd.PresentCount = %d, want 2", sd.PresentCount)
	}
	if sd.LifecycleStage != LifecycleStageIssued {
		t.Fatalf("sd.LifecycleStage = %q, want %q", sd.LifecycleStage, LifecycleStageIssued)
	}
	if sd.DigestAlgorithm != mdoc.DigestAlgorithmSHA256 {
		t.Fatalf("sd.DigestAlgorithm = %q, want %q", sd.DigestAlgorithm, mdoc.DigestAlgorithmSHA256)
	}
	if sd.HasUnrepresentedDisclosureForms {
		t.Fatalf("sd.HasUnrepresentedDisclosureForms = true for mdoc; mdoc has no nested or array-element disclosure forms")
	}
	nsCounts, ok := sd.PerNamespace[string(mdoc.NameSpaceMDL)]
	if !ok {
		t.Fatalf("sd.PerNamespace missing %q: %#v", mdoc.NameSpaceMDL, sd.PerNamespace)
	}
	if nsCounts.CommittedCount != 2 || nsCounts.PresentCount != 2 {
		t.Fatalf("sd.PerNamespace[%q] = %+v, want {2, 2}", mdoc.NameSpaceMDL, nsCounts)
	}
}

// TestBuildCredentialEvidenceLifecycleStageIsCallerProvidedNotInferred pins
// that lifecycle_stage on CredentialEvidence reflects the caller's
// parameter, not something inferred from the (byte-identical either way)
// mdoc artifact -- BuildCredentialEvidence has no way to tell an issued mDL
// from the same mDL presented with every element intact, so the same raw
// credential must faithfully echo back whichever stage the caller asserts.
func TestBuildCredentialEvidenceLifecycleStageIsCallerProvidedNotInferred(t *testing.T) {
	fixture := buildTestMdocCredential(t)

	issuedEvidence, err := BuildCredentialEvidence(fixture.credential, LifecycleStageIssued)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence(issued): %v", err)
	}
	if issuedEvidence.SelectiveDisclosure.LifecycleStage != LifecycleStageIssued {
		t.Fatalf("issued call: LifecycleStage = %q, want %q", issuedEvidence.SelectiveDisclosure.LifecycleStage, LifecycleStageIssued)
	}

	presentedEvidence, err := BuildCredentialEvidence(fixture.credential, LifecycleStagePresented)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence(presented): %v", err)
	}
	if presentedEvidence.SelectiveDisclosure.LifecycleStage != LifecycleStagePresented {
		t.Fatalf("presented call: LifecycleStage = %q, want %q", presentedEvidence.SelectiveDisclosure.LifecycleStage, LifecycleStagePresented)
	}
	// Every other field must be identical: only the caller-supplied stage
	// differs, confirming it is not derived from anything in the artifact.
	if issuedEvidence.SelectiveDisclosure.CommittedCount != presentedEvidence.SelectiveDisclosure.CommittedCount {
		t.Fatalf("CommittedCount differed between lifecycle stages on the identical artifact: issued=%d presented=%d",
			issuedEvidence.SelectiveDisclosure.CommittedCount, presentedEvidence.SelectiveDisclosure.CommittedCount)
	}
}

// TestBuildCredentialEvidenceForSDJWTCommittedCountIsNeverExact pins the
// asymmetry the mdoc fix must not re-introduce in a subtler form: SD-JWT
// permits decoy digests specifically so a verifier cannot infer the true
// claim count from the "_sd" digest count alone, so CommittedCountIsExact
// must read false unconditionally for sd_jwt_disclosures -- even for this
// credential, which happens to carry no decoys and whose digest count
// exactly matches its disclosure count. The format's property, not this
// instance's coincidence, is what CommittedCountIsExact reports.
func TestBuildCredentialEvidenceForSDJWTCommittedCountIsNeverExact(t *testing.T) {
	disclosure, err := CreateSDJWTDisclosure("family_name", "Doe", "fixed-salt")
	if err != nil {
		t.Fatalf("CreateSDJWTDisclosure: %v", err)
	}
	rawCredential := BuildSDJWTSerialization(
		signedTestJWT(t, jwt.SigningMethodHS256, []byte("sd-secret"), "dc+sd-jwt", jwt.MapClaims{
			"vct": "https://example.org/credential",
			"_sd": []string{disclosure.Digest},
			"vc": map[string]interface{}{
				"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
			},
		}),
		[]string{disclosure.Encoded},
		"",
	)

	evidence, err := BuildCredentialEvidence(rawCredential, LifecycleStageIssued)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence(dc+sd-jwt): %v", err)
	}
	sd := evidence.SelectiveDisclosure
	if sd == nil {
		t.Fatalf("evidence.SelectiveDisclosure is nil for dc+sd-jwt")
		return
	}
	if sd.Mechanism != "sd_jwt_disclosures" {
		t.Fatalf("sd.Mechanism = %q, want sd_jwt_disclosures", sd.Mechanism)
	}
	if sd.CommittedCountIsExact {
		t.Fatalf("sd.CommittedCountIsExact = true for sd_jwt_disclosures; SD-JWT's decoy-digest allowance means this must always be false")
	}
	if sd.PresentCount != 1 {
		t.Fatalf("sd.PresentCount = %d, want 1", sd.PresentCount)
	}
}

// RFC 9901 Section 7.1 makes only the Processed SD-JWT Payload available to
// the application. Credential evidence therefore must preserve the exact
// nested object/array positions produced by disclosure processing.
func TestBuildCredentialEvidenceUsesProcessedSDJWTClaimTree(t *testing.T) {
	role, err := CreateSDJWTArrayDisclosure("admin", "salt-role")
	if err != nil {
		t.Fatal(err)
	}
	department, err := CreateSDJWTDisclosure("department", map[string]interface{}{
		"name":  "Security",
		"roles": []interface{}{"reader", map[string]interface{}{"...": role.Digest}},
	}, "salt-department")
	if err != nil {
		t.Fatal(err)
	}
	rawCredential := BuildSDJWTSerialization(
		signedTestJWT(t, jwt.SigningMethodHS256, []byte("sd-secret"), "dc+sd-jwt", jwt.MapClaims{
			"_sd_alg": "sha-256",
			"vct":     "https://example.org/credential",
			"vc": map[string]interface{}{
				"credentialSubject": map[string]interface{}{
					"id":  "did:example:holder",
					"_sd": []interface{}{department.Digest},
				},
			},
		}),
		[]string{department.Encoded, role.Encoded},
		"",
	)

	evidence, err := BuildCredentialEvidence(rawCredential, LifecycleStagePresented)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence: %v", err)
	}
	subject := evidence.FullClaims["credentialSubject"].(map[string]interface{})
	departmentValue := subject["department"].(map[string]interface{})
	roles := departmentValue["roles"].([]interface{})
	if len(roles) != 2 || roles[0] != "reader" || roles[1] != "admin" {
		t.Fatalf("processed roles = %#v", roles)
	}
	if _, flattened := evidence.FullClaims["roles"]; flattened {
		t.Fatal("nested roles array was globally flattened")
	}
	if _, retained := evidence.FullClaims["_sd_alg"]; retained {
		t.Fatal("processed evidence retained _sd_alg")
	}
}

// TestBuildCredentialEvidenceOmitsSelectiveDisclosureForFullDisclosureFormats
// pins that jwt_vc_json, jwt_vc_json-ld, and ldp_vc -- which always reveal
// every claim they carry, with no selective-disclosure mechanism at all --
// get a nil SelectiveDisclosure rather than a zeroed-out summary. A zeroed
// struct (CommittedCount: 0, Mechanism: "") would read as "this credential
// committed to nothing", the same shape of false claim mdoc's old
// disclosureCount:0 made.
func TestBuildCredentialEvidenceOmitsSelectiveDisclosureForFullDisclosureFormats(t *testing.T) {
	rawCredential := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"vc": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	})
	evidence, err := BuildCredentialEvidence(rawCredential, LifecycleStageIssued)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence(jwt_vc_json-ld): %v", err)
	}
	if evidence.SelectiveDisclosure != nil {
		t.Fatalf("evidence.SelectiveDisclosure = %+v, want nil for a format with no selective-disclosure mechanism", evidence.SelectiveDisclosure)
	}
}
