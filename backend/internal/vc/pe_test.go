package vc

import (
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestEvaluateJSONPathSupportsWildcardAndQuotedSegments(t *testing.T) {
	root := map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"addresses": []interface{}{
				map[string]interface{}{"street_name": "Main"},
				map[string]interface{}{"street_name": "Elm"},
			},
		},
	}

	values, err := EvaluateJSONPath(root, "$.credentialSubject.addresses[*]['street_name']")
	if err != nil {
		t.Fatalf("EvaluateJSONPath: %v", err)
	}
	if len(values) != 2 || values[0] != "Main" || values[1] != "Elm" {
		t.Fatalf("unexpected JSONPath result %#v", values)
	}
}

func TestMatchCredentialToDescriptorSupportsJSONPathFilters(t *testing.T) {
	rawCredential := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"sub": "did:example:holder",
		"vc": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"credentialSubject": map[string]interface{}{
				"degree": "BSc",
			},
		},
	})
	evidence, err := BuildCredentialEvidence(rawCredential)
	if err != nil {
		t.Fatalf("BuildCredentialEvidence: %v", err)
	}

	match, err := MatchCredentialToDescriptor(
		PresentationInputDescriptor{
			ID: "degree_credential",
			FormatConstraints: map[string]map[string]interface{}{
				"jwt_vc_json": {},
			},
			Constraints: PresentationConstraints{
				Fields: []PresentationField{
					{
						Paths: []string{"$.vc.type"},
						Filter: map[string]interface{}{
							"type": "array",
							"contains": map[string]interface{}{
								"const": "UniversityDegreeCredential",
							},
						},
					},
					{
						Paths: []string{"$.vc.credentialSubject.degree"},
						Filter: map[string]interface{}{
							"allOf": []interface{}{
								map[string]interface{}{"type": "string"},
								map[string]interface{}{"enum": []interface{}{"BSc", "MSc"}},
							},
						},
					},
				},
			},
		},
		PresentationCandidate{
			RootFormat:        "jwt_vp_json",
			RootPath:          "$",
			CredentialPath:    "$.vp.verifiableCredential[0]",
			CredentialFormats: []string{"jwt_vc_json-ld", "jwt_vc_json", "jwt_vc"},
			Evidence:          *evidence,
		},
	)
	if err != nil {
		t.Fatalf("MatchCredentialToDescriptor: %v", err)
	}
	if match.CredentialFormat != "jwt_vc_json" {
		t.Fatalf("unexpected matched credential format %q", match.CredentialFormat)
	}
}

func TestBuildPresentationSubmissionForJWTVP(t *testing.T) {
	rawCredential := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"sub": "did:example:holder",
		"vc": map[string]interface{}{
			"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	})
	vpToken := signedTestJWT(t, jwt.SigningMethodHS256, []byte("vp-secret"), "vp+jwt", jwt.MapClaims{
		"iss": "did:example:holder",
		"vp": map[string]interface{}{
			"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
			"type":                 []string{"VerifiablePresentation"},
			"verifiableCredential": []interface{}{rawCredential},
		},
	})

	submission, err := BuildPresentationSubmission(map[string]interface{}{
		"id": "jwt_vc_request",
		"input_descriptors": []interface{}{
			map[string]interface{}{
				"id": "id_credential",
				"format": map[string]interface{}{
					"jwt_vc_json": map[string]interface{}{},
				},
				"constraints": map[string]interface{}{
					"fields": []interface{}{
						map[string]interface{}{
							"path": []interface{}{"$.vc.type"},
							"filter": map[string]interface{}{
								"type": "array",
								"contains": map[string]interface{}{
									"const": "UniversityDegreeCredential",
								},
							},
						},
					},
				},
			},
		},
	}, vpToken)
	if err != nil {
		t.Fatalf("BuildPresentationSubmission(jwt_vp_json): %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(submission), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	descriptorMap, _ := payload["descriptor_map"].([]interface{})
	if len(descriptorMap) != 1 {
		t.Fatalf("unexpected descriptor_map %#v", descriptorMap)
	}
	entry, _ := descriptorMap[0].(map[string]interface{})
	if entry["path"] != "$" || entry["format"] != "jwt_vp_json" {
		t.Fatalf("unexpected top-level descriptor mapping %#v", entry)
	}
	pathNested, _ := entry["path_nested"].(map[string]interface{})
	if pathNested["path"] != "$.vp.verifiableCredential[0]" || pathNested["format"] != "jwt_vc_json" {
		t.Fatalf("unexpected nested descriptor mapping %#v", pathNested)
	}
}

func TestBuildPresentationSubmissionForSDJWT(t *testing.T) {
	disclosure, err := CreateSDJWTDisclosure("family_name", "Doe", "fixed-salt")
	if err != nil {
		t.Fatalf("CreateSDJWTDisclosure: %v", err)
	}
	vpToken := BuildSDJWTSerialization(
		signedTestJWT(t, jwt.SigningMethodHS256, []byte("sd-secret"), "vc+sd-jwt", jwt.MapClaims{
			"sub": "did:example:holder",
			"vct": "https://credentials.example.com/identity_credential",
			"vc": map[string]interface{}{
				"type": []string{"VerifiableCredential", "IdentityCredential"},
			},
		}),
		[]string{disclosure.Encoded},
		"kb.jwt.token",
	)

	submission, err := BuildPresentationSubmission(map[string]interface{}{
		"id": "example_sd_jwt_vc_request",
		"input_descriptors": []interface{}{
			map[string]interface{}{
				"id": "identity_credential",
				"format": map[string]interface{}{
					"vc+sd-jwt": map[string]interface{}{},
				},
				"constraints": map[string]interface{}{
					"fields": []interface{}{
						map[string]interface{}{
							"path": []interface{}{"$.vct"},
							"filter": map[string]interface{}{
								"type":  "string",
								"const": "https://credentials.example.com/identity_credential",
							},
						},
						map[string]interface{}{
							"path": []interface{}{"$.family_name"},
						},
					},
				},
			},
		},
	}, vpToken)
	if err != nil {
		t.Fatalf("BuildPresentationSubmission(vc+sd-jwt): %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(submission), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	descriptorMap, _ := payload["descriptor_map"].([]interface{})
	if len(descriptorMap) != 1 {
		t.Fatalf("unexpected descriptor_map %#v", descriptorMap)
	}
	entry, _ := descriptorMap[0].(map[string]interface{})
	if entry["path"] != "$" || entry["format"] != "vc+sd-jwt" {
		t.Fatalf("unexpected sd-jwt descriptor mapping %#v", entry)
	}
	if _, hasPathNested := entry["path_nested"]; hasPathNested {
		t.Fatalf("vc+sd-jwt descriptor map must not contain path_nested")
	}
}
