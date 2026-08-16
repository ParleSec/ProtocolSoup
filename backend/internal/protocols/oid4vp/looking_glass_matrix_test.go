package oid4vp

import (
	"net/http"
	"testing"
)

// Looking Glass OID4VP request-create permutations. Payloads match
// oid4vp-direct-post.ts after HAIP x509_hash coercion (encrypted response + DCQL).
func TestLookingGlassOID4VPRequestCreatePermutations(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()
	env.vpPlugin.baseURL = "http://localhost"
	if err := env.vpPlugin.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure verifier identities: %v", err)
	}
	if _, ok := env.vpPlugin.supportedClientIDSchemes[ClientIDSchemeX509Hash]; !ok {
		t.Fatal("x509_hash must be available for Looking Glass HAIP permutations")
	}

	mdlDCQL := map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "mdl",
				"format": "mso_mdoc",
				"meta":   map[string]interface{}{"doctype_value": "org.iso.18013.5.1.mDL"},
				"claims": []map[string]interface{}{
					{"path": []string{"org.iso.18013.5.1", "family_name"}},
					{"path": []string{"org.iso.18013.5.1", "document_number"}},
				},
			},
		},
	}
	sdjwtDCQL := map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "university_degree",
				"format": "dc+sd-jwt",
				"meta":   map[string]interface{}{"vct_values": []string{"https://protocolsoup.com/credentials/university_degree"}},
				"claims": []map[string]interface{}{{"path": []string{"degree"}}, {"path": []string{"graduation_year"}}},
			},
		},
	}
	jwtVCDCQL := map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "university_degree",
				"format": "jwt_vc_json",
				"meta":   map[string]interface{}{"vct_values": []string{"https://protocolsoup.com/credentials/university_degree"}},
				"claims": []map[string]interface{}{{"path": []string{"degree"}}},
			},
		},
	}

	type queryCase struct {
		name  string
		dcql  map[string]interface{}
		scope string
	}
	queries := []queryCase{
		{name: "dcql-mdl", dcql: mdlDCQL},
		{name: "dcql-sdjwt", dcql: sdjwtDCQL},
		{name: "dcql-jwt-vc-json-paste", dcql: jwtVCDCQL},
		{name: "scope-openid", scope: "openid"},
	}
	schemes := []string{"redirect_uri", "verifier_attestation", "x509_san_dns", "x509_hash"}
	modes := []string{"direct_post", "direct_post.jwt"}
	methods := []string{"get", "post"}

	for _, scheme := range schemes {
		for _, mode := range modes {
			for _, method := range methods {
				for _, query := range queries {
					scheme, mode, method, query := scheme, mode, method, query
					name := scheme + "/" + mode + "/" + method + "/" + query.name
					t.Run(name, func(t *testing.T) {
						effectiveMode := mode
						if scheme == "x509_hash" {
							effectiveMode = "direct_post.jwt"
						}
						payload := map[string]interface{}{
							"response_mode":    effectiveMode,
							"client_id_scheme": scheme,
						}
						if scheme == "x509_san_dns" {
							payload["response_uri"] = "http://localhost/oid4vp/response"
						} else {
							payload["response_uri"] = env.Server.URL + "/oid4vp/response"
						}
						if scheme == "x509_hash" {
							payload["profile"] = "haip"
							if query.scope != "" {
								payload["dcql_query"] = mdlDCQL
							} else {
								payload["dcql_query"] = query.dcql
							}
						} else if query.scope != "" {
							payload["scope"] = query.scope
						} else {
							payload["dcql_query"] = query.dcql
						}
						if method == "post" {
							payload["request_uri_method"] = "post"
						}
						createResp := postVPJSON(t, env.Server.URL+"/oid4vp/request/create", payload)
						assertVPStatus(t, createResp, http.StatusCreated)
						created := decodeVPJSONMap(t, createResp)
						if asVPString(created["request_id"]) == "" {
							t.Fatal("expected request_id")
						}
						if scheme == "x509_hash" && asVPString(created["response_mode"]) != "direct_post.jwt" {
							t.Fatalf("x509_hash response_mode = %q, want direct_post.jwt", created["response_mode"])
						}
						if effectiveMode == "direct_post.jwt" {
							encValues, _ := created["encrypted_response_enc_values_supported"].([]interface{})
							if len(encValues) == 0 {
								t.Fatal("direct_post.jwt create must advertise encrypted_response_enc_values_supported")
							}
						}
					})
				}
			}
		}
	}
}

func TestLookingGlassX509HashWithoutCoerceIsRejected(t *testing.T) {
	env := newCombinedVCServer(t)
	defer env.Server.Close()
	env.vpPlugin.baseURL = "http://localhost"
	if err := env.vpPlugin.configureVerifierIdentities(); err != nil {
		t.Fatalf("configure verifier identities: %v", err)
	}

	createResp := postVPJSON(t, env.Server.URL+"/oid4vp/request/create", map[string]interface{}{
		"profile":          "haip",
		"response_mode":    "direct_post",
		"client_id_scheme": "x509_hash",
		"response_uri":     env.Server.URL + "/oid4vp/response",
		"dcql_query": map[string]interface{}{
			"credentials": []map[string]interface{}{
				{"id": "mdl", "format": "mso_mdoc"},
			},
		},
	})
	assertVPStatus(t, createResp, http.StatusBadRequest)
}
