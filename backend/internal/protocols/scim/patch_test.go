package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const patchURN = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

// patch sends a PATCH with the given operations, as JSON.
func (f *queryFixture) patch(t *testing.T, path, operations string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return f.request(t, http.MethodPatch, path, headers, `{"schemas":["`+patchURN+`"],"Operations":`+operations+`}`)
}

func (f *queryFixture) get(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	recorder := f.request(t, http.MethodGet, path, nil, "")
	var resource map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resource); err != nil || recorder.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, recorder.Code, recorder.Body.String())
	}
	return resource
}

// RFC 7644 Section 3.5.2 on the request itself.
func TestPatchRequestMustBeWellFormed(t *testing.T) {
	f := newQueryFixture(t)
	user := "/scim/v2/Users/" + f.alpha
	cases := map[string]struct{ body, scimType string }{
		// 'The body of each request MUST contain the "schemas" attribute with
		// the URI value of "urn:ietf:params:scim:api:messages:2.0:PatchOp".'
		"no schemas":     {`{"Operations":[{"op":"replace","path":"title","value":"X"}]}`, "invalidValue"},
		"another schema": {`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"Operations":[{"op":"replace","path":"title","value":"X"}]}`, "invalidSyntax"},
		// '"Operations", whose value is an array of one or more PATCH
		// operations.'
		"no Operations": {`{"schemas":["` + patchURN + `"]}`, "invalidSyntax"},
		"no operation":  {`{"schemas":["` + patchURN + `"],"Operations":[]}`, "invalidSyntax"},
		// 'Each PATCH operation object MUST have exactly one "op" member,
		// whose value indicates the operation to perform and MAY be one of
		// "add", "remove", or "replace".'
		"an unknown op": {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"move","path":"title","value":"X"}]}`, "invalidSyntax"},
		// 'If "path" is unspecified, the operation fails with HTTP status code
		// 400 and a "scimType" error code of "noTarget".'
		"remove, no path": {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"remove"}]}`, "noTarget"},
		// 'The operation MUST contain a "value" member'.
		"add, no value":                       {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"add","path":"title"}]}`, "invalidValue"},
		"a broken path":                       {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"replace","path":"emails[type eq","value":"X"}]}`, "invalidPath"},
		"an unknown attribute":                {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"replace","path":"shoeSize","value":"9"}]}`, "invalidPath"},
		"a value of the wrong type":           {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"replace","path":"active","value":"yes"}]}`, "invalidValue"},
		"an unknown sub-attribute in a value": {`{"schemas":["` + patchURN + `"],"Operations":[{"op":"add","path":"emails","value":[{"address":"a@example.com"}]}]}`, "invalidValue"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := f.request(t, http.MethodPatch, user, nil, testCase.body)
			body := scimErrorBody(t, recorder)
			if recorder.Code != http.StatusBadRequest || body["scimType"] != testCase.scimType {
				t.Errorf("status = %d, body = %v; want 400 %s", recorder.Code, body, testCase.scimType)
			}
		})
	}
}

// RFC 7644 Sections 3.5.2.1 to 3.5.2.3.
func TestPatchOperations(t *testing.T) {
	f := newQueryFixture(t)
	user := "/scim/v2/Users/" + f.alpha
	apply := func(operations string) map[string]interface{} {
		t.Helper()
		recorder := f.patch(t, user, operations, nil)
		// 'On successful completion, the server either MUST return a 200 OK
		// response code and the entire resource within the response body,
		// subject to the "attributes" query parameter (see Section 3.9), or
		// MAY return HTTP status code 204 (No Content)'.
		if recorder.Code != http.StatusOK {
			t.Fatalf("PATCH %s = %d %s", operations, recorder.Code, recorder.Body.String())
		}
		var resource map[string]interface{}
		_ = json.Unmarshal(recorder.Body.Bytes(), &resource)
		return resource
	}
	emails := func(resource map[string]interface{}) [][2]interface{} {
		var out [][2]interface{}
		for _, raw := range resource["emails"].([]interface{}) {
			email := raw.(map[string]interface{})
			out = append(out, [2]interface{}{email["value"], email["primary"] == true})
		}
		return out
	}

	// "If the target location specifies a single-valued attribute, the
	// existing value is replaced."
	if got := apply(`[{"op":"add","path":"title","value":"Principal"}]`); got["title"] != "Principal" {
		t.Errorf("title = %v", got["title"])
	}
	// "If the target location specifies a complex attribute, a set of
	// sub-attributes SHALL be specified in the "value" parameter"; the others
	// stay.
	got := apply(`[{"op":"add","path":"name.middleName","value":"Q"}]`)
	if want := map[string]interface{}{"givenName": "Zed", "familyName": "Alpha", "middleName": "Q"}; !reflect.DeepEqual(got["name"], want) {
		t.Errorf("after adding a sub-attribute, name = %v", got["name"])
	}
	// replace: "Sub-attributes that are not specified in the "value"
	// parameter are left unchanged."
	got = apply(`[{"op":"replace","path":"name","value":{"givenName":"Zoe"}}]`)
	if want := map[string]interface{}{"givenName": "Zoe", "familyName": "Alpha", "middleName": "Q"}; !reflect.DeepEqual(got["name"], want) {
		t.Errorf("after replacing a complex attribute, name = %v", got["name"])
	}
	// "If the target location specifies a multi-valued attribute, a new value
	// is added to the attribute."
	got = apply(`[{"op":"add","path":"emails","value":[{"value":"alpha@other.example.com","type":"other"}]}]`)
	if len(emails(got)) != 3 {
		t.Errorf("after adding a value, emails = %v", emails(got))
	}
	// 'a PATCH operation that sets a value's "primary" sub-attribute to "true"
	// SHALL cause the server to automatically set "primary" to "false" for any
	// other values in the array.'
	got = apply(`[{"op":"replace","path":"emails[type eq \"home\"].primary","value":true}]`)
	if want := [][2]interface{}{{"alpha@work.example.com", false}, {"alpha@home.example.com", true}, {"alpha@other.example.com", false}}; !reflect.DeepEqual(emails(got), want) {
		t.Errorf("after moving primary, emails = %v", emails(got))
	}
	// "all matching record values SHALL be replaced."
	got = apply(`[{"op":"replace","path":"emails[type eq \"other\"]","value":{"value":"alpha@third.example.com","type":"other"}}]`)
	if emails(got)[2][0] != "alpha@third.example.com" {
		t.Errorf("after replacing a selected value, emails = %v", emails(got))
	}
	// "the values matched by the filter are removed."
	got = apply(`[{"op":"remove","path":"emails[type eq \"other\"]"}]`)
	if len(emails(got)) != 2 {
		t.Errorf("after removing a selected value, emails = %v", emails(got))
	}
	// With no path, "the target location is assumed to be the resource
	// itself".
	got = apply(`[{"op":"replace","value":{"displayName":"Alpha Two","nickName":"Al"}}]`)
	if got["displayName"] != "Alpha Two" || got["nickName"] != "Al" {
		t.Errorf("after a replace with no path: %v %v", got["displayName"], got["nickName"])
	}
	// Section 3.10: an attribute may carry its schema URI.
	if got = apply(`[{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:title","value":"Via URI"}]`); got["title"] != "Via URI" {
		t.Errorf("title = %v", got["title"])
	}
	// "the attribute and its associated value is removed".
	if got = apply(`[{"op":"remove","path":"title"}]`); got["title"] != nil {
		t.Errorf("title = %v after remove", got["title"])
	}
	// "If no other values remain after removal of the selected values, the
	// multi-valued attribute SHALL be considered unassigned."
	if got = apply(`[{"op":"remove","path":"emails[value co \"@\"]"}]`); got["emails"] != nil {
		t.Errorf("emails = %v after every value was removed", got["emails"])
	}

	// 'Clients MAY implicitly modify the "schemas" attribute by adding (or
	// replacing) an attribute with its fully qualified name, including schema
	// URN.'
	charlie := "/scim/v2/Users/" + f.charlie
	recorder := f.patch(t, charlie, `[{"op":"add","path":"`+enterpriseURN+`:department","value":"Ops"}]`, nil)
	var extended map[string]interface{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &extended)
	if want := []interface{}{"urn:ietf:params:scim:schemas:core:2.0:User", enterpriseURN}; recorder.Code != http.StatusOK ||
		!reflect.DeepEqual(extended["schemas"], want) || !reflect.DeepEqual(extended[enterpriseURN], map[string]interface{}{"department": "Ops"}) {
		t.Errorf("adding an extension attribute = %d, schemas %v, extension %v", recorder.Code, extended["schemas"], extended[enterpriseURN])
	}
}

// 'An operation that is not compatible with an attribute's mutability or
// schema SHALL return the appropriate HTTP response status code and a JSON
// detail error response'; removing a required attribute gives "mutability".
func TestPatchRespectsMutability(t *testing.T) {
	f := newQueryFixture(t)
	user := "/scim/v2/Users/" + f.alpha
	group := "/scim/v2/Groups/" + f.group
	for name, target := range map[string][2]string{
		"remove a required attribute":     {user, `[{"op":"remove","path":"userName"}]`},
		"replace id":                      {user, `[{"op":"replace","path":"id","value":"x"}]`},
		"replace a sub-attribute of meta": {user, `[{"op":"replace","path":"meta.created","value":"1999-01-01T00:00:00Z"}]`},
		"add groups to a User":            {user, `[{"op":"add","path":"groups","value":[{"value":"g"}]}]`},
		"id in a value with no path":      {user, `[{"op":"replace","value":{"id":"x"}}]`},
		"remove a Group's displayName":    {group, `[{"op":"remove","path":"displayName"}]`},
		"change the value of a member":    {group, `[{"op":"replace","path":"members[value eq \"` + f.alpha + `\"].value","value":"` + f.bravo + `"}]`},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := f.patch(t, target[0], target[1], nil)
			if body := scimErrorBody(t, recorder); recorder.Code != http.StatusBadRequest || body["scimType"] != "mutability" {
				t.Errorf("status = %d, body = %v; want 400 mutability", recorder.Code, body)
			}
		})
	}
}

// "A PATCH request, regardless of the number of operations, SHALL be treated
// as atomic. If a single operation encounters an error condition, the
// original SCIM resource MUST be restored".
func TestPatchIsAtomic(t *testing.T) {
	f := newQueryFixture(t)
	user := "/scim/v2/Users/" + f.alpha
	before := f.get(t, user)
	recorder := f.patch(t, user, `[{"op":"replace","path":"displayName","value":"CHANGED"},{"op":"replace","path":"emails[type eq \"pager\"].value","value":"x@example.com"}]`, nil)
	// 'no record match was made, the service provider SHALL indicate failure
	// by returning HTTP status code 400 and a "scimType" error code of
	// "noTarget".'
	if body := scimErrorBody(t, recorder); recorder.Code != http.StatusBadRequest || body["scimType"] != "noTarget" {
		t.Fatalf("status = %d, body = %v; want 400 noTarget", recorder.Code, body)
	}
	if after := f.get(t, user); !reflect.DeepEqual(before, after) {
		t.Errorf("a failed PATCH changed the resource:\n%v\n%v", before, after)
	}
}

// "If the target location already contains the value specified, no changes
// SHOULD be made to the resource, and a success response SHOULD be returned.
// Unless other operations change the resource, this operation SHALL NOT
// change the modify timestamp of the resource."
func TestPatchThatChangesNothingLeavesTheVersion(t *testing.T) {
	f := newQueryFixture(t)
	user := "/scim/v2/Users/" + f.alpha
	before := f.get(t, user)
	for _, operations := range []string{
		`[{"op":"add","path":"title","value":"Engineer"}]`,
		`[{"op":"add","path":"emails","value":[{"value":"alpha@work.example.com","type":"work"}]}]`,
	} {
		if recorder := f.patch(t, user, operations, nil); recorder.Code != http.StatusOK {
			t.Fatalf("PATCH %s = %d %s", operations, recorder.Code, recorder.Body.String())
		}
	}
	after := f.get(t, user)
	if !reflect.DeepEqual(before["meta"], after["meta"]) {
		t.Errorf("meta changed: %v -> %v", before["meta"], after["meta"])
	}
}

// RFC 7644 Section 3.14 and Table 8: 412 when the If-Match entity-tag is not
// the current one, for PUT, PATCH and DELETE.
func TestIfMatchGuardsChanges(t *testing.T) {
	f := newQueryFixture(t)
	user := "/scim/v2/Users/" + f.charlie
	current := f.get(t, user)["meta"].(map[string]interface{})["version"].(string)
	replace := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"q.charlie@example.com","displayName":"Charlie"}`
	stale := map[string]string{"If-Match": `W/"999"`}

	for name, recorder := range map[string]*httptest.ResponseRecorder{
		"PATCH":                                  f.patch(t, user, `[{"op":"replace","path":"title","value":"Stale"}]`, stale),
		"PUT":                                    f.request(t, http.MethodPut, user, stale, replace),
		"DELETE":                                 f.request(t, http.MethodDelete, user, stale, ""),
		"PUT with an entity-tag that is not one": f.request(t, http.MethodPut, user, map[string]string{"If-Match": "garbage"}, replace),
	} {
		body := scimErrorBody(t, recorder)
		if recorder.Code != http.StatusPreconditionFailed || body["status"] != "412" {
			t.Errorf("%s with a stale If-Match = %d %v, want 412", name, recorder.Code, body)
		}
		// Table 9 defines no scimType for it.
		if _, present := body["scimType"]; present {
			t.Errorf("%s: scimType = %v on a 412", name, body["scimType"])
		}
	}
	if got := f.get(t, user); got["title"] != nil {
		t.Errorf("a refused change was applied: title = %v", got["title"])
	}
	if recorder := f.patch(t, user, `[{"op":"replace","path":"title","value":"Fresh"}]`, map[string]string{"If-Match": current}); recorder.Code != http.StatusOK {
		t.Errorf("PATCH with the current entity-tag = %d", recorder.Code)
	}
	if recorder := f.request(t, http.MethodDelete, user, map[string]string{"If-Match": "*"}, ""); recorder.Code != http.StatusNoContent {
		t.Errorf("DELETE with If-Match: * = %d", recorder.Code)
	}
	// "Service providers MAY choose not to permanently delete the resource but
	// MUST return a 404 (Not Found) error code for all operations associated
	// with the previously deleted resource."
	if recorder := f.request(t, http.MethodGet, user, nil, ""); recorder.Code != http.StatusNotFound {
		t.Errorf("GET after DELETE = %d", recorder.Code)
	}
}

// A PATCH that makes the resource invalid is refused like a POST would be.
func TestPatchKeepsUserNameUnique(t *testing.T) {
	f := newQueryFixture(t)
	recorder := f.patch(t, "/scim/v2/Users/"+f.charlie, `[{"op":"replace","path":"userName","value":"Q.ALPHA@example.com"}]`, nil)
	if body := scimErrorBody(t, recorder); recorder.Code != http.StatusConflict || body["scimType"] != "uniqueness" {
		t.Errorf("status = %d, body = %v; want 409 uniqueness", recorder.Code, body)
	}
}

// RFC 7643 Section 4.2: members of a Group, changed through the Group.
func TestGroupMembership(t *testing.T) {
	f := newQueryFixture(t)
	group := "/scim/v2/Groups/" + f.group
	members := func() []string {
		var ids []string
		raw, _ := f.get(t, group)["members"].([]interface{})
		for _, member := range raw {
			object := member.(map[string]interface{})
			ids = append(ids, object["value"].(string))
			if object["$ref"] != testResource+"/Users/"+object["value"].(string) || object["type"] != "User" {
				t.Errorf("member = %v", object)
			}
		}
		return ids
	}

	if recorder := f.patch(t, group, `[{"op":"add","path":"members","value":[{"value":"`+f.charlie+`"}]}]`, nil); recorder.Code != http.StatusOK || len(members()) != 2 {
		t.Fatalf("add a member = %d, members %v", recorder.Code, members())
	}
	// Adding a member that is there changes nothing.
	version := f.get(t, group)["meta"].(map[string]interface{})["version"]
	if recorder := f.patch(t, group, `[{"op":"add","path":"members","value":[{"value":"`+f.charlie+`"}]}]`, nil); recorder.Code != http.StatusOK ||
		len(members()) != 2 || f.get(t, group)["meta"].(map[string]interface{})["version"] != version {
		t.Errorf("adding the same member again = %d, members %v", recorder.Code, members())
	}
	// The User shows the Group it belongs to, as a direct membership.
	groups, _ := f.get(t, "/scim/v2/Users/"+f.charlie)["groups"].([]interface{})
	if len(groups) != 1 || groups[0].(map[string]interface{})["value"] != f.group || groups[0].(map[string]interface{})["type"] != "direct" {
		t.Errorf("the member's groups = %v", groups)
	}
	if recorder := f.patch(t, group, `[{"op":"remove","path":"members[value eq \"`+f.charlie+`\"]"}]`, nil); recorder.Code != http.StatusOK || !reflect.DeepEqual(members(), []string{f.alpha}) {
		t.Errorf("remove a member = %d, members %v", recorder.Code, members())
	}
	for name, operations := range map[string]string{
		"a member that is no User":        `[{"op":"add","path":"members","value":[{"value":"no-such-user"}]}]`,
		"a member of an unsupported type": `[{"op":"add","path":"members","value":[{"value":"` + f.group + `","type":"Group"}]}]`,
	} {
		if recorder := f.patch(t, group, operations, nil); recorder.Code != http.StatusBadRequest {
			t.Errorf("adding %s = %d, want 400", name, recorder.Code)
		}
	}
	created := f.request(t, http.MethodPost, "/scim/v2/Groups", nil, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Ghosts","members":[{"value":"no-such-user"}]}`)
	if created.Code != http.StatusBadRequest {
		t.Errorf("creating a Group with a member that is no User = %d, want 400", created.Code)
	}
	// displayName is REQUIRED (RFC 7643 Section 4.2).
	if recorder := f.request(t, http.MethodPut, group, nil, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"]}`); recorder.Code != http.StatusBadRequest {
		t.Errorf("PUT without displayName = %d, want 400", recorder.Code)
	}
}
