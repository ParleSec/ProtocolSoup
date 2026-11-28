package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const (
	enterpriseURN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	searchURN     = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
)

// queryFixture is three Users and a Group to query. The demo users the store
// seeds are there too, so every filter below also names the fixture.
type queryFixture struct {
	*authTestServer
	alpha, bravo, charlie string // ids
	group                 string
}

func newQueryFixture(t *testing.T) *queryFixture {
	t.Helper()
	f := &queryFixture{authTestServer: newAuthTestServer(t)}
	create := func(body string) string {
		recorder, resource := f.createUser(t, body)
		if recorder.Code != http.StatusCreated {
			t.Fatalf("create: %d %s", recorder.Code, recorder.Body.String())
		}
		return resource["id"].(string)
	}
	f.alpha = create(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","` + enterpriseURN + `"],"userName":"q.alpha@example.com",
		"name":{"givenName":"Zed","familyName":"Alpha"},"displayName":"Alpha","title":"Engineer","active":true,
		"emails":[{"value":"alpha@work.example.com","type":"work","primary":true},{"value":"alpha@home.example.com","type":"home"}],
		"` + enterpriseURN + `":{"department":"Security","employeeNumber":"701"}}`)
	f.bravo = create(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Q.Bravo@example.com",
		"name":{"givenName":"amy","familyName":"Bravo"},"displayName":"bravo","active":false,
		"emails":[{"value":"bravo@work.example.com","type":"work"}]}`)
	f.charlie = create(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"q.charlie@example.com","displayName":"Charlie"}`)
	recorder := f.request(t, http.MethodPost, "/scim/v2/Groups", nil,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Query Group","members":[{"value":"`+f.alpha+`"}]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create group: %d %s", recorder.Code, recorder.Body.String())
	}
	var group map[string]interface{}
	_ = json.Unmarshal(recorder.Body.Bytes(), &group)
	f.group = group["id"].(string)
	return f
}

// listed decodes a list response into the userName or displayName of each
// resource, in the order returned.
func listed(t *testing.T, recorder *httptest.ResponseRecorder) ([]string, map[string]interface{}) {
	t.Helper()
	var list map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &list); err != nil {
		t.Fatalf("not JSON: %s", recorder.Body.String())
	}
	names := []string{}
	resources, _ := list["Resources"].([]interface{})
	for _, raw := range resources {
		resource := raw.(map[string]interface{})
		if name, ok := resource["userName"].(string); ok {
			names = append(names, name)
		} else {
			names = append(names, resource["displayName"].(string))
		}
	}
	return names, list
}

func (f *queryFixture) filter(t *testing.T, expression, extra string) *httptest.ResponseRecorder {
	t.Helper()
	return f.request(t, http.MethodGet, "/scim/v2/Users?filter="+url.QueryEscape(expression)+extra, nil, "")
}

const mine = `userName sw "q." and `

// RFC 7644 Section 3.4.2.2, Tables 3 to 5 and the rules that follow them.
func TestFilterOperators(t *testing.T) {
	f := newQueryFixture(t)
	alpha, bravo, charlie := "q.alpha@example.com", "Q.Bravo@example.com", "q.charlie@example.com"
	cases := []struct {
		name, filter string
		want         []string
	}{
		// "When comparing attributes of type String, the case sensitivity for
		// String type attributes SHALL be determined by the attribute's
		// "caseExact" characteristic".
		{"eq is case insensitive for userName", `userName eq "Q.ALPHA@EXAMPLE.COM"`, []string{alpha}},
		// RFC 7644 Section 5: userName is compared with the PRECIS rules, which
		// map fullwidth characters to their ordinary form.
		{"eq on userName uses PRECIS", `userName eq "ｑ.ａｌｐｈａ@example.com"`, []string{alpha}},
		{"eq is case exact for id", `id eq "` + strings.ToUpper(f.alpha) + `"`, nil},
		{"eq on id", `id eq "` + f.alpha + `"`, []string{alpha}},
		// "Attribute names and attribute operators used in filters are case
		// insensitive."
		{"attribute name in another case", `USERNAME eq "q.alpha@example.com"`, []string{alpha}},
		{"operator in another case", `userName Eq "q.alpha@example.com"`, []string{alpha}},
		{"ne", mine + `userName ne "q.alpha@example.com"`, []string{bravo, charlie}},
		{"co", `userName co "q.char"`, []string{charlie}},
		{"sw", `userName sw "q."`, []string{alpha, bravo, charlie}},
		{"ew", mine + `userName ew "bravo@example.com"`, []string{bravo}},
		{"pr", mine + `title pr`, []string{alpha}},
		{"pr on a sub-attribute", mine + `name.givenName pr`, []string{alpha, bravo}},
		{"pr on a complex attribute", mine + `name pr`, []string{alpha, bravo}},
		{"sub-attribute", `name.familyName eq "alpha"`, []string{alpha}},
		{"boolean", mine + `active eq false`, []string{bravo}},
		// "if any of the values of the specified attribute match the specified
		// criterion".
		{"multi-valued sub-attribute", `emails.value co "@home.example"`, []string{alpha}},
		{"multi-valued attribute by its value", `emails co "bravo@work"`, []string{bravo}},
		{"multi-valued type", mine + `emails.type eq "home"`, []string{alpha}},
		// "expressions MUST be applied to the same value of a parent
		// attribute".
		{"value filter on one value", `emails[type eq "work" and value co "alpha@"]`, []string{alpha}},
		{"value filter across two values", `emails[type eq "home" and value co "alpha@work"]`, nil},
		// "not" takes precedence over "and", which takes precedence over "or".
		{"and binds tighter than or", `userName eq "q.alpha@example.com" or userName eq "q.charlie@example.com" and displayName eq "Charlie"`, []string{alpha, charlie}},
		{"grouping", `(userName eq "q.alpha@example.com" or userName eq "q.charlie@example.com") and displayName eq "Charlie"`, []string{charlie}},
		{"not", mine + `not (displayName eq "charlie")`, []string{alpha, bravo}},
		{"schema URI on a core attribute", `urn:ietf:params:scim:schemas:core:2.0:User:userName eq "q.alpha@example.com"`, []string{alpha}},
		{"schema URI and a sub-attribute", `urn:ietf:params:scim:schemas:core:2.0:User:name.familyName eq "Bravo"`, []string{bravo}},
		{"extension attribute", mine + enterpriseURN + `:department eq "security"`, []string{alpha}},
		{"extension attribute without its URI", mine + `employeeNumber eq "701"`, []string{alpha}},
		{"meta.resourceType", mine + `meta.resourceType eq "User"`, []string{alpha, bravo, charlie}},
		// "for DateTime types, it is a chronological comparison."
		{"dateTime gt", mine + `meta.lastModified gt "2020-01-01T00:00:00Z"`, []string{alpha, bravo, charlie}},
		{"dateTime gt with an offset", mine + `meta.lastModified gt "2020-01-01T10:00:00+10:00"`, []string{alpha, bravo, charlie}},
		{"dateTime lt", mine + `meta.lastModified lt "2020-01-01T00:00:00Z"`, nil},
		// "For string attribute types, this is a lexicographical comparison".
		{"string gt", mine + `userName gt "q.b"`, []string{bravo, charlie}},
		{"string le", mine + `displayName le "alpha"`, []string{alpha}},
		// An undefined attribute has no value: "a presence or equality filter
		// for an undefined attribute evaluates to false".
		{"undefined attribute eq", `shoeSize eq "9"`, nil},
		{"undefined attribute pr", `shoeSize pr`, nil},
		{"null for no value", mine + `title eq null`, []string{bravo, charlie}},
		{"derived groups attribute", `groups.display eq "query group"`, []string{alpha}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := f.filter(t, testCase.filter, "")
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
			}
			got, list := listed(t, recorder)
			sort.Strings(got)
			want := append([]string{}, testCase.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("matched %v, want %v", got, want)
			}
			// "A query that does not return any matches SHALL return success
			// (HTTP status code 200) with "totalResults" set to a value of 0."
			if list["totalResults"] != float64(len(want)) {
				t.Errorf("totalResults = %v, want %d", list["totalResults"], len(want))
			}
			if schemas, _ := list["schemas"].([]interface{}); len(schemas) != 1 || schemas[0] != SchemaURNListResponse {
				t.Errorf("schemas = %v", list["schemas"])
			}
		})
	}
}

// "Providers MUST decline to filter results if the specified filter operation
// is not recognized and return an HTTP 400 error with a "scimType" error of
// "invalidFilter"". Table 3: for gt, ge, lt and le, "Boolean and Binary
// attributes SHALL cause a failed response (HTTP status code 400) with
// "scimType" of "invalidFilter"."
func TestInvalidFiltersAreRefused(t *testing.T) {
	f := newQueryFixture(t)
	for name, filter := range map[string]string{
		"an unknown operator":                  `userName regex "a.*"`,
		"gt on a boolean":                      `active gt true`,
		"le on a boolean":                      `active le false`,
		"a string that is not closed":          `userName eq "abc`,
		"an empty filter":                      ``,
		"no value":                             `userName eq`,
		"no operator":                          `userName`,
		"an unbalanced bracket":                `(userName eq "a"`,
		"not without brackets":                 `not userName eq "a"`,
		"a value that is not JSON":             `userName eq abc`,
		"a boolean compared with a string":     `active eq "true"`,
		"a string compared with a number":      `userName eq 5`,
		"a dateTime that is not one":           `meta.created gt "yesterday"`,
		"a complex attribute compared":         `name eq "Alpha"`,
		"a value filter on a simple attribute": `userName[value eq "a"]`,
		"an attribute name that is not one":    `user name eq "a"`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder := f.filter(t, filter, "")
			body := scimErrorBody(t, recorder)
			if recorder.Code != http.StatusBadRequest || body["scimType"] != "invalidFilter" || body["status"] != "400" {
				t.Errorf("status = %d, body = %v; want 400 invalidFilter", recorder.Code, body)
			}
		})
	}
}

// RFC 7644 Section 3.4.2.3.
func TestSorting(t *testing.T) {
	f := newQueryFixture(t)
	alpha, bravo, charlie := "q.alpha@example.com", "Q.Bravo@example.com", "q.charlie@example.com"
	cases := []struct {
		name, parameters string
		want             []string
	}{
		// 'If a value for "sortBy" is provided and no "sortOrder" is
		// specified, "sortOrder" SHALL default to ascending.' userName is case
		// insensitive, so "Q.Bravo" sorts between the other two.
		{"ascending by default", "&sortBy=userName", []string{alpha, bravo, charlie}},
		{"descending", "&sortBy=userName&sortOrder=descending", []string{charlie, bravo, alpha}},
		{"case insensitive", "&sortBy=displayName", []string{alpha, bravo, charlie}},
		// "they are ordered last if ascending and first if descending."
		{"no data last when ascending", "&sortBy=name.givenName", []string{bravo, alpha, charlie}},
		{"no data first when descending", "&sortBy=name.givenName&sortOrder=descending", []string{charlie, alpha, bravo}},
		// "resources are sorted by the value of the primary attribute (see
		// Section 2.4 of [RFC7643]), if any, or else the first value in the
		// list, if any."
		{"multi-valued by its primary value", "&sortBy=emails", []string{alpha, bravo, charlie}},
		{"dateTime", "&sortBy=meta.created&sortOrder=descending", []string{charlie, bravo, alpha}},
		{"an attribute no resource has", "&sortBy=nickName", []string{alpha, bravo, charlie}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := f.filter(t, `userName sw "q."`, testCase.parameters)
			got, _ := listed(t, recorder)
			if recorder.Code != http.StatusOK || !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("status %d, order %v, want %v", recorder.Code, got, testCase.want)
			}
		})
	}
	// 'Allowed values are "ascending" and "descending".'
	if recorder := f.filter(t, `userName sw "q."`, "&sortBy=userName&sortOrder=sideways"); recorder.Code != http.StatusBadRequest {
		t.Errorf("sortOrder=sideways = %d, want 400", recorder.Code)
	}
}

// RFC 7644 Section 3.4.2.4, Table 6.
func TestPagination(t *testing.T) {
	f := newQueryFixture(t)
	base := `userName sw "q."`
	cases := []struct {
		name, parameters    string
		want                []string
		startIndex, perPage float64
	}{
		{"a page", "&sortBy=userName&startIndex=2&count=1", []string{"Q.Bravo@example.com"}, 2, 1},
		// startIndex: "A value less than 1 SHALL be interpreted as 1."
		{"startIndex 0", "&sortBy=userName&startIndex=0&count=1", []string{"q.alpha@example.com"}, 1, 1},
		{"startIndex negative", "&sortBy=userName&startIndex=-5&count=1", []string{"q.alpha@example.com"}, 1, 1},
		// count: 'A value of "0" indicates that no resource results are to be
		// returned except for "totalResults".'
		{"count 0", "&count=0", []string{}, 1, 0},
		// 'A negative value SHALL be interpreted as "0".'
		{"count negative", "&count=-3", []string{}, 1, 0},
		{"startIndex past the end", "&startIndex=50", []string{}, 50, 0},
		// "SHOULD ignore any query parameters they do not recognize".
		{"an unknown parameter", "&sortBy=userName&count=1&frobnicate=1", []string{"q.alpha@example.com"}, 1, 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := f.filter(t, base, testCase.parameters)
			got, list := listed(t, recorder)
			if recorder.Code != http.StatusOK || !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("status %d, resources %v, want %v", recorder.Code, got, testCase.want)
			}
			if list["totalResults"] != float64(3) || list["startIndex"] != testCase.startIndex || list["itemsPerPage"] != testCase.perPage {
				t.Errorf("totalResults %v startIndex %v itemsPerPage %v", list["totalResults"], list["startIndex"], list["itemsPerPage"])
			}
			if _, present := list["Resources"]; !present {
				t.Error("Resources is absent")
			}
		})
	}
	if recorder := f.filter(t, base, "&count=abc"); recorder.Code != http.StatusBadRequest {
		t.Errorf("count=abc = %d, want 400", recorder.Code)
	}
}

// RFC 7644 Section 3.9: the two parameters "MUST be supported by SCIM service
// providers" (Section 3.4.2.5).
func TestAttributesToReturn(t *testing.T) {
	f := newQueryFixture(t)
	keysOf := func(recorder *httptest.ResponseRecorder) (map[string]interface{}, []string) {
		var resource map[string]interface{}
		if err := json.Unmarshal(recorder.Body.Bytes(), &resource); err != nil {
			t.Fatalf("not JSON: %s", recorder.Body.String())
		}
		if resources, isList := resource["Resources"].([]interface{}); isList {
			resource = resources[0].(map[string]interface{})
		}
		keys := []string{}
		for key := range resource {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return resource, keys
	}
	user := "/scim/v2/Users/" + f.alpha

	// attributes: "the minimum set of resource attributes and any attributes
	// or sub-attributes explicitly requested". The minimum set is what is
	// returned "always": id, and the schemas of the representation.
	_, keys := keysOf(f.request(t, http.MethodGet, user+"?attributes=userName", nil, ""))
	if !reflect.DeepEqual(keys, []string{"id", "schemas", "userName"}) {
		t.Errorf("attributes=userName returned %v", keys)
	}
	resource, keys := keysOf(f.request(t, http.MethodGet, user+"?attributes=name.givenName,emails.value,"+enterpriseURN+":department", nil, ""))
	if !reflect.DeepEqual(keys, []string{"emails", "id", "name", "schemas", enterpriseURN}) ||
		!reflect.DeepEqual(resource["name"], map[string]interface{}{"givenName": "Zed"}) ||
		!reflect.DeepEqual(resource[enterpriseURN], map[string]interface{}{"department": "Security"}) ||
		!reflect.DeepEqual(resource["emails"].([]interface{})[0], map[string]interface{}{"value": "alpha@work.example.com"}) {
		t.Errorf("sub-attribute selection returned %v", resource)
	}
	// excludedAttributes "SHALL have no effect on attributes whose schema
	// "returned" setting is "always"".
	resource, _ = keysOf(f.request(t, http.MethodGet, user+"?excludedAttributes=emails,id,meta,name.familyName", nil, ""))
	if _, present := resource["emails"]; present || resource["id"] == nil || resource["meta"] != nil || resource["userName"] == nil ||
		!reflect.DeepEqual(resource["name"], map[string]interface{}{"givenName": "Zed"}) {
		t.Errorf("excludedAttributes returned %v", resource)
	}
	// A list, a POST query, and the responses of POST, PUT and PATCH take them
	// too.
	_, keys = keysOf(f.filter(t, `userName eq "q.alpha@example.com"`, "&attributes=displayName"))
	if !reflect.DeepEqual(keys, []string{"displayName", "id", "schemas"}) {
		t.Errorf("list attributes=displayName returned %v", keys)
	}
	_, keys = keysOf(f.request(t, http.MethodPost, "/scim/v2/Users/.search", nil,
		`{"schemas":["`+searchURN+`"],"filter":"userName eq \"q.alpha@example.com\"","attributes":["title"]}`))
	if !reflect.DeepEqual(keys, []string{"id", "schemas", "title"}) {
		t.Errorf("search attributes returned %v", keys)
	}
	_, keys = keysOf(f.request(t, http.MethodPatch, user+"?attributes=title", nil,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"title","value":"Lead"}]}`))
	if !reflect.DeepEqual(keys, []string{"id", "schemas", "title"}) {
		t.Errorf("PATCH attributes=title returned %v", keys)
	}
	// "either of the mutually exclusive URL query parameters".
	if recorder := f.request(t, http.MethodGet, user+"?attributes=userName&excludedAttributes=emails", nil, ""); recorder.Code != http.StatusBadRequest {
		t.Errorf("both parameters = %d, want 400", recorder.Code)
	}
}

// RFC 7644 Section 3.4.3, and Section 3.4.2.1 for the Base URI.
func TestQueryEndpoints(t *testing.T) {
	f := newQueryFixture(t)
	search := func(path, body string) ([]string, int) {
		recorder := f.request(t, http.MethodPost, path, nil, body)
		if recorder.Code != http.StatusOK {
			return nil, recorder.Code
		}
		names, _ := listed(t, recorder)
		sort.Strings(names)
		return names, recorder.Code
	}
	request := `{"schemas":["` + searchURN + `"],"filter":"displayName sw \"Query\" or userName sw \"q.char\""}`

	// "A query against a server root indicates that all resources within the
	// server SHALL be included, subject to filtering."
	for _, path := range []string{"/scim/v2/.search"} {
		if names, status := search(path, request); !reflect.DeepEqual(names, []string{"Query Group", "q.charlie@example.com"}) {
			t.Errorf("POST %s = %d %v, want the Group and the User", path, status, names)
		}
	}
	recorder := f.request(t, http.MethodGet, "/scim/v2/?filter="+url.QueryEscape(`meta.resourceType eq "Group" and displayName eq "query group"`), nil, "")
	if names, _ := listed(t, recorder); recorder.Code != http.StatusOK || !reflect.DeepEqual(names, []string{"Query Group"}) {
		t.Errorf("GET of the Base URI = %d %v", recorder.Code, names)
	}
	if names, status := search("/scim/v2/Users/.search", request); !reflect.DeepEqual(names, []string{"q.charlie@example.com"}) {
		t.Errorf("POST /Users/.search = %d %v", status, names)
	}
	if names, status := search("/scim/v2/Groups/.search", request); !reflect.DeepEqual(names, []string{"Query Group"}) {
		t.Errorf("POST /Groups/.search = %d %v", status, names)
	}
	if names, _ := listed(t, f.request(t, http.MethodGet, "/scim/v2/Groups?filter="+url.QueryEscape(`members.value eq "`+f.alpha+`"`), nil, "")); !reflect.DeepEqual(names, []string{"Query Group"}) {
		t.Errorf("Groups by member = %v", names)
	}

	// "Query requests MUST be identified using the following URI".
	for name, body := range map[string]string{
		"no schemas":     `{"filter":"userName pr"}`,
		"another schema": `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"filter":"userName pr"}`,
		"a bad filter":   `{"schemas":["` + searchURN + `"],"filter":"userName regex 1"}`,
	} {
		if _, status := search("/scim/v2/.search", body); status != http.StatusBadRequest {
			t.Errorf("search with %s = %d, want 400", name, status)
		}
	}
}

// RFC 7644 Section 3.12: errors are returned "in the body of the response in
// a JSON format"; Section 3.11 gives 501 for an unsupported "/Me".
func TestUnknownEndpointsAnswerWithSCIMErrors(t *testing.T) {
	f := newQueryFixture(t)
	for path, want := range map[string]int{"/scim/v2/Widgets": http.StatusNotFound, "/scim/v2/Me": http.StatusNotImplemented} {
		recorder := f.request(t, http.MethodGet, path, nil, "")
		if body := scimErrorBody(t, recorder); recorder.Code != want || body["status"] != strconv.Itoa(want) {
			t.Errorf("GET %s = %d %v, want %d", path, recorder.Code, body, want)
		}
	}
	recorder := f.request(t, http.MethodPost, "/scim/v2/Users/"+f.alpha, nil, `{}`)
	if body := scimErrorBody(t, recorder); recorder.Code != http.StatusMethodNotAllowed || body["status"] != "405" {
		t.Errorf("POST to a resource = %d %v, want a 405 SCIM error", recorder.Code, body)
	}
}
