package scim

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const bulkURN = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"

// bulk sends a bulk request and decodes the response.
func (f *queryFixture) bulk(t *testing.T, body string) (int, []map[string]interface{}, map[string]interface{}) {
	t.Helper()
	recorder := f.request(t, http.MethodPost, "/scim/v2/Bulk", nil, body)
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("not JSON: %s", recorder.Body.String())
	}
	var operations []map[string]interface{}
	raw, _ := response["Operations"].([]interface{})
	for _, operation := range raw {
		operations = append(operations, operation.(map[string]interface{}))
	}
	return recorder.Code, operations, response
}

// RFC 7644 Section 3.7.2: "The service provider MUST replace the string
// "bulkId:qwerty" with the permanent resource id once created." The Group
// comes first here, so the reference is resolved out of order.
func TestBulkResolvesBulkIdReferences(t *testing.T) {
	f := newQueryFixture(t)
	status, operations, response := f.bulk(t, `{"schemas":["`+bulkURN+`"],"Operations":[
		{"method":"POST","path":"/Groups","bulkId":"g1","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Bulk Group","members":[{"type":"User","value":"bulkId:u1"}]}},
		{"method":"POST","path":"/Users","bulkId":"u1","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bulk.one@example.com"}},
		{"method":"PATCH","path":"/Users/bulkId:u1","data":{"schemas":["`+patchURN+`"],"Operations":[{"op":"add","path":"title","value":"From bulk"}]}}
	]}`)
	// "If a bulk job is processed successfully, HTTP response code 200 OK
	// MUST be returned".
	if status != http.StatusOK || len(operations) != 3 {
		t.Fatalf("status = %d, operations = %v", status, operations)
	}
	if schemas, _ := response["schemas"].([]interface{}); len(schemas) != 1 || schemas[0] != SchemaURNBulkResponse {
		t.Errorf("schemas = %v", response["schemas"])
	}
	group, user, patch := operations[0], operations[1], operations[2]
	// "The service provider MUST return the same "bulkId" together with the
	// newly created resource", and location is "REQUIRED in a response".
	if group["bulkId"] != "g1" || user["bulkId"] != "u1" || group["status"] != "201" || user["status"] != "201" || patch["status"] != "200" {
		t.Fatalf("operations = %v", operations)
	}
	userLocation, _ := user["location"].(string)
	userID := userLocation[strings.LastIndex(userLocation, "/")+1:]
	if !strings.HasPrefix(userLocation, testResource+"/Users/") || patch["location"] != userLocation || user["version"] != `W/"1"` || patch["version"] != `W/"2"` {
		t.Errorf("user %v, patch %v", user, patch)
	}
	members, _ := f.get(t, strings.TrimPrefix(group["location"].(string), testOrigin))["members"].([]interface{})
	if len(members) != 1 || members[0].(map[string]interface{})["value"] != userID {
		t.Errorf("the Group's members = %v, want the User the request created (%s)", members, userID)
	}
	if got := f.get(t, "/scim/v2/Users/"+userID); got["title"] != "From bulk" {
		t.Errorf("title = %v", got["title"])
	}
}

// "The service provider MUST continue performing as many changes as possible
// and disregard partial failures." status: "When indicating an error, the
// "response" attribute MUST contain the detail error response as per Section
// 3.12."
func TestBulkReportsEachFailure(t *testing.T) {
	f := newQueryFixture(t)
	status, operations, _ := f.bulk(t, `{"schemas":["`+bulkURN+`"],"Operations":[
		{"method":"POST","path":"/Users","bulkId":"dup","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Q.ALPHA@example.com"}},
		{"method":"DELETE","path":"/Users/no-such-id"},
		{"method":"POST","path":"/Users","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bulk.nobulkid@example.com"}},
		{"method":"GET","path":"/Users"},
		{"method":"POST","path":"/Bulk","bulkId":"nested","data":{}},
		{"method":"PUT","path":"/Users/`+f.charlie+`","version":"W/\"999\"","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"q.charlie@example.com"}},
		{"method":"POST","path":"/Groups","bulkId":"g","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Refers nowhere","members":[{"value":"bulkId:missing"}]}},
		{"method":"PATCH","path":"/Users/`+f.alpha+`","data":{"schemas":["`+patchURN+`"],"Operations":[{"op":"replace","path":"nickName","value":"bulk"}]}}
	]}`)
	if status != http.StatusOK || len(operations) != 8 {
		t.Fatalf("status = %d, %d operations: %v", status, len(operations), operations)
	}
	want := []struct {
		status, scimType string
		location         bool
	}{
		{"409", "uniqueness", false},    // a POST that failed has no location
		{"404", "", true},               // location is "REQUIRED in a response, except in the event of a POST failure"
		{"400", "invalidValue", false},  // bulkId is "REQUIRED when "method" is "POST""
		{"400", "invalidSyntax", true},  // method is POST, PUT, PATCH or DELETE; it is no POST, so location is given
		{"400", "invalidSyntax", false}, // path names a resource endpoint
		{"412", "", true},               // version is sent as If-Match
		{"400", "invalidValue", false},  // a bulkId no operation defines
		{"200", "", true},
	}
	for i, expected := range want {
		operation := operations[i]
		response, _ := operation["response"].(map[string]interface{})
		_, hasLocation := operation["location"]
		if operation["status"] != expected.status || hasLocation != expected.location {
			t.Errorf("operation %d = %v, want status %s, location %v", i, operation, expected.status, expected.location)
		}
		if failed := !strings.HasPrefix(expected.status, "2"); failed {
			scimType, _ := response["scimType"].(string)
			if response["status"] != expected.status || scimType != expected.scimType || response["detail"] == nil {
				t.Errorf("operation %d error response = %v, want status %s scimType %q", i, response, expected.status, expected.scimType)
			}
		}
	}
	if got := f.get(t, "/scim/v2/Users/"+f.alpha); got["nickName"] != "bulk" {
		t.Errorf("the operation after the failures was not performed: nickName = %v", got["nickName"])
	}
}

// failOnErrors: "An integer specifying the number of errors that the service
// provider will accept before the operation is terminated and an error
// response is returned."
func TestBulkStopsAtFailOnErrors(t *testing.T) {
	f := newQueryFixture(t)
	status, operations, _ := f.bulk(t, `{"schemas":["`+bulkURN+`"],"failOnErrors":2,"Operations":[
		{"method":"DELETE","path":"/Users/x1"},{"method":"DELETE","path":"/Users/x2"},{"method":"DELETE","path":"/Users/`+f.charlie+`"}]}`)
	if status != http.StatusOK || len(operations) != 2 {
		t.Fatalf("status = %d, %d operations processed, want 2", status, len(operations))
	}
	if recorder := f.request(t, http.MethodGet, "/scim/v2/Users/"+f.charlie, nil, ""); recorder.Code != http.StatusOK {
		t.Errorf("an operation after the limit was performed: GET = %d", recorder.Code)
	}
}

// "If either limit is exceeded, the service provider MUST return HTTP
// response code 413 (Payload Too Large). The returned response MUST specify
// the limit exceeded in the body of the error response."
func TestBulkLimits(t *testing.T) {
	f := newQueryFixture(t)
	operations := strings.TrimSuffix(strings.Repeat(`{"method":"DELETE","path":"/Users/x"},`, bulkMaxOperations+1), ",")
	for name, testCase := range map[string]struct{ body, limit string }{
		"too many operations": {`{"schemas":["` + bulkURN + `"],"Operations":[` + operations + `]}`, "maxOperations (1000)"},
		"too large a payload": {`{"schemas":["` + bulkURN + `"],"Operations":[{"method":"POST","path":"/Users","bulkId":"b","data":{"title":"` + strings.Repeat("x", bulkMaxPayloadSize) + `"}}]}`, "maxPayloadSize (1048576)"},
	} {
		recorder := f.request(t, http.MethodPost, "/scim/v2/Bulk", nil, testCase.body)
		body := scimErrorBody(t, recorder)
		detail, _ := body["detail"].(string)
		if recorder.Code != http.StatusRequestEntityTooLarge || body["status"] != "413" || !strings.Contains(detail, testCase.limit) {
			t.Errorf("%s = %d %v, want 413 naming %s", name, recorder.Code, body, testCase.limit)
		}
	}
	for name, body := range map[string]string{
		"no schemas":    `{"Operations":[{"method":"DELETE","path":"/Users/x"}]}`,
		"no Operations": `{"schemas":["` + bulkURN + `"]}`,
	} {
		if recorder := f.request(t, http.MethodPost, "/scim/v2/Bulk", nil, body); recorder.Code != http.StatusBadRequest {
			t.Errorf("a bulk request with %s = %d, want 400", name, recorder.Code)
		}
	}
}
