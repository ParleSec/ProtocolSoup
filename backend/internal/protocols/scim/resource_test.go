package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
)

// request sends one SCIM request with a token that grants both scopes.
func (s *authTestServer) request(t *testing.T, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	token := s.accessToken(t, func(token *crypto.AccessToken) { token.Scope = ScopeRead + " " + ScopeWrite })
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		request.Header.Set("Content-Type", ContentTypeSCIM)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, request)
	return recorder
}

// createUser creates a User and returns the response and its decoded body.
func (s *authTestServer) createUser(t *testing.T, body string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	recorder := s.request(t, http.MethodPost, "/scim/v2/Users", nil, body)
	var resource map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resource); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, recorder.Body.String())
	}
	return recorder, resource
}

const testUser = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Resource.Test@example.com","externalId":"ext-1","name":{"givenName":"Resource","familyName":"Test"}}`

// RFC 7644 Section 3.3: "an HTTP response SHALL be returned with HTTP status
// code 201 (Created)" and "The URI of the created resource SHALL include, in
// the HTTP "Location" header and the HTTP body, a JSON representation
// [RFC7159] with the attribute "meta.location"." RFC 7643 Section 3.1 ties
// meta.location to Content-Location and meta.version to ETag.
func TestCreatedUserIsDescribedByItsHeaders(t *testing.T) {
	server := newAuthTestServer(t)
	recorder, user := server.createUser(t, testUser)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", recorder.Code, recorder.Body.String())
	}
	meta, _ := user["meta"].(map[string]interface{})
	id, _ := user["id"].(string)
	location, _ := meta["location"].(string)
	if id == "" || location != testResource+"/Users/"+id {
		t.Fatalf("id = %q, meta.location = %q", id, location)
	}
	for _, name := range []string{"Location", "Content-Location"} {
		if got := recorder.Header().Get(name); got != location {
			t.Errorf("%s = %q, want meta.location %q", name, got, location)
		}
	}
	if got := recorder.Header().Get("ETag"); got == "" || got != meta["version"] {
		t.Errorf("ETag = %q, meta.version = %v", got, meta["version"])
	}
	if !strings.HasPrefix(recorder.Header().Get("ETag"), `W/"`) {
		t.Errorf("ETag %q is not marked weak", recorder.Header().Get("ETag"))
	}
	// "If this resource has never been modified since its initial creation,
	// the value MUST be the same as the value of "created"."
	if meta["created"] == nil || meta["created"] != meta["lastModified"] {
		t.Errorf("created = %v, lastModified = %v", meta["created"], meta["lastModified"])
	}
	if meta["resourceType"] != "User" {
		t.Errorf("meta.resourceType = %v", meta["resourceType"])
	}

	// RFC 7644 Section 3.4.1: the resource is retrievable at its location,
	// and the representation is the one the creation returned.
	fetched := server.request(t, http.MethodGet, strings.TrimPrefix(location, testOrigin), nil, "")
	if fetched.Code != http.StatusOK || fetched.Header().Get("Content-Location") != location {
		t.Fatalf("GET meta.location = %d, Content-Location %q", fetched.Code, fetched.Header().Get("Content-Location"))
	}
	if fetched.Body.String() != recorder.Body.String() {
		t.Errorf("retrieved representation differs from the created one:\n%s\n%s", fetched.Body.String(), recorder.Body.String())
	}
}

// RFC 7644 Section 3.3: "In the request body, attributes whose mutability is
// "readOnly" (see Sections 2.2 and 7 of [RFC7643]) SHALL be ignored." RFC 7643
// Section 3.1: "id" is "always issued by the service provider and MUST NOT be
// specified by the client".
func TestClientCannotSetReadOnlyAttributes(t *testing.T) {
	server := newAuthTestServer(t)
	recorder, user := server.createUser(t, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"readonly.test@example.com",
		"id":"client-chosen-id","password":"t1meMa$heen",
		"meta":{"resourceType":"Group","created":"1999-01-01T00:00:00Z","location":"https://elsewhere.example/x","version":"W/\"client\""},
		"groups":[{"value":"g1","display":"Admins"}]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	meta, _ := user["meta"].(map[string]interface{})
	if user["id"] == "client-chosen-id" || user["id"] == "" {
		t.Errorf("id = %v, want one the service provider issued", user["id"])
	}
	if meta["resourceType"] != "User" || meta["version"] != `W/"1"` || !strings.HasPrefix(meta["location"].(string), testResource) {
		t.Errorf("meta = %v, want the service provider's values", meta)
	}
	if _, present := user["groups"]; present {
		t.Errorf("groups = %v, want none: the client cannot assert membership on the User", user["groups"])
	}
	// RFC 7643 Section 7: "password" has "returned" of "never".
	if strings.Contains(recorder.Body.String(), "password") {
		t.Errorf("the response carries the password attribute: %s", recorder.Body.String())
	}
}

// RFC 7643 Section 4.1.1: userName "MUST be unique across the service
// provider's entire set of Users. This attribute is REQUIRED and is case
// insensitive." RFC 7644 Section 3.3 gives 409 with scimType "uniqueness".
func TestUserNameIsUniqueWithoutRegardToCase(t *testing.T) {
	server := newAuthTestServer(t)
	if recorder, _ := server.createUser(t, testUser); recorder.Code != http.StatusCreated {
		t.Fatalf("first create = %d", recorder.Code)
	}
	recorder, body := server.createUser(t, strings.Replace(testUser, "Resource.Test@example.com", "resource.test@EXAMPLE.com", 1))
	if recorder.Code != http.StatusConflict || body["scimType"] != "uniqueness" || body["status"] != "409" {
		t.Errorf("a userName that differs in case only = %d %v, want 409 uniqueness", recorder.Code, body)
	}

	// A name the PRECIS UsernameCaseMapped profile refuses cannot be compared.
	recorder, body = server.createUser(t, strings.Replace(testUser, "Resource.Test@example.com", "resource test", 1))
	if recorder.Code != http.StatusBadRequest || body["scimType"] != "invalidValue" {
		t.Errorf("a userName with a space = %d %v, want 400 invalidValue", recorder.Code, body)
	}
}

// RFC 7643 Section 3 on "schemas": REQUIRED, only the resource type's schema
// and schema extensions, no duplicates.
func TestSchemasAttributeIsChecked(t *testing.T) {
	server := newAuthTestServer(t)
	cases := map[string]struct{ body, scimType string }{
		"no schemas":                                     {`{"userName":"s1@example.com"}`, "invalidValue"},
		"another resource type's schema":                 {`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"userName":"s2@example.com"}`, "invalidSyntax"},
		"a repeated value":                               {`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"s3@example.com"}`, "invalidSyntax"},
		"the extension without the core":                 {`{"schemas":["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"s4@example.com"}`, "invalidSyntax"},
		"extension attributes the schemas does not name": {`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"s5@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Security"}}`, "invalidSyntax"},
		"no userName":                                    {`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}`, "invalidValue"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			recorder, body := server.createUser(t, testCase.body)
			if recorder.Code != http.StatusBadRequest || body["scimType"] != testCase.scimType || body["status"] != "400" {
				t.Errorf("status = %d, body = %v; want 400 %s", recorder.Code, body, testCase.scimType)
			}
		})
	}

	recorder, user := server.createUser(t, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"userName":"s6@example.com","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"department":"Security"}}`)
	if recorder.Code != http.StatusCreated || len(user["schemas"].([]interface{})) != 2 {
		t.Errorf("a User with the enterprise extension = %d %v", recorder.Code, user["schemas"])
	}
}

// RFC 7644 Section 3.14: "If the resource has not changed, the service
// provider simply returns an empty body with a 304 (Not Modified) response
// code."
func TestConditionalRetrieval(t *testing.T) {
	server := newAuthTestServer(t)
	created, user := server.createUser(t, testUser)
	path := "/scim/v2/Users/" + user["id"].(string)
	etag := created.Header().Get("ETag")

	for name, header := range map[string]string{"the current entity-tag": etag, "its opaque value, strong": strings.TrimPrefix(etag, "W/"), "a list that holds it": `W/"0", ` + etag} {
		recorder := server.request(t, http.MethodGet, path, map[string]string{"If-None-Match": header}, "")
		if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 || recorder.Header().Get("ETag") != etag {
			t.Errorf("If-None-Match with %s = %d, %d body bytes, ETag %q; want 304 and no body", name, recorder.Code, recorder.Body.Len(), recorder.Header().Get("ETag"))
		}
	}
	if recorder := server.request(t, http.MethodGet, path, map[string]string{"If-None-Match": `W/"0"`}, ""); recorder.Code != http.StatusOK {
		t.Errorf("If-None-Match with another entity-tag = %d, want 200", recorder.Code)
	}
}

// RFC 7644 Section 3.8: 'Service providers MUST support the "Accept" header
// "Accept: application/scim+json" and SHOULD support the header "Accept:
// application/json"'. 'The format defaults to "application/scim+json" if no
// format is specified.'
func TestResponseMediaTypeFollowsAccept(t *testing.T) {
	server := newAuthTestServer(t)
	for accept, want := range map[string]string{
		"":                                ContentTypeSCIM,
		"application/scim+json":           ContentTypeSCIM,
		"*/*":                             ContentTypeSCIM,
		"application/json":                "application/json",
		"application/json; charset=utf-8": "application/json",
		"application/json, application/scim+json;q=0.9": ContentTypeSCIM,
	} {
		headers := map[string]string{}
		if accept != "" {
			headers["Accept"] = accept
		}
		recorder := server.request(t, http.MethodGet, "/scim/v2/Users", headers, "")
		if got := recorder.Header().Get("Content-Type"); recorder.Code != http.StatusOK || got != want {
			t.Errorf("Accept %q: status %d, Content-Type %q, want %q", accept, recorder.Code, got, want)
		}
	}
	// An error response is labelled the same way.
	recorder := server.request(t, http.MethodGet, "/scim/v2/Users/unknown", map[string]string{"Accept": "application/json"}, "")
	if recorder.Code != http.StatusNotFound || recorder.Header().Get("Content-Type") != "application/json" {
		t.Errorf("404 with Accept: application/json has Content-Type %q", recorder.Header().Get("Content-Type"))
	}
}

// meta.created is "The "DateTime" that the resource was added to the service
// provider" (RFC 7643 Section 3.1): replacing the resource does not move it.
func TestReplacingAUserKeepsItsIdentityAndCreationTime(t *testing.T) {
	server := newAuthTestServer(t)
	_, user := server.createUser(t, testUser)
	id := user["id"].(string)
	created := user["meta"].(map[string]interface{})["created"]

	replaced := server.request(t, http.MethodPut, "/scim/v2/Users/"+id, nil,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"another-id","userName":"resource.test@example.com","displayName":"Replaced","groups":[{"value":"g1"}]}`)
	if replaced.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", replaced.Code, replaced.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(replaced.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	meta := body["meta"].(map[string]interface{})
	if body["id"] != id || meta["created"] != created || meta["version"] != `W/"2"` {
		t.Errorf("after PUT: id %v, created %v (was %v), version %v", body["id"], meta["created"], created, meta["version"])
	}
	if _, present := body["groups"]; present {
		t.Errorf("PUT set groups: %v", body["groups"])
	}
	if replaced.Header().Get("Content-Location") != meta["location"] || replaced.Header().Get("ETag") != meta["version"] {
		t.Errorf("PUT headers: Content-Location %q, ETag %q", replaced.Header().Get("Content-Location"), replaced.Header().Get("ETag"))
	}

	// RFC 7644 Section 3.5.1: 'If an attribute is "required", clients MUST
	// specify the attribute in the PUT request.'
	missing := server.request(t, http.MethodPut, "/scim/v2/Users/"+id, nil, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"displayName":"No userName"}`)
	if missing.Code != http.StatusBadRequest {
		t.Errorf("PUT without userName = %d, want 400", missing.Code)
	}
}

func TestServiceProviderConfigDoesNotClaimPasswordChange(t *testing.T) {
	if GetServiceProviderConfig(testOrigin).ChangePassword.Supported {
		t.Error("changePassword.supported is true, and the password attribute is dropped on input")
	}
}

// RFC 7643 Section 4.1.2 on emails: "Service providers SHOULD canonicalize the
// value according to [RFC5321], e.g., "bjensen@example.com" instead of
// "bjensen@EXAMPLE.COM"."
func TestEmailDomainIsCanonicalized(t *testing.T) {
	server := newAuthTestServer(t)
	recorder, user := server.createUser(t, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"email.test@example.com","emails":[{"value":"BJensen@EXAMPLE.COM","type":"work"}]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	email := user["emails"].([]interface{})[0].(map[string]interface{})
	if email["value"] != "BJensen@example.com" {
		t.Errorf("email value = %v, want the domain in lower case and the local part as sent", email["value"])
	}
}
