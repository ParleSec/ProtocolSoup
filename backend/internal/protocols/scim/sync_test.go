package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/plugin"
)

func TestHandleClientSyncCreatesThenUpdatesRemoteUsers(t *testing.T) {
	storage, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	defer storage.Close()

	for _, userName := range []string{"alice@example.com", "bob@example.com"} {
		user := NewUser()
		user.UserName = userName
		if _, err := storage.CreateUser(context.Background(), user); err != nil {
			t.Fatalf("create local user: %v", err)
		}
	}

	var mu sync.Mutex
	remoteIDs := make(map[string]string)
	creates := 0
	updates := 0
	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer remote-secret" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/scim/v2/ServiceProviderConfig":
			w.Header().Set("Content-Type", ContentTypeSCIM)
			json.NewEncoder(w).Encode(GetServiceProviderConfig(target.URL + "/scim/v2"))
		case r.Method == http.MethodPost && r.URL.Path == "/scim/v2/Users":
			var user User
			if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
				t.Errorf("decode create: %v", err)
			}
			if user.ID != "" || user.Meta != nil || len(user.Groups) != 0 {
				t.Errorf("server-managed fields were forwarded: %+v", user.BaseResource)
			}
			if user.ExternalID == "" {
				t.Error("externalId must correlate the source identity")
			}
			mu.Lock()
			creates++
			remoteID := fmt.Sprintf("remote-%d", creates)
			remoteIDs[user.UserName] = remoteID
			mu.Unlock()
			user.ID = remoteID
			w.Header().Set("Content-Type", ContentTypeSCIM)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(user)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/scim/v2/Users/"):
			var user User
			if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
				t.Errorf("decode update: %v", err)
			}
			mu.Lock()
			updates++
			remoteID := remoteIDs[user.UserName]
			mu.Unlock()
			user.ID = remoteID
			w.Header().Set("Content-Type", ContentTypeSCIM)
			json.NewEncoder(w).Encode(user)
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()

	p := NewPlugin()
	p.storage = storage
	p.SetConfig(plugin.PluginConfig{Environment: "development"})

	first := performSyncRequest(t, p, target.URL+"/scim/v2")
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
	}
	var firstResponse ClientSyncResponse
	if err := json.NewDecoder(first.Body).Decode(&firstResponse); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if firstResponse.Status != "completed" || firstResponse.Result.Created != 2 || firstResponse.Result.Errors != 0 {
		t.Fatalf("first response = %+v", firstResponse)
	}

	second := performSyncRequest(t, p, target.URL+"/scim/v2")
	if second.Code != http.StatusOK {
		t.Fatalf("second status = %d, body = %s", second.Code, second.Body.String())
	}
	var secondResponse ClientSyncResponse
	if err := json.NewDecoder(second.Body).Decode(&secondResponse); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if secondResponse.Result.Updated != 2 || secondResponse.Result.Created != 0 || secondResponse.Result.Errors != 0 {
		t.Fatalf("second result = %+v", secondResponse.Result)
	}

	mu.Lock()
	defer mu.Unlock()
	if creates != 2 || updates != 2 {
		t.Fatalf("remote operations: creates=%d updates=%d", creates, updates)
	}
	mappings, err := storage.GetSyncMappings(context.Background(), target.URL+"/scim/v2")
	if err != nil {
		t.Fatalf("get mappings: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("mapping count = %d", len(mappings))
	}
	lastSync, _, err := storage.GetSyncState(context.Background(), target.URL+"/scim/v2")
	if err != nil || lastSync.IsZero() {
		t.Fatalf("last successful sync = %v, err = %v", lastSync, err)
	}
}

func TestNormalizeSCIMTargetURLRequiresHTTPSInProduction(t *testing.T) {
	if _, err := normalizeSCIMTargetURL("http://203.0.113.10/v2", "production"); err == nil {
		t.Fatal("production HTTP target should be rejected")
	}
	got, err := normalizeSCIMTargetURL("https://203.0.113.10/v2/", "production")
	if err != nil {
		t.Fatalf("normalize HTTPS target: %v", err)
	}
	if got != "https://203.0.113.10/v2" {
		t.Fatalf("normalized target = %q", got)
	}
}

func TestNormalizeSCIMTargetURLRejectsPrivateTargetsInProduction(t *testing.T) {
	privateTargets := []string{
		"https://127.0.0.1/scim/v2",       // loopback
		"https://10.0.0.5/scim/v2",        // RFC 1918 private
		"https://169.254.169.254/scim/v2", // link-local (cloud metadata endpoint)
		"https://[::1]/scim/v2",           // IPv6 loopback
	}
	for _, target := range privateTargets {
		if _, err := normalizeSCIMTargetURL(target, "production"); err == nil {
			t.Fatalf("production target %q should be rejected as private/loopback", target)
		}
	}

	// The same private targets are allowed outside production (e.g. docker-compose
	// networks, local IdP emulators) as long as they still satisfy the scheme rule.
	for _, target := range privateTargets {
		if _, err := normalizeSCIMTargetURL(target, "development"); err != nil {
			t.Fatalf("development target %q should be allowed: %v", target, err)
		}
	}
}

func TestNormalizeSCIMTargetURLRejectsUnresolvableHostInProduction(t *testing.T) {
	if _, err := normalizeSCIMTargetURL("https://this-host-does-not-exist.invalid/scim/v2", "production"); err == nil {
		t.Fatal("production target with an unresolvable host should be rejected")
	}
}

func TestPluginRequiresAuthTokenInProduction(t *testing.T) {
	t.Setenv("SCIM_API_TOKEN", "")
	p := NewPlugin()
	err := p.Initialize(context.Background(), plugin.PluginConfig{
		Environment: "production",
		BaseURL:     "https://scim.example.test",
	})
	if err == nil || !strings.Contains(err.Error(), "SCIM_API_TOKEN") {
		t.Fatalf("initialize error = %v", err)
	}
}

func TestHandleClientSyncDoesNotAdvanceLastSyncAfterUserFailure(t *testing.T) {
	storage, err := NewStorage(t.TempDir())
	if err != nil {
		t.Fatalf("new storage: %v", err)
	}
	defer storage.Close()
	user := NewUser()
	user.UserName = "failed@example.com"
	if _, err := storage.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("create local user: %v", err)
	}

	var target *httptest.Server
	target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/scim/v2/ServiceProviderConfig" {
			json.NewEncoder(w).Encode(GetServiceProviderConfig(target.URL + "/scim/v2"))
			return
		}
		WriteError(w, &SCIMError{Status: http.StatusInternalServerError, Detail: "target rejected user"})
	}))
	defer target.Close()

	p := NewPlugin()
	p.storage = storage
	p.SetConfig(plugin.PluginConfig{Environment: "development"})
	recorder := performSyncRequest(t, p, target.URL+"/scim/v2")
	if recorder.Code != http.StatusMultiStatus {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	lastSync, _, err := storage.GetSyncState(context.Background(), target.URL+"/scim/v2")
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if !lastSync.IsZero() {
		t.Fatalf("last sync advanced after failure: %v", lastSync)
	}
	mappings, err := storage.GetSyncMappings(context.Background(), target.URL+"/scim/v2")
	if err != nil {
		t.Fatalf("get mappings: %v", err)
	}
	if len(mappings) != 0 {
		t.Fatalf("failed mappings were persisted: %v", mappings)
	}
}

func TestHandleClientProvisionStripsServerManagedFieldsAndNormalizesTarget(t *testing.T) {
	var received User
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer remote-secret" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Method != http.MethodPost || r.URL.Path != "/scim/v2/Users" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode create: %v", err)
		}
		response := received
		response.ID = "remote-1"
		w.Header().Set("Content-Type", ContentTypeSCIM)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer target.Close()

	p := NewPlugin()
	p.SetConfig(plugin.PluginConfig{Environment: "development"})

	localUser := NewUser()
	localUser.ID = "local-forged-id"
	localUser.UserName = "carol@example.com"
	localUser.Meta = &Meta{ResourceType: "User"}
	localUser.Groups = []GroupRef{{Value: "should-not-forward"}}

	body, err := json.Marshal(map[string]interface{}{
		"targetUrl": target.URL + "/scim/v2/", // trailing slash must be normalized away
		"authToken": "remote-secret",
		"user":      localUser,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/scim/client/provision", strings.NewReader(string(body)))
	recorder := httptest.NewRecorder()
	p.handleClientProvision(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if received.ID != "" || received.Meta != nil || len(received.Groups) != 0 {
		t.Errorf("server-managed fields were forwarded: %+v", received.BaseResource)
	}
	if received.ExternalID != "local-forged-id" {
		t.Errorf("externalId = %q, want source local id preserved for correlation", received.ExternalID)
	}

	var response User
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ID != "remote-1" {
		t.Fatalf("response id = %q", response.ID)
	}
}

func TestHandleClientProvisionRejectsInvalidTargetURL(t *testing.T) {
	p := NewPlugin()
	p.SetConfig(plugin.PluginConfig{Environment: "production"})

	localUser := NewUser()
	localUser.UserName = "dave@example.com"
	body, _ := json.Marshal(map[string]interface{}{
		"targetUrl": "http://scim.example.test/scim/v2", // HTTP is rejected in production
		"authToken": "remote-secret",
		"user":      localUser,
	})

	req := httptest.NewRequest(http.MethodPost, "/scim/client/provision", strings.NewReader(string(body)))
	recorder := httptest.NewRecorder()
	p.handleClientProvision(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestHandleClientProvisionRequiresUserName(t *testing.T) {
	p := NewPlugin()
	p.SetConfig(plugin.PluginConfig{Environment: "development"})

	body, _ := json.Marshal(map[string]interface{}{
		"targetUrl": "https://scim.example.test/scim/v2",
		"authToken": "remote-secret",
		"user":      NewUser(),
	})

	req := httptest.NewRequest(http.MethodPost, "/scim/client/provision", strings.NewReader(string(body)))
	recorder := httptest.NewRecorder()
	p.handleClientProvision(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
}

func performSyncRequest(t *testing.T, p *Plugin, targetURL string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"targetUrl":%q,"authToken":"remote-secret"}`, targetURL)
	req := httptest.NewRequest(http.MethodPost, "/scim/client/sync", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	p.handleClientSync(recorder, req)
	return recorder
}
