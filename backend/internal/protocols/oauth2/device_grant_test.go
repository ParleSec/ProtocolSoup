package oauth2

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
)

func TestDeviceAuthorizationIssueAndPendingPoll(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	issued := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	if issued["device_code"] == "" || issued["user_code"] == "" || issued["verification_uri"] == "" {
		t.Fatalf("missing required RFC 8628 Section 3.2 fields: %#v", issued)
	}
	if issued["expires_in"].(float64) != float64(mockidp.DeviceAuthorizationTTL/time.Second) {
		t.Fatalf("expires_in = %#v", issued["expires_in"])
	}
	if issued["interval"].(float64) != 5 {
		t.Fatalf("interval = %#v", issued["interval"])
	}

	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {issued["device_code"].(string)},
		"client_id":   {"public-app"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Fatalf("pending poll status = %d body = %#v", status, body)
	}
}

func TestDeviceAuthorizationSlowDownThenApprove(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	issued := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	deviceCode := issued["device_code"].(string)
	userCode := issued["user_code"].(string)

	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"public-app"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "authorization_pending" {
		t.Fatalf("first poll = %d %#v", status, body)
	}
	status, body = postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"public-app"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "slow_down" {
		t.Fatalf("rapid second poll = %d %#v, want slow_down", status, body)
	}

	alice := server.idp.GetDemoUserPresets()[0]
	approveDevice(t, server.server.URL, userCode, alice.Credentials.Email, alice.Credentials.Password, "approve")

	*server.now = server.now.Add(15 * time.Second)
	status, body = postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {deviceCode},
		"client_id":   {"public-app"},
	}, "")
	if status != http.StatusOK {
		t.Fatalf("approved poll status = %d body = %#v", status, body)
	}
	if body["access_token"] == "" || body["refresh_token"] == "" {
		t.Fatalf("token response missing tokens: %#v", body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %#v", body["token_type"])
	}
}

func TestDeviceAuthorizationDeniedAndExpired(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	issued := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	alice := server.idp.GetDemoUserPresets()[0]
	approveDevice(t, server.server.URL, issued["user_code"].(string), alice.Credentials.Email, alice.Credentials.Password, "deny")

	status, body := postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {issued["device_code"].(string)},
		"client_id":   {"public-app"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "access_denied" {
		t.Fatalf("denied poll = %d %#v", status, body)
	}

	expired := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	server.idp.ExpireDeviceAuthorization(expired["device_code"].(string), *server.now)
	status, body = postTokenRequest(t, server.server.URL, url.Values{
		"grant_type":  {mockidp.DeviceCodeGrantType},
		"device_code": {expired["device_code"].(string)},
		"client_id":   {"public-app"},
	}, "")
	if status != http.StatusBadRequest || body["error"] != "expired_token" {
		t.Fatalf("expired poll = %d %#v", status, body)
	}
}

func TestDeviceAuthorizeConfidentialClientMustAuthenticate(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	status, body := postDeviceAuthorizeStatus(t, server.server.URL, url.Values{"client_id": {"demo-app"}})
	if status != http.StatusBadRequest || body["error"] != "unauthorized_client" && body["error"] != "invalid_client" {
		t.Fatalf("confidential device authorize without secret = %d %#v", status, body)
	}
}

func TestDeviceAuthorizePublicClientAndMetadata(t *testing.T) {
	flows := NewPlugin().GetFlowDefinitions()
	var sawDevice, sawROPC bool
	for _, flow := range flows {
		if flow.ID == "device_code" && flow.Executable {
			sawDevice = true
		}
		if flow.ID == "resource_owner" {
			sawROPC = true
		}
	}
	if !sawDevice {
		t.Fatalf("expected executable device_code flow")
	}
	if sawROPC {
		t.Fatalf("resource_owner must not be advertised (RFC 9700 Section 2.4)")
	}
}

func TestDeviceVerificationPageMatchesAuthorizeChrome(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	issued := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	userCode := issued["user_code"].(string)

	resp, err := http.Get(server.server.URL + "/oauth2/device?user_code=" + url.QueryEscape(userCode))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body = %s", resp.StatusCode, raw)
	}
	html := string(raw)
	for _, want := range []string{
		"Login - Protocol Showcase",
		"OAuth 2.0 Device Authorization",
		"Public Application (SPA)",
		">Sign In<",
		"Demo Users (click to autofill)",
		"to authorize a device",
		userCode,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("verification HTML missing %q", want)
		}
	}
	if strings.Contains(html, "Authorize a device") {
		t.Fatalf("old device chrome still present")
	}
	peek := server.idp.PeekDeviceAuthorizationByUserCode(userCode)
	if peek == nil || peek.FailedAttempts != 0 {
		t.Fatalf("GET must not count a user_code failure: %#v", peek)
	}
}

func TestDeviceVerificationResultNotifiesOpener(t *testing.T) {
	server := newOAuthAssertionTestServer(t)
	issued := postDeviceAuthorize(t, server.server.URL, url.Values{"client_id": {"public-app"}})
	alice := server.idp.GetDemoUserPresets()[0]
	html := approveDevice(t, server.server.URL, issued["user_code"].(string), alice.Credentials.Email, alice.Credentials.Password, "approve")
	for _, want := range []string{
		`data-approved="true"`,
		"oauth_device_complete",
		"Protocol Showcase",
		"window.location.origin",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("result HTML missing %q", want)
		}
	}
}

func postDeviceAuthorize(t *testing.T, serverURL string, form url.Values) map[string]interface{} {
	t.Helper()
	status, body := postDeviceAuthorizeStatus(t, serverURL, form)
	if status != http.StatusOK {
		t.Fatalf("device authorize status = %d body = %#v", status, body)
	}
	return body
}

func postDeviceAuthorizeStatus(t *testing.T, serverURL string, form url.Values) (int, map[string]interface{}) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/oauth2/device/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func approveDevice(t *testing.T, serverURL, userCode, email, password, decision string) string {
	t.Helper()
	form := url.Values{
		"user_code": {userCode},
		"email":     {email},
		"password":  {password},
		"decision":  {decision},
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+"/oauth2/device", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device verify status = %d body = %s", resp.StatusCode, raw)
	}
	return string(raw)
}
