package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestClassifyOID4VCIProtocolHop(t *testing.T) {
	cases := []struct {
		rawURL string
		want   string
	}{
		{"https://issuer.example/oid4vci/.well-known/openid-credential-issuer", "Fetch Credential Issuer Metadata"},
		{"https://issuer.example/.well-known/oauth-authorization-server/oid4vci", "Fetch Authorization Server Metadata"},
		{"https://issuer.example/oid4vci/credential-offer/abc", "Fetch Credential Offer"},
		{"https://issuer.example/oid4vci/token", "Token Request"},
		{"https://issuer.example/oid4vci/nonce", "Nonce Request"},
		{"https://issuer.example/oid4vci/credential", "Credential Request"},
		{"https://issuer.example/oid4vci/deferred_credential", "Deferred Credential Poll"},
		{"https://issuer.example/oid4vci/notification", "Credential Status Notification"},
		{"https://issuer.example/api/.well-known/jwks.json", "Fetch Issuer JWKS"},
	}
	for _, testCase := range cases {
		parsed, err := url.Parse(testCase.rawURL)
		if err != nil {
			t.Fatalf("parse %q: %v", testCase.rawURL, err)
		}
		step, _ := classifyOID4VCIProtocolHop("POST", parsed)
		if step != testCase.want {
			t.Fatalf("%s: got %q, want %q", testCase.rawURL, step, testCase.want)
		}
	}
}

func TestCaptureHTTPBodyRecordsNothingOfAnOversizedBody(t *testing.T) {
	small := io.NopCloser(strings.NewReader(`{"ok":true}`))
	body, recorded := captureHTTPBody(&small, "application/json")
	if decoded, _ := body.(map[string]interface{}); !recorded || decoded["ok"] != true {
		t.Fatalf("small body: recorded=%v body=%#v", recorded, body)
	}

	oversized := strings.Repeat("a", maxTranscriptBodyBytes+10)
	reader := io.NopCloser(strings.NewReader(oversized))
	body, recorded = captureHTTPBody(&reader, "text/plain")
	if recorded || body != nil {
		t.Fatalf("an oversized body must not be recorded, even in part: recorded=%v", recorded)
	}
	rest, err := io.ReadAll(reader)
	if err != nil || string(rest) != oversized {
		t.Fatalf("the caller must still read the whole body: read %d of %d bytes, err %v", len(rest), len(oversized), err)
	}
}

// TestAPIResolveReturnsRequestObjectFetchWhenRefusing proves a refusal carries
// the hop that caused it: the verifier answers the request_uri GET with a
// Content-Type other than application/oauth-authz-req+jwt, and the 400 holds
// the recorded exchange.
func TestAPIResolveReturnsRequestObjectFetchWhenRefusing(t *testing.T) {
	requestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("not a request object"))
	}))
	defer requestServer.Close()
	host, _ := url.Parse(requestServer.URL)
	server := &walletHarnessServer{httpClient: requestServer.Client(), targetHost: host.Host}

	request := httptest.NewRequest(http.MethodPost, "https://wallet.example/api/resolve",
		strings.NewReader(fmt.Sprintf(`{"request_uri":%q}`, requestServer.URL)))
	recorder := httptest.NewRecorder()
	server.handleAPIResolve(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		ErrorDescription string        `json:"error_description"`
		Exchanges        []protocolHop `json:"_protocol_exchanges"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(response.ErrorDescription, "unsupported Content-Type") {
		t.Fatalf("error_description = %q", response.ErrorDescription)
	}
	if len(response.Exchanges) != 1 {
		t.Fatalf("want the request_uri hop, got %d hops", len(response.Exchanges))
	}
	hop := response.Exchanges[0]
	if hop.Step != "Fetch Request Object" || hop.RFCReference != "RFC 9101 Section 5.2.3" || hop.Actor != "wallet→verifier" ||
		hop.Method != http.MethodGet || hop.ResponseStatus != http.StatusOK || hop.ResponseBody != "not a request object" {
		t.Fatalf("unexpected hop %+v", hop)
	}
}

func TestSubmitToVerifierRecordsAuthorizationResponse(t *testing.T) {
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer verifier.Close()
	server := &walletHarnessServer{httpClient: verifier.Client()}
	transcript := &protocolTranscript{}

	status, _, err := server.submitToVerifier(withProtocolTranscript(context.Background(), transcript), nil, &resolvedRequestContext{
		ResponseMode: "direct_post",
		ResponseURI:  verifier.URL,
		State:        "state-123",
	}, "vp-token-value", "")
	if err != nil || status != http.StatusOK {
		t.Fatalf("submitToVerifier: status=%d err=%v", status, err)
	}
	hops, _ := transcript.snapshot()
	if len(hops) != 1 {
		t.Fatalf("want one hop, got %d", len(hops))
	}
	hop := hops[0]
	form, _ := hop.RequestBody.(map[string]string)
	response, _ := hop.ResponseBody.(map[string]interface{})
	if hop.Step != "Authorization Response" || hop.RFCReference != "OpenID4VP 1.0 Section 8.2" || hop.Actor != "wallet→verifier" ||
		form["vp_token"] != "vp-token-value" || form["state"] != "state-123" || response["status"] != "received" {
		t.Fatalf("unexpected hop %+v", hop)
	}
}
