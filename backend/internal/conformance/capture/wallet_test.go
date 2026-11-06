package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCallWalletAddsTheWalletsOwnHopsAfterTheCall proves the artefact holds
// the client's call to the wallet first, then each hop the wallet recorded,
// with the hop's exact bytes and marked as recorded by the hosted wallet.
func TestCallWalletAddsTheWalletsOwnHopsAfterTheCall(t *testing.T) {
	binary := []byte{0xa2, 0x61, 0x76, 0xff}
	wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Wallet-Session") == "" {
			t.Error("the wallet session header is missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_request",
			"error_description": "request_uri GET returned unsupported Content-Type \"application/json\"",
			"_protocol_exchanges": []map[string]any{{
				"step":             "Fetch Request Object",
				"rfc_reference":    "RFC 9101 Section 5.2.3",
				"method":           "GET",
				"url":              "https://counterparty.example/scenarios/vp-004/request",
				"request_headers":  map[string]string{"Accept": "application/oauth-authz-req+jwt"},
				"response_status":  200,
				"response_headers": map[string]string{"Content-Type": "application/json"},
				"response_body":    `{"z":1,"a":2}`,
				"duration_ms":      12,
				"actor":            "wallet→verifier",
			}, {
				"step":                  "Credential Request",
				"method":                "POST",
				"url":                   "https://issuer.example/credential",
				"request_body":          base64.StdEncoding.EncodeToString(binary),
				"request_body_encoding": "base64",
				"response_status":       401,
			}},
		})
	}))
	defer wallet.Close()

	recorder := NewRecorder(nil)
	env := NewEnv("http://unused.localhost", wallet.URL, "", recorder, 6000)
	result, err := CallWallet(context.Background(), env, WalletCall{Path: "/api/resolve", Body: map[string]any{"request_uri": "x"}, Session: NewWalletSession()})
	if err != nil {
		t.Fatalf("CallWallet: %v", err)
	}
	if result.Status != http.StatusOK || result.Error() != "invalid_request" || result.Hop("Fetch Request Object") == nil || result.Hop("Nonce Request") != nil {
		t.Fatalf("unexpected result %+v", result)
	}

	exchanges := recorder.Take()
	if len(exchanges) != 3 {
		t.Fatalf("want the call plus two hops, got %d exchanges", len(exchanges))
	}
	call, first, second := exchanges[0], exchanges[1], exchanges[2]
	if call.Meta.CaptureSource != "conformance_client" || call.Request.URL != wallet.URL+"/api/resolve" {
		t.Fatalf("the client's call must come first: %+v", call.Request)
	}
	if first.Meta.CaptureSource != "hosted_wallet" || first.Request.Method != "GET" || first.Request.Host != "counterparty.example" ||
		first.Response.Status != 200 || first.Response.StatusText != "OK" || first.Response.Body.Data != `{"z":1,"a":2}` ||
		first.Request.Headers["Accept"][0] != "application/oauth-authz-req+jwt" || first.Timing.DurationMicro != 12000 {
		t.Fatalf("first hop not converted exactly: %+v", first)
	}
	if second.Request.Body == nil || second.Request.Body.Encoding != "base64" ||
		second.Request.Body.Data != base64.StdEncoding.EncodeToString(binary) || second.Response.Status != 401 {
		t.Fatalf("binary hop body not kept: %+v", second.Request.Body)
	}
	if env.PublishAfter().IsZero() {
		t.Fatal("a wallet call must delay publication for the wallet session's lifetime")
	}
}

func TestCallWalletNeedsAWallet(t *testing.T) {
	env := NewEnv("http://unused.localhost", "", "", NewRecorder(nil), 6000)
	if _, err := CallWallet(context.Background(), env, WalletCall{Path: "/api/resolve"}); err == nil {
		t.Fatal("a run without a wallet must refuse wallet calls")
	}
}
