package capture

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRecorderKeepsWholeBodies checks the recorder stores what crossed the
// wire in full, including bodies far beyond the Looking Glass capture limit.
func TestRecorderKeepsWholeBodies(t *testing.T) {
	large := strings.Repeat("y", 300*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Echo-Length", r.Header.Get("Content-Length"))
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write(append(body, large...))
	}))
	defer server.Close()

	recorder := NewRecorder(nil)
	client := &http.Client{Transport: recorder}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/echo?x=1", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	received, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if len(received) != len("hello")+len(large) {
		t.Fatalf("caller received %d bytes; the recorder must hand the body on intact", len(received))
	}

	exchanges := recorder.Take()
	if len(exchanges) != 1 {
		t.Fatalf("recorded %d exchanges, want 1", len(exchanges))
	}
	exchange := exchanges[0]
	if exchange.Request.Body == nil || exchange.Request.Body.Data != "hello" {
		t.Fatalf("request body = %+v", exchange.Request.Body)
	}
	if got := exchange.Request.Headers["User-Agent"]; len(got) != 1 || got[0] != UserAgent {
		t.Fatalf("User-Agent = %v", got)
	}
	if got := exchange.Request.Headers["Host"]; len(got) != 1 || got[0] == "" {
		t.Fatalf("Host = %v", got)
	}
	if exchange.Response.Status != http.StatusTeapot || exchange.Response.Body == nil {
		t.Fatalf("response = %+v", exchange.Response)
	}
	if body := exchange.Response.Body; body.Truncated || len(body.Data) != len("hello")+len(large) || body.Size != int64(len(body.Data)) {
		t.Fatalf("response body truncated=%t len=%d size=%d", body.Truncated, len(body.Data), body.Size)
	}
	if exchange.Request.Raw == nil || !strings.HasPrefix(exchange.Request.Raw.Data, "POST /echo?x=1 HTTP/1.1\r\n") {
		t.Fatalf("raw request = %+v", exchange.Request.Raw)
	}
	if exchange.Meta.CaptureSource != "conformance_client" || exchange.Meta.BodyLimitBytes != 0 {
		t.Fatalf("meta = %+v", exchange.Meta)
	}
	if len(recorder.Take()) != 0 {
		t.Fatal("Take must clear the recorded exchanges")
	}
}
