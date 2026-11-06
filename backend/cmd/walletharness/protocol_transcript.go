package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// protocolHop is one outbound HTTP exchange as the wallet sent and received
// it. Bodies are the exact bytes on the wire: UTF-8 text as is, anything else
// base64 with its *_body_encoding set to "base64".
type protocolHop struct {
	Step                string            `json:"step"`
	RFCReference        string            `json:"rfc_reference,omitempty"`
	Method              string            `json:"method"`
	URL                 string            `json:"url"`
	RequestHeaders      map[string]string `json:"request_headers,omitempty"`
	RequestBody         string            `json:"request_body,omitempty"`
	RequestBodyEncoding string            `json:"request_body_encoding,omitempty"`
	// RequestPlaintext is the exact bytes the wallet encrypted into
	// RequestBody, and ResponsePlaintext the exact bytes it decrypted from
	// ResponseBody, when that body is a JWE. The bodies stay as sent on the
	// wire; these show what was inside them.
	RequestPlaintext     string                 `json:"request_plaintext,omitempty"`
	ResponsePlaintext    string                 `json:"response_plaintext,omitempty"`
	ResponseStatus       int                    `json:"response_status"`
	ResponseHeaders      map[string]string      `json:"response_headers,omitempty"`
	ResponseBody         string                 `json:"response_body,omitempty"`
	ResponseBodyEncoding string                 `json:"response_body_encoding,omitempty"`
	DurationMS           int64                  `json:"duration_ms"`
	Actor                string                 `json:"actor,omitempty"`
	Extra                map[string]interface{} `json:"extra,omitempty"`
}

type protocolTranscript struct {
	mu     sync.Mutex
	hops   []protocolHop
	events []walletLifecycleEvent
}

type protocolTranscriptContextKey struct{}

// maxTranscriptBodyBytes bounds how much of one body the transcript buffers.
// It matches the wallet's request object limit, so recording a hop never
// reads more of an untrusted response than the wallet itself would. A larger
// body is not recorded at all rather than recorded in part.
const maxTranscriptBodyBytes = maxRequestObjectBytes

// protocolStep labels the hops doHTTP records under a context.
type protocolStep struct {
	Step         string
	RFCReference string
	Actor        string
}

type protocolStepContextKey struct{}

type requestPlaintextContextKey struct{}

// withRequestPlaintext tells doHTTP what the wallet encrypted into the body
// of the requests sent under ctx, so the recorded hop can show it.
func withRequestPlaintext(ctx context.Context, plaintext []byte) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestPlaintextContextKey{}, string(plaintext))
}

// recordResponsePlaintext notes, on the hop recorded last, what the wallet
// decrypted from its response body.
func recordResponsePlaintext(ctx context.Context, plaintext []byte) {
	transcript := protocolTranscriptFrom(ctx)
	if transcript == nil {
		return
	}
	transcript.mu.Lock()
	defer transcript.mu.Unlock()
	if last := len(transcript.hops) - 1; last >= 0 {
		transcript.hops[last].ResponsePlaintext = string(plaintext)
	}
}

// withProtocolStep labels the hops doHTTP records under ctx. Unlabelled hops
// are classified as wallet-to-issuer OID4VCI exchanges.
func withProtocolStep(ctx context.Context, step protocolStep) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, protocolStepContextKey{}, step)
}

// recordProtocolExchanges attaches a fresh transcript to r, so every hop the
// wallet makes while handling it is recorded, and returns a writer that adds
// those hops to the JSON response, error responses included.
func recordProtocolExchanges(w http.ResponseWriter, r *http.Request) (*http.Request, func(int, interface{})) {
	transcript := &protocolTranscript{}
	r = r.WithContext(withProtocolTranscript(r.Context(), transcript))
	return r, func(status int, payload interface{}) {
		writeJSONWithTranscript(w, status, payload, transcript)
	}
}

// writeJSONWithTranscript writes payload as writeJSON does, adding the hops
// the transcript recorded as _protocol_exchanges when there are any.
func writeJSONWithTranscript(w http.ResponseWriter, status int, payload interface{}, transcript *protocolTranscript) {
	if hops, _ := transcript.snapshot(); len(hops) > 0 {
		switch body := payload.(type) {
		case map[string]interface{}:
			body["_protocol_exchanges"] = hops
		case map[string]string:
			withHops := make(map[string]interface{}, len(body)+1)
			for key, value := range body {
				withHops[key] = value
			}
			withHops["_protocol_exchanges"] = hops
			payload = withHops
		}
	}
	writeJSON(w, status, payload)
}

func withProtocolTranscript(ctx context.Context, transcript *protocolTranscript) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if transcript == nil {
		return ctx
	}
	return context.WithValue(ctx, protocolTranscriptContextKey{}, transcript)
}

func protocolTranscriptFrom(ctx context.Context) *protocolTranscript {
	if ctx == nil {
		return nil
	}
	transcript, _ := ctx.Value(protocolTranscriptContextKey{}).(*protocolTranscript)
	return transcript
}

func (t *protocolTranscript) addEvent(eventType, title string, data map[string]interface{}) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, newWalletEvent(eventType, title, data))
}

func (t *protocolTranscript) addHop(hop protocolHop) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.hops = append(t.hops, hop)
}

func (t *protocolTranscript) snapshot() (hops []protocolHop, events []walletLifecycleEvent) {
	if t == nil {
		return nil, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	hops = append([]protocolHop(nil), t.hops...)
	events = append([]walletLifecycleEvent(nil), t.events...)
	return hops, events
}

// doHTTP executes an outbound request and, when a protocol transcript is attached
// to ctx, records the real hop (method/URL/bodies) for Looking Glass glass-box
// playback. Looking Glass must show protocol stages, not wallet API calls, so
// each hop carries the step a withProtocolStep label names, or its OID4VCI
// classification.
func (s *walletHarnessServer) doHTTP(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, http.ErrNotSupported
	}
	transcript := protocolTranscriptFrom(ctx)
	if transcript == nil {
		return s.httpClient.Do(req)
	}

	step, rfc := classifyOID4VCIProtocolHop(req.Method, req.URL)
	actor := "wallet→issuer"
	if labelled, ok := ctx.Value(protocolStepContextKey{}).(protocolStep); ok {
		step, rfc, actor = labelled.Step, labelled.RFCReference, labelled.Actor
	}
	extra := map[string]interface{}{}
	requestPlaintext, _ := ctx.Value(requestPlaintextContextKey{}).(string)
	requestHeaders := flattenHeader(req.Header)
	requestBody, requestEncoding, requestRecorded := captureHTTPBody(&req.Body)
	if !requestRecorded {
		extra["request_body_not_recorded"] = fmt.Sprintf("request body exceeds %d bytes", maxTranscriptBodyBytes)
	}

	started := time.Now()
	resp, err := s.httpClient.Do(req)
	durationMS := time.Since(started).Milliseconds()
	if err != nil {
		extra["error"] = err.Error()
		transcript.addHop(protocolHop{
			Step:                step,
			RFCReference:        rfc,
			Method:              req.Method,
			URL:                 requestURLString(req),
			RequestHeaders:      requestHeaders,
			RequestBody:         requestBody,
			RequestBodyEncoding: requestEncoding,
			RequestPlaintext:    requestPlaintext,
			DurationMS:          durationMS,
			Actor:               actor,
			Extra:               extra,
		})
		return nil, err
	}

	responseBody, responseEncoding, responseRecorded := captureHTTPBody(&resp.Body)
	if !responseRecorded {
		extra["response_body_not_recorded"] = fmt.Sprintf("response body exceeds %d bytes", maxTranscriptBodyBytes)
	}
	if len(extra) == 0 {
		extra = nil
	}
	transcript.addHop(protocolHop{
		Step:                 step,
		RFCReference:         rfc,
		Method:               req.Method,
		URL:                  requestURLString(req),
		RequestHeaders:       requestHeaders,
		RequestBody:          requestBody,
		RequestBodyEncoding:  requestEncoding,
		RequestPlaintext:     requestPlaintext,
		ResponseStatus:       resp.StatusCode,
		ResponseHeaders:      flattenHeader(resp.Header),
		ResponseBody:         responseBody,
		ResponseBodyEncoding: responseEncoding,
		DurationMS:           durationMS,
		Actor:                actor,
		Extra:                extra,
	})
	transcript.addEvent("http_exchange", step, map[string]interface{}{
		"method":          req.Method,
		"url":             requestURLString(req),
		"response_status": resp.StatusCode,
		"rfc_reference":   rfc,
		"duration_ms":     durationMS,
	})
	return resp, nil
}

func classifyOID4VCIProtocolHop(method string, parsed *url.URL) (step string, rfc string) {
	path := ""
	if parsed != nil {
		path = strings.ToLower(parsed.EscapedPath())
	}
	switch {
	case strings.Contains(path, "/.well-known/openid-credential-issuer"):
		return "Fetch Credential Issuer Metadata", "OpenID4VCI 1.0 Section 11.2.2"
	case strings.Contains(path, "/.well-known/oauth-authorization-server"):
		return "Fetch Authorization Server Metadata", "RFC 8414 Section 3"
	case strings.Contains(path, "credential-offer"):
		return "Fetch Credential Offer", "OpenID4VCI 1.0 Section 4.1.3"
	case strings.Contains(path, "/oid4vci/offers/"):
		// ProtocolSoup's issuer API for creating an offer; OpenID4VCI defines
		// no such endpoint, so the hop cites none.
		return "Create Credential Offer", ""
	case strings.HasSuffix(path, "/token") || strings.Contains(path, "/oid4vci/token"):
		return "Token Request", "OpenID4VCI 1.0 Section 6"
	case strings.Contains(path, "/nonce"):
		return "Nonce Request", "OpenID4VCI 1.0 Section 7"
	case strings.Contains(path, "deferred_credential"):
		return "Deferred Credential Poll", "OpenID4VCI 1.0 Section 9"
	case strings.Contains(path, "/notification"):
		return "Credential Status Notification", "OpenID4VCI 1.0 Section 11.1"
	case strings.Contains(path, "/credential") && !strings.Contains(path, "credential-offer"):
		return "Credential Request", "OpenID4VCI 1.0 Section 8"
	case strings.Contains(path, "jwks"):
		return "Fetch Issuer JWKS", "RFC 8414 / OpenID4VCI 1.0"
	case strings.Contains(path, "/par") || strings.Contains(path, "pushed-authorization"):
		return "Pushed Authorization Request", "RFC 9126 / OpenID4VCI 1.0 Section 5"
	default:
		label := strings.TrimSpace(method + " " + path)
		if label == "" {
			label = "Issuer HTTP Exchange"
		}
		return label, "OpenID4VCI 1.0"
	}
}

func requestURLString(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	if req.URL.IsAbs() {
		return req.URL.String()
	}
	return req.URL.RequestURI()
}

func flattenHeader(header http.Header) map[string]string {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]string, len(header))
	for key, values := range header {
		out[key] = strings.Join(values, ", ")
	}
	return out
}

// captureHTTPBody copies the body's exact bytes for the transcript and leaves
// the body readable in full for the caller. Nothing is decoded or re-encoded,
// so JSON member order and repeated form fields survive as sent. Valid UTF-8
// is returned as text; anything else is base64 with encoding "base64". It
// buffers at most maxTranscriptBodyBytes; recorded is false when the body is
// larger, and then nothing of it is recorded.
func captureHTTPBody(bodyPtr *io.ReadCloser) (body string, encoding string, recorded bool) {
	if bodyPtr == nil || *bodyPtr == nil || *bodyPtr == http.NoBody {
		return "", "", true
	}
	original := *bodyPtr
	raw, err := io.ReadAll(io.LimitReader(original, maxTranscriptBodyBytes+1))
	*bodyPtr = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(raw), original), original}
	if len(raw) > maxTranscriptBodyBytes {
		return "", "", false
	}
	if err != nil || len(raw) == 0 {
		return "", "", true
	}
	if !utf8.Valid(raw) {
		return base64.StdEncoding.EncodeToString(raw), "base64", true
	}
	return string(raw), "", true
}

// decodeProofJWTForTranscript returns the compact JWT plus decoded header/payload
// so Looking Glass can show the real proof without stripping fields.
func decodeProofJWTForTranscript(proofJWT string) map[string]interface{} {
	normalized := strings.TrimSpace(proofJWT)
	if normalized == "" {
		return map[string]interface{}{"present": false}
	}
	summary := map[string]interface{}{
		"present": true,
		"raw":     normalized,
	}
	parts := strings.Split(normalized, ".")
	if len(parts) >= 2 {
		if headerJSON, err := base64URLDecodeToJSON(parts[0]); err == nil {
			summary["header"] = headerJSON
		}
		if payloadJSON, err := base64URLDecodeToJSON(parts[1]); err == nil {
			summary["payload"] = payloadJSON
		}
	}
	return summary
}

func base64URLDecodeToJSON(segment string) (interface{}, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(segment))
	if err != nil {
		padded := strings.TrimSpace(segment)
		if pad := len(padded) % 4; pad != 0 {
			padded += strings.Repeat("=", 4-pad)
		}
		raw, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return nil, err
		}
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
