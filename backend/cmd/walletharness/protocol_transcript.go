package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type protocolHop struct {
	Step            string                 `json:"step"`
	RFCReference    string                 `json:"rfc_reference,omitempty"`
	Method          string                 `json:"method"`
	URL             string                 `json:"url"`
	RequestHeaders  map[string]string      `json:"request_headers,omitempty"`
	RequestBody     interface{}            `json:"request_body,omitempty"`
	ResponseStatus  int                    `json:"response_status"`
	ResponseHeaders map[string]string      `json:"response_headers,omitempty"`
	ResponseBody    interface{}            `json:"response_body,omitempty"`
	DurationMS      int64                  `json:"duration_ms"`
	Actor           string                 `json:"actor,omitempty"`
	Extra           map[string]interface{} `json:"extra,omitempty"`
}

type protocolTranscript struct {
	mu     sync.Mutex
	hops   []protocolHop
	events []walletLifecycleEvent
}

type protocolTranscriptContextKey struct{}

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
// playback. Looking Glass must show OID4VCI protocol stages, not wallet API calls.
func (s *walletHarnessServer) doHTTP(ctx context.Context, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, http.ErrNotSupported
	}
	transcript := protocolTranscriptFrom(ctx)
	if transcript == nil {
		return s.httpClient.Do(req)
	}

	step, rfc := classifyOID4VCIProtocolHop(req.Method, req.URL)
	requestHeaders := flattenHeader(req.Header)
	requestBody := captureHTTPBody(&req.Body, req.Header.Get("Content-Type"))

	started := time.Now()
	resp, err := s.httpClient.Do(req)
	durationMS := time.Since(started).Milliseconds()
	if err != nil {
		transcript.addHop(protocolHop{
			Step:           step,
			RFCReference:   rfc,
			Method:         req.Method,
			URL:            requestURLString(req),
			RequestHeaders: requestHeaders,
			RequestBody:    requestBody,
			DurationMS:     durationMS,
			Actor:          "wallet→issuer",
			Extra:          map[string]interface{}{"error": err.Error()},
		})
		return nil, err
	}

	responseBody := captureHTTPBody(&resp.Body, resp.Header.Get("Content-Type"))
	transcript.addHop(protocolHop{
		Step:            step,
		RFCReference:    rfc,
		Method:          req.Method,
		URL:             requestURLString(req),
		RequestHeaders:  requestHeaders,
		RequestBody:     requestBody,
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: flattenHeader(resp.Header),
		ResponseBody:    responseBody,
		DurationMS:      durationMS,
		Actor:           "wallet→issuer",
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

func captureHTTPBody(bodyPtr *io.ReadCloser, contentType string) interface{} {
	if bodyPtr == nil || *bodyPtr == nil || *bodyPtr == http.NoBody {
		return nil
	}
	raw, err := io.ReadAll(*bodyPtr)
	_ = (*bodyPtr).Close()
	*bodyPtr = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) == 0 {
		return nil
	}
	trimmedType := strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(trimmedType, "application/json") || json.Valid(raw) {
		var decoded interface{}
		if err := json.Unmarshal(raw, &decoded); err == nil {
			return decoded
		}
	}
	if strings.Contains(trimmedType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(raw))
		if err == nil {
			form := make(map[string]string, len(values))
			for key, list := range values {
				form[key] = strings.Join(list, ",")
			}
			return form
		}
	}
	return string(raw)
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
