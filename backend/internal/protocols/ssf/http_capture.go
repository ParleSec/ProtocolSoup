package ssf

import "time"

// CapturedHTTPExchange records the full request/response details of an HTTP
// exchange between SSF components (e.g., push delivery, JWKS fetch).
// Defined locally to avoid importing from Looking Glass (SSF has its own sandbox).
type CapturedHTTPExchange struct {
	Label      string      `json:"label"`
	Request    HTTPCapture `json:"request"`
	Response   HTTPCapture `json:"response"`
	DurationMs int64       `json:"duration_ms"`
	Timestamp  time.Time   `json:"timestamp"`
	SessionID  string      `json:"session_id,omitempty"`
}

// HTTPCapture holds either the request or response side of an HTTP exchange.
type HTTPCapture struct {
	Method     string            `json:"method,omitempty"`
	URL        string            `json:"url,omitempty"`
	StatusCode int               `json:"status_code,omitempty"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
}
