package ssf

import "time"

// CapturedHTTPExchange records a transmitter/receiver HTTP hop before it is
// mapped onto lookingglass.CapturedExchange. This is an internal DTO, not a
// second event bus.
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
