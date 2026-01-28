package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// RequestLogger logs HTTP requests with timing information
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			log.Printf(
				"%s %s %d %s %s",
				r.Method,
				r.URL.Path,
				ww.Status(),
				time.Since(start),
				r.RemoteAddr,
			)
		}()

		next.ServeHTTP(ww, r)
	})
}

// SecurityHeaders adds security headers to responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// RateLimiter provides basic rate limiting (simple in-memory implementation)
type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
	mu       sync.RWMutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Limit returns middleware that rate limits requests by IP
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		rl.mu.Lock()
		// Clean old requests
		now := time.Now()
		cutoff := now.Add(-rl.window)
		var valid []time.Time
		for _, t := range rl.requests[ip] {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rl.requests[ip] = valid

		// Check limit
		if len(rl.requests[ip]) >= rl.limit {
			rl.mu.Unlock()
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Record request
		rl.requests[ip] = append(rl.requests[ip], now)
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

// Recovery middleware recovers from panics
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

const (
	captureSessionHeader   = "X-Looking-Glass-Session"
	captureSessionQueryKey = "lg_session"
	captureBodyLimitBytes  = int64(64 * 1024)
	captureRawLimitBytes   = int64(128 * 1024)
)

type bodyCapture struct {
	limit     int64
	buf       bytes.Buffer
	total     int64
	truncated bool
}

func newBodyCapture(limit int64) *bodyCapture {
	if limit < 0 {
		limit = 0
	}
	return &bodyCapture{limit: limit}
}

func (c *bodyCapture) add(p []byte) {
	if len(p) == 0 {
		return
	}
	c.total += int64(len(p))
	if c.limit == 0 {
		c.truncated = true
		return
	}
	remaining := c.limit - int64(c.buf.Len())
	if remaining <= 0 {
		c.truncated = true
		return
	}
	if int64(len(p)) > remaining {
		c.buf.Write(p[:remaining])
		c.truncated = true
		return
	}
	c.buf.Write(p)
}

func (c *bodyCapture) snapshot() ([]byte, int64, bool) {
	data := c.buf.Bytes()
	copied := make([]byte, len(data))
	copy(copied, data)
	truncated := c.truncated || c.total > int64(len(data))
	return copied, c.total, truncated
}

type captureReadCloser struct {
	rc      io.ReadCloser
	capture *bodyCapture
}

func (c *captureReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.capture.add(p[:n])
	}
	return n, err
}

func (c *captureReadCloser) Close() error {
	return c.rc.Close()
}

type captureResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	capture     *bodyCapture
}

func newCaptureResponseWriter(w http.ResponseWriter, capture *bodyCapture) *captureResponseWriter {
	return &captureResponseWriter{
		ResponseWriter: w,
		status:         http.StatusOK,
		capture:        capture,
	}
}

func (w *captureResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *captureResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.capture.add(p[:n])
	}
	return n, err
}

func (w *captureResponseWriter) Status() int {
	if w.wroteHeader {
		return w.status
	}
	return http.StatusOK
}

func (w *captureResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *captureResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *captureResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *captureResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func CaptureMiddleware(lg *lookingglass.Engine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID := captureSessionID(r)
			if lg == nil || sessionID == "" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			requestCapture := newBodyCapture(captureBodyLimitBytes)
			if r.Body != nil && r.Body != http.NoBody {
				r.Body = &captureReadCloser{rc: r.Body, capture: requestCapture}
			}

			responseCapture := newBodyCapture(captureBodyLimitBytes)
			captureWriter := newCaptureResponseWriter(w, responseCapture)

			next.ServeHTTP(captureWriter, r)

			end := time.Now()

			exchange := buildCapturedExchange(sessionID, r, captureWriter, requestCapture, responseCapture, start, end)
			title := "HTTP Exchange " + r.Method + " " + exchange.Request.URL
			lg.NewEventBroadcaster(sessionID).EmitHTTPExchange(title, exchange)
		})
	}
}

func captureSessionID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if sessionID := r.Header.Get(captureSessionHeader); sessionID != "" {
		return sessionID
	}
	return r.URL.Query().Get(captureSessionQueryKey)
}

func buildCapturedExchange(
	sessionID string,
	r *http.Request,
	w *captureResponseWriter,
	requestCapture *bodyCapture,
	responseCapture *bodyCapture,
	start time.Time,
	end time.Time,
) lookingglass.CapturedExchange {
	requestHeaders := cloneHeader(r.Header)
	if r.Host != "" && len(requestHeaders["Host"]) == 0 {
		requestHeaders["Host"] = []string{r.Host}
	}

	requestBody := payloadFromCapture(requestCapture, r.Header.Get("Content-Type"))
	requestRaw := rawPayload(buildRawRequest(r, requestHeaders, requestCapture), captureRawLimitBytes, r.Header.Get("Content-Type"))

	responseHeaders := cloneHeader(w.Header())
	status := w.Status()
	statusText := http.StatusText(status)
	if statusText == "" {
		statusText = "Unknown"
	}

	responseBody := payloadFromCapture(responseCapture, w.Header().Get("Content-Type"))
	responseRaw := rawPayload(buildRawResponse(r.Proto, status, statusText, responseHeaders, responseCapture), captureRawLimitBytes, w.Header().Get("Content-Type"))

	return lookingglass.CapturedExchange{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		Request: lookingglass.CapturedMessage{
			Method:  r.Method,
			URL:     requestURL(r),
			Host:    r.Host,
			Proto:   r.Proto,
			Headers: requestHeaders,
			Body:    requestBody,
			Raw:     requestRaw,
		},
		Response: lookingglass.CapturedMessage{
			Status:     status,
			StatusText: statusText,
			Proto:      r.Proto,
			Headers:    responseHeaders,
			Body:       responseBody,
			Raw:        responseRaw,
		},
		Timing: lookingglass.ExchangeTiming{
			StartUnixMicro: start.UnixMicro(),
			EndUnixMicro:   end.UnixMicro(),
			DurationMicro:  end.Sub(start).Microseconds(),
		},
		TLS: buildTLSInfo(r.TLS),
		Meta: lookingglass.CaptureMeta{
			CaptureSource:            "middleware",
			HeaderOrderPreserved:     false,
			BodyLimitBytes:           captureBodyLimitBytes,
			RequestBodyReadBytes:     requestCapture.total,
			ResponseBodyWrittenBytes: responseCapture.total,
			RawReconstructed:         true,
		},
	}
}

func requestURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.RequestURI != "" {
		return r.RequestURI
	}
	if r.URL != nil {
		if uri := r.URL.RequestURI(); uri != "" {
			return uri
		}
		return r.URL.String()
	}
	return ""
}

func cloneHeader(header http.Header) map[string][]string {
	if header == nil {
		return nil
	}
	clone := make(map[string][]string, len(header))
	for key, values := range header {
		copied := make([]string, len(values))
		copy(copied, values)
		clone[key] = copied
	}
	return clone
}

func buildRawRequest(r *http.Request, headers map[string][]string, capture *bodyCapture) []byte {
	requestURI := requestURL(r)
	var buf bytes.Buffer
	buf.WriteString(r.Method)
	buf.WriteString(" ")
	buf.WriteString(requestURI)
	buf.WriteString(" ")
	buf.WriteString(r.Proto)
	buf.WriteString("\r\n")
	if err := http.Header(headers).Write(&buf); err != nil {
		return buf.Bytes()
	}
	buf.WriteString("\r\n")
	body, _, _ := capture.snapshot()
	buf.Write(body)
	return buf.Bytes()
}

func buildRawResponse(proto string, status int, statusText string, headers map[string][]string, capture *bodyCapture) []byte {
	if statusText == "" {
		statusText = http.StatusText(status)
	}
	var buf bytes.Buffer
	buf.WriteString(proto)
	buf.WriteString(" ")
	buf.WriteString(strconv.Itoa(status))
	buf.WriteString(" ")
	buf.WriteString(statusText)
	buf.WriteString("\r\n")
	if err := http.Header(headers).Write(&buf); err != nil {
		return buf.Bytes()
	}
	buf.WriteString("\r\n")
	body, _, _ := capture.snapshot()
	buf.Write(body)
	return buf.Bytes()
}

func payloadFromCapture(capture *bodyCapture, contentType string) *lookingglass.CapturedPayload {
	if capture == nil {
		return nil
	}
	body, total, truncated := capture.snapshot()
	if total == 0 && len(body) == 0 && !truncated {
		return nil
	}
	return encodePayload(body, total, truncated, contentType)
}

func rawPayload(raw []byte, limit int64, contentType string) *lookingglass.CapturedPayload {
	if len(raw) == 0 {
		return nil
	}
	total := int64(len(raw))
	truncated := false
	if limit > 0 && total > limit {
		raw = raw[:limit]
		truncated = true
	}
	return encodePayload(raw, total, truncated, contentType)
}

func encodePayload(data []byte, total int64, truncated bool, contentType string) *lookingglass.CapturedPayload {
	encoding := "utf-8"
	encoded := string(data)
	if !utf8.Valid(data) {
		encoding = "base64"
		encoded = base64.StdEncoding.EncodeToString(data)
	}
	return &lookingglass.CapturedPayload{
		Encoding:    encoding,
		Data:        encoded,
		Size:        total,
		Truncated:   truncated,
		ContentType: contentType,
	}
}

func buildTLSInfo(state *tls.ConnectionState) *lookingglass.TLSInfo {
	if state == nil {
		return nil
	}
	version := tls.VersionName(state.Version)
	if version == "" {
		version = "0x" + strconv.FormatUint(uint64(state.Version), 16)
	}
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if cipher == "" {
		cipher = "0x" + strconv.FormatUint(uint64(state.CipherSuite), 16)
	}
	peerCerts := make([]string, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		if cert == nil {
			continue
		}
		peerCerts = append(peerCerts, cert.Subject.String())
	}
	return &lookingglass.TLSInfo{
		Version:            version,
		CipherSuite:        cipher,
		ServerName:         state.ServerName,
		NegotiatedProtocol: state.NegotiatedProtocol,
		PeerCertificates:   peerCerts,
	}
}