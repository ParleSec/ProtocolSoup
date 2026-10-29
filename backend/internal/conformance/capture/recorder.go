// Package capture drives the deployed ProtocolSoup servers through a passing
// and a failing scenario per conformance requirement and records every HTTP
// exchange in full, for cmd/conformance-capture. Requests that a conformant
// party would never send come from the conformance client, which is always
// labelled as such; the hosted wallet only ever acts as itself.
package capture

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/google/uuid"
)

// UserAgent identifies the conformance client on every request it sends.
const UserAgent = "ProtocolSoup-Conformance-Client/1"

// Recorder is an http.RoundTripper that records each exchange it carries as
// a lookingglass.CapturedExchange. Bodies are kept whole: unlike the Looking
// Glass middleware there is no capture limit, because an artefact shows the
// payload in full or not at all.
type Recorder struct {
	base http.RoundTripper

	mu        sync.Mutex
	exchanges []lookingglass.CapturedExchange
}

// NewRecorder wraps base, or NewTransport() when base is nil.
func NewRecorder(base http.RoundTripper) *Recorder {
	if base == nil {
		base = NewTransport()
	}
	return &Recorder{base: base}
}

// NewTransport never asks for compression, so a recorded response body is
// the bytes the server sent rather than a transparently decoded copy.
func NewTransport() http.RoundTripper {
	return &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
}

// RoundTrip sends req and records the exchange.
func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var requestBody []byte
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		requestBody = body
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}

	start := time.Now()
	resp, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	responseBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	end := time.Now()
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(responseBody))

	r.mu.Lock()
	r.exchanges = append(r.exchanges, exchangeFor(req, requestBody, resp, responseBody, start, end))
	r.mu.Unlock()
	return resp, nil
}

// Take returns the exchanges recorded since the last call and clears them.
func (r *Recorder) Take() []lookingglass.CapturedExchange {
	r.mu.Lock()
	defer r.mu.Unlock()
	taken := r.exchanges
	r.exchanges = nil
	return taken
}

func exchangeFor(req *http.Request, requestBody []byte, resp *http.Response, responseBody []byte, start, end time.Time) lookingglass.CapturedExchange {
	requestHeaders := cloneHeader(req.Header)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	requestHeaders["Host"] = []string{host}
	if len(requestBody) > 0 {
		requestHeaders["Content-Length"] = []string{strconv.Itoa(len(requestBody))}
	}
	responseHeaders := cloneHeader(resp.Header)

	// The request travelled over the protocol the connection negotiated,
	// which the response reports; req.Proto is only the client default.
	proto := resp.Proto
	statusText := http.StatusText(resp.StatusCode)
	requestType := req.Header.Get("Content-Type")
	responseType := resp.Header.Get("Content-Type")

	return lookingglass.CapturedExchange{
		ID: uuid.NewString(),
		Request: lookingglass.CapturedMessage{
			Method:  req.Method,
			URL:     req.URL.String(),
			Host:    host,
			Proto:   proto,
			Headers: requestHeaders,
			Body:    payload(requestBody, requestType),
			Raw:     payload(lookingglass.RawRequest(req.Method, req.URL.RequestURI(), proto, requestHeaders, requestBody), requestType),
		},
		Response: lookingglass.CapturedMessage{
			Status:     resp.StatusCode,
			StatusText: statusText,
			Proto:      proto,
			Headers:    responseHeaders,
			Body:       payload(responseBody, responseType),
			Raw:        payload(lookingglass.RawResponse(proto, resp.StatusCode, statusText, responseHeaders, responseBody), responseType),
		},
		Timing: lookingglass.ExchangeTiming{
			StartUnixMicro: start.UnixMicro(),
			EndUnixMicro:   end.UnixMicro(),
			DurationMicro:  end.Sub(start).Microseconds(),
		},
		TLS: lookingglass.OutboundTLSInfo(resp.TLS, nil),
		Meta: lookingglass.CaptureMeta{
			CaptureSource:            "conformance_client",
			HeaderOrderPreserved:     false,
			BodyLimitBytes:           0,
			RequestBodyReadBytes:     int64(len(requestBody)),
			ResponseBodyWrittenBytes: int64(len(responseBody)),
			RawReconstructed:         true,
		},
	}
}

func payload(data []byte, contentType string) *lookingglass.CapturedPayload {
	if len(data) == 0 {
		return nil
	}
	return lookingglass.EncodePayload(data, int64(len(data)), false, contentType)
}

func cloneHeader(header http.Header) map[string][]string {
	clone := make(map[string][]string, len(header))
	for key, values := range header {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}
