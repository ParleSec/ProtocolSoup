package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultRequestsPerMinute keeps the client well under the 100 requests per
// minute per IP that production applies to its protocol routes.
const DefaultRequestsPerMinute = 60

// Env is what a scenario uses to talk to the deployed servers.
type Env struct {
	// BaseURL is the main app, e.g. https://protocolsoup.com.
	BaseURL string
	// WalletURL is the hosted wallet, e.g. https://wallet.protocolsoup.com.
	WalletURL string
	// CounterpartyURL is the deliberately broken counterparty, when deployed.
	CounterpartyURL string

	recorded   *http.Client
	unrecorded *http.Client
	recorder   *Recorder
	pace       <-chan time.Time

	mu        sync.Mutex
	expiresAt time.Time
}

// NewEnv builds an Env whose recorded requests go through recorder. Both
// clients return redirects instead of following them, so each hop is an
// explicit, recorded request.
func NewEnv(baseURL, walletURL, counterpartyURL string, recorder *Recorder, requestsPerMinute int) *Env {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if requestsPerMinute <= 0 {
		requestsPerMinute = DefaultRequestsPerMinute
	}
	return &Env{
		BaseURL:         strings.TrimRight(baseURL, "/"),
		WalletURL:       strings.TrimRight(walletURL, "/"),
		CounterpartyURL: strings.TrimRight(counterpartyURL, "/"),
		recorded:        &http.Client{Transport: recorder, CheckRedirect: noRedirect, Timeout: 30 * time.Second},
		unrecorded:      &http.Client{Transport: NewTransport(), CheckRedirect: noRedirect, Timeout: 30 * time.Second},
		recorder:        recorder,
		pace:            time.Tick(time.Minute / time.Duration(requestsPerMinute)),
	}
}

// Response is a fully read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body as a JSON object.
func (r *Response) JSON() (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(r.Body, &out); err != nil {
		return nil, fmt.Errorf("decode %d response: %w: %s", r.Status, err, truncate(r.Body))
	}
	return out, nil
}

// Error returns the OAuth-style "error" member of a JSON body, or "".
func (r *Response) Error() string {
	body, err := r.JSON()
	if err != nil {
		return ""
	}
	value, _ := body["error"].(string)
	return value
}

// Do sends req and records the exchange as part of the current artefact.
func (e *Env) Do(ctx context.Context, req *http.Request) (*Response, error) {
	return e.send(ctx, e.recorded, req)
}

// Setup sends req without recording it. Scenarios use it for preparation
// the artefact is not about, such as creating the offer whose token
// exchange is the subject; it is still a real request to the same server.
func (e *Env) Setup(ctx context.Context, req *http.Request) (*Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	return e.send(ctx, e.unrecorded, req)
}

func (e *Env) send(ctx context.Context, client *http.Client, req *http.Request) (*Response, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-e.pace:
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// NoteExpiry records that something the run obtained (a token, a code, a
// request session) stays usable for lifetime from now. The artefact set is
// withheld until the latest such moment has passed.
func (e *Env) NoteExpiry(lifetime time.Duration) {
	at := time.Now().Add(lifetime)
	e.mu.Lock()
	if at.After(e.expiresAt) {
		e.expiresAt = at
	}
	e.mu.Unlock()
}

// PublishAfter is the latest expiry noted so far.
func (e *Env) PublishAfter() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.expiresAt
}

// NewForm builds a form-encoded POST.
func NewForm(target string, form url.Values) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// NewJSON builds a JSON POST.
func NewJSON(target string, body any) (*http.Request, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(string(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func truncate(body []byte) string {
	const limit = 300
	if len(body) > limit {
		return string(body[:limit]) + "..."
	}
	return string(body)
}
