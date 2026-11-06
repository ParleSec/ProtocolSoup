package capture

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/google/uuid"
)

// The conformance client's side of a hosted-wallet exchange. The client
// calls the wallet's own API, which is recorded like any other request; the
// wallet answers with _protocol_exchanges, its own record of every HTTP hop
// it made for the call. Those hops join the artefact as exchanges recorded
// by the hosted wallet, so a requirement page shows the whole process: the
// call, then what the wallet sent and received.

// WalletSessionLifetime is how long the hosted wallet keeps a session, and
// the Credentials in it, after its last use (WALLET_SESSION_TTL default).
const WalletSessionLifetime = 20 * time.Minute

// walletFanOut is how many requests one wallet call can make the wallet send
// to the main app: a fresh session's issuance is metadata, authorization
// server metadata, token, nonce, credential, JWKS and notification, with a
// DPoP nonce retry or two. Each wallet call waits that many request slots,
// so the wallet's requests on the client's behalf stay within the main
// app's rate limit too.
const walletFanOut = 10

// WalletCall is one call to the hosted wallet's API.
type WalletCall struct {
	// Path is the wallet route, such as /api/present.
	Path string
	// Body is the JSON request body.
	Body map[string]any
	// Session isolates the wallet's credential store for this scenario. A
	// fresh value per scenario keeps one scenario's Credentials from changing
	// which hops another makes.
	Session string
	// Setup marks preparation the artefact is not about, such as having the
	// wallet obtain the Credential a later call presents. The call is still
	// a real request to the wallet; neither it nor its hops are recorded.
	Setup bool
}

// WalletResult is what the wallet answered, with its recorded hops.
type WalletResult struct {
	Status int
	Body   map[string]any
	// Hops are the wallet's _protocol_exchanges, in order.
	Hops []WalletHop
}

// WalletHop is one outbound HTTP exchange as the hosted wallet recorded it
// (cmd/walletharness protocolHop). Bodies are the exact bytes on the wire,
// base64 when *_body_encoding is "base64".
type WalletHop struct {
	Step                string            `json:"step"`
	RFCReference        string            `json:"rfc_reference"`
	Method              string            `json:"method"`
	URL                 string            `json:"url"`
	RequestHeaders      map[string]string `json:"request_headers"`
	RequestBody         string            `json:"request_body"`
	RequestBodyEncoding string            `json:"request_body_encoding"`
	// RequestPlaintext and ResponsePlaintext are what the wallet encrypted
	// into, and decrypted from, a body that is a JWE on the wire.
	RequestPlaintext     string            `json:"request_plaintext"`
	ResponsePlaintext    string            `json:"response_plaintext"`
	ResponseStatus       int               `json:"response_status"`
	ResponseHeaders      map[string]string `json:"response_headers"`
	ResponseBody         string            `json:"response_body"`
	ResponseBodyEncoding string            `json:"response_body_encoding"`
	DurationMS           int64             `json:"duration_ms"`
	Actor                string            `json:"actor"`
	Extra                map[string]any    `json:"extra"`
}

// Error returns the wallet's "error" member, or "".
func (r *WalletResult) Error() string {
	value, _ := r.Body["error"].(string)
	return value
}

// ErrorDescription returns the wallet's "error_description", or "".
func (r *WalletResult) ErrorDescription() string {
	value, _ := r.Body["error_description"].(string)
	return value
}

// Hop returns the first recorded hop whose step is step, or nil.
func (r *WalletResult) Hop(step string) *WalletHop {
	for i := range r.Hops {
		if r.Hops[i].Step == step {
			return &r.Hops[i]
		}
	}
	return nil
}

// DPoPNonceChallenge reports whether the hop was answered with an RFC 9449
// nonce challenge rather than the endpoint's own answer: the use_dpop_nonce
// error from an authorization server (Section 8) or in a resource server's
// WWW-Authenticate header (Section 9). The wallet retries such a request, so
// the hop that follows carries the endpoint's answer.
func (h *WalletHop) DPoPNonceChallenge() bool {
	if h.ResponseStatus != http.StatusBadRequest && h.ResponseStatus != http.StatusUnauthorized {
		return false
	}
	for name, value := range h.ResponseHeaders {
		if strings.EqualFold(name, "WWW-Authenticate") && strings.Contains(value, "use_dpop_nonce") {
			return true
		}
	}
	var body struct {
		Error string `json:"error"`
	}
	return json.Unmarshal([]byte(h.ResponseBody), &body) == nil && body.Error == "use_dpop_nonce"
}

// CompletedHop returns the first hop labelled step that is not a DPoP nonce
// challenge, or nil. The production wallet's requests are DPoP-bound, so
// each endpoint may answer the first attempt with a challenge.
func (r *WalletResult) CompletedHop(step string) *WalletHop {
	for i := range r.Hops {
		if r.Hops[i].Step == step && !r.Hops[i].DPoPNonceChallenge() {
			return &r.Hops[i]
		}
	}
	return nil
}

// NewWalletSession returns a fresh session identifier for X-Wallet-Session.
func NewWalletSession() string {
	return "conformance-" + uuid.NewString()
}

// CallWallet sends call to the hosted wallet, recorded, then adds the hops
// the wallet recorded for it to the artefact. It fails only when the wallet
// cannot be reached or does not answer JSON; the caller reads the status
// and body to decide the outcome.
func CallWallet(ctx context.Context, env *Env, call WalletCall) (*WalletResult, error) {
	if env.WalletURL == "" {
		return nil, fmt.Errorf("this run has no hosted wallet")
	}
	req, err := NewJSON(env.WalletURL+call.Path, call.Body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if call.Session != "" {
		req.Header.Set("X-Wallet-Session", call.Session)
	}
	if err := env.Pace(ctx, walletFanOut); err != nil {
		return nil, err
	}
	send := env.Do
	if call.Setup {
		send = env.Setup
	}
	resp, err := send(ctx, req)
	if err != nil {
		return nil, err
	}
	body, err := resp.JSON()
	if err != nil {
		return nil, fmt.Errorf("wallet %s: %w", call.Path, err)
	}
	result := &WalletResult{Status: resp.Status, Body: body}
	if raw, ok := body["_protocol_exchanges"]; ok {
		encoded, err := json.Marshal(raw)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(encoded, &result.Hops); err != nil {
			return nil, fmt.Errorf("wallet %s: decode _protocol_exchanges: %w", call.Path, err)
		}
	}
	// Whatever the wallet obtained stays in its session store until the
	// session expires.
	env.NoteExpiry(WalletSessionLifetime)
	if !call.Setup {
		env.recorder.Append(walletExchanges(result.Hops))
	}
	return result, nil
}

// walletExchanges converts the wallet's hops into captured exchanges. Each
// is marked as recorded by the hosted wallet: the conformance client did not
// see these requests, and the wallet records no protocol version or TLS
// details, so those are left empty rather than filled in.
func walletExchanges(hops []WalletHop) []lookingglass.CapturedExchange {
	exchanges := make([]lookingglass.CapturedExchange, 0, len(hops))
	for _, hop := range hops {
		requestBody := hopPayload(hop.RequestBody, hop.RequestBodyEncoding, hop.RequestHeaders["Content-Type"])
		responseBody := hopPayload(hop.ResponseBody, hop.ResponseBodyEncoding, hop.ResponseHeaders["Content-Type"])
		exchanges = append(exchanges, lookingglass.CapturedExchange{
			ID: uuid.NewString(),
			Request: lookingglass.CapturedMessage{
				Method:  hop.Method,
				URL:     hop.URL,
				Host:    hostOf(hop.URL),
				Headers: singleValued(hop.RequestHeaders),
				Body:    requestBody,
			},
			Response: lookingglass.CapturedMessage{
				Status:     hop.ResponseStatus,
				StatusText: http.StatusText(hop.ResponseStatus),
				Headers:    singleValued(hop.ResponseHeaders),
				Body:       responseBody,
			},
			Timing: lookingglass.ExchangeTiming{DurationMicro: hop.DurationMS * 1000},
			Meta: lookingglass.CaptureMeta{
				CaptureSource:            "hosted_wallet",
				HeaderOrderPreserved:     false,
				RequestBodyReadBytes:     payloadSize(requestBody),
				ResponseBodyWrittenBytes: payloadSize(responseBody),
			},
		})
	}
	return exchanges
}

// hopPayload rebuilds the exact body bytes the wallet recorded.
func hopPayload(body, encoding, contentType string) *lookingglass.CapturedPayload {
	if body == "" {
		return nil
	}
	data := []byte(body)
	if encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(body)
		if err == nil {
			data = decoded
		}
	}
	return lookingglass.EncodePayload(data, int64(len(data)), false, contentType)
}

func payloadSize(payload *lookingglass.CapturedPayload) int64 {
	if payload == nil {
		return 0
	}
	return payload.Size
}

// singleValued widens the wallet's joined header map to the captured form.
// The wallet joins repeated values with ", ", which is how HTTP allows them
// to be combined, so each value is kept as the wallet recorded it.
func singleValued(headers map[string]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for key, value := range headers {
		out[key] = []string{value}
	}
	return out
}

func hostOf(rawURL string) string {
	rest, found := strings.CutPrefix(rawURL, "https://")
	if !found {
		rest, found = strings.CutPrefix(rawURL, "http://")
		if !found {
			return ""
		}
	}
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// WalletStatusText names a wallet HTTP status for a scenario error.
func WalletStatusText(status int) string {
	return strconv.Itoa(status) + " " + http.StatusText(status)
}
