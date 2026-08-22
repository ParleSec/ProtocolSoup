package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/core"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

type ssfTestEnv struct {
	plugin *Plugin
	server *httptest.Server
	lg     *lookingglass.Engine
}

func startSSFTestEnv(t *testing.T) *ssfTestEnv {
	t.Helper()

	recvLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen receiver port: %v", err)
	}
	recvPort := recvLn.Addr().(*net.TCPAddr).Port
	if err := recvLn.Close(); err != nil {
		t.Fatalf("close receiver probe: %v", err)
	}

	t.Setenv("SSF_DATA_DIR", t.TempDir())
	t.Setenv("SSF_RECEIVER_PORT", strconv.Itoa(recvPort))
	t.Setenv("SSF_RECEIVER_TOKEN", "ssf-test-receiver-token")
	if os.Getenv("FEDERATION_SERVICE_URL") == "" {
		t.Setenv("FEDERATION_SERVICE_URL", "http://127.0.0.1:1")
	}

	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("key set: %v", err)
	}
	lg := lookingglass.NewEngine()
	p := NewPlugin()

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	if err := p.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL:      srv.URL,
		KeySet:       keySet,
		LookingGlass: lg,
	}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Shutdown(context.Background())
	})

	router := chi.NewRouter()
	router.Use(core.CaptureMiddleware(lg))
	ssfRouter := chi.NewRouter()
	p.RegisterRoutes(ssfRouter)
	router.Mount("/ssf", ssfRouter)
	router.Method(http.MethodGet, "/.well-known/ssf-configuration", ssfRouter)
	handler = router

	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", recvPort), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("receiver did not start on %d: %v", recvPort, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	return &ssfTestEnv{plugin: p, server: srv, lg: lg}
}

func (e *ssfTestEnv) session(t *testing.T) (id, token string) {
	t.Helper()
	sess, token, err := e.lg.CreateSession("ssf", "caep-session-revoked")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID, token
}

func (e *ssfTestEnv) doJSON(t *testing.T, method, path, sessionID string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, e.server.URL+path, reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sessionID != "" {
		req.Header.Set(lookingGlassSessionHeader, sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func (e *ssfTestEnv) sessionStreamID(t *testing.T, sessionID string) string {
	t.Helper()
	status, body := e.doJSON(t, http.MethodGet, "/ssf/stream", sessionID, nil)
	if status != http.StatusOK {
		t.Fatalf("list streams %d: %s", status, body)
	}
	var streams []Stream
	if err := json.Unmarshal(body, &streams); err != nil {
		t.Fatalf("decode stream list: %v %s", err, body)
	}
	if len(streams) > 0 && streams[0].ID != "" {
		return streams[0].ID
	}
	status, body = e.doJSON(t, http.MethodPost, "/ssf/stream", sessionID, map[string]any{
		"delivery": map[string]string{
			"method":       DeliveryMethodPush,
			"endpoint_url": e.server.URL + "/ssf/receiver/push",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create stream %d: %s", status, body)
	}
	var created Stream
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode created stream: %v %s", err, body)
	}
	if created.ID == "" {
		t.Fatal("created stream missing stream_id")
	}
	return created.ID
}

func compactSETFromSession(t *testing.T, env *ssfTestEnv, sessionID string) (token string, claims jwt.MapClaims) {
	t.Helper()
	sess, ok := env.lg.GetSession(sessionID)
	if !ok {
		t.Fatal("looking glass session missing")
	}
	for i := len(sess.Events) - 1; i >= 0; i-- {
		ev := sess.Events[i]
		if ev.Type != lookingglass.EventTypeCryptoOperation && ev.Type != lookingglass.EventTypeTokenIssued {
			continue
		}
		raw, ok := ev.Data["token"].(string)
		if !ok || raw == "" {
			continue
		}
		parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("parse SET: %v", err)
		}
		c, ok := parsed.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("SET claims type")
		}
		return raw, c
	}
	t.Fatal("SET compact JWT not emitted on Looking Glass bus")
	return "", nil
}

func TestSETClaimsRequired(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("action status %d: %s", status, body)
	}

	token, claims := compactSETFromSession(t, env, sessionID)
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse SET: %v", err)
	}
	if typ, _ := parsed.Header["typ"].(string); typ != "secevent+jwt" {
		t.Fatalf("typ header %q, want secevent+jwt", typ)
	}
	if _, ok := claims["sub"]; ok {
		t.Error("JWT sub MUST NOT be present (SSF §4.1.2)")
	}
	subID, ok := claims["sub_id"].(map[string]interface{})
	if !ok {
		t.Fatal("top-level sub_id MUST be present (SSF §3.1)")
	}
	if fmt.Sprint(subID["format"]) != SubjectFormatEmail {
		t.Errorf("sub_id.format %v", subID["format"])
	}
	for _, required := range []string{"iss", "iat", "jti", "aud", "events"} {
		if _, ok := claims[required]; !ok {
			t.Errorf("missing required SET claim %s", required)
		}
	}
	events, ok := claims["events"].(map[string]interface{})
	if !ok || len(events) == 0 {
		t.Fatal("events claim must be a non-empty object keyed by event URIs")
	}
	payload, ok := events[EventTypeSessionRevoked].(map[string]interface{})
	if !ok {
		t.Fatalf("events claim missing session-revoked URI, got %#v", events)
	}
	for _, forbidden := range []string{"session_id", "id", "event_type"} {
		if _, found := payload[forbidden]; found {
			t.Errorf("event object must not contain %s", forbidden)
		}
	}
	if _, inSET := claims["session_id"]; inSET {
		t.Error("session id must not appear inside the SET")
	}
	if _, nested := payload["subject"]; nested {
		t.Error("event object must not nest subject (SSF §3.1.2)")
	}
}

func TestPushDeliveryAcceptedNotOK(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("action status %d: %s", status, body)
	}

	sess, ok := env.lg.GetSession(sessionID)
	if !ok {
		t.Fatal("looking glass session missing")
	}

	found202 := false
	found200Push := false
	for _, ev := range sess.Events {
		if ev.Type != lookingglass.EventTypeHTTPExchange {
			continue
		}
		exchange, _ := ev.Data["exchange"].(lookingglass.CapturedExchange)
		if exchange.Request.URL == "" {
			// JSON round-trip through map[string]interface{}
			raw, _ := json.Marshal(ev.Data["exchange"])
			_ = json.Unmarshal(raw, &exchange)
		}
		ct := headerFirst(exchange.Request.Headers, "Content-Type")
		isPush := strings.Contains(strings.ToLower(ct), "secevent+jwt") ||
			strings.Contains(exchange.Request.URL, "/receiver/push") ||
			strings.Contains(exchange.Request.URL, "/ssf/push")
		if !isPush {
			continue
		}
		if exchange.Response.Status == http.StatusAccepted {
			found202 = true
		}
		if exchange.Response.Status == http.StatusOK {
			found200Push = true
		}
	}
	if !found202 {
		t.Fatal("expected push delivery hop with 202 Accepted")
	}
	if found200Push {
		t.Fatal("SET Recipient SHOULD NOT return 200 OK for push delivery")
	}
}

func TestPollSetsAndAcks(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)
	streamID := env.sessionStreamID(t, sessionID)

	status, body := env.doJSON(t, http.MethodPatch, "/ssf/stream?stream_id="+streamID, sessionID, map[string]any{
		"stream_id": streamID,
		"delivery":  map[string]string{"method": DeliveryMethodPoll},
	})
	if status != http.StatusOK {
		t.Fatalf("patch stream %d: %s", status, body)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/account-disabled", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
		"reason":             AccountDisabledReasonHijacking,
	})
	if status != http.StatusOK {
		t.Fatalf("action %d: %s", status, body)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"maxEvents":         10,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("poll %d: %s", status, body)
	}
	var poll PollResponse
	if err := json.Unmarshal(body, &poll); err != nil {
		t.Fatalf("decode poll: %v", err)
	}
	if len(poll.Sets) == 0 {
		t.Fatal("poll response missing sets map")
	}
	acks := make([]string, 0, len(poll.Sets))
	for jti, raw := range poll.Sets {
		if raw == "" || strings.Count(raw, ".") != 2 {
			t.Errorf("set for jti %s is not a compact JWT", jti)
		}
		acks = append(acks, jti)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"maxEvents":         10,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("retransmit poll %d: %s", status, body)
	}
	var again PollResponse
	if err := json.Unmarshal(body, &again); err != nil {
		t.Fatalf("decode retransmit poll: %v", err)
	}
	if len(again.Sets) == 0 {
		t.Fatal("unacknowledged SETs MUST be retransmitted")
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"ack":               acks,
		"maxEvents":         0,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("ack-only poll %d: %s", status, body)
	}
	var ackOnly PollResponse
	if err := json.Unmarshal(body, &ackOnly); err != nil {
		t.Fatalf("decode ack-only: %v", err)
	}
	if len(ackOnly.Sets) != 0 {
		t.Fatalf("maxEvents 0 must not return SETs, got %d", len(ackOnly.Sets))
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"maxEvents":         10,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("post-ack poll %d: %s", status, body)
	}
	var empty PollResponse
	if err := json.Unmarshal(body, &empty); err != nil {
		t.Fatalf("decode post-ack: %v", err)
	}
	if len(empty.Sets) != 0 {
		t.Fatal("acknowledged SETs must not be retransmitted")
	}
}

func TestPollSetErrsStopsRetransmit(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)
	streamID := env.sessionStreamID(t, sessionID)

	status, body := env.doJSON(t, http.MethodPatch, "/ssf/stream?stream_id="+streamID, sessionID, map[string]any{
		"stream_id": streamID,
		"delivery":  map[string]string{"method": DeliveryMethodPoll},
	})
	if status != http.StatusOK {
		t.Fatalf("patch stream %d: %s", status, body)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/account-disabled", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
		"reason":             AccountDisabledReasonHijacking,
	})
	if status != http.StatusOK {
		t.Fatalf("action %d: %s", status, body)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"maxEvents":         10,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("poll %d: %s", status, body)
	}
	var poll PollResponse
	if err := json.Unmarshal(body, &poll); err != nil {
		t.Fatalf("decode poll: %v", err)
	}
	if len(poll.Sets) == 0 {
		t.Fatal("poll response missing sets")
	}
	setErrs := map[string]map[string]string{}
	for jti := range poll.Sets {
		setErrs[jti] = map[string]string{"err": "invalid_key", "description": "test"}
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"setErrs":           setErrs,
		"maxEvents":         0,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("setErrs poll %d: %s", status, body)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/poll/"+streamID, sessionID, map[string]any{
		"maxEvents":         10,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("post-setErrs poll %d: %s", status, body)
	}
	var after PollResponse
	if err := json.Unmarshal(body, &after); err != nil {
		t.Fatalf("decode post-setErrs: %v", err)
	}
	if len(after.Sets) != 0 {
		t.Fatal("SETs reported in setErrs must not be retransmitted")
	}
}

func TestJTIReplayRejected(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("action %d: %s", status, body)
	}

	sess, ok := env.lg.GetSession(sessionID)
	if !ok {
		t.Fatal("looking glass session missing")
	}
	var token string
	for _, ev := range sess.Events {
		if raw, ok := ev.Data["token"].(string); ok && raw != "" {
			token = raw
			break
		}
	}
	if token == "" {
		t.Fatal("missing SET token")
	}

	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/ssf/receiver/push", strings.NewReader(token))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Authorization", "Bearer "+env.plugin.receiverToken)
	req.Header.Set(lookingGlassSessionHeader, sessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	replayBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusAccepted {
		t.Fatalf("replayed SET was accepted: %s", replayBody)
	}
}

func TestStreamCRUD(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)
	streamID := env.sessionStreamID(t, sessionID)

	status, body := env.doJSON(t, http.MethodGet, "/ssf/stream?stream_id="+streamID, sessionID, nil)
	if status != http.StatusOK {
		t.Fatalf("get stream %d: %s", status, body)
	}
	var stream Stream
	if err := json.Unmarshal(body, &stream); err != nil {
		t.Fatalf("decode stream: %v", err)
	}
	if stream.ID == "" || stream.Issuer == "" {
		t.Fatal("stream missing id or iss")
	}
	if stream.DeliveryMethod == "" {
		t.Fatal("nested delivery.method missing")
	}
	if len(stream.EventsSupported) == 0 {
		t.Fatal("events_supported missing")
	}
	var wire map[string]interface{}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["delivery_method"]; ok {
		t.Fatal("flat delivery_method must not appear on the stream")
	}
	delivery, _ := wire["delivery"].(map[string]interface{})
	if delivery["method"] == nil {
		t.Fatal("delivery.method required")
	}
	if _, ok := wire["events_delivered"]; !ok {
		t.Fatal("events_delivered required")
	}

	status, body = env.doJSON(t, http.MethodPatch, "/ssf/stream?stream_id="+streamID, sessionID, map[string]any{
		"stream_id": streamID,
		"delivery":  map[string]string{"method": DeliveryMethodPoll},
	})
	if status != http.StatusOK {
		t.Fatalf("patch %d: %s", status, body)
	}
	if err := json.Unmarshal(body, &stream); err != nil {
		t.Fatalf("decode patched stream: %v", err)
	}
	if stream.DeliveryMethod != DeliveryMethodPoll {
		t.Fatalf("delivery method %s", stream.DeliveryMethod)
	}

	status, body = env.doJSON(t, http.MethodPatch, "/ssf/stream", sessionID, map[string]any{
		"delivery": map[string]string{"method": DeliveryMethodPush},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("PATCH without stream_id status %d: %s", status, body)
	}

	status, _ = env.doJSON(t, http.MethodDelete, "/ssf/stream?stream_id="+streamID, sessionID, nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Fatalf("delete stream %d", status)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/stream", sessionID, map[string]any{
		"delivery": map[string]string{"method": DeliveryMethodPoll},
		"events_requested": []string{
			EventTypeSessionRevoked,
		},
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("create stream %d: %s", status, body)
	}
}

func TestLookingGlassSessionIsolation(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionA, _ := env.session(t)
	sessionB, _ := env.session(t)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", sessionA, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("action %d: %s", status, body)
	}

	sessA, _ := env.lg.GetSession(sessionA)
	sessB, _ := env.lg.GetSession(sessionB)
	if len(sessA.Events) == 0 {
		t.Fatal("session A should receive transmitter/receiver events")
	}
	if len(sessB.Events) != 0 {
		t.Fatalf("session B leaked %d events from session A", len(sessB.Events))
	}
}

func TestWellKnownSpecVersionAndIssuer(t *testing.T) {
	env := startSSFTestEnv(t)
	status, body := env.doJSON(t, http.MethodGet, "/.well-known/ssf-configuration", "", nil)
	if status != http.StatusOK {
		t.Fatalf("well-known %d: %s", status, body)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["spec_version"] != "1_0" {
		t.Fatalf("spec_version %v", cfg["spec_version"])
	}
	if cfg["issuer"] != env.server.URL {
		t.Fatalf("issuer %v want %s", cfg["issuer"], env.server.URL)
	}
	if _, ok := cfg["events_supported"]; ok {
		t.Fatal("events_supported belongs on the stream, not transmitter metadata")
	}
	members, _ := cfg["critical_subject_members"].([]interface{})
	joined := fmt.Sprint(members)
	if !strings.Contains(joined, "user") || !strings.Contains(joined, "session") {
		t.Fatalf("critical_subject_members %v", members)
	}
}

func TestVerifyNoContentRequiresStreamID(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)
	streamID := env.sessionStreamID(t, sessionID)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/verify", sessionID, map[string]string{
		"state": "abc",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("verify without stream_id %d: %s", status, body)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/verify", sessionID, map[string]string{
		"stream_id": streamID,
		"state":     "abc",
	})
	if status != http.StatusNoContent {
		t.Fatalf("verify %d: %s", status, body)
	}
	if len(body) != 0 {
		t.Fatalf("verify 204 must have empty body, got %s", body)
	}

	_, claims := compactSETFromSession(t, env, sessionID)
	events, _ := claims["events"].(map[string]interface{})
	payload, ok := events[EventTypeVerification].(map[string]interface{})
	if !ok {
		t.Fatalf("verification SET missing, events %#v", events)
	}
	if payload["state"] != "abc" {
		t.Fatalf("state %v", payload["state"])
	}
	subID, _ := claims["sub_id"].(map[string]interface{})
	if fmt.Sprint(subID["format"]) != SubjectFormatOpaque || fmt.Sprint(subID["id"]) != streamID {
		t.Fatalf("verification sub_id %#v", subID)
	}
}

func TestCAEPRISCRequiredMembers(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/assurance-level-change", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("assurance %d: %s", status, body)
	}
	_, claims := compactSETFromSession(t, env, sessionID)
	events, _ := claims["events"].(map[string]interface{})
	payload, _ := events[EventTypeAssuranceLevelChange].(map[string]interface{})
	if payload["namespace"] != AssuranceNamespaceNIST {
		t.Fatalf("namespace %v", payload["namespace"])
	}
	if payload["current_level"] == nil {
		t.Fatal("current_level required")
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/credential-compromise", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("compromise %d: %s", status, body)
	}
	_, claims = compactSETFromSession(t, env, sessionID)
	events, _ = claims["events"].(map[string]interface{})
	payload, _ = events[EventTypeCredentialCompromise].(map[string]interface{})
	if payload["credential_type"] != CredentialTypePassword {
		t.Fatalf("credential_type %v", payload["credential_type"])
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/device-compliance-change", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("compliance %d: %s", status, body)
	}
	_, claims = compactSETFromSession(t, env, sessionID)
	events, _ = claims["events"].(map[string]interface{})
	payload, _ = events[EventTypeDeviceComplianceChange].(map[string]interface{})
	if payload["current_status"] != ComplianceStatusNonCompliant {
		t.Fatalf("current_status %v want not-compliant", payload["current_status"])
	}
	if payload["previous_status"] != ComplianceStatusCompliant {
		t.Fatalf("previous_status %v", payload["previous_status"])
	}
	if _, ok := payload["reason_admin"]; !ok {
		t.Fatal("CAEP Interop Device Compliance: reason_admin MUST be a non-empty object")
	}
	subID, _ := claims["sub_id"].(map[string]interface{})
	if fmt.Sprint(subID["format"]) != SubjectFormatComplex {
		t.Fatalf("device-compliance sub_id format %v want complex [SSF §3 / CAEP §3.5]", subID["format"])
	}
	device, _ := subID["device"].(map[string]interface{})
	if fmt.Sprint(device["format"]) != SubjectFormatIssuerSub || fmt.Sprint(device["sub"]) == "" {
		t.Fatalf("device member %#v [CAEP §3.5 example]", device)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/sessions-revoked", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("sessions-revoked %d: %s", status, body)
	}
	_, claims = compactSETFromSession(t, env, sessionID)
	events, _ = claims["events"].(map[string]interface{})
	if _, ok := events[EventTypeSessionRevoked]; !ok {
		t.Fatalf("lab sessions-revoked must emit CAEP session-revoked, got %#v", events)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/account-disabled", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
		"reason":             "admin prose must not be the RISC reason",
	})
	if status != http.StatusOK {
		t.Fatalf("account-disabled %d: %s", status, body)
	}
	_, claims = compactSETFromSession(t, env, sessionID)
	events, _ = claims["events"].(map[string]interface{})
	payload, _ = events[EventTypeAccountDisabled].(map[string]interface{})
	if _, ok := payload["reason"]; ok {
		t.Fatalf("RISC reason must be hijacking|bulk-account or omitted, got %#v", payload["reason"])
	}
}

func TestFederationCAEPHopAfterSessionRevoked(t *testing.T) {
	var gotAuth, gotEmail string
	fed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/demo/caep/revoke-subject" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Email string `json:"email"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotEmail = body.Email
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{
			"sessions_deleted":       1,
			"refresh_tokens_revoked": 1,
			"access_tokens_revoked":  1,
		})
	}))
	t.Cleanup(fed.Close)

	t.Setenv("FEDERATION_SERVICE_URL", fed.URL)
	t.Setenv("SSF_TO_FEDERATION_TOKEN", "ssf-federation-caep-lab")

	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)
	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("action %d: %s", status, body)
	}
	if gotEmail != "alice@example.com" {
		t.Fatalf("federation email %q", gotEmail)
	}
	if gotAuth != "Bearer ssf-federation-caep-lab" {
		t.Fatalf("federation auth %q", gotAuth)
	}

	sess, _ := env.lg.GetSession(sessionID)
	foundHop := false
	for _, ev := range sess.Events {
		if ev.Type != lookingglass.EventTypeHTTPExchange {
			continue
		}
		raw, _ := json.Marshal(ev.Data["exchange"])
		if strings.Contains(string(raw), "/oauth2/demo/caep/revoke-subject") {
			foundHop = true
			break
		}
		if strings.Contains(fmt.Sprint(ev.Data), "revoke-subject") {
			foundHop = true
			break
		}
	}
	if !foundHop {
		t.Fatal("Looking Glass bus missing federation CAEP HTTP hop")
	}
}

func headerFirst(h map[string][]string, key string) string {
	if h == nil {
		return ""
	}
	if vals := h[key]; len(vals) > 0 {
		return vals[0]
	}
	for k, vals := range h {
		if strings.EqualFold(k, key) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}
