package ssf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func TestCAEPInteropTransmitterMetadata(t *testing.T) {
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
		t.Fatalf("spec_version %v, want 1_0 [CAEPINTEROP Specification Version]", cfg["spec_version"])
	}
	if cfg["issuer"] != env.server.URL {
		t.Fatalf("issuer %v want %s [SSF §7.2.4]", cfg["issuer"], env.server.URL)
	}
	if cfg["default_subjects"] != "ALL" {
		t.Fatalf("default_subjects %v, want ALL [CAEPINTEROP Implicitly Added Subjects]", cfg["default_subjects"])
	}
	schemes, _ := cfg["authorization_schemes"].([]interface{})
	foundRFC6749 := false
	for _, raw := range schemes {
		obj, _ := raw.(map[string]interface{})
		if fmt.Sprint(obj["spec_urn"]) == "urn:ietf:rfc:6749" {
			foundRFC6749 = true
		}
	}
	if !foundRFC6749 {
		t.Fatalf("authorization_schemes missing urn:ietf:rfc:6749, got %#v", schemes)
	}
	methods, _ := cfg["delivery_methods_supported"].([]interface{})
	joined := fmt.Sprint(methods)
	if !strings.Contains(joined, DeliveryMethodPush) || !strings.Contains(joined, DeliveryMethodPoll) {
		t.Fatalf("delivery_methods_supported %v", methods)
	}
	for _, key := range []string{"jwks_uri", "configuration_endpoint", "status_endpoint", "verification_endpoint", "add_subject_endpoint", "remove_subject_endpoint"} {
		val, _ := cfg[key].(string)
		if val == "" {
			t.Errorf("missing %s [CAEPINTEROP Transmitters]", key)
		}
	}
	if cfg["add_subject_endpoint"] == cfg["remove_subject_endpoint"] {
		t.Fatal("add_subject_endpoint and remove_subject_endpoint MUST be distinct [SSF §7.1]")
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", "", map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("action %d: %s", status, body)
	}
	stream, err := env.plugin.storage.GetDefaultStream(t.Context(), env.plugin.baseURL)
	if err != nil {
		t.Fatal(err)
	}
	events, err := env.plugin.storage.GetEvents(t.Context(), stream.ID, "", 1)
	if err != nil || len(events) == 0 {
		t.Fatalf("stored events: %v len=%d", err, len(events))
	}
	decoded, err := DecodeWithoutValidation(events[0].SETToken)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Issuer != cfg["issuer"] {
		t.Fatalf("SET iss %q != metadata issuer %v [SSF §7.2.4]", decoded.Issuer, cfg["issuer"])
	}
}

func TestStreamIDLifecycleWithoutLookingGlassHeader(t *testing.T) {
	env := startSSFTestEnv(t)
	_ = env.plugin.storage.DeleteStream(t.Context(), "default")

	status, body := env.doJSON(t, http.MethodGet, "/ssf/stream", "", nil)
	if status != http.StatusOK {
		t.Fatalf("empty list %d: %s", status, body)
	}
	if strings.TrimSpace(string(body)) != "[]" && !bytes.Equal(bytes.TrimSpace(body), []byte("[]\n")) {
		var listed []Stream
		if err := json.Unmarshal(body, &listed); err != nil {
			t.Fatalf("list must be a JSON array, got %s", body)
		}
		if len(listed) != 0 {
			t.Fatalf("want empty list for new receiver, got %#v", listed)
		}
	}
	req, err := http.NewRequest(http.MethodGet, env.server.URL+"/ssf/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q, want no-store [SSF §8.1.1.2]", resp.Header.Get("Cache-Control"))
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/stream", "", map[string]any{
		"delivery": map[string]string{
			"method":       DeliveryMethodPush,
			"endpoint_url": "https://receiver.example/ssf-push",
		},
		"events_requested": []string{
			EventTypeSessionRevoked,
			"https://example.invalid/unknown-event",
		},
		"description": "caep interop",
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d: %s", status, body)
	}
	var created Stream
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || strings.HasPrefix(created.ID, "session-") {
		t.Fatalf("stream_id %q", created.ID)
	}
	if created.DeliveryMethod != DeliveryMethodPush || created.DeliveryEndpoint != "https://receiver.example/ssf-push" {
		t.Fatalf("delivery %#v %#v", created.DeliveryMethod, created.DeliveryEndpoint)
	}
	delivered := eventsDelivered(created.EventsSupported, created.EventsRequested)
	if len(delivered) != 1 || delivered[0] != EventTypeSessionRevoked {
		t.Fatalf("events_delivered %v (unknown URIs must be ignored)", delivered)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/stream", "", map[string]any{})
	if status != http.StatusCreated {
		t.Fatalf("create default poll %d: %s", status, body)
	}
	var pollStream Stream
	if err := json.Unmarshal(body, &pollStream); err != nil {
		t.Fatal(err)
	}
	if pollStream.DeliveryMethod != DeliveryMethodPoll {
		t.Fatalf("absent delivery must default to poll URN, got %s [SSF §8.1.1.1]", pollStream.DeliveryMethod)
	}
	wantPollURL := env.server.URL + "/ssf/poll/" + pollStream.ID
	if pollStream.DeliveryEndpoint != wantPollURL {
		t.Fatalf("poll endpoint_url %q want %q [SSF §6.1.2 unique per stream]", pollStream.DeliveryEndpoint, wantPollURL)
	}

	status, body = env.doJSON(t, http.MethodGet, "/ssf/stream?stream_id="+created.ID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("get one %d: %s", status, body)
	}
	var one Stream
	if err := json.Unmarshal(body, &one); err != nil {
		t.Fatal(err)
	}
	if one.ID != created.ID {
		t.Fatalf("got %s want %s", one.ID, created.ID)
	}

	status, body = env.doJSON(t, http.MethodGet, "/ssf/status?stream_id="+created.ID, "", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %s", status, body)
	}
	var st map[string]interface{}
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st["stream_id"] != created.ID || st["status"] != StreamStatusEnabled {
		t.Fatalf("status body %#v [SSF §8.1.2.1]", st)
	}

	status, body = env.doJSON(t, http.MethodGet, "/ssf/status", "", nil)
	if status == http.StatusOK {
		t.Fatalf("status without stream_id must not succeed: %s", body)
	}

	status, _ = env.doJSON(t, http.MethodDelete, "/ssf/stream?stream_id="+created.ID, "", nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete %d", status)
	}
	status, _ = env.doJSON(t, http.MethodGet, "/ssf/stream?stream_id="+created.ID, "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("deleted stream GET %d, want 404", status)
	}
}

func TestOAuthResourceServerIsolationAndQueryToken(t *testing.T) {
	asKeys, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(asKeys.PublicJWKS())
	}))
	t.Cleanup(jwksSrv.Close)

	t.Setenv("SSF_AS_ISSUER", "https://as.example")
	t.Setenv("SSF_AS_JWKS_URI", jwksSrv.URL)
	env := startSSFTestEnv(t)

	jwtSvc := crypto.NewJWTService(asKeys, "https://as.example")
	tokenA, err := jwtSvc.CreateAccessToken("client-a", env.server.URL, ScopeSSFManage, 15*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	tokenB, err := jwtSvc.CreateAccessToken("client-b", env.server.URL, ScopeSSFManage, 15*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	readOnly, err := jwtSvc.CreateAccessToken("client-a", env.server.URL, ScopeSSFRead, 15*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}

	createBody := map[string]any{
		"delivery": map[string]string{
			"method":       DeliveryMethodPush,
			"endpoint_url": "https://receiver.example/ssf-push",
		},
	}
	status, body := env.doBearerJSON(t, http.MethodPost, "/ssf/stream", tokenA, createBody)
	if status != http.StatusCreated {
		t.Fatalf("create %d: %s", status, body)
	}
	var created Stream
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	status, body = env.doBearerJSON(t, http.MethodGet, "/ssf/stream?stream_id="+created.ID, tokenB, nil)
	if status != http.StatusForbidden {
		t.Fatalf("client-b GET %d, want 403: %s", status, body)
	}
	status, body = env.doBearerJSON(t, http.MethodDelete, "/ssf/stream?stream_id="+created.ID, tokenB, nil)
	if status != http.StatusForbidden {
		t.Fatalf("client-b DELETE %d, want 403: %s", status, body)
	}
	status, body = env.doBearerJSON(t, http.MethodPost, "/ssf/verify", tokenB, map[string]string{"stream_id": created.ID})
	if status != http.StatusForbidden {
		t.Fatalf("client-b verify %d, want 403: %s", status, body)
	}

	status, body = env.doBearerJSON(t, http.MethodPost, "/ssf/stream", readOnly, createBody)
	if status != http.StatusForbidden {
		t.Fatalf("ssf.read create %d, want 403 insufficient_scope: %s", status, body)
	}
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/ssf/stream", bytes.NewReader(mustJSON(createBody)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+readOnly)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("WWW-Authenticate %q [RFC 6750 §3.1]", resp.Header.Get("WWW-Authenticate"))
	}

	q := env.server.URL + "/ssf/stream?access_token=" + tokenA
	req, err = http.NewRequest(http.MethodGet, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("query access_token was accepted: %s", raw)
	}
}

func TestSETProfileConformance(t *testing.T) {
	env := startSSFTestEnv(t)
	sessionID, _ := env.session(t)
	streamID := env.sessionStreamID(t, sessionID)

	assertSET := func(t *testing.T, token string, eventURI string, check func(jwt.MapClaims, map[string]interface{})) {
		t.Helper()
		parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(parsed.Header["typ"]) != "secevent+jwt" {
			t.Fatalf("typ %v [SSF §4.1.1]", parsed.Header["typ"])
		}
		if fmt.Sprint(parsed.Header["alg"]) != "RS256" {
			t.Fatalf("alg %v [CAEPINTEROP Event Signatures]", parsed.Header["alg"])
		}
		claims, _ := parsed.Claims.(jwt.MapClaims)
		if _, ok := claims["sub"]; ok {
			t.Error("JWT sub MUST NOT be present [SSF §4.1.2]")
		}
		if _, ok := claims["exp"]; ok {
			t.Error("JWT exp MUST NOT be present [SSF §4.1.7]")
		}
		if claims["iss"] != env.plugin.baseURL {
			t.Errorf("iss %v want %s", claims["iss"], env.plugin.baseURL)
		}
		if claims["txn"] == nil || fmt.Sprint(claims["txn"]) == "" {
			t.Error("txn SHOULD be present [SSF §4.1.9]")
		}
		subID, _ := claims["sub_id"].(map[string]interface{})
		if subID == nil {
			t.Fatal("sub_id required [SSF §3.1]")
		}
		events, _ := claims["events"].(map[string]interface{})
		if len(events) != 1 {
			t.Fatalf("events must contain exactly one event, got %#v [CAEPINTEROP]", events)
		}
		payload, _ := events[eventURI].(map[string]interface{})
		if payload == nil {
			t.Fatalf("missing %s in %#v", eventURI, events)
		}
		check(claims, payload)
	}

	status, body := env.doJSON(t, http.MethodPost, "/ssf/actions/session-revoked", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("session-revoked %d: %s", status, body)
	}
	token, _ := compactSETFromSession(t, env, sessionID)
	assertSET(t, token, EventTypeSessionRevoked, func(_ jwt.MapClaims, payload map[string]interface{}) {
		reason, _ := payload["reason_admin"].(map[string]interface{})
		if reason == nil || fmt.Sprint(reason["en"]) == "" {
			t.Fatalf("reason_admin must be a non-empty object, got %#v", payload["reason_admin"])
		}
	})

	status, body = env.doJSON(t, http.MethodPost, "/ssf/actions/credential-change", sessionID, map[string]string{
		"subject_identifier": "alice@example.com",
	})
	if status != http.StatusOK {
		t.Fatalf("credential-change %d: %s", status, body)
	}
	token, _ = compactSETFromSession(t, env, sessionID)
	assertSET(t, token, EventTypeCredentialChange, func(_ jwt.MapClaims, payload map[string]interface{}) {
		if payload["change_type"] == nil || payload["credential_type"] == nil {
			t.Fatalf("credential-change missing members %#v", payload)
		}
		reason, _ := payload["reason_admin"].(map[string]interface{})
		if reason == nil || fmt.Sprint(reason["en"]) == "" {
			t.Fatalf("credential-change reason_admin %#v", payload["reason_admin"])
		}
	})

	status, body = env.doJSON(t, http.MethodPost, "/ssf/verify", sessionID, map[string]string{
		"stream_id": streamID,
	})
	if status != http.StatusNoContent {
		t.Fatalf("verify without state %d: %s", status, body)
	}
	token, _ = compactSETFromSession(t, env, sessionID)
	assertSET(t, token, EventTypeVerification, func(claims jwt.MapClaims, payload map[string]interface{}) {
		subID, _ := claims["sub_id"].(map[string]interface{})
		if fmt.Sprint(subID["format"]) != SubjectFormatOpaque || fmt.Sprint(subID["id"]) != streamID {
			t.Fatalf("verification sub_id %#v", subID)
		}
		if _, ok := payload["state"]; ok {
			t.Fatalf("state must be omitted when not supplied, got %#v", payload["state"])
		}
	})

	if _, err := env.plugin.transmitter.TriggerStreamUpdated(t.Context(), streamID, StreamStatusPaused, "lab", sessionID); err != nil {
		t.Fatal(err)
	}
	token, _ = compactSETFromSession(t, env, sessionID)
	assertSET(t, token, EventTypeStreamUpdated, func(claims jwt.MapClaims, payload map[string]interface{}) {
		subID, _ := claims["sub_id"].(map[string]interface{})
		if fmt.Sprint(subID["id"]) != streamID {
			t.Fatalf("stream-updated sub_id %#v", subID)
		}
		if payload["status"] != StreamStatusPaused {
			t.Fatalf("status %v", payload["status"])
		}
	})

	bad := SETClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    env.plugin.baseURL,
			Subject:   "must-not-be-present",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        "bad-jti",
			Audience:  jwt.ClaimStrings{env.plugin.baseURL},
		},
		Events:    map[string]interface{}{EventTypeSessionRevoked: map[string]string{}},
		SubjectID: &SETSubject{Format: SubjectFormatEmail, Email: "alice@example.com"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, bad)
	tok.Header["typ"] = "secevent+jwt"
	signed, err := tok.SignedString(env.plugin.keySet.RSAPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewSETDecoder(env.plugin.keySet.RSAPublicKey(), env.plugin.baseURL, "")
	if _, err := decoder.Decode(signed); err == nil {
		t.Fatal("SET carrying sub or exp must fail validation [SSF §4.1.2 / §4.1.7]")
	}

	if bits := env.plugin.keySet.RSAPrivateKey().N.BitLen(); bits < 2048 {
		t.Fatalf("RSA key %d bits, CAEPINTEROP requires >= 2048", bits)
	}
}

func TestPushDeliveryToReceiverEndpointURL(t *testing.T) {
	env := startSSFTestEnv(t)
	var gotCT, gotAuth, gotLG string
	var gotBody []byte
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		gotLG = r.Header.Get(lookingGlassSessionHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(listener.Close)

	status, body := env.doJSON(t, http.MethodPost, "/ssf/stream", "", map[string]any{
		"delivery": map[string]string{
			"method":                DeliveryMethodPush,
			"endpoint_url":          listener.URL,
			"authorization_header":  "Bearer receiver-supplied",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d: %s", status, body)
	}
	var stream Stream
	if err := json.Unmarshal(body, &stream); err != nil {
		t.Fatal(err)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/verify", "", map[string]string{
		"stream_id": stream.ID,
		"state":     "probe",
	})
	if status != http.StatusNoContent {
		t.Fatalf("verify %d: %s", status, body)
	}
	if gotCT != "application/secevent+jwt" {
		t.Fatalf("Content-Type %q [RFC 8935]", gotCT)
	}
	if gotAuth != "Bearer receiver-supplied" {
		t.Fatalf("Authorization %q [SSF §6.1.1]", gotAuth)
	}
	if gotLG != "" {
		t.Fatalf("must not send Looking Glass header to an external push URL, got %q", gotLG)
	}
	decoded, err := DecodeWithoutValidation(string(gotBody))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Subject == nil || decoded.Subject.Format != SubjectFormatOpaque || decoded.Subject.ID != stream.ID {
		t.Fatalf("verification sub_id %#v", decoded.Subject)
	}
	if len(decoded.Events) != 1 || decoded.Events[0].Type != EventTypeVerification {
		t.Fatalf("events %#v", decoded.Events)
	}
	if decoded.Events[0].Payload.State != "probe" {
		t.Fatalf("state %q", decoded.Events[0].Payload.State)
	}

	env.plugin.minVerifyInt = 60
	status, _ = env.doJSON(t, http.MethodPost, "/ssf/verify", "", map[string]string{
		"stream_id": stream.ID,
		"state":     "again",
	})
	if status != http.StatusTooManyRequests {
		t.Fatalf("second verify %d, want 429", status)
	}
}

func (e *ssfTestEnv) doBearerJSON(t *testing.T, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(mustJSON(body))
	}
	req, err := http.NewRequest(method, e.server.URL+path, reader)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestReplaceStreamPUT(t *testing.T) {
	env := startSSFTestEnv(t)
	status, body := env.doJSON(t, http.MethodPost, "/ssf/stream", "", map[string]any{
		"delivery": map[string]string{
			"method":       DeliveryMethodPush,
			"endpoint_url": "https://receiver.example/ssf-push",
		},
		"description": "original",
		"events_requested": []string{
			EventTypeSessionRevoked,
			EventTypeCredentialChange,
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d: %s", status, body)
	}
	var created Stream
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	status, body = env.doJSON(t, http.MethodPut, "/ssf/stream", "", map[string]any{
		"stream_id": created.ID,
		"delivery": map[string]string{
			"method": DeliveryMethodPoll,
		},
		"events_requested": []string{EventTypeSessionRevoked},
	})
	if status != http.StatusOK {
		t.Fatalf("PUT %d: %s", status, body)
	}
	var replaced Stream
	if err := json.Unmarshal(body, &replaced); err != nil {
		t.Fatal(err)
	}
	if replaced.DeliveryMethod != DeliveryMethodPoll {
		t.Fatalf("method %s", replaced.DeliveryMethod)
	}
	if replaced.DeliveryEndpoint != env.server.URL+"/ssf/poll/"+created.ID {
		t.Fatalf("poll URL %s [SSF §6.1.2]", replaced.DeliveryEndpoint)
	}
	if replaced.Description != "" {
		t.Fatalf("missing description MUST be deleted, got %q [SSF §8.1.1.3]", replaced.Description)
	}
	if len(replaced.EventsRequested) != 1 || replaced.EventsRequested[0] != EventTypeSessionRevoked {
		t.Fatalf("events_requested %#v", replaced.EventsRequested)
	}
}

func TestSubjectAddRemoveFiltersTransmission(t *testing.T) {
	env := startSSFTestEnv(t)
	status, body := env.doJSON(t, http.MethodPost, "/ssf/stream", "", map[string]any{
		"delivery": map[string]string{"method": DeliveryMethodPoll},
		"events_requested": []string{EventTypeSessionRevoked},
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d: %s", status, body)
	}
	var stream Stream
	if err := json.Unmarshal(body, &stream); err != nil {
		t.Fatal(err)
	}

	alice := map[string]string{"format": SubjectFormatEmail, "email": "alice@example.com"}
	status, body = env.doJSON(t, http.MethodPost, "/ssf/subjects/remove", "", map[string]any{
		"stream_id": stream.ID,
		"subject":   alice,
	})
	if status != http.StatusNoContent {
		t.Fatalf("remove %d: %s [SSF §8.1.3.2]", status, body)
	}

	subject := SubjectIdentifier{Format: SubjectFormatEmail, Email: "alice@example.com"}
	_, err := env.plugin.transmitter.TriggerSessionRevoked(t.Context(), stream.ID, subject, "revoked", InitiatingEntityAdmin)
	if err != ErrSubjectNotInStream {
		t.Fatalf("removed subject still transmitted: %v", err)
	}

	status, body = env.doJSON(t, http.MethodPost, "/ssf/subjects/add", "", map[string]any{
		"stream_id": stream.ID,
		"subject":   alice,
		"verified":  true,
	})
	if status != http.StatusOK {
		t.Fatalf("add %d: %s [SSF §8.1.3.1]", status, body)
	}

	if _, err := env.plugin.transmitter.TriggerSessionRevoked(t.Context(), stream.ID, subject, "revoked", InitiatingEntityAdmin); err != nil {
		t.Fatalf("re-added subject: %v", err)
	}

	pollPath := "/ssf/poll/" + stream.ID
	status, body = env.doJSON(t, http.MethodPost, pollPath, "", map[string]any{
		"maxEvents":         10,
		"returnImmediately": true,
	})
	if status != http.StatusOK {
		t.Fatalf("poll %d: %s", status, body)
	}
	var poll PollResponse
	if err := json.Unmarshal(body, &poll); err != nil {
		t.Fatal(err)
	}
	if len(poll.Sets) == 0 {
		t.Fatal("re-added subject SET missing from poll")
	}
}

func TestRevokedAccessTokenRejected(t *testing.T) {
	asKeys, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(asKeys.PublicJWKS())
	}))
	t.Cleanup(jwksSrv.Close)

	t.Setenv("SSF_AS_ISSUER", "https://as.example")
	t.Setenv("SSF_AS_JWKS_URI", jwksSrv.URL)
	env := startSSFTestEnv(t)
	revoker := &mapRevoker{revoked: map[string]bool{}}
	env.plugin.revoker = revoker

	jwtSvc := crypto.NewJWTService(asKeys, "https://as.example")
	token, err := jwtSvc.CreateAccessToken("client-a", env.server.URL, ScopeSSFManage, 15*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}

	status, body := env.doBearerJSON(t, http.MethodPost, "/ssf/stream", token, map[string]any{
		"delivery": map[string]string{"method": DeliveryMethodPoll},
	})
	if status != http.StatusCreated {
		t.Fatalf("create %d: %s", status, body)
	}

	revoker.revoked[token] = true
	status, body = env.doBearerJSON(t, http.MethodGet, "/ssf/stream", token, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked token %d, want 401: %s [CAEPINTEROP Transmitter as RS]", status, body)
	}
}

type mapRevoker struct {
	revoked map[string]bool
}

func (m *mapRevoker) IsTokenRevoked(token string) bool {
	return m.revoked[token]
}
