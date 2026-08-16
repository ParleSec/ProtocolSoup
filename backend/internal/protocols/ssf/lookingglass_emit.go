package ssf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/google/uuid"
)

const lookingGlassSessionHeader = "X-Looking-Glass-Session"

type glassBox struct {
	engine *lookingglass.Engine
}

func newGlassBox(engine *lookingglass.Engine) *glassBox {
	if engine == nil {
		return nil
	}
	return &glassBox{engine: engine}
}

func (g *glassBox) emitTransmitter(ev TransmitterEvent) {
	if g == nil || g.engine == nil || ev.SessionID == "" {
		return
	}
	b := g.engine.NewEventBroadcaster(ev.SessionID)
	data := eventPayload(ev.Data)
	data["jti"] = ev.EventID
	data["event_id"] = ev.EventID
	data["ssf_source"] = "transmitter"
	data["ssf_stage"] = ev.Type
	data["subject_id"] = ev.SubjectID
	data["event_type"] = ev.EventType
	data["session_in_set"] = false
	data["session_header"] = lookingGlassSessionHeader

	switch ev.Type {
	case TransmitterEventHTTPExchange:
		if exchange := captureToLGExchange(ev.EventID, ev.SessionID, ev.Data); exchange != nil {
			b.EmitHTTPExchange(exchangeLabel(ev.Data, "Transmitter HTTP"), *exchange)
		}
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: SET delivery hop", withActors(data, "Transmitter", "Receiver"),
			rfcAnnotation("RFC 8935 Section 2", "The SET Transmitter sends (pushes) SETs to the SET Recipient's endpoint via HTTP POST."))
	case TransmitterEventActionTriggered:
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: security event triggered", withActors(data, "Transmitter", "Transmitter"),
			rfcAnnotation("OpenID SSF 1.0 Section 8", "A Transmitter emits security events for subjects on a configured stream."))
	case TransmitterEventSETGenerated:
		b.Emit(lookingglass.EventTypeTokenIssued, "Transmitter: SET created", data,
			rfcAnnotation("RFC 8417 Section 2.2", "A SET is a JSON Web Token (JWT). REQUIRED claims: iss, iat, jti, aud, events."))
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: SET generated", withActors(data, "Transmitter", "Transmitter"),
			rfcAnnotation("RFC 8417 Section 2", "A SET is a JSON Web Token (JWT)."))
	case TransmitterEventSETSigned:
		b.Emit(lookingglass.EventTypeCryptoOperation, "Transmitter: SET signed (RS256)", data,
			rfcAnnotation("RFC 7515", "JSON Web Signature (JWS) compact serialization."))
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: SET signed", withActors(data, "Transmitter", "Transmitter"),
			rfcAnnotation("RFC 8417 Section 2", "A SET is a JSON Web Token (JWT)."))
	case TransmitterEventQueued:
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: SET queued for delivery", withActors(data, "Transmitter", "Transmitter"),
			rfcAnnotation("RFC 8936 Section 2", "The Transmitter holds undelivered SETs until the Receiver polls or push delivery succeeds."))
	case TransmitterEventDeliveryStarted:
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: push delivery started", withActors(data, "Transmitter", "Receiver"),
			rfcAnnotation("RFC 8935 Section 2", "The SET Transmitter sends (pushes) SETs to the SET Recipient's endpoint via HTTP POST."))
	case TransmitterEventDeliverySuccess:
		status := deliveryStatusCode(ev.Data)
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: push delivery succeeded", withActors(data, "Receiver", "Transmitter"),
			rfcAnnotation("RFC 8935 Section 2.2", fmt.Sprintf("%d %s -- SET Recipient response.", status, httpStatusText(status))))
	case TransmitterEventDeliveryFailed:
		b.Emit(lookingglass.EventTypeSecurityWarning, "Transmitter: push delivery failed", data,
			rfcAnnotation("RFC 8935 Section 2.2", "The SET Recipient SHALL validate the SET and return an error status when it cannot."))
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: push delivery failed", withActors(data, "Transmitter", "Receiver"))
	default:
		b.Emit(lookingglass.EventTypeFlowStep, "Transmitter: "+ev.Type, withActors(data, "Transmitter", "Transmitter"))
	}
}

func (g *glassBox) emitReceiver(ev ReceiverEvent) {
	if g == nil || g.engine == nil || ev.SessionID == "" {
		return
	}
	b := g.engine.NewEventBroadcaster(ev.SessionID)
	data := eventPayload(ev.Data)
	data["jti"] = ev.EventID
	data["event_id"] = ev.EventID
	data["ssf_source"] = "receiver"
	data["ssf_stage"] = ev.Type
	data["session_in_set"] = false
	data["session_header"] = lookingGlassSessionHeader

	switch ev.Type {
	case ReceiverEventHTTPExchange:
		if exchange := captureToLGExchange(ev.EventID, ev.SessionID, ev.Data); exchange != nil {
			b.EmitHTTPExchange(exchangeLabel(ev.Data, "Receiver HTTP"), *exchange)
		}
		ref, desc := receiverHopAnnotation(ev.Data)
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: HTTP hop", withActors(data, "Receiver", "Transmitter"),
			rfcAnnotation(ref, desc))
	case ReceiverEventReceived:
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: SET received", withActors(data, "Transmitter", "Receiver"),
			rfcAnnotation("RFC 8935 Section 2", "The SET Recipient SHALL validate the SET."))
	case ReceiverEventVerified:
		b.Emit(lookingglass.EventTypeSecurityInfo, "Receiver: SET signature verified", data,
			rfcAnnotation("RFC 7515 Section 5.2", "Message signature or MAC validation."))
		b.Emit(lookingglass.EventTypeTokenValidated, "Receiver: SET validated", data)
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: SET verified", withActors(data, "Receiver", "Receiver"),
			rfcAnnotation("RFC 8417 Section 2.2", "jti MUST be unique to prevent replays."))
	case ReceiverEventVerifyFailed:
		b.Emit(lookingglass.EventTypeSecurityWarning, "Receiver: SET verification failed", data,
			rfcAnnotation("RFC 8935 Section 2", "The SET Recipient SHALL validate the SET."))
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: SET verification failed", withActors(data, "Receiver", "Receiver"))
	case ReceiverEventProcessing:
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: processing SET events", withActors(data, "Receiver", "Receiver"),
			rfcAnnotation("RFC 8417 Section 2.2", "events claim is a JSON object where keys are event type URIs."))
	case ReceiverEventProcessed:
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: SET processed", withActors(data, "Receiver", "Receiver"),
			rfcAnnotation("RFC 8935 Section 2.2", "The Recipient processes a verified SET after acknowledging receipt."))
	case ReceiverEventResponseAction:
		b.Emit(lookingglass.EventTypeSecurityInfo, "Receiver: response action", data)
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: RP response action", withActors(data, "Receiver", "Receiver"),
			rfcAnnotation("OpenID CAEP 1.0", "RP policy after a verified SET. This hop is not an SSF SET field."))
	default:
		b.Emit(lookingglass.EventTypeFlowStep, "Receiver: "+ev.Type, withActors(data, "Receiver", "Receiver"))
	}
}

func eventPayload(raw interface{}) map[string]interface{} {
	if raw == nil {
		return map[string]interface{}{}
	}
	if m, ok := raw.(map[string]interface{}); ok {
		out := make(map[string]interface{}, len(m)+8)
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	return map[string]interface{}{"payload": raw}
}

func withActors(data map[string]interface{}, from, to string) map[string]interface{} {
	data["from"] = from
	data["to"] = to
	return data
}

func rfcAnnotation(reference, description string) lookingglass.Annotation {
	return lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeRFCReference,
		Title:       reference,
		Description: description,
		Reference:   reference,
	}
}

func exchangeLabel(raw interface{}, fallback string) string {
	switch v := raw.(type) {
	case *CapturedHTTPExchange:
		if v != nil && v.Label != "" {
			return v.Label
		}
	case CapturedHTTPExchange:
		if v.Label != "" {
			return v.Label
		}
	}
	return fallback
}

func captureToLGExchange(eventID, sessionID string, raw interface{}) *lookingglass.CapturedExchange {
	var cap *CapturedHTTPExchange
	switch v := raw.(type) {
	case *CapturedHTTPExchange:
		cap = v
	case CapturedHTTPExchange:
		copied := v
		cap = &copied
	default:
		return nil
	}
	if cap == nil {
		return nil
	}

	start := cap.Timestamp
	end := cap.Timestamp.Add(time.Duration(cap.DurationMs) * time.Millisecond)
	id := eventID
	if id == "" {
		id = uuid.NewString()
	} else {
		id = fmt.Sprintf("%s-%s", id, strings.ReplaceAll(strings.ToLower(cap.Label), " ", "-"))
	}

	contentType := cap.Request.Headers["Content-Type"]
	if contentType == "" {
		contentType = cap.Request.Headers["content-type"]
	}
	respType := cap.Response.Headers["Content-Type"]
	if respType == "" {
		respType = cap.Response.Headers["content-type"]
	}

	return &lookingglass.CapturedExchange{
		ID:        id,
		SessionID: sessionID,
		Request: lookingglass.CapturedMessage{
			Method:  cap.Request.Method,
			URL:     cap.Request.URL,
			Headers: headerMap(cap.Request.Headers),
			Body:    payload(cap.Request.Body, contentType),
		},
		Response: lookingglass.CapturedMessage{
			Status:     cap.Response.StatusCode,
			StatusText: httpStatusText(cap.Response.StatusCode),
			Headers:    headerMap(cap.Response.Headers),
			Body:       payload(cap.Response.Body, respType),
		},
		Timing: lookingglass.ExchangeTiming{
			StartUnixMicro: start.UnixMicro(),
			EndUnixMicro:   end.UnixMicro(),
			DurationMicro:  cap.DurationMs * 1000,
		},
		Meta: lookingglass.CaptureMeta{
			CaptureSource:            "ssf-protocol",
			HeaderOrderPreserved:     false,
			BodyLimitBytes:           0,
			RequestBodyReadBytes:     int64(len(cap.Request.Body)),
			ResponseBodyWrittenBytes: int64(len(cap.Response.Body)),
			RawReconstructed:         false,
		},
	}
}

func headerMap(in map[string]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = []string{v}
	}
	return out
}

func payload(body, contentType string) *lookingglass.CapturedPayload {
	if body == "" {
		return nil
	}
	return &lookingglass.CapturedPayload{
		Encoding:    "utf-8",
		Data:        body,
		Size:        int64(len(body)),
		Truncated:   false,
		ContentType: contentType,
	}
}

func peekSET(setToken string) (jti string, eventURIs []string, claims map[string]interface{}) {
	eventURIs = []string{}
	claims = map[string]interface{}{}
	if setToken == "" {
		return "", eventURIs, claims
	}
	parts := strings.Split(setToken, ".")
	if len(parts) < 2 {
		return "", eventURIs, claims
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", eventURIs, claims
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", eventURIs, claims
	}
	if v, ok := claims["jti"].(string); ok {
		jti = v
	}
	if events, ok := claims["events"].(map[string]interface{}); ok {
		for uri := range events {
			eventURIs = append(eventURIs, uri)
		}
	}
	return jti, eventURIs, claims
}

func httpStatusText(code int) string {
	if code == 202 {
		return "Accepted"
	}
	if code == 204 {
		return "No Content"
	}
	if code >= 200 && code < 300 {
		return "OK"
	}
	if code >= 400 {
		return "Error"
	}
	return ""
}

func deliveryStatusCode(raw interface{}) int {
	data, ok := raw.(map[string]interface{})
	if !ok {
		return 202
	}
	switch v := data["status_code"].(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 202
}

func receiverHopAnnotation(raw interface{}) (string, string) {
	label := strings.ToLower(exchangeLabel(raw, ""))
	if strings.Contains(label, "jwks") {
		return "RFC 7517", "The Receiver fetches the Transmitter JSON Web Key Set to verify the SET signature."
	}
	if strings.Contains(label, "caep") || strings.Contains(label, "federation") || strings.Contains(label, "revoke-subject") {
		return "OpenID CAEP 1.0", "RP policy after a verified session-revoked SET. This HTTP hop is not an SSF SET field."
	}
	return "RFC 8935 Section 2", "The SET Recipient exchanges HTTP with the Transmitter or an RP backend."
}
