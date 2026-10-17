package binding

import (
	"net/http"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// Events publishes binding exchanges to Looking Glass. The zero value emits
// nothing.
type Events struct {
	Engine *lookingglass.Engine

	// Origins are the browser origins an outcome page may hand its outcome
	// to: the deployment's own origin and the Looking Glass frontend origins.
	Origins []string
}

// Emit publishes an event to the Looking Glass session named on r, if any.
func (e Events) Emit(r *http.Request, eventType lookingglass.EventType, title string, data map[string]interface{}, annotations ...lookingglass.Annotation) {
	if e.Engine == nil {
		return
	}
	if sessionID := LookingGlassSession(r); sessionID != "" {
		e.Engine.NewEventBroadcaster(sessionID).Emit(eventType, title, data, annotations...)
	}
}

// LookingGlassSession reads the capture session the same way the core capture
// middleware does: the X-Looking-Glass-Session header, or lg_session where a
// header cannot be set (browser redirects and form posts).
func LookingGlassSession(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("X-Looking-Glass-Session")); id != "" {
		return id
	}
	return strings.TrimSpace(r.URL.Query().Get("lg_session"))
}

// Reference is an annotation citing a spec section.
func Reference(title, description, ref string) lookingglass.Annotation {
	return lookingglass.Annotation{Type: lookingglass.AnnotationTypeRFCReference, Title: title, Description: description, Reference: ref}
}
