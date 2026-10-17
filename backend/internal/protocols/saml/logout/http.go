package logout

import (
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
)

// WriteResult reports a Single Logout step that ends at this entity, either a
// processed LogoutResponse or a rejected LogoutRequest, as JSON and to
// Looking Glass.
func WriteResult(w http.ResponseWriter, r *http.Request, events binding.Events, title string, msg *binding.Received, result *Result, err error) {
	status := http.StatusOK
	if err != nil {
		status = http.StatusForbidden
	}
	events.Emit(r, lookingglass.EventTypeFlowStep, title, map[string]interface{}{
		"binding": msg.Binding, "samlXML": string(msg.XML), "validation": result.Report,
	}, binding.Reference("Single Logout", "Processed per the Single Logout protocol rules.", "SAML Core Section 3.7.3"))
	body := map[string]interface{}{"success": err == nil, "result": result}
	if err != nil {
		body["error"] = err.Error()
	}
	binding.WriteJSON(w, status, body)
}
