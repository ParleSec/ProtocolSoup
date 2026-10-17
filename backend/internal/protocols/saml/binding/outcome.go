package binding

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/gel"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// Outcome is what an entity concluded about the message that ends a browser
// exchange: the assertion consumer service on a <Response>, or a
// SingleLogoutService on a <LogoutResponse> or a rejected <LogoutRequest>.
// Everything in it comes from the message that actually arrived and the
// checks that actually ran.
type Outcome struct {
	Flow        string                 `json:"flow"`   // "sso" or "slo"
	Entity      string                 `json:"entity"` // entityID of the entity that processed the message
	Title       string                 `json:"title"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Binding     string                 `json:"binding"`
	Param       string                 `json:"param"`
	RelayState  string                 `json:"relayState,omitempty"`
	ReceivedXML string                 `json:"receivedXml"`
	Validation  *Report                `json:"validation"`
	Reference   string                 `json:"reference"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// NewOutcome starts an Outcome for the received message msg.
func NewOutcome(flow, entity, title, reference string, msg *Received, report *Report, err error) Outcome {
	outcome := Outcome{
		Flow:        flow,
		Entity:      entity,
		Title:       title,
		Success:     err == nil,
		Binding:     msg.Binding,
		Param:       msg.Param,
		RelayState:  msg.RelayState,
		ReceivedXML: string(msg.XML),
		Validation:  report,
		Reference:   reference,
	}
	if err != nil {
		outcome.Error = err.Error()
	}
	return outcome
}

var outcomeTemplate = template.Must(template.New("outcome").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Outcome.Title}} - ProtocolSoup</title>
<style>{{.CSS}}</style>
</head>
<body>
<main>
<h1>{{.Outcome.Title}}</h1>
<p class="muted">Processed by {{.Outcome.Entity}} &middot; {{.Outcome.Reference}}</p>
<div class="panel">
{{if .Outcome.Success}}<p class="status status-success">{{.IconSuccess}}<span>Accepted</span></p>
{{else}}<p class="status status-danger">{{.IconDanger}}<span>Rejected</span></p>
<pre>{{.Outcome.Error}}</pre>
{{end}}</div>
{{with .Outcome.Validation}}<h2>Checks that ran</h2>
<div class="panel"><ul class="checks">
{{range .Checks}}<li>{{if .Passed}}<span class="status status-success">{{$.IconSuccess}}<span>Pass</span></span>{{else}}<span class="status status-danger">{{$.IconDanger}}<span>Fail</span></span>{{end}} {{.Name}}
<span class="check-detail">{{.Detail}}</span><span class="check-ref">{{.Reference}}</span></li>
{{end}}</ul></div>{{end}}
<h2>{{.Outcome.Param}} received over {{.Outcome.Binding}}</h2>
<pre>{{.Outcome.ReceivedXML}}</pre>
{{if .Details}}<h2>Result</h2>
<pre>{{.Details}}</pre>{{end}}
<p class="muted">Looking Glass has the full exchange. You can close this window.</p>
</main>
<script type="application/json" id="saml-outcome">{{.Outcome}}</script>
<script type="application/json" id="saml-opener-origins">{{.Origins}}</script>
<script>
(function () {
  if (!window.opener) return;
  var outcome = JSON.parse(document.getElementById('saml-outcome').textContent);
  var origins = JSON.parse(document.getElementById('saml-opener-origins').textContent);
  origins.forEach(function (origin) {
    window.opener.postMessage({ type: 'saml_outcome', outcome: outcome }, origin);
  });
})();
</script>
</body>
</html>`))

// WriteOutcome publishes outcome to Looking Glass and answers the user agent
// with a page showing it. When the page was opened by Looking Glass, it hands
// the outcome to its opener with postMessage, addressed only to the origins
// in e.Origins (browsers drop a message whose target origin does not match).
func (e Events) WriteOutcome(w http.ResponseWriter, r *http.Request, eventType lookingglass.EventType, status int, outcome Outcome) {
	e.Emit(r, eventType, outcome.Title, map[string]interface{}{
		"flow":       outcome.Flow,
		"entity":     outcome.Entity,
		"success":    outcome.Success,
		"error":      outcome.Error,
		"binding":    outcome.Binding,
		"relayState": outcome.RelayState,
		"samlXML":    outcome.ReceivedXML,
		"validation": outcome.Validation,
		"details":    outcome.Details,
	}, Reference(outcome.Title, "Every check listed ran on the received message; any failure rejects it.", outcome.Reference))

	details := ""
	if len(outcome.Details) > 0 {
		if b, err := json.MarshalIndent(outcome.Details, "", "  "); err == nil {
			details = string(b)
		}
	}
	origins := e.Origins
	if origins == nil {
		origins = []string{}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = outcomeTemplate.Execute(w, map[string]interface{}{
		"CSS":         gel.PageCSS(),
		"IconSuccess": gel.IconSuccess,
		"IconDanger":  gel.IconDanger,
		"Outcome":     outcome,
		"Origins":     origins,
		"Details":     details,
	})
}
