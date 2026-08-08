package oidc

import (
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// handleThirdPartyInitiate is a ProtocolSoup demonstration initiator. It is not
// a standardized OpenID Provider endpoint. OIDC Core §4 places initiate_login_uri
// on the RP; this handler redirects the browser to that registered RP URI with
// the required iss parameter and optional login_hint / target_link_uri.
func (p *Plugin) handleThirdPartyInitiate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Invalid form encoding")
		return
	}

	clientID := strings.TrimSpace(r.Form.Get("client_id"))
	loginHint := strings.TrimSpace(r.Form.Get("login_hint"))
	targetLinkURI := strings.TrimSpace(r.Form.Get("target_link_uri"))
	sessionID := p.getSessionFromRequest(r)

	if clientID == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writeHTML(w, p.generateThirdPartyInitiatePage("", ""))
		return
	}

	client, exists := p.mockIdP.GetClient(clientID)
	if !exists {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		writeHTML(w, p.generateThirdPartyInitiatePage(html.EscapeString(clientID), "Unknown client_id"))
		return
	}
	initiateURI := strings.TrimSpace(client.InitiateLoginURI)
	if initiateURI == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		writeHTML(w, p.generateThirdPartyInitiatePage(html.EscapeString(clientID), "Client has no registered initiate_login_uri"))
		return
	}
	if err := validateHTTPSURL(initiateURI, "initiate_login_uri"); err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_client", "Registered initiate_login_uri must use https")
		return
	}

	issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/")
	if !strings.HasPrefix(strings.ToLower(issuer), "https://") {
		writeOIDCError(w, http.StatusBadRequest, "invalid_request", "Issuer must use the https scheme for third-party initiation (OIDC Core 1.0 Section 4)")
		return
	}

	dest, err := url.Parse(initiateURI)
	if err != nil {
		writeOIDCError(w, http.StatusBadRequest, "invalid_client", "Registered initiate_login_uri is invalid")
		return
	}
	q := dest.Query()
	q.Set("iss", issuer)
	if loginHint != "" {
		q.Set("login_hint", loginHint)
	}
	if targetLinkURI != "" {
		q.Set("target_link_uri", targetLinkURI)
	}
	dest.RawQuery = q.Encode()

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Third-Party Login Initiation", map[string]interface{}{
		"client_id":          clientID,
		"initiate_login_uri": initiateURI,
		"iss":                issuer,
		"login_hint":         loginHint,
		"target_link_uri":    targetLinkURI,
		"redirect_to":        dest.String(),
	}, lookingglass.Annotation{
		Type:        lookingglass.AnnotationTypeExplanation,
		Title:       "Initiating Login from a Third Party",
		Description: "The initiator redirects the User Agent to the RP's registered initiate_login_uri with iss (REQUIRED) and optional login_hint / target_link_uri. The RP then builds an Authentication Request to this OP.",
		Reference:   "OpenID Connect Core 1.0 Section 4",
	})

	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (p *Plugin) generateThirdPartyInitiatePage(escapedClientID, errMsg string) string {
	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div class="error">` + html.EscapeString(errMsg) + `</div>`
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>ProtocolSoup Third-Party Login Initiator</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0b1220; color: #e2e8f0; padding: 2rem; }
    .card { max-width: 560px; margin: 0 auto; background: #111827; border-radius: 12px; padding: 1.5rem; }
    label { display: block; margin-top: 1rem; font-size: 0.9rem; }
    input { width: 100%; padding: 0.6rem; margin-top: 0.35rem; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; }
    button { margin-top: 1.25rem; padding: 0.7rem 1rem; border: 0; border-radius: 8px; background: #2563eb; color: white; font-weight: 600; cursor: pointer; }
    .error { margin-top: 1rem; padding: 0.75rem; background: rgba(239,68,68,0.15); color: #fecaca; border-radius: 8px; }
    .note { margin-top: 1rem; color: #94a3b8; font-size: 0.85rem; line-height: 1.4; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Third-Party Login Initiator</h1>
    <p class="note">This ProtocolSoup page demonstrates OIDC Core §4 by redirecting to a registered RP <code>initiate_login_uri</code>. It is not itself a standardized OP endpoint.</p>
    ` + errorHTML + `
    <form method="GET" action="/oidc/third-party/initiate">
      <label>client_id
        <input name="client_id" value="` + escapedClientID + `" required />
      </label>
      <label>login_hint (optional)
        <input name="login_hint" />
      </label>
      <label>target_link_uri (optional)
        <input name="target_link_uri" />
      </label>
      <button type="submit">Initiate login at RP</button>
    </form>
  </div>
</body>
</html>`
}

func writeHTML(w http.ResponseWriter, page string) {
	_, _ = w.Write([]byte(page))
}
