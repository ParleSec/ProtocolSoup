package agentauth

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// claimStartRequest begins a claim ceremony for an already registered agent.
type claimStartRequest struct {
	ClaimToken string `json:"claim_token"`
	Email      string `json:"email"`
}

// handleClaimStart issues a user_code for an agent that wants to be bound to a
// person. The response mirrors the device authorization response of RFC 8628
// Section 3.2: a code the person types, the URI where they type it, a
// pre-filled variant of that URI, a lifetime, and the minimum poll interval.
func (p *Plugin) handleClaimStart(w http.ResponseWriter, r *http.Request) {
	sessionID := p.sessionFromRequest(r)

	var req claimStartRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Request body must be a JSON object")
		return
	}
	if req.ClaimToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `"claim_token" is required`)
		return
	}
	if !strings.Contains(req.Email, "@") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `"email" is required and must be an email address`)
		return
	}

	now := time.Now()

	p.mu.Lock()
	identity, ok := p.identities[req.ClaimToken]
	if !ok || identity.Revoked || now.After(identity.ExpiresAt) {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant",
			"Unknown, revoked, or expired claim_token")
		return
	}

	// A fresh attempt supersedes any outstanding one, so a person cannot
	// approve a stale code that the agent has stopped polling for.
	for code, attempt := range p.attempts {
		if attempt.ClaimToken == req.ClaimToken {
			delete(p.attempts, code)
		}
	}

	attempt := &claimAttempt{
		UserCode:          newUserCode(),
		ClaimAttemptToken: randomToken(),
		ClaimToken:        req.ClaimToken,
		Email:             strings.TrimSpace(req.Email),
		CreatedAt:         now,
		ExpiresAt:         now.Add(claimAttemptTTL),
	}
	p.attempts[attempt.UserCode] = attempt
	agentID := identity.AgentID
	p.mu.Unlock()

	verificationURI := p.issuer() + "/claim"

	p.emitEvent(sessionID, lookingglass.EventTypeFlowStep, "Claim ceremony started",
		map[string]interface{}{
			"agent_id":         agentID,
			"user_code":        attempt.UserCode,
			"verification_uri": verificationURI,
			"expires_in":       int(claimAttemptTTL.Seconds()),
			"interval":         int(pollInterval.Seconds()),
			"email":            attempt.Email,
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "The agent cannot approve itself",
			Description: "The agent surfaces the user_code to a person, who approves it in a browser the agent does not control. Splitting the ceremony across two channels is what stops an agent from silently claiming an identity it was never granted.",
			Reference:   "RFC 8628 Section 3.3",
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeSecurityHint,
			Title:       "The code is deliberately short and short-lived",
			Description: "A user_code has to be readable aloud, so it carries far less entropy than a token. RFC 8628 Section 5.1 compensates with a short lifetime, single use, and rate limiting on the verification endpoint.",
			Reference:   "RFC 8628 Section 5.1",
		})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"claim_attempt_token":       attempt.ClaimAttemptToken,
		"user_code":                 attempt.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(attempt.UserCode),
		"expires_in":                int(claimAttemptTTL.Seconds()),
		"interval":                  int(pollInterval.Seconds()),
		"grant_type":                grantTypeClaim,
	})
}

// claimCompleteRequest is submitted by the person approving the agent.
type claimCompleteRequest struct {
	UserCode string `json:"user_code"`
}

// handleClaimComplete records a person's approval of an outstanding user_code.
// The agent learns of the approval on its next poll of the token endpoint,
// exactly as RFC 8628 Section 3.4 describes.
func (p *Plugin) handleClaimComplete(w http.ResponseWriter, r *http.Request) {
	sessionID := p.sessionFromRequest(r)

	userCode := ""
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var req claimCompleteRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Request body must be a JSON object")
			return
		}
		userCode = req.UserCode
	} else {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body")
			return
		}
		userCode = r.PostFormValue("user_code")
	}

	userCode = normalizeUserCode(userCode)
	if userCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", `"user_code" is required`)
		return
	}

	now := time.Now()

	p.mu.Lock()
	attempt, ok := p.attempts[userCode]
	if !ok || now.After(attempt.ExpiresAt) {
		p.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Unknown or expired user_code")
		return
	}
	attempt.Completed = true
	identity := p.identities[attempt.ClaimToken]
	email := attempt.Email
	agentID := ""
	if identity != nil {
		agentID = identity.AgentID
	}
	p.mu.Unlock()

	p.emitEvent(sessionID, lookingglass.EventTypeSecurityInfo, "Agent claimed by a person",
		map[string]interface{}{
			"agent_id":  agentID,
			"user_code": userCode,
			"email":     email,
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "Approval is recorded, not delivered",
			Description: "The person's browser and the agent are separate channels. Approval only marks the attempt complete; the agent discovers it by polling, and that is when its new assertion and wider scope are issued.",
			Reference:   "RFC 8628 Section 3.4",
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeVulnerability,
			Title:       "This sandbox does not authenticate the approver",
			Description: "A production deployment MUST require the person to sign in before completing a claim, and MUST bind the claim to that authenticated identity rather than to an email the agent supplied. Without it, anyone who learns a user_code can take ownership of the agent.",
			Severity:    "warning",
			Reference:   "RFC 8628 Section 5.4",
		})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"claimed":   true,
		"agent_id":  agentID,
		"email":     email,
		"user_code": userCode,
	})
}

// handleClaimPage renders the verification_uri a person opens to approve an
// agent. RFC 8628 Section 3.3 has the user_code entered here rather than
// carried back to the agent.
func (p *Plugin) handleClaimPage(w http.ResponseWriter, r *http.Request) {
	prefilled := html.EscapeString(normalizeUserCode(r.URL.Query().Get("user_code")))
	action := html.EscapeString(p.issuer() + "/identity/claim/complete")

	page := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Approve an agent - ProtocolSoup</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         background:#0b1020; color:#e6e9f2;
         font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
  main { width:min(30rem,92vw); background:#131a30; border:1px solid #243055;
         border-radius:14px; padding:2rem; }
  h1 { margin:0 0 .35rem; font-size:1.3rem; }
  p { margin:0 0 1.25rem; color:#9fabc9; font-size:.94rem; }
  label { display:block; font-size:.8rem; text-transform:uppercase;
          letter-spacing:.07em; color:#9fabc9; margin-bottom:.4rem; }
  input { width:100%; box-sizing:border-box; padding:.8rem .9rem; font-size:1.4rem;
          letter-spacing:.18em; text-align:center; text-transform:uppercase;
          font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
          background:#0b1020; color:#e6e9f2; border:1px solid #2c3a63;
          border-radius:9px; }
  button { width:100%; margin-top:1.1rem; padding:.8rem; font-size:1rem; font-weight:600;
           color:#08122b; background:#5ac8fa; border:0; border-radius:9px; cursor:pointer; }
  button:hover { background:#7ad4fb; }
  .note { margin-top:1.4rem; padding:.85rem .95rem; border-radius:9px;
          background:#2a1c10; border:1px solid #5c3d1a; color:#f0c48a; font-size:.83rem; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
</style>
</head>
<body>
<main>
  <h1>Approve an agent</h1>
  <p>Enter the code the agent showed you. This binds that agent to you and widens
     the access it is allowed.</p>
  <form method="post" action="` + action + `">
    <label for="user_code">User code</label>
    <input id="user_code" name="user_code" value="` + prefilled + `"
           placeholder="XXXX-XXXX" autocomplete="off" spellcheck="false" required>
    <button type="submit">Approve</button>
  </form>
  <div class="note">
    <strong>Sandbox behaviour.</strong> A real deployment must make you sign in
    before this step and bind the agent to the account you signed in with. This
    one accepts the code on its own, so treat every <code>user_code</code> here
    as public.
  </div>
</main>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(page))
}
