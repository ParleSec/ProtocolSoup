package idp

import (
	"html/template"
	"net/http"

	"github.com/ParleSec/ProtocolSoup/internal/gel"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
)

// The sign-in page follows the pattern of the OAuth 2.0 and OpenID Connect
// sign-in pages: a centred card with the protocol badge, the relying party
// being signed in to, email and password, Cancel, and the demo users to
// autofill. Colours come from the GEL tokens.

const loginPageCSS = `
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: var(--ps-font-sans);
  background: var(--ps-bg-base);
  color: var(--ps-fg);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
}
.container {
  background: var(--ps-glass);
  border: 1px solid var(--ps-border-default);
  border-radius: 16px;
  padding: 28px;
  width: 100%;
  max-width: 420px;
}
@media (min-width: 480px) {
  body { padding: 0; }
  .container { padding: 40px; }
}
.logo { text-align: center; margin-bottom: 30px; }
.logo h1 { font-size: 24px; font-weight: 600; color: var(--ps-fg); }
.badge {
  display: inline-block;
  margin-top: 8px;
  padding: 4px 12px;
  border-radius: var(--ps-radius-pill);
  font-size: 12px;
  font-weight: 600;
  color: var(--ps-protocol-saml);
  background: color-mix(in srgb, var(--ps-protocol-saml) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--ps-protocol-saml) 30%, transparent);
}
.client-info {
  background: var(--ps-bg-raised);
  border: 1px solid var(--ps-border-subtle);
  border-radius: var(--ps-radius-control);
  padding: 16px;
  margin-bottom: 24px;
  text-align: center;
  font-size: 14px;
  color: var(--ps-fg-muted);
  overflow-wrap: anywhere;
}
.client-info strong { color: var(--ps-fg); font-weight: 600; }
.client-info .detail { display: block; margin-top: 6px; font-size: 12px; font-family: var(--ps-font-mono); }
.error {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--ps-status-danger);
  background: color-mix(in srgb, var(--ps-status-danger) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--ps-status-danger) 20%, transparent);
  border-radius: var(--ps-radius-control);
  padding: 12px;
  margin-bottom: 20px;
  font-size: 14px;
}
.error svg { width: 18px; height: 18px; flex: none; }
.form-group { margin-bottom: 20px; }
label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 8px; color: var(--ps-fg-muted); }
input[type="email"], input[type="password"] {
  width: 100%;
  padding: 12px 16px;
  font: inherit;
  font-size: 16px;
  color: var(--ps-fg);
  background: var(--ps-bg-raised);
  border: 1px solid var(--ps-border-default);
  border-radius: var(--ps-radius-control);
}
input::placeholder { color: var(--ps-fg-subtle); }
button {
  width: 100%;
  min-height: 44px;
  padding: 14px;
  font: inherit;
  font-size: 16px;
  font-weight: 600;
  color: var(--ps-bg-base);
  background: var(--ps-interactive);
  border: 1px solid var(--ps-interactive);
  border-radius: var(--ps-radius-control);
  cursor: pointer;
  transition: opacity var(--ps-duration-hover) var(--ps-ease-out);
}
button:hover { opacity: 0.9; }
button.cancel {
  margin-top: 10px;
  color: var(--ps-fg-muted);
  background: transparent;
  border-color: var(--ps-border-strong);
}
button.cancel:hover { opacity: 1; background: var(--ps-glass); }
input:focus-visible, button:focus-visible {
  outline: 2px solid var(--ps-focus-ring);
  outline-offset: 2px;
}
.demo-users { margin-top: 24px; padding-top: 24px; border-top: 1px solid var(--ps-border-default); }
.demo-users h3 { font-size: 14px; font-weight: 500; color: var(--ps-fg-muted); margin-bottom: 12px; }
button.demo-user {
  display: block;
  min-height: 0;
  margin-bottom: 8px;
  padding: 12px;
  text-align: left;
  font-size: 14px;
  font-weight: 400;
  color: var(--ps-fg);
  background: var(--ps-bg-raised);
  border-color: var(--ps-border-subtle);
}
button.demo-user:hover { opacity: 1; background: color-mix(in srgb, var(--ps-interactive) 10%, transparent); border-color: color-mix(in srgb, var(--ps-interactive) 30%, transparent); }
.demo-user .name { display: block; font-weight: 500; }
.demo-user .email { display: block; font-size: 12px; color: var(--ps-fg-muted); }
.footer { margin-top: 16px; font-size: 12px; color: var(--ps-fg-muted); }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
`

var loginPageTemplate = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in - SAML Identity Provider</title>
<style>{{.Tokens}}{{.CSS}}</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <h1>Mock Identity Provider</h1>
    <div class="badge">SAML 2.0</div>
  </div>

  <div class="client-info">
    Signing in to <strong>{{.SP}}</strong>
    {{if .RequestID}}<span class="detail">AuthnRequest {{.RequestID}}{{if .ForceAuthn}} &middot; ForceAuthn{{end}}</span>
    {{else}}<span class="detail">IdP-initiated: unsolicited Response, no AuthnRequest</span>{{end}}
  </div>

  {{if .Error}}<div class="error" role="alert">{{.IconDanger}}<span>{{.Error}}</span></div>{{end}}

  <form method="POST" action="{{.Action}}" autocomplete="off">
    <div class="form-group">
      <label for="email">Email</label>
      <input type="email" id="email" name="email" placeholder="alice@example.com" required autocomplete="username">
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="password" required autocomplete="current-password">
    </div>
    <button type="submit" name="user_action" value="login">Sign In with SAML</button>
  </form>
  <form method="POST" action="{{.Action}}">
    <button type="submit" name="user_action" value="cancel" formnovalidate class="cancel">Cancel</button>
  </form>

  {{if .Users}}<div class="demo-users">
    <h3>Demo Users (click to autofill)</h3>
    {{range .Users}}<button type="button" class="demo-user" data-email="{{.Email}}" data-password="{{.Password}}">
      <span class="name">{{.Name}}</span><span class="email">{{.Email}}</span>
    </button>
    {{end}}
  </div>{{end}}

  <div class="footer">Mock IdP: sign in with a demo user and never enter real credentials. After you sign in, later SAML logins reuse this IdP session until you log out.</div>
</div>
<script>
document.querySelectorAll('.demo-user').forEach(function (button) {
  button.addEventListener('click', function () {
    document.getElementById('email').value = button.dataset.email || '';
    document.getElementById('password').value = button.dataset.password || '';
  });
});
</script>
</body>
</html>`))

func (idp *IdentityProvider) showLoginPage(w http.ResponseWriter, r *http.Request, login *PendingLogin, status int, errorMessage string) {
	http.SetCookie(w, &http.Cookie{
		Name: loginCookieName, Value: login.ID, Path: loginCookiePath,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	type demoUser struct{ Name, Email, Password string }
	var users []demoUser
	for _, preset := range idp.cfg.Users.GetDemoUserPresets() {
		if preset.Credentials.Email == "" || preset.Credentials.Password == "" {
			continue
		}
		users = append(users, demoUser{Name: preset.Name, Email: preset.Credentials.Email, Password: preset.Credentials.Password})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = loginPageTemplate.Execute(w, map[string]interface{}{
		"Tokens":     gel.TokensCSS(),
		"CSS":        template.CSS(loginPageCSS),
		"IconDanger": gel.IconDanger,
		"SP":         idp.cfg.SPEntityID,
		"RequestID":  login.RequestID,
		"ForceAuthn": login.ForceAuthn,
		"Error":      errorMessage,
		"Action":     binding.WithSession(r, idp.cfg.LoginURL),
		"Users":      users,
	})
}
