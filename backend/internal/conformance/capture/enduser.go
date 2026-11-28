package capture

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// The End-User's side of an authorization_code issuance. The hosted wallet
// answers /api/import with an authorization_url and waits for the
// Authorization Response at its callback; between the two stands the
// End-User, who authenticates at the Mock IdP in a browser. The conformance
// client plays that user agent: it opens the Authorization Request, signs
// in as a demo user, and delivers the Authorization Response to the wallet.
//
// How the End-User authenticates is the authorization server's own business,
// not an OpenID4VCI exchange, so the login page and the credentials posted to
// it are not recorded. The Authorization Response is: it is the request the
// user agent makes to the wallet's callback, and it is followed by every hop
// the wallet made to redeem the code.

// walletCallbackPath is the hosted wallet's redirect_uri path.
const walletCallbackPath = "/api/oid4vci/callback"

// loginRequestIDPattern finds the hidden login_request_id field of the Mock
// IdP's login page, which ties the posted credentials to the pending
// Authorization Request.
var loginRequestIDPattern = regexp.MustCompile(`name="login_request_id" value="([^"]+)"`)

// AuthorizeAsEndUser completes the authorization the wallet asked for in an
// import answered authorization_required, in the same wallet session. It
// returns the wallet's callback answer, with the hops it recorded while
// redeeming the code, and the Authorization Response parameters as the
// authorization server delivered them.
func AuthorizeAsEndUser(ctx context.Context, env *Env, authorizationURL, session string) (*WalletResult, url.Values, error) {
	callbackURL, err := AuthenticateEndUser(ctx, env, authorizationURL, false)
	if err != nil {
		return nil, nil, err
	}
	// The Authorization Response must come back to the wallet that pushed
	// the request, at its registered redirect_uri.
	if !strings.HasPrefix(callbackURL, env.WalletURL+walletCallbackPath+"?") {
		return nil, nil, fmt.Errorf("the Authorization Response went to %q, not the wallet's callback", callbackURL)
	}
	response, err := url.ParseQuery(strings.TrimPrefix(callbackURL, env.WalletURL+walletCallbackPath+"?"))
	if err != nil {
		return nil, nil, fmt.Errorf("parse the Authorization Response query: %w", err)
	}
	result, err := CallWallet(ctx, env, WalletCall{
		Method:  http.MethodGet,
		Path:    strings.TrimPrefix(callbackURL, env.WalletURL),
		Session: session,
	})
	if err != nil {
		return nil, nil, err
	}
	return result, response, nil
}

// AuthenticateEndUser sends the Authorization Request at authorizationURL
// as the End-User's user agent, signs in at the Mock IdP as a demo user, and
// returns the URL the authorization server redirects the user agent to: the
// Authorization Response. With record set, the Authorization Request and the
// login page that answers it are recorded. The sign-in never is.
func AuthenticateEndUser(ctx context.Context, env *Env, authorizationURL string, record bool) (string, error) {
	if !strings.HasPrefix(authorizationURL, env.BaseURL+"/") {
		return "", fmt.Errorf("the authorization URL %q is not at the main app", authorizationURL)
	}
	loginRequestID, err := openAuthorizationRequest(ctx, env, authorizationURL, record)
	if err != nil {
		return "", err
	}
	email, password, err := DemoUser(ctx, env)
	if err != nil {
		return "", err
	}
	return signIn(ctx, env, loginRequestID, email, password)
}

// openAuthorizationRequest fetches the Authorization Request as a browser
// would and returns the login request the Mock IdP opened for it.
func openAuthorizationRequest(ctx context.Context, env *Env, authorizationURL string, record bool) (string, error) {
	req, err := http.NewRequest(http.MethodGet, authorizationURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html")
	do := env.Setup
	if record {
		do = env.Do
	}
	resp, err := do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("the Authorization Request was answered %d, not the login page: %s", resp.Status, Truncate(resp.Body))
	}
	match := loginRequestIDPattern.FindSubmatch(resp.Body)
	if match == nil {
		return "", fmt.Errorf("the authorization server's %d answer carries no login_request_id field", resp.Status)
	}
	return string(match[1]), nil
}

// DemoUser reads the first demo user's credentials from /oauth2/demo/users,
// the public listing the Mock IdP's login page offers for autofill.
func DemoUser(ctx context.Context, env *Env) (email, password string, err error) {
	req, err := http.NewRequest(http.MethodGet, env.BaseURL+"/oauth2/demo/users", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", "", err
	}
	body, err := resp.JSON()
	if err != nil {
		return "", "", err
	}
	users, _ := body["users"].([]any)
	for _, raw := range users {
		user, _ := raw.(map[string]any)
		credentials, _ := user["credentials"].(map[string]any)
		email, _ = credentials["email"].(string)
		password, _ = credentials["password"].(string)
		if email != "" && password != "" {
			return email, password, nil
		}
	}
	return "", "", fmt.Errorf("/oauth2/demo/users lists no user with credentials")
}

// signIn posts the demo user's credentials to the Mock IdP's login form and
// returns the Authorization Response it redirects the user agent to.
func signIn(ctx context.Context, env *Env, loginRequestID, email, password string) (string, error) {
	req, err := NewForm(env.BaseURL+"/oidc/authorize", url.Values{
		"login_request_id": {loginRequestID},
		"email":            {email},
		"password":         {password},
	})
	if err != nil {
		return "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusFound && resp.Status != http.StatusSeeOther {
		return "", fmt.Errorf("the login was answered %d, not an Authorization Response redirect: %s", resp.Status, Truncate(resp.Body))
	}
	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("the %d Authorization Response carries no Location", resp.Status)
	}
	return location, nil
}
