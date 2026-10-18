package saml

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/session"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/sp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
	"github.com/go-chi/chi/v5"
)

// harness runs the plugin behind a real TLS server so both roles fetch each
// other's metadata over HTTP and every message crosses the bindings.
type harness struct {
	t       *testing.T
	plugin  *Plugin
	server  *httptest.Server
	browser *http.Client
	user    string
	pass    string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	router := chi.NewRouter()
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)

	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatal(err)
	}
	users := mockidp.NewMockIdP(keySet)
	p := NewPlugin()
	p.httpClient = server.Client()
	if err := p.Initialize(context.Background(), plugin.PluginConfig{BaseURL: server.URL, MockIdP: users, KeySet: keySet, CORSOrigins: []string{"http://frontend.example/"}}); err != nil {
		t.Fatal(err)
	}
	router.Route("/saml", p.RegisterRoutes)

	jar, _ := cookiejar.New(nil)
	browser := server.Client()
	browser.Jar = jar
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	user := users.ListUsers()[0]
	return &harness{t: t, plugin: p, server: server, browser: browser, user: user.Email, pass: user.Password}
}

func (h *harness) get(target string) *http.Response {
	h.t.Helper()
	resp, err := h.browser.Get(target)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) post(target string, form url.Values) *http.Response {
	h.t.Helper()
	resp, err := h.browser.PostForm(target, form)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var (
	formActionPattern = regexp.MustCompile(`action="([^"]+)"`)
	formInputPattern  = regexp.MustCompile(`name="(SAMLRequest|SAMLResponse|RelayState)" value="([^"]*)"`)
)

// submitPostForm does what the browser does with an HTTP-POST binding page.
func (h *harness) submitPostForm(page string) *http.Response {
	h.t.Helper()
	action := formActionPattern.FindStringSubmatch(page)
	if action == nil {
		h.t.Fatalf("no form action in page:\n%s", page)
	}
	form := url.Values{}
	for _, m := range formInputPattern.FindAllStringSubmatch(page, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	return h.post(html.UnescapeString(action[1]), form)
}

// loginAtIdP authenticates at the IdP login page and returns the POST
// binding page carrying the SAML Response.
func (h *harness) loginAtIdP() string {
	h.t.Helper()
	resp := h.post(h.server.URL+"/saml/idp/login", url.Values{"email": {h.user}, "password": {h.pass}})
	body := readBody(h.t, resp)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("IdP login: HTTP %d: %s", resp.StatusCode, body)
	}
	return body
}

// pageOutcome is the outcome an ACS or SingleLogoutService page embeds for
// its Looking Glass opener.
type pageOutcome struct {
	binding.Outcome
	Details struct {
		Session    *session.Session `json:"session"`
		StatusCode string           `json:"statusCode"`
	} `json:"details"`
}

var outcomePattern = regexp.MustCompile(`(?s)<script type="application/json" id="saml-outcome">(.*?)</script>`)

func decodeOutcome(t *testing.T, resp *http.Response) (int, pageOutcome) {
	t.Helper()
	body := readBody(t, resp)
	match := outcomePattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("response is not an outcome page (HTTP %d): %s", resp.StatusCode, body)
	}
	var result pageOutcome
	if err := json.Unmarshal([]byte(match[1]), &result); err != nil {
		t.Fatalf("outcome JSON: %v: %s", err, match[1])
	}
	return resp.StatusCode, result
}

func failedCheck(report *binding.Report) string {
	if report == nil {
		return ""
	}
	for _, c := range report.Checks {
		if !c.Passed {
			return c.Name + ": " + c.Detail
		}
	}
	return ""
}

func TestMetadataIsPublishedPerRole(t *testing.T) {
	h := newHarness(t)
	for _, tc := range []struct {
		entityID string
		role     metadata.Role
	}{
		{h.plugin.idp.EntityID(), metadata.RoleIdP},
		{h.plugin.sp.EntityID(), metadata.RoleSP},
	} {
		resp := h.get(tc.entityID)
		body := readBody(t, resp)
		if got := resp.Header.Get("Content-Type"); got != metadata.MediaType {
			t.Fatalf("%s Content-Type = %q", tc.entityID, got)
		}
		meta, err := metadata.Parse([]byte(body), tc.entityID, tc.role, time.Now())
		if err != nil {
			t.Fatalf("%s: %v", tc.entityID, err)
		}
		if len(meta.SigningCerts) != 1 {
			t.Fatalf("%s publishes %d signing certificates", tc.entityID, len(meta.SigningCerts))
		}
		for _, tag := range []string{"OrganizationName", "OrganizationDisplayName", "OrganizationURL", "validUntil", "cacheDuration"} {
			if !strings.Contains(body, tag) {
				t.Errorf("%s metadata lacks %s", tc.entityID, tag)
			}
		}
	}
	if h.plugin.idp.Credentials().Certificate().Equal(h.plugin.sp.Credentials().Certificate()) {
		t.Fatal("IdP and SP share a certificate")
	}
	spMeta, _ := metadata.Parse([]byte(readBody(t, h.get(h.plugin.sp.EntityID()))), h.plugin.sp.EntityID(), metadata.RoleSP, time.Now())
	for _, acs := range spMeta.AssertionConsumers {
		if acs.Binding != message.BindingHTTPPost {
			t.Fatalf("SP publishes an AssertionConsumerService with %s", acs.Binding)
		}
	}
}

func TestSPInitiatedSSOOverBothBindings(t *testing.T) {
	for _, binding := range []string{"redirect", "post"} {
		t.Run(binding, func(t *testing.T) {
			h := newHarness(t)
			resp := h.get(h.server.URL + "/saml/sp/login?binding=" + binding + "&RelayState=target-42")
			var idpResp *http.Response
			if binding == "redirect" {
				if resp.StatusCode != http.StatusFound {
					t.Fatalf("SP login: HTTP %d", resp.StatusCode)
				}
				location := resp.Header.Get("Location")
				for _, param := range []string{"SAMLRequest=", "RelayState=target-42", "SigAlg=", "Signature="} {
					if !strings.Contains(location, param) {
						t.Fatalf("redirect URL lacks %s: %s", param, location)
					}
				}
				idpResp = h.get(location)
			} else {
				idpResp = h.submitPostForm(readBody(t, resp))
			}
			if body := readBody(t, idpResp); idpResp.StatusCode != http.StatusOK || !strings.Contains(body, "/saml/idp/login") {
				t.Fatalf("IdP SSO: HTTP %d: %s", idpResp.StatusCode, body)
			}

			status, result := decodeOutcome(t, h.submitPostForm(h.loginAtIdP()))
			if status != http.StatusOK || !result.Success {
				t.Fatalf("ACS rejected the response: %s (%s)", result.Error, failedCheck(result.Validation))
			}
			if result.Details.Session == nil || result.Details.Session.NameID != h.user || result.Details.Session.SessionIndex == "" {
				t.Fatalf("unexpected session: %+v", result.Details.Session)
			}
			if result.RelayState != "target-42" {
				t.Fatalf("RelayState = %q", result.RelayState)
			}
		})
	}
}

func TestReplayedAssertionIsRejected(t *testing.T) {
	h := newHarness(t)
	readBody(t, h.get(h.server.URL+"/saml/idp/initiate"))
	page := h.loginAtIdP()

	if status, result := decodeOutcome(t, h.submitPostForm(page)); status != http.StatusOK {
		t.Fatalf("first delivery rejected: %s", result.Error)
	}
	status, result := decodeOutcome(t, h.submitPostForm(page))
	if status != http.StatusForbidden || !strings.Contains(failedCheck(result.Validation), "Replay") {
		t.Fatalf("replay accepted or rejected for the wrong reason: HTTP %d %q", status, failedCheck(result.Validation))
	}
}

func TestUnsignedAuthnRequestGetsSAMLErrorResponse(t *testing.T) {
	h := newHarness(t)
	// A real AuthnRequest from the SP, sent without its signature.
	out, err := h.plugin.sp.NewAuthnRequest(context.Background(), message.BindingHTTPPost, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	xmlBytes, _ := message.Serialize(out.Element)
	resp := h.post(h.server.URL+"/saml/idp/sso", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(xmlBytes)}})
	page := readBody(t, resp)
	if !strings.Contains(page, `name="SAMLResponse"`) {
		t.Fatalf("expected an error Response form, got HTTP %d: %s", resp.StatusCode, page)
	}
	// The SP accepts the signed error Response as authentic and reports its status.
	status, result := decodeOutcome(t, h.submitPostForm(page))
	if status != http.StatusForbidden || !strings.Contains(result.Error, message.StatusRequestDenied) {
		t.Fatalf("expected RequestDenied, got HTTP %d %q", status, result.Error)
	}
}

func TestTamperedRedirectQueryIsDiscarded(t *testing.T) {
	h := newHarness(t)
	location := h.get(h.server.URL + "/saml/sp/login?RelayState=original").Header.Get("Location")
	tampered := strings.Replace(location, "RelayState=original", "RelayState=modified", 1)
	resp := h.get(tampered)
	if body := readBody(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Signature") {
		t.Fatalf("tampered query accepted: HTTP %d %s", resp.StatusCode, body)
	}
}

func TestRelayStateLongerThan80BytesIsRefused(t *testing.T) {
	h := newHarness(t)
	resp := h.get(h.server.URL + "/saml/sp/login?RelayState=" + strings.Repeat("a", binding.MaxRelayStateBytes+1))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
}

func TestSignedRequestWithWrongDestinationIsDiscarded(t *testing.T) {
	h := newHarness(t)
	request := message.BuildAuthnRequest(message.AuthnRequestParams{
		Issuer: h.plugin.sp.EntityID(), Destination: "https://elsewhere.example/sso", ACSURL: h.plugin.sp.ACSURL(), NameIDFormat: message.NameIDFormatEmail,
	})
	xmlBytes, err := binding.SignedPostXML(request, h.plugin.sp.Credentials())
	if err != nil {
		t.Fatal(err)
	}
	resp := h.post(h.server.URL+"/saml/idp/sso", url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(xmlBytes)}})
	if body := readBody(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Destination") {
		t.Fatalf("HTTP %d: %s", resp.StatusCode, body)
	}
}

// issueSignedResponse returns a Response the IdP signed for an unsolicited
// login, without delivering it.
func (h *harness) issueSignedResponse() *etree.Element {
	h.t.Helper()
	login, err := h.plugin.idp.StartUnsolicited(context.Background(), "", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	user, _ := h.plugin.idp.Authenticate(h.user, h.pass)
	out, _, err := h.plugin.idp.IssueResponse(login, user, time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	if err := xmldsig.SignEnveloped(out.Element, h.plugin.idp.Credentials()); err != nil {
		h.t.Fatal(err)
	}
	return out.Element
}

func (h *harness) deliver(response *etree.Element) (*sp.SSOResult, error) {
	h.t.Helper()
	xmlBytes, err := message.Serialize(response)
	if err != nil {
		h.t.Fatal(err)
	}
	msg, err := binding.PostMessage(binding.ParamSAMLResponse, xmlBytes, "")
	if err != nil {
		h.t.Fatal(err)
	}
	return h.plugin.sp.ConsumeResponse(context.Background(), msg)
}

func TestTamperedAssertionIsRejected(t *testing.T) {
	h := newHarness(t)
	response := h.issueSignedResponse()
	response.FindElement(".//NameID").SetText("attacker@example.com")
	if _, err := h.deliver(response); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered assertion accepted: %v", err)
	}
}

func TestSignatureWrappingIsRejected(t *testing.T) {
	t.Run("assertion inserted under a signed Response", func(t *testing.T) {
		h := newHarness(t)
		response := h.issueSignedResponse()
		evil := response.FindElement("./Assertion").Copy()
		evil.FindElement(".//NameID").SetText("attacker@example.com")
		response.InsertChildAt(response.FindElement("./Assertion").Index(), evil)
		if _, err := h.deliver(response); err == nil || !strings.Contains(err.Error(), "verification failed") {
			t.Fatalf("wrapped response accepted or rejected for the wrong reason: %v", err)
		}
	})
	t.Run("duplicate assertion ID", func(t *testing.T) {
		h := newHarness(t)
		response := h.issueSignedResponse()
		response.RemoveChild(response.FindElement("./Signature"))
		assertion := response.FindElement("./Assertion")
		evil := assertion.Copy() // keeps the original's valid <ds:Signature>
		evil.FindElement(".//NameID").SetText("attacker@example.com")
		response.InsertChildAt(assertion.Index(), evil)
		if _, err := h.deliver(response); err == nil || !strings.Contains(err.Error(), "declared 2 times") {
			t.Fatalf("wrapped response accepted or rejected for the wrong reason: %v", err)
		}
	})
	t.Run("signed assertion moved aside", func(t *testing.T) {
		h := newHarness(t)
		response := h.issueSignedResponse()
		response.RemoveChild(response.FindElement("./Signature"))
		assertion := response.FindElement("./Assertion")
		response.RemoveChild(assertion)
		extensions := response.CreateElement("samlp:Extensions")
		extensions.AddChild(assertion)
		evil := assertion.Copy()
		evil.RemoveChild(evil.FindElement("./Signature"))
		evil.CreateAttr("ID", message.GenerateID())
		evil.FindElement(".//NameID").SetText("attacker@example.com")
		response.AddChild(evil)
		if _, err := h.deliver(response); err == nil || !strings.Contains(err.Error(), "unsigned") {
			t.Fatalf("wrapped response accepted: %v", err)
		}
	})
}

func TestSignatureFromKeyOutsideMetadataIsRejected(t *testing.T) {
	h := newHarness(t)
	attacker, err := xmldsig.NewCredentials("https://attacker.example")
	if err != nil {
		t.Fatal(err)
	}
	login, _ := h.plugin.idp.StartUnsolicited(context.Background(), "", nil)
	user, _ := h.plugin.idp.Authenticate(h.user, h.pass)
	out, _, _ := h.plugin.idp.IssueResponse(login, user, time.Now())
	// Re-sign the assertion and the Response with a key whose certificate is
	// carried in KeyInfo but not published in the IdP's metadata.
	assertion := out.Element.FindElement("./Assertion")
	assertion.RemoveChild(assertion.FindElement("./Signature"))
	if err := xmldsig.SignEnveloped(assertion, attacker); err != nil {
		t.Fatal(err)
	}
	if err := xmldsig.SignEnveloped(out.Element, attacker); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deliver(out.Element); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("response signed by an unknown key accepted: %v", err)
	}
}

func TestSingleLogoutOverRedirectBinding(t *testing.T) {
	h := newHarness(t)
	readBody(t, h.get(h.server.URL+"/saml/idp/initiate"))
	_, result := decodeOutcome(t, h.submitPostForm(h.loginAtIdP()))
	if result.Details.Session == nil {
		t.Fatalf("SSO failed: %s", result.Error)
	}

	resp := h.get(h.server.URL + "/saml/sp/logout?binding=redirect&session_id=" + url.QueryEscape(result.Details.Session.ID))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("SP logout: HTTP %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp = h.get(resp.Header.Get("Location")) // LogoutRequest at the IdP
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP SLO: HTTP %d %s", resp.StatusCode, readBody(t, resp))
	}
	status, outcome := decodeOutcome(t, h.get(resp.Header.Get("Location"))) // LogoutResponse at the SP
	if status != http.StatusOK || !outcome.Success || outcome.Details.StatusCode != message.StatusSuccess {
		t.Fatalf("SP SLO: HTTP %d %s (%s)", status, outcome.Error, failedCheck(outcome.Validation))
	}
	if n := len(h.plugin.idp.Sessions()) + len(h.plugin.sp.Sessions()); n != 0 {
		t.Fatalf("%d sessions remain after Single Logout", n)
	}
}

// TestCaptureSessionFollowsEveryHop starts SP-initiated SSO with a Looking
// Glass capture session and checks that each endpoint the user agent is sent
// to carries it, outside the signed query values.
func TestCaptureSessionFollowsEveryHop(t *testing.T) {
	for _, bindingName := range []string{"redirect", "post"} {
		t.Run(bindingName, func(t *testing.T) {
			h := newHarness(t)
			resp := h.get(h.server.URL + "/saml/sp/login?binding=" + bindingName + "&lg_session=lg-123")
			var idpResp *http.Response
			if bindingName == "redirect" {
				location := resp.Header.Get("Location")
				if !strings.Contains(location, "lg_session=lg-123") {
					t.Fatalf("redirect to the IdP lost lg_session: %s", location)
				}
				idpResp = h.get(location)
			} else {
				page := readBody(t, resp)
				if !strings.Contains(page, "lg_session=lg-123") {
					t.Fatalf("POST form to the IdP lost lg_session: %s", page)
				}
				idpResp = h.submitPostForm(page)
			}
			loginPage := readBody(t, idpResp)
			if idpResp.StatusCode != http.StatusOK || !strings.Contains(loginPage, "/saml/idp/login?lg_session=lg-123") {
				t.Fatalf("IdP login form lost lg_session (HTTP %d): %s", idpResp.StatusCode, loginPage)
			}
			form := h.post(h.server.URL+"/saml/idp/login?lg_session=lg-123", url.Values{"email": {h.user}, "password": {h.pass}})
			page := readBody(t, form)
			if !strings.Contains(page, "/saml/sp/acs?lg_session=lg-123") {
				t.Fatalf("POST form to the ACS lost lg_session: %s", page)
			}
			status, outcome := decodeOutcome(t, h.submitPostForm(page))
			if status != http.StatusOK || !outcome.Success {
				t.Fatalf("ACS: HTTP %d %s (%s)", status, outcome.Error, failedCheck(outcome.Validation))
			}
		})
	}
}

// TestOutcomePageAddressesOnlyConfiguredOrigins checks the origins an outcome
// page will hand its result to.
func TestOutcomePageAddressesOnlyConfiguredOrigins(t *testing.T) {
	h := newHarness(t)
	readBody(t, h.get(h.server.URL+"/saml/idp/initiate"))
	body := readBody(t, h.submitPostForm(h.loginAtIdP()))
	match := regexp.MustCompile(`<script type="application/json" id="saml-opener-origins">(.*?)</script>`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("outcome page has no opener origins: %s", body)
	}
	var origins []string
	if err := json.Unmarshal([]byte(match[1]), &origins); err != nil {
		t.Fatal(err)
	}
	if len(origins) != 2 || origins[0] != h.server.URL || origins[1] != "http://frontend.example" {
		t.Fatalf("opener origins = %v", origins)
	}
}

// TestLateAssertionAfterIdPInitiatedLogoutIsRefused issues an assertion,
// lets the IdP log the session out at the SP first, and then delivers the
// assertion: SAML Core Section 3.7.3.1 requires the SP to apply the logout
// "even if the assertion arrives after the logout request".
func TestLateAssertionAfterIdPInitiatedLogoutIsRefused(t *testing.T) {
	h := newHarness(t)
	response := h.issueSignedResponse()
	idpSessions := h.plugin.idp.Sessions()
	if len(idpSessions) != 1 {
		t.Fatalf("IdP holds %d sessions", len(idpSessions))
	}

	resp := h.get(h.server.URL + "/saml/idp/logout?binding=redirect&session_id=" + url.QueryEscape(idpSessions[0].ID))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("IdP logout: HTTP %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp = h.get(resp.Header.Get("Location")) // LogoutRequest at the SP
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("SP SLO: HTTP %d %s", resp.StatusCode, readBody(t, resp))
	}
	status, outcome := decodeOutcome(t, h.get(resp.Header.Get("Location"))) // LogoutResponse at the IdP
	if status != http.StatusOK || !outcome.Success || outcome.Details.StatusCode != message.StatusSuccess {
		t.Fatalf("IdP-initiated logout over HTTP-Redirect: HTTP %d %s (%s)", status, outcome.Error, failedCheck(outcome.Validation))
	}

	if _, err := h.deliver(response); err == nil || !strings.Contains(err.Error(), "LogoutRequest already processed") {
		t.Fatalf("late assertion accepted after logout: %v", err)
	}
}

// startSSO sends a signed AuthnRequest from the SP over HTTP-Redirect and
// returns the IdP's answer: the sign-in page, or the HTTP-POST form carrying
// the Response when the IdP answers from its session.
func (h *harness) startSSO(query string) (*http.Response, string) {
	h.t.Helper()
	resp := h.get(h.server.URL + "/saml/sp/login?binding=redirect" + query)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("SP login: HTTP %d %s", resp.StatusCode, readBody(h.t, resp))
	}
	idpResp := h.get(resp.Header.Get("Location"))
	return idpResp, readBody(h.t, idpResp)
}

func isSignInPage(page string) bool {
	return strings.Contains(page, `name="password"`)
}

func isResponseForm(page string) bool {
	return strings.Contains(page, `name="SAMLResponse"`)
}

// signInOnce completes one SP-initiated SSO by signing in at the IdP.
func (h *harness) signInOnce() pageOutcome {
	h.t.Helper()
	_, page := h.startSSO("")
	if !isSignInPage(page) {
		h.t.Fatalf("first SSO did not ask for credentials: %s", page)
	}
	status, outcome := decodeOutcome(h.t, h.submitPostForm(h.loginAtIdP()))
	if status != http.StatusOK || !outcome.Success {
		h.t.Fatalf("first SSO failed: %s (%s)", outcome.Error, failedCheck(outcome.Validation))
	}
	return outcome
}

// TestSecondSSOReusesTheIdPSession is single sign-on: after one sign-in, the
// IdP answers the next AuthnRequest from its session without asking for
// credentials (SAML Profiles Section 4.1.3.4).
func TestSecondSSOReusesTheIdPSession(t *testing.T) {
	h := newHarness(t)
	first := h.signInOnce()

	_, page := h.startSSO("")
	if isSignInPage(page) || !isResponseForm(page) {
		t.Fatalf("second SSO did not answer from the IdP session: %s", page)
	}
	status, second := decodeOutcome(t, h.submitPostForm(page))
	if status != http.StatusOK || !second.Success {
		t.Fatalf("second SSO rejected: %s (%s)", second.Error, failedCheck(second.Validation))
	}
	if second.Details.Session.AuthnInstant != first.Details.Session.AuthnInstant {
		t.Fatalf("AuthnInstant %s is not the original authentication %s", second.Details.Session.AuthnInstant, first.Details.Session.AuthnInstant)
	}

	resp := h.get(h.server.URL + "/saml/idp/initiate")
	if page := readBody(t, resp); !isResponseForm(page) {
		t.Fatalf("IdP-initiated SSO did not reuse the session: %s", page)
	}
}

func TestForceAuthnAsksForCredentialsAgain(t *testing.T) {
	h := newHarness(t)
	h.signInOnce()
	_, page := h.startSSO("&force_authn=true")
	if !isSignInPage(page) || !strings.Contains(page, "ForceAuthn") {
		t.Fatalf("ForceAuthn did not ask the principal to authenticate: %s", page)
	}
}

func TestIsPassive(t *testing.T) {
	h := newHarness(t)
	_, page := h.startSSO("&is_passive=true")
	if !isResponseForm(page) {
		t.Fatalf("IsPassive without a session did not get an error Response: %s", page)
	}
	if status, outcome := decodeOutcome(t, h.submitPostForm(page)); status != http.StatusForbidden || !strings.Contains(outcome.Error, message.StatusNoPassive) {
		t.Fatalf("expected NoPassive, got HTTP %d %q", status, outcome.Error)
	}

	h.signInOnce()
	_, page = h.startSSO("&is_passive=true")
	if status, outcome := decodeOutcome(t, h.submitPostForm(page)); status != http.StatusOK || !outcome.Success {
		t.Fatalf("IsPassive with a session failed: HTTP %d %s", status, outcome.Error)
	}
	_, page = h.startSSO("&is_passive=true&force_authn=true")
	if status, outcome := decodeOutcome(t, h.submitPostForm(page)); status != http.StatusForbidden || !strings.Contains(outcome.Error, message.StatusNoPassive) {
		t.Fatalf("ForceAuthn with IsPassive: expected NoPassive, got HTTP %d %q", status, outcome.Error)
	}
}

// TestLogoutEndsTheIdPSession: after Single Logout the session authority has
// terminated the principal's session (SAML Core Section 3.7.3.2), so the next
// SSO asks for credentials.
func TestLogoutEndsTheIdPSession(t *testing.T) {
	h := newHarness(t)
	first := h.signInOnce()
	resp := h.get(h.server.URL + "/saml/sp/logout?binding=redirect&session_id=" + url.QueryEscape(first.Details.Session.ID))
	resp = h.get(resp.Header.Get("Location"))
	if status, outcome := decodeOutcome(t, h.get(resp.Header.Get("Location"))); status != http.StatusOK || !outcome.Success {
		t.Fatalf("SLO failed: HTTP %d %s", status, outcome.Error)
	}
	if _, page := h.startSSO(""); !isSignInPage(page) {
		t.Fatalf("SSO after logout did not ask for credentials: %s", page)
	}
}

func TestWrongPasswordCanBeRetried(t *testing.T) {
	h := newHarness(t)
	h.startSSO("")
	resp := h.post(h.server.URL+"/saml/idp/login", url.Values{"email": {h.user}, "password": {"wrong"}})
	if page := readBody(t, resp); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(page, "Invalid email or password") {
		t.Fatalf("wrong password: HTTP %d %s", resp.StatusCode, page)
	}
	if status, outcome := decodeOutcome(t, h.submitPostForm(h.loginAtIdP())); status != http.StatusOK || !outcome.Success {
		t.Fatalf("retry failed: HTTP %d %s", status, outcome.Error)
	}
}

func TestCancelSendsAuthnFailed(t *testing.T) {
	h := newHarness(t)
	h.startSSO("")
	resp := h.post(h.server.URL+"/saml/idp/login", url.Values{"user_action": {"cancel"}})
	page := readBody(t, resp)
	if !isResponseForm(page) {
		t.Fatalf("cancel did not send an error Response: %s", page)
	}
	if status, outcome := decodeOutcome(t, h.submitPostForm(page)); status != http.StatusForbidden || !strings.Contains(outcome.Error, message.StatusAuthnFailed) {
		t.Fatalf("expected AuthnFailed, got HTTP %d %q", status, outcome.Error)
	}
}
