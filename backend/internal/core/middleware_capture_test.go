package core

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

func TestCaptureMiddlewareNeverPersistsPrivateJWKOrOwnerCapability(t *testing.T) {
	for name, body := range map[string]string{
		"valid private JWKS": `{"keys":[{"kty":"RSA","n":"public","e":"AQAB","d":"private-d","p":"private-p","q":"private-q","dp":"private-dp","dq":"private-dq","qi":"private-qi","oth":[{"r":"private-r"}],"k":"private-k"}]}`,
		"malformed JWKS":     `{"keys":[{"d":"malformed-private-value"}`,
	} {
		t.Run(name, func(t *testing.T) {
			engine := lookingglass.NewEngine()
			session, ownerToken, err := engine.CreateSession("oauth2", "client_credentials")
			if err != nil {
				t.Fatal(err)
			}
			handler := CaptureMiddleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusBadRequest)
			}))
			request := httptest.NewRequest(
				http.MethodPost,
				"https://as.example/oauth2/demo/clients/machine-client-pkjwt/jwks",
				strings.NewReader(body),
			)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(captureSessionHeader, session.ID)
			request.Header.Set(lookingglass.OwnerTokenHeader, ownerToken)
			handler.ServeHTTP(httptest.NewRecorder(), request)

			snapshot, authorized := engine.AuthorizedSessionSnapshot(session.ID, ownerToken)
			if !authorized || len(snapshot.Events) != 1 {
				t.Fatalf("captured events = %#v", snapshot)
			}
			persisted, err := json.Marshal(snapshot.Events)
			if err != nil {
				t.Fatal(err)
			}
			persistedText := string(persisted)
			for _, secret := range []string{
				ownerToken,
				"private-d",
				"private-p",
				"private-q",
				"private-dp",
				"private-dq",
				"private-qi",
				"private-r",
				"private-k",
				"malformed-private-value",
			} {
				if strings.Contains(persistedText, secret) {
					t.Fatalf("capture persisted secret %q: %s", secret, persistedText)
				}
			}
			if !strings.Contains(persistedText, "REDACTED") &&
				!strings.Contains(persistedText, "redacted") {
				t.Fatalf("capture did not explain redaction: %s", persistedText)
			}
		})
	}
}
