// Package agentauth implements agentic registration as described by the
// auth.md profile (https://github.com/workos/auth.md).
//
// An autonomous agent registers itself at the identity endpoint, receives a
// service-signed identity assertion, and exchanges that assertion for an
// access token using the JWT bearer authorization grant of RFC 7523. An agent
// that registered anonymously can later be bound to a human owner through a
// claim ceremony modelled on the RFC 8628 device authorization grant: the
// service issues a user_code, a person approves it in a browser, and the agent
// polls the token endpoint until the binding completes.
package agentauth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/go-chi/chi/v5"
)

const (
	// identityAssertionTTL bounds how long a freshly minted identity
	// assertion may be exchanged at the token endpoint. RFC 7523 Section 3
	// requires an exp claim and requires the authorization server to reject
	// expired assertions; a short window keeps a leaked assertion useful for
	// very little time.
	identityAssertionTTL = 10 * time.Minute

	// claimAttemptTTL is the lifetime of a single user_code, mirroring the
	// expires_in of RFC 8628 Section 3.2.
	claimAttemptTTL = 10 * time.Minute

	// claimTokenTTL is the outer window during which an agent may run claim
	// attempts. RFC 8628 has a single window; auth.md separates the two so a
	// user_code can expire and be reissued without restarting registration.
	claimTokenTTL = 24 * time.Hour

	// pollInterval is the minimum spacing between token endpoint polls,
	// returned as "interval" per RFC 8628 Section 3.2 and enforced with the
	// slow_down error of Section 3.5.
	pollInterval = 5 * time.Second

	// accessTokenTTL is the lifetime of an agent access token.
	accessTokenTTL = time.Hour
)

// Grant type and assertion identifiers.
const (
	// grantTypeJWTBearer is the JWT bearer authorization grant of RFC 7523
	// Section 2.1.
	grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// grantTypeClaim is the auth.md profile grant an agent polls while a
	// claim ceremony is outstanding.
	grantTypeClaim = "urn:workos:agent-auth:grant-type:claim"

	// assertionTypeIDJAG identifies an Identity Assertion Authorization Grant
	// minted by an external agent provider.
	assertionTypeIDJAG = "urn:ietf:params:oauth:token-type:id-jag"

	// credentialTypeJWT is the credential this service issues in exchange for
	// an identity assertion.
	credentialTypeJWT = "urn:ietf:params:oauth:token-type:access_token"

	// eventAssertionRevoked is the auth.md revocation event.
	eventAssertionRevoked = "https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"
)

// Identity types this service accepts at the identity endpoint.
const (
	identityTypeAnonymous = "anonymous"
	identityTypeAssertion = "identity_assertion"
)

// Scopes granted before and after a claim ceremony binds an agent to a person.
const (
	scopePreClaim  = "agent:read"
	scopePostClaim = "agent:read agent:write"
)

// agentIdentity is a registered agent. It is created by the identity endpoint
// and lives until its claim window closes.
type agentIdentity struct {
	AgentID      string
	IdentityType string
	// Email is empty until a claim ceremony completes, at which point it
	// records the person who took ownership of the agent.
	Email string
	// AssertionVersion increments when the agent's standing changes, so a
	// post-claim assertion is distinguishable from the pre-claim one.
	AssertionVersion int
	Claimed          bool
	Revoked          bool
	ClaimToken       string
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

// claimAttempt is one outstanding user_code within an agent's claim window.
type claimAttempt struct {
	UserCode          string
	ClaimAttemptToken string
	ClaimToken        string
	Email             string
	Completed         bool
	CreatedAt         time.Time
	ExpiresAt         time.Time
	LastPolledAt      time.Time
}

// Plugin implements agentic registration.
type Plugin struct {
	*plugin.BasePlugin

	mockIdP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string

	mu sync.RWMutex
	// identities is keyed by claim_token, the only handle an agent holds
	// after registration.
	identities map[string]*agentIdentity
	// attempts is keyed by user_code so the browser-side completion can find
	// the pending attempt from what the person typed in.
	attempts map[string]*claimAttempt
	// seenAssertionIDs records the jti of every assertion already redeemed,
	// so a bearer assertion cannot be replayed (RFC 7523 Section 3).
	seenAssertionIDs map[string]time.Time

	stop chan struct{}
}

// NewPlugin creates the agentic registration plugin.
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "agentauth",
			Name:        "Agentic Registration",
			Version:     "1.0.0",
			Description: "Registration and credential issuance for autonomous agents: identity assertions, an RFC 8628-style claim ceremony that binds an agent to a person, and the RFC 7523 JWT bearer grant that turns an assertion into an access token.",
			Tags:        []string{"agents", "authentication", "registration", "auth.md"},
			RFCs:        []string{"RFC 7523", "RFC 8628", "RFC 8414", "RFC 9728", "auth.md"},
		}),
		identities:       make(map[string]*agentIdentity),
		attempts:         make(map[string]*claimAttempt),
		seenAssertionIDs: make(map[string]time.Time),
		stop:             make(chan struct{}),
	}
}

// Initialize wires the plugin to shared infrastructure.
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	p.SetConfig(config)
	p.baseURL = strings.TrimRight(config.BaseURL, "/")

	if idp, ok := config.MockIdP.(*mockidp.MockIdP); ok {
		p.mockIdP = idp
	}
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}

	go p.pruneExpiredState()

	return nil
}

// Shutdown stops the background pruner.
func (p *Plugin) Shutdown(ctx context.Context) error {
	close(p.stop)
	return nil
}

// RegisterRoutes registers the plugin's HTTP routes.
func (p *Plugin) RegisterRoutes(router chi.Router) {
	// RFC 8414 metadata for this authorization server, carrying the auth.md
	// agent_auth block. The wildcard serves the canonical root-level URL
	// /.well-known/oauth-authorization-server/agentauth, which the core
	// router forwards here with the path intact.
	router.Get("/.well-known/oauth-authorization-server", p.handleAuthorizationServerMetadata)
	router.Get("/.well-known/oauth-authorization-server/*", p.handleAuthorizationServerMetadata)

	// Registration and the claim ceremony.
	router.Post("/identity", p.handleIdentity)
	router.Post("/identity/claim", p.handleClaimStart)
	router.Post("/identity/claim/complete", p.handleClaimComplete)

	// The verification_uri a person opens to approve an agent.
	router.Get("/claim", p.handleClaimPage)

	// Token endpoint for the JWT bearer and claim grants.
	router.Post("/token", p.handleToken)

	// Revocation (RFC 7009 shape) for issued identity assertions.
	router.Post("/revoke", p.handleRevoke)
}

// issuer is this authorization server's issuer identifier. RFC 8414
// Section 3.1 places its metadata at
// /.well-known/oauth-authorization-server/agentauth.
func (p *Plugin) issuer() string {
	return p.origin() + "/agentauth"
}

// origin is the deployment's public origin.
func (p *Plugin) origin() string {
	if p.mockIdP != nil {
		if issuer := strings.TrimRight(p.mockIdP.GetIssuer(), "/"); issuer != "" {
			return issuer
		}
	}
	return p.baseURL
}

// emitEvent publishes a Looking Glass event for the session driving this
// request, when there is one.
func (p *Plugin) emitEvent(sessionID string, eventType lookingglass.EventType, title string, data map[string]interface{}, annotations ...lookingglass.Annotation) {
	if p.lookingGlass == nil || sessionID == "" {
		return
	}
	p.lookingGlass.NewEventBroadcaster(sessionID).Emit(eventType, title, data, annotations...)
}

// sessionFromRequest extracts the Looking Glass session identifier.
func (p *Plugin) sessionFromRequest(r *http.Request) string {
	if s := r.Header.Get("X-Looking-Glass-Session"); s != "" {
		return s
	}
	return r.URL.Query().Get("lg_session")
}

// pruneExpiredState evicts registrations and claim attempts whose windows have
// closed, along with replay records that can no longer match a live assertion.
func (p *Plugin) pruneExpiredState() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.evictExpiredState()
		}
	}
}

func (p *Plugin) evictExpiredState() {
	now := time.Now()

	p.mu.Lock()
	defer p.mu.Unlock()

	for token, identity := range p.identities {
		if now.After(identity.ExpiresAt) {
			delete(p.identities, token)
		}
	}
	for code, attempt := range p.attempts {
		if now.After(attempt.ExpiresAt) {
			delete(p.attempts, code)
		}
	}
	// An assertion can only be replayed while it would still verify, so
	// replay records outlive the assertion lifetime by a small margin and no
	// longer.
	for id, seenAt := range p.seenAssertionIDs {
		if now.Sub(seenAt) > identityAssertionTTL+time.Minute {
			delete(p.seenAssertionIDs, id)
		}
	}
}

// writeJSON writes a JSON body with the given status.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// writeOAuthError writes an OAuth 2.0 error response (RFC 6749 Section 5.2).
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// randomToken returns a URL-safe random string with 256 bits of entropy.
func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is not a recoverable condition for a
		// credential-issuing endpoint.
		panic("agentauth: secure random source unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// userCodeAlphabet excludes vowels and easily confused characters so a person
// reading a code aloud or typing it in cannot produce a different valid code.
// RFC 8628 Section 6.1 recommends exactly this kind of reduced alphabet.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// newUserCode returns a code in the WDJB-MJHT shape used by RFC 8628
// Section 3.2. Twenty symbols across eight positions is a little over 34 bits
// of entropy, and the code is single-use and expires in ten minutes.
func newUserCode() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic("agentauth: secure random source unavailable: " + err.Error())
	}
	out := make([]byte, 0, 9)
	for i, b := range buf {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
	}
	return string(out)
}

// normalizeUserCode makes comparison forgiving of the ways a person may retype
// a code, as RFC 8628 Section 6.1 advises.
func normalizeUserCode(input string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(input), " ", ""))
}

// newAgentID returns a stable, opaque subject identifier for a registered
// agent.
func newAgentID() string {
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		panic("agentauth: secure random source unavailable: " + err.Error())
	}
	return "agent-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
}
