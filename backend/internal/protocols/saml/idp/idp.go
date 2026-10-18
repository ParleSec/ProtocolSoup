// Package idp is the SAML 2.0 identity provider: a separate entity from the
// service provider, with its own entityID, signing key and metadata. It knows
// one service provider, whose endpoints and keys come only from the SP's
// metadata, fetched over HTTP from the SP's entityID. It cannot import the sp
// package.
package idp

import (
	"context"
	"fmt"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/logout"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/session"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/beevik/etree"
)

const (
	assertionLifetime = 5 * time.Minute
	pendingTTL        = 10 * time.Minute
)

// Config describes the identity provider's endpoints, keys, users and the
// service provider it serves.
type Config struct {
	EntityID    string // also the URL its metadata is published at
	SSOURL      string
	SLOURL      string
	LoginURL    string
	SPEntityID  string
	Credentials *xmldsig.Credentials
	Resolver    *metadata.Resolver
	Users       *mockidp.MockIdP
	Events      binding.Events
}

// IdentityProvider is the SAML IdP role.
type IdentityProvider struct {
	cfg            Config
	logins         *loginStore
	logoutRequests *session.Pending
	sessions       *session.Store // assertions issued to the SP
	authn          *authnStore    // the IdP's own authentication sessions
}

// New returns an identity provider with empty state.
func New(cfg Config) *IdentityProvider {
	return &IdentityProvider{
		cfg:            cfg,
		logins:         newLoginStore(pendingTTL),
		logoutRequests: session.NewPending(pendingTTL),
		sessions:       session.NewStore(),
		authn:          newAuthnStore(),
	}
}

func (idp *IdentityProvider) EntityID() string                  { return idp.cfg.EntityID }
func (idp *IdentityProvider) SLOURL() string                    { return idp.cfg.SLOURL }
func (idp *IdentityProvider) Credentials() *xmldsig.Credentials { return idp.cfg.Credentials }

// Sessions lists the sessions the IdP issued assertions for.
func (idp *IdentityProvider) Sessions() []*session.Session { return idp.sessions.List() }

// Authenticate checks the principal's credentials against the mock IdP's users.
func (idp *IdentityProvider) Authenticate(email, password string) (*models.User, error) {
	return idp.cfg.Users.ValidateCredentials(email, password)
}

// Metadata is the IdP's <md:EntityDescriptor>. The IdP requires signed
// AuthnRequests.
func (idp *IdentityProvider) Metadata() *etree.Element {
	return metadata.BuildIdP(metadata.IdPParams{
		Entity: metadata.Entity{
			EntityID:    idp.cfg.EntityID,
			Credentials: idp.cfg.Credentials,
			SingleLogout: []metadata.Endpoint{
				{Binding: message.BindingHTTPRedirect, Location: idp.cfg.SLOURL},
				{Binding: message.BindingHTTPPost, Location: idp.cfg.SLOURL},
			},
			OrganizationName: "ProtocolSoup SAML Identity Provider",
			OrganizationURL:  idp.cfg.EntityID,
		},
		SingleSignOn: []metadata.Endpoint{
			{Binding: message.BindingHTTPRedirect, Location: idp.cfg.SSOURL},
			{Binding: message.BindingHTTPPost, Location: idp.cfg.SSOURL},
		},
		WantAuthnRequestsSigned: true,
		Attributes:              releasedAttributes(nil),
	})
}

func (idp *IdentityProvider) spMetadata(ctx context.Context) (*metadata.Peer, error) {
	return idp.cfg.Resolver.Resolve(ctx, idp.cfg.SPEntityID, metadata.RoleSP)
}

// releasedAttributes lists the attributes the IdP releases, named by their
// X.500/LDAP OIDs. With a nil user it describes them for metadata.
func releasedAttributes(user *models.User) []message.ReleasedAttribute {
	value := func(v string) []string {
		if user == nil || v == "" {
			return nil
		}
		return []string{v}
	}
	var u models.User
	if user != nil {
		u = *user
	}
	all := []message.ReleasedAttribute{
		{Name: "urn:oid:0.9.2342.19200300.100.1.1", FriendlyName: "uid", Values: value(u.ID)},
		{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail", Values: value(u.Email)},
		{Name: "urn:oid:2.16.840.1.113730.3.1.241", FriendlyName: "displayName", Values: value(u.Name)},
		{Name: "urn:oid:2.5.4.42", FriendlyName: "givenName", Values: value(u.GivenName)},
		{Name: "urn:oid:2.5.4.4", FriendlyName: "sn", Values: value(u.FamilyName)},
	}
	if user == nil {
		return all
	}
	var released []message.ReleasedAttribute
	for _, attr := range all {
		if len(attr.Values) > 0 {
			released = append(released, attr)
		}
	}
	return released
}

// ============================================================================
// Single Logout (the IdP is the session authority)
// ============================================================================

// HandleLogoutRequest processes an SP-initiated <LogoutRequest>. This IdP has
// a single session participant, the SP that sent the request, so there is no
// one else to propagate the logout to (SAML Core Section 3.7.3.2).
func (idp *IdentityProvider) HandleLogoutRequest(ctx context.Context, msg *binding.Received) (*binding.Outbound, *logout.Result, error) {
	meta, err := idp.spMetadata(ctx)
	if err != nil {
		return nil, &logout.Result{Report: &binding.Report{}}, err
	}
	out, result, err := logout.ProcessRequest(msg, logout.Party{
		EntityID:            idp.cfg.EntityID,
		Location:            idp.cfg.SLOURL,
		Peer:                meta,
		Sessions:            idp.sessions,
		RequireSessionIndex: true,
	})
	// The session authority also terminates "the principal's current session"
	// (SAML Core Section 3.7.3.2): its own authentication session ends, so the
	// next <AuthnRequest> asks the principal to sign in again.
	if out != nil && result.StatusCode == message.StatusSuccess {
		idp.endAuthentication(result)
	}
	return out, result, err
}

func (idp *IdentityProvider) endAuthentication(result *logout.Result) {
	ended := idp.authn.endFor(result.NameID)
	result.Report.Add("IdP authentication session", true, fmt.Sprintf("ended %d authentication session(s) for %s", ended, result.NameID), "SAML Core Section 3.7.3.2")
}

// NewLogoutRequest starts IdP-initiated Single Logout for one IdP session.
// "the session authority MUST set the value of the NotOnOrAfter attribute"
// (SAML Core Section 3.7.3.2); it covers the assertion's lifetime.
func (idp *IdentityProvider) NewLogoutRequest(ctx context.Context, sessionID, bindingID, relayState string) (*binding.Outbound, error) {
	if err := binding.CheckRelayState(relayState); err != nil {
		return nil, err
	}
	sess, ok := idp.sessions.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("no IdP session %q", sessionID)
	}
	meta, err := idp.spMetadata(ctx)
	if err != nil {
		return nil, err
	}
	ep, ok := meta.SingleLogoutService(bindingID)
	if !ok {
		return nil, fmt.Errorf("SP metadata publishes no SingleLogoutService for %s", bindingID)
	}
	request := message.BuildLogoutRequest(message.LogoutRequestParams{
		Issuer:       idp.cfg.EntityID,
		Destination:  ep.Location,
		NameID:       sess.NameID,
		NameIDFormat: sess.NameIDFormat,
		SessionIndex: sess.SessionIndex,
		Lifetime:     assertionLifetime,
		Reason:       message.LogoutReasonUser,
	})
	idp.sessions.Remove(sess.ID)
	idp.authn.endFor(sess.NameID)
	idp.logoutRequests.Store(session.PendingRequest{ID: request.SelectAttrValue("ID", ""), RelayState: relayState})
	return &binding.Outbound{Element: request, Location: ep.Location, Binding: bindingID, Param: binding.ParamSAMLRequest, RelayState: relayState}, nil
}

// ConsumeLogoutResponse matches the SP's <LogoutResponse> to the IdP's
// outstanding <LogoutRequest>.
func (idp *IdentityProvider) ConsumeLogoutResponse(ctx context.Context, msg *binding.Received) (*logout.Result, error) {
	meta, err := idp.spMetadata(ctx)
	if err != nil {
		return &logout.Result{Report: &binding.Report{}}, err
	}
	return logout.ProcessResponse(msg, logout.Party{
		EntityID: idp.cfg.EntityID,
		Location: idp.cfg.SLOURL,
		Peer:     meta,
		Pending:  idp.logoutRequests,
	})
}
