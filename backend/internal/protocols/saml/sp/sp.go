// Package sp is the SAML 2.0 service provider: a separate entity from the
// identity provider, with its own entityID, signing key and metadata. It
// trusts the IdP only through the IdP's metadata, fetched over HTTP from the
// IdP's entityID, and it cannot import the idp package.
package sp

import (
	"context"
	"fmt"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/binding"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/logout"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/message"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/metadata"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/session"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/saml/xmldsig"
	"github.com/beevik/etree"
)

const (
	requestTTL       = 10 * time.Minute
	logoutRequestTTL = 5 * time.Minute
)

// Config describes the service provider's endpoints, keys and trusted IdP.
type Config struct {
	EntityID    string // also the URL its metadata is published at
	ACSURL      string
	SLOURL      string
	IdPEntityID string
	Credentials *xmldsig.Credentials
	Resolver    *metadata.Resolver
	Events      binding.Events
}

// ServiceProvider is the SAML SP role.
type ServiceProvider struct {
	cfg            Config
	authnRequests  *session.Pending
	logoutRequests *session.Pending
	replay         *session.ReplayCache
	sessions       *session.Store
	loggedOut      *session.LogoutRecords
}

// New returns a service provider with empty state.
func New(cfg Config) *ServiceProvider {
	return &ServiceProvider{
		cfg:            cfg,
		authnRequests:  session.NewPending(requestTTL),
		logoutRequests: session.NewPending(requestTTL),
		replay:         session.NewReplayCache(),
		sessions:       session.NewStore(),
		loggedOut:      &session.LogoutRecords{},
	}
}

func (sp *ServiceProvider) EntityID() string                  { return sp.cfg.EntityID }
func (sp *ServiceProvider) ACSURL() string                    { return sp.cfg.ACSURL }
func (sp *ServiceProvider) SLOURL() string                    { return sp.cfg.SLOURL }
func (sp *ServiceProvider) Credentials() *xmldsig.Credentials { return sp.cfg.Credentials }

// Sessions lists the security contexts the SP holds.
func (sp *ServiceProvider) Sessions() []*session.Session { return sp.sessions.List() }

// Metadata is the SP's <md:EntityDescriptor>. The SP signs its requests and
// requires signed assertions.
func (sp *ServiceProvider) Metadata() *etree.Element {
	return metadata.BuildSP(metadata.SPParams{
		Entity: metadata.Entity{
			EntityID:    sp.cfg.EntityID,
			Credentials: sp.cfg.Credentials,
			SingleLogout: []metadata.Endpoint{
				{Binding: message.BindingHTTPRedirect, Location: sp.cfg.SLOURL},
				{Binding: message.BindingHTTPPost, Location: sp.cfg.SLOURL},
			},
			OrganizationName: "ProtocolSoup SAML Service Provider",
			OrganizationURL:  sp.cfg.EntityID,
		},
		ACSURL:               sp.cfg.ACSURL,
		AuthnRequestsSigned:  true,
		WantAssertionsSigned: true,
	})
}

func (sp *ServiceProvider) idpMetadata(ctx context.Context) (*metadata.Peer, error) {
	return sp.cfg.Resolver.Resolve(ctx, sp.cfg.IdPEntityID, metadata.RoleIdP)
}

// NewAuthnRequest builds an <AuthnRequest> for the IdP's SingleSignOnService
// on the chosen binding and remembers its ID and RelayState.
func (sp *ServiceProvider) NewAuthnRequest(ctx context.Context, bindingID, relayState string) (*binding.Outbound, error) {
	if err := binding.CheckRelayState(relayState); err != nil {
		return nil, err
	}
	meta, err := sp.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	location, ok := meta.SingleSignOnService(bindingID)
	if !ok {
		return nil, fmt.Errorf("IdP metadata publishes no SingleSignOnService for %s", bindingID)
	}
	request := message.BuildAuthnRequest(message.AuthnRequestParams{
		Issuer:       sp.cfg.EntityID,
		Destination:  location,
		ACSURL:       sp.cfg.ACSURL,
		NameIDFormat: message.NameIDFormatEmail,
	})
	sp.authnRequests.Store(session.PendingRequest{ID: request.SelectAttrValue("ID", ""), RelayState: relayState})
	return &binding.Outbound{Element: request, Location: location, Binding: bindingID, Param: binding.ParamSAMLRequest, RelayState: relayState}, nil
}

// NewLogoutRequest ends the local session and builds the <LogoutRequest> the
// SP sends to the IdP's SingleLogoutService on bindingID.
func (sp *ServiceProvider) NewLogoutRequest(ctx context.Context, sessionID, bindingID, relayState string) (*binding.Outbound, error) {
	if err := binding.CheckRelayState(relayState); err != nil {
		return nil, err
	}
	sess, ok := sp.sessions.Get(sessionID)
	if !ok {
		return nil, fmt.Errorf("no SP session %q", sessionID)
	}
	meta, err := sp.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	ep, ok := meta.SingleLogoutService(bindingID)
	if !ok {
		return nil, fmt.Errorf("IdP metadata publishes no SingleLogoutService for %s", bindingID)
	}
	request := message.BuildLogoutRequest(message.LogoutRequestParams{
		Issuer:       sp.cfg.EntityID,
		Destination:  ep.Location,
		NameID:       sess.NameID,
		NameIDFormat: sess.NameIDFormat,
		SessionIndex: sess.SessionIndex,
		Lifetime:     logoutRequestTTL,
		Reason:       message.LogoutReasonUser,
	})
	sp.sessions.Remove(sess.ID)
	sp.logoutRequests.Store(session.PendingRequest{ID: request.SelectAttrValue("ID", ""), RelayState: relayState})
	return &binding.Outbound{Element: request, Location: ep.Location, Binding: bindingID, Param: binding.ParamSAMLRequest, RelayState: relayState}, nil
}

// HandleLogoutRequest processes an IdP-initiated <LogoutRequest> and returns
// the <LogoutResponse> to send back on the same binding.
func (sp *ServiceProvider) HandleLogoutRequest(ctx context.Context, msg *binding.Received) (*binding.Outbound, *logout.Result, error) {
	meta, err := sp.idpMetadata(ctx)
	if err != nil {
		return nil, &logout.Result{Report: &binding.Report{}}, err
	}
	return logout.ProcessRequest(msg, logout.Party{
		EntityID:  sp.cfg.EntityID,
		Location:  sp.cfg.SLOURL,
		Peer:      meta,
		Sessions:  sp.sessions,
		LoggedOut: sp.loggedOut,
	})
}

// ConsumeLogoutResponse matches the IdP's <LogoutResponse> to the SP's
// outstanding <LogoutRequest>.
func (sp *ServiceProvider) ConsumeLogoutResponse(ctx context.Context, msg *binding.Received) (*logout.Result, error) {
	meta, err := sp.idpMetadata(ctx)
	if err != nil {
		return &logout.Result{Report: &binding.Report{}}, err
	}
	return logout.ProcessResponse(msg, logout.Party{
		EntityID: sp.cfg.EntityID,
		Location: sp.cfg.SLOURL,
		Peer:     meta,
		Pending:  sp.logoutRequests,
	})
}
