package oid4vci

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
)

const (
	defaultCredentialConfigurationID = "UniversityDegreeCredential"
	defaultCredentialVCT             = "https://protocolsoup.com/credentials/university_degree"
	tokenTTL                         = 10 * time.Minute
	nonceTTL                         = 5 * time.Minute
	deferredReadyDelay               = 3 * time.Second
)

type offerRecord struct {
	ID             string
	Offer          models.VCCredentialOffer
	TxCodeRequired bool
	TxCodeValue    string
	WalletID       string
	Deferred       bool
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type accessGrant struct {
	Token                      string
	Subject                    string
	WalletID                   string
	CredentialConfigurationIDs map[string]struct{}
	CNonce                     models.VCNonce
	CNonceUsed                 bool
	OfferID                    string
	Deferred                   bool
	ExpiresAt                  time.Time
}

type walletIdentity struct {
	ID             string
	UserID         string
	Subject        string
	GivenName      string
	FamilyName     string
	Department     string
	Degree         string
	GraduationYear int
	CreatedAt      time.Time
}

type issuanceTransaction struct {
	Model      models.VCIssuanceTransaction
	Subject    string
	ReadyAt    time.Time
	Credential string
}

// Plugin implements OpenID for Verifiable Credential Issuance.
type Plugin struct {
	*plugin.BasePlugin

	mockIDP      *mockidp.MockIdP
	keySet       *crypto.KeySet
	lookingGlass *lookingglass.Engine
	baseURL      string
	walletStore  *vc.WalletCredentialStore

	mu                   sync.RWMutex
	offers               map[string]*offerRecord
	offersByPreAuthCode  map[string]string
	accessGrants         map[string]*accessGrant
	issuanceTransactions map[string]*issuanceTransaction
	wallets              map[string]*walletIdentity
	walletsByUserID      map[string]string
}

// NewPlugin creates a new OID4VCI plugin instance.
func NewPlugin() *Plugin {
	return &Plugin{
		BasePlugin: plugin.NewBasePlugin(plugin.PluginInfo{
			ID:          "oid4vci",
			Name:        "OpenID4VCI",
			Version:     "0.1.0",
			Description: "OpenID for Verifiable Credential Issuance with SD-JWT VC",
			Tags:        []string{"vc", "oid4vci", "credential-issuance", "sd-jwt"},
			RFCs:        []string{"OpenID4VCI 1.0", "OAuth 2.0", "SD-JWT VC"},
		}),
		offers:               make(map[string]*offerRecord),
		offersByPreAuthCode:  make(map[string]string),
		accessGrants:         make(map[string]*accessGrant),
		issuanceTransactions: make(map[string]*issuanceTransaction),
		wallets:              make(map[string]*walletIdentity),
		walletsByUserID:      make(map[string]string),
	}
}

// Initialize wires shared services used by the plugin.
func (p *Plugin) Initialize(ctx context.Context, config plugin.PluginConfig) error {
	_ = ctx

	p.SetConfig(config)
	p.baseURL = strings.TrimRight(config.BaseURL, "/")
	if p.baseURL == "" {
		p.baseURL = "http://localhost:8080"
	}

	if idp, ok := config.MockIdP.(*mockidp.MockIdP); ok {
		p.mockIDP = idp
	}
	if ks, ok := config.KeySet.(*crypto.KeySet); ok {
		p.keySet = ks
	}
	if lg, ok := config.LookingGlass.(*lookingglass.Engine); ok {
		p.lookingGlass = lg
	}
	p.walletStore = vc.DefaultWalletCredentialStore()
	if dataDir := strings.TrimSpace(config.DataDir); dataDir != "" {
		storePath := filepath.Join(dataDir, "vc", "wallet_credentials.json")
		if err := p.walletStore.EnablePersistence(storePath); err != nil {
			return fmt.Errorf("initialize wallet credential store persistence: %w", err)
		}
	}
	return nil
}

// Shutdown stops plugin lifecycle resources.
func (p *Plugin) Shutdown(ctx context.Context) error {
	_ = ctx
	return nil
}

// RegisterRoutes registers OID4VCI endpoints.
func (p *Plugin) RegisterRoutes(router chi.Router) {
	router.Get("/.well-known/openid-credential-issuer", p.handleCredentialIssuerMetadata)
	router.Get("/.well-known/openid-credential-issuer/*", p.handleCredentialIssuerMetadata)
	router.Get("/credential-offer/{offerID}", p.handleCredentialOfferByReference)
	router.Post("/offers/pre-authorized", p.handleCreatePreAuthorizedOffer)
	router.Post("/offers/pre-authorized/by-value", p.handleCreatePreAuthorizedOfferByValue)
	router.Post("/offers/pre-authorized/deferred", p.handleCreateDeferredPreAuthorizedOffer)

	router.Post("/token", p.handleToken)
	router.Post("/nonce", p.handleNonce)
	router.Post("/credential", p.handleCredential)
	router.Post("/deferred_credential", p.handleDeferredCredential)
}

// GetInspectors returns OID4VCI-focused inspectors.
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "oid4vci-credential-inspector",
			Name:        "VC Issuance Inspector",
			Description: "Inspect credential offers, c_nonce challenges, and issued SD-JWT VC artifacts",
			Type:        "token",
		},
	}
}

// GetFlowDefinitions returns executable OID4VCI flow definitions.
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "oid4vci-pre-authorized",
			Name:        "OID4VCI Pre-Authorized Code",
			Description: "Wallet resolves an offer URI, exchanges pre-authorized code for an access token, and requests an SD-JWT VC.",
			Executable:  true,
			Category:    "issuance",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Resolve Credential Offer",
					Description: "Wallet resolves credential_offer_uri and validates issuer metadata relationship.",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_offer_uri": "Reference URI returned out-of-band to the wallet",
					},
					Security: []string{
						"Credential offer envelope must include exactly one of credential_offer or credential_offer_uri",
					},
				},
				{
					Order:       2,
					Name:        "Token Request (Pre-Authorized)",
					Description: "Wallet uses the pre-authorized code to get a credential access token and c_nonce challenge.",
					From:        "Wallet",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":          "urn:ietf:params:oauth:grant-type:pre-authorized_code",
						"pre-authorized_code": "Code from offer grants block",
					},
					Security: []string{
						"If tx_code is required by the offer, token request must include tx_code",
						"Token response should include c_nonce when nonce freshness checks are enforced",
					},
				},
				{
					Order:       3,
					Name:        "Credential Request",
					Description: "Wallet submits proof(s) with c_nonce binding and requests selected credential configuration.",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_configuration_id": "Requested credential configuration",
						"proofs":                      "Proof object(s) with jwt proof type",
					},
					Security: []string{
						"proofs are mandatory when proof_types_supported is declared",
						"Proof audience and nonce must match issuer and fresh c_nonce challenge",
					},
				},
				{
					Order:       4,
					Name:        "Credential Issued",
					Description: "Issuer returns SD-JWT VC serialization bound to verified proof context.",
					From:        "Credential Issuer",
					To:          "Wallet",
					Type:        "response",
				},
			},
		},
		{
			ID:          "oid4vci-pre-authorized-tx-code",
			Name:        "OID4VCI Pre-Authorized Code + tx_code",
			Description: "Same as pre-authorized flow but with transaction code enforcement.",
			Executable:  true,
			Category:    "issuance",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Resolve Offer with tx_code Constraint",
					Description: "Offer declares a tx_code object requiring user-entered transaction code.",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
				},
				{
					Order:       2,
					Name:        "Token Request with tx_code",
					Description: "Wallet includes tx_code alongside pre-authorized code to obtain access token.",
					From:        "Wallet",
					To:          "Authorization Server",
					Type:        "request",
				},
				{
					Order:       3,
					Name:        "Credential Request",
					Description: "Wallet sends proof bound to c_nonce and receives issued credential.",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
				},
			},
		},
		{
			ID:          "oid4vci-deferred-issuance",
			Name:        "OID4VCI Deferred Credential Issuance",
			Description: "Wallet receives transaction_id and polls deferred_credential endpoint until issuance is ready.",
			Executable:  true,
			Category:    "issuance",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Initial Credential Request",
					Description: "Issuer returns transaction_id instead of immediate credential.",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
				},
				{
					Order:       2,
					Name:        "Poll Deferred Endpoint",
					Description: "Wallet polls deferred_credential endpoint using transaction_id.",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
				},
				{
					Order:       3,
					Name:        "Deferred Credential Ready",
					Description: "Issuer returns final credential once issuance backend marks transaction ready.",
					From:        "Credential Issuer",
					To:          "Wallet",
					Type:        "response",
				},
			},
		},
	}
}

// GetDemoScenarios returns Looking Glass flow scenarios for OID4VCI.
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "oid4vci-pre-authorized",
			Name:        "Pre-Authorized Issuance",
			Description: "Credential issuance using pre-authorized_code grant with proof and c_nonce checks",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Create Offer", Description: "Generate credential_offer_uri", Auto: true},
				{Order: 2, Name: "Exchange Token", Description: "Use pre-authorized code for access token", Auto: true},
				{Order: 3, Name: "Submit Proof", Description: "Create nonce-bound proof JWT", Auto: true},
				{Order: 4, Name: "Receive Credential", Description: "Fetch issued SD-JWT VC", Auto: true},
			},
		},
		{
			ID:          "oid4vci-pre-authorized-tx-code",
			Name:        "Pre-Authorized + tx_code",
			Description: "Flow that enforces tx_code in token exchange",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Create tx_code Offer", Description: "Generate offer with tx_code object", Auto: true},
				{Order: 2, Name: "Token Request", Description: "Enter matching out-of-band tx_code value before token exchange", Auto: false},
				{Order: 3, Name: "Credential Request", Description: "Submit proof and obtain credential", Auto: true},
			},
		},
		{
			ID:          "oid4vci-deferred-issuance",
			Name:        "Deferred Issuance Polling",
			Description: "Issue transaction_id first then complete issuance through deferred endpoint",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Create Deferred Offer", Description: "Generate deferred-capable offer", Auto: true},
				{Order: 2, Name: "Initial Credential Request", Description: "Receive transaction_id", Auto: true},
				{Order: 3, Name: "Poll Deferred Endpoint", Description: "Retrieve final credential", Auto: true},
			},
		},
	}
}

func (p *Plugin) getSessionFromRequest(r *http.Request) string {
	if sessionID := r.Header.Get("X-Looking-Glass-Session"); sessionID != "" {
		return sessionID
	}
	return r.URL.Query().Get("lg_session")
}

func (p *Plugin) emitEvent(sessionID string, eventType lookingglass.EventType, title string, data map[string]interface{}, annotations ...lookingglass.Annotation) {
	if p.lookingGlass == nil || sessionID == "" {
		return
	}
	p.lookingGlass.NewEventBroadcaster(sessionID).Emit(eventType, title, data, annotations...)
}

func (p *Plugin) vcAnnotation(key string) []lookingglass.Annotation {
	annotationSet := lookingglass.NewAnnotationLibrary().OID4VCIAnnotations()
	if items, ok := annotationSet[key]; ok {
		return items
	}
	return nil
}

func (p *Plugin) issuerID() string {
	return p.baseURL + "/oid4vci"
}

func (p *Plugin) metadataWellKnownPath() string {
	parsed, err := url.Parse(p.issuerID())
	if err != nil {
		return "/.well-known/openid-credential-issuer"
	}
	issuerPath := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	if issuerPath == "" {
		return "/.well-known/openid-credential-issuer"
	}
	return "/.well-known/openid-credential-issuer/" + issuerPath
}

func (p *Plugin) credentialConfigurationsSupported() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		defaultCredentialConfigurationID: {
			"format": "dc+sd-jwt",
			"vct":    defaultCredentialVCT,
			"scope":  "vc:university_degree",
			"cryptographic_binding_methods_supported": []string{
				"jwk",
			},
			"proof_types_supported": map[string]interface{}{
				"jwt": map[string]interface{}{
					"proof_signing_alg_values_supported": []string{"RS256"},
				},
			},
		},
	}
}

func (p *Plugin) randomValue(size int) string {
	if size <= 0 {
		size = 24
	}
	raw := make([]byte, size)
	_, _ = rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)[:size]
}

func (p *Plugin) getOrCreateWallet(userID string) (*walletIdentity, error) {
	normalizedUserID := strings.TrimSpace(userID)
	if normalizedUserID == "" {
		normalizedUserID = "holder-" + p.randomValue(10)
	}

	p.mu.RLock()
	if walletID, ok := p.walletsByUserID[normalizedUserID]; ok {
		if wallet, exists := p.wallets[walletID]; exists {
			p.mu.RUnlock()
			return wallet, nil
		}
	}
	p.mu.RUnlock()

	var givenName string
	var familyName string
	var department string
	if p.mockIDP != nil {
		if user, ok := p.mockIDP.GetUser(normalizedUserID); ok {
			givenName, familyName = splitName(user.Name)
			if givenName == "" {
				givenName = "Credential"
			}
			if familyName == "" {
				familyName = "Holder"
			}
			department = strings.TrimSpace(user.Claims["department"])
		}
	}
	if department == "" {
		department = "General"
	}
	if givenName == "" {
		givenName = "Credential"
	}
	if familyName == "" {
		familyName = "Holder"
	}

	now := time.Now().UTC()
	subjectComponent := normalizeSubjectComponent(normalizedUserID)
	walletID := "wallet-" + subjectComponent
	wallet := &walletIdentity{
		ID:             walletID,
		UserID:         normalizedUserID,
		Subject:        "did:example:wallet:" + subjectComponent,
		GivenName:      givenName,
		FamilyName:     familyName,
		Department:     department,
		Degree:         strings.TrimSpace(fmt.Sprintf("%s Credential", department)),
		GraduationYear: now.Year() - 5,
		CreatedAt:      now,
	}

	p.mu.Lock()
	p.wallets[walletID] = wallet
	p.walletsByUserID[normalizedUserID] = walletID
	p.mu.Unlock()
	return wallet, nil
}

func (p *Plugin) getWalletByID(walletID string) (*walletIdentity, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	wallet, ok := p.wallets[walletID]
	return wallet, ok
}

func splitName(name string) (string, string) {
	parts := strings.Fields(strings.TrimSpace(name))
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
}

func normalizeSubjectComponent(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "holder"
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
		case r == '-', r == '_':
			b.WriteRune('-')
		default:
			b.WriteRune('-')
		}
	}
	normalized := strings.Trim(b.String(), "-")
	if normalized == "" {
		return "holder"
	}
	return normalized
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeOID4VCIError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func writeServerError(w http.ResponseWriter, action string, err error) {
	writeOID4VCIError(w, http.StatusInternalServerError, "server_error", fmt.Sprintf("%s: %v", action, err))
}
