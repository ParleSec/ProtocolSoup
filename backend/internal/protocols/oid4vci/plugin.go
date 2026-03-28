package oid4vci

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
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
	tokenTTL           = 10 * time.Minute
	nonceTTL           = 5 * time.Minute
	deferredReadyDelay = 3 * time.Second
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
	Credential interface{}
}

// Plugin implements OpenID for Verifiable Credential Issuance.
type Plugin struct {
	*plugin.BasePlugin

	mockIDP                  *mockidp.MockIdP
	keySet                   *crypto.KeySet
	lookingGlass             *lookingglass.Engine
	baseURL                  string
	walletStore              *vc.WalletCredentialStore
	credentialConfigurations map[string]credentialConfiguration
	issuerDrivers            map[string]credentialIssuerDriver

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
			Description: "OpenID for Verifiable Credential Issuance with multi-format VC support",
			Tags:        []string{"vc", "oid4vci", "credential-issuance", "sd-jwt", "jwt-vc", "ldp-vc"},
			RFCs:        []string{"OpenID4VCI 1.0", "OAuth 2.0", "SD-JWT VC", "VC Data Model 2.0"},
		}),
		credentialConfigurations: defaultCredentialConfigurationRegistry(),
		offers:                   make(map[string]*offerRecord),
		offersByPreAuthCode:      make(map[string]string),
		accessGrants:             make(map[string]*accessGrant),
		issuanceTransactions:     make(map[string]*issuanceTransaction),
		wallets:                  make(map[string]*walletIdentity),
		walletsByUserID:          make(map[string]string),
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
	p.issuerDrivers = map[string]credentialIssuerDriver{
		credentialFormatDCSdJWT:    &sdJWTCredentialIssuerDriver{plugin: p},
		credentialFormatJWTVCJSON:  &jwtVCCredentialIssuerDriver{plugin: p},
		credentialFormatJWTVCJSONL: &jwtVCJSONLDCredentialIssuerDriver{plugin: p},
		credentialFormatLDPVC:      &ldpVCCredentialIssuerDriver{plugin: p},
	}
	p.walletStore = vc.DefaultWalletCredentialStore()
	p.walletStore.SetEncryptionKey(strings.TrimSpace(os.Getenv("WALLET_PERSISTENCE_KEY")))
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
			Description: "Wallet resolves a credential offer URI, discovers issuer metadata, exchanges a pre-authorized code for an access token with c_nonce, and requests an SD-JWT VC bound to a proof JWT.",
			Executable:  true,
			Category:    "issuance",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Resolve Credential Offer",
					Description: "Wallet receives credential_offer_uri out-of-band and resolves it by fetching the credential offer object from the Credential Issuer (OID4VCI §4.1).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_offer_uri": "Reference URI delivered out-of-band to the wallet",
					},
					Security: []string{
						"Credential offer envelope must include exactly one of credential_offer or credential_offer_uri (XOR)",
						"Offer must contain credential_issuer, credential_configuration_ids, and grants with pre-authorized_code",
					},
				},
				{
					Order:       2,
					Name:        "Discover Issuer Metadata",
					Description: "Wallet fetches Credential Issuer Metadata from /.well-known/openid-credential-issuer to discover supported credential configurations, endpoints, and proof requirements (OID4VCI §5).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"metadata_path": "/.well-known/openid-credential-issuer/{issuer_path}",
					},
					Security: []string{
						"Wallet must verify credential_issuer in metadata matches the offer's credential_issuer",
						"Metadata must declare credential_configurations_supported for offered configuration IDs",
					},
				},
				{
					Order:       3,
					Name:        "Token Request (Pre-Authorized Code)",
					Description: "Wallet exchanges the pre-authorized code from the offer's grant block for an access token at the token endpoint (OID4VCI §6.1).",
					From:        "Wallet",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":          "urn:ietf:params:oauth:grant-type:pre-authorized_code (REQUIRED)",
						"pre-authorized_code": "Code from credential offer grants block (REQUIRED)",
					},
					Security: []string{
						"Content-Type must be application/x-www-form-urlencoded",
						"Pre-authorized code is single-use and expires within offer TTL",
						"If offer grant includes tx_code object, token request must include tx_code",
					},
				},
				{
					Order:       4,
					Name:        "Token Response",
					Description: "Authorization Server validates the pre-authorized code and returns an access token with a c_nonce challenge for proof binding (OID4VCI §6.2).",
					From:        "Authorization Server",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":       "Bearer token authorizing credential issuance (REQUIRED)",
						"token_type":         "Bearer (REQUIRED)",
						"expires_in":         "Token lifetime in seconds",
						"scope":              "Granted scope for credential issuance",
						"c_nonce":            "Challenge nonce for proof JWT binding (REQUIRED when nonce freshness enforced)",
						"c_nonce_expires_in": "Nonce lifetime in seconds",
					},
					Security: []string{
						"Access token is bound to specific credential_configuration_ids from the offer",
						"c_nonce must be used in the next credential request proof and is single-use",
					},
				},
				{
					Order:       5,
					Name:        "Credential Request",
					Description: "Wallet submits a credential request with proof JWT(s) bound to the active c_nonce and the issuer audience (OID4VCI §7).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_configuration_id": "Requested credential configuration (REQUIRED)",
						"proof / proofs":              "Proof object(s) with proof_type=jwt containing signed JWT (REQUIRED when proof_types_supported declared)",
					},
					Security: []string{
						"Proof JWT header typ must be openid4vci-proof+jwt",
						"Proof must include iss, sub, aud (issuer ID), nonce (active c_nonce), iat, exp, and cnf.jwk",
						"Proof audience must match credential_issuer identifier",
						"c_nonce is consumed on use — replayed or expired nonces are rejected",
					},
				},
				{
					Order:       6,
					Name:        "Credential Response",
					Description: "Credential Issuer validates proof key binding, nonce freshness, and audience, then returns the issued SD-JWT VC with a fresh c_nonce for subsequent requests (OID4VCI §7.3).",
					From:        "Credential Issuer",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"format":             "dc+sd-jwt (SD-JWT VC serialization)",
						"credential":         "Issuer-signed JWT with selective disclosure segments",
						"c_nonce":            "Next challenge nonce for any follow-up credential requests",
						"c_nonce_expires_in": "Next nonce lifetime in seconds",
					},
					Security: []string{
						"Credential must be signed by the issuer using advertised key material and algorithm",
						"SD-JWT includes _sd digests for selectively disclosable claims",
						"Wallet stores issued credential material securely for later presentation",
					},
				},
			},
		},
		{
			ID:          "oid4vci-pre-authorized-tx-code",
			Name:        "OID4VCI Pre-Authorized Code + tx_code",
			Description: "Pre-authorized credential issuance with mandatory transaction code enforcement at token exchange — the offer's grant block declares a tx_code object requiring wallet to include a user-entered code (OID4VCI §6.1).",
			Executable:  true,
			Category:    "issuance",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Resolve Credential Offer with tx_code",
					Description: "Wallet resolves credential_offer_uri and observes the tx_code object in the pre-authorized_code grant, indicating a transaction code is required at token exchange (OID4VCI §4.1.1).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_offer_uri": "Reference URI delivered out-of-band to the wallet",
					},
					Security: []string{
						"Offer grant must include tx_code object with description, length, and input_mode",
						"Wallet must prompt user for the transaction code before proceeding to token exchange",
					},
				},
				{
					Order:       2,
					Name:        "Discover Issuer Metadata",
					Description: "Wallet fetches Credential Issuer Metadata to discover supported configurations, endpoints, and proof requirements (OID4VCI §5).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"metadata_path": "/.well-known/openid-credential-issuer/{issuer_path}",
					},
					Security: []string{
						"Metadata credential_issuer must match the offer's credential_issuer",
					},
				},
				{
					Order:       3,
					Name:        "Token Request with tx_code",
					Description: "Wallet includes the user-entered tx_code alongside the pre-authorized code to obtain an access token (OID4VCI §6.1).",
					From:        "Wallet",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":          "urn:ietf:params:oauth:grant-type:pre-authorized_code (REQUIRED)",
						"pre-authorized_code": "Code from credential offer grants block (REQUIRED)",
						"tx_code":             "User-entered transaction code (REQUIRED when tx_code object present in offer)",
					},
					Security: []string{
						"Missing or incorrect tx_code results in invalid_grant error",
						"tx_code is delivered via an out-of-band channel (e.g., email, SMS)",
						"Content-Type must be application/x-www-form-urlencoded",
					},
				},
				{
					Order:       4,
					Name:        "Token Response",
					Description: "Authorization Server validates pre-authorized code and tx_code, then returns access token with c_nonce challenge (OID4VCI §6.2).",
					From:        "Authorization Server",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":       "Bearer token authorizing credential issuance (REQUIRED)",
						"token_type":         "Bearer (REQUIRED)",
						"c_nonce":            "Challenge nonce for proof JWT binding (REQUIRED)",
						"c_nonce_expires_in": "Nonce lifetime in seconds",
					},
					Security: []string{
						"Access token is bound to credential_configuration_ids from the offer",
						"c_nonce is single-use and must appear in the proof JWT nonce claim",
					},
				},
				{
					Order:       5,
					Name:        "Credential Request",
					Description: "Wallet submits credential request with proof JWT bound to c_nonce and issuer audience (OID4VCI §7).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_configuration_id": "Requested credential configuration (REQUIRED)",
						"proof / proofs":              "Proof object(s) with proof_type=jwt (REQUIRED)",
					},
					Security: []string{
						"Proof JWT typ must be openid4vci-proof+jwt",
						"Proof must bind to active c_nonce and credential issuer audience",
					},
				},
				{
					Order:       6,
					Name:        "Credential Response",
					Description: "Credential Issuer validates proof and returns the issued SD-JWT VC with a fresh c_nonce (OID4VCI §7.3).",
					From:        "Credential Issuer",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"format":     "dc+sd-jwt (SD-JWT VC serialization)",
						"credential": "Issuer-signed JWT with selective disclosure segments",
						"c_nonce":    "Next challenge nonce",
					},
					Security: []string{
						"Credential is signed by the issuer and returned as SD-JWT VC serialization",
					},
				},
			},
		},
		{
			ID:          "oid4vci-deferred-issuance",
			Name:        "OID4VCI Deferred Credential Issuance",
			Description: "Full pre-authorized code flow where the credential endpoint returns a transaction_id for deferred issuance — wallet polls the deferred_credential endpoint until the credential is ready (OID4VCI §9).",
			Executable:  true,
			Category:    "issuance",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Resolve Credential Offer",
					Description: "Wallet resolves credential_offer_uri from the Credential Issuer. The offer uses a pre-authorized_code grant and the issuer marks issuance for deferred delivery (OID4VCI §4.1).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_offer_uri": "Reference URI delivered out-of-band to the wallet",
					},
					Security: []string{
						"Offer envelope must include exactly one of credential_offer or credential_offer_uri",
					},
				},
				{
					Order:       2,
					Name:        "Discover Issuer Metadata",
					Description: "Wallet fetches Credential Issuer Metadata to discover supported configurations, token endpoint, nonce endpoint, and deferred_credential_endpoint (OID4VCI §5).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"metadata_path": "/.well-known/openid-credential-issuer/{issuer_path}",
					},
					Security: []string{
						"Metadata must declare deferred_credential_endpoint for deferred issuance support",
					},
				},
				{
					Order:       3,
					Name:        "Token Request (Pre-Authorized Code)",
					Description: "Wallet exchanges pre-authorized code for an access token with c_nonce (OID4VCI §6.1).",
					From:        "Wallet",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"grant_type":          "urn:ietf:params:oauth:grant-type:pre-authorized_code (REQUIRED)",
						"pre-authorized_code": "Code from credential offer grants block (REQUIRED)",
					},
					Security: []string{
						"Content-Type must be application/x-www-form-urlencoded",
					},
				},
				{
					Order:       4,
					Name:        "Token Response",
					Description: "Authorization Server returns access token and c_nonce challenge for proof binding (OID4VCI §6.2).",
					From:        "Authorization Server",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"access_token":       "Bearer token (REQUIRED)",
						"c_nonce":            "Challenge nonce for proof binding (REQUIRED)",
						"c_nonce_expires_in": "Nonce lifetime in seconds",
					},
					Security: []string{
						"Access token lineage is verified on deferred polling — only the original token can retrieve the credential",
					},
				},
				{
					Order:       5,
					Name:        "Credential Request",
					Description: "Wallet submits credential request with proof JWT bound to c_nonce. Issuer accepts proof but defers credential delivery (OID4VCI §7).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"credential_configuration_id": "Requested credential configuration (REQUIRED)",
						"proof / proofs":              "Proof object(s) with proof_type=jwt (REQUIRED)",
					},
					Security: []string{
						"Proof JWT typ must be openid4vci-proof+jwt",
						"Proof must bind to active c_nonce and credential issuer audience",
					},
				},
				{
					Order:       6,
					Name:        "Deferred Credential Response",
					Description: "Credential Issuer validates proof but responds with a transaction_id instead of an immediate credential, signalling deferred issuance (OID4VCI §9).",
					From:        "Credential Issuer",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"transaction_id":     "Opaque identifier for the pending issuance transaction (REQUIRED)",
						"c_nonce":            "Next challenge nonce",
						"c_nonce_expires_in": "Next nonce lifetime in seconds",
					},
					Security: []string{
						"transaction_id is bound to the original access token — a different token cannot poll for this credential",
					},
				},
				{
					Order:       7,
					Name:        "Poll Deferred Endpoint",
					Description: "Wallet polls the deferred_credential endpoint with transaction_id until the credential is ready. Issuer returns issuance_pending while processing (OID4VCI §9.1).",
					From:        "Wallet",
					To:          "Credential Issuer",
					Type:        "request",
					Parameters: map[string]string{
						"transaction_id": "Transaction ID from deferred credential response (REQUIRED)",
						"Authorization":  "Bearer {access_token} (REQUIRED — must match original token lineage)",
					},
					Security: []string{
						"Access token must match the token used in the original credential request",
						"Wallet should poll according to server guidance and apply reasonable backoff",
						"issuance_pending error indicates credential is not yet ready",
					},
				},
				{
					Order:       8,
					Name:        "Credential Ready",
					Description: "Credential Issuer returns the final SD-JWT VC once the issuance backend marks the transaction as ready (OID4VCI §9.1).",
					From:        "Credential Issuer",
					To:          "Wallet",
					Type:        "response",
					Parameters: map[string]string{
						"format":     "dc+sd-jwt (SD-JWT VC serialization)",
						"credential": "Issuer-signed JWT with selective disclosure segments",
					},
					Security: []string{
						"Credential is identical to what would have been returned in an immediate response",
						"Transaction is consumed — subsequent polls for the same transaction_id are rejected",
					},
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
	return credentialConfigurationsSupportedFromRegistry(p.credentialConfigurations)
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
