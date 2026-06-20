package core

import (
	"fmt"
	"log"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/palette"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
)

// BootstrapOptions controls which shared dependencies are initialized.
type BootstrapOptions struct {
	EnableKeySet       bool
	EnableMockIdP      bool
	EnableLookingGlass bool
	EnablePalette      bool
}

// BootstrapResult holds initialized dependencies and plugin config.
type BootstrapResult struct {
	Config       *Config
	KeySet       *crypto.KeySet
	MockIdP      *mockidp.MockIdP
	LookingGlass *lookingglass.Engine
	Palette      *palette.Service
	PluginConfig plugin.PluginConfig
}

// Bootstrap initializes shared dependencies based on options.
func Bootstrap(opts BootstrapOptions) (*BootstrapResult, error) {
	cfg := LoadConfig()

	var keySet *crypto.KeySet
	if opts.EnableKeySet {
		// Persist keys under KeyStorePath when configured so signing keys and
		// their kids survive restarts (required for a certified deployment).
		// An empty path yields ephemeral in-memory keys for development.
		ks, err := crypto.LoadOrCreateKeySet(cfg.KeyStorePath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize key set: %w", err)
		}
		keySet = ks
		if cfg.KeyStorePath == "" {
			log.Println("Cryptographic keys initialized (ephemeral, in-memory)")
			if cfg.IsProduction() {
				log.Println("WARNING: SHOWCASE_KEY_STORE_PATH is unset in production; signing keys will not survive a restart")
			}
		} else {
			log.Printf("Cryptographic keys initialized (persistent store at %s)", cfg.KeyStorePath)
		}
	}

	var idp *mockidp.MockIdP
	if opts.EnableMockIdP {
		if keySet == nil {
			return nil, fmt.Errorf("mock IdP requires keyset")
		}
		idp = mockidp.NewMockIdP(keySet)
		idp.SetIssuer(cfg.BaseURL)
		log.Printf("Mock Identity Provider initialized with issuer: %s", cfg.BaseURL)
		registerConformanceClients(idp, cfg)
	}

	var lg *lookingglass.Engine
	if opts.EnableLookingGlass {
		lg = lookingglass.NewEngine()
		log.Println("Looking Glass engine initialized")
	}

	var paletteSvc *palette.Service
	if opts.EnablePalette {
		if cfg.PaletteDBPath == "" {
			if cfg.IsProduction() {
				return nil, fmt.Errorf("SHOWCASE_PALETTE_DB is required in production")
			}
			log.Println("Palette service disabled: SHOWCASE_PALETTE_DB is empty")
		} else {
			svc, err := palette.NewService(cfg.PaletteDBPath)
			if err != nil {
				if cfg.IsProduction() {
					return nil, fmt.Errorf("load palette index at %s: %w", cfg.PaletteDBPath, err)
				}
				log.Printf("Palette service disabled: %v", err)
			} else {
				paletteSvc = svc
				stats := svc.Stats()
				log.Printf("Palette service initialized from %s (%d artefacts, index v%s)",
					cfg.PaletteDBPath, stats.ArtefactCount, stats.IndexVersion)
			}
		}
	}

	pluginConfig := plugin.PluginConfig{
		BaseURL:      cfg.BaseURL,
		DataDir:      cfg.DataDir,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lg,
	}

	return &BootstrapResult{
		Config:       cfg,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lg,
		Palette:      paletteSvc,
		PluginConfig: pluginConfig,
	}, nil
}

// registerConformanceClients provisions the static confidential clients the
// OIDF OP conformance suite requires. Two clients are registered because the
// suite tests that an authorization code issued to one client cannot be
// redeemed by another (client binding). They are only registered when the
// redirect URIs and both secrets are supplied, so a production deployment that
// has not opted in is unaffected, and a secretless confidential client (which
// would accept anyone) is never created.
func registerConformanceClients(idp *mockidp.MockIdP, cfg *Config) {
	uris := trimmedNonEmpty(cfg.ConformanceRedirectURIs)
	if len(uris) == 0 {
		return
	}
	if cfg.ConformanceClientSecret == "" {
		log.Println("Conformance redirect URIs are set but OIDC_CONFORMANCE_CLIENT_SECRET is missing; conformance clients NOT registered")
		return
	}
	// The second client needs a valid secret to authenticate at the token
	// endpoint. When no distinct secret is supplied it reuses the first, which
	// keeps it a separate registration (distinct client_id) while requiring only
	// one secret to be provisioned.
	client2Secret := cfg.ConformanceClient2Secret
	if client2Secret == "" {
		client2Secret = cfg.ConformanceClientSecret
	}

	scopes := []string{"openid", "profile", "email"}
	grants := []string{"authorization_code", "refresh_token"}

	idp.RegisterClient(&models.Client{
		ID:           cfg.ConformanceClientID,
		Secret:       cfg.ConformanceClientSecret,
		Name:         "OIDF Conformance Client",
		RedirectURIs: uris,
		GrantTypes:   grants,
		Scopes:       scopes,
		Public:       false,
	})
	idp.RegisterClient(&models.Client{
		ID:           cfg.ConformanceClient2ID,
		Secret:       client2Secret,
		Name:         "OIDF Conformance Client 2",
		RedirectURIs: uris,
		GrantTypes:   grants,
		Scopes:       scopes,
		Public:       false,
	})
	log.Printf("Registered OIDF conformance clients %q and %q with %d redirect URI(s)",
		cfg.ConformanceClientID, cfg.ConformanceClient2ID, len(uris))
}

// trimmedNonEmpty trims surrounding whitespace from each value and drops empty
// entries, so a comma-separated env list tolerates spaces after commas.
func trimmedNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}
