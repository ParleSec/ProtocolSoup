package core

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/palette"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
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
	if err := validateProductionBaseURL(cfg); err != nil {
		return nil, err
	}
	if err := validateProductionKeyStorage(cfg, opts.EnableKeySet); err != nil {
		return nil, err
	}

	var keySet *crypto.KeySet
	if opts.EnableKeySet {
		// Persist keys under KeyStorePath when configured so signing keys and
		// their kids survive restarts. An empty path yields ephemeral in-memory
		// keys for development.
		ks, err := crypto.LoadOrCreateKeySet(cfg.KeyStorePath)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize key set: %w", err)
		}
		keySet = ks
		if cfg.KeyStorePath == "" {
			log.Println("Cryptographic keys initialized (ephemeral, in-memory)")
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
		Environment:                       cfg.Environment,
		BaseURL:                           cfg.BaseURL,
		DataDir:                           cfg.DataDir,
		OAuth2ReplayRedisURL:              cfg.OAuth2ReplayRedisURL,
		CORSOrigins:                       cfg.CORSOrigins,
		DPoPNonceRequired:                 cfg.DPoPNonceRequired,
		DPoPResourceNonceRequired:         cfg.DPoPResourceNonceRequired,
		KeySet:                            keySet,
		MockIdP:                           idp,
		LookingGlass:                      lg,
		OIDCDynamicRegistrationEnabled:    cfg.OIDCDynamicRegistrationEnabled,
		OIDCDynamicRegistrationTTL:        cfg.OIDCDynamicRegistrationTTL,
		OIDCDynamicRegistrationMaxClients: cfg.OIDCDynamicRegistrationMaxClients,
		OIDCDynamicRegistrationRateLimit:  cfg.OIDCDynamicRegistrationRateLimit,
		OIDCDynamicRegistrationRateWindow: cfg.OIDCDynamicRegistrationRateWindow,
		OIDCPairwiseSubjectSalt:           cfg.OIDCPairwiseSubjectSalt,
		OIDCKeyRotationToken:              cfg.OIDCKeyRotationToken,
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

func validateProductionKeyStorage(cfg *Config, enabled bool) error {
	if cfg != nil && enabled && cfg.IsProduction() && strings.TrimSpace(cfg.KeyStorePath) == "" {
		return fmt.Errorf("SHOWCASE_KEY_STORE_PATH is required in production when signing keys are enabled")
	}
	return nil
}

func validateProductionBaseURL(cfg *Config) error {
	if cfg == nil || !cfg.IsProduction() {
		return nil
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid SHOWCASE_BASE_URL: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("SHOWCASE_BASE_URL must be a pathless HTTPS origin in production")
	}
	return nil
}
