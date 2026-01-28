package core

import (
	"fmt"
	"log"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
)

// BootstrapOptions controls which shared dependencies are initialized.
type BootstrapOptions struct {
	EnableKeySet       bool
	EnableMockIdP      bool
	EnableLookingGlass bool
}

// BootstrapResult holds initialized dependencies and plugin config.
type BootstrapResult struct {
	Config       *Config
	KeySet       *crypto.KeySet
	MockIdP      *mockidp.MockIdP
	LookingGlass *lookingglass.Engine
	PluginConfig plugin.PluginConfig
}

// Bootstrap initializes shared dependencies based on options.
func Bootstrap(opts BootstrapOptions) (*BootstrapResult, error) {
	cfg := LoadConfig()

	var keySet *crypto.KeySet
	if opts.EnableKeySet {
		ks, err := crypto.NewKeySet()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize key set: %w", err)
		}
		keySet = ks
		log.Println("Cryptographic keys initialized")
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

	pluginConfig := plugin.PluginConfig{
		BaseURL:      cfg.BaseURL,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lg,
	}

	return &BootstrapResult{
		Config:       cfg,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lg,
		PluginConfig: pluginConfig,
	}, nil
}
