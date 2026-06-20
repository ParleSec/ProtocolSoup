package core

import (
	"os"
	"strings"
)

// Config holds the application configuration
type Config struct {
	// Environment (development, demo, production)
	Environment string

	// Server listening address
	ListenAddr string

	// Base URL for constructing absolute URLs
	BaseURL string

	// Enable mock identity provider
	MockIdPEnabled bool

	// CORS allowed origins
	CORSOrigins []string

	// Enable debug logging
	Debug bool

	// Frontend runtime origin (for proxying web routes to Next.js server)
	FrontendOrigin string

	// Data directory for durable protocol state (wallet lineage, verifier sessions)
	DataDir string

	// PaletteDBPath points at the prebuilt palette SQLite index. Empty
	// disables the palette query service (and the /api/palette/query route).
	PaletteDBPath string

	// KeyStorePath is the directory that persists OP signing keys and retired
	// public keys across restarts. Empty means ephemeral in-memory keys
	// (development only). A certified deployment MUST set this to a durable
	// path so issued tokens remain verifiable after a restart.
	KeyStorePath string

	// Conformance client provisioning. When ConformanceRedirectURIs is set AND
	// both client secrets are present, two confidential clients are registered
	// for OIDF conformance testing. The second client is required by tests that
	// verify authorization codes are bound to the client they were issued to.
	// Without an explicit secret no client is registered, so production is
	// unaffected unless conformance is deliberately enabled.
	ConformanceRedirectURIs  []string
	ConformanceClientID      string
	ConformanceClientSecret  string
	ConformanceClient2ID     string
	ConformanceClient2Secret string
}

// LoadConfig loads configuration from environment variables with sensible defaults
func LoadConfig() *Config {
	cfg := &Config{
		Environment:    getEnv("SHOWCASE_ENV", "development"),
		ListenAddr:     getEnv("SHOWCASE_LISTEN_ADDR", ":8080"),
		BaseURL:        getEnv("SHOWCASE_BASE_URL", "http://localhost:8080"),
		MockIdPEnabled: getEnvBool("SHOWCASE_MOCK_IDP", true),
		CORSOrigins:    getEnvList("SHOWCASE_CORS_ORIGINS", []string{"http://localhost:3000", "http://localhost:5173"}),
		Debug:          getEnvBool("SHOWCASE_DEBUG", false),
		FrontendOrigin: getEnv("SHOWCASE_FRONTEND_ORIGIN", ""),
		DataDir:        getEnv("SHOWCASE_DATA_DIR", ""),
		PaletteDBPath: getEnv("SHOWCASE_PALETTE_DB", ""),
		KeyStorePath:  getEnv("SHOWCASE_KEY_STORE_PATH", ""),

		ConformanceRedirectURIs:  getEnvList("OIDC_CONFORMANCE_REDIRECT_URIS", nil),
		ConformanceClientID:      getEnv("OIDC_CONFORMANCE_CLIENT_ID", "conformance-client"),
		ConformanceClientSecret:  getEnv("OIDC_CONFORMANCE_CLIENT_SECRET", ""),
		ConformanceClient2ID:     getEnv("OIDC_CONFORMANCE_CLIENT2_ID", "conformance-client-2"),
		ConformanceClient2Secret: getEnv("OIDC_CONFORMANCE_CLIENT2_SECRET", ""),
	}

	return cfg
}

// IsDevelopment returns true if running in development mode
func (c *Config) IsDevelopment() bool {
	return c.Environment == "development"
}

// IsDemo returns true if running in demo mode
func (c *Config) IsDemo() bool {
	return c.Environment == "demo"
}

// IsProduction returns true when SHOWCASE_ENV is production.
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.ToLower(value) == "true" || value == "1"
}

func getEnvList(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.Split(value, ",")
}

