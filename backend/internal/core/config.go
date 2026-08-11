package core

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the application configuration
type Config struct {
	// Environment (development, demo, production)
	Environment string
	// BuildCommit is the immutable source revision exposed by /health so
	// conformance evidence can be tied to the deployed candidate.
	BuildCommit string

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

	// OAuth2ReplayRedisURL is the shared Redis endpoint used to reserve
	// private_key_jwt assertion IDs atomically across processes.
	OAuth2ReplayRedisURL string

	// DPoPNonceRequired enables the RFC 9449 Section 8 server-provided
	// nonce challenge at authorization-server token endpoints (oauth2 and
	// oid4vci's own token endpoint). Off by default (RFC 9449 treats
	// nonces as optional hardening, not a baseline requirement).
	DPoPNonceRequired bool

	// DPoPResourceNonceRequired enables the same challenge, independently,
	// at oid4vci's resource-server endpoints (credential, nonce,
	// deferred_credential). Off by default.
	DPoPResourceNonceRequired bool

	// PaletteDBPath points at the prebuilt palette SQLite index. Empty
	// disables the palette query service (and the /api/palette/query route).
	PaletteDBPath string

	// KeyStorePath is the directory that persists OP signing keys and retired
	// public keys across restarts. Empty means ephemeral in-memory keys
	// (development only). A certified deployment MUST set this to a durable
	// path so issued tokens remain verifiable after a restart.
	KeyStorePath string

	// OIDC Dynamic Client Registration (open, ephemeral by default).
	OIDCDynamicRegistrationEnabled    bool
	OIDCDynamicRegistrationTTL        time.Duration
	OIDCDynamicRegistrationMaxClients int
	OIDCDynamicRegistrationRateLimit  int
	OIDCDynamicRegistrationRateWindow time.Duration
	// OIDCPairwiseSubjectSalt persists the secret used for OIDC pairwise
	// subject derivation across process restarts.
	OIDCPairwiseSubjectSalt string
	// OIDCKeyRotationToken enables bearer-protected OP signing-key rotation.
	OIDCKeyRotationToken string
}

// LoadConfig loads configuration from environment variables with sensible defaults
func LoadConfig() *Config {
	cfg := &Config{
		Environment:          getEnv("SHOWCASE_ENV", "development"),
		BuildCommit:          getEnv("BUILD_COMMIT", ""),
		ListenAddr:           getEnv("SHOWCASE_LISTEN_ADDR", ":8080"),
		BaseURL:              getEnv("SHOWCASE_BASE_URL", "http://localhost:8080"),
		MockIdPEnabled:       getEnvBool("SHOWCASE_MOCK_IDP", true),
		CORSOrigins:          getEnvList("SHOWCASE_CORS_ORIGINS", []string{"http://localhost:3000", "http://localhost:5173"}),
		Debug:                getEnvBool("SHOWCASE_DEBUG", false),
		FrontendOrigin:       getEnv("SHOWCASE_FRONTEND_ORIGIN", ""),
		DataDir:              getEnv("SHOWCASE_DATA_DIR", ""),
		OAuth2ReplayRedisURL: getEnv("OAUTH2_REPLAY_REDIS_URL", ""),
		PaletteDBPath:        getEnv("SHOWCASE_PALETTE_DB", ""),
		KeyStorePath:         getEnv("SHOWCASE_KEY_STORE_PATH", ""),

		DPoPNonceRequired:         getEnvBool("SHOWCASE_DPOP_NONCE_REQUIRED", false),
		DPoPResourceNonceRequired: getEnvBool("SHOWCASE_DPOP_RESOURCE_NONCE_REQUIRED", false),

		OIDCDynamicRegistrationEnabled:    getEnvBool("OIDC_DYNAMIC_REGISTRATION_ENABLED", true),
		OIDCDynamicRegistrationTTL:        getEnvDuration("OIDC_DYNAMIC_REGISTRATION_TTL", 2*time.Hour),
		OIDCDynamicRegistrationMaxClients: getEnvInt("OIDC_DYNAMIC_REGISTRATION_MAX_CLIENTS", 200),
		OIDCDynamicRegistrationRateLimit:  getEnvInt("OIDC_DYNAMIC_REGISTRATION_RATE_LIMIT", 30),
		OIDCDynamicRegistrationRateWindow: getEnvDuration("OIDC_DYNAMIC_REGISTRATION_RATE_WINDOW", time.Minute),
		OIDCPairwiseSubjectSalt:           getEnv("OIDC_PAIRWISE_SUBJECT_SALT", ""),
		OIDCKeyRotationToken:              getEnv("OIDC_KEY_ROTATION_TOKEN", ""),
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

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}
