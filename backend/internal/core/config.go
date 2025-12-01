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

	// Static files directory (for serving frontend in combined deployment)
	StaticDir string
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
		StaticDir:      getEnv("SHOWCASE_STATIC_DIR", ""),
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

