package scim

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SCIMAuthConfig holds authentication configuration
type SCIMAuthConfig struct {
	// APIToken is the bearer token that Okta/IdP will send
	APIToken string
	// RequireAuth determines if authentication is required
	RequireAuth bool
}

var (
	authConfig     SCIMAuthConfig
	authConfigOnce sync.Once
)

// loadAuthConfig loads authentication configuration from environment
func loadAuthConfig() SCIMAuthConfig {
	authConfigOnce.Do(func() {
		token := os.Getenv("SCIM_API_TOKEN")
		authConfig = SCIMAuthConfig{
			APIToken:    token,
			RequireAuth: token != "", // Require auth if token is configured
		}

		if authConfig.RequireAuth {
			log.Printf("SCIM authentication enabled (token configured)")
		} else {
			log.Printf("SCIM authentication disabled (no SCIM_API_TOKEN set)")
		}
	})
	return authConfig
}

// GetAuthConfig returns the current auth configuration
func GetAuthConfig() SCIMAuthConfig {
	return loadAuthConfig()
}

// AuthMiddleware returns middleware that validates Bearer tokens
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		config := loadAuthConfig()

		// If auth is not required, pass through
		if !config.RequireAuth {
			next.ServeHTTP(w, r)
			return
		}

		// Extract Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeSCIMError(w, http.StatusUnauthorized, "invalidValue", "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeSCIMError(w, http.StatusUnauthorized, "invalidValue", "Bearer token required")
			return
		}

		token := parts[1]

		// Constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(config.APIToken)) != 1 {
			writeSCIMError(w, http.StatusUnauthorized, "invalidValue", "Invalid bearer token")
			return
		}

		// Token valid, continue
		next.ServeHTTP(w, r)
	})
}

// writeSCIMError writes an RFC 7644 compliant error response
func writeSCIMError(w http.ResponseWriter, status int, scimType string, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  status,
		"scimType": scimType,
		"detail":  detail,
	})
}

// ProvisioningEvent represents an event from Okta provisioning
type ProvisioningEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"` // "okta", "azure", etc.
	Action    string                 `json:"action"` // "create", "update", "delete"
	Resource  string                 `json:"resource"` // "User", "Group"
	UserAgent string                 `json:"userAgent"`
	Data      map[string]interface{} `json:"data"`
}

// ProvisioningLog tracks provisioning events from external IdPs
type ProvisioningLog struct {
	events []ProvisioningEvent
	mu     sync.RWMutex
	maxSize int
}

var provisioningLog = &ProvisioningLog{
	events:  make([]ProvisioningEvent, 0),
	maxSize: 100, // Keep last 100 events
}

// LogProvisioningEvent logs a provisioning event
func LogProvisioningEvent(event ProvisioningEvent) {
	provisioningLog.mu.Lock()
	defer provisioningLog.mu.Unlock()

	// Add to front
	provisioningLog.events = append([]ProvisioningEvent{event}, provisioningLog.events...)

	// Trim if needed
	if len(provisioningLog.events) > provisioningLog.maxSize {
		provisioningLog.events = provisioningLog.events[:provisioningLog.maxSize]
	}

	log.Printf("[SCIM Provisioning] %s %s from %s - %s", event.Action, event.Resource, event.Source, event.ID)
}

// GetProvisioningEvents returns recent provisioning events
func GetProvisioningEvents(limit int) []ProvisioningEvent {
	provisioningLog.mu.RLock()
	defer provisioningLog.mu.RUnlock()

	if limit <= 0 || limit > len(provisioningLog.events) {
		limit = len(provisioningLog.events)
	}

	result := make([]ProvisioningEvent, limit)
	copy(result, provisioningLog.events[:limit])
	return result
}

// DetectIdPSource attempts to detect the IdP from request headers
func DetectIdPSource(r *http.Request) string {
	userAgent := r.Header.Get("User-Agent")
	
	// Okta's SCIM client
	if strings.Contains(userAgent, "Okta") {
		return "okta"
	}
	
	// Azure AD SCIM client
	if strings.Contains(userAgent, "Azure") || strings.Contains(userAgent, "Microsoft") {
		return "azure"
	}
	
	// OneLogin
	if strings.Contains(userAgent, "OneLogin") {
		return "onelogin"
	}
	
	// JumpCloud
	if strings.Contains(userAgent, "JumpCloud") {
		return "jumpcloud"
	}

	// Check for custom header that some IdPs send
	if idp := r.Header.Get("X-IdP-Source"); idp != "" {
		return strings.ToLower(idp)
	}

	return "unknown"
}

// InternalTokenResponse is returned by the internal token endpoint
type InternalTokenResponse struct {
	Token       string `json:"token,omitempty"`
	Configured  bool   `json:"configured"`
	AuthEnabled bool   `json:"authEnabled"`
	Message     string `json:"message,omitempty"`
}

// HandleInternalToken returns the SCIM bearer token for same-origin Looking Glass requests
// This endpoint is intentionally NOT protected by auth - it's for internal frontend use only
// Security: Only responds to same-origin requests (Sec-Fetch-Site: same-origin)
func HandleInternalToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Security check: Only allow same-origin requests
	// Modern browsers send Sec-Fetch-Site header for all requests
	fetchSite := r.Header.Get("Sec-Fetch-Site")
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")
	
	// Strict same-origin check
	isSameOrigin := fetchSite == "same-origin" || fetchSite == "same-site"
	
	// Fallback for older browsers: check Origin matches our host
	if !isSameOrigin && fetchSite == "" {
		// If Origin header is present, it must match
		if origin != "" {
			host := r.Host
			isSameOrigin = strings.Contains(origin, host)
		} else if referer != "" {
			// Last resort: check referer
			host := r.Host
			isSameOrigin = strings.Contains(referer, host)
		}
	}
	
	config := loadAuthConfig()
	
	// For cross-origin requests, return status but never the token
	if !isSameOrigin {
		log.Printf("SCIM internal token request rejected: cross-origin (Sec-Fetch-Site: %s)", fetchSite)
		json.NewEncoder(w).Encode(InternalTokenResponse{
			Configured:  config.RequireAuth,
			AuthEnabled: config.RequireAuth,
			Message:     "Token only available to same-origin requests",
		})
		return
	}
	
	// Same-origin request from Looking Glass
	if !config.RequireAuth {
		json.NewEncoder(w).Encode(InternalTokenResponse{
			Configured:  false,
			AuthEnabled: false,
			Message:     "SCIM authentication is disabled (no SCIM_API_TOKEN configured)",
		})
		return
	}
	
	// Return the token for Looking Glass to use
	json.NewEncoder(w).Encode(InternalTokenResponse{
		Token:       config.APIToken,
		Configured:  true,
		AuthEnabled: true,
		Message:     "Token retrieved successfully",
	})
}

