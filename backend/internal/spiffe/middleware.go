package spiffe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// SPIFFEIDContextKey is the context key for the authenticated SPIFFE ID
	SPIFFEIDContextKey ContextKey = "spiffe_id"

	// JWTSVIDContextKey is the context key for the validated JWT-SVID
	JWTSVIDContextKey ContextKey = "jwt_svid"

	// X509SVIDContextKey is the context key for the peer's X.509-SVID info
	X509SVIDContextKey ContextKey = "x509_svid"
)

// AuthorizationPolicy defines authorization rules based on SPIFFE IDs
type AuthorizationPolicy struct {
	// AllowedPaths maps URL path prefixes to allowed SPIFFE ID patterns
	// Pattern format: "spiffe://trust-domain/path/*" supports wildcards
	AllowedPaths map[string][]string

	// AllowedIDs is a list of explicitly allowed SPIFFE IDs
	AllowedIDs []spiffeid.ID

	// AllowTrustDomain allows any ID from the specified trust domain
	AllowTrustDomain bool

	// TrustDomain for authorization
	TrustDomain spiffeid.TrustDomain
}

// JWTMiddlewareConfig configures the JWT-SVID middleware
type JWTMiddlewareConfig struct {
	// Client is the SPIFFE workload client
	Client *WorkloadClient

	// Audiences that are acceptable in the JWT
	Audiences []string

	// Policy for authorization decisions
	Policy *AuthorizationPolicy

	// Optional indicates if authentication is optional
	Optional bool

	// HeaderName is the header containing the JWT (default: Authorization)
	HeaderName string

	// HeaderPrefix is the prefix before the token (default: Bearer)
	HeaderPrefix string
}

// JWTMiddleware validates JWT-SVIDs from incoming requests
type JWTMiddleware struct {
	config *JWTMiddlewareConfig
}

// NewJWTMiddleware creates a new JWT-SVID validation middleware
func NewJWTMiddleware(cfg *JWTMiddlewareConfig) *JWTMiddleware {
	if cfg.HeaderName == "" {
		cfg.HeaderName = "Authorization"
	}
	if cfg.HeaderPrefix == "" {
		cfg.HeaderPrefix = "Bearer"
	}
	if len(cfg.Audiences) == 0 {
		cfg.Audiences = []string{"protocolsoup", "protocolsoup.com"}
	}

	return &JWTMiddleware{config: cfg}
}

// Handler returns the middleware handler function
func (m *JWTMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if SPIFFE is not enabled
		if !m.config.Client.IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from header
		authHeader := r.Header.Get(m.config.HeaderName)
		if authHeader == "" {
			if m.config.Optional {
				next.ServeHTTP(w, r)
				return
			}
			writeAuthError(w, "missing_token", "No authorization header present")
			return
		}

		// Parse header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], m.config.HeaderPrefix) {
			writeAuthError(w, "invalid_header", "Invalid authorization header format")
			return
		}
		token := parts[1]

		// Validate JWT-SVID
		svid, err := m.validateJWTSVID(token)
		if err != nil {
			log.Printf("JWT-SVID validation failed: %v", err)
			writeAuthError(w, "invalid_token", "Invalid JWT-SVID")
			return
		}

		// Check authorization policy
		if m.config.Policy != nil {
			if !m.authorize(svid.ID, r.URL.Path) {
				log.Printf("Authorization denied for %s accessing %s", svid.ID.String(), r.URL.Path)
				writeAuthError(w, "unauthorized", "Access denied")
				return
			}
		}

		// Add SPIFFE ID and SVID to context
		ctx := context.WithValue(r.Context(), SPIFFEIDContextKey, svid.ID)
		ctx = context.WithValue(ctx, JWTSVIDContextKey, svid)

		log.Printf("JWT-SVID authenticated: %s", svid.ID.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateJWTSVID validates a JWT-SVID token
func (m *JWTMiddleware) validateJWTSVID(token string) (*jwtsvid.SVID, error) {
	jwtSource := m.config.Client.JWTSource()
	if jwtSource == nil {
		return nil, fmt.Errorf("JWT source not available")
	}

	// Parse and validate the JWT-SVID
	// The JWT source provides the trust bundle for validation
	bundles, err := m.config.Client.bundleSet.GetBundleForTrustDomain(m.config.Client.TrustDomain())
	if err != nil {
		return nil, fmt.Errorf("failed to get trust bundle: %w", err)
	}

	svid, err := jwtsvid.ParseAndValidate(token, bundles, m.config.Audiences)
	if err != nil {
		return nil, fmt.Errorf("JWT-SVID validation failed: %w", err)
	}

	return svid, nil
}

// authorize checks if the SPIFFE ID is authorized for the given path
func (m *JWTMiddleware) authorize(id spiffeid.ID, path string) bool {
	policy := m.config.Policy

	// Check trust domain
	if policy.AllowTrustDomain && id.TrustDomain() == policy.TrustDomain {
		return true
	}

	// Check explicit allowed IDs
	for _, allowedID := range policy.AllowedIDs {
		if id == allowedID {
			return true
		}
	}

	// Check path-based rules
	for pathPrefix, patterns := range policy.AllowedPaths {
		if strings.HasPrefix(path, pathPrefix) {
			for _, pattern := range patterns {
				if matchSPIFFEIDPattern(id, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// matchSPIFFEIDPattern checks if a SPIFFE ID matches a pattern
// Supports wildcards: spiffe://domain/* matches all paths
func matchSPIFFEIDPattern(id spiffeid.ID, pattern string) bool {
	idStr := id.String()

	// Exact match
	if idStr == pattern {
		return true
	}

	// Wildcard match
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(idStr, prefix)
	}

	return false
}

// MTLSMiddleware validates X.509-SVIDs from mTLS connections
type MTLSMiddleware struct {
	client *WorkloadClient
	policy *AuthorizationPolicy
}

// NewMTLSMiddleware creates a new mTLS validation middleware
func NewMTLSMiddleware(client *WorkloadClient, policy *AuthorizationPolicy) *MTLSMiddleware {
	return &MTLSMiddleware{
		client: client,
		policy: policy,
	}
}

// Handler returns the middleware handler function
func (m *MTLSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip if SPIFFE is not enabled
		if !m.client.IsEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		// Get TLS connection state
		if r.TLS == nil {
			writeAuthError(w, "no_tls", "TLS connection required")
			return
		}

		// Extract SPIFFE ID from peer certificate
		spiffeID, err := PeerSPIFFEID(*r.TLS, m.client.TrustDomain())
		if err != nil {
			log.Printf("Failed to extract SPIFFE ID from peer certificate: %v", err)
			writeAuthError(w, "invalid_cert", "Invalid peer certificate")
			return
		}

		// Check authorization policy
		if m.policy != nil {
			if !m.authorize(spiffeID, r.URL.Path) {
				log.Printf("Authorization denied for %s accessing %s", spiffeID.String(), r.URL.Path)
				writeAuthError(w, "unauthorized", "Access denied")
				return
			}
		}

		// Add SPIFFE ID and certificate info to context
		ctx := context.WithValue(r.Context(), SPIFFEIDContextKey, spiffeID)
		if len(r.TLS.PeerCertificates) > 0 {
			ctx = context.WithValue(ctx, X509SVIDContextKey, r.TLS.PeerCertificates[0])
		}

		log.Printf("mTLS authenticated: %s", spiffeID.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorize checks if the SPIFFE ID is authorized
func (m *MTLSMiddleware) authorize(id spiffeid.ID, path string) bool {
	if m.policy == nil {
		return true
	}

	// Same logic as JWT middleware
	if m.policy.AllowTrustDomain && id.TrustDomain() == m.policy.TrustDomain {
		return true
	}

	for _, allowedID := range m.policy.AllowedIDs {
		if id == allowedID {
			return true
		}
	}

	for pathPrefix, patterns := range m.policy.AllowedPaths {
		if strings.HasPrefix(path, pathPrefix) {
			for _, pattern := range patterns {
				if matchSPIFFEIDPattern(id, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// CombinedMiddleware supports both JWT-SVID and mTLS authentication
type CombinedMiddleware struct {
	jwtMiddleware  *JWTMiddleware
	mtlsMiddleware *MTLSMiddleware
	preferMTLS     bool
}

// NewCombinedMiddleware creates middleware that supports both auth methods
func NewCombinedMiddleware(client *WorkloadClient, policy *AuthorizationPolicy, audiences []string) *CombinedMiddleware {
	return &CombinedMiddleware{
		jwtMiddleware: NewJWTMiddleware(&JWTMiddlewareConfig{
			Client:    client,
			Audiences: audiences,
			Policy:    policy,
			Optional:  true, // JWT is optional if mTLS present
		}),
		mtlsMiddleware: NewMTLSMiddleware(client, policy),
		preferMTLS:     true,
	}
}

// Handler returns the middleware handler function
func (m *CombinedMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authenticated bool
		var spiffeID spiffeid.ID

		// Try mTLS first if preferred and TLS is present
		if m.preferMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			id, err := PeerSPIFFEID(*r.TLS, m.mtlsMiddleware.client.TrustDomain())
			if err == nil {
				spiffeID = id
				authenticated = true
			}
		}

		// Fall back to JWT-SVID
		if !authenticated {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				svid, err := m.jwtMiddleware.validateJWTSVID(token)
				if err == nil {
					spiffeID = svid.ID
					authenticated = true
					r = r.WithContext(context.WithValue(r.Context(), JWTSVIDContextKey, svid))
				}
			}
		}

		if !authenticated {
			writeAuthError(w, "unauthenticated", "No valid SPIFFE credentials")
			return
		}

		// Add SPIFFE ID to context
		ctx := context.WithValue(r.Context(), SPIFFEIDContextKey, spiffeID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSPIFFEID extracts the authenticated SPIFFE ID from the request context
func GetSPIFFEID(ctx context.Context) (spiffeid.ID, bool) {
	id, ok := ctx.Value(SPIFFEIDContextKey).(spiffeid.ID)
	return id, ok
}

// GetJWTSVID extracts the JWT-SVID from the request context
func GetJWTSVID(ctx context.Context) (*jwtsvid.SVID, bool) {
	svid, ok := ctx.Value(JWTSVIDContextKey).(*jwtsvid.SVID)
	return svid, ok
}

// GetPeerCertificate extracts the peer's X.509 certificate from context
func GetPeerCertificate(ctx context.Context) (*tls.ConnectionState, bool) {
	state, ok := ctx.Value(X509SVIDContextKey).(*tls.ConnectionState)
	return state, ok
}

// RequireSPIFFE is a middleware that requires SPIFFE authentication
func RequireSPIFFE(client *WorkloadClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !client.IsEnabled() {
				// SPIFFE not enabled, allow through
				next.ServeHTTP(w, r)
				return
			}

			_, ok := GetSPIFFEID(r.Context())
			if !ok {
				writeAuthError(w, "unauthorized", "SPIFFE authentication required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AuthError represents an authentication error response
type AuthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func writeAuthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="spiffe"`)
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(AuthError{
		Error:       code,
		Description: description,
	})
}

