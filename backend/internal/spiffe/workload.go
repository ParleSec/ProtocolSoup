// Package spiffe provides SPIFFE/SPIRE workload identity integration.
// It implements the SPIFFE Workload API client for automatic SVID
// acquisition, rotation, and validation.
package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Config holds SPIFFE configuration options
type Config struct {
	// SocketPath is the path to the SPIRE Agent Workload API socket
	// Default: unix:///run/spire/sockets/agent.sock
	SocketPath string

	// TrustDomain is the SPIFFE trust domain
	// Example: protocolsoup.com
	TrustDomain string

	// Enabled indicates whether SPIFFE integration is enabled
	Enabled bool

	// AllowedSPIFFEIDs is a list of SPIFFE IDs allowed for authentication
	// If empty, all IDs from the trust domain are allowed
	AllowedSPIFFEIDs []string

	// Audiences for JWT-SVID validation
	Audiences []string
}

// DefaultConfig returns the default SPIFFE configuration
// Configuration can be overridden via environment variables:
//   - SHOWCASE_SPIFFE_ENABLED: set to "true" to enable SPIFFE integration
//   - SHOWCASE_SPIFFE_SOCKET_PATH: path to SPIRE Agent socket (default: /run/spire/sockets/agent.sock)
//   - SHOWCASE_SPIFFE_TRUST_DOMAIN: trust domain (default: protocolsoup.com)
func DefaultConfig() *Config {
	enabled := getEnvBool("SHOWCASE_SPIFFE_ENABLED", false)
	socketPath := getEnvString("SHOWCASE_SPIFFE_SOCKET_PATH", "unix:///run/spire/sockets/agent.sock")
	trustDomain := getEnvString("SHOWCASE_SPIFFE_TRUST_DOMAIN", "protocolsoup.com")
	
	return &Config{
		SocketPath:  socketPath,
		TrustDomain: trustDomain,
		Enabled:     enabled,
		Audiences:   []string{"protocolsoup", "protocolsoup.com"},
	}
}

// getEnvString returns the value of an environment variable or a default
func getEnvString(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// getEnvBool returns the boolean value of an environment variable
func getEnvBool(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return val == "true" || val == "1" || val == "yes"
}

// RotationEvent records a certificate rotation event
type RotationEvent struct {
	Timestamp       time.Time `json:"timestamp"`
	OldSerialNumber string    `json:"old_serial_number"`
	NewSerialNumber string    `json:"new_serial_number"`
	OldExpiry       time.Time `json:"old_expiry"`
	NewExpiry       time.Time `json:"new_expiry"`
	SPIFFEID        string    `json:"spiffe_id"`
	TriggerReason   string    `json:"trigger_reason"` // "ttl_threshold", "manual", "initial"
}

// WorkloadClient provides access to SPIFFE SVIDs via the Workload API
type WorkloadClient struct {
	config         *Config
	x509Source     *workloadapi.X509Source
	jwtSource      *workloadapi.JWTSource
	bundleSet      *workloadapi.BundleSource
	trustDomain    spiffeid.TrustDomain
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	started        bool
	rotationEvents []RotationEvent
	rotationMu     sync.RWMutex
	lastSerial     string
	lastExpiry     time.Time
}

// NewWorkloadClient creates a new SPIFFE Workload API client
func NewWorkloadClient(cfg *Config) (*WorkloadClient, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	td, err := spiffeid.TrustDomainFromString(cfg.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("invalid trust domain: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkloadClient{
		config:      cfg,
		trustDomain: td,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// Start initializes the Workload API connection and starts SVID rotation
func (c *WorkloadClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return nil
	}

	if !c.config.Enabled {
		log.Println("SPIFFE integration disabled")
		return nil
	}

	log.Printf("Connecting to SPIFFE Workload API at %s", c.config.SocketPath)

	// Create context with timeout for initial connection
	connectCtx, connectCancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer connectCancel()

	// Create X.509 source for automatic SVID rotation
	x509Source, err := workloadapi.NewX509Source(
		connectCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(c.config.SocketPath)),
	)
	if err != nil {
		return fmt.Errorf("failed to create X509Source: %w", err)
	}
	c.x509Source = x509Source

	// Create JWT source for JWT-SVID acquisition
	jwtSource, err := workloadapi.NewJWTSource(
		connectCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(c.config.SocketPath)),
	)
	if err != nil {
		x509Source.Close()
		return fmt.Errorf("failed to create JWTSource: %w", err)
	}
	c.jwtSource = jwtSource

	// Create bundle source for trust bundle access
	bundleSource, err := workloadapi.NewBundleSource(
		c.ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(c.config.SocketPath)),
	)
	if err != nil {
		x509Source.Close()
		jwtSource.Close()
		return fmt.Errorf("failed to create BundleSource: %w", err)
	}
	c.bundleSet = bundleSource

	// Verify we can get an SVID
	svid, err := x509Source.GetX509SVID()
	if err != nil {
		c.Close()
		return fmt.Errorf("failed to get initial X509-SVID: %w", err)
	}

	log.Printf("SPIFFE Workload API connected - SPIFFE ID: %s", svid.ID.String())
	c.started = true

	// Start monitoring for SVID updates
	go c.monitorSVIDUpdates()

	return nil
}

// monitorSVIDUpdates logs and records SVID rotation events
func (c *WorkloadClient) monitorSVIDUpdates() {
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds for responsiveness
	defer ticker.Stop()

	// Initialize with current SVID
	if svid, err := c.GetX509SVID(); err == nil {
		c.rotationMu.Lock()
		c.lastSerial = svid.Certificates[0].SerialNumber.String()
		c.lastExpiry = svid.Certificates[0].NotAfter
		// Record initial SVID as first "rotation" event
		c.rotationEvents = append(c.rotationEvents, RotationEvent{
			Timestamp:       time.Now(),
			OldSerialNumber: "",
			NewSerialNumber: c.lastSerial,
			OldExpiry:       time.Time{},
			NewExpiry:       c.lastExpiry,
			SPIFFEID:        svid.ID.String(),
			TriggerReason:   "initial",
		})
		c.rotationMu.Unlock()
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			svid, err := c.GetX509SVID()
			if err != nil {
				log.Printf("Warning: Failed to get X509-SVID: %v", err)
				continue
			}

			currentSerial := svid.Certificates[0].SerialNumber.String()
			currentExpiry := svid.Certificates[0].NotAfter

			c.rotationMu.Lock()
			if c.lastSerial != "" && c.lastSerial != currentSerial {
				// Rotation detected!
				event := RotationEvent{
					Timestamp:       time.Now(),
					OldSerialNumber: c.lastSerial,
					NewSerialNumber: currentSerial,
					OldExpiry:       c.lastExpiry,
					NewExpiry:       currentExpiry,
					SPIFFEID:        svid.ID.String(),
					TriggerReason:   "ttl_threshold",
				}
				c.rotationEvents = append(c.rotationEvents, event)

				// Keep only last 100 events
				if len(c.rotationEvents) > 100 {
					c.rotationEvents = c.rotationEvents[len(c.rotationEvents)-100:]
				}

				log.Printf("X509-SVID rotated - Old serial: %s..., New serial: %s..., New expiry: %s",
					c.lastSerial[:min(16, len(c.lastSerial))],
					currentSerial[:min(16, len(currentSerial))],
					currentExpiry.Format(time.RFC3339))
			}
			c.lastSerial = currentSerial
			c.lastExpiry = currentExpiry
			c.rotationMu.Unlock()
		}
	}
}

// GetRotationEvents returns the recorded rotation events
func (c *WorkloadClient) GetRotationEvents() []RotationEvent {
	c.rotationMu.RLock()
	defer c.rotationMu.RUnlock()

	// Return a copy to avoid race conditions
	events := make([]RotationEvent, len(c.rotationEvents))
	copy(events, c.rotationEvents)
	return events
}

// GetLastRotation returns the most recent rotation event
func (c *WorkloadClient) GetLastRotation() *RotationEvent {
	c.rotationMu.RLock()
	defer c.rotationMu.RUnlock()

	if len(c.rotationEvents) == 0 {
		return nil
	}
	event := c.rotationEvents[len(c.rotationEvents)-1]
	return &event
}

// Close releases all resources
func (c *WorkloadClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancel()

	var errs []error
	if c.x509Source != nil {
		if err := c.x509Source.Close(); err != nil {
			errs = append(errs, fmt.Errorf("x509source: %w", err))
		}
	}
	if c.jwtSource != nil {
		if err := c.jwtSource.Close(); err != nil {
			errs = append(errs, fmt.Errorf("jwtsource: %w", err))
		}
	}
	if c.bundleSet != nil {
		if err := c.bundleSet.Close(); err != nil {
			errs = append(errs, fmt.Errorf("bundlesource: %w", err))
		}
	}

	c.started = false

	if len(errs) > 0 {
		return fmt.Errorf("errors closing SPIFFE client: %v", errs)
	}
	return nil
}

// GetX509SVID returns the current X.509-SVID
func (c *WorkloadClient) GetX509SVID() (*x509svid.SVID, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.x509Source == nil {
		return nil, errors.New("X509Source not initialized")
	}

	return c.x509Source.GetX509SVID()
}

// GetX509SVIDChain returns the current X.509-SVID certificate chain as PEM
func (c *WorkloadClient) GetX509SVIDChain() ([]byte, error) {
	svid, err := c.GetX509SVID()
	if err != nil {
		return nil, err
	}

	var pemData []byte
	for _, cert := range svid.Certificates {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}

	return pemData, nil
}

// GetJWTSVID fetches a JWT-SVID for the given audience(s)
func (c *WorkloadClient) GetJWTSVID(ctx context.Context, audiences ...string) (*jwtsvid.SVID, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.jwtSource == nil {
		return nil, errors.New("JWTSource not initialized")
	}

	if len(audiences) == 0 {
		audiences = c.config.Audiences
	}

	// Get the SPIFFE ID from X509-SVID
	x509SVID, err := c.x509Source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("failed to get X509-SVID for JWT request: %w", err)
	}

	return c.jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Subject:  x509SVID.ID,
		Audience: audiences[0],
	})
}

// GetJWTSVIDToken fetches a JWT-SVID and returns just the token string
func (c *WorkloadClient) GetJWTSVIDToken(ctx context.Context, audience string) (string, error) {
	svid, err := c.GetJWTSVID(ctx, audience)
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

// ValidateJWTSVID validates a JWT-SVID token against the trust bundle
// Per SPIFFE JWT-SVID specification, this verifies:
// - Signature against trust bundle public keys
// - Expiration (exp claim)
// - Audience (aud claim) if provided
// - SPIFFE ID format in sub claim
func (c *WorkloadClient) ValidateJWTSVID(ctx context.Context, token string, expectedAudiences []string) (*jwtsvid.SVID, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.bundleSet == nil {
		return nil, errors.New("BundleSource not initialized - cannot validate JWT-SVID")
	}

	// Get the JWT bundle for validation
	bundle, err := c.bundleSet.GetBundleForTrustDomain(c.trustDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT bundle for validation: %w", err)
	}

	// Validate the JWT-SVID against the trust bundle
	// This performs full cryptographic signature verification
	svid, err := jwtsvid.ParseAndValidate(token, bundle, expectedAudiences)
	if err != nil {
		return nil, fmt.Errorf("JWT-SVID validation failed: %w", err)
	}

	return svid, nil
}

// GetTrustBundle returns the X.509 trust bundle for the trust domain
func (c *WorkloadClient) GetTrustBundle() ([]*x509.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.bundleSet == nil {
		return nil, errors.New("BundleSource not initialized")
	}

	bundle, err := c.bundleSet.GetBundleForTrustDomain(c.trustDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to get trust bundle: %w", err)
	}

	return bundle.X509Authorities(), nil
}

// GetTrustBundlePEM returns the trust bundle as PEM-encoded certificates
func (c *WorkloadClient) GetTrustBundlePEM() ([]byte, error) {
	certs, err := c.GetTrustBundle()
	if err != nil {
		return nil, err
	}

	var pemData []byte
	for _, cert := range certs {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}

	return pemData, nil
}

// GetSPIFFEID returns the current workload's SPIFFE ID
func (c *WorkloadClient) GetSPIFFEID() (spiffeid.ID, error) {
	svid, err := c.GetX509SVID()
	if err != nil {
		return spiffeid.ID{}, err
	}
	return svid.ID, nil
}

// X509Source returns the underlying X509Source for TLS configuration
func (c *WorkloadClient) X509Source() *workloadapi.X509Source {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.x509Source
}

// JWTSource returns the underlying JWTSource
func (c *WorkloadClient) JWTSource() *workloadapi.JWTSource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.jwtSource
}

// TLSConfig returns a TLS configuration helper for the client
func (c *WorkloadClient) TLSConfig() *TLSConfigHelper {
	return &TLSConfigHelper{client: c}
}

// TLSConfigHelper provides helper methods for TLS configuration
type TLSConfigHelper struct {
	client *WorkloadClient
}

// ServerAuthorizer returns an authorizer for TLS servers
func (h *TLSConfigHelper) ServerAuthorizer() tlsconfig.Authorizer {
	return tlsconfig.AuthorizeAny()
}

// MTLSAuthorizer returns an authorizer for mTLS servers
func (h *TLSConfigHelper) MTLSAuthorizer() tlsconfig.Authorizer {
	return tlsconfig.AuthorizeMemberOf(h.client.trustDomain)
}

// ClientAuthorizer returns an authorizer for clients
func (h *TLSConfigHelper) ClientAuthorizer() tlsconfig.Authorizer {
	return tlsconfig.AuthorizeAny()
}

// IsEnabled returns whether SPIFFE is enabled
func (c *WorkloadClient) IsEnabled() bool {
	return c.config.Enabled && c.started
}

// TrustDomain returns the configured trust domain
func (c *WorkloadClient) TrustDomain() spiffeid.TrustDomain {
	return c.trustDomain
}

// SVIDInfo contains information about an SVID for display/inspection
type SVIDInfo struct {
	SPIFFEID     string    `json:"spiffe_id"`
	TrustDomain  string    `json:"trust_domain"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	DNSNames     []string  `json:"dns_names,omitempty"`
	URIs         []string  `json:"uris,omitempty"`
	PublicKeyAlg string    `json:"public_key_algorithm"`
	SignatureAlg string    `json:"signature_algorithm"`
}

// GetSVIDInfo returns detailed information about the current X.509-SVID
func (c *WorkloadClient) GetSVIDInfo() (*SVIDInfo, error) {
	svid, err := c.GetX509SVID()
	if err != nil {
		return nil, err
	}

	cert := svid.Certificates[0]

	var uris []string
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	return &SVIDInfo{
		SPIFFEID:     svid.ID.String(),
		TrustDomain:  svid.ID.TrustDomain().String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Issuer:       cert.Issuer.String(),
		Subject:      cert.Subject.String(),
		DNSNames:     cert.DNSNames,
		URIs:         uris,
		PublicKeyAlg: cert.PublicKeyAlgorithm.String(),
		SignatureAlg: cert.SignatureAlgorithm.String(),
	}, nil
}

