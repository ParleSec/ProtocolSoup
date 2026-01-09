package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// MTLSConfig holds configuration for mTLS setup
type MTLSConfig struct {
	// AllowedSPIFFEIDs restricts which SPIFFE IDs can connect
	// If empty, all IDs in the trust domain are allowed
	AllowedSPIFFEIDs []spiffeid.ID

	// RequireClientCert determines if client certificates are mandatory
	RequireClientCert bool

	// TrustDomain for authorization
	TrustDomain spiffeid.TrustDomain
}

// MTLSServer wraps an HTTP server with SPIFFE mTLS
type MTLSServer struct {
	client     *WorkloadClient
	config     *MTLSConfig
	httpServer *http.Server
	listener   net.Listener
}

// NewMTLSServer creates a new mTLS-enabled HTTP server
func NewMTLSServer(client *WorkloadClient, handler http.Handler, addr string, cfg *MTLSConfig) (*MTLSServer, error) {
	if !client.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE client not enabled")
	}

	if cfg == nil {
		cfg = &MTLSConfig{
			RequireClientCert: true,
			TrustDomain:       client.TrustDomain(),
		}
	}

	server := &MTLSServer{
		client: client,
		config: cfg,
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  120 * time.Second,
		},
	}

	return server, nil
}

// ListenAndServeTLS starts the mTLS server
func (s *MTLSServer) ListenAndServeTLS(ctx context.Context) error {
	x509Source := s.client.X509Source()
	if x509Source == nil {
		return fmt.Errorf("X509Source not available")
	}

	// Create authorizer based on configuration
	var authorizer tlsconfig.Authorizer
	if len(s.config.AllowedSPIFFEIDs) > 0 {
		authorizer = tlsconfig.AuthorizeOneOf(s.config.AllowedSPIFFEIDs...)
	} else {
		authorizer = tlsconfig.AuthorizeMemberOf(s.config.TrustDomain)
	}

	// Create TLS config using SPIFFE
	tlsConfig := tlsconfig.MTLSServerConfig(x509Source, x509Source, authorizer)

	// Create listener
	listener, err := tls.Listen("tcp", s.httpServer.Addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS listener: %w", err)
	}
	s.listener = listener

	log.Printf("mTLS server listening on %s", s.httpServer.Addr)
	log.Printf("Trust domain: %s", s.config.TrustDomain.String())
	if len(s.config.AllowedSPIFFEIDs) > 0 {
		log.Printf("Allowed SPIFFE IDs: %v", s.config.AllowedSPIFFEIDs)
	}

	return s.httpServer.Serve(listener)
}

// Shutdown gracefully shuts down the server
func (s *MTLSServer) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Close immediately closes the server
func (s *MTLSServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// ServerTLSConfig returns a tls.Config for standard TLS server (not mTLS)
func ServerTLSConfig(client *WorkloadClient) (*tls.Config, error) {
	if !client.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE client not enabled")
	}

	x509Source := client.X509Source()
	if x509Source == nil {
		return nil, fmt.Errorf("X509Source not available")
	}

	return tlsconfig.TLSServerConfig(x509Source), nil
}

// MTLSServerTLSConfig returns a tls.Config for mTLS server
func MTLSServerTLSConfig(client *WorkloadClient, authorizer tlsconfig.Authorizer) (*tls.Config, error) {
	if !client.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE client not enabled")
	}

	x509Source := client.X509Source()
	if x509Source == nil {
		return nil, fmt.Errorf("X509Source not available")
	}

	if authorizer == nil {
		authorizer = tlsconfig.AuthorizeMemberOf(client.TrustDomain())
	}

	return tlsconfig.MTLSServerConfig(x509Source, x509Source, authorizer), nil
}

// DualModeServer supports both mTLS and standard TLS connections
type DualModeServer struct {
	client       *WorkloadClient
	mtlsAddr     string
	standardAddr string
	handler      http.Handler
	mtlsServer   *http.Server
	stdServer    *http.Server
	mtlsListener net.Listener
	stdListener  net.Listener
}

// NewDualModeServer creates a server that supports both mTLS and standard TLS
func NewDualModeServer(client *WorkloadClient, handler http.Handler, mtlsAddr, standardAddr string) *DualModeServer {
	return &DualModeServer{
		client:       client,
		mtlsAddr:     mtlsAddr,
		standardAddr: standardAddr,
		handler:      handler,
		mtlsServer: &http.Server{
			Addr:         mtlsAddr,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		stdServer: &http.Server{
			Addr:         standardAddr,
			Handler:      handler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
	}
}

// Start starts both servers
func (s *DualModeServer) Start(ctx context.Context) error {
	if !s.client.IsEnabled() {
		// Fallback to standard HTTP if SPIFFE not enabled
		log.Printf("SPIFFE not enabled, starting standard HTTP server on %s", s.standardAddr)
		return s.stdServer.ListenAndServe()
	}

	x509Source := s.client.X509Source()

	// Start mTLS server
	mtlsConfig := tlsconfig.MTLSServerConfig(
		x509Source,
		x509Source,
		tlsconfig.AuthorizeMemberOf(s.client.TrustDomain()),
	)

	mtlsListener, err := tls.Listen("tcp", s.mtlsAddr, mtlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create mTLS listener: %w", err)
	}
	s.mtlsListener = mtlsListener

	// Start standard TLS server
	stdConfig := tlsconfig.TLSServerConfig(x509Source)
	stdListener, err := tls.Listen("tcp", s.standardAddr, stdConfig)
	if err != nil {
		mtlsListener.Close()
		return fmt.Errorf("failed to create TLS listener: %w", err)
	}
	s.stdListener = stdListener

	// Start servers in goroutines
	errChan := make(chan error, 2)

	go func() {
		log.Printf("mTLS server listening on %s", s.mtlsAddr)
		if err := s.mtlsServer.Serve(mtlsListener); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("mTLS server error: %w", err)
		}
	}()

	go func() {
		log.Printf("TLS server listening on %s", s.standardAddr)
		if err := s.stdServer.Serve(stdListener); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("TLS server error: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return nil
	}
}

// Shutdown gracefully shuts down both servers
func (s *DualModeServer) Shutdown(ctx context.Context) error {
	var errs []error
	if err := s.mtlsServer.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.stdServer.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// DialTLS creates a TLS connection to a peer using SPIFFE credentials
func DialTLS(ctx context.Context, client *WorkloadClient, network, addr string, authorizer tlsconfig.Authorizer) (net.Conn, error) {
	if !client.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE client not enabled")
	}

	x509Source := client.X509Source()
	if x509Source == nil {
		return nil, fmt.Errorf("X509Source not available")
	}

	if authorizer == nil {
		authorizer = tlsconfig.AuthorizeMemberOf(client.TrustDomain())
	}

	// Create TLS config with the authorizer
	tlsConfig := tlsconfig.MTLSClientConfig(x509Source, x509Source, authorizer)

	// Dial with standard TLS
	return tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, network, addr, tlsConfig)
}

// VerifyCertificate extracts and validates SPIFFE ID from a peer certificate
func VerifyCertificate(cert *x509.Certificate, trustDomain spiffeid.TrustDomain) (spiffeid.ID, error) {
	// Extract SPIFFE ID from SAN URI
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			id, err := spiffeid.FromURI(uri)
			if err != nil {
				continue
			}
			// Verify trust domain
			if id.TrustDomain() != trustDomain {
				return spiffeid.ID{}, fmt.Errorf("certificate trust domain %s does not match expected %s",
					id.TrustDomain().String(), trustDomain.String())
			}
			return id, nil
		}
	}
	return spiffeid.ID{}, fmt.Errorf("no valid SPIFFE ID found in certificate")
}

// PeerSPIFFEID extracts the SPIFFE ID from a TLS connection state
func PeerSPIFFEID(state tls.ConnectionState, trustDomain spiffeid.TrustDomain) (spiffeid.ID, error) {
	if len(state.PeerCertificates) == 0 {
		return spiffeid.ID{}, fmt.Errorf("no peer certificate present")
	}
	return VerifyCertificate(state.PeerCertificates[0], trustDomain)
}

// MTLSCallResult contains the results of a real mTLS call
type MTLSCallResult struct {
	Success          bool      `json:"success"`
	ClientSPIFFEID   string    `json:"client_spiffe_id"`
	ServerSPIFFEID   string    `json:"server_spiffe_id"`
	TLSVersion       string    `json:"tls_version"`
	CipherSuite      string    `json:"cipher_suite"`
	ServerName       string    `json:"server_name"`
	HandshakeTime    string    `json:"handshake_time"`
	PeerCertSubject  string    `json:"peer_cert_subject"`
	PeerCertIssuer   string    `json:"peer_cert_issuer"`
	PeerCertExpiry   time.Time `json:"peer_cert_expiry"`
	PeerCertSerial   string    `json:"peer_cert_serial"`
	TrustChainLength int       `json:"trust_chain_length"`
	Error            string    `json:"error,omitempty"`
	Steps            []string  `json:"steps"`
}

// PerformMTLSCall makes a real mTLS connection to a target endpoint
// This demonstrates actual mutual TLS authentication using X.509-SVIDs
func (c *WorkloadClient) PerformMTLSCall(ctx context.Context, targetAddr string) (*MTLSCallResult, error) {
	result := &MTLSCallResult{
		Steps: make([]string, 0),
	}

	if !c.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE client not enabled")
	}

	// Step 1: Get our X.509-SVID
	startTime := time.Now()
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Fetching X.509-SVID from SPIRE Agent Workload API", time.Now().Format("15:04:05.000")))

	svid, err := c.GetX509SVID()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to get X.509-SVID: %v", err)
		return result, err
	}
	result.ClientSPIFFEID = svid.ID.String()
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Obtained X.509-SVID: %s", time.Now().Format("15:04:05.000"), svid.ID.String()))

	// Step 2: Get trust bundle for server verification
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Fetching trust bundle for peer verification", time.Now().Format("15:04:05.000")))

	bundle, err := c.GetTrustBundle()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to get trust bundle: %v", err)
		return result, err
	}
	result.TrustChainLength = len(bundle)
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Trust bundle loaded with %d CA certificate(s)", time.Now().Format("15:04:05.000"), len(bundle)))

	// Step 3: Create mTLS config
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Configuring TLS with X.509-SVID and trust bundle", time.Now().Format("15:04:05.000")))

	x509Source := c.X509Source()
	if x509Source == nil {
		result.Error = "X509Source not available"
		return result, fmt.Errorf("X509Source not available")
	}

	// Create TLS config that accepts any member of our trust domain
	tlsConfig := tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeMemberOf(c.trustDomain))

	// Step 4: Dial the target with mTLS
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Initiating TLS handshake to %s", time.Now().Format("15:04:05.000"), targetAddr))

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", targetAddr, tlsConfig)
	if err != nil {
		result.Error = fmt.Sprintf("TLS dial failed: %v", err)
		result.Steps = append(result.Steps, fmt.Sprintf("[%s] ERROR: TLS handshake failed: %v", time.Now().Format("15:04:05.000"), err))
		return result, err
	}
	defer conn.Close()

	handshakeTime := time.Since(startTime)
	result.HandshakeTime = handshakeTime.String()
	result.Success = true

	// Step 5: Extract connection details
	state := conn.ConnectionState()
	result.TLSVersion = tlsVersionString(state.Version)
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	result.ServerName = state.ServerName

	result.Steps = append(result.Steps, fmt.Sprintf("[%s] TLS handshake completed in %s", time.Now().Format("15:04:05.000"), handshakeTime))
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Negotiated TLS version: %s", time.Now().Format("15:04:05.000"), result.TLSVersion))
	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Negotiated cipher suite: %s", time.Now().Format("15:04:05.000"), result.CipherSuite))

	// Step 6: Extract peer certificate info
	if len(state.PeerCertificates) > 0 {
		peerCert := state.PeerCertificates[0]
		result.PeerCertSubject = peerCert.Subject.String()
		result.PeerCertIssuer = peerCert.Issuer.String()
		result.PeerCertExpiry = peerCert.NotAfter
		result.PeerCertSerial = peerCert.SerialNumber.String()

		// Extract SPIFFE ID from peer certificate
		for _, uri := range peerCert.URIs {
			if uri.Scheme == "spiffe" {
				result.ServerSPIFFEID = uri.String()
				break
			}
		}

		result.Steps = append(result.Steps, fmt.Sprintf("[%s] Server presented certificate for: %s", time.Now().Format("15:04:05.000"), result.ServerSPIFFEID))
		result.Steps = append(result.Steps, fmt.Sprintf("[%s] Certificate verified against trust bundle", time.Now().Format("15:04:05.000")))
		result.Steps = append(result.Steps, fmt.Sprintf("[%s] SPIFFE ID validated in trust domain: %s", time.Now().Format("15:04:05.000"), c.trustDomain.String()))
	}

	result.Steps = append(result.Steps, fmt.Sprintf("[%s] Mutual TLS authentication successful!", time.Now().Format("15:04:05.000")))

	return result, nil
}

// tlsVersionString returns a human-readable TLS version string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}
