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

