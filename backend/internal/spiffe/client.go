package spiffe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// HTTPClient is an HTTP client that uses SPIFFE credentials
type HTTPClient struct {
	workloadClient *WorkloadClient
	httpClient     *http.Client
	audiences      []string
}

// HTTPClientConfig configures the SPIFFE HTTP client
type HTTPClientConfig struct {
	// Timeout for requests
	Timeout time.Duration

	// Audiences for JWT-SVID (if using JWT auth)
	Audiences []string

	// UseMTLS enables mTLS mode (X.509-SVID)
	UseMTLS bool

	// Authorizer for validating peer SPIFFE IDs
	Authorizer tlsconfig.Authorizer

	// MaxIdleConns controls the maximum number of idle connections
	MaxIdleConns int

	// MaxConnsPerHost limits connections per host
	MaxConnsPerHost int

	// IdleConnTimeout is how long idle connections stay open
	IdleConnTimeout time.Duration
}

// DefaultHTTPClientConfig returns default configuration
func DefaultHTTPClientConfig() *HTTPClientConfig {
	return &HTTPClientConfig{
		Timeout:         30 * time.Second,
		Audiences:       []string{"protocolsoup"},
		UseMTLS:         true,
		MaxIdleConns:    100,
		MaxConnsPerHost: 10,
		IdleConnTimeout: 90 * time.Second,
	}
}

// NewHTTPClient creates a new SPIFFE-authenticated HTTP client
func NewHTTPClient(workloadClient *WorkloadClient, cfg *HTTPClientConfig) (*HTTPClient, error) {
	if !workloadClient.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE workload client not enabled")
	}

	if cfg == nil {
		cfg = DefaultHTTPClientConfig()
	}

	x509Source := workloadClient.X509Source()
	if x509Source == nil {
		return nil, fmt.Errorf("X509Source not available")
	}

	// Set up authorizer
	authorizer := cfg.Authorizer
	if authorizer == nil {
		authorizer = tlsconfig.AuthorizeMemberOf(workloadClient.TrustDomain())
	}

	// Create TLS config
	var tlsConfig *tls.Config
	if cfg.UseMTLS {
		tlsConfig = tlsconfig.MTLSClientConfig(x509Source, x509Source, authorizer)
	} else {
		// For non-mTLS, use MTLSClientConfig but with AuthorizeAny to accept any server
		tlsConfig = tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeAny())
	}

	// Create transport with SPIFFE TLS
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	return &HTTPClient{
		workloadClient: workloadClient,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		audiences: cfg.Audiences,
	}, nil
}

// Do executes an HTTP request with SPIFFE credentials
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

// DoWithJWT executes an HTTP request with JWT-SVID in the Authorization header
func (c *HTTPClient) DoWithJWT(ctx context.Context, req *http.Request, audience string) (*http.Response, error) {
	if audience == "" && len(c.audiences) > 0 {
		audience = c.audiences[0]
	}

	token, err := c.workloadClient.GetJWTSVIDToken(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT-SVID: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return c.httpClient.Do(req)
}

// Get performs a GET request
func (c *HTTPClient) Get(url string) (*http.Response, error) {
	return c.httpClient.Get(url)
}

// GetWithJWT performs a GET request with JWT-SVID
func (c *HTTPClient) GetWithJWT(ctx context.Context, url, audience string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.DoWithJWT(ctx, req, audience)
}

// Post performs a POST request
func (c *HTTPClient) Post(url, contentType string, body interface{}) (*http.Response, error) {
	return c.httpClient.Post(url, contentType, nil)
}

// Close closes the HTTP client
func (c *HTTPClient) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}

// Transport returns the underlying HTTP transport
func (c *HTTPClient) Transport() *http.Transport {
	return c.httpClient.Transport.(*http.Transport)
}

// RoundTripper implements http.RoundTripper with SPIFFE mTLS
type SPIFFERoundTripper struct {
	workloadClient *WorkloadClient
	base           http.RoundTripper
	addJWT         bool
	audiences      []string
}

// NewSPIFFERoundTripper creates a round tripper that adds SPIFFE credentials
func NewSPIFFERoundTripper(client *WorkloadClient, audiences []string, addJWT bool) (*SPIFFERoundTripper, error) {
	if !client.IsEnabled() {
		return nil, fmt.Errorf("SPIFFE client not enabled")
	}

	x509Source := client.X509Source()
	tlsConfig := tlsconfig.MTLSClientConfig(
		x509Source,
		x509Source,
		tlsconfig.AuthorizeMemberOf(client.TrustDomain()),
	)

	return &SPIFFERoundTripper{
		workloadClient: client,
		base: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		addJWT:    addJWT,
		audiences: audiences,
	}, nil
}

// RoundTrip implements http.RoundTripper
func (rt *SPIFFERoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request to avoid modifying the original
	reqCopy := req.Clone(req.Context())

	// Add JWT-SVID if configured
	if rt.addJWT && reqCopy.Header.Get("Authorization") == "" {
		audience := "protocolsoup"
		if len(rt.audiences) > 0 {
			audience = rt.audiences[0]
		}

		token, err := rt.workloadClient.GetJWTSVIDToken(req.Context(), audience)
		if err == nil {
			reqCopy.Header.Set("Authorization", "Bearer "+token)
		}
	}

	return rt.base.RoundTrip(reqCopy)
}

// ServiceClient is a client for calling a specific SPIFFE-authenticated service
type ServiceClient struct {
	httpClient *HTTPClient
	baseURL    string
	serviceID  spiffeid.ID
}

// NewServiceClient creates a client for a specific service
func NewServiceClient(workloadClient *WorkloadClient, baseURL string, serviceID spiffeid.ID) (*ServiceClient, error) {
	// Create HTTP client that only authorizes the specific service
	cfg := DefaultHTTPClientConfig()
	cfg.Authorizer = tlsconfig.AuthorizeID(serviceID)

	httpClient, err := NewHTTPClient(workloadClient, cfg)
	if err != nil {
		return nil, err
	}

	return &ServiceClient{
		httpClient: httpClient,
		baseURL:    baseURL,
		serviceID:  serviceID,
	}, nil
}

// Get performs a GET request to the service
func (c *ServiceClient) Get(ctx context.Context, path string) (*http.Response, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.httpClient.Do(req)
}

// GetWithJWT performs a GET request with JWT-SVID
func (c *ServiceClient) GetWithJWT(ctx context.Context, path, audience string) (*http.Response, error) {
	url := c.baseURL + path
	return c.httpClient.GetWithJWT(ctx, url, audience)
}

// Close closes the service client
func (c *ServiceClient) Close() error {
	return c.httpClient.Close()
}

// ServiceID returns the SPIFFE ID of the target service
func (c *ServiceClient) ServiceID() spiffeid.ID {
	return c.serviceID
}

