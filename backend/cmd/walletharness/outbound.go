package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	maxOutboundRedirects   = 2
	maxRequestObjectBytes  = 1 << 20
	outboundResolveTimeout = 5 * time.Second
)

// Extra prefixes beyond Go's IsPrivate/IsLoopback/IsLinkLocal set. Shared
// address space, IETF protocol assignments, documentation, and benchmarking
// ranges must not be treated as public request_uri / metadata destinations.
var extraBlockedExternalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

func (s *walletHarnessServer) newOutboundHTTPClient(timeout time.Duration) *http.Client {
	if s == nil {
		return &http.Client{Timeout: timeout}
	}
	if s.dialContext == nil {
		s.dialContext = (&net.Dialer{Timeout: timeout}).DialContext
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = s.secureDialContext
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxOutboundRedirects {
				return fmt.Errorf("too many redirects")
			}
			if req == nil || req.URL == nil {
				return fmt.Errorf("redirect URL is required")
			}
			ctx := req.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if _, err := s.validateOutboundURL(ctx, req.URL.String()); err != nil {
				return fmt.Errorf("redirect URL is not allowed: %w", err)
			}
			return nil
		},
	}
}

func (s *walletHarnessServer) validateExternalURL(raw string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), outboundResolveTimeout)
	defer cancel()
	return s.validateOutboundURL(ctx, raw)
}

// validateOutboundURL enforces the wallet fetch policy for caller-supplied
// URLs (OID4VP request_uri, OID4VCI metadata/token/credential endpoints, and
// redirects). RFC 9101 §5: "The request_uri value MUST be an https URI ...
// unless the contents are pre-registered." Pre-registered here is the
// configured target/issuer origin. Untrusted destinations are resolved and
// rejected when any address is non-public.
func (s *walletHarnessServer) validateOutboundURL(ctx context.Context, raw string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := strings.TrimSpace(raw)
	parsed, err := url.ParseRequestURI(normalized)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL userinfo is not allowed")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("external URL scheme %q is not allowed", parsed.Scheme)
	}
	hostWithPort := strings.ToLower(strings.TrimSpace(parsed.Host))
	if hostWithPort == "" {
		return "", fmt.Errorf("URL host is required")
	}
	if s.isTrustedURLHost(hostWithPort) {
		return parsed.String(), nil
	}
	if s == nil || !s.allowExternal {
		return "", fmt.Errorf("URL host %q is not allowed", hostWithPort)
	}

	hostName := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if hostName == "" {
		return "", fmt.Errorf("URL hostname is required")
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("external URL scheme %q is not allowed", parsed.Scheme)
	}
	if isBlockedExternalHostname(hostName) {
		return "", fmt.Errorf("external URL host %q is not allowed", hostName)
	}
	ips, err := s.resolveExternalIPs(ctx, hostName)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("external URL host %q could not be resolved", hostName)
	}
	for _, ip := range ips {
		if isBlockedExternalAddress(ip) {
			return "", fmt.Errorf("external URL host %q is not allowed", hostName)
		}
	}
	return parsed.String(), nil
}

func (s *walletHarnessServer) secureDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if s.isTrustedDialTarget(host, port) {
		return s.outboundDial(ctx, network, address)
	}
	ips, err := s.resolveExternalIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		if isBlockedExternalAddress(ip) {
			lastErr = fmt.Errorf("external URL host %q is not allowed", host)
			continue
		}
		conn, dialErr := s.outboundDial(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("external URL host %q is not allowed", host)
	}
	return nil, lastErr
}

func (s *walletHarnessServer) outboundDial(ctx context.Context, network, address string) (net.Conn, error) {
	if s != nil && s.dialContext != nil {
		return s.dialContext(ctx, network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (s *walletHarnessServer) resolveExternalIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	lookup := defaultLookupIPs
	if s != nil && s.lookupIPs != nil {
		lookup = s.lookupIPs
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("external URL host %q could not be resolved", host)
	}
	return ips, nil
}

func defaultLookupIPs(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if len(addr.IP) > 0 {
			ips = append(ips, addr.IP)
		}
	}
	return ips, nil
}

func (s *walletHarnessServer) trustedHostList() []string {
	if s == nil {
		return nil
	}
	hosts := make([]string, 0, 2)
	if host := strings.ToLower(strings.TrimSpace(s.targetHost)); host != "" {
		hosts = append(hosts, host)
	}
	if issuerURL, err := url.Parse(strings.TrimSpace(s.issuerBaseURL)); err == nil {
		if host := strings.ToLower(strings.TrimSpace(issuerURL.Host)); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func (s *walletHarnessServer) isTrustedURLHost(hostWithPort string) bool {
	hostWithPort = strings.ToLower(strings.TrimSpace(hostWithPort))
	if hostWithPort == "" {
		return false
	}
	for _, trusted := range s.trustedHostList() {
		if trusted != "" && hostWithPort == trusted {
			return true
		}
	}
	return false
}

func (s *walletHarnessServer) isTrustedDialTarget(host, port string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	port = strings.TrimSpace(port)
	if host == "" {
		return false
	}
	hostPort := host
	if port != "" {
		hostPort = net.JoinHostPort(host, port)
	}
	for _, trusted := range s.trustedHostList() {
		if trusted == host || trusted == hostPort {
			return true
		}
		trustedHost, trustedPort, err := net.SplitHostPort(trusted)
		if err != nil {
			if strings.EqualFold(trusted, host) && (port == "80" || port == "443") {
				return true
			}
			continue
		}
		if strings.EqualFold(trustedHost, host) && trustedPort == port {
			return true
		}
	}
	return false
}

func isBlockedExternalHostname(hostName string) bool {
	if hostName == "localhost" || strings.HasSuffix(hostName, ".localhost") {
		return true
	}
	if strings.HasSuffix(hostName, ".local") || strings.HasSuffix(hostName, ".internal") {
		return true
	}
	return false
}

func isBlockedExternalAddress(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	if !addr.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range extraBlockedExternalPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
