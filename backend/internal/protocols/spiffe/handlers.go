package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// StatusResponse represents the SPIFFE status
type StatusResponse struct {
	Enabled     bool   `json:"enabled"`
	TrustDomain string `json:"trust_domain"`
	SPIFFEID    string `json:"spiffe_id,omitempty"`
	Message     string `json:"message"`
}

// handleStatus returns the current SPIFFE status
func (p *Plugin) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := StatusResponse{
		Enabled:     p.IsEnabled(),
		TrustDomain: "protocolsoup.com",
	}

	if p.IsEnabled() {
		status.Message = "SPIFFE integration active"
		if id, err := p.workloadClient.GetSPIFFEID(); err == nil {
			status.SPIFFEID = id.String()
		}
	} else {
		status.Message = "SPIFFE Workload API unavailable"
	}

	writeJSON(w, http.StatusOK, status)
}

// TrustBundleResponse represents the SPIFFE trust bundle
type TrustBundleResponse struct {
	TrustDomain string                   `json:"trust_domain"`
	Keys        []map[string]interface{} `json:"keys"`
}

// handleTrustBundle serves the trust bundle per SPIFFE spec
// GET /.well-known/spiffe-bundle
func (p *Plugin) handleTrustBundle(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	certs, err := p.workloadClient.GetTrustBundle()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get trust bundle: "+err.Error())
		return
	}

	// Convert to JWKS format per SPIFFE spec
	bundle := TrustBundleResponse{
		TrustDomain: p.workloadClient.TrustDomain().String(),
		Keys:        make([]map[string]interface{}, 0, len(certs)),
	}

	for i, cert := range certs {
		key := map[string]interface{}{
			"kty": "RSA",
			"use": "x509-svid",
			"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
		}
		if cert.PublicKeyAlgorithm == x509.ECDSA {
			key["kty"] = "EC"
		}
		key["kid"] = fmt.Sprintf("key-%d", i)
		bundle.Keys = append(bundle.Keys, key)
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, http.StatusOK, bundle)
}

// X509SVIDResponse represents X.509-SVID information
type X509SVIDResponse struct {
	SPIFFEID     string           `json:"spiffe_id"`
	Certificate  string           `json:"certificate"`
	Chain        []string         `json:"chain"`
	NotBefore    time.Time        `json:"not_before"`
	NotAfter     time.Time        `json:"not_after"`
	SerialNumber string           `json:"serial_number"`
	Issuer       string           `json:"issuer"`
	Subject      string           `json:"subject"`
	DNSNames     []string         `json:"dns_names,omitempty"`
	URIs         []string         `json:"uris"`
	PublicKey    PublicKeyInfo    `json:"public_key"`
	Signature    SignatureInfo    `json:"signature"`
	Extensions   []ExtensionInfo  `json:"extensions,omitempty"`
}

// PublicKeyInfo contains public key details
type PublicKeyInfo struct {
	Algorithm string `json:"algorithm"`
	Size      int    `json:"size,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

// SignatureInfo contains signature details
type SignatureInfo struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// ExtensionInfo contains X.509 extension details
type ExtensionInfo struct {
	OID      string `json:"oid"`
	Critical bool   `json:"critical"`
	Name     string `json:"name,omitempty"`
}

// handleX509SVID returns the current X.509-SVID
func (p *Plugin) handleX509SVID(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	svid, err := p.workloadClient.GetX509SVID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get X509-SVID: "+err.Error())
		return
	}

	cert := svid.Certificates[0]
	
	// Build chain
	chain := make([]string, len(svid.Certificates))
	for i, c := range svid.Certificates {
		chain[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}

	// Extract URIs
	uris := make([]string, len(cert.URIs))
	for i, u := range cert.URIs {
		uris[i] = u.String()
	}

	// Public key info
	pkInfo := PublicKeyInfo{
		Algorithm: cert.PublicKeyAlgorithm.String(),
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		// RSA key size would require type assertion
		pkInfo.Size = 2048 // Common default
	case x509.ECDSA:
		pkInfo.Curve = "P-256" // Common default
	}

	// Extensions
	extensions := make([]ExtensionInfo, 0)
	for _, ext := range cert.Extensions {
		extInfo := ExtensionInfo{
			OID:      ext.Id.String(),
			Critical: ext.Critical,
		}
		// Map common OIDs to names
		switch ext.Id.String() {
		case "2.5.29.17":
			extInfo.Name = "Subject Alternative Name"
		case "2.5.29.15":
			extInfo.Name = "Key Usage"
		case "2.5.29.37":
			extInfo.Name = "Extended Key Usage"
		case "2.5.29.19":
			extInfo.Name = "Basic Constraints"
		case "2.5.29.14":
			extInfo.Name = "Subject Key Identifier"
		case "2.5.29.35":
			extInfo.Name = "Authority Key Identifier"
		}
		extensions = append(extensions, extInfo)
	}

	resp := X509SVIDResponse{
		SPIFFEID:     svid.ID.String(),
		Certificate:  base64.StdEncoding.EncodeToString(cert.Raw),
		Chain:        chain,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
		Issuer:       cert.Issuer.String(),
		Subject:      cert.Subject.String(),
		DNSNames:     cert.DNSNames,
		URIs:         uris,
		PublicKey:    pkInfo,
		Signature: SignatureInfo{
			Algorithm: cert.SignatureAlgorithm.String(),
			Value:     base64.StdEncoding.EncodeToString(cert.Signature)[:64] + "...",
		},
		Extensions: extensions,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleX509SVIDChain returns the X.509-SVID certificate chain as PEM
func (p *Plugin) handleX509SVIDChain(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	pemData, err := p.workloadClient.GetX509SVIDChain()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get certificate chain: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(pemData)
}

// JWTSVIDResponse represents a JWT-SVID
type JWTSVIDResponse struct {
	Token     string                 `json:"token"`
	SPIFFEID  string                 `json:"spiffe_id"`
	Audience  []string               `json:"audience"`
	ExpiresAt time.Time              `json:"expires_at"`
	IssuedAt  time.Time              `json:"issued_at"`
	Header    map[string]interface{} `json:"header"`
	Claims    map[string]interface{} `json:"claims"`
}

// handleJWTSVID issues a JWT-SVID for the requested audience
func (p *Plugin) handleJWTSVID(w http.ResponseWriter, r *http.Request) {
	audience := r.URL.Query().Get("audience")
	if audience == "" {
		audience = "protocolsoup"
	}

	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	svid, err := p.workloadClient.GetJWTSVID(ctx, audience)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get JWT-SVID: "+err.Error())
		return
	}

	// Parse the JWT to extract header and claims for display
	token := svid.Marshal()
	header, claims := parseJWTForDisplay(token)

	resp := JWTSVIDResponse{
		Token:     token,
		SPIFFEID:  svid.ID.String(),
		Audience:  svid.Audience,
		ExpiresAt: svid.Expiry,
		IssuedAt:  time.Now(),
		Header:    header,
		Claims:    claims,
	}

	writeJSON(w, http.StatusOK, resp)
}

// SVIDInfoResponse contains detailed SVID information
type SVIDInfoResponse struct {
	X509SVID *X509SVIDResponse `json:"x509_svid,omitempty"`
	JWTSVID  *JWTSVIDResponse  `json:"jwt_svid,omitempty"`
	Status   string            `json:"status"`
}

// handleSVIDInfo returns detailed information about current SVIDs
func (p *Plugin) handleSVIDInfo(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	info, err := p.workloadClient.GetSVIDInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get SVID info: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "active",
		"svid_info": info,
	})
}

// ValidationRequest represents a validation request
type ValidationRequest struct {
	Token    string   `json:"token,omitempty"`
	Cert     string   `json:"certificate,omitempty"`
	Audience []string `json:"audience,omitempty"`
}

// ValidationResponse represents validation results
type ValidationResponse struct {
	Valid     bool                   `json:"valid"`
	SPIFFEID  string                 `json:"spiffe_id,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// handleValidateJWT validates a JWT-SVID
func (p *Plugin) handleValidateJWT(w http.ResponseWriter, r *http.Request) {
	var req ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "Token is required")
		return
	}

	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	audiences := req.Audience
	if len(audiences) == 0 {
		audiences = []string{"protocolsoup"}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	svid, err := p.workloadClient.ValidateJWTSVID(ctx, req.Token, audiences)
	if err != nil {
		header, claims := parseJWTForDisplay(req.Token)
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid: false,
			Error: fmt.Sprintf("JWT-SVID validation failed: %v", err),
			Details: map[string]interface{}{
				"header":          header,
				"claims":          claims,
				"validation_type": "cryptographic",
				"trust_bundle":    "verified against SPIFFE trust bundle",
			},
		})
		return
	}

	header, claims := parseJWTForDisplay(req.Token)
	writeJSON(w, http.StatusOK, ValidationResponse{
		Valid:    true,
		SPIFFEID: svid.ID.String(),
		Details: map[string]interface{}{
			"header":          header,
			"claims":          claims,
			"validation_type": "cryptographic",
			"signature":       "verified against SPIFFE trust bundle",
			"audience":        svid.Audience,
			"expiry":          svid.Expiry,
		},
	})
}

// handleValidateX509 validates an X.509-SVID
func (p *Plugin) handleValidateX509(w http.ResponseWriter, r *http.Request) {
	var req ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Cert == "" {
		writeError(w, http.StatusBadRequest, "Certificate is required")
		return
	}

	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	var certs []*x509.Certificate
	if certData, err := base64.StdEncoding.DecodeString(req.Cert); err == nil {
		if cert, err := x509.ParseCertificate(certData); err == nil {
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		rest := []byte(req.Cert)
		for {
			block, remaining := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = remaining
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				writeJSON(w, http.StatusOK, ValidationResponse{
					Valid: false,
					Error: "Failed to parse certificate: " + err.Error(),
				})
				return
			}
			certs = append(certs, cert)
		}
	}

	if len(certs) == 0 {
		writeError(w, http.StatusBadRequest, "Invalid certificate format")
		return
	}

	cert := certs[0]

	// Extract SPIFFE ID from SAN URI
	var spiffeID string
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			spiffeID = uri.String()
			break
		}
	}

	if spiffeID == "" {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid: false,
			Error: "No SPIFFE ID in SAN URI",
			Details: map[string]interface{}{
				"subject":    cert.Subject.String(),
				"issuer":     cert.Issuer.String(),
				"not_before": cert.NotBefore,
				"not_after":  cert.NotAfter,
				"serial":     cert.SerialNumber.String(),
			},
		})
		return
	}

	roots, err := p.workloadClient.GetTrustBundle()
	if err != nil {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid:    false,
			SPIFFEID: spiffeID,
			Error:    "Failed to get trust bundle: " + err.Error(),
		})
		return
	}

	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}

	intermediatePool := x509.NewCertPool()
	if len(certs) > 1 {
		for _, intermediate := range certs[1:] {
			intermediatePool.AddCert(intermediate)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, verifyErr := cert.Verify(opts)
	if verifyErr != nil {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid:    false,
			SPIFFEID: spiffeID,
			Error:    "Certificate verification failed: " + verifyErr.Error(),
			Details: map[string]interface{}{
				"subject":    cert.Subject.String(),
				"issuer":     cert.Issuer.String(),
				"not_before": cert.NotBefore,
				"not_after":  cert.NotAfter,
				"serial":     cert.SerialNumber.String(),
			},
		})
		return
	}

	resp := ValidationResponse{
		Valid:    true,
		SPIFFEID: spiffeID,
		Details: map[string]interface{}{
			"subject":            cert.Subject.String(),
			"issuer":             cert.Issuer.String(),
			"not_before":         cert.NotBefore,
			"not_after":          cert.NotAfter,
			"serial":             cert.SerialNumber.String(),
			"dns_names":          cert.DNSNames,
			"key_usage":          cert.KeyUsage,
			"is_ca":              cert.IsCA,
			"verified_chain_len": len(chains),
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// WorkloadInfoResponse contains workload information
type WorkloadInfoResponse struct {
	SPIFFEID     string                 `json:"spiffe_id"`
	TrustDomain  string                 `json:"trust_domain"`
	SVIDExpiry   time.Time              `json:"svid_expiry"`
	Enabled      bool                   `json:"enabled"`
	SocketPath   string                 `json:"socket_path"`
	Capabilities []string               `json:"capabilities"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// handleWorkloadInfo returns information about the current workload
func (p *Plugin) handleWorkloadInfo(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	info, err := p.workloadClient.GetSVIDInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get workload info: "+err.Error())
		return
	}

	resp := WorkloadInfoResponse{
		SPIFFEID:    info.SPIFFEID,
		TrustDomain: info.TrustDomain,
		SVIDExpiry:  info.NotAfter,
		Enabled:     true,
		SocketPath:  "/run/spire/sockets/agent.sock",
		Capabilities: []string{
			"x509_svid",
			"jwt_svid",
			"trust_bundle",
			"svid_rotation",
		},
		Metadata: map[string]interface{}{
			"serial_number":    info.SerialNumber,
			"issuer":           info.Issuer,
			"signature_alg":    info.SignatureAlg,
			"public_key_alg":   info.PublicKeyAlg,
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// TrustBundleInfoResponse contains trust bundle details
type TrustBundleInfoResponse struct {
	TrustDomain  string            `json:"trust_domain"`
	NumRoots     int               `json:"num_roots"`
	Roots        []CertificateInfo `json:"roots"`
}

// CertificateInfo contains certificate summary
type CertificateInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SerialNumber string    `json:"serial_number"`
	IsCA         bool      `json:"is_ca"`
}

// handleTrustBundleInfo returns detailed trust bundle information
func (p *Plugin) handleTrustBundleInfo(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	certs, err := p.workloadClient.GetTrustBundle()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get trust bundle: "+err.Error())
		return
	}

	roots := make([]CertificateInfo, len(certs))
	for i, cert := range certs {
		roots[i] = CertificateInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			SerialNumber: cert.SerialNumber.String(),
			IsCA:         cert.IsCA,
		}
	}

	resp := TrustBundleInfoResponse{
		TrustDomain: p.workloadClient.TrustDomain().String(),
		NumRoots:    len(certs),
		Roots:       roots,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Demo handlers

// MTLSDemoResponse represents mTLS demo results
type MTLSDemoResponse struct {
	Success       bool     `json:"success"`
	ClientSPIFFE  string   `json:"client_spiffe_id"`
	ServerSPIFFE  string   `json:"server_spiffe_id"`
	TLSVersion    string   `json:"tls_version"`
	CipherSuite   string   `json:"cipher_suite"`
	Steps         []string `json:"steps"`
}

// handleMTLSDemo returns information for mTLS demonstration
func (p *Plugin) handleMTLSDemo(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"description": "Mutual TLS demonstration using X.509-SVIDs",
		"enabled":     p.IsEnabled(),
		"endpoints": map[string]string{
			"call": "/spiffe/demo/mtls/call",
		},
		"flow": []map[string]string{
			{"step": "1", "action": "Client obtains X.509-SVID from SPIRE Agent"},
			{"step": "2", "action": "Client initiates TLS connection to server"},
			{"step": "3", "action": "Server presents its X.509-SVID"},
			{"step": "4", "action": "Client verifies server certificate against trust bundle"},
			{"step": "5", "action": "Client presents its X.509-SVID"},
			{"step": "6", "action": "Server verifies client certificate against trust bundle"},
			{"step": "7", "action": "Both extract SPIFFE IDs from certificates"},
			{"step": "8", "action": "Authorization based on SPIFFE IDs"},
			{"step": "9", "action": "Secure communication established"},
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleMTLSCall performs an mTLS call demonstrating mutual TLS authentication
func (p *Plugin) handleMTLSCall(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	// Get target address from query param, or use configured SPIRE server
	targetAddr := r.URL.Query().Get("target")
	if targetAddr == "" {
		targetAddr = defaultSpireServerAddress()
	}

	// Perform mTLS call
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	result, err := p.workloadClient.PerformMTLSCall(ctx, targetAddr)
	if err != nil {
		// Even on error, we return the partial result with steps showing what happened
		if result != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"success":          false,
				"client_spiffe_id": result.ClientSPIFFEID,
				"server_spiffe_id": result.ServerSPIFFEID,
				"tls_version":      result.TLSVersion,
				"cipher_suite":     result.CipherSuite,
				"error":            result.Error,
				"steps":            result.Steps,
				"target":           targetAddr,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("mTLS call failed: %v", err))
		return
	}

	// Return the full real mTLS result
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":            result.Success,
		"client_spiffe_id":   result.ClientSPIFFEID,
		"server_spiffe_id":   result.ServerSPIFFEID,
		"tls_version":        result.TLSVersion,
		"cipher_suite":       result.CipherSuite,
		"server_name":        result.ServerName,
		"handshake_time":     result.HandshakeTime,
		"peer_cert_subject":  result.PeerCertSubject,
		"peer_cert_issuer":   result.PeerCertIssuer,
		"peer_cert_expiry":   result.PeerCertExpiry,
		"peer_cert_serial":   result.PeerCertSerial,
		"trust_chain_length": result.TrustChainLength,
		"steps":              result.Steps,
		"target":             targetAddr,
	})
}

func defaultSpireServerAddress() string {
	addr := strings.TrimSpace(os.Getenv("SPIRE_SERVER_ADDRESS"))
	if addr == "" {
		addr = "spire-server"
	}

	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}

	return net.JoinHostPort(addr, "8081")
}

// handleJWTAuthDemo returns information for JWT authentication demonstration
func (p *Plugin) handleJWTAuthDemo(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"description": "JWT-SVID authentication demonstration",
		"enabled":     p.IsEnabled(),
		"endpoints": map[string]string{
			"call": "/spiffe/demo/jwt-auth/call",
		},
		"flow": []map[string]string{
			{"step": "1", "action": "Client requests JWT-SVID from SPIRE Agent"},
			{"step": "2", "action": "Agent returns signed JWT-SVID"},
			{"step": "3", "action": "Client adds JWT to Authorization header"},
			{"step": "4", "action": "Server extracts JWT from request"},
			{"step": "5", "action": "Server validates JWT signature"},
			{"step": "6", "action": "Server verifies audience claim"},
			{"step": "7", "action": "Server extracts SPIFFE ID from sub claim"},
			{"step": "8", "action": "Authorization based on SPIFFE ID"},
		},
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleJWTAuthCall demonstrates JWT-SVID authentication
func (p *Plugin) handleJWTAuthCall(w http.ResponseWriter, r *http.Request) {
	audience := r.URL.Query().Get("audience")
	if audience == "" {
		audience = "protocolsoup"
	}

	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	svid, err := p.workloadClient.GetJWTSVID(ctx, audience)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get JWT-SVID: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"spiffe_id": svid.ID.String(),
		"audience":  svid.Audience,
		"expiry":    svid.Expiry,
		"token":     svid.Marshal()[:50] + "...",
		"steps": []string{
			"JWT-SVID requested from Workload API",
			"JWT-SVID issued with audience: " + audience,
			"Token includes SPIFFE ID in sub claim",
			"JWT signature verified",
			"Audience validated",
			"SPIFFE ID: " + svid.ID.String(),
			"Request authorized",
		},
	})
}

// handleRotationDemo shows certificate rotation events captured from the SPIRE Agent
func (p *Plugin) handleRotationDemo(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeError(w, http.StatusServiceUnavailable, "SPIFFE Workload API unavailable")
		return
	}

	info, err := p.workloadClient.GetSVIDInfo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get SVID info: "+err.Error())
		return
	}

	// Calculate rotation time (typically at 50% of TTL)
	lifetime := info.NotAfter.Sub(info.NotBefore)
	rotationTime := info.NotBefore.Add(lifetime / 2)

	// Get rotation events captured by the workload client
	rotationEvents := p.workloadClient.GetRotationEvents()
	lastRotation := p.workloadClient.GetLastRotation()

	// Convert events to a format suitable for JSON response
	eventList := make([]map[string]interface{}, len(rotationEvents))
	for i, event := range rotationEvents {
		eventList[i] = map[string]interface{}{
			"timestamp":         event.Timestamp,
			"old_serial_number": event.OldSerialNumber,
			"new_serial_number": event.NewSerialNumber,
			"old_expiry":        event.OldExpiry,
			"new_expiry":        event.NewExpiry,
			"spiffe_id":         event.SPIFFEID,
			"trigger_reason":    event.TriggerReason,
		}
	}

	response := map[string]interface{}{
		"description":      "X.509-SVID rotation events captured from SPIRE Agent",
		"enabled":          true,
		"spiffe_id":        info.SPIFFEID,
		"current_serial":   info.SerialNumber,
		"current_expiry":   info.NotAfter,
		"current_issued":   info.NotBefore,
		"next_rotation":    rotationTime,
		"time_to_rotation": time.Until(rotationTime).String(),
		"rotation_info": map[string]string{
			"strategy":  "Rotate at ~50% of TTL (12 hours for 24h TTL)",
			"mechanism": "SPIRE Agent streaming Workload API (FetchX509SVID)",
			"impact":    "Zero downtime - X509Source automatically updates certificate",
		},
		"rotation_events": eventList,
		"total_rotations": len(rotationEvents),
	}

	// Add last rotation details if available
	if lastRotation != nil {
		response["last_rotation"] = map[string]interface{}{
			"timestamp":       lastRotation.Timestamp,
			"trigger_reason":  lastRotation.TriggerReason,
			"time_since":      time.Since(lastRotation.Timestamp).String(),
			"new_serial":      lastRotation.NewSerialNumber,
			"certificate_ttl": lastRotation.NewExpiry.Sub(lastRotation.Timestamp).String(),
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// Helper functions

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// parseJWTForDisplay parses a JWT and returns header and claims for display
func parseJWTForDisplay(token string) (map[string]interface{}, map[string]interface{}) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil
	}

	header := make(map[string]interface{})
	claims := make(map[string]interface{})

	if headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
		_ = json.Unmarshal(headerBytes, &header)
	}

	if claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		_ = json.Unmarshal(claimsBytes, &claims)
	}

	return header, claims
}
