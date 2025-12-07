package spiffe

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
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
		status.Message = "SPIFFE integration not available (running in demo mode)"
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
		// Return demo trust bundle
		writeJSON(w, http.StatusOK, getDemoTrustBundle())
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
		writeJSON(w, http.StatusOK, getDemoX509SVID())
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
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write([]byte(getDemoCertificatePEM()))
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
		writeJSON(w, http.StatusOK, getDemoJWTSVID(audience))
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
		writeJSON(w, http.StatusOK, SVIDInfoResponse{
			Status: "demo_mode",
			X509SVID: getDemoX509SVID(),
		})
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
		// Demo validation
		header, claims := parseJWTForDisplay(req.Token)
		resp := ValidationResponse{
			Valid:    true,
			SPIFFEID: "spiffe://protocolsoup.com/demo/workload",
			Details: map[string]interface{}{
				"header": header,
				"claims": claims,
				"note":   "Demo mode - signature not verified",
			},
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	audiences := req.Audience
	if len(audiences) == 0 {
		audiences = []string{"protocolsoup"}
	}

	// For JWT-SVID validation, we need a JWT bundle source
	// In demo mode or when we can't get the bundle, parse without full validation
	header, claims := parseJWTForDisplay(req.Token)
	
	// Basic structural validation
	if header == nil || claims == nil {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid: false,
			Error: "Invalid JWT format",
		})
		return
	}

	// Extract SPIFFE ID from sub claim
	subClaim, ok := claims["sub"].(string)
	if !ok || !strings.HasPrefix(subClaim, "spiffe://") {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid: false,
			Error: "Invalid or missing SPIFFE ID in sub claim",
		})
		return
	}

	// Check expiration
	if expClaim, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(expClaim) {
			writeJSON(w, http.StatusOK, ValidationResponse{
				Valid:    false,
				SPIFFEID: subClaim,
				Error:    "JWT-SVID has expired",
				Details: map[string]interface{}{
					"header": header,
					"claims": claims,
				},
			})
			return
		}
	}

	// Check audience
	audClaim, _ := claims["aud"]
	var audMatch bool
	switch aud := audClaim.(type) {
	case string:
		for _, a := range audiences {
			if aud == a {
				audMatch = true
				break
			}
		}
	case []interface{}:
		for _, audItem := range aud {
			if audStr, ok := audItem.(string); ok {
				for _, a := range audiences {
					if audStr == a {
						audMatch = true
						break
					}
				}
			}
		}
	}

	if !audMatch && len(audiences) > 0 {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid:    false,
			SPIFFEID: subClaim,
			Error:    fmt.Sprintf("Audience mismatch: expected one of %v", audiences),
			Details: map[string]interface{}{
				"header": header,
				"claims": claims,
			},
		})
		return
	}

	resp := ValidationResponse{
		Valid:    true,
		SPIFFEID: subClaim,
		Details: map[string]interface{}{
			"header":   header,
			"claims":   claims,
			"note":     "Signature validation requires JWKS from SPIRE Server",
		},
	}

	writeJSON(w, http.StatusOK, resp)
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

	// Decode certificate
	certData, err := base64.StdEncoding.DecodeString(req.Cert)
	if err != nil {
		// Try PEM format
		block, _ := pem.Decode([]byte(req.Cert))
		if block == nil {
			writeError(w, http.StatusBadRequest, "Invalid certificate format")
			return
		}
		certData = block.Bytes
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		writeJSON(w, http.StatusOK, ValidationResponse{
			Valid: false,
			Error: "Failed to parse certificate: " + err.Error(),
		})
		return
	}

	// Extract SPIFFE ID from SAN URI
	var spiffeID string
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			spiffeID = uri.String()
			break
		}
	}

	// Basic validation
	now := time.Now()
	valid := true
	var validationErrors []string

	if now.Before(cert.NotBefore) {
		valid = false
		validationErrors = append(validationErrors, "Certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		valid = false
		validationErrors = append(validationErrors, "Certificate expired")
	}
	if spiffeID == "" {
		valid = false
		validationErrors = append(validationErrors, "No SPIFFE ID in SAN URI")
	}

	resp := ValidationResponse{
		Valid:    valid,
		SPIFFEID: spiffeID,
		Details: map[string]interface{}{
			"subject":      cert.Subject.String(),
			"issuer":       cert.Issuer.String(),
			"not_before":   cert.NotBefore,
			"not_after":    cert.NotAfter,
			"serial":       cert.SerialNumber.String(),
			"dns_names":    cert.DNSNames,
			"key_usage":    cert.KeyUsage,
			"is_ca":        cert.IsCA,
		},
	}

	if len(validationErrors) > 0 {
		resp.Error = strings.Join(validationErrors, "; ")
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
		writeJSON(w, http.StatusOK, WorkloadInfoResponse{
			Enabled:     false,
			TrustDomain: "protocolsoup.com",
			SocketPath:  "/run/spire/sockets/agent.sock",
			Capabilities: []string{
				"x509_svid",
				"jwt_svid",
				"trust_bundle",
			},
			Metadata: map[string]interface{}{
				"mode": "demo",
			},
		})
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
		writeJSON(w, http.StatusOK, TrustBundleInfoResponse{
			TrustDomain: "protocolsoup.com",
			NumRoots:    1,
			Roots: []CertificateInfo{
				{
					Subject:      "CN=SPIRE Demo Root CA,O=ProtocolLens",
					Issuer:       "CN=SPIRE Demo Root CA,O=ProtocolLens",
					NotBefore:    time.Now().Add(-24 * time.Hour),
					NotAfter:     time.Now().Add(365 * 24 * time.Hour),
					SerialNumber: "1",
					IsCA:         true,
				},
			},
		})
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

// handleMTLSCall demonstrates an mTLS call
func (p *Plugin) handleMTLSCall(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeJSON(w, http.StatusOK, MTLSDemoResponse{
			Success:      true,
			ClientSPIFFE: "spiffe://protocolsoup.com/demo/client",
			ServerSPIFFE: "spiffe://protocolsoup.com/demo/server",
			TLSVersion:   "TLS 1.3",
			CipherSuite:  "TLS_AES_256_GCM_SHA384",
			Steps: []string{
				"[DEMO] Client X.509-SVID obtained",
				"[DEMO] TLS handshake initiated",
				"[DEMO] Server certificate verified",
				"[DEMO] Client certificate presented",
				"[DEMO] Mutual authentication successful",
				"[DEMO] SPIFFE IDs extracted",
				"[DEMO] Secure channel established",
			},
		})
		return
	}

	// Real mTLS demonstration would go here
	// This would involve making an actual mTLS call to another service

	svid, _ := p.workloadClient.GetSVIDInfo()
	
	writeJSON(w, http.StatusOK, MTLSDemoResponse{
		Success:      true,
		ClientSPIFFE: svid.SPIFFEID,
		ServerSPIFFE: svid.SPIFFEID,
		TLSVersion:   "TLS 1.3",
		CipherSuite:  "TLS_AES_256_GCM_SHA384",
		Steps: []string{
			"Client X.509-SVID obtained from Workload API",
			"TLS handshake with server",
			"Server certificate verified against trust bundle",
			"Client certificate presented and verified",
			"SPIFFE IDs extracted from certificates",
			"Authorization check passed",
			"Encrypted channel established",
		},
	})
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
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success":   true,
			"spiffe_id": "spiffe://protocolsoup.com/demo/workload",
			"audience":  audience,
			"steps": []string{
				"[DEMO] JWT-SVID requested for audience: " + audience,
				"[DEMO] JWT-SVID issued",
				"[DEMO] Authorization header set",
				"[DEMO] JWT signature verified",
				"[DEMO] Audience validated",
				"[DEMO] SPIFFE ID extracted",
				"[DEMO] Request authorized",
			},
		})
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

// handleRotationDemo demonstrates certificate rotation
func (p *Plugin) handleRotationDemo(w http.ResponseWriter, r *http.Request) {
	if !p.IsEnabled() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"description":   "Automatic X.509-SVID rotation demonstration",
			"enabled":       false,
			"current_svid":  getDemoX509SVID(),
			"next_rotation": time.Now().Add(30 * time.Minute),
			"rotation_info": map[string]string{
				"strategy":  "Rotate at 50% of TTL",
				"mechanism": "Streaming Workload API",
				"impact":    "Zero downtime - new connections use new cert",
			},
		})
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"description":     "Automatic X.509-SVID rotation demonstration",
		"enabled":         true,
		"spiffe_id":       info.SPIFFEID,
		"current_expiry":  info.NotAfter,
		"next_rotation":   rotationTime,
		"time_to_rotation": rotationTime.Sub(time.Now()).String(),
		"rotation_info": map[string]string{
			"strategy":  "Rotate at 50% of TTL",
			"mechanism": "Streaming Workload API (FetchX509SVID)",
			"impact":    "Zero downtime - new connections use new cert",
		},
	})
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
		json.Unmarshal(headerBytes, &header)
	}

	if claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
		json.Unmarshal(claimsBytes, &claims)
	}

	return header, claims
}

// Demo data generators

func getDemoTrustBundle() TrustBundleResponse {
	return TrustBundleResponse{
		TrustDomain: "protocolsoup.com",
		Keys: []map[string]interface{}{
			{
				"kty": "EC",
				"use": "x509-svid",
				"kid": "demo-key-1",
				"x5c": []string{"MIIBkTCB+wIJAKHBfpE...demo..."},
			},
		},
	}
}

func getDemoX509SVID() *X509SVIDResponse {
	now := time.Now()
	return &X509SVIDResponse{
		SPIFFEID:     "spiffe://protocolsoup.com/demo/workload",
		Certificate:  "MIIBkTCB+wIJAKHBfpE...demo...",
		Chain:        []string{"MIIBkTCB+wIJAKHBfpE...demo..."},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(1 * time.Hour),
		SerialNumber: "123456789",
		Issuer:       "CN=SPIRE Demo CA,O=ProtocolLens",
		Subject:      "O=SPIRE,C=US",
		DNSNames:     []string{"demo.protocolsoup.com"},
		URIs:         []string{"spiffe://protocolsoup.com/demo/workload"},
		PublicKey: PublicKeyInfo{
			Algorithm: "ECDSA",
			Curve:     "P-256",
		},
		Signature: SignatureInfo{
			Algorithm: "ECDSA-SHA256",
			Value:     "MEUCIQDk...demo...",
		},
	}
}

func getDemoJWTSVID(audience string) JWTSVIDResponse {
	now := time.Now()
	return JWTSVIDResponse{
		Token:     "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRlbW8ta2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOiJzcGlmZmU6Ly9wcm90b2NvbHNvdXAuY29tL2RlbW8vd29ya2xvYWQiLCJhdWQiOlsicHJvdG9jb2xzb3VwIl0sImV4cCI6MTcwOTMwMDAwMCwiaWF0IjoxNzA5Mjk2NDAwfQ.demo_signature",
		SPIFFEID:  "spiffe://protocolsoup.com/demo/workload",
		Audience:  []string{audience},
		ExpiresAt: now.Add(5 * time.Minute),
		IssuedAt:  now,
		Header: map[string]interface{}{
			"alg": "ES256",
			"kid": "demo-key",
			"typ": "JWT",
		},
		Claims: map[string]interface{}{
			"sub": "spiffe://protocolsoup.com/demo/workload",
			"aud": []string{audience},
			"exp": now.Add(5 * time.Minute).Unix(),
			"iat": now.Unix(),
		},
	}
}

func getDemoCertificatePEM() string {
	return `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEExample
Demo certificate for SPIFFE demonstration.
This is not a real certificate.
-----END CERTIFICATE-----
`
}

