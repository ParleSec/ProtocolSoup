package oid4vp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

const (
	verifierAttestationClientIDEnv   = "OID4VP_VERIFIER_ATTESTATION_CLIENT_ID"
	verifierAttestationIssuerEnv     = "OID4VP_VERIFIER_ATTESTATION_ISSUER"
	verifierAttestationPrivateKeyEnv = "OID4VP_VERIFIER_ATTESTATION_PRIVATE_KEY_PEM"
	x509SANDNSClientIDEnv            = "OID4VP_X509_SANDNS_CLIENT_ID"
	x509SANDNSCertificateChainPEMEnv = "OID4VP_X509_SANDNS_CERT_CHAIN_PEM"
	x509SANDNSPrivateKeyPEMEnv       = "OID4VP_X509_SANDNS_PRIVATE_KEY_PEM"
)

type verifierAttestationIssuer struct {
	issuer        string
	clientID      string
	privateKey    interface{}
	signingMethod jwt.SigningMethod
	publicJWK     intcrypto.JWK
}

type x509RequestSigner struct {
	clientID     string
	certificates []*x509.Certificate
	privateKey   interface{}
}

func (p *Plugin) configureVerifierIdentities() error {
	p.supportedClientIDSchemes = DefaultMVPClientIDSchemeSet()
	if p.keySet == nil {
		p.verifierAttestation = nil
		p.x509SANDNSSigner = nil
		return nil
	}

	attestationIssuer, err := newVerifierAttestationIssuer(p.baseURL)
	if err != nil {
		return err
	}
	p.verifierAttestation = attestationIssuer
	p.supportedClientIDSchemes[ClientIDSchemeVerifierAttestation] = struct{}{}

	x509Signer, err := newX509RequestSigner(p.baseURL)
	if err != nil {
		return err
	}
	p.x509SANDNSSigner = x509Signer
	if x509Signer != nil {
		p.supportedClientIDSchemes[ClientIDSchemeX509SANDNS] = struct{}{}
	}
	return nil
}

func newVerifierAttestationIssuer(baseURL string) (*verifierAttestationIssuer, error) {
	issuer := strings.TrimSpace(os.Getenv(verifierAttestationIssuerEnv))
	if issuer == "" {
		issuer = strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/oid4vp/verifier-attestation"
	}
	parsedIssuer, err := url.Parse(issuer)
	if err != nil || !parsedIssuer.IsAbs() || strings.TrimSpace(parsedIssuer.Host) == "" {
		return nil, fmt.Errorf("verifier attestation issuer %q must be an absolute URL", issuer)
	}
	privateKey, publicJWK, signingMethod, err := resolveVerifierAttestationSigningMaterial(
		strings.TrimSpace(os.Getenv(verifierAttestationPrivateKeyEnv)),
	)
	if err != nil {
		return nil, err
	}
	clientID, err := normalizeConfiguredClientID(
		ClientIDSchemeVerifierAttestation,
		os.Getenv(verifierAttestationClientIDEnv),
		baseURL,
	)
	if err != nil {
		return nil, err
	}
	return &verifierAttestationIssuer{
		issuer:        strings.TrimRight(parsedIssuer.String(), "/"),
		clientID:      clientID,
		privateKey:    privateKey,
		signingMethod: signingMethod,
		publicJWK:     publicJWK,
	}, nil
}

func resolveVerifierAttestationSigningMaterial(rawPrivateKey string) (interface{}, intcrypto.JWK, jwt.SigningMethod, error) {
	if strings.TrimSpace(rawPrivateKey) == "" {
		keySet, err := intcrypto.NewKeySet()
		if err != nil {
			return nil, intcrypto.JWK{}, nil, fmt.Errorf("initialize verifier attestation issuer keyset: %w", err)
		}
		publicJWK, err := jwkFromPublicKey(keySet.ECPublicKey(), keySet.ECKeyID())
		if err != nil {
			return nil, intcrypto.JWK{}, nil, fmt.Errorf("resolve verifier attestation issuer jwk: %w", err)
		}
		return keySet.ECPrivateKey(), publicJWK, jwt.SigningMethodES256, nil
	}

	privateKey, err := parsePEMPrivateKey(rawPrivateKey)
	if err != nil {
		return nil, intcrypto.JWK{}, nil, fmt.Errorf("parse verifier attestation issuer private key: %w", err)
	}
	signingMethod, err := signingMethodForPrivateKey(privateKey)
	if err != nil {
		return nil, intcrypto.JWK{}, nil, fmt.Errorf("resolve verifier attestation signing method: %w", err)
	}
	publicKey, err := publicKeyFromPrivateKey(privateKey)
	if err != nil {
		return nil, intcrypto.JWK{}, nil, fmt.Errorf("resolve verifier attestation public key: %w", err)
	}
	publicJWK, err := jwkFromPublicKey(publicKey, "")
	if err != nil {
		return nil, intcrypto.JWK{}, nil, fmt.Errorf("resolve verifier attestation issuer jwk: %w", err)
	}
	publicJWK.Kid = publicJWK.Thumbprint()
	if strings.TrimSpace(publicJWK.Kid) == "" {
		return nil, intcrypto.JWK{}, nil, fmt.Errorf("resolve verifier attestation issuer kid")
	}
	return privateKey, publicJWK, signingMethod, nil
}

func newX509RequestSigner(baseURL string) (*x509RequestSigner, error) {
	rawCertificateChain := strings.TrimSpace(os.Getenv(x509SANDNSCertificateChainPEMEnv))
	rawPrivateKey := strings.TrimSpace(os.Getenv(x509SANDNSPrivateKeyPEMEnv))

	if rawCertificateChain == "" && rawPrivateKey == "" {
		return newEphemeralX509RequestSigner(baseURL)
	}
	if rawCertificateChain == "" || rawPrivateKey == "" {
		return nil, fmt.Errorf("x509_san_dns signing requires both %s and %s", x509SANDNSCertificateChainPEMEnv, x509SANDNSPrivateKeyPEMEnv)
	}

	clientID, err := normalizeConfiguredClientID(ClientIDSchemeX509SANDNS, os.Getenv(x509SANDNSClientIDEnv), baseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("x509_san_dns signing requires %s or a DNS base URL host", x509SANDNSClientIDEnv)
	}

	certificates, err := parsePEMCertificateChain(rawCertificateChain)
	if err != nil {
		return nil, fmt.Errorf("parse x509_san_dns certificate chain: %w", err)
	}
	privateKey, err := parsePEMPrivateKey(rawPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse x509_san_dns private key: %w", err)
	}
	clientDNSName := stripClientIDSchemePrefixValue(clientID, ClientIDSchemeX509SANDNS)
	if !isDNSNameHost(clientDNSName) {
		return nil, fmt.Errorf("x509_san_dns client_id %q must be a DNS name", clientID)
	}
	if err := certificates[0].VerifyHostname(clientDNSName); err != nil {
		return nil, fmt.Errorf("x509_san_dns certificate SAN does not match client_id %q: %w", clientID, err)
	}
	if err := verifyPrivateKeyMatchesCertificate(certificates[0], privateKey); err != nil {
		return nil, fmt.Errorf("x509_san_dns private key does not match leaf certificate: %w", err)
	}
	log.Printf("[oid4vp] x509_san_dns: using provisioned certificate chain (leaf SAN: %s)", clientDNSName)
	return &x509RequestSigner{
		clientID:     clientID,
		certificates: certificates,
		privateKey:   privateKey,
	}, nil
}

func newEphemeralX509RequestSigner(baseURL string) (*x509RequestSigner, error) {
	hostname := verifierIdentityHostname(baseURL)
	if !isDNSNameHost(hostname) {
		return nil, nil
	}
	clientID := string(ClientIDSchemeX509SANDNS) + ":" + hostname

	certificates, leafKey, err := generateEphemeralX509Chain(hostname)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral x509_san_dns chain: %w", err)
	}
	log.Printf("[oid4vp] x509_san_dns: generated ephemeral certificate chain (leaf SAN: %s, CA: %s, expires: %s)",
		hostname, certificates[1].Subject.CommonName, certificates[0].NotAfter.Format(time.RFC3339))
	return &x509RequestSigner{
		clientID:     clientID,
		certificates: certificates,
		privateKey:   leafKey,
	}, nil
}

func generateEphemeralX509Chain(hostname string) ([]*x509.Certificate, *ecdsa.PrivateKey, error) {
	now := time.Now().UTC()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ProtocolSoup Ephemeral CA", Organization: []string{"ProtocolSoup"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: hostname, Organization: []string{"ProtocolSoup"}},
		DNSNames:              []string{hostname},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf certificate: %w", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	return []*x509.Certificate{leafCert, caCert}, leafKey, nil
}

func (p *Plugin) defaultClientIDForScheme(scheme ClientIDScheme) string {
	switch scheme {
	case ClientIDSchemeVerifierAttestation:
		if p.verifierAttestation != nil {
			return p.verifierAttestation.clientID
		}
	case ClientIDSchemeX509SANDNS:
		if p.x509SANDNSSigner != nil {
			return p.x509SANDNSSigner.clientID
		}
	case ClientIDSchemeRedirectURI:
		return defaultVerifierClientID
	}
	return ""
}

func (p *Plugin) validateVerifierIdentityRequest(scheme ClientIDScheme, clientID string, responseURI string) error {
	switch scheme {
	case ClientIDSchemeRedirectURI:
		// OID4VP Section 5.9.3: for redirect_uri scheme, the client_id value
		// (after prefix) IS the response_uri
		clientValue := stripClientIDSchemePrefixValue(clientID, ClientIDSchemeRedirectURI)
		if clientValue != "" && strings.TrimSpace(responseURI) != "" {
			if clientValue != strings.TrimSpace(responseURI) {
				return fmt.Errorf("response_uri %q must match redirect_uri client_id value %q", responseURI, clientValue)
			}
		}
	case ClientIDSchemeVerifierAttestation:
		if p.verifierAttestation == nil {
			return fmt.Errorf("verifier_attestation is not configured")
		}
		if !strings.EqualFold(strings.TrimSpace(clientID), strings.TrimSpace(p.verifierAttestation.clientID)) {
			return fmt.Errorf("client_id %q does not match configured verifier_attestation profile %q", clientID, p.verifierAttestation.clientID)
		}
	case ClientIDSchemeX509SANDNS:
		if p.x509SANDNSSigner == nil {
			return fmt.Errorf("x509_san_dns is not configured")
		}
		if !strings.EqualFold(strings.TrimSpace(clientID), strings.TrimSpace(p.x509SANDNSSigner.clientID)) {
			return fmt.Errorf("client_id %q does not match configured x509_san_dns profile %q", clientID, p.x509SANDNSSigner.clientID)
		}
		parsedResponseURI, err := url.Parse(strings.TrimSpace(responseURI))
		if err != nil || !parsedResponseURI.IsAbs() {
			return fmt.Errorf("response_uri must be an absolute URL for x509_san_dns")
		}
		clientDNSName := stripClientIDSchemePrefixValue(clientID, ClientIDSchemeX509SANDNS)
		if !strings.EqualFold(strings.TrimSpace(parsedResponseURI.Hostname()), clientDNSName) {
			return fmt.Errorf("response_uri host %q must match x509_san_dns client_id %q", parsedResponseURI.Hostname(), clientDNSName)
		}
	}
	return nil
}

func (p *Plugin) signAuthorizationRequestObject(
	clientIDScheme ClientIDScheme,
	clientID string,
	requestClaims jwt.MapClaims,
	responseURI string,
) (string, error) {
	switch clientIDScheme {
	case ClientIDSchemeVerifierAttestation:
		if p.verifierAttestation == nil {
			return "", fmt.Errorf("verifier_attestation is not configured")
		}
		attestationJWT, err := p.createVerifierAttestationJWT(clientID, responseURI)
		if err != nil {
			return "", err
		}
		requestObject := jwt.NewWithClaims(jwt.SigningMethodES256, requestClaims)
		requestObject.Header["typ"] = "oauth-authz-req+jwt"
		requestObject.Header["kid"] = p.keySet.ECKeyID()
		requestObject.Header["jwt"] = attestationJWT
		if err := ValidateRequestObjectType(fmt.Sprint(requestObject.Header["typ"])); err != nil {
			return "", err
		}
		return requestObject.SignedString(p.keySet.ECPrivateKey())
	case ClientIDSchemeX509SANDNS:
		if p.x509SANDNSSigner == nil {
			return "", fmt.Errorf("x509_san_dns is not configured")
		}
		method, err := signingMethodForPrivateKey(p.x509SANDNSSigner.privateKey)
		if err != nil {
			return "", err
		}
		requestObject := jwt.NewWithClaims(method, requestClaims)
		requestObject.Header["typ"] = "oauth-authz-req+jwt"
		requestObject.Header["x5c"] = p.x509SANDNSSigner.x5cHeader()
		if err := ValidateRequestObjectType(fmt.Sprint(requestObject.Header["typ"])); err != nil {
			return "", err
		}
		return requestObject.SignedString(p.x509SANDNSSigner.privateKey)
	default:
		requestObject := jwt.NewWithClaims(jwt.SigningMethodRS256, requestClaims)
		requestObject.Header["typ"] = "oauth-authz-req+jwt"
		requestObject.Header["kid"] = p.keySet.RSAKeyID()
		if err := ValidateRequestObjectType(fmt.Sprint(requestObject.Header["typ"])); err != nil {
			return "", err
		}
		return requestObject.SignedString(p.keySet.RSAPrivateKey())
	}
}

func (p *Plugin) createVerifierAttestationJWT(clientID string, responseURI string) (string, error) {
	if p.verifierAttestation == nil {
		return "", fmt.Errorf("verifier_attestation is not configured")
	}
	cnfJWK, err := jwkFromPublicKey(p.keySet.ECPublicKey(), p.keySet.ECKeyID())
	if err != nil {
		return "", fmt.Errorf("resolve verifier confirmation key: %w", err)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":           p.verifierAttestation.issuer,
		"sub":           stripClientIDSchemePrefixValue(clientID, ClientIDSchemeVerifierAttestation),
		"cnf":           map[string]interface{}{"jwk": cnfJWK},
		"redirect_uris": []string{strings.TrimSpace(responseURI)},
		"iat":           now.Unix(),
		"exp":           now.Add(requestObjectTTL).Unix(),
		"jti":           p.randomValue(24),
	}
	token := jwt.NewWithClaims(p.verifierAttestation.signingMethod, claims)
	token.Header["typ"] = "verifier-attestation+jwt"
	token.Header["kid"] = p.verifierAttestation.publicJWK.Kid
	return token.SignedString(p.verifierAttestation.privateKey)
}

func (p *Plugin) handleVerifierAttestationOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	_ = r
	if p.verifierAttestation == nil {
		writeOID4VPError(w, http.StatusServiceUnavailable, "server_error", "verifier_attestation is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":                                p.verifierAttestation.issuer,
		"jwks_uri":                              p.verifierAttestation.issuer + "/jwks",
		"response_types_supported":              []string{"vp_token"},
		"vp_formats_supported":                  defaultVPFormatsSupported(),
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
		"request_object_signing_alg_values_supported": []string{"ES256", "RS256", "EdDSA"},
	})
}

func (p *Plugin) handleVerifierAttestationAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	p.handleVerifierAttestationOpenIDConfiguration(w, r)
}

func (p *Plugin) handleVerifierAttestationJWKS(w http.ResponseWriter, r *http.Request) {
	_ = r
	if p.verifierAttestation == nil {
		writeOID4VPError(w, http.StatusServiceUnavailable, "server_error", "verifier_attestation is unavailable")
		return
	}
	if strings.TrimSpace(p.verifierAttestation.publicJWK.Kid) == "" {
		writeOID4VPError(w, http.StatusServiceUnavailable, "server_error", "verifier attestation jwks is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, intcrypto.JWKS{Keys: []intcrypto.JWK{p.verifierAttestation.publicJWK}})
}

func normalizeConfiguredClientID(scheme ClientIDScheme, raw string, baseURL string) (string, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		normalized = defaultOriginalClientID(scheme, baseURL)
	}
	if normalized == "" {
		return "", nil
	}
	if !strings.Contains(normalized, ":") {
		return string(scheme) + ":" + normalized, nil
	}
	parsedScheme, err := ParseClientIDScheme(normalized)
	if err != nil {
		return "", err
	}
	if parsedScheme != scheme {
		return "", fmt.Errorf("client_id %q does not match required scheme %q", normalized, scheme)
	}
	return normalized, nil
}

func defaultOriginalClientID(scheme ClientIDScheme, baseURL string) string {
	host := verifierIdentityHostname(baseURL)
	switch scheme {
	case ClientIDSchemeVerifierAttestation:
		if host != "" {
			return host
		}
		return "protocolsoup-verifier"
	case ClientIDSchemeX509SANDNS:
		if isDNSNameHost(host) {
			return host
		}
	}
	return ""
}

func verifierIdentityHostname(baseURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
}

func parsePEMCertificateChain(raw string) ([]*x509.Certificate, error) {
	pemBytes := []byte(normalizePEMValue(raw))
	certificates := make([]*x509.Certificate, 0, 2)
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}
		pemBytes = rest
		if !strings.Contains(block.Type, "CERTIFICATE") {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("certificate chain PEM did not contain any certificates")
	}
	return certificates, nil
}

func parsePEMPrivateKey(raw string) (interface{}, error) {
	block, _ := pem.Decode([]byte(normalizePEMValue(raw)))
	if block == nil {
		return nil, fmt.Errorf("private key PEM is invalid")
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return parsed, nil
	}
	if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return parsed, nil
	}
	if parsed, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return parsed, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

func verifyPrivateKeyMatchesCertificate(certificate *x509.Certificate, privateKey interface{}) error {
	switch typed := privateKey.(type) {
	case *rsa.PrivateKey:
		publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not RSA")
		}
		if publicKey.E != typed.PublicKey.E || publicKey.N.Cmp(typed.PublicKey.N) != 0 {
			return fmt.Errorf("rsa public key mismatch")
		}
	case *ecdsa.PrivateKey:
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not EC")
		}
		if publicKey.X.Cmp(typed.PublicKey.X) != 0 || publicKey.Y.Cmp(typed.PublicKey.Y) != 0 || publicKey.Curve != typed.PublicKey.Curve {
			return fmt.Errorf("ecdsa public key mismatch")
		}
	case ed25519.PrivateKey:
		publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key is not Ed25519")
		}
		signerPublicKey, _ := typed.Public().(ed25519.PublicKey)
		if !bytes.Equal(publicKey, signerPublicKey) {
			return fmt.Errorf("ed25519 public key mismatch")
		}
	default:
		return fmt.Errorf("unsupported private key type %T", privateKey)
	}
	return nil
}

func signingMethodForPrivateKey(privateKey interface{}) (jwt.SigningMethod, error) {
	switch typed := privateKey.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		switch typed.Curve {
		case elliptic.P256():
			return jwt.SigningMethodES256, nil
		case elliptic.P384():
			return jwt.SigningMethodES384, nil
		case elliptic.P521():
			return jwt.SigningMethodES512, nil
		default:
			return nil, fmt.Errorf("unsupported ecdsa curve")
		}
	case ed25519.PrivateKey:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func publicKeyFromPrivateKey(privateKey interface{}) (interface{}, error) {
	switch typed := privateKey.(type) {
	case *rsa.PrivateKey:
		return &typed.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &typed.PublicKey, nil
	case ed25519.PrivateKey:
		publicKey, ok := typed.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("resolve ed25519 public key")
		}
		return publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privateKey)
	}
}

func jwkFromPublicKey(publicKey interface{}, kid string) (intcrypto.JWK, error) {
	switch typed := publicKey.(type) {
	case *rsa.PublicKey:
		return intcrypto.JWKFromRSAPublicKey(typed, kid), nil
	case *ecdsa.PublicKey:
		return intcrypto.JWKFromECPublicKey(typed, kid), nil
	case ed25519.PublicKey:
		return intcrypto.JWKFromEd25519PublicKey(typed, kid), nil
	default:
		return intcrypto.JWK{}, fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func (p *Plugin) describeX509Chain() map[string]interface{} {
	if p.x509SANDNSSigner == nil || len(p.x509SANDNSSigner.certificates) == 0 {
		return nil
	}
	certs := p.x509SANDNSSigner.certificates
	leaf := certs[0]

	method, _ := signingMethodForPrivateKey(p.x509SANDNSSigner.privateKey)
	sigAlg := "unknown"
	if method != nil {
		sigAlg = method.Alg()
	}

	chain := map[string]interface{}{
		"chain_depth":     len(certs),
		"signing_algorithm": sigAlg,
		"leaf": map[string]interface{}{
			"subject":        leaf.Subject.CommonName,
			"issuer":         leaf.Issuer.CommonName,
			"dns_names":      leaf.DNSNames,
			"serial":         leaf.SerialNumber.String(),
			"not_before":     leaf.NotBefore.Format(time.RFC3339),
			"not_after":      leaf.NotAfter.Format(time.RFC3339),
			"public_key_algorithm": leaf.PublicKeyAlgorithm.String(),
		},
	}
	if len(certs) > 1 {
		root := certs[len(certs)-1]
		chain["root"] = map[string]interface{}{
			"subject":     root.Subject.CommonName,
			"issuer":      root.Issuer.CommonName,
			"self_signed": root.CheckSignatureFrom(root) == nil,
			"not_after":   root.NotAfter.Format(time.RFC3339),
		}
	}
	return chain
}

func (s *x509RequestSigner) x5cHeader() []string {
	values := make([]string, 0, len(s.certificates))
	for _, certificate := range s.certificates {
		if certificate == nil {
			continue
		}
		values = append(values, base64.StdEncoding.EncodeToString(certificate.Raw))
	}
	return values
}

func normalizePEMValue(raw string) string {
	return strings.ReplaceAll(strings.TrimSpace(raw), `\n`, "\n")
}

func stripClientIDSchemePrefixValue(clientID string, scheme ClientIDScheme) string {
	prefix := string(scheme) + ":"
	trimmed := strings.TrimSpace(clientID)
	if strings.HasPrefix(trimmed, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
	}
	return trimmed
}

func isDNSNameHost(host string) bool {
	normalized := strings.TrimSpace(host)
	if normalized == "" {
		return false
	}
	if net.ParseIP(normalized) != nil {
		return false
	}
	return !strings.ContainsAny(normalized, "/:@")
}
