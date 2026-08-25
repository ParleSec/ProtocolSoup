package oid4vp

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/golang-jwt/jwt/v5"
)

func (p *Plugin) initSDJWTIssuerTrustAnchors() error {
	pemBytes := []byte(strings.TrimSpace(os.Getenv("OID4VP_SD_JWT_TRUST_ANCHOR_PEM")))
	if len(pemBytes) == 0 {
		if path := strings.TrimSpace(os.Getenv("OID4VP_SD_JWT_TRUST_ANCHOR_PEM_FILE")); path != "" {
			loaded, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read OID4VP_SD_JWT_TRUST_ANCHOR_PEM_FILE: %w", err)
			}
			pemBytes = loaded
		}
	}
	if len(pemBytes) == 0 {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("OID4VP SD-JWT trust anchor PEM contains no certificates")
	}
	p.sdJWTIssuerTrustAnchors = pool
	return nil
}

func (p *Plugin) validateSDJWTCredentialStatus(raw interface{}, issuerKeys []crypto.JWK) error {
	status, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("status claim must be an object")
	}
	reference, ok := status["status_list"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("status.status_list is required")
	}
	indexNumber, ok := reference["idx"].(float64)
	if !ok || indexNumber < 0 || indexNumber != float64(int(indexNumber)) {
		return fmt.Errorf("status list idx must be a non-negative integer")
	}
	statusURI, _ := reference["uri"].(string)
	issuerPublicKeys, err := publicKeysFromIssuerJWKs(issuerKeys)
	if err != nil {
		return err
	}
	rawToken, err := p.fetchStatusListToken(statusURI)
	if err != nil {
		return err
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(strings.TrimSpace(string(rawToken)))
	if err != nil {
		return fmt.Errorf("decode status list token: %w", err)
	}
	if decoded.Header["typ"] != "statuslist+jwt" {
		return fmt.Errorf("status list token typ must be statuslist+jwt")
	}
	verifyKey := issuerPublicKeys[0]
	if _, hasX5C := decoded.Header["x5c"]; hasX5C {
		chain, err := crypto.ParseX5CCertificateChain(decoded.Header["x5c"])
		if err != nil {
			return fmt.Errorf("status list x5c: %w", err)
		}
		for _, certificate := range chain {
			if certificate.IsCA && certificate.CheckSignatureFrom(certificate) == nil {
				return fmt.Errorf("status list x5c must exclude the trust anchor")
			}
		}
		// Token Status List §11.3: when the Referenced Token issuer is the
		// Status Issuer, the Status List Token may use the same key (same x5c)
		// already verified on the credential. Do not require a separately
		// configured SD-JWT trust-anchor PEM for that same-issuer case.
		if !issuerKeyMatches(issuerPublicKeys, chain[0].PublicKey) {
			return fmt.Errorf("status list signer does not match the credential issuer key")
		}
		verifyKey = chain[0].PublicKey
	}
	parsed, err := jwt.Parse(strings.TrimSpace(string(rawToken)), func(_ *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil || !parsed.Valid {
		return fmt.Errorf("status list signature is invalid: %w", err)
	}
	if decoded.Payload["sub"] != statusURI {
		return fmt.Errorf("status list token sub does not match its URI")
	}
	list, ok := decoded.Payload["status_list"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("status_list claim is required")
	}
	bitsNumber, ok := list["bits"].(float64)
	if !ok || bitsNumber < 1 || bitsNumber > 8 || bitsNumber != float64(int(bitsNumber)) {
		return fmt.Errorf("status list bits is invalid")
	}
	encoded, _ := list["lst"].(string)
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode status list: %w", err)
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("decompress status list: %w", err)
	}
	defer reader.Close()
	uncompressed, err := io.ReadAll(io.LimitReader(reader, 2*1024*1024))
	if err != nil {
		return fmt.Errorf("read decompressed status list: %w", err)
	}
	bits := int(bitsNumber)
	index := int(indexNumber)
	bitOffset := index * bits
	if bitOffset+bits > len(uncompressed)*8 {
		return fmt.Errorf("status list idx is out of range")
	}
	value := 0
	for bit := 0; bit < bits; bit++ {
		absolute := bitOffset + bit
		value |= int((uncompressed[absolute/8]>>uint(absolute%8))&1) << bit
	}
	if value != 0 {
		return fmt.Errorf("credential status is not valid (value %d)", value)
	}
	return nil
}

func publicKeysFromIssuerJWKs(keys []crypto.JWK) ([]interface{}, error) {
	var publicKeys []interface{}
	for idx := range keys {
		publicKey, err := keys[idx].ToPublicKey()
		if err != nil {
			continue
		}
		publicKeys = append(publicKeys, publicKey)
	}
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("credential issuer key is required to validate status list")
	}
	return publicKeys, nil
}

func issuerKeyMatches(keys []interface{}, candidate interface{}) bool {
	for _, key := range keys {
		if publicKeysEqual(key, candidate) {
			return true
		}
	}
	return false
}

func publicKeysEqual(left, right interface{}) bool {
	switch typed := left.(type) {
	case *ecdsa.PublicKey:
		other, ok := right.(*ecdsa.PublicKey)
		return ok && typed.Equal(other)
	case *rsa.PublicKey:
		other, ok := right.(*rsa.PublicKey)
		return ok && typed.Equal(other)
	default:
		return false
	}
}

func (p *Plugin) fetchStatusListToken(statusURI string) ([]byte, error) {
	fetchURL, own, err := p.statusListFetchURL(statusURI)
	if err != nil {
		return nil, err
	}
	client := externalStatusListHTTPClient()
	if own {
		client = ownStatusListHTTPClient(p)
	}
	request, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build status list request: %w", err)
	}
	request.Header.Set("Accept", "application/statuslist+jwt")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch status list: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status list returned HTTP %d", response.StatusCode)
	}
	rawToken, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read status list: %w", err)
	}
	return rawToken, nil
}

func (p *Plugin) statusListFetchURL(statusURI string) (string, bool, error) {
	if p.isOwnStatusListURI(statusURI) {
		parsed, err := url.Parse(strings.TrimSpace(statusURI))
		if err != nil {
			return "", true, fmt.Errorf("status list URI must be an absolute URL")
		}
		if origin := strings.TrimRight(strings.TrimSpace(os.Getenv("BACKEND_ORIGIN")), "/"); origin != "" {
			return origin + parsed.EscapedPath(), true, nil
		}
		return strings.TrimSpace(statusURI), true, nil
	}
	if err := validateExternalStatusListURI(statusURI); err != nil {
		return "", false, err
	}
	return strings.TrimSpace(statusURI), false, nil
}

func (p *Plugin) isOwnStatusListURI(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return false
	}
	if _, ok := parseStatusListPath(parsed.EscapedPath()); !ok {
		return false
	}
	base, err := url.Parse(strings.TrimSpace(p.baseURL))
	if err != nil || base.Hostname() == "" {
		return false
	}
	return strings.EqualFold(parsed.Hostname(), base.Hostname())
}

func parseStatusListPath(path string) (string, bool) {
	const prefix = "/oid4vci/status-lists/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	listID := strings.Trim(path[len(prefix):], "/")
	if listID == "" || strings.Contains(listID, "/") {
		return "", false
	}
	for _, r := range listID {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return "", false
		}
	}
	return listID, true
}

func ownStatusListHTTPClient(plugin *Plugin) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("status list redirected too many times")
			}
			if plugin == nil || !plugin.isOwnStatusListURI(request.URL.String()) {
				return fmt.Errorf("status list redirect is not this issuer's status list")
			}
			return nil
		},
	}
}

func validateExternalStatusListURI(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("status list URI must be an absolute HTTPS URL without userinfo")
	}
	return validateExternalStatusListHost(parsed.Hostname())
}

func validateExternalStatusListHost(host string) error {
	addresses, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("status list host could not be resolved")
	}
	for _, address := range addresses {
		value, ok := netip.AddrFromSlice(address)
		if !ok {
			continue
		}
		value = value.Unmap()
		if value.IsLoopback() || value.IsPrivate() || value.IsLinkLocalUnicast() || value.IsLinkLocalMulticast() || value.IsMulticast() || value.IsUnspecified() {
			return fmt.Errorf("status list URI must not target private or local addresses")
		}
	}
	return nil
}

func externalStatusListHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid status list network address")
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(addresses) == 0 {
				return nil, fmt.Errorf("status list host could not be resolved")
			}
			for _, address := range addresses {
				value := address.Unmap()
				if value.IsLoopback() || value.IsPrivate() || value.IsLinkLocalUnicast() || value.IsLinkLocalMulticast() || value.IsMulticast() || value.IsUnspecified() {
					continue
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(value.String(), port))
			}
			return nil, fmt.Errorf("status list host resolved only to private or local addresses")
		},
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			return validateExternalStatusListURI(request.URL.String())
		},
	}
}

func (p *Plugin) externalSDJWTIssuerJWK(rawCredential string) (crypto.JWK, error) {
	if p.sdJWTIssuerTrustAnchors == nil {
		return crypto.JWK{}, fmt.Errorf("no external SD-JWT issuer trust anchor is configured")
	}
	envelope, err := vc.ParseSDJWTEnvelope(rawCredential)
	if err != nil {
		return crypto.JWK{}, fmt.Errorf("parse SD-JWT: %w", err)
	}
	decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
	if err != nil {
		return crypto.JWK{}, fmt.Errorf("decode issuer JWT: %w", err)
	}
	chain, err := crypto.ParseX5CCertificateChain(decoded.Header["x5c"])
	if err != nil {
		return crypto.JWK{}, fmt.Errorf("issuer x5c: %w", err)
	}
	if len(chain) == 0 {
		return crypto.JWK{}, fmt.Errorf("issuer x5c is empty")
	}
	for _, certificate := range chain {
		if certificate.IsCA && certificate.CheckSignatureFrom(certificate) == nil {
			return crypto.JWK{}, fmt.Errorf("issuer x5c must exclude the trust anchor")
		}
	}
	leaf, err := crypto.ValidateCertificateChainAgainstRoots(chain, p.sdJWTIssuerTrustAnchors, time.Now().UTC())
	if err != nil {
		return crypto.JWK{}, fmt.Errorf("issuer x5c chain is untrusted: %w", err)
	}
	switch publicKey := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return crypto.JWKFromECPublicKey(publicKey, ""), nil
	case *rsa.PublicKey:
		return crypto.JWKFromRSAPublicKey(publicKey, ""), nil
	default:
		return crypto.JWK{}, fmt.Errorf("issuer certificate key type %T is unsupported", leaf.PublicKey)
	}
}
