package lookingglass

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"strconv"
	"unicode/utf8"
)

// EncodePayload wraps captured bytes for a CapturedExchange. Valid UTF-8 is
// kept as text and anything else is base64, so binary bodies survive JSON.
// total is the full size seen on the wire; truncated says data holds less.
func EncodePayload(data []byte, total int64, truncated bool, contentType string) *CapturedPayload {
	encoding := "utf-8"
	encoded := string(data)
	if !utf8.Valid(data) {
		encoding = "base64"
		encoded = base64.StdEncoding.EncodeToString(data)
	}
	return &CapturedPayload{
		Encoding:    encoding,
		Data:        encoded,
		Size:        total,
		Truncated:   truncated,
		ContentType: contentType,
	}
}

// RawRequest rebuilds an HTTP/1.x request message from its parts. Header order
// is not preserved, which CaptureMeta.HeaderOrderPreserved records.
func RawRequest(method, requestURI, proto string, headers map[string][]string, body []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(method)
	buf.WriteString(" ")
	buf.WriteString(requestURI)
	buf.WriteString(" ")
	buf.WriteString(proto)
	buf.WriteString("\r\n")
	if err := http.Header(headers).Write(&buf); err != nil {
		return buf.Bytes()
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// RawResponse rebuilds an HTTP/1.x response message from its parts.
func RawResponse(proto string, status int, statusText string, headers map[string][]string, body []byte) []byte {
	if statusText == "" {
		statusText = http.StatusText(status)
	}
	var buf bytes.Buffer
	buf.WriteString(proto)
	buf.WriteString(" ")
	buf.WriteString(strconv.Itoa(status))
	buf.WriteString(" ")
	buf.WriteString(statusText)
	buf.WriteString("\r\n")
	if err := http.Header(headers).Write(&buf); err != nil {
		return buf.Bytes()
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// CertificateInfoFromX509 summarises a certificate for display.
func CertificateInfoFromX509(cert *x509.Certificate) *CertificateInfo {
	if cert == nil {
		return nil
	}

	thumbprint := ""
	if len(cert.Raw) > 0 {
		sum := sha256.Sum256(cert.Raw)
		thumbprint = base64.RawURLEncoding.EncodeToString(sum[:])
	}

	spiffeID := ""
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		if uri.Scheme == "spiffe" {
			spiffeID = uri.String()
			break
		}
	}

	return &CertificateInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SPIFFEID:     spiffeID,
		Thumbprint:   thumbprint,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: cert.SerialNumber.String(),
	}
}

// OutboundTLSInfo describes a TLS session this process opened as a client:
// the server's chain from the handshake and, for mTLS, the client
// certificates it presented.
func OutboundTLSInfo(state *tls.ConnectionState, clientCerts []*x509.Certificate) *TLSInfo {
	if state == nil {
		return nil
	}
	version := tls.VersionName(state.Version)
	if version == "" {
		version = "0x" + strconv.FormatUint(uint64(state.Version), 16)
	}
	cipher := tls.CipherSuiteName(state.CipherSuite)
	if cipher == "" {
		cipher = "0x" + strconv.FormatUint(uint64(state.CipherSuite), 16)
	}

	peerCerts := make([]string, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		if cert == nil {
			continue
		}
		peerCerts = append(peerCerts, cert.Subject.String())
	}

	verifiedChainLength := 0
	serverChain := state.PeerCertificates
	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 0 {
		serverChain = state.VerifiedChains[0]
		verifiedChainLength = len(state.VerifiedChains[0])
	}

	var serverCert *CertificateInfo
	serverChainInfo := make([]CertificateInfo, 0, len(serverChain))
	for _, cert := range serverChain {
		info := CertificateInfoFromX509(cert)
		if info == nil {
			continue
		}
		if serverCert == nil {
			serverCert = info
		}
		serverChainInfo = append(serverChainInfo, *info)
	}

	var clientCert *CertificateInfo
	clientChainInfo := make([]CertificateInfo, 0, len(clientCerts))
	for _, cert := range clientCerts {
		info := CertificateInfoFromX509(cert)
		if info == nil {
			continue
		}
		if clientCert == nil {
			clientCert = info
		}
		clientChainInfo = append(clientChainInfo, *info)
	}

	return &TLSInfo{
		Version:             version,
		CipherSuite:         cipher,
		ServerName:          state.ServerName,
		NegotiatedProtocol:  state.NegotiatedProtocol,
		PeerCertificates:    peerCerts,
		ClientCert:          clientCert,
		ServerCert:          serverCert,
		ClientChain:         clientChainInfo,
		ServerChain:         serverChainInfo,
		MutualTLS:           clientCert != nil && serverCert != nil,
		VerifiedChainLength: verifiedChainLength,
		Source:              "outbound",
	}
}
