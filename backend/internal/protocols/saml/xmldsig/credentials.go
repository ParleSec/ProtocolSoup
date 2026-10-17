package xmldsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Credentials is one SAML entity's signing key and the self-signed X.509
// certificate published for it in a <md:KeyDescriptor use="signing"> element.
// Trust in the key comes from the metadata that carries the certificate
// (SAML Metadata Section 2.4.1.1), not from a certificate chain, so a
// self-signed certificate is the conventional form.
type Credentials struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

const (
	credentialKeyBits     = 2048
	credentialValidity    = 5 * 365 * 24 * time.Hour
	credentialRenewBefore = 30 * 24 * time.Hour
	credentialFilePerm    = 0o600
)

// LoadOrCreateCredentials returns the entity's key and certificate persisted
// under dir (as <name>.key.pem and <name>.cert.pem), generating and writing
// them on first use or when the stored certificate is about to expire. An
// empty dir yields ephemeral credentials for development and tests.
func LoadOrCreateCredentials(dir, name, entityID string) (*Credentials, error) {
	if dir == "" {
		return NewCredentials(entityID)
	}
	keyPath := filepath.Join(dir, name+".key.pem")
	certPath := filepath.Join(dir, name+".cert.pem")

	creds, err := readCredentials(keyPath, certPath)
	switch {
	case err == nil && time.Until(creds.cert.NotAfter) > credentialRenewBefore:
		return creds, nil
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	}

	creds, err = NewCredentials(entityID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create SAML credential dir %q: %w", dir, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(creds.key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: creds.cert.Raw})
	if err := writeFileAtomic(keyPath, keyPEM); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, certPEM); err != nil {
		return nil, err
	}
	return creds, nil
}

func readCredentials(keyPath, certPath string) (*Credentials, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("SAML key %q is not PEM encoded", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SAML key %q: %w", keyPath, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("SAML certificate %q is not PEM encoded", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SAML certificate %q: %w", certPath, err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("SAML certificate %q does not match key %q", certPath, keyPath)
	}
	return &Credentials{key: key, cert: cert}, nil
}

// NewCredentials generates an ephemeral RSA key and self-signed certificate.
func NewCredentials(entityID string) (*Credentials, error) {
	key, err := rsa.GenerateKey(rand.Reader, credentialKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate SAML signing key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	commonName := entityID
	if parsed, err := url.Parse(entityID); err == nil && parsed.Host != "" {
		commonName = parsed.Host
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"ProtocolSoup"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(credentialValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create SAML signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Credentials{key: key, cert: cert}, nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, credentialFilePerm); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("persist %q: %w", path, err)
	}
	return nil
}

// Certificate is the certificate published in the entity's metadata.
func (c *Credentials) Certificate() *x509.Certificate {
	return c.cert
}
