package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ISO/IEC 18013-5 Annex B certificate-profile object identifiers and validity
// caps. These are not generic PKIX values: a conforming mdoc verifier rejects a
// document-signer certificate that is missing the mDL DS extended key usage or
// that exceeds the profile validity, even when the certificate is otherwise a
// valid X.509 path.
var (
	// OIDExtKeyUsageMDLDS is the extended key usage reserved for the mDL
	// document signer (ISO/IEC 18013-5 clause B.1.1.3, Table B.3): 1.0.18013.5.1.2.
	OIDExtKeyUsageMDLDS = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}

	// oidIssuerAltName is the X.509 issuerAltName extension (RFC 5280 Section
	// 4.2.1.7), mandatory in the IACA and DS profiles (Tables B.1 and B.3).
	oidIssuerAltName = asn1.ObjectIdentifier{2, 5, 29, 18}
)

const (
	// iacaMaxValidity is the IACA root certificate validity cap (ISO/IEC
	// 18013-5 Table B.1: "Not After ... Maximum of 15 years after Not Before").
	iacaMaxValidity = 15*365*24*time.Hour + 4*24*time.Hour // ~15 years incl. leap days

	// dsMaxValidity is the mDL document signer certificate validity cap
	// (ISO/IEC 18013-5 Table B.3: "Not After ... Maximum of 15 months after
	// Not Before").
	dsMaxValidity = 457 * 24 * time.Hour // ~15 months

	// pkiStoreFile is the on-disk name for the persisted issuer PKI bundle.
	pkiStoreFile = "mdoc_issuer_pki.json"

	// iacaRootFile is a standalone copy of the IACA root certificate, written
	// so a verifier can be configured to trust it without parsing the
	// full bundle.
	iacaRootFile = "iaca_root.pem"
)

// PKIParams configures generation of the issuer PKI. The country and
// organisation flow into the certificate subjects, which ISO/IEC 18013-5
// Tables B.1 and B.3 require (countryName and organizationName are mandatory).
type PKIParams struct {
	// Country is the ISO 3166-1 alpha-2 code of the issuing country, upper
	// case (Table B.1 / B.3, countryName).
	Country string
	// Organization is the issuing authority organisation name (mandatory).
	Organization string
	// IACACommonName is the IACA root subject common name.
	IACACommonName string
	// DSCommonName is the document signer subject common name. It must differ
	// from the IACA common name.
	DSCommonName string
	// IACAValidity is the IACA root lifetime (capped at 15 years).
	IACAValidity time.Duration
	// DSValidity is the document signer lifetime (capped at 15 months).
	DSValidity time.Duration
	// CRLDistribution is the HTTP CRL distribution point URI, mandatory in
	// both profiles (Table B.1 / B.3, CRLDistributionPoints).
	CRLDistribution string
	// IssuerAltNameURI is the issuer contact URI carried in issuerAltName,
	// mandatory in both profiles (Table B.1 / B.3, IssuerAltName).
	IssuerAltNameURI string
}

// DefaultPKIParams returns sensible Annex B-conformant defaults derived from the
// issuer identifier. Validity periods are set comfortably inside the profile
// caps. Country and organisation are demo defaults the caller may override.
func DefaultPKIParams(issuerID string) PKIParams {
	base := strings.TrimRight(strings.TrimSpace(issuerID), "/")
	if base == "" {
		base = "https://issuer.protocolsoup.example"
	}
	return PKIParams{
		Country:          "US",
		Organization:     "ProtocolSoup",
		IACACommonName:   "ProtocolSoup mDL IACA Root",
		DSCommonName:     "ProtocolSoup mDL Document Signer",
		IACAValidity:     10 * 365 * 24 * time.Hour,
		DSValidity:       365 * 24 * time.Hour,
		CRLDistribution:  base + "/crl/mdl-iaca.crl",
		IssuerAltNameURI: base,
	}
}

func (p PKIParams) validate() error {
	country := strings.TrimSpace(p.Country)
	if len(country) != 2 {
		return fmt.Errorf("mdoc: PKI country must be an ISO 3166-1 alpha-2 code, got %q", p.Country)
	}
	if strings.TrimSpace(p.Organization) == "" {
		return errors.New("mdoc: PKI organization is required (Table B.1 / B.3 organizationName)")
	}
	if strings.TrimSpace(p.IACACommonName) == "" || strings.TrimSpace(p.DSCommonName) == "" {
		return errors.New("mdoc: PKI common names are required")
	}
	if strings.EqualFold(strings.TrimSpace(p.IACACommonName), strings.TrimSpace(p.DSCommonName)) {
		return errors.New("mdoc: DS common name must differ from the IACA common name")
	}
	if p.IACAValidity <= 0 || p.IACAValidity > iacaMaxValidity {
		return fmt.Errorf("mdoc: IACA validity %s exceeds the 15-year Annex B cap", p.IACAValidity)
	}
	if p.DSValidity <= 0 || p.DSValidity > dsMaxValidity {
		return fmt.Errorf("mdoc: DS validity %s exceeds the 15-month Annex B cap", p.DSValidity)
	}
	if p.DSValidity > p.IACAValidity {
		return errors.New("mdoc: DS validity must not exceed IACA validity")
	}
	if strings.TrimSpace(p.CRLDistribution) == "" {
		return errors.New("mdoc: CRL distribution point is required (Table B.1 / B.3)")
	}
	if strings.TrimSpace(p.IssuerAltNameURI) == "" {
		return errors.New("mdoc: issuerAltName URI is required (Table B.1 / B.3)")
	}
	return nil
}

// IssuerPKI holds the persistent IACA root and the document signer chained to
// it. The document-signer private key signs IssuerAuth; the document-signer
// certificate (leaf only, the IACA root is the verifier's trust anchor and is
// excluded) is carried in the COSE x5chain.
type IssuerPKI struct {
	iacaCert  *x509.Certificate
	iacaKey   *ecdsa.PrivateKey
	dsCert    *x509.Certificate
	dsKey     *ecdsa.PrivateKey
	createdAt time.Time
}

// DocumentSignerKey returns the document-signer private key used to sign
// IssuerAuth (COSE_Sign1).
func (p *IssuerPKI) DocumentSignerKey() *ecdsa.PrivateKey { return p.dsKey }

// DocumentSignerChain returns the x5chain to embed in IssuerAuth: the document
// signer certificate leaf-first, excluding the IACA root (ISO/IEC 18013-5
// clause 9.1.2.4 / RFC 9360 Section 2 -- the trust anchor is configured at the
// verifier, not carried in the chain).
func (p *IssuerPKI) DocumentSignerChain() []*x509.Certificate {
	return []*x509.Certificate{p.dsCert}
}

// IACACertificate returns the IACA root certificate (the verifier trust anchor).
func (p *IssuerPKI) IACACertificate() *x509.Certificate { return p.iacaCert }

// DocumentSignerCertificate returns the document signer leaf certificate.
func (p *IssuerPKI) DocumentSignerCertificate() *x509.Certificate { return p.dsCert }

// TrustAnchors returns a certificate pool containing the IACA root, suitable
// for VerifyIssuerSigned.
func (p *IssuerPKI) TrustAnchors() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.iacaCert)
	return pool
}

// Country returns the issuing country code from the IACA subject.
func (p *IssuerPKI) Country() string {
	if len(p.iacaCert.Subject.Country) > 0 {
		return p.iacaCert.Subject.Country[0]
	}
	return ""
}

// Organization returns the issuing organisation from the IACA subject.
func (p *IssuerPKI) Organization() string {
	if len(p.iacaCert.Subject.Organization) > 0 {
		return p.iacaCert.Subject.Organization[0]
	}
	return ""
}

// IACARootPEM returns the IACA root certificate PEM, the value a verifier loads
// as its configured mdoc trust anchor.
func (p *IssuerPKI) IACARootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.iacaCert.Raw})
}

// GenerateIssuerPKI builds a fresh IACA root and a document signer chained to
// it, both conforming to the ISO/IEC 18013-5 Annex B certificate profile.
func GenerateIssuerPKI(params PKIParams) (*IssuerPKI, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mdoc: generate IACA key: %w", err)
	}
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mdoc: generate DS key: %w", err)
	}

	iacaCert, err := buildIACACertificate(params, iacaKey, now)
	if err != nil {
		return nil, err
	}
	dsCert, err := buildDocumentSignerCertificate(params, iacaCert, iacaKey, &dsKey.PublicKey, now)
	if err != nil {
		return nil, err
	}

	return &IssuerPKI{
		iacaCert:  iacaCert,
		iacaKey:   iacaKey,
		dsCert:    dsCert,
		dsKey:     dsKey,
		createdAt: now,
	}, nil
}

// LoadOrCreateIssuerPKI returns the issuer PKI persisted under dir. On first run
// it generates and writes the IACA and DS material; on subsequent runs it loads
// the same keys and certificates so the trust anchor and signing key remain
// stable across restarts (device binding and verifier trust depend on this). An
// empty dir yields an ephemeral in-memory PKI (development and tests only).
func LoadOrCreateIssuerPKI(dir string, params PKIParams) (*IssuerPKI, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return GenerateIssuerPKI(params)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mdoc: create PKI store dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, pkiStoreFile)
	if _, statErr := os.Stat(path); statErr == nil {
		pki, loadErr := loadIssuerPKI(path)
		if loadErr != nil {
			return nil, fmt.Errorf("mdoc: load PKI from %q: %w", path, loadErr)
		}
		return pki, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("mdoc: stat PKI store %q: %w", path, statErr)
	}

	pki, err := GenerateIssuerPKI(params)
	if err != nil {
		return nil, err
	}
	if err := pki.persist(dir); err != nil {
		return nil, fmt.Errorf("mdoc: persist new PKI to %q: %w", dir, err)
	}
	return pki, nil
}

// buildIACACertificate builds the self-signed IACA root per ISO/IEC 18013-5
// Table B.1 (clause B.1.1.2.1).
func buildIACACertificate(params PKIParams, key *ecdsa.PrivateKey, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	skid, err := subjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	ianExt, err := issuerAltNameExtension(params.IssuerAltNameURI)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:      []string{strings.ToUpper(strings.TrimSpace(params.Country))},
			Organization: []string{params.Organization},
			CommonName:   params.IACACommonName,
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(params.IACAValidity),
		// Table B.1 Key Usage (critical): keyCertSign and cRLSign only.
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true, // pathLenConstraint = 0
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		SubjectKeyId:          skid,
		CRLDistributionPoints: []string{params.CRLDistribution},
		ExtraExtensions:       []pkix.Extension{ianExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("mdoc: create IACA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mdoc: parse IACA certificate: %w", err)
	}
	return cert, nil
}

// buildDocumentSignerCertificate builds the mDL document signer leaf signed by
// the IACA per ISO/IEC 18013-5 Table B.3 (clause B.1.1.3).
func buildDocumentSignerCertificate(params PKIParams, iaca *x509.Certificate, iacaKey *ecdsa.PrivateKey, dsPub *ecdsa.PublicKey, now time.Time) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	skid, err := subjectKeyID(dsPub)
	if err != nil {
		return nil, err
	}
	ianExt, err := issuerAltNameExtension(params.IssuerAltNameURI)
	if err != nil {
		return nil, err
	}

	notAfter := now.Add(params.DSValidity)
	if notAfter.After(iaca.NotAfter) {
		notAfter = iaca.NotAfter // DS must not outlive the IACA (Table B.3 note).
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:      []string{strings.ToUpper(strings.TrimSpace(params.Country))},
			Organization: []string{params.Organization},
			CommonName:   params.DSCommonName,
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  notAfter,
		// Table B.3 Key Usage (critical): digitalSignature only.
		KeyUsage: x509.KeyUsageDigitalSignature,
		// Table B.3 Extended key usage (mandatory): mDL document signer OID.
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{OIDExtKeyUsageMDLDS},
		BasicConstraintsValid: true,
		IsCA:                  false, // Table B.3 Basic Constraints: CA = FALSE.
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		SubjectKeyId:          skid,
		AuthorityKeyId:        iaca.SubjectKeyId,
		CRLDistributionPoints: []string{params.CRLDistribution},
		ExtraExtensions:       []pkix.Extension{ianExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, iaca, dsPub, iacaKey)
	if err != nil {
		return nil, fmt.Errorf("mdoc: create DS certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mdoc: parse DS certificate: %w", err)
	}
	return cert, nil
}

// randomSerial returns a 128-bit positive serial. ISO/IEC 18013-5 Table B.1 /
// B.3 require a non-sequential positive non-zero integer with at least 63 bits
// of CSPRNG output and at most 20 octets.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mdoc: generate certificate serial: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// subjectKeyID computes a 160-bit key identifier from the subjectPublicKey BIT
// STRING using the RFC 7093 Section 2 method 1 derivation (the leftmost 160 bits
// of SHA-256), which RFC 5280 Section 4.2.1.2 permits as a SubjectKeyIdentifier
// generation method and which Tables B.1 and B.3 mandate be present. IACA SKI
// and DS authorityKeyIdentifier are derived by this same function, so chain
// matching stays consistent.
func subjectKeyID(pub *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("mdoc: marshal public key for SKI: %w", err)
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("mdoc: parse subjectPublicKeyInfo for SKI: %w", err)
	}
	sum := sha256.Sum256(spki.SubjectPublicKey.Bytes)
	return sum[:20], nil
}

// issuerAltNameExtension builds the non-critical issuerAltName extension (RFC
// 5280 Section 4.2.1.7) carrying a single uniformResourceIdentifier GeneralName,
// as required by ISO/IEC 18013-5 Tables B.1 and B.3.
func issuerAltNameExtension(uri string) (pkix.Extension, error) {
	// GeneralName CHOICE uniformResourceIdentifier [6] IA5String.
	uriName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)}
	value, err := asn1.Marshal([]asn1.RawValue{uriName}) // GeneralNames ::= SEQUENCE OF GeneralName
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("mdoc: encode issuerAltName: %w", err)
	}
	return pkix.Extension{Id: oidIssuerAltName, Critical: false, Value: value}, nil
}

// persistedIssuerPKI is the JSON serialisation of the issuer PKI. Private keys
// are PEM-encoded SEC1 (EC PRIVATE KEY); certificates are PEM CERTIFICATE.
type persistedIssuerPKI struct {
	IACACertPEM string    `json:"iaca_cert_pem"`
	IACAKeyPEM  string    `json:"iaca_key_pem"`
	DSCertPEM   string    `json:"ds_cert_pem"`
	DSKeyPEM    string    `json:"ds_key_pem"`
	CreatedAt   time.Time `json:"created_at"`
}

func (p *IssuerPKI) persist(dir string) error {
	iacaKeyPEM, err := encodeECPrivatePEM(p.iacaKey)
	if err != nil {
		return err
	}
	dsKeyPEM, err := encodeECPrivatePEM(p.dsKey)
	if err != nil {
		return err
	}
	persisted := persistedIssuerPKI{
		IACACertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.iacaCert.Raw})),
		IACAKeyPEM:  iacaKeyPEM,
		DSCertPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.dsCert.Raw})),
		DSKeyPEM:    dsKeyPEM,
		CreatedAt:   p.createdAt,
	}
	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, pkiStoreFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Write a standalone IACA root PEM so a verifier can be configured to trust
	// it directly as a trust anchor. Best effort; the bundle is canonical.
	_ = os.WriteFile(filepath.Join(dir, iacaRootFile), p.IACARootPEM(), 0o600)
	return nil
}

func loadIssuerPKI(path string) (*IssuerPKI, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var persisted persistedIssuerPKI
	if err := json.Unmarshal(raw, &persisted); err != nil {
		return nil, fmt.Errorf("invalid PKI store JSON: %w", err)
	}
	iacaCert, err := parseCertPEM(persisted.IACACertPEM)
	if err != nil {
		return nil, fmt.Errorf("iaca cert: %w", err)
	}
	iacaKey, err := parseECPrivatePEM(persisted.IACAKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("iaca key: %w", err)
	}
	dsCert, err := parseCertPEM(persisted.DSCertPEM)
	if err != nil {
		return nil, fmt.Errorf("ds cert: %w", err)
	}
	dsKey, err := parseECPrivatePEM(persisted.DSKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("ds key: %w", err)
	}
	createdAt := persisted.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	return &IssuerPKI{
		iacaCert:  iacaCert,
		iacaKey:   iacaKey,
		dsCert:    dsCert,
		dsKey:     dsKey,
		createdAt: createdAt,
	}, nil
}

func encodeECPrivatePEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("mdoc: marshal EC private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}

func parseECPrivatePEM(encoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return key, nil
}

func parseCertPEM(encoded string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// TrustAnchorsFromPEM builds a certificate pool from one or more PEM-encoded
// certificates. A verifier uses this to load a configured IACA root as its mdoc
// trust anchor.
func TrustAnchorsFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("mdoc: no certificates found in trust anchor PEM")
	}
	return pool, nil
}

// TrustAnchorCertificatesFromPEM parses one or more PEM-encoded certificates
// into their X.509 form. A verifier uses this alongside TrustAnchorsFromPEM to
// retain the parsed IACA root(s), so it can read each root's
// SubjectKeyIdentifier for the OID4VP DCQL Authority Key Identifier Trusted
// Authorities Query (HAIP 1.0 Section 5). The DS certificate's
// AuthorityKeyIdentifier equals the IACA root's SubjectKeyIdentifier
// (RFC 5280 Section 4.2.1.1), so the root SKI is the AKI value to advertise.
func TrustAnchorCertificatesFromPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0, 1)
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mdoc: parse trust anchor certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("mdoc: no certificates found in trust anchor PEM")
	}
	return certs, nil
}
