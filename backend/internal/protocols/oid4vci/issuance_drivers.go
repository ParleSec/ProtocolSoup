package oid4vci

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"sort"
	"strings"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// msoValidity is the MSO validity window (the credential refresh period),
	// kept well inside the document signer certificate lifetime.
	msoValidity = 180 * 24 * time.Hour
	// mdlLicenceValidity is the mDL expiry_date horizon (the licence's own
	// validity, distinct from the MSO refresh window).
	mdlLicenceValidity = 5 * 365 * 24 * time.Hour
	// jwtCredentialLifetime is the lifetime of JWT/SD-JWT credentials measured
	// from the rounded issuance instant. Day-rounding (RFC 9901 §10.1) makes
	// a short wall-clock TTL unsafe, so this is at least one quantization
	// period.
	jwtCredentialLifetime = 24 * time.Hour
	// credentialTimeRounding is the RFC 9901 Section 10.1 quantization for
	// issuance time claims (iat/nbf/exp and mdoc validityInfo). Rounding to
	// the start of the UTC day prevents same-dataset credentials issued
	// seconds apart from embedding the precise inter-issuance gap.
	credentialTimeRounding = 24 * time.Hour
)

// roundCredentialIssuanceTime returns the RFC 9901 §10.1-rounded issuance
// instant for credential time claims: the start of the UTC day containing now.
func roundCredentialIssuanceTime(now time.Time) time.Time {
	return now.UTC().Truncate(credentialTimeRounding)
}

type issuedCredential struct {
	Format          string
	Credential      interface{}
	CredentialJWT   string
	IssuerSignedJWT string
	CredentialID    string
	VCT             string
	Doctype         string
	CredentialTypes []string
	Issuer          string
	IssuerJWK       crypto.JWK
}

type credentialIssuerDriver interface {
	IssueCredential(subject string, configuration credentialConfiguration, wallet *walletIdentity, holderJWK *crypto.JWK) (*issuedCredential, error)
}

type sdJWTCredentialIssuerDriver struct {
	plugin *Plugin
}

type jwtVCCredentialIssuerDriver struct {
	plugin *Plugin
}

type jwtVCJSONLDCredentialIssuerDriver struct {
	plugin *Plugin
}

type ldpVCCredentialIssuerDriver struct {
	plugin *Plugin
}

type msoMdocCredentialIssuerDriver struct {
	plugin *Plugin
}

func (p *Plugin) issueCredential(subject string, configurationID string, wallet *walletIdentity, holderJWK *crypto.JWK) (*issuedCredential, error) {
	if p == nil {
		return nil, fmt.Errorf("plugin is unavailable")
	}
	configurationID = strings.TrimSpace(configurationID)
	if configurationID == "" {
		configurationID = defaultCredentialConfigurationID
	}
	configuration, ok := p.credentialConfigurations[configurationID]
	if !ok {
		return nil, fmt.Errorf("unsupported credential_configuration_id %q", configurationID)
	}
	driver, ok := p.issuerDrivers[configuration.Format]
	if !ok {
		return nil, fmt.Errorf("unsupported format %q", configuration.Format)
	}
	issued, err := driver.IssueCredential(subject, configuration, wallet, holderJWK)
	if err != nil {
		return nil, err
	}
	if issued != nil {
		issued.Format = strings.TrimSpace(configuration.Format)
		if strings.TrimSpace(issued.VCT) == "" {
			issued.VCT = strings.TrimSpace(configuration.VCT)
		}
		if strings.TrimSpace(issued.Doctype) == "" {
			issued.Doctype = strings.TrimSpace(configuration.Doctype)
		}
		if len(issued.CredentialTypes) == 0 {
			issued.CredentialTypes = append([]string{}, configuration.CredentialTypes...)
		}
	}
	return issued, nil
}

func (d *sdJWTCredentialIssuerDriver) IssueCredential(subject string, configuration credentialConfiguration, wallet *walletIdentity, holderJWK *crypto.JWK) (*issuedCredential, error) {
	if d == nil || d.plugin == nil {
		return nil, fmt.Errorf("sd-jwt credential issuer driver is unavailable")
	}
	if d.plugin.keySet == nil {
		return nil, fmt.Errorf("keyset is unavailable")
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet context is required")
	}
	now := time.Now().UTC()
	issuedAt := roundCredentialIssuanceTime(now)
	selectiveClaims := walletSelectiveClaims(wallet)
	claimNames := make([]string, 0, len(selectiveClaims))
	for claimName := range selectiveClaims {
		claimNames = append(claimNames, claimName)
	}
	sort.Strings(claimNames)
	disclosureDigests := make([]string, 0, len(claimNames))
	disclosureSegments := make([]string, 0, len(claimNames))
	for _, claimName := range claimNames {
		disclosure, err := vc.CreateSDJWTDisclosure(claimName, selectiveClaims[claimName], "")
		if err != nil {
			return nil, fmt.Errorf("create sd-jwt disclosure for %q: %w", claimName, err)
		}
		disclosureDigests = append(disclosureDigests, disclosure.Digest)
		disclosureSegments = append(disclosureSegments, disclosure.Encoded)
	}

	credentialID := d.plugin.randomValue(24)
	claims := jwt.MapClaims{
		"_sd_alg": "sha-256",
		"_sd":     disclosureDigests,
		"iss":     nowIssuer(d.plugin.issuerID()),
		"sub":     subject,
		"iat":     issuedAt.Unix(),
		"nbf":     issuedAt.Unix(),
		"exp":     issuedAt.Add(jwtCredentialLifetime).Unix(),
		"jti":     credentialID,
		"vct":     configuration.VCT,
	}
	if configuration.UseX509CredentialSigner {
		statusListIndex, err := d.plugin.allocateStatusListIndex()
		if err != nil {
			return nil, err
		}
		claims["status"] = map[string]interface{}{
			"status_list": map[string]interface{}{
				"idx": statusListIndex,
				"uri": d.plugin.statusListURI(),
			},
		}
	}
	if holderJWK != nil && strings.TrimSpace(holderJWK.Kty) != "" {
		claims["cnf"] = map[string]interface{}{
			"jwk": *holderJWK,
		}
	}

	var (
		issuerSignedJWT string
		issuerJWK       crypto.JWK
		err             error
	)
	if configuration.UseX509CredentialSigner {
		if d.plugin.mdocPKI == nil || d.plugin.mdocPKI.DocumentSignerKey() == nil {
			return nil, fmt.Errorf("certificate-backed credential signer is unavailable")
		}
		signerKey := d.plugin.mdocPKI.DocumentSignerKey()
		chain := d.plugin.mdocPKI.DocumentSignerChain()
		if len(chain) == 0 || chain[0] == nil {
			return nil, fmt.Errorf("certificate-backed credential signer chain is unavailable")
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["typ"] = "dc+sd-jwt"
		x5c := make([]string, 0, len(chain))
		for _, certificate := range chain {
			if certificate == nil {
				return nil, fmt.Errorf("certificate-backed credential signer chain contains an empty certificate")
			}
			x5c = append(x5c, base64.StdEncoding.EncodeToString(certificate.Raw))
		}
		token.Header["x5c"] = x5c
		issuerSignedJWT, err = token.SignedString(signerKey)
		if err != nil {
			return nil, err
		}
		issuerJWK = crypto.JWKFromECPublicKey(&signerKey.PublicKey, "")
	} else {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["typ"] = "dc+sd-jwt"
		token.Header["kid"] = d.plugin.keySet.RSAKeyID()
		issuerSignedJWT, err = token.SignedString(d.plugin.keySet.RSAPrivateKey())
		if err != nil {
			return nil, err
		}
		var ok bool
		issuerJWK, ok = d.plugin.keySet.GetJWKByID(d.plugin.keySet.RSAKeyID())
		if !ok {
			return nil, fmt.Errorf("issuer rsa jwk is unavailable")
		}
	}

	serialized := vc.BuildSDJWTSerialization(issuerSignedJWT, disclosureSegments, "")
	return &issuedCredential{
		Format:          configuration.Format,
		Credential:      serialized,
		CredentialJWT:   serialized,
		IssuerSignedJWT: issuerSignedJWT,
		CredentialID:    credentialID,
		VCT:             configuration.VCT,
		CredentialTypes: credentialTypes(configuration),
		Issuer:          d.plugin.issuerID(),
		IssuerJWK:       issuerJWK,
	}, nil
}

func (d *jwtVCCredentialIssuerDriver) IssueCredential(subject string, configuration credentialConfiguration, wallet *walletIdentity, _ *crypto.JWK) (*issuedCredential, error) {
	return issueJWTBackedCredential(d.plugin, "vc+jwt", subject, configuration, wallet, false, false)
}

func (d *jwtVCJSONLDCredentialIssuerDriver) IssueCredential(subject string, configuration credentialConfiguration, wallet *walletIdentity, _ *crypto.JWK) (*issuedCredential, error) {
	return issueJWTBackedCredential(d.plugin, "vc+jwt", subject, configuration, wallet, true, false)
}

func (d *ldpVCCredentialIssuerDriver) IssueCredential(subject string, configuration credentialConfiguration, wallet *walletIdentity, _ *crypto.JWK) (*issuedCredential, error) {
	if d == nil || d.plugin == nil {
		return nil, fmt.Errorf("ldp_vc credential issuer driver is unavailable")
	}
	if d.plugin.keySet == nil {
		return nil, fmt.Errorf("keyset is unavailable")
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet context is required")
	}

	now := time.Now().UTC()
	issuedAt := roundCredentialIssuanceTime(now)
	credentialID := d.plugin.randomValue(24)
	issuerJWK, ok := d.plugin.keySet.GetJWKByID(d.plugin.keySet.ECKeyID())
	if !ok {
		return nil, fmt.Errorf("issuer ec jwk is unavailable")
	}
	issuerDID, err := vc.DIDJWKFromJSON(issuerJWK)
	if err != nil {
		return nil, fmt.Errorf("derive issuer did:jwk: %w", err)
	}
	expiry := issuedAt.Add(jwtCredentialLifetime)
	credential := map[string]interface{}{
		"@context": credentialContexts(configuration),
		"id":       strings.TrimRight(d.plugin.issuerID(), "/") + "/credentials/" + credentialID,
		"type":     credentialTypes(configuration),
		"issuer": map[string]interface{}{
			"id":   issuerDID,
			"name": "ProtocolSoup Issuer",
		},
		"issuanceDate":      issuedAt.Format(time.RFC3339),
		"validFrom":         issuedAt.Format(time.RFC3339),
		"expirationDate":    expiry.Format(time.RFC3339),
		"validUntil":        expiry.Format(time.RFC3339),
		"credentialSubject": walletFullCredentialSubject(subject, wallet),
		"credentialStatus": map[string]interface{}{
			"id":                   strings.TrimRight(d.plugin.issuerID(), "/") + "/credentials/" + credentialID + "/status",
			"type":                 "StatusList2021Entry",
			"statusPurpose":        "revocation",
			"statusListIndex":      "0",
			"statusListCredential": strings.TrimRight(d.plugin.issuerID(), "/") + "/status-list",
		},
	}
	if strings.TrimSpace(configuration.VCT) != "" {
		credential["vct"] = strings.TrimSpace(configuration.VCT)
	}
	securedCredential, err := vc.SecureDataIntegrityDocument(
		credential,
		map[string]interface{}{
			"created":            issuedAt.Format(time.RFC3339),
			"proofPurpose":       "assertionMethod",
			"verificationMethod": vc.DefaultVerificationMethodID(issuerDID),
		},
		issuerJWK,
		func(data []byte) ([]byte, error) {
			digest := sha256.Sum256(data)
			rValue, sValue, signErr := ecdsa.Sign(rand.Reader, d.plugin.keySet.ECPrivateKey(), digest[:])
			if signErr != nil {
				return nil, signErr
			}
			componentSize := 32
			signature := make([]byte, componentSize*2)
			rBytes := rValue.Bytes()
			sBytes := sValue.Bytes()
			copy(signature[componentSize-len(rBytes):componentSize], rBytes)
			copy(signature[len(signature)-len(sBytes):], sBytes)
			return signature, nil
		},
	)
	if err != nil {
		return nil, err
	}
	serialized, err := json.Marshal(securedCredential)
	if err != nil {
		return nil, err
	}
	serializedCredential := strings.TrimSpace(string(serialized))
	return &issuedCredential{
		Format:          configuration.Format,
		Credential:      securedCredential,
		CredentialJWT:   serializedCredential,
		IssuerSignedJWT: serializedCredential,
		CredentialID:    credentialID,
		VCT:             configuration.VCT,
		CredentialTypes: credentialTypes(configuration),
		Issuer:          issuerDID,
		IssuerJWK:       issuerJWK,
	}, nil
}

func issueJWTBackedCredential(
	p *Plugin,
	tokenType string,
	subject string,
	configuration credentialConfiguration,
	wallet *walletIdentity,
	includeContext bool,
	includeLDPProof bool,
) (*issuedCredential, error) {
	if p == nil {
		return nil, fmt.Errorf("plugin is unavailable")
	}
	if p.keySet == nil {
		return nil, fmt.Errorf("keyset is unavailable")
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet context is required")
	}

	now := time.Now().UTC()
	issuedAt := roundCredentialIssuanceTime(now)
	credentialID := p.randomValue(24)
	issuerJWK, ok := p.keySet.GetJWKByID(p.keySet.RSAKeyID())
	if !ok {
		return nil, fmt.Errorf("issuer rsa jwk is unavailable")
	}
	credentialSubject := walletFullCredentialSubject(subject, wallet)
	vcClaim := map[string]interface{}{
		"type":              credentialTypes(configuration),
		"credentialSubject": credentialSubject,
	}
	if includeContext {
		vcClaim["@context"] = credentialContexts(configuration)
	}
	if includeLDPProof {
		vcClaim["proof"] = map[string]interface{}{
			"type":               "JsonWebSignature2020",
			"proofPurpose":       "assertionMethod",
			"verificationMethod": p.issuerID() + "#keys-1",
			"created":            issuedAt.Format(time.RFC3339),
		}
	}

	claims := jwt.MapClaims{
		"iss": nowIssuer(p.issuerID()),
		"sub": subject,
		"iat": issuedAt.Unix(),
		"nbf": issuedAt.Unix(),
		"exp": issuedAt.Add(jwtCredentialLifetime).Unix(),
		"jti": credentialID,
		"vct": configuration.VCT,
		"vc":  vcClaim,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = tokenType
	token.Header["kid"] = p.keySet.RSAKeyID()
	signed, err := token.SignedString(p.keySet.RSAPrivateKey())
	if err != nil {
		return nil, err
	}
	return &issuedCredential{
		Format:          configuration.Format,
		Credential:      signed,
		CredentialJWT:   signed,
		IssuerSignedJWT: signed,
		CredentialID:    credentialID,
		VCT:             configuration.VCT,
		CredentialTypes: credentialTypes(configuration),
		Issuer:          p.issuerID(),
		IssuerJWK:       issuerJWK,
	}, nil
}

// IssueCredential issues an ISO/IEC 18013-5 mDL in the OID4VCI mso_mdoc format.
// It binds the holder device key from the proof into the MSO, builds the
// issuer-signed namespaces and value digests (internal/mdoc), signs
// IssuerAuth (COSE_Sign1) with the document-signer key attaching the DS
// x5chain, and returns the credential as base64url-encoded CBOR of IssuerSigned
// (OID4VCI 1.0 Appendix A.2 mso_mdoc; the credential value is the base64url of
// the ISO 18013-5 IssuerSigned structure).
func (d *msoMdocCredentialIssuerDriver) IssueCredential(subject string, configuration credentialConfiguration, wallet *walletIdentity, holderJWK *crypto.JWK) (*issuedCredential, error) {
	if d == nil || d.plugin == nil {
		return nil, fmt.Errorf("mso_mdoc credential issuer driver is unavailable")
	}
	if d.plugin.mdocPKI == nil {
		return nil, fmt.Errorf("mso_mdoc issuer pki is unavailable")
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet context is required")
	}

	// The device key is the holder's, supplied in the proof, never generated at
	// the issuer (ISO/IEC 18013-5 clause 9.1.2 deviceKeyInfo.deviceKey). mdoc
	// device keys are EC2/P-256 COSE keys.
	if holderJWK == nil || strings.TrimSpace(holderJWK.Kty) == "" {
		return nil, fmt.Errorf("mso_mdoc issuance requires a device key bound in the proof")
	}
	if !strings.EqualFold(strings.TrimSpace(holderJWK.Kty), "EC") {
		return nil, fmt.Errorf("mso_mdoc device key must be EC (P-256), got kty %q", holderJWK.Kty)
	}
	if crv := strings.TrimSpace(holderJWK.Crv); crv != "" && crv != "P-256" {
		return nil, fmt.Errorf("mso_mdoc device key must use curve P-256, got %q", crv)
	}
	devicePub, err := crypto.ParseECPublicKeyFromJWK(*holderJWK)
	if err != nil {
		return nil, fmt.Errorf("parse device key from proof: %w", err)
	}
	deviceKey, err := intcose.ECPublicKeyToCOSEKey(devicePub)
	if err != nil {
		return nil, fmt.Errorf("convert device key to COSE_Key: %w", err)
	}

	docType := strings.TrimSpace(configuration.Doctype)
	if docType == "" {
		docType = mdoc.DocTypeMDL
	}

	now := time.Now().UTC()
	issuedAt := roundCredentialIssuanceTime(now)
	credentialID := d.plugin.randomValue(24)

	items, err := buildMDLIssuerSignedItems(issuedAt, wallet, d.plugin.mdocPKI)
	if err != nil {
		return nil, fmt.Errorf("build mDL data elements: %w", err)
	}
	nameSpaces, err := mdoc.BuildIssuerNameSpaces(map[mdoc.NameSpace][]mdoc.IssuerSignedItem{
		mdoc.NameSpaceMDL: items,
	})
	if err != nil {
		return nil, fmt.Errorf("build issuer namespaces: %w", err)
	}
	valueDigests, err := mdoc.BuildValueDigests(nameSpaces, mdoc.DigestAlgorithmSHA256)
	if err != nil {
		return nil, fmt.Errorf("build value digests: %w", err)
	}

	validity := mdoc.ValidityInfo{
		Signed:     issuedAt,
		ValidFrom:  issuedAt,
		ValidUntil: issuedAt.Add(msoValidity),
	}
	mso := mdoc.BuildMSO(valueDigests, deviceKey, docType, validity)
	msoBytes, err := mdoc.EncodeMSOBytes(mso)
	if err != nil {
		return nil, fmt.Errorf("encode MSO: %w", err)
	}
	issuerAuth, err := mdoc.BuildIssuerAuth(msoBytes, d.plugin.mdocPKI.DocumentSignerKey(), d.plugin.mdocPKI.DocumentSignerChain())
	if err != nil {
		return nil, fmt.Errorf("sign IssuerAuth: %w", err)
	}

	issuerSigned := mdoc.IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: issuerAuth}
	encoded, err := mdoc.EncodeIssuerSigned(issuerSigned)
	if err != nil {
		return nil, fmt.Errorf("encode IssuerSigned: %w", err)
	}
	credential := base64.RawURLEncoding.EncodeToString(encoded)

	dsKey := d.plugin.mdocPKI.DocumentSignerKey()
	issuerJWK := crypto.JWKFromECPublicKey(&dsKey.PublicKey, "mdoc-ds")

	return &issuedCredential{
		Format:        configuration.Format,
		Credential:    credential,
		CredentialJWT: credential,
		// IssuerSignedJWT carries the same base64url CBOR so the wallet store
		// lineage holds the verbatim issued artifact.
		IssuerSignedJWT: credential,
		CredentialID:    credentialID,
		Doctype:         docType,
		Issuer:          d.plugin.issuerID(),
		IssuerJWK:       issuerJWK,
	}, nil
}

// buildMDLIssuerSignedItems assembles the org.iso.18013.5.1 data elements from
// the issuer's identity record and current issuance context. It never invents
// identity attributes from unrelated fields.
func buildMDLIssuerSignedItems(now time.Time, wallet *walletIdentity, pki *mdoc.IssuerPKI) ([]mdoc.IssuerSignedItem, error) {
	if wallet == nil {
		return nil, fmt.Errorf("wallet identity is required")
	}
	country := pki.Country()
	if country == "" {
		country = "US"
	}
	authority := pki.Organization()
	if authority == "" {
		authority = "ProtocolSoup"
	}

	birthDate, err := time.Parse("2006-01-02", strings.TrimSpace(wallet.Birthdate))
	if err != nil {
		return nil, fmt.Errorf("identity record has no valid birthdate: %w", err)
	}
	documentNumber := strings.TrimSpace(wallet.Claims["mdl_document_number"])
	if documentNumber == "" {
		return nil, fmt.Errorf("identity record is missing mdl_document_number")
	}
	privilegeCodes := splitNonEmptyCSV(wallet.Claims["mdl_driving_privilege_codes"])
	if len(privilegeCodes) == 0 {
		return nil, fmt.Errorf("identity record is missing mdl_driving_privilege_codes")
	}
	licenceExpiry := now.Add(mdlLicenceValidity)
	age := now.Year() - birthDate.Year()
	birthdayThisYear := time.Date(now.Year(), birthDate.Month(), birthDate.Day(), 0, 0, 0, 0, time.UTC)
	if now.Before(birthdayThisYear) {
		age--
	}
	ageOver21 := age >= 21
	portrait, err := generatedMDLPortrait(wallet)
	if err != nil {
		return nil, err
	}

	drivingPrivileges := make([]map[string]interface{}, 0, len(privilegeCodes))
	for _, privilegeCode := range privilegeCodes {
		drivingPrivileges = append(drivingPrivileges, map[string]interface{}{
			"vehicle_category_code": "B",
			"issue_date":            intcose.FullDate(now),
			"expiry_date":           intcose.FullDate(licenceExpiry),
		})
		drivingPrivileges[len(drivingPrivileges)-1]["vehicle_category_code"] = privilegeCode
	}

	elements := []struct {
		id    string
		value any
	}{
		{"family_name", strings.TrimSpace(wallet.FamilyName)},
		{"given_name", strings.TrimSpace(wallet.GivenName)},
		{"birth_date", intcose.FullDate(birthDate)},
		{"issue_date", intcose.FullDate(now)},
		{"expiry_date", intcose.FullDate(licenceExpiry)},
		{"issuing_country", country},
		{"issuing_authority", authority},
		{"document_number", documentNumber},
		{"portrait", portrait},
		{"un_distinguishing_sign", unDistinguishingSign(country)},
		{"driving_privileges", drivingPrivileges},
		{"age_over_21", ageOver21},
	}

	items := make([]mdoc.IssuerSignedItem, 0, len(elements))
	for index, element := range elements {
		item, err := mdoc.NewIssuerSignedItem(mdoc.DigestID(index), element.id, element.value)
		if err != nil {
			return nil, fmt.Errorf("create item %q: %w", element.id, err)
		}
		items = append(items, item)
	}
	return items, nil
}

// generatedMDLPortrait creates a valid JPEG avatar from the identity record.
// It is intentionally stylized so the demo identity cannot be mistaken for a
// photograph of a real person, while still carrying real image bytes through
// the ISO/IEC 18013-5 issuance and verification paths.
func generatedMDLPortrait(wallet *walletIdentity) ([]byte, error) {
	const (
		width  = 96
		height = 128
	)
	seed := sha256.Sum256([]byte(strings.TrimSpace(wallet.GivenName) + "\x00" + strings.TrimSpace(wallet.FamilyName)))
	background := color.RGBA{R: 210 + seed[0]%30, G: 220 + seed[1]%25, B: 225 + seed[2]%25, A: 255}
	hair := color.RGBA{R: 35 + seed[3]%70, G: 25 + seed[4]%55, B: 20 + seed[5]%45, A: 255}
	skin := color.RGBA{R: 190 + seed[6]%50, G: 135 + seed[7]%55, B: 100 + seed[8]%45, A: 255}
	shirt := color.RGBA{R: 35 + seed[9]%120, G: 55 + seed[10]%120, B: 85 + seed[11]%120, A: 255}

	portrait := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixel := background
			if dx, dy := x-width/2, y-54; dx*dx*4+dy*dy*3 <= 38*38*3 {
				pixel = skin
			}
			if dx, dy := x-width/2, y-38; dy < 0 && dx*dx+dy*dy <= 34*34 {
				pixel = hair
			}
			if y >= 96 && (x-48)*(x-48) <= (y-90)*(y-90) {
				pixel = shirt
			}
			if y >= 52 && y <= 57 && (x == 35 || x == 36 || x == 59 || x == 60) {
				pixel = color.RGBA{R: 30, G: 30, B: 30, A: 255}
			}
			portrait.SetRGBA(x, y, pixel)
		}
	}
	var encoded bytes.Buffer
	if err := jpeg.Encode(&encoded, portrait, &jpeg.Options{Quality: 90}); err != nil {
		return nil, fmt.Errorf("encode identity-derived mDL portrait: %w", err)
	}
	return encoded.Bytes(), nil
}

func splitNonEmptyCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

// unDistinguishingSign maps an ISO 3166-1 country code to its UN distinguishing
// sign where known (ISO/IEC 18013-5 references the UN vehicle sign), falling
// back to the country code.
func unDistinguishingSign(country string) string {
	switch strings.ToUpper(country) {
	case "US":
		return "USA"
	case "AU":
		return "AUS"
	case "DE":
		return "D"
	case "GB":
		return "UK"
	case "NL":
		return "NL"
	case "FR":
		return "F"
	default:
		return strings.ToUpper(country)
	}
}

func walletSelectiveClaims(wallet *walletIdentity) map[string]interface{} {
	claims := map[string]interface{}{
		"family_name": wallet.FamilyName,
		"given_name":  wallet.GivenName,
	}
	if wallet.Department != "" {
		claims["department"] = wallet.Department
	}
	if wallet.Degree != "" {
		claims["degree"] = wallet.Degree
	}
	if wallet.GraduationYear > 0 {
		claims["graduation_year"] = wallet.GraduationYear
	}
	return claims
}

func walletFullCredentialSubject(subject string, wallet *walletIdentity) map[string]interface{} {
	credentialSubject := map[string]interface{}{
		"id": subject,
	}
	for claimName, claimValue := range walletSelectiveClaims(wallet) {
		credentialSubject[claimName] = claimValue
	}
	return credentialSubject
}

func credentialTypes(configuration credentialConfiguration) []string {
	if len(configuration.CredentialTypes) == 0 {
		return []string{"VerifiableCredential", "UniversityDegreeCredential"}
	}
	return append([]string{}, configuration.CredentialTypes...)
}

func credentialContexts(configuration credentialConfiguration) []string {
	if len(configuration.Contexts) == 0 {
		return []string{"https://www.w3.org/2018/credentials/v1"}
	}
	return append([]string{}, configuration.Contexts...)
}
