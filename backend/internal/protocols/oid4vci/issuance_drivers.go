package oid4vci

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/golang-jwt/jwt/v5"
)

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
	credentialSubject := map[string]interface{}{
		"id":      subject,
		"_sd":     disclosureDigests,
		"_sd_alg": "sha-256",
	}
	claims := jwt.MapClaims{
		"iss": nowIssuer(d.plugin.issuerID()),
		"sub": subject,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(20 * time.Minute).Unix(),
		"jti": credentialID,
		"vct": configuration.VCT,
		"vc": map[string]interface{}{
			"@context":          credentialContexts(configuration),
			"type":              credentialTypes(configuration),
			"credentialSubject": credentialSubject,
		},
	}
	if holderJWK != nil && strings.TrimSpace(holderJWK.Kty) != "" {
		cnf := map[string]interface{}{
			"jwk": *holderJWK,
		}
		thumbprint := strings.TrimSpace(holderJWK.Thumbprint())
		if thumbprint != "" {
			cnf["jkt"] = thumbprint
		}
		claims["cnf"] = cnf
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = "vc+sd-jwt"
	token.Header["kid"] = d.plugin.keySet.RSAKeyID()
	issuerSignedJWT, err := token.SignedString(d.plugin.keySet.RSAPrivateKey())
	if err != nil {
		return nil, err
	}
	issuerJWK, ok := d.plugin.keySet.GetJWKByID(d.plugin.keySet.RSAKeyID())
	if !ok {
		return nil, fmt.Errorf("issuer rsa jwk is unavailable")
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
	credentialID := d.plugin.randomValue(24)
	issuerJWK, ok := d.plugin.keySet.GetJWKByID(d.plugin.keySet.ECKeyID())
	if !ok {
		return nil, fmt.Errorf("issuer ec jwk is unavailable")
	}
	issuerDID, err := vc.DIDJWKFromJSON(issuerJWK)
	if err != nil {
		return nil, fmt.Errorf("derive issuer did:jwk: %w", err)
	}
	expiry := now.Add(20 * time.Minute)
	credential := map[string]interface{}{
		"@context":          credentialContexts(configuration),
		"id":                strings.TrimRight(d.plugin.issuerID(), "/") + "/credentials/" + credentialID,
		"type":              credentialTypes(configuration),
		"issuer": map[string]interface{}{
			"id":   issuerDID,
			"name": "ProtocolSoup Issuer",
		},
		"issuanceDate":      now.Format(time.RFC3339),
		"validFrom":         now.Format(time.RFC3339),
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
			"created":            now.Format(time.RFC3339),
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
			"created":            now.Format(time.RFC3339),
		}
	}

	claims := jwt.MapClaims{
		"iss": nowIssuer(p.issuerID()),
		"sub": subject,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(20 * time.Minute).Unix(),
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

func walletSelectiveClaims(wallet *walletIdentity) map[string]interface{} {
	return map[string]interface{}{
		"department":      wallet.Department,
		"degree":          wallet.Degree,
		"family_name":     wallet.FamilyName,
		"given_name":      wallet.GivenName,
		"graduation_year": wallet.GraduationYear,
	}
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
