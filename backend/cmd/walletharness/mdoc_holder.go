package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// mso_mdoc OID4VP encrypted-response content encryption algorithms (OID4VP 1.0
// Section 8.3 / HAIP 1.0 Section 5). The verifier accepts both on decrypt;
// A256GCM is preferred when the verifier advertises it (HAIP), otherwise A128GCM
// (the mdoc online-profile default) is used.
const (
	// mdocResponseEncA256GCM is the AES-256-GCM content encryption identifier
	// preferred for HAIP 1.0 Section 5 encrypted responses when the verifier
	// advertises it.
	mdocResponseEncA256GCM = "A256GCM"
	// mdocResponseEncAlg is the ECDH-ES key-agreement algorithm the verifier
	// advertises (alg=ECDH-ES) for mso_mdoc response encryption, used here to
	// select the verifier's response-encryption key from client_metadata.jwks.
	mdocResponseEncAlg = "ECDH-ES"
)

// credentialFormatMsoMdoc is the OID4VCI/ISO 18013-5 mso_mdoc credential format
// identifier (OID4VCI Appendix A.3). mso_mdoc credentials are base64url-encoded
// CBOR IssuerSigned rather than JWTs.
const credentialFormatMsoMdoc = "mso_mdoc"

// createMdocDeviceProofJWT builds an OID4VCI proof JWT (OID4VCI Section 8.2.1)
// that carries the persistent device key in cnf.jwk and is signed by that key
// with ES256. The issuer binds the proof key into the MSO deviceKeyInfo.deviceKey
// (ISO/IEC 18013-5 clause 9.1.2), so the holder can later authenticate the
// device with the same persistent key.
func (s *walletHarnessServer) createMdocDeviceProofJWT(subject, cNonce, audience string) (string, error) {
	if s.deviceKey == nil {
		return "", fmt.Errorf("wallet device key is unavailable")
	}
	normalizedSubject := strings.TrimSpace(subject)
	if normalizedSubject == "" {
		return "", fmt.Errorf("wallet subject is required for mso_mdoc proof")
	}
	if strings.TrimSpace(cNonce) == "" {
		return "", fmt.Errorf("c_nonce is required for mso_mdoc proof")
	}
	publicJWK := intcrypto.JWKFromECPublicKey(&s.deviceKey.PublicKey, s.deviceKeyID)
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   normalizedSubject,
		"sub":   normalizedSubject,
		"aud":   firstNonEmpty(strings.TrimSpace(audience), s.issuerBaseURL+"/oid4vci"),
		"nonce": cNonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   randomValue(20),
		"cnf": map[string]interface{}{
			"jwk": publicJWK,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	if s.deviceKeyID != "" {
		token.Header["kid"] = s.deviceKeyID
	}
	signed, err := token.SignedString(s.deviceKey)
	if err != nil {
		return "", fmt.Errorf("sign mso_mdoc device proof: %w", err)
	}
	return signed, nil
}

// bindMdocCredential stores an issued mso_mdoc credential (base64url CBOR
// IssuerSigned) in the wallet, after confirming it is bound to this wallet's
// persistent device key. Storing the IssuerSigned plus its MSO doctype with the
// device-key association is the holder-side of ISO/IEC 18013-5 clause 9.1.2:
// the stored credential and the device key together enable later device
// authentication (DeviceResponse) over the same persistent key.
func (s *walletHarnessServer) bindMdocCredential(wallet *walletMaterial, credentialB64 string, credentialConfigID string) error {
	trimmed := strings.TrimSpace(credentialB64)
	if trimmed == "" {
		return fmt.Errorf("mso_mdoc credential is required")
	}
	raw, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return fmt.Errorf("decode mso_mdoc credential: %w", err)
	}
	issuerSigned, err := mdoc.DecodeIssuerSigned(raw)
	if err != nil {
		return fmt.Errorf("decode mso_mdoc IssuerSigned: %w", err)
	}
	mso, err := s.verifyMdocDeviceBinding(issuerSigned)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	sum := sha256.Sum256(raw)
	credentialID := hex.EncodeToString(sum[:16])
	record := walletCredentialMaterial{
		CredentialID:              credentialID,
		CredentialJWT:             trimmed,
		Format:                    credentialFormatMsoMdoc,
		CredentialConfigurationID: strings.TrimSpace(credentialConfigID),
		Doctype:                   mso.DocType,
		IssuedAt:                  now,
		UpdatedAt:                 now,
	}
	if wallet.Credentials == nil {
		wallet.Credentials = make(map[string]walletCredentialMaterial)
	}
	if existing, ok := wallet.Credentials[credentialID]; ok && !existing.IssuedAt.IsZero() {
		record.IssuedAt = existing.IssuedAt
	}
	wallet.Credentials[credentialID] = record
	activateWalletCredential(wallet, record)
	return nil
}

// verifyMdocDeviceBinding verifies the complete issuer-authenticated credential
// before confirming that deviceKeyInfo.deviceKey is this wallet's persistent
// device key. The wallet must trust the issuer independently; an x5chain carried
// by the credential cannot appoint its own root.
func (s *walletHarnessServer) verifyMdocDeviceBinding(issuerSigned mdoc.IssuerSigned) (*mdoc.MobileSecurityObject, error) {
	if s.deviceKey == nil {
		return nil, fmt.Errorf("wallet device key is unavailable")
	}
	if s.mdocIssuerRoots == nil {
		return nil, fmt.Errorf("wallet has no configured mso_mdoc IACA trust anchor")
	}
	mso, err := mdoc.VerifyIssuerSigned(issuerSigned, s.mdocIssuerRoots, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("verify mso_mdoc issuer authentication: %w", err)
	}
	boundKey, err := intcose.COSEKeyToECPublicKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return nil, fmt.Errorf("decode bound device key: %w", err)
	}
	if !boundKey.Equal(&s.deviceKey.PublicKey) {
		return nil, fmt.Errorf("mso_mdoc credential is not bound to this wallet's device key")
	}
	return mso, nil
}

// buildMdocDeviceResponse produces an ISO/IEC 18013-5 DeviceResponse for a stored
// mso_mdoc credential, disclosing the requested elements and authenticating the
// device with the persistent device key over the shared SessionTranscript. The
// handover is supplied by the caller: Phases 4 and 5 use a fixed test handover,
// and the OID4VP online profile defines the OpenID4VPHandover. The returned bytes are the
// canonical-CBOR DeviceResponse.
func (s *walletHarnessServer) buildMdocDeviceResponse(wallet *walletMaterial, credentialID string, requested map[mdoc.NameSpace][]string, handover []byte) ([]byte, error) {
	if s.deviceKey == nil {
		return nil, fmt.Errorf("wallet device key is unavailable")
	}
	record, ok := wallet.Credentials[strings.TrimSpace(credentialID)]
	if !ok || !strings.EqualFold(record.Format, credentialFormatMsoMdoc) {
		return nil, fmt.Errorf("no stored mso_mdoc credential %q", credentialID)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(record.CredentialJWT))
	if err != nil {
		return nil, fmt.Errorf("decode stored mso_mdoc credential: %w", err)
	}
	issuerSigned, err := mdoc.DecodeIssuerSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("decode stored IssuerSigned: %w", err)
	}
	transcript, err := mdoc.NewOID4VPSessionTranscript(handover)
	if err != nil {
		return nil, err
	}
	transcriptBytes, err := transcript.Encode()
	if err != nil {
		return nil, err
	}
	docType := record.Doctype
	if docType == "" {
		docType = mdoc.DocTypeMDL
	}
	response, err := mdoc.BuildDeviceResponse(s.deviceKey, issuerSigned, docType, transcriptBytes, requested, nil)
	if err != nil {
		return nil, err
	}
	return mdoc.EncodeDeviceResponse(response)
}

// decodeMdocIssuerSignedB64 decodes a base64url CBOR mso_mdoc credential into its
// IssuerSigned. mso_mdoc credentials are CBOR, not JWTs, so the JWT/SD-JWT parsers
// cannot be used on them.
func decodeMdocIssuerSignedB64(credentialB64 string) (mdoc.IssuerSigned, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(credentialB64))
	if err != nil {
		return mdoc.IssuerSigned{}, fmt.Errorf("decode mso_mdoc credential: %w", err)
	}
	issuerSigned, err := mdoc.DecodeIssuerSigned(raw)
	if err != nil {
		return mdoc.IssuerSigned{}, fmt.Errorf("decode mso_mdoc IssuerSigned: %w", err)
	}
	return issuerSigned, nil
}

// decodeStoredMdocIssuerSigned decodes a stored mso_mdoc credential (base64url
// CBOR) back into its IssuerSigned.
func decodeStoredMdocIssuerSigned(record walletCredentialMaterial) (mdoc.IssuerSigned, error) {
	return decodeMdocIssuerSignedB64(record.CredentialJWT)
}

// mdocCredentialSummary builds the wallet credential summary for a stored
// mso_mdoc credential (base64url CBOR IssuerSigned). mso_mdoc credentials are
// CBOR, not JWTs, so the generic JWT/SD-JWT summary path yields an empty summary;
// this surfaces the real docType, validity window, and issuer-signed elements
// (ISO/IEC 18013-5 clause 9.1.2) so the wallet UI renders authentic mDL data
// instead of blank metadata. Returns nil when the input is not a decodable
// mso_mdoc credential.
func mdocCredentialSummary(rawCredential string) *credentialSummary {
	issuerSigned, err := decodeMdocIssuerSignedB64(rawCredential)
	if err != nil {
		return nil
	}
	summary := &credentialSummary{Format: credentialFormatMsoMdoc}
	if msoBytes, _, perr := mdoc.ParseIssuerAuth(issuerSigned.IssuerAuth); perr == nil {
		if mso, merr := mdoc.DecodeMSOBytes(msoBytes); merr == nil {
			summary.Doctype = strings.TrimSpace(mso.DocType)
			if !mso.ValidityInfo.ValidUntil.IsZero() {
				summary.ExpiresAt = mso.ValidityInfo.ValidUntil.UTC().Format(time.RFC3339)
			}
		}
	}
	disclosed, derr := mdoc.CollectDisclosedElements(issuerSigned)
	if derr != nil {
		return summary
	}
	namespaces := make([]string, 0, len(disclosed))
	for ns := range disclosed {
		namespaces = append(namespaces, string(ns))
	}
	sort.Strings(namespaces)
	claims := make(map[string]interface{}, len(disclosed))
	for _, ns := range namespaces {
		elements := disclosed[mdoc.NameSpace(ns)]
		nsClaims := make(map[string]interface{}, len(elements))
		for element, value := range elements {
			nsClaims[element] = mdoc.JSONSafeValue(value)
		}
		claims[ns] = nsClaims
	}
	summary.Claims = claims
	if mdl, ok := disclosed[mdoc.NameSpaceMDL]; ok {
		if docNumber, ok := mdl["document_number"]; ok {
			summary.Subject = fmt.Sprintf("%v", docNumber)
		}
	}
	return summary
}

// mdocAvailableElements returns the namespace -> elementIdentifier -> value map
// of a stored mso_mdoc credential's issuer-signed elements (ISO/IEC 18013-5).
func mdocAvailableElements(record walletCredentialMaterial) (map[mdoc.NameSpace]map[string]any, error) {
	issuerSigned, err := decodeStoredMdocIssuerSigned(record)
	if err != nil {
		return nil, err
	}
	disclosed, err := mdoc.CollectDisclosedElements(issuerSigned)
	if err != nil {
		return nil, fmt.Errorf("collect mso_mdoc elements: %w", err)
	}
	return disclosed, nil
}

// mdocMatchEvidence builds the DCQL mdoc matcher view (vc.MdocCredentialEvidence)
// from a stored mso_mdoc credential: the issuer-verified docType plus the set of
// issuer-signed element identifiers per namespace. The wallet uses this to
// evaluate an mso_mdoc DCQL query (OID4VP/DCQL) without parsing the credential
// as a JWT, mirroring the verifier's matchMdocAgainstDCQL evidence.
func mdocMatchEvidence(record walletCredentialMaterial) (vc.MdocCredentialEvidence, error) {
	disclosed, err := mdocAvailableElements(record)
	if err != nil {
		return vc.MdocCredentialEvidence{}, err
	}
	namespaces := make(map[string]map[string]struct{}, len(disclosed))
	for ns, elements := range disclosed {
		set := make(map[string]struct{}, len(elements))
		for element := range elements {
			set[element] = struct{}{}
		}
		namespaces[string(ns)] = set
	}
	doctype := strings.TrimSpace(record.Doctype)
	if doctype == "" {
		if issuerSigned, derr := decodeStoredMdocIssuerSigned(record); derr == nil {
			if msoBytes, _, perr := mdoc.ParseIssuerAuth(issuerSigned.IssuerAuth); perr == nil {
				if mso, merr := mdoc.DecodeMSOBytes(msoBytes); merr == nil {
					doctype = strings.TrimSpace(mso.DocType)
				}
			}
		}
	}
	issuerSigned, err := decodeStoredMdocIssuerSigned(record)
	if err != nil {
		return vc.MdocCredentialEvidence{}, err
	}
	issuerAKI, err := mdoc.IssuerAuthorityKeyIdentifier(issuerSigned)
	if err != nil {
		return vc.MdocCredentialEvidence{}, err
	}
	return vc.MdocCredentialEvidence{
		Format:                       credentialFormatMsoMdoc,
		Doctype:                      doctype,
		IssuerAuthorityKeyIdentifier: base64.RawURLEncoding.EncodeToString(issuerAKI),
		NameSpaces:                   namespaces,
	}, nil
}

// mdocRequestedElements resolves the namespace -> element identifiers that the
// DCQL query asks the wallet to disclose from a stored mso_mdoc credential. mdoc
// claim paths are [namespace, elementIdentifier] (OID4VP/DCQL + ISO/IEC
// 18013-5). A single-segment [namespace] path or a requirement with no claims
// requests the whole namespace, so every available element in scope is
// disclosed. Requested elements are always intersected with what the credential
// actually carries, so the DeviceResponse never claims to disclose an element it
// does not hold.
func mdocRequestedElements(dcqlQueryRaw string, record walletCredentialMaterial) (map[mdoc.NameSpace][]string, error) {
	available, err := mdocAvailableElements(record)
	if err != nil {
		return nil, err
	}
	doctype := strings.TrimSpace(record.Doctype)
	requested := make(map[mdoc.NameSpace]map[string]struct{})
	addElement := func(ns mdoc.NameSpace, element string) {
		avail, ok := available[ns]
		if !ok {
			return
		}
		if _, ok := avail[element]; !ok {
			return
		}
		if requested[ns] == nil {
			requested[ns] = make(map[string]struct{})
		}
		requested[ns][element] = struct{}{}
	}
	addNamespace := func(ns mdoc.NameSpace) {
		for element := range available[ns] {
			addElement(ns, element)
		}
	}
	addAll := func() {
		for ns := range available {
			addNamespace(ns)
		}
	}

	requirements := vc.ParseDCQLCredentialRequirements(strings.TrimSpace(dcqlQueryRaw))
	matchedAnyRequirement := false
	for _, requirement := range requirements {
		if requirement.Format != "" && !strings.EqualFold(requirement.Format, credentialFormatMsoMdoc) {
			continue
		}
		if len(requirement.DoctypeValues) > 0 && doctype != "" && !containsFold(requirement.DoctypeValues, doctype) {
			continue
		}
		matchedAnyRequirement = true
		if len(requirement.RequiredClaimPathSegments) == 0 {
			addAll()
			continue
		}
		for _, segments := range requirement.RequiredClaimPathSegments {
			switch len(segments) {
			case 0:
				continue
			case 1:
				addNamespace(mdoc.NameSpace(strings.TrimSpace(segments[0])))
			default:
				addElement(mdoc.NameSpace(strings.TrimSpace(segments[0])), strings.TrimSpace(segments[1]))
			}
		}
	}
	// With no DCQL requirement scoping this credential (e.g. a scope-aliased
	// request), default to disclosing the full credential so the verifier can
	// evaluate it. An empty requested map would disclose nothing (issuerAuth
	// only), which is never the intent for a matched credential.
	if !matchedAnyRequirement {
		addAll()
	}

	out := make(map[mdoc.NameSpace][]string, len(requested))
	for ns, elements := range requested {
		list := make([]string, 0, len(elements))
		for element := range elements {
			list = append(list, element)
		}
		sort.Strings(list)
		out[ns] = list
	}
	return out, nil
}

// reconstructMdocHandover rebuilds the OID4VP 1.0 SessionTranscript Handover the
// verifier binds device authentication to, from this request's context. It MUST
// be byte-identical to the verifier's reconstructSessionHandover or device
// authentication fails. The redirect / direct_post profile uses the
// OpenID4VPHandover over [client_id, nonce, jwkThumbprint, response_uri]
// (Appendix B.2.6.1); the jwkThumbprint is the verifier response-encryption key
// thumbprint, present only when the response is encrypted (direct_post.jwt).
func (s *walletHarnessServer) reconstructMdocHandover(requestContext *resolvedRequestContext) ([]byte, error) {
	if requestContext == nil {
		return nil, fmt.Errorf("request context is required")
	}
	var jwkThumbprint []byte
	if requestContext.ResponseMode == "direct_post.jwt" {
		// Encrypted mdoc responses (OID4VP 1.0 Section 8.3 / HAIP 1.0 Section 5)
		// bind the verifier's ECDH-ES response-encryption key RFC 7638 thumbprint
		// into OpenID4VPHandoverInfo (Appendix B.2.6.1). The verifier reconstructs
		// the identical handover from the same key, so device authentication
		// verifies only when the wallet binds the same thumbprint here. Without the
		// verifier key the handover cannot be reproduced, so this is reported
		// rather than silently producing a handover the verifier cannot match.
		if requestContext.ResponseEncryptionJWK == nil {
			return nil, fmt.Errorf("encrypted mso_mdoc response (direct_post.jwt) requires the verifier response-encryption key in client_metadata.jwks")
		}
		thumbprint, err := requestContext.ResponseEncryptionJWK.ThumbprintBytes()
		if err != nil {
			return nil, fmt.Errorf("compute verifier response-encryption thumbprint: %w", err)
		}
		jwkThumbprint = thumbprint
	}
	return mdoc.NewOpenID4VPHandover(requestContext.ClientID, requestContext.Nonce, jwkThumbprint, requestContext.ResponseURI)
}

// extractResponseEncryptionJWK pulls the verifier's ECDH-ES response-encryption
// public key from a resolved request object's client_metadata.jwks (OID4VP 1.0
// Section 8.3). It selects the first EC key marked for encryption (use=enc or
// alg=ECDH-ES). Returns nil when the request advertises no such key: an
// unencrypted direct_post request carries none, and the SD-JWT direct_post.jwt
// path uses the verifier's RSA well-known key rather than a client_metadata key.
func extractResponseEncryptionJWK(clientMetadata map[string]interface{}) *intcrypto.JWK {
	if clientMetadata == nil {
		return nil
	}
	jwks, ok := clientMetadata["jwks"].(map[string]interface{})
	if !ok {
		return nil
	}
	keys, ok := jwks["keys"].([]interface{})
	if !ok {
		return nil
	}
	for _, entry := range keys {
		keyMap, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}
		encoded, err := json.Marshal(keyMap)
		if err != nil {
			continue
		}
		var jwk intcrypto.JWK
		if err := json.Unmarshal(encoded, &jwk); err != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(jwk.Kty), "EC") {
			continue
		}
		forEncryption := strings.EqualFold(strings.TrimSpace(jwk.Use), "enc") ||
			strings.EqualFold(strings.TrimSpace(jwk.Alg), mdocResponseEncAlg)
		if !forEncryption {
			continue
		}
		selected := jwk
		return &selected
	}
	return nil
}

// selectMdocResponseEnc picks the JWE content encryption algorithm for the
// encrypted mso_mdoc response from the verifier's advertised
// encrypted_response_enc_values_supported list. A256GCM is preferred when
// offered (HAIP 1.0 Section 5); otherwise A128GCM (the mdoc online-profile
// default, always accepted by the verifier) is used.
func selectMdocResponseEnc(encValues []string) jose.ContentEncryption {
	for _, encValue := range encValues {
		if strings.EqualFold(strings.TrimSpace(encValue), mdocResponseEncA256GCM) {
			return jose.A256GCM
		}
	}
	return jose.A128GCM
}

// encryptMdocResponseForVerifier builds the OID4VP 1.0 Section 8.3 encrypted
// response (JWE) for a direct_post.jwt mso_mdoc presentation: the Authorization
// Response members (vp_token, and state when present) form the JWE payload,
// encrypted to the verifier's ephemeral ECDH-ES response-encryption public key
// with AES-GCM content encryption (HAIP 1.0 Section 5). The same verifier key
// whose RFC 7638 thumbprint is bound into the OpenID4VPHandover is used here, so
// re-encrypting to a different key is detectable as a device-authentication
// failure (OID4VP 1.0 Appendix B.2.6 anti-substitution). This is the wallet
// parallel of the verifier's own encrypt/decrypt pair.
func encryptMdocResponseForVerifier(encJWK intcrypto.JWK, vpToken string, state string, enc jose.ContentEncryption) (string, error) {
	pub, err := intcrypto.ParseECPublicKeyFromJWK(encJWK)
	if err != nil {
		return "", fmt.Errorf("parse verifier response-encryption key: %w", err)
	}
	var vpTokenValue interface{}
	if err := json.Unmarshal([]byte(vpToken), &vpTokenValue); err != nil {
		// A bare base64url DeviceResponse is not JSON; carry it as a string.
		vpTokenValue = vpToken
	}
	payload := map[string]interface{}{"vp_token": vpTokenValue}
	if strings.TrimSpace(state) != "" {
		payload["state"] = state
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal mso_mdoc response payload: %w", err)
	}
	recipient := jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}
	if kid := strings.TrimSpace(encJWK.Kid); kid != "" {
		recipient.KeyID = kid
	}
	encrypter, err := jose.NewEncrypter(enc, recipient, (&jose.EncrypterOptions{}).WithType("JWT"))
	if err != nil {
		return "", fmt.Errorf("build mso_mdoc response encrypter: %w", err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt mso_mdoc response: %w", err)
	}
	return object.CompactSerialize()
}

// createMdocVPToken builds the mso_mdoc vp_token: a base64url CBOR DeviceResponse
// disclosing the DCQL-requested elements and authenticating the holder device
// over the verifier-reconstructed OID4VP SessionTranscript (ISO/IEC 18013-5
// clause 9.1.5 + OID4VP 1.0 Appendix B.2). This is the mdoc parallel of the
// JWT/SD-JWT registry presentation path in createVPToken.
func (s *walletHarnessServer) createMdocVPToken(wallet *walletMaterial, requestContext *resolvedRequestContext, credential walletCredentialMaterial) (string, string, error) {
	credentialID := strings.TrimSpace(credential.CredentialID)
	if credentialID == "" {
		return "", "", fmt.Errorf("no active mso_mdoc credential to present")
	}
	handover, err := s.reconstructMdocHandover(requestContext)
	if err != nil {
		return "", "", fmt.Errorf("reconstruct mdoc handover: %w", err)
	}
	requested, err := mdocRequestedElements(requestContext.DCQLQuery, credential)
	if err != nil {
		return "", "", err
	}
	responseBytes, err := s.buildMdocDeviceResponse(wallet, credentialID, requested, handover)
	if err != nil {
		return "", "", err
	}
	encodedResponse := base64.RawURLEncoding.EncodeToString(responseBytes)

	requirements := vc.ParseDCQLCredentialRequirements(requestContext.DCQLQuery)
	if len(requirements) == 0 {
		return encodedResponse, credentialFormatMsoMdoc, nil
	}
	evidence, err := mdocMatchEvidence(credential)
	if err != nil {
		return "", "", fmt.Errorf("build mso_mdoc DCQL evidence: %w", err)
	}
	vpToken := make(map[string][]string)
	for _, requirement := range requirements {
		if !strings.EqualFold(strings.TrimSpace(requirement.Format), credentialFormatMsoMdoc) {
			continue
		}
		if strings.TrimSpace(requirement.ID) == "" {
			return "", "", fmt.Errorf("mso_mdoc DCQL credential query is missing id")
		}
		matched, _, _ := vc.RequirementMatchesMdoc(requirement, evidence)
		if matched {
			vpToken[requirement.ID] = []string{encodedResponse}
		}
	}
	if len(vpToken) == 0 {
		return "", "", fmt.Errorf("mso_mdoc credential does not satisfy any DCQL credential query")
	}
	encodedVPToken, err := json.Marshal(vpToken)
	if err != nil {
		return "", "", fmt.Errorf("encode mso_mdoc DCQL vp_token: %w", err)
	}
	return string(encodedVPToken), credentialFormatMsoMdoc, nil
}

// containsFold reports whether values contains target using case-insensitive
// comparison after trimming surrounding whitespace.
func containsFold(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(target)) {
			return true
		}
	}
	return false
}
