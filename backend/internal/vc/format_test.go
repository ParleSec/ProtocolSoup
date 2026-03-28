package vc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/golang-jwt/jwt/v5"
)

func TestParseAnyCredentialDetectsFormats(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()

	disclosure, err := CreateSDJWTDisclosure("family_name", "Doe", "fixed-salt")
	if err != nil {
		t.Fatalf("CreateSDJWTDisclosure: %v", err)
	}
	sdJWT := BuildSDJWTSerialization(
		signedTestJWT(t, jwt.SigningMethodHS256, []byte("sd-secret"), "vc+sd-jwt", jwt.MapClaims{
			"sub": "did:example:holder",
			"vct": "https://example.org/credential",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"vc": map[string]interface{}{
				"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
				"credentialSubject": map[string]interface{}{
					"id": "did:example:holder",
				},
			},
		}),
		[]string{disclosure.Encoded},
		"",
	)
	parsedSDJWT, err := registry.ParseAnyCredential(sdJWT)
	if err != nil {
		t.Fatalf("ParseAnyCredential(sd-jwt): %v", err)
	}
	if parsedSDJWT.Format != "dc+sd-jwt" {
		t.Fatalf("unexpected sd-jwt format %q", parsedSDJWT.Format)
	}
	if !parsedSDJWT.IsSDJWT || parsedSDJWT.DisclosureCount != 1 || len(parsedSDJWT.DisclosureClaims) != 1 {
		t.Fatalf("unexpected sd-jwt parse result %+v", parsedSDJWT)
	}

	jwtVC := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"sub": "did:example:holder",
		"vc": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"credentialSubject": map[string]interface{}{
				"id": "did:example:holder",
			},
		},
	})
	parsedJWTVC, err := registry.ParseAnyCredential(jwtVC)
	if err != nil {
		t.Fatalf("ParseAnyCredential(jwt-vc): %v", err)
	}
	if parsedJWTVC.Format != "jwt_vc_json-ld" {
		t.Fatalf("unexpected jwt-vc format %q", parsedJWTVC.Format)
	}

	ldpVC := `{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiableCredential","UniversityDegreeCredential"],"credentialSubject":{"id":"did:example:holder"},"proof":{"type":"Ed25519Signature2020"}}`
	parsedLDPVC, err := registry.ParseAnyCredential(ldpVC)
	if err != nil {
		t.Fatalf("ParseAnyCredential(ldp_vc): %v", err)
	}
	if parsedLDPVC.Format != "ldp_vc" {
		t.Fatalf("unexpected ldp_vc format %q", parsedLDPVC.Format)
	}
}

func TestSDJWTFormatBuildPresentationBuildsKBJWT(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()
	format, ok := registry.Lookup("dc+sd-jwt")
	if !ok {
		t.Fatalf("dc+sd-jwt format handler not found")
	}

	disclosure, err := CreateSDJWTDisclosure("degree", "BSc", "fixed-salt")
	if err != nil {
		t.Fatalf("CreateSDJWTDisclosure: %v", err)
	}
	issuerSignedJWT := signedTestJWT(t, jwt.SigningMethodHS256, []byte("issuer-secret"), "vc+sd-jwt", jwt.MapClaims{
		"sub": "did:example:holder",
		"vc": map[string]interface{}{
			"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	})
	rawCredential := BuildSDJWTSerialization(issuerSignedJWT, []string{disclosure.Encoded}, "")

	var (
		capturedClaims  map[string]interface{}
		capturedHeaders map[string]interface{}
	)
	result, err := format.BuildPresentation(PresentationBuildInput{
		Credential: rawCredential,
		Holder:     "did:example:holder",
		Audience:   "did:example:verifier",
		Nonce:      "nonce-123",
		Signer: func(claims map[string]interface{}, headerOverrides map[string]interface{}) (string, error) {
			capturedClaims = claims
			capturedHeaders = headerOverrides
			return "kb.jwt.token", nil
		},
	})
	if err != nil {
		t.Fatalf("BuildPresentation(sd-jwt): %v", err)
	}
	expected := BuildSDJWTSerialization(issuerSignedJWT, []string{disclosure.Encoded}, "kb.jwt.token")
	if result.VPToken != expected {
		t.Fatalf("unexpected sd-jwt presentation %q", result.VPToken)
	}
	if capturedHeaders["typ"] != "kb+jwt" {
		t.Fatalf("unexpected signer typ %v", capturedHeaders["typ"])
	}
	if capturedClaims["sd_hash"] == nil {
		t.Fatalf("expected sd_hash in kb-jwt claims")
	}
}

func TestJWTVCFormatBuildPresentationUsesHolderForPE(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()
	format, ok := registry.Lookup("jwt_vc_json")
	if !ok {
		t.Fatalf("jwt_vc_json format handler not found")
	}

	rawCredential := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"sub": "did:example:holder",
		"vc": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	})

	var capturedClaims map[string]interface{}
	result, err := format.BuildPresentation(PresentationBuildInput{
		Credential: rawCredential,
		Holder:     "did:example:holder",
		Audience:   "did:example:verifier",
		Nonce:      "nonce-123",
		PresentationDefinition: map[string]interface{}{
			"id": "pd-123",
		},
		Signer: func(claims map[string]interface{}, headerOverrides map[string]interface{}) (string, error) {
			if headerOverrides["typ"] != "vp+jwt" {
				t.Fatalf("unexpected signer typ %v", headerOverrides["typ"])
			}
			capturedClaims = claims
			return "vp.jwt.token", nil
		},
	})
	if err != nil {
		t.Fatalf("BuildPresentation(jwt-vc): %v", err)
	}
	if result.VPToken != "vp.jwt.token" {
		t.Fatalf("unexpected vp token %q", result.VPToken)
	}
	if _, ok := capturedClaims["sub"]; ok {
		t.Fatalf("expected PE presentation to omit sub claim")
	}

	vpClaim, ok := capturedClaims["vp"].(map[string]interface{})
	if !ok {
		t.Fatalf("vp claim has type %T", capturedClaims["vp"])
	}
	if vpClaim["holder"] != "did:example:holder" {
		t.Fatalf("unexpected vp holder %v", vpClaim["holder"])
	}
	credentials, ok := vpClaim["verifiableCredential"].([]interface{})
	if !ok || len(credentials) != 1 || credentials[0] != rawCredential {
		t.Fatalf("unexpected verifiableCredential payload %#v", vpClaim["verifiableCredential"])
	}
}

func TestJWTVCFormatValidateIssuerSignatureWithEdDSA(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()
	format, ok := registry.Lookup("jwt_vc_json")
	if !ok {
		t.Fatalf("jwt_vc_json format handler not found")
	}

	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	issuerJWK := intcrypto.JWKFromEd25519PublicKey(keySet.Ed25519PublicKey(), keySet.Ed25519KeyID())
	credential := signedTestJWT(t, jwt.SigningMethodEdDSA, keySet.Ed25519PrivateKey(), "vc+jwt", jwt.MapClaims{
		"sub": "did:example:holder",
		"vc": map[string]interface{}{
			"type": []string{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	})

	if err := format.ValidateIssuerSignature(CredentialValidationInput{
		Credential: credential,
		IssuerKeys: []intcrypto.JWK{issuerJWK},
	}); err != nil {
		t.Fatalf("ValidateIssuerSignature(EdDSA): %v", err)
	}
}

func TestParseAnyCredentialFallsBackToCredentialSubjectID(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()

	credential := signedTestJWT(t, jwt.SigningMethodHS256, []byte("jwt-secret"), "vc+jwt", jwt.MapClaims{
		"iss": "https://issuer.example",
		"vc": map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"credentialSubject": map[string]interface{}{
				"id": "did:key:z6Mkexampleholder",
			},
		},
	})

	parsed, err := registry.ParseAnyCredential(credential)
	if err != nil {
		t.Fatalf("ParseAnyCredential(jwt-vc subject fallback): %v", err)
	}
	if parsed.Subject != "did:key:z6Mkexampleholder" {
		t.Fatalf("unexpected parsed subject %q", parsed.Subject)
	}
}

func TestLDPVCFormatBuildPresentationSupportsEd25519Proofs(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()
	format, ok := registry.Lookup("ldp_vc")
	if !ok {
		t.Fatalf("ldp_vc format handler not found")
	}

	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet(issuer): %v", err)
	}
	issuerJWK := intcrypto.JWKFromEd25519PublicKey(issuerKeySet.Ed25519PublicKey(), issuerKeySet.Ed25519KeyID())
	issuerDID, err := DIDJWKFromJSON(issuerJWK)
	if err != nil {
		t.Fatalf("DIDJWKFromJSON(issuer): %v", err)
	}
	holderKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet(holder): %v", err)
	}
	holderJWK := intcrypto.JWKFromEd25519PublicKey(holderKeySet.Ed25519PublicKey(), holderKeySet.Ed25519KeyID())
	holderDID, err := DIDJWKFromJSON(holderJWK)
	if err != nil {
		t.Fatalf("DIDJWKFromJSON(holder): %v", err)
	}

	credentialDocument, err := SecureDataIntegrityDocument(
		map[string]interface{}{
			"@context":     []string{vcContextV1},
			"type":         []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"issuer":       issuerDID,
			"issuanceDate": time.Now().UTC().Format(time.RFC3339),
			"credentialSubject": map[string]interface{}{
				"id":     holderDID,
				"degree": "BSc",
			},
		},
		map[string]interface{}{
			"created":            time.Now().UTC().Format(time.RFC3339),
			"proofPurpose":       "assertionMethod",
			"verificationMethod": DefaultVerificationMethodID(issuerDID),
		},
		issuerJWK,
		func(data []byte) ([]byte, error) {
			return ed25519.Sign(issuerKeySet.Ed25519PrivateKey(), data), nil
		},
	)
	if err != nil {
		t.Fatalf("SecureDataIntegrityDocument(credential): %v", err)
	}
	serializedCredential, err := json.Marshal(credentialDocument)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}

	result, err := format.BuildPresentation(PresentationBuildInput{
		Credential:               string(serializedCredential),
		Holder:                   holderDID,
		HolderPublicJWK:          holderJWK,
		HolderVerificationMethod: DefaultVerificationMethodID(holderDID),
		Audience:                 "did:example:verifier",
		Nonce:                    "nonce-123",
		ProofSigner: func(data []byte) ([]byte, error) {
			return ed25519.Sign(holderKeySet.Ed25519PrivateKey(), data), nil
		},
	})
	if err != nil {
		t.Fatalf("BuildPresentation(ldp_vc, Ed25519): %v", err)
	}
	if result.VPToken == "" {
		t.Fatalf("expected vp token")
	}

	var vpDocument map[string]interface{}
	if err := json.Unmarshal([]byte(result.VPToken), &vpDocument); err != nil {
		t.Fatalf("unmarshal vp token: %v", err)
	}
	if err := VerifyDataIntegrityPresentation(vpDocument, nil); err != nil {
		t.Fatalf("VerifyDataIntegrityPresentation: %v", err)
	}
	proof, ok := vpDocument["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected vp proof object")
	}
	if got := proof["type"]; got != dataIntegrityType {
		t.Fatalf("unexpected vp proof type %v", got)
	}
	if got := proof["cryptosuite"]; got != cryptosuiteEdDSARDFC2022 {
		t.Fatalf("unexpected vp proof cryptosuite %v", got)
	}
}

func TestLDPVCFormatBuildPresentationSupportsECDSAP256Proofs(t *testing.T) {
	registry := DefaultCredentialFormatRegistry()
	format, ok := registry.Lookup("ldp_vc")
	if !ok {
		t.Fatalf("ldp_vc format handler not found")
	}

	issuerKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet(issuer): %v", err)
	}
	issuerJWK, found := issuerKeySet.GetJWKByID(issuerKeySet.ECKeyID())
	if !found {
		t.Fatalf("issuer ec jwk is unavailable")
	}
	issuerDID, err := DIDJWKFromJSON(issuerJWK)
	if err != nil {
		t.Fatalf("DIDJWKFromJSON(issuer): %v", err)
	}

	holderKeySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet(holder): %v", err)
	}
	holderJWK, found := holderKeySet.GetJWKByID(holderKeySet.ECKeyID())
	if !found {
		t.Fatalf("holder ec jwk is unavailable")
	}
	holderDID, err := DIDJWKFromJSON(holderJWK)
	if err != nil {
		t.Fatalf("DIDJWKFromJSON(holder): %v", err)
	}

	credentialDocument, err := SecureDataIntegrityDocument(
		map[string]interface{}{
			"@context":     []string{vcContextV1},
			"type":         []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"issuer":       issuerDID,
			"issuanceDate": time.Now().UTC().Format(time.RFC3339),
			"validFrom":    time.Now().UTC().Format(time.RFC3339),
			"credentialSubject": map[string]interface{}{
				"id":     holderDID,
				"degree": "BSc",
			},
		},
		map[string]interface{}{
			"created":            time.Now().UTC().Format(time.RFC3339),
			"proofPurpose":       "assertionMethod",
			"verificationMethod": DefaultVerificationMethodID(issuerDID),
		},
		issuerJWK,
		func(data []byte) ([]byte, error) {
			digest := sha256.Sum256(data)
			r, s, err := ecdsa.Sign(rand.Reader, issuerKeySet.ECPrivateKey(), digest[:])
			if err != nil {
				return nil, err
			}
			sig := make([]byte, 64)
			rB, sB := r.Bytes(), s.Bytes()
			copy(sig[32-len(rB):32], rB)
			copy(sig[64-len(sB):], sB)
			return sig, nil
		},
	)
	if err != nil {
		t.Fatalf("SecureDataIntegrityDocument(credential): %v", err)
	}

	if err := VerifyDataIntegrityDocument(credentialDocument, []intcrypto.JWK{issuerJWK}, nil); err != nil {
		t.Fatalf("VerifyDataIntegrityDocument(credential): %v", err)
	}

	serializedCredential, err := json.Marshal(credentialDocument)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}

	result, err := format.BuildPresentation(PresentationBuildInput{
		Credential:               string(serializedCredential),
		Holder:                   holderDID,
		HolderPublicJWK:          holderJWK,
		HolderVerificationMethod: DefaultVerificationMethodID(holderDID),
		Audience:                 "did:example:verifier",
		Nonce:                    "nonce-p256",
		ProofSigner: func(data []byte) ([]byte, error) {
			digest := sha256.Sum256(data)
			r, s, err := ecdsa.Sign(rand.Reader, holderKeySet.ECPrivateKey(), digest[:])
			if err != nil {
				return nil, err
			}
			sig := make([]byte, 64)
			rB, sB := r.Bytes(), s.Bytes()
			copy(sig[32-len(rB):32], rB)
			copy(sig[64-len(sB):], sB)
			return sig, nil
		},
	})
	if err != nil {
		t.Fatalf("BuildPresentation(ldp_vc, ECDSA P-256): %v", err)
	}
	if result.VPToken == "" {
		t.Fatalf("expected vp token")
	}

	var vpDocument map[string]interface{}
	if err := json.Unmarshal([]byte(result.VPToken), &vpDocument); err != nil {
		t.Fatalf("unmarshal vp token: %v", err)
	}
	if err := VerifyDataIntegrityPresentation(vpDocument, nil); err != nil {
		t.Fatalf("VerifyDataIntegrityPresentation: %v", err)
	}
	proof, ok := vpDocument["proof"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected vp proof object")
	}
	if got := proof["type"]; got != dataIntegrityType {
		t.Fatalf("unexpected vp proof type %v", got)
	}
	if got := proof["cryptosuite"]; got != cryptosuiteEcdsaRDFC2019 {
		t.Fatalf("unexpected vp proof cryptosuite %v", got)
	}
}

func TestLDPVCFormatBuildPresentationSupportsECDSAP384Proofs(t *testing.T) {
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	issuerJWK := intcrypto.JWKFromECPublicKey(&p384Key.PublicKey, "issuer-p384")
	issuerDID, err := DIDJWKFromJSON(issuerJWK)
	if err != nil {
		t.Fatalf("DIDJWKFromJSON(issuer): %v", err)
	}

	holderP384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder P-384 key: %v", err)
	}
	holderJWK := intcrypto.JWKFromECPublicKey(&holderP384Key.PublicKey, "holder-p384")
	holderDID, err := DIDJWKFromJSON(holderJWK)
	if err != nil {
		t.Fatalf("DIDJWKFromJSON(holder): %v", err)
	}

	p384Sign := func(key *ecdsa.PrivateKey) func([]byte) ([]byte, error) {
		return func(data []byte) ([]byte, error) {
			digest := sha512.Sum384(data)
			r, s, signErr := ecdsa.Sign(rand.Reader, key, digest[:])
			if signErr != nil {
				return nil, signErr
			}
			sig := make([]byte, 96)
			rB, sB := r.Bytes(), s.Bytes()
			copy(sig[48-len(rB):48], rB)
			copy(sig[96-len(sB):], sB)
			return sig, nil
		}
	}

	credentialDocument, err := SecureDataIntegrityDocument(
		map[string]interface{}{
			"@context":     []string{vcContextV1},
			"type":         []string{"VerifiableCredential", "UniversityDegreeCredential"},
			"issuer":       issuerDID,
			"issuanceDate": time.Now().UTC().Format(time.RFC3339),
			"credentialSubject": map[string]interface{}{
				"id":     holderDID,
				"degree": "MSc",
			},
		},
		map[string]interface{}{
			"created":            time.Now().UTC().Format(time.RFC3339),
			"proofPurpose":       "assertionMethod",
			"verificationMethod": DefaultVerificationMethodID(issuerDID),
		},
		issuerJWK,
		p384Sign(p384Key),
	)
	if err != nil {
		t.Fatalf("SecureDataIntegrityDocument(P-384 credential): %v", err)
	}

	if err := VerifyDataIntegrityDocument(credentialDocument, []intcrypto.JWK{issuerJWK}, nil); err != nil {
		t.Fatalf("VerifyDataIntegrityDocument(P-384 credential): %v", err)
	}

	serialized, err := json.Marshal(credentialDocument)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}

	registry := DefaultCredentialFormatRegistry()
	format, ok := registry.Lookup("ldp_vc")
	if !ok {
		t.Fatalf("ldp_vc format handler not found")
	}
	vpResult, err := format.BuildPresentation(PresentationBuildInput{
		Credential:               string(serialized),
		Holder:                   holderDID,
		HolderPublicJWK:          holderJWK,
		HolderVerificationMethod: DefaultVerificationMethodID(holderDID),
		Audience:                 "did:example:verifier",
		Nonce:                    "nonce-p384",
		ProofSigner:              p384Sign(holderP384Key),
	})
	if err != nil {
		t.Fatalf("BuildPresentation(ldp_vc, ECDSA P-384): %v", err)
	}

	var vpDocument map[string]interface{}
	if err := json.Unmarshal([]byte(vpResult.VPToken), &vpDocument); err != nil {
		t.Fatalf("unmarshal vp token: %v", err)
	}
	if err := VerifyDataIntegrityPresentation(vpDocument, nil); err != nil {
		t.Fatalf("VerifyDataIntegrityPresentation(P-384): %v", err)
	}
}

func signedTestJWT(t *testing.T, method jwt.SigningMethod, key interface{}, typ string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["typ"] = typ
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString(%s): %v", method.Alg(), err)
	}
	return signed
}
