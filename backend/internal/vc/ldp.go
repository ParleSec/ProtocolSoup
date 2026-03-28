package vc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/piprate/json-gold/ld"
)

const (
	vcContextV1              = "https://www.w3.org/2018/credentials/v1"
	didContextV1             = "https://www.w3.org/ns/did/v1"
	dataIntegrityContextV2   = "https://w3id.org/security/data-integrity/v2"
	ed25519Signature2020V1   = "https://w3id.org/security/suites/ed25519-2020/v1"
	dataIntegrityType        = "DataIntegrityProof"
	cryptosuiteEcdsaRDFC2019 = "ecdsa-rdfc-2019"
	cryptosuiteEdDSARDFC2022 = "eddsa-rdfc-2022"
	legacyEd25519ProofType   = "Ed25519Signature2020"
)

type ldpProofSuite struct {
	ProofType       string
	Cryptosuite     string
	RequiredContext string
	RequiredKeyType string
	Curve           string
}

type resolvedVerificationKey struct {
	PublicKey          interface{}
	PublicJWK          *intcrypto.JWK
	Curve              string
	VerificationMethod string
}

var embeddedJSONLDContextsLDP = map[string]interface{}{
	vcContextV1: mustUnmarshalJSONLDP(`{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "VerifiableCredential": {
      "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "credentialStatus": {"@id": "cred:credentialStatus", "@type": "@id"},
        "credentialSubject": {"@id": "cred:credentialSubject", "@type": "@id"},
        "evidence": {"@id": "cred:evidence", "@type": "@id"},
        "expirationDate": {"@id": "cred:expirationDate", "@type": "xsd:dateTime"},
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "issued": {"@id": "cred:issued", "@type": "xsd:dateTime"},
        "issuer": {"@id": "cred:issuer", "@type": "@id"},
        "issuanceDate": {"@id": "cred:issuanceDate", "@type": "xsd:dateTime"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "termsOfUse": {"@id": "cred:termsOfUse", "@type": "@id"},
        "validFrom": {"@id": "cred:validFrom", "@type": "xsd:dateTime"},
        "validUntil": {"@id": "cred:validUntil", "@type": "xsd:dateTime"}
      }
    },
    "VerifiablePresentation": {
      "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "cred": "https://www.w3.org/2018/credentials#",
        "sec": "https://w3id.org/security#",
        "holder": {"@id": "cred:holder", "@type": "@id"},
        "proof": {"@id": "sec:proof", "@type": "@id", "@container": "@graph"},
        "verifiableCredential": {"@id": "cred:verifiableCredential", "@type": "@id", "@container": "@graph"}
      }
    },
    "proof": {"@id": "https://w3id.org/security#proof", "@type": "@id", "@container": "@graph"}
  }
}`),
	dataIntegrityContextV2: mustUnmarshalJSONLDP(`{
  "@context": {
    "id": "@id",
    "type": "@type",
    "@protected": true,
    "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}`),
	ed25519Signature2020V1: mustUnmarshalJSONLDP(`{
  "@context": {
    "id": "@id",
    "type": "@type",
    "@protected": true,
    "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "Ed25519VerificationKey2020": {
      "@id": "https://w3id.org/security#Ed25519VerificationKey2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "controller": {
          "@id": "https://w3id.org/security#controller",
          "@type": "@id"
        },
        "publicKeyMultibase": {
          "@id": "https://w3id.org/security#publicKeyMultibase",
          "@type": "https://w3id.org/security#multibase"
        }
      }
    },
    "Ed25519Signature2020": {
      "@id": "https://w3id.org/security#Ed25519Signature2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}`),
}

// SecureDataIntegrityDocument signs a JSON-LD document and returns the secured copy.
func SecureDataIntegrityDocument(
	unsecuredDocument map[string]interface{},
	proofOptions map[string]interface{},
	publicJWK intcrypto.JWK,
	signer func(data []byte) ([]byte, error),
) (map[string]interface{}, error) {
	if len(unsecuredDocument) == 0 {
		return nil, fmt.Errorf("unsecured document is required")
	}
	if len(proofOptions) == 0 {
		return nil, fmt.Errorf("proof options are required")
	}
	if signer == nil {
		return nil, fmt.Errorf("proof signer is required")
	}

	suite, err := proofSuiteFromOptions(proofOptions, publicJWK)
	if err != nil {
		return nil, err
	}

	document := cloneJSONMapLDP(unsecuredDocument)
	delete(document, "proof")
	document["@context"] = mergeJSONLDContexts(document["@context"], suite.RequiredContext)

	proof := cloneJSONMapLDP(proofOptions)
	proof["type"] = suite.ProofType
	if strings.TrimSpace(suite.Cryptosuite) != "" {
		proof["cryptosuite"] = suite.Cryptosuite
	} else {
		delete(proof, "cryptosuite")
	}
	if err := validateProofMetadataLDP(proof, ""); err != nil {
		return nil, err
	}
	proof["@context"] = cloneJSONValueLDP(document["@context"])

	transformedDocument, err := canonicalizeJSONLDDocument(document, nil)
	if err != nil {
		return nil, fmt.Errorf("canonicalize unsecured document: %w", err)
	}
	canonicalProofConfig, err := canonicalizeJSONLDDocument(proof, nil)
	if err != nil {
		return nil, fmt.Errorf("canonicalize proof configuration: %w", err)
	}

	hashData, err := ldpHashData(suite, transformedDocument, canonicalProofConfig, curveForJWK(publicJWK))
	if err != nil {
		return nil, err
	}
	proofBytes, err := signer(hashData)
	if err != nil {
		return nil, err
	}
	proof["proofValue"] = multibaseBase58EncodeLDP(proofBytes)
	delete(proof, "@context")

	securedDocument := cloneJSONMapLDP(document)
	securedDocument["proof"] = proof
	return securedDocument, nil
}

// VerifyDataIntegrityDocument verifies a supported JSON-LD Data Integrity proof.
func VerifyDataIntegrityDocument(
	securedDocument map[string]interface{},
	issuerKeys []intcrypto.JWK,
	httpClient *http.Client,
) error {
	return verifyDataIntegrityDocument(securedDocument, issuerKeys, httpClient, "assertionMethod")
}

// VerifyDataIntegrityPresentation verifies a supported JSON-LD VP proof.
func VerifyDataIntegrityPresentation(
	securedDocument map[string]interface{},
	httpClient *http.Client,
) error {
	return verifyDataIntegrityDocument(securedDocument, nil, httpClient, "authentication")
}

func verifyDataIntegrityDocument(
	securedDocument map[string]interface{},
	issuerKeys []intcrypto.JWK,
	httpClient *http.Client,
	expectedProofPurpose string,
) error {
	if len(securedDocument) == 0 {
		return fmt.Errorf("secured document is required")
	}

	proofs, err := proofObjectsFromValue(securedDocument["proof"])
	if err != nil {
		return err
	}
	if len(proofs) == 0 {
		return fmt.Errorf("secured document is missing proof")
	}

	unsecuredDocument := cloneJSONMapLDP(securedDocument)
	delete(unsecuredDocument, "proof")
	var lastErr error

	for _, originalProof := range proofs {
		suite, err := proofSuiteFromMap(originalProof)
		if err != nil {
			lastErr = err
			continue
		}
		if err := validateProofMetadataLDP(originalProof, expectedProofPurpose); err != nil {
			lastErr = err
			continue
		}
		proofValue := strings.TrimSpace(asString(originalProof["proofValue"]))
		if proofValue == "" {
			lastErr = fmt.Errorf("data integrity proof is missing proofValue")
			continue
		}
		proofBytes, err := multibaseBase58DecodeLDP(proofValue)
		if err != nil {
			lastErr = err
			continue
		}

		proofConfig := cloneJSONMapLDP(originalProof)
		delete(proofConfig, "proofValue")
		proofConfig["@context"] = cloneJSONValueLDP(unsecuredDocument["@context"])

		transformedDocument, err := canonicalizeJSONLDDocument(unsecuredDocument, httpClient)
		if err != nil {
			lastErr = fmt.Errorf("canonicalize unsecured document: %w", err)
			continue
		}
		canonicalProofConfig, err := canonicalizeJSONLDDocument(proofConfig, httpClient)
		if err != nil {
			lastErr = fmt.Errorf("canonicalize proof configuration: %w", err)
			continue
		}

		candidates, err := resolveVerificationKeysForProof(originalProof, issuerKeys, httpClient)
		if err != nil {
			lastErr = err
			continue
		}
		if len(candidates) == 0 {
			lastErr = fmt.Errorf("no verification keys are available for proof")
			continue
		}

		for _, candidate := range candidates {
			if !isVerificationKeyCompatible(suite, candidate) {
				continue
			}
			hashData, err := ldpHashData(suite, transformedDocument, canonicalProofConfig, candidate.Curve)
			if err != nil {
				lastErr = err
				continue
			}
			if err := verifyDataIntegritySignature(suite, hashData, proofBytes, candidate.PublicKey); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("document does not contain a supported data integrity proof")
	}
	return lastErr
}

func buildDataIntegrityPresentation(parsed *ParsedCredential, input PresentationBuildInput) (*PresentationBuildResult, error) {
	if parsed == nil {
		return nil, fmt.Errorf("parsed credential is required")
	}
	if input.ProofSigner == nil {
		return nil, fmt.Errorf("presentation proof signer is required")
	}
	holder := strings.TrimSpace(input.Holder)
	if holder == "" {
		return nil, fmt.Errorf("presentation holder is required")
	}

	var credentialDocument map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(parsed.Original)), &credentialDocument); err != nil {
		return nil, fmt.Errorf("decode ldp_vc credential: %w", err)
	}

	suite, err := proofSuiteForJWK(input.HolderPublicJWK)
	if err != nil {
		return nil, err
	}
	verificationMethod := strings.TrimSpace(input.HolderVerificationMethod)
	if verificationMethod == "" {
		verificationMethod = DefaultVerificationMethodID(holder)
	}
	if verificationMethod == "" {
		return nil, fmt.Errorf("holder verification method is required for ldp_vc presentation")
	}

	vpDocument := map[string]interface{}{
		"@context":             mergeJSONLDContexts(credentialDocument["@context"], vcContextV1),
		"type":                 []interface{}{"VerifiablePresentation"},
		"holder":               holder,
		"verifiableCredential": []interface{}{credentialDocument},
	}
	proof := map[string]interface{}{
		"type":               suite.ProofType,
		"created":            time.Now().UTC().Format(time.RFC3339),
		"verificationMethod": verificationMethod,
		"proofPurpose":       "authentication",
	}
	if strings.TrimSpace(suite.Cryptosuite) != "" {
		proof["cryptosuite"] = suite.Cryptosuite
	}
	if audience := strings.TrimSpace(input.Audience); audience != "" {
		proof["domain"] = audience
	}
	if nonce := strings.TrimSpace(input.Nonce); nonce != "" {
		proof["challenge"] = nonce
	}

	securedPresentation, err := SecureDataIntegrityDocument(vpDocument, proof, input.HolderPublicJWK, input.ProofSigner)
	if err != nil {
		return nil, err
	}
	serialized, err := json.Marshal(securedPresentation)
	if err != nil {
		return nil, fmt.Errorf("marshal ldp_vp: %w", err)
	}
	return &PresentationBuildResult{
		VPToken:          string(serialized),
		CredentialFormat: parsed.Format,
	}, nil
}

func validateDataIntegrityCredential(parsed *ParsedCredential, input CredentialValidationInput) error {
	if parsed == nil {
		return fmt.Errorf("parsed credential is required")
	}
	var securedDocument map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(parsed.Original)), &securedDocument); err != nil {
		return fmt.Errorf("decode ldp_vc credential: %w", err)
	}
	return VerifyDataIntegrityDocument(securedDocument, input.IssuerKeys, input.HTTPClient)
}

// DefaultVerificationMethodID returns the default verification method fragment for a DID.
func DefaultVerificationMethodID(did string) string {
	normalized := strings.TrimSpace(did)
	switch {
	case strings.HasPrefix(normalized, "did:key:"):
		return normalized + "#" + strings.TrimPrefix(normalized, "did:key:")
	case strings.HasPrefix(normalized, "did:jwk:"):
		return normalized + "#0"
	case strings.HasPrefix(normalized, "did:web:"):
		return normalized + "#keys-1"
	case normalized != "":
		return normalized + "#keys-1"
	default:
		return ""
	}
}

func jsonLDCredentialIssuer(raw interface{}) string {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed)
	case map[string]interface{}:
		return strings.TrimSpace(asString(typed["id"]))
	default:
		return ""
	}
}

func proofSuiteForJWK(jwk intcrypto.JWK) (ldpProofSuite, error) {
	switch strings.TrimSpace(jwk.Kty) {
	case "OKP":
		if strings.TrimSpace(jwk.Crv) != "Ed25519" {
			return ldpProofSuite{}, fmt.Errorf("unsupported OKP curve %q for ldp_vc proofs", jwk.Crv)
		}
		return ldpProofSuite{
			ProofType:       dataIntegrityType,
			Cryptosuite:     cryptosuiteEdDSARDFC2022,
			RequiredContext: dataIntegrityContextV2,
			RequiredKeyType: "OKP",
			Curve:           "Ed25519",
		}, nil
	case "EC":
		switch strings.TrimSpace(jwk.Crv) {
		case "P-256", "P-384":
			return ldpProofSuite{
				ProofType:       dataIntegrityType,
				Cryptosuite:     cryptosuiteEcdsaRDFC2019,
				RequiredContext: dataIntegrityContextV2,
				RequiredKeyType: "EC",
				Curve:           strings.TrimSpace(jwk.Crv),
			}, nil
		default:
			return ldpProofSuite{}, fmt.Errorf("unsupported EC curve %q for ldp_vc proofs", jwk.Crv)
		}
	default:
		return ldpProofSuite{}, fmt.Errorf("wallet key type %q cannot build ldp_vc proofs", jwk.Kty)
	}
}

func proofSuiteFromOptions(proofOptions map[string]interface{}, publicJWK intcrypto.JWK) (ldpProofSuite, error) {
	if len(proofOptions) == 0 {
		return proofSuiteForJWK(publicJWK)
	}
	if strings.TrimSpace(asString(proofOptions["type"])) == "" {
		suite, err := proofSuiteForJWK(publicJWK)
		if err != nil {
			return ldpProofSuite{}, err
		}
		return suite, nil
	}
	return proofSuiteFromMap(proofOptions)
}

func proofSuiteFromMap(proof map[string]interface{}) (ldpProofSuite, error) {
	proofType := strings.TrimSpace(asString(proof["type"]))
	cryptosuite := strings.TrimSpace(asString(proof["cryptosuite"]))
	switch {
	case proofType == legacyEd25519ProofType:
		return ldpProofSuite{
			ProofType:       legacyEd25519ProofType,
			RequiredContext: ed25519Signature2020V1,
			RequiredKeyType: "OKP",
			Curve:           "Ed25519",
		}, nil
	case proofType == dataIntegrityType && cryptosuite == cryptosuiteEcdsaRDFC2019:
		return ldpProofSuite{
			ProofType:       dataIntegrityType,
			Cryptosuite:     cryptosuiteEcdsaRDFC2019,
			RequiredContext: dataIntegrityContextV2,
			RequiredKeyType: "EC",
		}, nil
	case proofType == dataIntegrityType && cryptosuite == cryptosuiteEdDSARDFC2022:
		return ldpProofSuite{
			ProofType:       dataIntegrityType,
			Cryptosuite:     cryptosuiteEdDSARDFC2022,
			RequiredContext: dataIntegrityContextV2,
			RequiredKeyType: "OKP",
			Curve:           "Ed25519",
		}, nil
	default:
		return ldpProofSuite{}, fmt.Errorf("unsupported ldp_vc proof type %q cryptosuite %q", proofType, cryptosuite)
	}
}

func validateProofMetadataLDP(proof map[string]interface{}, expectedProofPurpose string) error {
	if len(proof) == 0 {
		return fmt.Errorf("ldp_vc proof is required")
	}
	if created := strings.TrimSpace(asString(proof["created"])); created != "" {
		if _, err := time.Parse(time.RFC3339, created); err != nil {
			return fmt.Errorf("ldp_vc proof created is invalid: %w", err)
		}
	}
	proofPurpose := strings.TrimSpace(asString(proof["proofPurpose"]))
	if proofPurpose == "" {
		return fmt.Errorf("ldp_vc proof is missing proofPurpose")
	}
	if strings.TrimSpace(expectedProofPurpose) != "" && proofPurpose != strings.TrimSpace(expectedProofPurpose) {
		return fmt.Errorf("ldp_vc proofPurpose must be %s", strings.TrimSpace(expectedProofPurpose))
	}
	switch typed := proof["verificationMethod"].(type) {
	case string:
		if strings.TrimSpace(typed) == "" {
			return fmt.Errorf("ldp_vc proof is missing verificationMethod")
		}
	case map[string]interface{}:
		if strings.TrimSpace(asString(typed["id"])) == "" {
			return fmt.Errorf("ldp_vc proof is missing verificationMethod")
		}
	default:
		return fmt.Errorf("ldp_vc proof is missing verificationMethod")
	}
	return nil
}

func ldpHashData(suite ldpProofSuite, transformedDocument string, canonicalProofConfig string, curve string) ([]byte, error) {
	switch {
	case suite.RequiredKeyType == "OKP" || curve == "Ed25519":
		proofConfigHash := sha256.Sum256([]byte(canonicalProofConfig))
		transformedDocumentHash := sha256.Sum256([]byte(transformedDocument))
		hashData := make([]byte, 0, len(proofConfigHash)+len(transformedDocumentHash))
		hashData = append(hashData, proofConfigHash[:]...)
		hashData = append(hashData, transformedDocumentHash[:]...)
		return hashData, nil
	case curve == "P-256":
		proofConfigHash := sha256.Sum256([]byte(canonicalProofConfig))
		transformedDocumentHash := sha256.Sum256([]byte(transformedDocument))
		hashData := make([]byte, 0, len(proofConfigHash)+len(transformedDocumentHash))
		hashData = append(hashData, proofConfigHash[:]...)
		hashData = append(hashData, transformedDocumentHash[:]...)
		return hashData, nil
	case curve == "P-384":
		proofConfigHash := sha512.Sum384([]byte(canonicalProofConfig))
		transformedDocumentHash := sha512.Sum384([]byte(transformedDocument))
		hashData := make([]byte, 0, len(proofConfigHash)+len(transformedDocumentHash))
		hashData = append(hashData, proofConfigHash[:]...)
		hashData = append(hashData, transformedDocumentHash[:]...)
		return hashData, nil
	default:
		return nil, fmt.Errorf("unsupported proof curve %q", curve)
	}
}

func verifyDataIntegritySignature(suite ldpProofSuite, hashData []byte, proofBytes []byte, publicKey interface{}) error {
	switch suite.RequiredKeyType {
	case "OKP":
		edKey, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("proof verification key has type %T, expected ed25519.PublicKey", publicKey)
		}
		if !ed25519.Verify(edKey, hashData, proofBytes) {
			return fmt.Errorf("ed25519 data integrity proof verification failed")
		}
		return nil
	case "EC":
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("proof verification key has type %T, expected *ecdsa.PublicKey", publicKey)
		}
		componentSize := 32
		if ecKey.Curve != nil && ecKey.Curve.Params() != nil {
			componentSize = (ecKey.Curve.Params().BitSize + 7) / 8
		}
		if len(proofBytes) != componentSize*2 {
			return fmt.Errorf("ecdsa proofValue length %d does not match curve size %d", len(proofBytes), componentSize*2)
		}
		r := new(big.Int).SetBytes(proofBytes[:componentSize])
		s := new(big.Int).SetBytes(proofBytes[componentSize:])
		var digest []byte
		switch componentSize {
		case 48:
			d := sha512.Sum384(hashData)
			digest = d[:]
		default:
			d := sha256.Sum256(hashData)
			digest = d[:]
		}
		if !ecdsa.Verify(ecKey, digest, r, s) {
			return fmt.Errorf("ecdsa data integrity proof verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported proof key type %q", suite.RequiredKeyType)
	}
}

func canonicalizeJSONLDDocument(document interface{}, httpClient *http.Client) (string, error) {
	processor := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.Algorithm = ld.AlgorithmURDNA2015
	options.Format = "application/n-quads"
	options.DocumentLoader = newLDPDocumentLoader(httpClient)
	normalized, err := processor.Normalize(document, options)
	if err != nil {
		return "", err
	}
	normalizedString, ok := normalized.(string)
	if !ok {
		return "", fmt.Errorf("json-ld normalization returned %T, expected string", normalized)
	}
	return normalizedString, nil
}

func resolveVerificationKeysForProof(
	proof map[string]interface{},
	issuerKeys []intcrypto.JWK,
	httpClient *http.Client,
) ([]resolvedVerificationKey, error) {
	candidates := make([]resolvedVerificationKey, 0, len(issuerKeys)+1)
	for _, issuerKey := range issuerKeys {
		resolved, err := resolvedVerificationKeyFromJWK(issuerKey)
		if err != nil {
			continue
		}
		candidates = append(candidates, resolved)
	}

	resolvedFromMethod, err := resolveVerificationKeysFromMethod(proof["verificationMethod"], httpClient)
	if err != nil && len(candidates) == 0 {
		return nil, err
	}
	candidates = append(candidates, resolvedFromMethod...)
	return candidates, nil
}

// ResolveVerificationMethodJWKs resolves the public JWKs referenced by a verification method.
func ResolveVerificationMethodJWKs(raw interface{}, httpClient *http.Client) ([]intcrypto.JWK, error) {
	resolved, err := resolveVerificationKeysFromMethod(raw, httpClient)
	if err != nil {
		return nil, err
	}
	jwks := make([]intcrypto.JWK, 0, len(resolved))
	for _, candidate := range resolved {
		if candidate.PublicJWK == nil {
			continue
		}
		jwks = append(jwks, *candidate.PublicJWK)
	}
	if len(jwks) == 0 {
		return nil, fmt.Errorf("verificationMethod did not resolve to a public jwk")
	}
	return jwks, nil
}

func resolveVerificationKeysFromMethod(raw interface{}, httpClient *http.Client) ([]resolvedVerificationKey, error) {
	switch typed := raw.(type) {
	case map[string]interface{}:
		resolved, err := resolvedVerificationKeyFromMethodObject(typed)
		if err != nil {
			return nil, err
		}
		return []resolvedVerificationKey{resolved}, nil
	case string:
		return resolveVerificationKeysFromMethodID(strings.TrimSpace(typed), httpClient)
	default:
		return nil, fmt.Errorf("unsupported verificationMethod type %T", raw)
	}
}

func resolveVerificationKeysFromMethodID(methodID string, httpClient *http.Client) ([]resolvedVerificationKey, error) {
	normalized := strings.TrimSpace(methodID)
	if normalized == "" {
		return nil, fmt.Errorf("verificationMethod is required")
	}

	switch {
	case strings.HasPrefix(normalized, "did:key:"):
		baseDID := normalized
		if idx := strings.Index(baseDID, "#"); idx >= 0 {
			baseDID = baseDID[:idx]
		}
		encoded := strings.TrimPrefix(baseDID, "did:key:")
		publicKey, kty, err := DecodeMultibaseMulticodecKey(encoded)
		if err != nil {
			return nil, err
		}
		publicJWK, err := jwkFromPublicKeyLDP(publicKey, "")
		if err != nil {
			return nil, err
		}
		return []resolvedVerificationKey{{
			PublicKey:          publicKey,
			PublicJWK:          publicJWK,
			Curve:              curveFromPublicKey(publicKey, kty),
			VerificationMethod: DefaultVerificationMethodID(baseDID),
		}}, nil
	case strings.HasPrefix(normalized, "did:jwk:"):
		jwk, err := decodeDIDJWK(normalized)
		if err != nil {
			return nil, err
		}
		resolved, err := resolvedVerificationKeyFromJWK(jwk)
		if err != nil {
			return nil, err
		}
		resolved.VerificationMethod = DefaultVerificationMethodID(strings.Split(normalized, "#")[0])
		return []resolvedVerificationKey{resolved}, nil
	case strings.HasPrefix(normalized, "did:web:"):
		return resolveDidWebVerificationKey(normalized, httpClient)
	case strings.HasPrefix(normalized, "http://"), strings.HasPrefix(normalized, "https://"):
		return resolveHTTPVerificationKey(normalized, httpClient)
	default:
		return nil, fmt.Errorf("unsupported verificationMethod %q", normalized)
	}
}

func resolveDidWebVerificationKey(methodID string, httpClient *http.Client) ([]resolvedVerificationKey, error) {
	baseDID := methodID
	if idx := strings.Index(baseDID, "#"); idx >= 0 {
		baseDID = baseDID[:idx]
	}
	documentURL, err := didWebDocumentURLForLDP(baseDID)
	if err != nil {
		return nil, err
	}
	document, err := fetchJSONDocumentLDP(documentURL, httpClient)
	if err != nil {
		return nil, err
	}
	methodObject := resolveVerificationMethodObjectLDP(document, methodID)
	if methodObject == nil {
		return nil, fmt.Errorf("did:web document does not contain verificationMethod %q", methodID)
	}
	resolved, err := resolvedVerificationKeyFromMethodObject(methodObject)
	if err != nil {
		return nil, err
	}
	resolved.VerificationMethod = strings.TrimSpace(methodID)
	return []resolvedVerificationKey{resolved}, nil
}

func resolveHTTPVerificationKey(methodID string, httpClient *http.Client) ([]resolvedVerificationKey, error) {
	parsed, err := url.Parse(methodID)
	if err != nil {
		return nil, err
	}
	documentURL := methodID
	if parsed.Fragment != "" {
		parsed.Fragment = ""
		documentURL = parsed.String()
	}
	document, err := fetchJSONDocumentLDP(documentURL, httpClient)
	if err != nil {
		return nil, err
	}
	if parsed.Fragment != "" {
		methodObject := resolveVerificationMethodObjectLDP(document, methodID)
		if methodObject == nil {
			return nil, fmt.Errorf("verification method %q was not found in %q", methodID, documentURL)
		}
		resolved, err := resolvedVerificationKeyFromMethodObject(methodObject)
		if err != nil {
			return nil, err
		}
		resolved.VerificationMethod = strings.TrimSpace(methodID)
		return []resolvedVerificationKey{resolved}, nil
	}
	resolved, err := resolvedVerificationKeyFromMethodObject(document)
	if err != nil {
		return nil, err
	}
	resolved.VerificationMethod = strings.TrimSpace(methodID)
	return []resolvedVerificationKey{resolved}, nil
}

func resolvedVerificationKeyFromMethodObject(method map[string]interface{}) (resolvedVerificationKey, error) {
	if jwkRaw, ok := method["publicKeyJwk"]; ok {
		jwkBytes, err := json.Marshal(jwkRaw)
		if err != nil {
			return resolvedVerificationKey{}, err
		}
		var jwk intcrypto.JWK
		if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
			return resolvedVerificationKey{}, err
		}
		return resolvedVerificationKeyFromJWK(jwk)
	}
	if multibaseRaw := strings.TrimSpace(asString(method["publicKeyMultibase"])); multibaseRaw != "" {
		publicKey, kty, err := DecodeMultibaseMulticodecKey(multibaseRaw)
		if err != nil {
			return resolvedVerificationKey{}, err
		}
		publicJWK, err := jwkFromPublicKeyLDP(publicKey, strings.TrimSpace(asString(method["id"])))
		if err != nil {
			return resolvedVerificationKey{}, err
		}
		return resolvedVerificationKey{
			PublicKey: publicKey,
			PublicJWK: publicJWK,
			Curve:     curveFromPublicKey(publicKey, kty),
		}, nil
	}
	return resolvedVerificationKey{}, fmt.Errorf("verification method is missing publicKeyJwk/publicKeyMultibase")
}

func resolvedVerificationKeyFromJWK(jwk intcrypto.JWK) (resolvedVerificationKey, error) {
	publicKey, err := jwk.ToPublicKey()
	if err != nil {
		return resolvedVerificationKey{}, err
	}
	jwkCopy := jwk
	return resolvedVerificationKey{
		PublicKey: publicKey,
		PublicJWK: &jwkCopy,
		Curve:     curveForJWK(jwk),
	}, nil
}

func isVerificationKeyCompatible(suite ldpProofSuite, candidate resolvedVerificationKey) bool {
	switch suite.RequiredKeyType {
	case "OKP":
		return candidate.Curve == "Ed25519"
	case "EC":
		return candidate.Curve == "P-256" || candidate.Curve == "P-384"
	default:
		return false
	}
}

func proofObjectsFromValue(raw interface{}) ([]map[string]interface{}, error) {
	switch typed := raw.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{typed}, nil
	case []interface{}:
		proofs := make([]map[string]interface{}, 0, len(typed))
		for _, item := range typed {
			proofMap, ok := item.(map[string]interface{})
			if ok {
				proofs = append(proofs, proofMap)
			}
		}
		return proofs, nil
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported proof type %T", raw)
	}
}

func resolveVerificationMethodObjectLDP(document map[string]interface{}, methodID string) map[string]interface{} {
	if len(document) == 0 {
		return nil
	}
	if strings.TrimSpace(asString(document["id"])) == strings.TrimSpace(methodID) {
		return document
	}
	methods, _ := document["verificationMethod"].([]interface{})
	for _, rawMethod := range methods {
		methodObject, ok := rawMethod.(map[string]interface{})
		if ok && strings.TrimSpace(asString(methodObject["id"])) == strings.TrimSpace(methodID) {
			return methodObject
		}
	}
	for _, relationship := range []string{"authentication", "assertionMethod"} {
		rawRelationship, _ := document[relationship].([]interface{})
		for _, rawMethod := range rawRelationship {
			methodObject, ok := rawMethod.(map[string]interface{})
			if ok && strings.TrimSpace(asString(methodObject["id"])) == strings.TrimSpace(methodID) {
				return methodObject
			}
			if ref, ok := rawMethod.(string); ok && strings.TrimSpace(ref) == strings.TrimSpace(methodID) {
				return resolveVerificationMethodObjectLDP(document, ref)
			}
		}
	}
	return nil
}

func fetchJSONDocumentLDP(documentURL string, httpClient *http.Client) (map[string]interface{}, error) {
	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequest(http.MethodGet, documentURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/did+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verification method fetch returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func newLDPDocumentLoader(httpClient *http.Client) ld.DocumentLoader {
	loader := ld.NewCachingDocumentLoader(ld.NewDefaultDocumentLoader(httpClient))
	for documentURL, document := range embeddedJSONLDContextsLDP {
		loader.AddDocument(documentURL, cloneJSONValueLDP(document))
	}
	return loader
}

func didWebDocumentURLForLDP(did string) (string, error) {
	normalized := strings.TrimSpace(did)
	if !strings.HasPrefix(normalized, "did:web:") {
		return "", fmt.Errorf("did %q is not did:web", did)
	}
	identifier := strings.TrimPrefix(normalized, "did:web:")
	if identifier == "" {
		return "", fmt.Errorf("did:web identifier is empty")
	}
	segments := strings.Split(identifier, ":")
	host, err := url.PathUnescape(strings.TrimSpace(segments[0]))
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", fmt.Errorf("did:web host is empty")
	}
	if len(segments) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	pathSegments := make([]string, 0, len(segments)-1)
	for _, rawSegment := range segments[1:] {
		segment, err := url.PathUnescape(strings.TrimSpace(rawSegment))
		if err != nil {
			return "", err
		}
		if segment == "" {
			continue
		}
		pathSegments = append(pathSegments, segment)
	}
	if len(pathSegments) == 0 {
		return "https://" + host + "/.well-known/did.json", nil
	}
	return "https://" + host + "/" + strings.Join(pathSegments, "/") + "/did.json", nil
}

func decodeDIDJWK(did string) (intcrypto.JWK, error) {
	normalized := strings.TrimSpace(did)
	if idx := strings.Index(normalized, "#"); idx >= 0 {
		normalized = normalized[:idx]
	}
	if !strings.HasPrefix(normalized, "did:jwk:") {
		return intcrypto.JWK{}, fmt.Errorf("unsupported did:jwk value %q", did)
	}
	encoded := strings.TrimPrefix(normalized, "did:jwk:")
	rawJWK, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return intcrypto.JWK{}, fmt.Errorf("decode did:jwk: %w", err)
	}
	var jwk intcrypto.JWK
	if err := json.Unmarshal(rawJWK, &jwk); err != nil {
		return intcrypto.JWK{}, fmt.Errorf("unmarshal did:jwk public key: %w", err)
	}
	jwk.D = ""
	return jwk, nil
}

func jwkFromPublicKeyLDP(publicKey interface{}, kid string) (*intcrypto.JWK, error) {
	switch typed := publicKey.(type) {
	case *ecdsa.PublicKey:
		jwk := intcrypto.JWKFromECPublicKey(typed, kid)
		return &jwk, nil
	case ed25519.PublicKey:
		jwk := intcrypto.JWKFromEd25519PublicKey(typed, kid)
		return &jwk, nil
	case *rsa.PublicKey:
		jwk := intcrypto.JWKFromRSAPublicKey(typed, kid)
		return &jwk, nil
	default:
		return nil, fmt.Errorf("unsupported verification key type %T", publicKey)
	}
}

func curveForJWK(jwk intcrypto.JWK) string {
	switch strings.TrimSpace(jwk.Kty) {
	case "OKP":
		if strings.TrimSpace(jwk.Crv) == "Ed25519" {
			return "Ed25519"
		}
	case "EC":
		return strings.TrimSpace(jwk.Crv)
	}
	return ""
}

func curveFromPublicKey(publicKey interface{}, fallbackKTY string) string {
	switch typed := publicKey.(type) {
	case ed25519.PublicKey:
		return "Ed25519"
	case *ecdsa.PublicKey:
		if typed.Curve != nil && typed.Curve.Params() != nil {
			switch typed.Curve.Params().BitSize {
			case 256:
				return "P-256"
			case 384:
				return "P-384"
			}
		}
	}
	switch strings.TrimSpace(fallbackKTY) {
	case "OKP":
		return "Ed25519"
	case "EC":
		return "P-256"
	default:
		return ""
	}
}

func mergeJSONLDContexts(existing interface{}, extras ...string) interface{} {
	contexts := make([]interface{}, 0, 4)
	seen := make(map[string]struct{})
	var appendContext func(value interface{})
	appendContext = func(value interface{}) {
		switch typed := value.(type) {
		case nil:
			return
		case string:
			key := strings.TrimSpace(typed)
			if key == "" {
				return
			}
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			contexts = append(contexts, key)
		case []interface{}:
			for _, item := range typed {
				appendContext(item)
			}
		default:
			raw, err := json.Marshal(typed)
			if err != nil {
				return
			}
			key := string(raw)
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			contexts = append(contexts, typed)
		}
	}

	appendContext(existing)
	for _, extra := range extras {
		appendContext(extra)
	}
	return contexts
}

func multibaseBase58EncodeLDP(raw []byte) string {
	return "z" + base58btcEncode(raw)
}

func multibaseBase58DecodeLDP(encoded string) ([]byte, error) {
	normalized := strings.TrimSpace(encoded)
	if !strings.HasPrefix(normalized, "z") {
		return nil, fmt.Errorf("proofValue must be base58-btc multibase")
	}
	return base58btcDecode(strings.TrimPrefix(normalized, "z"))
}

func cloneJSONMapLDP(source map[string]interface{}) map[string]interface{} {
	if len(source) == 0 {
		return map[string]interface{}{}
	}
	cloned := make(map[string]interface{}, len(source))
	for key, value := range source {
		cloned[key] = cloneJSONValueLDP(value)
	}
	return cloned
}

func cloneJSONValueLDP(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var cloned interface{}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return value
	}
	return cloned
}

func asString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func mustUnmarshalJSONLDP(raw string) interface{} {
	var document interface{}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		panic(err)
	}
	return document
}
