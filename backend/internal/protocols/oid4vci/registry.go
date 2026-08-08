package oid4vci

import (
	"sort"
	"strings"
)

const (
	// defaultCredentialConfigurationID is the issuer's default and lead
	// credential configuration. The default is the ISO/IEC
	// 18013-5 mobile driving licence (mso_mdoc): an offer or credential request
	// that does not name a configuration receives the mDL. SD-JWT VC and the
	// W3C formats remain fully supported and selectable by naming their
	// configuration explicitly.
	defaultCredentialConfigurationID = "MobileDrivingLicenceMsoMdoc"
	// universityDegreeVCT and universityDegreeScope are the VCT and scope shared
	// by the (now non-default) university-degree SD-JWT VC, JWT VC, JWT VC JSON-LD
	// and LDP VC configurations.
	universityDegreeVCT   = "https://protocolsoup.com/credentials/university_degree"
	universityDegreeScope = "vc:university_degree"
)

const (
	credentialFormatDCSdJWT    = "dc+sd-jwt"
	credentialFormatJWTVCJSON  = "jwt_vc_json"
	credentialFormatJWTVCJSONL = "jwt_vc_json-ld"
	credentialFormatLDPVC      = "ldp_vc"
	credentialFormatMsoMdoc    = "mso_mdoc"
)

const (
	// mdlDoctype is the ISO/IEC 18013-5 mobile driving licence document type.
	mdlDoctype = "org.iso.18013.5.1.mDL"
	// mdlNamespace is the ISO/IEC 18013-5 mDL namespace for data elements.
	mdlNamespace = "org.iso.18013.5.1"
)

// claimDescription is an OID4VCI 1.0 claims description object (Appendix B). For
// the mso_mdoc format the path is [namespace, elementIdentifier].
type claimDescription struct {
	Path      []string
	Mandatory bool
}

type credentialConfiguration struct {
	ID                          string
	Format                      string
	Scope                       string
	VCT                         string
	Doctype                     string
	CredentialTypes             []string
	Contexts                    []string
	Claims                      []claimDescription
	BindingMethodsSupported     []string
	ProofSigningAlgsSupported   []string
	CredentialSigningAlgs       []interface{}
	SupportedDisplayName        string
	SupportsSelectiveDisclosure bool

	// RequireKeyAttestation gates OID4VCI 1.0 Appendix D key attestation
	// enforcement (key_attestation.go) for this configuration only, so the
	// unattested Final plan configuration keeps working unchanged while a
	// distinct HAIP-flavoured configuration id can demand it.
	RequireKeyAttestation bool
	// KeyAttestationKeyStorage / KeyAttestationUserAuth are the accepted
	// key_storage / user_authentication attack-potential values (Appendix
	// D.2), advertised in key_attestations_required and enforced in
	// keyAttestationSatisfiesRequirement. Empty means "any" (only presence of
	// a valid attestation is required).
	KeyAttestationKeyStorage []string
	KeyAttestationUserAuth   []string
}

func (c credentialConfiguration) toMetadataObject() map[string]interface{} {
	metadata := map[string]interface{}{
		"format": c.Format,
	}
	if scope := strings.TrimSpace(c.Scope); scope != "" {
		metadata["scope"] = scope
	}
	if len(c.BindingMethodsSupported) > 0 {
		metadata["cryptographic_binding_methods_supported"] = append([]string{}, c.BindingMethodsSupported...)
	}
	if len(c.ProofSigningAlgsSupported) > 0 {
		jwtProofMetadata := map[string]interface{}{
			"proof_signing_alg_values_supported": append([]string{}, c.ProofSigningAlgsSupported...),
		}
		if c.RequireKeyAttestation {
			// OID4VCI 1.0 §5 / Appendix D: key_attestations_required MUST NOT be
			// present unless the issuer actually requires an attestation, and its
			// key_storage / user_authentication members are only included when
			// constrained (empty otherwise permits any attested key).
			requirement := map[string]interface{}{}
			if len(c.KeyAttestationKeyStorage) > 0 {
				requirement["key_storage"] = append([]string{}, c.KeyAttestationKeyStorage...)
			}
			if len(c.KeyAttestationUserAuth) > 0 {
				requirement["user_authentication"] = append([]string{}, c.KeyAttestationUserAuth...)
			}
			jwtProofMetadata["key_attestations_required"] = requirement
		}
		metadata["proof_types_supported"] = map[string]interface{}{
			"jwt": jwtProofMetadata,
		}
	}
	if len(c.CredentialSigningAlgs) > 0 {
		metadata["credential_signing_alg_values_supported"] = append([]interface{}{}, c.CredentialSigningAlgs...)
	}
	if vct := strings.TrimSpace(c.VCT); vct != "" {
		metadata["vct"] = vct
	}
	if doctype := strings.TrimSpace(c.Doctype); doctype != "" {
		metadata["doctype"] = doctype
	}
	if len(c.Claims) > 0 {
		claims := make([]map[string]interface{}, 0, len(c.Claims))
		for _, claim := range c.Claims {
			entry := map[string]interface{}{
				"path": append([]string{}, claim.Path...),
			}
			if claim.Mandatory {
				entry["mandatory"] = true
			}
			claims = append(claims, entry)
		}
		metadata["claims"] = claims
	}
	if len(c.CredentialTypes) > 0 || len(c.Contexts) > 0 {
		credentialDefinition := make(map[string]interface{})
		if len(c.CredentialTypes) > 0 {
			credentialDefinition["type"] = append([]string{}, c.CredentialTypes...)
		}
		if len(c.Contexts) > 0 {
			credentialDefinition["@context"] = append([]string{}, c.Contexts...)
		}
		metadata["credential_definition"] = credentialDefinition
	}
	return metadata
}

func defaultCredentialConfigurationRegistry() map[string]credentialConfiguration {
	registry := map[string]credentialConfiguration{
		"UniversityDegreeCredentialSDJWT": {
			ID:                          "UniversityDegreeCredentialSDJWT",
			Format:                      credentialFormatDCSdJWT,
			Scope:                       universityDegreeScope,
			VCT:                         universityDegreeVCT,
			CredentialTypes:             []string{"VerifiableCredential", "UniversityDegreeCredential"},
			BindingMethodsSupported:     []string{"jwk"},
			ProofSigningAlgsSupported:   []string{"RS256"},
			CredentialSigningAlgs:       []interface{}{"RS256"},
			SupportedDisplayName:        "University Degree (SD-JWT VC)",
			SupportsSelectiveDisclosure: true,
		},
		"UniversityDegreeCredentialJWT": {
			ID:                        "UniversityDegreeCredentialJWT",
			Format:                    credentialFormatJWTVCJSON,
			Scope:                     universityDegreeScope,
			VCT:                       universityDegreeVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []interface{}{"RS256"},
			SupportedDisplayName:      "University Degree (JWT VC JSON)",
		},
		"UniversityDegreeCredentialJWTLD": {
			ID:                        "UniversityDegreeCredentialJWTLD",
			Format:                    credentialFormatJWTVCJSONL,
			Scope:                     universityDegreeScope,
			VCT:                       universityDegreeVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Contexts:                  []string{"https://www.w3.org/2018/credentials/v1"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []interface{}{"RS256"},
			SupportedDisplayName:      "University Degree (JWT VC JSON-LD)",
		},
		"UniversityDegreeCredentialLDP": {
			ID:                        "UniversityDegreeCredentialLDP",
			Format:                    credentialFormatLDPVC,
			Scope:                     universityDegreeScope,
			VCT:                       universityDegreeVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Contexts:                  []string{"https://www.w3.org/2018/credentials/v1"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"ES256"},
			CredentialSigningAlgs:     []interface{}{"ES256"},
			SupportedDisplayName:      "University Degree (LDP VC profile)",
		},
		// mso_mdoc mobile driving licence (ISO/IEC 18013-5). The device key is
		// bound from the proof as a COSE_Key; IssuerAuth is signed with ES256 by
		// the document signer. OID4VCI 1.0 Appendix A.2 defines the mso_mdoc
		// configuration parameters: format, doctype, and claims by [namespace,
		// element] path.
		"MobileDrivingLicenceMsoMdoc": {
			ID:                        "MobileDrivingLicenceMsoMdoc",
			Format:                    credentialFormatMsoMdoc,
			Scope:                     "vc:mdl",
			Doctype:                   mdlDoctype,
			BindingMethodsSupported:   []string{"cose_key"},
			ProofSigningAlgsSupported: []string{"ES256"},
			CredentialSigningAlgs:     []interface{}{-7},
			SupportedDisplayName:      "Mobile Driving Licence (ISO/IEC 18013-5 mso_mdoc)",
			Claims: []claimDescription{
				{Path: []string{mdlNamespace, "family_name"}, Mandatory: true},
				{Path: []string{mdlNamespace, "given_name"}, Mandatory: true},
				{Path: []string{mdlNamespace, "birth_date"}, Mandatory: true},
				{Path: []string{mdlNamespace, "issue_date"}, Mandatory: true},
				{Path: []string{mdlNamespace, "expiry_date"}, Mandatory: true},
				{Path: []string{mdlNamespace, "issuing_country"}, Mandatory: true},
				{Path: []string{mdlNamespace, "issuing_authority"}, Mandatory: true},
				{Path: []string{mdlNamespace, "document_number"}, Mandatory: true},
				{Path: []string{mdlNamespace, "un_distinguishing_sign"}, Mandatory: true},
				{Path: []string{mdlNamespace, "driving_privileges"}, Mandatory: true},
				{Path: []string{mdlNamespace, "age_over_21"}},
			},
		},
		// HAIP-flavoured mDL configuration: identical credential content to
		// MobileDrivingLicenceMsoMdoc, but requires OID4VCI 1.0 Appendix D key
		// attestation in the jwt proof (key_attestation.go), matching the
		// non-normative key_storage/user_authentication example the spec itself
		// gives (Appendix D.1/D.2). Kept as a separate id, rather than toggling
		// the default configuration, so the already-passing unattested Final
		// plan is unaffected.
		"MobileDrivingLicenceMsoMdocHAIP": {
			ID:                        "MobileDrivingLicenceMsoMdocHAIP",
			Format:                    credentialFormatMsoMdoc,
			Scope:                     "vc:mdl",
			Doctype:                   mdlDoctype,
			BindingMethodsSupported:   []string{"cose_key"},
			ProofSigningAlgsSupported: []string{"ES256"},
			CredentialSigningAlgs:     []interface{}{-7},
			SupportedDisplayName:      "Mobile Driving Licence (ISO/IEC 18013-5 mso_mdoc, HAIP key-attested)",
			RequireKeyAttestation:     true,
			KeyAttestationKeyStorage:  []string{"iso_18045_moderate"},
			KeyAttestationUserAuth:    []string{"iso_18045_moderate"},
			Claims: []claimDescription{
				{Path: []string{mdlNamespace, "family_name"}, Mandatory: true},
				{Path: []string{mdlNamespace, "given_name"}, Mandatory: true},
				{Path: []string{mdlNamespace, "birth_date"}, Mandatory: true},
				{Path: []string{mdlNamespace, "issue_date"}, Mandatory: true},
				{Path: []string{mdlNamespace, "expiry_date"}, Mandatory: true},
				{Path: []string{mdlNamespace, "issuing_country"}, Mandatory: true},
				{Path: []string{mdlNamespace, "issuing_authority"}, Mandatory: true},
				{Path: []string{mdlNamespace, "document_number"}, Mandatory: true},
				{Path: []string{mdlNamespace, "un_distinguishing_sign"}, Mandatory: true},
				{Path: []string{mdlNamespace, "driving_privileges"}, Mandatory: true},
				{Path: []string{mdlNamespace, "age_over_21"}},
			},
		},
	}

	// Backward-compatible alias used by older clients and tests.
	registry["UniversityDegreeCredential"] = registry["UniversityDegreeCredentialSDJWT"]
	return registry
}

func credentialConfigurationsSupportedFromRegistry(registry map[string]credentialConfiguration) map[string]map[string]interface{} {
	supported := make(map[string]map[string]interface{}, len(registry))
	for id, configuration := range registry {
		supported[id] = configuration.toMetadataObject()
	}
	return supported
}

func sortedCredentialConfigurationIDs(registry map[string]credentialConfiguration) []string {
	ids := make([]string, 0, len(registry))
	for configurationID := range registry {
		trimmed := strings.TrimSpace(configurationID)
		// Skip the backward-compatible alias and the default; the default leads.
		if trimmed == "UniversityDegreeCredential" || trimmed == defaultCredentialConfigurationID {
			continue
		}
		ids = append(ids, configurationID)
	}
	sort.Strings(ids)
	// Lead with the default credential configuration (the mDL mso_mdoc),
	// so that an authorization without an explicit selection leads with mdoc.
	if _, ok := registry[defaultCredentialConfigurationID]; ok {
		ids = append([]string{defaultCredentialConfigurationID}, ids...)
	}
	return ids
}

func normalizeCredentialConfigurationIDs(rawIDs []string, registry map[string]credentialConfiguration) []string {
	seen := make(map[string]struct{}, len(rawIDs))
	normalized := make([]string, 0, len(rawIDs))
	for _, rawID := range rawIDs {
		configurationID := strings.TrimSpace(rawID)
		if configurationID == "" {
			continue
		}
		if _, exists := seen[configurationID]; exists {
			continue
		}
		if _, supported := registry[configurationID]; !supported {
			continue
		}
		seen[configurationID] = struct{}{}
		normalized = append(normalized, configurationID)
	}
	if len(normalized) == 0 {
		normalized = append(normalized, defaultCredentialConfigurationID)
	}
	return normalized
}
