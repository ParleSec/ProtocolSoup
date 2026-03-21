package oid4vci

import (
	"sort"
	"strings"
)

const (
	defaultCredentialConfigurationID = "UniversityDegreeCredential"
	defaultCredentialVCT             = "https://protocolsoup.com/credentials/university_degree"
	defaultCredentialScope           = "vc:university_degree"
)

const (
	credentialFormatDCSdJWT    = "dc+sd-jwt"
	credentialFormatMSOMDOC    = "mso_mdoc"
	credentialFormatJWTVCJSON  = "jwt_vc_json"
	credentialFormatJWTVCJSONL = "jwt_vc_json-ld"
	credentialFormatLDPVC      = "ldp_vc"
)

type credentialConfiguration struct {
	ID                          string
	Format                      string
	Scope                       string
	VCT                         string
	Doctype                     string
	CredentialTypes             []string
	Contexts                    []string
	BindingMethodsSupported     []string
	ProofSigningAlgsSupported   []string
	CredentialSigningAlgs       []string
	SupportedDisplayName        string
	SupportsSelectiveDisclosure bool
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
		metadata["proof_types_supported"] = map[string]interface{}{
			"jwt": map[string]interface{}{
				"proof_signing_alg_values_supported": append([]string{}, c.ProofSigningAlgsSupported...),
			},
		}
	}
	if len(c.CredentialSigningAlgs) > 0 {
		metadata["credential_signing_alg_values_supported"] = append([]string{}, c.CredentialSigningAlgs...)
	}
	if vct := strings.TrimSpace(c.VCT); vct != "" {
		metadata["vct"] = vct
	}
	if doctype := strings.TrimSpace(c.Doctype); doctype != "" {
		metadata["doctype"] = doctype
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
			ID:                        "UniversityDegreeCredentialSDJWT",
			Format:                    credentialFormatDCSdJWT,
			Scope:                     defaultCredentialScope,
			VCT:                       defaultCredentialVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []string{"RS256"},
			SupportedDisplayName:      "University Degree (SD-JWT VC)",
			SupportsSelectiveDisclosure: true,
		},
		"UniversityDegreeCredentialJWT": {
			ID:                        "UniversityDegreeCredentialJWT",
			Format:                    credentialFormatJWTVCJSON,
			Scope:                     defaultCredentialScope,
			VCT:                       defaultCredentialVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []string{"RS256"},
			SupportedDisplayName:      "University Degree (JWT VC JSON)",
		},
		"UniversityDegreeCredentialJWTLD": {
			ID:                        "UniversityDegreeCredentialJWTLD",
			Format:                    credentialFormatJWTVCJSONL,
			Scope:                     defaultCredentialScope,
			VCT:                       defaultCredentialVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Contexts:                  []string{"https://www.w3.org/2018/credentials/v1"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []string{"RS256"},
			SupportedDisplayName:      "University Degree (JWT VC JSON-LD)",
		},
		"UniversityDegreeCredentialLDP": {
			ID:                        "UniversityDegreeCredentialLDP",
			Format:                    credentialFormatLDPVC,
			Scope:                     defaultCredentialScope,
			VCT:                       defaultCredentialVCT,
			CredentialTypes:           []string{"VerifiableCredential", "UniversityDegreeCredential"},
			Contexts:                  []string{"https://www.w3.org/2018/credentials/v1"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []string{"RS256"},
			SupportedDisplayName:      "University Degree (LDP VC profile)",
		},
		"UniversityDegreeCredentialMDOC": {
			ID:                        "UniversityDegreeCredentialMDOC",
			Format:                    credentialFormatMSOMDOC,
			Scope:                     defaultCredentialScope,
			Doctype:                   "org.iso.18013.5.1.mDL",
			CredentialTypes:           []string{"org.iso.18013.5.1.mDL"},
			BindingMethodsSupported:   []string{"jwk"},
			ProofSigningAlgsSupported: []string{"RS256"},
			CredentialSigningAlgs:     []string{"RS256"},
			SupportedDisplayName:      "mDoc style university profile",
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
		if strings.TrimSpace(configurationID) == "UniversityDegreeCredential" {
			continue
		}
		ids = append(ids, configurationID)
	}
	sort.Strings(ids)
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

