package oid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// This file holds the OpenID4VC High Assurance Interoperability Profile
// (HAIP 1.0, Final, 24 December 2025) enforcement mode and the
// OpenID4VP-over-W3C-Digital-Credentials-API presentation path. Both are layered
// on top of the general SD-JWT VC and mdoc support, which stays available and
// unchanged outside HAIP / DC API mode.
const (
	responseModeDirectPost    = "direct_post"
	responseModeDirectPostJWT = "direct_post.jwt"
	// responseModeDCAPI / responseModeDCAPIJWT are the W3C Digital Credentials
	// API response modes (OID4VP 1.0 Appendix A.2). HAIP 1.0 Section 5.2 mandates
	// the encrypted dc_api.jwt variant for the DC API path.
	responseModeDCAPI    = "dc_api"
	responseModeDCAPIJWT = "dc_api.jwt"

	// profileHAIP marks a request session as operating under the HAIP profile.
	profileHAIP = "haip"

	// HAIP 1.0 Section 5: Verifiers MUST support and advertise both A128GCM and
	// A256GCM for response encryption (RFC 7518 Section 5.3).
	encA128GCM = "A128GCM"
	encA256GCM = "A256GCM"
)

// isDCAPIResponseMode reports whether a response_mode is one of the W3C Digital
// Credentials API modes (OID4VP 1.0 Appendix A.2).
func isDCAPIResponseMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case responseModeDCAPI, responseModeDCAPIJWT:
		return true
	default:
		return false
	}
}

// isEncryptedResponseMode reports whether a response_mode carries an encrypted
// (JWE) Authorization Response: direct_post.jwt (OID4VP Section 8.3.1) or
// dc_api.jwt (Appendix A.2 + Section 8.3).
func isEncryptedResponseMode(mode string) bool {
	switch strings.TrimSpace(mode) {
	case responseModeDirectPostJWT, responseModeDCAPIJWT:
		return true
	default:
		return false
	}
}

// dcAPIAudience returns the Origin prefixed with "origin:" as required for the
// response audience over the DC API (OID4VP 1.0 Appendix A.4). Note this is the
// audience binding only; the OpenID4VPDCAPIHandover embeds the bare Origin
// without the prefix (Appendix B.2.6.2).
func dcAPIAudience(origin string) string {
	trimmed := strings.TrimSpace(origin)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "origin:") {
		return trimmed
	}
	return "origin:" + trimmed
}

// normalizeOrigin validates and canonicalizes a Web Origin (scheme + host[:port],
// no path) for the DC API handover. The handover binds the bare Origin string,
// so producer and verifier must agree on its exact form.
func normalizeOrigin(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("origin is required for the dc_api response mode")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("origin %q must be an absolute web origin (scheme://host)", raw)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("origin %q must not include a path", raw)
	}
	// Reassemble scheme://host[:port] without a trailing slash, matching how the
	// platform reports the Verifier Origin.
	return strings.ToLower(parsed.Scheme) + "://" + parsed.Host, nil
}

// validateHAIPProfile enforces the HAIP 1.0 Section 5 presentation constraints
// at Authorization Request creation, rejecting out-of-profile choices rather
// than merely permitting conformant ones. It runs only when the request opts
// into the HAIP profile, so the general profile is unaffected.
//
// HAIP is a constraining profile (HAIP 1.0 Section 5; risk note "HAIP is a
// constraining profile, not an additive feature"): a HAIP-mode request that
// still allowed direct_post (unencrypted), a scope alias, or an out-of-profile
// client_id scheme would not be HAIP.
func validateHAIPProfile(responseMode, dcqlQuery, scopeAlias string, scheme ClientIDScheme) error {
	// HAIP 1.0 Section 5: the DCQL query and response MUST be used.
	if strings.TrimSpace(dcqlQuery) == "" {
		return fmt.Errorf("haip: dcql_query is required (HAIP 1.0 Section 5); scope alias is out of profile")
	}
	if strings.TrimSpace(scopeAlias) != "" {
		return fmt.Errorf("haip: scope alias is out of profile; HAIP requires DCQL (HAIP 1.0 Section 5)")
	}
	// HAIP 1.0 Section 5 / 5.2: response encryption MUST be performed; the only
	// in-profile response modes are direct_post.jwt (redirects) and dc_api.jwt
	// (DC API). Unencrypted direct_post / dc_api are out of profile.
	if !isEncryptedResponseMode(responseMode) {
		return fmt.Errorf("haip: response_mode %q is out of profile; HAIP requires an encrypted response (direct_post.jwt or dc_api.jwt)", responseMode)
	}
	// HAIP 1.0 Section 5: for signed requests the Client Identifier Prefix MUST
	// be x509_hash. We reject the other X.509 scheme (x509_san_dns) and the
	// unsigned-only redirect_uri scheme in HAIP mode.
	if scheme != ClientIDSchemeX509Hash {
		return fmt.Errorf("haip: client_id scheme %q is out of profile; HAIP signed requests require x509_hash", scheme)
	}
	return nil
}

// trustedAuthorityTypeAKI is the DCQL Trusted Authorities Query type for an
// Authority Key Identifier (OID4VP 1.0 Section 6.1.1, "aki"). HAIP 1.0 Section 5
// requires verifiers to support the AKI-based Trusted Authority Query for the
// mso_mdoc presentation path. The query value is the base64url-encoded
// KeyIdentifier of the AuthorityKeyIdentifier (RFC 5280 Section 4.2.1.1); for an
// mdoc this matches the AKI of the document-signer certificate, which equals the
// SubjectKeyIdentifier of the IACA root that signed it.
const trustedAuthorityTypeAKI = "aki"

// mdocTrustedAuthorityAKIs returns the base64url-encoded SubjectKeyIdentifier of
// each configured IACA root: the AKI values a HAIP mso_mdoc Trusted Authorities
// Query advertises. A presented credential is accepted only if its issuer chains
// to one of these same roots (VerifyIssuerSigned), so advertising the AKI is the
// request-side half of a trust decision the existing IACA chain validation
// enforces on the response, not a decorative hint. Roots without a
// SubjectKeyIdentifier are skipped, since there is no AKI to advertise.
func (p *Plugin) mdocTrustedAuthorityAKIs() []string {
	values := make([]string, 0, len(p.mdocTrustAnchorCerts))
	seen := make(map[string]struct{}, len(p.mdocTrustAnchorCerts))
	for _, cert := range p.mdocTrustAnchorCerts {
		if cert == nil || len(cert.SubjectKeyId) == 0 {
			continue
		}
		encoded := base64.RawURLEncoding.EncodeToString(cert.SubjectKeyId)
		if _, ok := seen[encoded]; ok {
			continue
		}
		seen[encoded] = struct{}{}
		values = append(values, encoded)
	}
	return values
}

// injectMdocTrustedAuthorities adds an AKI Trusted Authorities Query (OID4VP 1.0
// Section 6.1.1) to each mso_mdoc credential in a DCQL query that does not
// already constrain its trusted authorities, returning the rewritten query and
// whether anything changed. HAIP 1.0 Section 5 mandates this query for the mdoc
// path. Credentials of other formats, and any credential that already carries a
// trusted_authorities entry, are left untouched so an explicit query is never
// overridden.
func injectMdocTrustedAuthorities(dcqlJSON []byte, akiValues []string) ([]byte, bool, error) {
	if len(akiValues) == 0 {
		return dcqlJSON, false, nil
	}
	var query map[string]interface{}
	if err := json.Unmarshal(dcqlJSON, &query); err != nil {
		return dcqlJSON, false, err
	}
	rawCredentials, ok := query["credentials"].([]interface{})
	if !ok {
		return dcqlJSON, false, nil
	}
	changed := false
	for _, rawCredential := range rawCredentials {
		credential, ok := rawCredential.(map[string]interface{})
		if !ok {
			continue
		}
		format, _ := credential["format"].(string)
		if strings.TrimSpace(format) != credentialFormatMsoMdoc {
			continue
		}
		if _, exists := credential["trusted_authorities"]; exists {
			continue
		}
		credential["trusted_authorities"] = []map[string]interface{}{
			{
				"type":   trustedAuthorityTypeAKI,
				"values": akiValues,
			},
		}
		changed = true
	}
	if !changed {
		return dcqlJSON, false, nil
	}
	rewritten, err := json.Marshal(query)
	if err != nil {
		return dcqlJSON, false, err
	}
	return rewritten, true, nil
}

// extractDCQLKeyedSDJWT unwraps a DCQL-keyed vp_token JSON object
// ({"<id>": "<sd-jwt~kb>"} or {"<id>": ["<sd-jwt~kb>", ...]}) to the first
// SD-JWT presentation string it contains. OID4VP 1.0 Appendix B.2 keys the
// vp_token by DCQL credential id for every format; the existing SD-JWT evaluator
// expects the bare compact serialization, so DC API / DCQL responses are
// normalized here. It only matches values that look like an SD-JWT (contain the
// "~" disclosure separator), so JSON-LD VPs and mdoc tokens are never touched.
func extractDCQLKeyedSDJWT(vpToken string) (string, bool) {
	trimmed := strings.TrimSpace(vpToken)
	if !strings.HasPrefix(trimmed, "{") || !strings.Contains(trimmed, "~") {
		return "", false
	}
	var keyed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &keyed); err != nil {
		return "", false
	}
	for _, rawValue := range keyed {
		for _, candidate := range decodeVPTokenEntry(rawValue) {
			candidate = strings.TrimSpace(candidate)
			if strings.Contains(candidate, "~") {
				return candidate, true
			}
		}
	}
	return "", false
}
