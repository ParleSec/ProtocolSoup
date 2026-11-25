package oid4vci

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
)

// How a recipient finds the key that verifies an SD-JWT VC from this Issuer.
// SD-JWT VC draft 11 Section 3.5 defines two Issuer Signature Mechanisms and
// the Issuer supports both: the X.509 chain the credential carries in x5c,
// and JWT VC Issuer Metadata, served here. "If a recipient cannot validate
// that the public verification key corresponds the Issuer of the
// Issuer-signed JWT using a permitted Issuer Signature Mechanism, the SD-JWT
// VC MUST be rejected."

// jwtVCIssuerWellKnown is the string Section 5 inserts "between the host
// component and the path component (if any) of the iss claim value".
const jwtVCIssuerWellKnown = "/.well-known/jwt-vc-issuer"

// jwtVCIssuerMetadataPath is the JWT VC Issuer Metadata location for this
// Issuer's iss value.
func (p *Plugin) jwtVCIssuerMetadataPath() string {
	parsed, err := url.Parse(p.issuerID())
	if err != nil {
		return jwtVCIssuerWellKnown
	}
	issuerPath := strings.Trim(strings.TrimSpace(parsed.Path), "/")
	if issuerPath == "" {
		return jwtVCIssuerWellKnown
	}
	return jwtVCIssuerWellKnown + "/" + issuerPath
}

// sdJWTVCSignerJWK is the public key every SD-JWT VC is signed with: the
// certificate-backed ES256 key whose chain the credential carries in x5c.
// Its kid is the key's RFC 7638 thumbprint, and the credential's kid header
// parameter carries the same value: Section 5.2 says "It is RECOMMENDED that
// the JWT contains a kid JWT header parameter that can be used to look up the
// public key in the JWK Set included by value or referenced in the JWT VC
// Issuer Metadata."
func (p *Plugin) sdJWTVCSignerJWK() (crypto.JWK, error) {
	if p.mdocPKI == nil || p.mdocPKI.DocumentSignerKey() == nil {
		return crypto.JWK{}, fmt.Errorf("certificate-backed credential signer is unavailable")
	}
	jwk := crypto.JWKFromECPublicKey(&p.mdocPKI.DocumentSignerKey().PublicKey, "")
	jwk.Kid = jwk.Thumbprint()
	jwk.Use = "sig"
	return jwk, nil
}

// handleJWTVCIssuerMetadata serves the JWT VC Issuer Metadata configuration.
// Section 5.2: "A successful response MUST use the 200 OK HTTP and return the
// JWT VC Issuer Metadata configuration using the application/json content
// type." issuer is "REQUIRED. The Issuer identifier, which MUST be identical
// to the iss value in the JWT." The keys are given by value: "JWT VC Issuer
// Metadata MUST include either jwks_uri or jwks in their JWT VC Issuer
// Metadata, but not both."
func (p *Plugin) handleJWTVCIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != p.jwtVCIssuerMetadataPath() {
		http.NotFound(w, r)
		return
	}
	signer, err := p.sdJWTVCSignerJWK()
	if err != nil {
		writeOID4VCIError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	issuer := nowIssuer(p.issuerID())
	metadata := map[string]interface{}{
		"issuer": issuer,
		"jwks":   crypto.JWKS{Keys: []crypto.JWK{signer}},
	}

	p.emitEvent(
		p.getSessionFromRequest(r),
		lookingglass.EventTypeFlowStep,
		"JWT VC Issuer Metadata Retrieved",
		map[string]interface{}{
			"issuer":        issuer,
			"metadata_path": p.jwtVCIssuerMetadataPath(),
			"keys":          []string{signer.Kid},
		},
		lookingglass.Annotation{
			Type:        lookingglass.AnnotationTypeExplanation,
			Title:       "JWT VC Issuer Metadata",
			Description: "A recipient of an SD-JWT VC whose iss is an HTTPS URI retrieves the Issuer's public keys from this document and selects one by the credential's kid. The issuer value \"MUST be identical to the iss value of the JWT. If these values are not identical, the data contained in the response MUST NOT be used.\"",
			Reference:   "SD-JWT VC draft 11 Section 5",
		},
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(metadata)
}
