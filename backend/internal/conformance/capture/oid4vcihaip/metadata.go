package oid4vcihaip

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"sort"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/golang-jwt/jwt/v5"
)

// haipSDJWTConfigurationID is the HAIP SD-JWT VC Credential Configuration.
const haipSDJWTConfigurationID = "UniversityDegreeCredentialSDJWTHAIP"

// haipStatusListPath is the HAIP status list that issued HAIP SD-JWT VCs
// reference in status.status_list.uri.
const haipStatusListPath = "/status-lists/haip-sd-jwt-1"

func init() {
	capture.Register("CI-018", capture.Entry{
		Passing: &capture.Scenario{
			Name: "mdoc-cose-algorithm-identifiers",
			Description: "The conformance client fetches Credential Issuer Metadata from /.well-known/openid-credential-issuer/oid4vci. " +
				"The capture checks that every mso_mdoc Credential Configuration lists credential_signing_alg_values_supported as JSON integers, the numeric COSE algorithm identifiers, not JOSE names.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeAccepted,
			Run:      mdocSigningAlgorithms,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The requirement constrains what the issuer publishes in its own metadata, and no request a client sends can make it advertise a different value.",
		},
	})
	capture.Register("CI-020", capture.Entry{
		Passing: &capture.Scenario{
			Name: "certificate-backed-haip-signatures",
			Description: "The conformance client fetches the signed Credential Issuer Metadata with Accept: application/jwt, the Type Metadata at the vct URL of the " + haipSDJWTConfigurationID + " configuration, " +
				"and the Status List Token at /oid4vci" + haipStatusListPath + ". The capture checks that both JWTs are ES256-signed by the leaf certificate of an x5c chain with no self-signed certificate, and that the Type Metadata repeats the vct. " +
				"Issuing a HAIP Credential needs a client attestation from an attester the issuer trusts, which the conformance client does not hold, so no issued Credential is captured.",
			Actor:    conformance.ActorConformanceClient,
			Expected: conformance.OutcomeAccepted,
			Run:      haipSignatures,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The requirement constrains how the issuer signs its own metadata, Credentials and status lists, and no request a client sends can make it sign them differently.",
		},
	})
}

// mdocSigningAlgorithms records the metadata response and checks OID4VCI
// 1.0 Appendix A.2.2: mso_mdoc identifiers are numeric COSE algorithm
// identifiers.
func mdocSigningAlgorithms(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	req, err := http.NewRequest(http.MethodGet, capture.IssuerMetadataURL(env), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("credential issuer metadata answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return "", err
	}
	configurations, _ := body["credential_configurations_supported"].(map[string]any)
	ids := make([]string, 0, len(configurations))
	for id := range configurations {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	mdoc := 0
	for _, id := range ids {
		configuration, _ := configurations[id].(map[string]any)
		if configuration["format"] != "mso_mdoc" {
			continue
		}
		mdoc++
		algs, _ := configuration["credential_signing_alg_values_supported"].([]any)
		if len(algs) == 0 {
			return "", fmt.Errorf("mso_mdoc configuration %s advertises no credential_signing_alg_values_supported", id)
		}
		for _, alg := range algs {
			number, ok := alg.(float64)
			if !ok || number != math.Trunc(number) {
				return "", fmt.Errorf("mso_mdoc configuration %s advertises %v, which is not a numeric COSE algorithm identifier", id, alg)
			}
		}
	}
	if mdoc == 0 {
		return "", fmt.Errorf("credential issuer metadata advertises no mso_mdoc configuration")
	}
	return conformance.OutcomeAccepted, nil
}

// haipSignatures records the signed metadata, the HAIP Type Metadata and the
// HAIP Status List Token, and checks HAIP 1.0 Sections 4.1 and 6.1.
func haipSignatures(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	req, err := http.NewRequest(http.MethodGet, capture.IssuerMetadataURL(env), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/jwt")
	resp, err := env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK || mediaType(resp) != "application/jwt" {
		return "", fmt.Errorf("signed metadata answered %d %s %s", resp.Status, resp.Header.Get("Content-Type"), capture.Truncate(resp.Body))
	}
	claims, err := verifyX5CSigned(string(resp.Body), "openidvci-issuer-metadata+jwt")
	if err != nil {
		return "", fmt.Errorf("signed metadata: %w", err)
	}
	meta, err := capture.ParseIssuerMetadata(claims)
	if err != nil {
		return "", err
	}
	configurations, _ := claims["credential_configurations_supported"].(map[string]any)
	haip, _ := configurations[haipSDJWTConfigurationID].(map[string]any)
	vct, _ := haip["vct"].(string)
	if vct == "" {
		return "", fmt.Errorf("signed metadata has no vct for %s", haipSDJWTConfigurationID)
	}

	req, err = http.NewRequest(http.MethodGet, vct, nil)
	if err != nil {
		return "", err
	}
	resp, err = env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("type metadata at %s answered %d %s", vct, resp.Status, capture.Truncate(resp.Body))
	}
	typeMetadata, err := resp.JSON()
	if err != nil {
		return "", err
	}
	if typeMetadata["vct"] != vct {
		return "", fmt.Errorf("type metadata vct is %v, want %s", typeMetadata["vct"], vct)
	}

	req, err = http.NewRequest(http.MethodGet, meta.ID+haipStatusListPath, nil)
	if err != nil {
		return "", err
	}
	resp, err = env.Do(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("status list answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	statusClaims, err := verifyX5CSigned(string(resp.Body), "statuslist+jwt")
	if err != nil {
		return "", fmt.Errorf("status list token: %w", err)
	}
	statusList, _ := statusClaims["status_list"].(map[string]any)
	if _, ok := statusList["bits"].(float64); !ok || statusList["lst"] == nil {
		return "", fmt.Errorf("status list token has no status_list bits and lst")
	}
	return conformance.OutcomeAccepted, nil
}

// verifyX5CSigned checks a compact JWS has the given typ and alg ES256, an
// x5c chain in which no certificate is self-signed (HAIP 1.0 Section 6.1.1:
// the trust anchor "MUST NOT be included" and the signing certificate "MUST
// NOT be self-signed"), and a signature that verifies under the leaf key.
func verifyX5CSigned(compact, typ string) (jwt.MapClaims, error) {
	header, _, err := capture.JWTParts(compact)
	if err != nil {
		return nil, err
	}
	if header["typ"] != typ {
		return nil, fmt.Errorf("typ is %v, want %s", header["typ"], typ)
	}
	if header["alg"] != "ES256" {
		return nil, fmt.Errorf("alg is %v, want ES256", header["alg"])
	}
	chain, _ := header["x5c"].([]any)
	if len(chain) == 0 {
		return nil, fmt.Errorf("no x5c header")
	}
	certificates := make([]*x509.Certificate, 0, len(chain))
	for _, raw := range chain {
		encoded, _ := raw.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode x5c entry: %w", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse x5c entry: %w", err)
		}
		// CheckSignature, not CheckSignatureFrom, so a self-signed leaf
		// without CA basic constraints is still caught.
		if certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil {
			return nil, fmt.Errorf("x5c includes self-signed certificate %q", certificate.Subject.String())
		}
		certificates = append(certificates, certificate)
	}
	for i := 0; i+1 < len(certificates); i++ {
		if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
			return nil, fmt.Errorf("x5c entry %d is not signed by entry %d: %w", i, i+1, err)
		}
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(compact, claims, func(*jwt.Token) (any, error) {
		return certificates[0].PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return nil, fmt.Errorf("signature does not verify under the x5c leaf key: %w", err)
	}
	return claims, nil
}
