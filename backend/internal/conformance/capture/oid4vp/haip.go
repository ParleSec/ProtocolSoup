package oid4vp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// universityDegreeVCT is the vct the issuer's University Degree SD-JWT VC
// carries and the HAIP requests below ask for.
const universityDegreeVCT = "https://protocolsoup.com/credentials/university_degree"

// untrustedIssuerHost names the conformance client's own issuer. The .invalid
// top-level domain is reserved (RFC 2606), so it can never be a real issuer.
const untrustedIssuerHost = "issuer.conformance-client.invalid"

func init() {
	capture.Register("HAIP-VP-001", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "leaf-only-x5c",
			Description: "The conformance client fetches the request object of a HAIP request, which the verifier signs under the x509_hash Client Identifier Prefix. Its x5c header must start with a leaf certificate that is not self-signed and whose SHA-256 hash is the client_id, and must not include the self-signed root, which the wallet holds as its own trust anchor. The request object's signature must verify with the leaf key.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         leafOnlyX5C,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The verifier builds the x5c header from its own certificate chain, and OpenID4VP defines no wallet or client request that could make it include the root, so there is nothing for the verifier to reject.",
		},
	})

	capture.Register("HAIP-VP-002", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "Acceptance needs an SD-JWT VC signed under a trust anchor the operator configured for independent issuers, and the conformance client holds no such issuer key; credentials ProtocolSoup issues itself are checked against their issuance lineage instead.",
		},
		Failing: &capture.Scenario{
			Name:        "self-made-issuer-ca",
			Description: "The conformance client creates its own CA and issuer certificate, signs an SD-JWT VC with the issuer key, and puts only the issuer certificate in the x5c header, leaving its root out as HAIP requires. It presents the credential, with a valid Key Binding JWT, in an encrypted direct_post.jwt response to a HAIP request at /oid4vp/response. ProtocolSoup holds no issuance record for this credential, and its chain leads to no trust anchor the operator configured, so the verifier must deny it in the result at /oid4vp/result.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         selfMadeIssuerCA,
		},
	})
}

// leafOnlyX5C checks a HAIP request object's x5c header against HAIP 1.0
// Section 5.
func leafOnlyX5C(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	_, requestURI, err := createRequest(ctx, env, requestOptions{haip: true, responseMode: "direct_post.jwt", vct: universityDegreeVCT})
	if err != nil {
		return "", err
	}
	object, err := fetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return "", err
	}
	rawChain, _ := object.header["x5c"].([]any)
	if len(rawChain) == 0 {
		return "", fmt.Errorf("request object header has no x5c")
	}
	chain := make([]*x509.Certificate, 0, len(rawChain))
	for index, raw := range rawChain {
		encoded, _ := raw.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("x5c[%d] is not base64 DER: %w", index, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return "", fmt.Errorf("x5c[%d] is not a certificate: %w", index, err)
		}
		chain = append(chain, certificate)
	}
	for index, certificate := range chain {
		if certificate.CheckSignatureFrom(certificate) == nil {
			return "", fmt.Errorf("x5c[%d] (%s) is self-signed; the trust anchor must not be included", index, certificate.Subject.CommonName)
		}
		if index+1 < len(chain) {
			if err := certificate.CheckSignatureFrom(chain[index+1]); err != nil {
				return "", fmt.Errorf("x5c[%d] is not signed by x5c[%d]: %w", index, index+1, err)
			}
		}
	}
	leaf := chain[0]
	digest := sha256.Sum256(leaf.Raw)
	if want := "x509_hash:" + base64.RawURLEncoding.EncodeToString(digest[:]); object.claim("client_id") != want {
		return "", fmt.Errorf("client_id is %q, want the leaf hash %q", object.claim("client_id"), want)
	}
	if _, err := jwt.Parse(object.compact, func(*jwt.Token) (any, error) { return leaf.PublicKey, nil }); err != nil {
		return "", fmt.Errorf("request object signature does not verify with the x5c leaf key: %w", err)
	}
	return conformance.OutcomeAccepted, nil
}

// selfMadeIssuerCA presents an SD-JWT VC whose x5c chain leads only to a CA
// the conformance client made (HAIP 1.0 Section 6.1.1).
func selfMadeIssuerCA(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	h, err := untrustedIssuerHolder()
	if err != nil {
		return "", err
	}
	requestID, requestURI, err := createRequest(ctx, env, requestOptions{haip: true, responseMode: "direct_post.jwt", vct: h.vct})
	if err != nil {
		return "", err
	}
	object, err := fetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return "", err
	}
	vpToken, err := h.present(object.claim("client_id"), object.claim("nonce"))
	if err != nil {
		return "", err
	}
	response, err := encryptResponse(object, map[string]any{"vp_token": json.RawMessage(vpToken), "state": object.claim("state")})
	if err != nil {
		return "", err
	}
	resp, err := postResponse(ctx, env, object, url.Values{"response": {response}})
	if err != nil {
		return "", err
	}
	if resp.Status != http.StatusOK {
		return "", fmt.Errorf("response_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	decision, err := fetchResult(ctx, env, requestID)
	if err != nil {
		return "", err
	}
	if decision.Allowed {
		return conformance.OutcomeAccepted, nil
	}
	// missing_lineage: no anchor for independent issuers is configured.
	// credential_signature_invalid: one is, and the chain does not reach it.
	for _, code := range decision.ReasonCodes {
		if code != "missing_lineage" && code != "credential_signature_invalid" {
			return "", fmt.Errorf("verifier denied the presentation for a reason other than issuer trust: %s (%s)",
				strings.Join(decision.ReasonCodes, ", "), strings.Join(decision.Reasons, "; "))
		}
	}
	if len(decision.ReasonCodes) == 0 {
		return "", fmt.Errorf("verifier denied the presentation without a reason code")
	}
	return conformance.OutcomeRejected, nil
}

// untrustedIssuerHolder mints an SD-JWT VC under a CA the conformance client
// generates on the spot, bound to a fresh holder key.
func untrustedIssuerHolder() (*holder, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: "ProtocolSoup conformance client CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               pkix.Name{CommonName: "ProtocolSoup conformance client issuer"},
		DNSNames:              []string{untrustedIssuerHost},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, caCert, &issuerKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	holderKey, err := capture.NewHolderKey()
	if err != nil {
		return nil, err
	}
	holderJWK, err := holderKey.PublicJWK()
	if err != nil {
		return nil, err
	}
	disclosure, digest, err := newDisclosure("given_name", "Conformance")
	if err != nil {
		return nil, err
	}
	issuerJWT := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":     "https://" + untrustedIssuerHost,
		"sub":     "did:example:conformance-client:" + uuid.NewString(),
		"vct":     universityDegreeVCT,
		"iat":     now.Unix(),
		"exp":     now.Add(time.Hour).Unix(),
		"cnf":     map[string]any{"jwk": holderJWK},
		"_sd_alg": "sha-256",
		"_sd":     []string{digest},
	})
	issuerJWT.Header["typ"] = "dc+sd-jwt"
	// HAIP 1.0 Section 6.1.1: the issuer certificate, without the trust anchor.
	issuerJWT.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(issuerDER)}
	signed, err := issuerJWT.SignedString(issuerKey)
	if err != nil {
		return nil, err
	}
	return &holder{key: holderKey, credential: signed + "~" + disclosure + "~", vct: universityDegreeVCT}, nil
}

// newDisclosure builds an object-property disclosure and its digest (SD-JWT
// Sections 4.2.1 and 4.2.3).
func newDisclosure(name string, value any) (disclosure, digest string, err error) {
	raw, err := json.Marshal([]any{newSalt(), name, value})
	if err != nil {
		return "", "", err
	}
	disclosure = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(disclosure))
	return disclosure, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// newSalt is a disclosure salt (SD-JWT Section 4.2.1).
func newSalt() string {
	return base64.RawURLEncoding.EncodeToString([]byte(uuid.NewString()))
}

func serialNumber() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
