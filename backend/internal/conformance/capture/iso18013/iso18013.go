// Package iso18013 captures the ISO/IEC 18013-5 mdoc format rules: the
// conformance client obtains an mDL from the issuer over OID4VCI and
// presents it to the verifier over OID4VP 1.0 Appendix B.
package iso18013

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"image/jpeg"
	"math/big"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/fxamacker/cbor/v2"
)

// presentDescription is the shared opening of every verifier-side
// description.
const presentDescription = "The conformance client obtains an mDL from the issuer through the Pre-Authorized Code Flow, with a jwt proof of its own P-256 key, and fetches the request object of a direct_post.jwt request for that mDL from the verifier's request_uri. It builds a DeviceResponse itself, disclosing family_name and given_name and signing device authentication over the OpenID4VPHandover SessionTranscript of OpenID4VP 1.0 Appendix B.2.6.1, encrypts it as vp_token to the verifier's response key and POSTs it to /oid4vp/response, then reads the verifier's decision from /oid4vp/result."

func init() {
	capture.Register("MDOC-001", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "p256-public-device-key",
			Description: presentDescription + " The issuer bound the conformance client's key into the MSO as an EC2 P-256 COSE_Key without the private scalar d, so the verifier must read it as the device key, verify the deviceSignature with it and allow the presentation.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         presentConformant,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The deviceKey sits inside the issuer-signed MSO, the issuer binds only the P-256 public key from the proof, and the verifier checks the IssuerAuth signature before it reads the deviceKey, so no presentation can bring a deviceKey with private material or another curve to that check.",
		},
	})

	capture.Register("MDOC-002", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "issuer-signed-mso",
			Description: presentDescription + " The IssuerAuth payload is the issuer's tag 24 MobileSecurityObjectBytes, whose MSO carries version 1.0, digestAlgorithm SHA-256, the mDL docType, the conformance client's device key, the value digests and a validity interval, so the verifier must accept the MSO and allow the presentation.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         presentConformant,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "Every field this requirement checks sits inside the issuer-signed MSO, and the verifier validates the IssuerAuth certificate chain and signature before it decodes the MSO, so an altered MSO is refused for its signature and never reaches these checks.",
		},
	})

	capture.Register("MDOC-003", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "disclosed-items-match-digests",
			Description: presentDescription + " Each disclosed IssuerSignedItem is the issuer's own bytes, appears once and hashes to its digestID's entry in the MSO valueDigests, so the verifier must allow the presentation.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         presentConformant,
		},
		Failing: &capture.Scenario{
			Name:        "altered-element-value",
			Description: presentDescription + " Before presenting, it replaces the elementValue of the family_name IssuerSignedItem with another name, keeping that item's digestID, random and elementIdentifier and leaving IssuerAuth unchanged. The item's SHA-256 digest no longer equals the MSO valueDigests entry for its digestID, so the verifier must deny the presentation with a digest mismatch.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         presentAlteredElementValue,
		},
	})

	capture.Register("MDOC-004", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "version-1-0",
			Description: presentDescription + " The DeviceResponse version is the text string \"1.0\", so the verifier must allow the presentation.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         presentConformant,
		},
		Failing: &capture.Scenario{
			Name:        "version-2-0",
			Description: presentDescription + " The DeviceResponse is otherwise valid, with the issuer's IssuerSigned and a valid deviceSignature, but its version is \"2.0\". The verifier must refuse a DeviceResponse whose version is not exactly \"1.0\".",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         presentVersion2,
		},
	})

	capture.Register("MDOC-005", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "document-signer-under-iaca",
			Description: presentDescription + " The IssuerAuth x5chain carries the issuer's document-signer certificate, which chains to the IACA root the verifier is configured with and holds the key that signed IssuerAuth, so the verifier must allow the presentation.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         presentConformant,
		},
		Failing: &capture.Scenario{
			Name:        "self-made-document-signer",
			Description: presentDescription + " Before presenting, it creates its own CA and a document-signer certificate under it, and puts that certificate in place of the issuer's in the IssuerAuth unprotected x5chain header (label 33), which the COSE signature does not cover; the MSO and signature are unchanged. The certificate does not chain to any IACA root the verifier is configured with, so the verifier must deny the presentation when certificate path validation fails.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         presentSelfMadeDocumentSigner,
		},
	})

	capture.Register("MDOC-006", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "mdl-mandatory-elements",
			Description: "The conformance client redeems a pre-authorized offer for the MobileDrivingLicenceMsoMdoc configuration and sends a Credential Request with a jwt proof of its own P-256 key to /oid4vci/credential. The issuer must answer with an mDL whose org.iso.18013.5.1 namespace carries every mandatory data element (family_name, given_name, birth_date, issue_date, expiry_date, issuing_country, issuing_authority, document_number, portrait, driving_privileges and un_distinguishing_sign), each hashing to its entry in the issuer-signed MSO, with portrait a byte string that decodes as a JPEG image.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run:         issueWithMandatoryElements,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The issuer builds every mDL's data elements itself from its own identity record and document-signer PKI, and no Credential Request parameter can make it leave out a mandatory element or replace the portrait.",
		},
	})
}

// presentConformant presents an unaltered mDL; the verifier must allow it.
func presentConformant(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	h, err := issueMDL(ctx, env)
	if err != nil {
		return "", err
	}
	decision, err := h.present(ctx, env, (*mdlHolder).defaultPresentation)
	if err != nil {
		return "", err
	}
	if !decision.Allowed {
		return "", fmt.Errorf("verifier denied a conformant mDL presentation: %s (%s)",
			strings.Join(decision.ReasonCodes, ", "), strings.Join(decision.Reasons, "; "))
	}
	return conformance.OutcomeAccepted, nil
}

// presentAltered presents an altered mDL. It reports rejected only when the
// verifier's decision carries code with a reason containing detail, which
// shows the requirement's own check refused it.
func presentAltered(ctx context.Context, env *capture.Env, build func(*mdlHolder) (presentation, error), code, detail string) (conformance.ArtefactOutcome, error) {
	h, err := issueMDL(ctx, env)
	if err != nil {
		return "", err
	}
	decision, err := h.present(ctx, env, build)
	if err != nil {
		return "", err
	}
	if decision.Allowed {
		return conformance.OutcomeAccepted, nil
	}
	if !decision.HasReason(code, detail) {
		return "", fmt.Errorf("verifier denied the presentation, but not with %s %q: %s (%s)", code, detail,
			strings.Join(decision.ReasonCodes, ", "), strings.Join(decision.Reasons, "; "))
	}
	return conformance.OutcomeRejected, nil
}

// presentAlteredElementValue changes one disclosed element value (ISO/IEC
// 18013-5 Section 9.1.2.3, value digests).
func presentAlteredElementValue(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	return presentAltered(ctx, env, func(h *mdlHolder) (presentation, error) {
		p, err := h.defaultPresentation()
		if err != nil {
			return p, err
		}
		items := p.NameSpaces[mdlNameSpace]
		altered := make([]cbor.RawMessage, len(items))
		copy(altered, items)
		changed := false
		for index, raw := range altered {
			item, err := decodeItem(raw)
			if err != nil {
				return p, err
			}
			if item.ElementIdentifier != "family_name" {
				continue
			}
			var current string
			if err := decMode.Unmarshal(item.ElementValue, &current); err != nil {
				return p, fmt.Errorf("family_name is not a text string: %w", err)
			}
			replacement := "Conformance"
			if current == replacement {
				replacement = "Client"
			}
			if altered[index], err = withElementValue(raw, replacement); err != nil {
				return p, err
			}
			changed = true
		}
		if !changed {
			return p, fmt.Errorf("presentation discloses no family_name item")
		}
		p.NameSpaces = map[string][]cbor.RawMessage{mdlNameSpace: altered}
		return p, nil
	}, "device_auth_invalid", `("family_name"): digest mismatch`)
}

// presentVersion2 sends DeviceResponse version "2.0" (ISO/IEC 18013-5
// Section 8.3.2.1).
func presentVersion2(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	return presentAltered(ctx, env, func(h *mdlHolder) (presentation, error) {
		p, err := h.defaultPresentation()
		p.Version = "2.0"
		return p, err
	}, "vp_token_invalid", `unsupported DeviceResponse version "2.0"`)
}

// presentSelfMadeDocumentSigner replaces the unprotected x5chain with a
// certificate under a CA the conformance client made (ISO/IEC 18013-5
// Annex B.1).
func presentSelfMadeDocumentSigner(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	return presentAltered(ctx, env, func(h *mdlHolder) (presentation, error) {
		p, err := h.defaultPresentation()
		if err != nil {
			return p, err
		}
		der, err := selfMadeDocumentSigner()
		if err != nil {
			return p, err
		}
		auth := h.Auth
		auth.Unprotected = make(map[int]cbor.RawMessage, len(h.Auth.Unprotected))
		for label, value := range h.Auth.Unprotected {
			auth.Unprotected[label] = value
		}
		if auth.Unprotected[x5chainLabel], err = encMode.Marshal(der); err != nil {
			return p, err
		}
		if p.IssuerAuth, err = auth.encode(); err != nil {
			return p, err
		}
		return p, nil
	}, "device_auth_invalid", "x5chain certificate path validation failed")
}

// selfMadeDocumentSigner issues a document-signer certificate, in the shape
// Annex B profiles, under a CA the conformance client generates on the spot.
func selfMadeDocumentSigner() ([]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	subject := pkix.Name{Country: []string{"XX"}, Organization: []string{"ProtocolSoup conformance client"}}
	caSubject := subject
	caSubject.CommonName = "Conformance client IACA"
	caTemplate := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               caSubject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
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
	signerSubject := subject
	signerSubject.CommonName = "Conformance client document signer"
	signerTemplate := &x509.Certificate{
		SerialNumber:          serialNumber(),
		Subject:               signerSubject,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		// 1.0.18013.5.1.2, the mDL document-signer extended key usage.
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 2}},
	}
	return x509.CreateCertificate(rand.Reader, signerTemplate, caCert, &signerKey.PublicKey, caKey)
}

// mandatoryElements are the org.iso.18013.5.1 data elements ISO/IEC 18013-5
// Section 7.2.1 marks mandatory for an mDL.
var mandatoryElements = []string{
	"family_name", "given_name", "birth_date", "issue_date", "expiry_date",
	"issuing_country", "issuing_authority", "document_number", "portrait",
	"driving_privileges", "un_distinguishing_sign",
}

// issueWithMandatoryElements records the Credential Request and checks the
// issued mDL (ISO/IEC 18013-5 Section 7.2.1).
func issueWithMandatoryElements(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	request, err := newMDLCredentialRequest(ctx, env)
	if err != nil {
		return "", err
	}
	resp, err := env.Do(ctx, request.Request)
	if err != nil {
		return "", err
	}
	h, err := readCredentialResponse(resp, request.Key)
	if err != nil {
		return "", err
	}
	if err := h.Auth.verifySignature(); err != nil {
		return "", err
	}
	items, err := h.items(mdlNameSpace)
	if err != nil {
		return "", err
	}
	digests := h.MSO.ValueDigests[mdlNameSpace]
	byElement := make(map[string]signedItem, len(items))
	for _, item := range items {
		sum := sha256.Sum256(item.Raw)
		if !bytes.Equal(digests[item.DigestID], sum[:]) {
			return "", fmt.Errorf("issued %s item does not hash to MSO valueDigests[%d]", item.ElementIdentifier, item.DigestID)
		}
		byElement[item.ElementIdentifier] = item
	}
	var missing []string
	for _, element := range mandatoryElements {
		if _, ok := byElement[element]; !ok {
			missing = append(missing, element)
		}
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("issued mDL lacks mandatory elements %s", strings.Join(missing, ", "))
	}
	var portrait []byte
	if err := decMode.Unmarshal(byElement["portrait"].ElementValue, &portrait); err != nil {
		return "", fmt.Errorf("portrait is not a byte string: %w", err)
	}
	if _, err := jpeg.Decode(bytes.NewReader(portrait)); err != nil {
		return "", fmt.Errorf("portrait does not decode as JPEG: %w", err)
	}
	return conformance.OutcomeAccepted, nil
}

func serialNumber() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial.Add(serial, big.NewInt(1))
}
