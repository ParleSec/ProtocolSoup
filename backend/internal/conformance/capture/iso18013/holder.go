package iso18013

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/fxamacker/cbor/v2"
	jose "github.com/go-jose/go-jose/v4"
)

// The conformance client's mdoc holder: it obtains an mDL from the issuer
// over OID4VCI and presents it to the verifier over OID4VP 1.0 Appendix B.
// Every CBOR and COSE structure is decoded and built here with
// fxamacker/cbor, independently of the product's internal/mdoc and
// internal/cose packages.

const (
	// mdlConfiguration is the issuer's non-HAIP mDL Credential Configuration.
	mdlConfiguration = "MobileDrivingLicenceMsoMdoc"
	mdlDocType       = "org.iso.18013.5.1.mDL"
	mdlNameSpace     = "org.iso.18013.5.1"
	// mdlQueryID names the single Credential Query in every request.
	mdlQueryID = "mdl"
	// x5chainLabel is the COSE x5chain header parameter (RFC 9360).
	x5chainLabel = 33
)

// requestedElements are the elements every request asks for and every
// presentation discloses.
var requestedElements = []string{"family_name", "given_name"}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	if encMode, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(err)
	}
	if decMode, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF}).DecMode(); err != nil {
		panic(err)
	}
}

// issuerSigned is ISO/IEC 18013-5 IssuerSigned with every item and the
// IssuerAuth kept as the exact bytes the issuer produced.
type issuerSigned struct {
	NameSpaces map[string][]cbor.RawMessage `cbor:"nameSpaces"`
	IssuerAuth cbor.RawMessage              `cbor:"issuerAuth"`
}

// signedItem is one decoded IssuerSignedItem, with the tag 24 bytes it came
// from.
type signedItem struct {
	Raw               cbor.RawMessage
	DigestID          uint64
	ElementIdentifier string
	ElementValue      cbor.RawMessage
}

// mso is the part of the MobileSecurityObject the conformance client reads.
type mso struct {
	Version         string                       `cbor:"version"`
	DigestAlgorithm string                       `cbor:"digestAlgorithm"`
	ValueDigests    map[string]map[uint64][]byte `cbor:"valueDigests"`
	DeviceKeyInfo   struct {
		DeviceKey map[int]cbor.RawMessage `cbor:"deviceKey"`
	} `cbor:"deviceKeyInfo"`
	DocType string `cbor:"docType"`
}

// issuerAuth is the IssuerAuth COSE_Sign1 split into its four members.
type issuerAuth struct {
	Tagged      bool
	Protected   []byte
	Unprotected map[int]cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// mdlHolder is an mDL the issuer issued to the conformance client.
type mdlHolder struct {
	Key    *capture.HolderKey
	Signed issuerSigned
	Auth   issuerAuth
	MSO    mso
}

// credentialRequest is the conformance client's Credential Request for an
// mDL, ready to send, and the key its proof was made with.
type credentialRequest struct {
	Request *http.Request
	Key     *capture.HolderKey
}

// newMDLCredentialRequest has the issuer create a pre-authorized mDL offer,
// redeems it and builds the Credential Request with a jwt proof of a fresh
// holder key over a fresh c_nonce. All of this is preparation.
func newMDLCredentialRequest(ctx context.Context, env *capture.Env) (*credentialRequest, error) {
	issuer, err := capture.DiscoverIssuer(ctx, env)
	if err != nil {
		return nil, err
	}
	grant, err := capture.PreAuthorizedGrant(ctx, env, issuer, capture.GrantOptions{OfferOptions: capture.OfferOptions{ConfigurationID: mdlConfiguration}})
	if err != nil {
		return nil, err
	}
	key, err := capture.NewHolderKey()
	if err != nil {
		return nil, err
	}
	nonce, err := capture.FreshNonce(ctx, env, issuer)
	if err != nil {
		return nil, err
	}
	proof, err := key.Proof(issuer.ID, nonce)
	if err != nil {
		return nil, err
	}
	req, err := capture.BearerJSON(issuer.Credential, grant.AccessToken, grant.CredentialRequest(proof))
	if err != nil {
		return nil, err
	}
	return &credentialRequest{Request: req, Key: key}, nil
}

// issueMDL obtains an mDL through Setup and checks the MSO binds the
// conformance client's key.
func issueMDL(ctx context.Context, env *capture.Env) (*mdlHolder, error) {
	request, err := newMDLCredentialRequest(ctx, env)
	if err != nil {
		return nil, err
	}
	resp, err := env.Setup(ctx, request.Request)
	if err != nil {
		return nil, err
	}
	return readCredentialResponse(resp, request.Key)
}

// readCredentialResponse decodes the single mso_mdoc Credential in an HTTP 200
// Credential Response: base64url-encoded IssuerSigned (OID4VCI 1.0 Appendix
// A.2.4).
func readCredentialResponse(resp *capture.Response, key *capture.HolderKey) (*mdlHolder, error) {
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("credential request answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	body, err := resp.JSON()
	if err != nil {
		return nil, err
	}
	credentials, err := capture.IssuedCredentials(body)
	if err != nil {
		return nil, err
	}
	if len(credentials) != 1 {
		return nil, fmt.Errorf("credential response carries %d credentials, want 1", len(credentials))
	}
	raw, err := base64.RawURLEncoding.DecodeString(credentials[0])
	if err != nil {
		return nil, fmt.Errorf("credential is not base64url: %w", err)
	}
	h := &mdlHolder{Key: key}
	if err := decMode.Unmarshal(raw, &h.Signed); err != nil {
		return nil, fmt.Errorf("decode IssuerSigned: %w", err)
	}
	if h.Auth, err = decodeIssuerAuth(h.Signed.IssuerAuth); err != nil {
		return nil, err
	}
	if h.MSO, err = decodeMSO(h.Auth.Payload); err != nil {
		return nil, err
	}
	if h.MSO.Version != "1.0" || h.MSO.DigestAlgorithm != "SHA-256" || h.MSO.DocType != mdlDocType {
		return nil, fmt.Errorf("MSO has version %q, digestAlgorithm %q and docType %q, want 1.0, SHA-256 and %s",
			h.MSO.Version, h.MSO.DigestAlgorithm, h.MSO.DocType, mdlDocType)
	}
	if err := h.checkDeviceKey(); err != nil {
		return nil, err
	}
	return h, nil
}

// decodeIssuerAuth splits a COSE_Sign1 (RFC 9052 Section 4.2), tagged 18 or
// untagged.
func decodeIssuerAuth(raw cbor.RawMessage) (issuerAuth, error) {
	var out issuerAuth
	content := []byte(raw)
	var tag cbor.RawTag
	if err := decMode.Unmarshal(raw, &tag); err == nil {
		if tag.Number != 18 {
			return out, fmt.Errorf("IssuerAuth carries CBOR tag %d, want 18 or none", tag.Number)
		}
		out.Tagged = true
		content = tag.Content
	}
	var members []cbor.RawMessage
	if err := decMode.Unmarshal(content, &members); err != nil || len(members) != 4 {
		return out, fmt.Errorf("IssuerAuth is not a four-member COSE_Sign1")
	}
	if err := decMode.Unmarshal(members[0], &out.Protected); err != nil {
		return out, fmt.Errorf("IssuerAuth protected header: %w", err)
	}
	if err := decMode.Unmarshal(members[1], &out.Unprotected); err != nil {
		return out, fmt.Errorf("IssuerAuth unprotected header: %w", err)
	}
	if err := decMode.Unmarshal(members[2], &out.Payload); err != nil || len(out.Payload) == 0 {
		return out, fmt.Errorf("IssuerAuth carries no payload")
	}
	if err := decMode.Unmarshal(members[3], &out.Signature); err != nil {
		return out, fmt.Errorf("IssuerAuth signature: %w", err)
	}
	return out, nil
}

// encode rebuilds the COSE_Sign1, keeping the issuer's protected header,
// payload and signature bytes.
func (a issuerAuth) encode() (cbor.RawMessage, error) {
	members := []any{a.Protected, a.Unprotected, a.Payload, a.Signature}
	if a.Tagged {
		return encMode.Marshal(cbor.Tag{Number: 18, Content: members})
	}
	return encMode.Marshal(members)
}

// x5chain returns the certificates of the unprotected x5chain header, which
// RFC 9360 allows as a single bstr or an array of them.
func (a issuerAuth) x5chain() ([]*x509.Certificate, error) {
	raw, ok := a.Unprotected[x5chainLabel]
	if !ok {
		return nil, fmt.Errorf("IssuerAuth has no unprotected x5chain")
	}
	var ders [][]byte
	var single []byte
	if err := decMode.Unmarshal(raw, &single); err == nil {
		ders = [][]byte{single}
	} else if err := decMode.Unmarshal(raw, &ders); err != nil {
		return nil, fmt.Errorf("x5chain is neither a bstr nor an array of them")
	}
	chain := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5chain certificate: %w", err)
		}
		chain = append(chain, certificate)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("x5chain is empty")
	}
	return chain, nil
}

// verifySignature checks the IssuerAuth ES256 signature (RFC 9052 Section
// 4.4) with the x5chain leaf key.
func (a issuerAuth) verifySignature() error {
	chain, err := a.x5chain()
	if err != nil {
		return err
	}
	leafKey, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("x5chain leaf key is %T, want ECDSA", chain[0].PublicKey)
	}
	toBeSigned, err := encMode.Marshal([]any{"Signature1", a.Protected, []byte{}, a.Payload})
	if err != nil {
		return err
	}
	if len(a.Signature) != 64 {
		return fmt.Errorf("IssuerAuth signature is %d bytes, want 64", len(a.Signature))
	}
	digest := sha256.Sum256(toBeSigned)
	r := new(big.Int).SetBytes(a.Signature[:32])
	s := new(big.Int).SetBytes(a.Signature[32:])
	if !ecdsa.Verify(leafKey, digest[:], r, s) {
		return fmt.Errorf("IssuerAuth signature does not verify with the x5chain leaf key")
	}
	return nil
}

// decodeMSO reads MobileSecurityObjectBytes: #6.24(bstr .cbor
// MobileSecurityObject).
func decodeMSO(payload []byte) (mso, error) {
	var out mso
	var wrapped cbor.Tag
	if err := decMode.Unmarshal(payload, &wrapped); err != nil || wrapped.Number != 24 {
		return out, fmt.Errorf("IssuerAuth payload is not tag 24 MobileSecurityObjectBytes")
	}
	inner, ok := wrapped.Content.([]byte)
	if !ok {
		return out, fmt.Errorf("MobileSecurityObjectBytes does not wrap a bstr")
	}
	if err := decMode.Unmarshal(inner, &out); err != nil {
		return out, fmt.Errorf("decode MobileSecurityObject: %w", err)
	}
	return out, nil
}

// checkDeviceKey confirms the MSO deviceKey is the EC2 P-256 public key the
// conformance client proved possession of.
func (h *mdlHolder) checkDeviceKey() error {
	key := h.MSO.DeviceKeyInfo.DeviceKey
	var kty, crv int64
	var x, y []byte
	if err := decMode.Unmarshal(key[1], &kty); err != nil || kty != 2 {
		return fmt.Errorf("MSO deviceKey kty is not EC2")
	}
	if err := decMode.Unmarshal(key[-1], &crv); err != nil || crv != 1 {
		return fmt.Errorf("MSO deviceKey crv is not P-256")
	}
	if _, private := key[-4]; private {
		return fmt.Errorf("MSO deviceKey carries the private scalar d")
	}
	if err := decMode.Unmarshal(key[-2], &x); err != nil {
		return fmt.Errorf("MSO deviceKey has no x coordinate")
	}
	if err := decMode.Unmarshal(key[-3], &y); err != nil {
		return fmt.Errorf("MSO deviceKey has no y coordinate")
	}
	point, err := h.Key.PublicKey.Bytes()
	if err != nil {
		return err
	}
	if !bytes.Equal(point, append(append([]byte{0x04}, x...), y...)) {
		return fmt.Errorf("MSO deviceKey is not the key the conformance client proved possession of")
	}
	return nil
}

// items decodes the items of one namespace.
func (h *mdlHolder) items(nameSpace string) ([]signedItem, error) {
	raws := h.Signed.NameSpaces[nameSpace]
	out := make([]signedItem, 0, len(raws))
	for _, raw := range raws {
		item, err := decodeItem(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

// decodeItem reads IssuerSignedItemBytes: #6.24(bstr .cbor IssuerSignedItem).
func decodeItem(raw cbor.RawMessage) (signedItem, error) {
	item := signedItem{Raw: raw}
	var wrapped cbor.Tag
	if err := decMode.Unmarshal(raw, &wrapped); err != nil || wrapped.Number != 24 {
		return item, fmt.Errorf("IssuerSignedItemBytes is not tag 24")
	}
	inner, ok := wrapped.Content.([]byte)
	if !ok {
		return item, fmt.Errorf("IssuerSignedItemBytes does not wrap a bstr")
	}
	var fields map[string]cbor.RawMessage
	if err := decMode.Unmarshal(inner, &fields); err != nil {
		return item, fmt.Errorf("decode IssuerSignedItem: %w", err)
	}
	if err := decMode.Unmarshal(fields["digestID"], &item.DigestID); err != nil {
		return item, fmt.Errorf("IssuerSignedItem digestID: %w", err)
	}
	if err := decMode.Unmarshal(fields["elementIdentifier"], &item.ElementIdentifier); err != nil {
		return item, fmt.Errorf("IssuerSignedItem elementIdentifier: %w", err)
	}
	item.ElementValue = fields["elementValue"]
	return item, nil
}

// withElementValue re-encodes an item with a different elementValue, keeping
// its digestID, random and elementIdentifier.
func withElementValue(raw cbor.RawMessage, value any) (cbor.RawMessage, error) {
	var wrapped cbor.Tag
	if err := decMode.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	inner, _ := wrapped.Content.([]byte)
	var fields map[string]cbor.RawMessage
	if err := decMode.Unmarshal(inner, &fields); err != nil {
		return nil, err
	}
	encodedValue, err := encMode.Marshal(value)
	if err != nil {
		return nil, err
	}
	fields["elementValue"] = encodedValue
	reencoded, err := encMode.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return encMode.Marshal(cbor.Tag{Number: 24, Content: reencoded})
}

// disclosed is the mDL namespace narrowed to the requested elements, as a
// wallet discloses them.
func (h *mdlHolder) disclosed() (map[string][]cbor.RawMessage, error) {
	items, err := h.items(mdlNameSpace)
	if err != nil {
		return nil, err
	}
	selected := make([]cbor.RawMessage, 0, len(requestedElements))
	for _, element := range requestedElements {
		found := false
		for _, item := range items {
			if item.ElementIdentifier == element {
				selected = append(selected, item.Raw)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("issued mDL has no %s element", element)
		}
	}
	return map[string][]cbor.RawMessage{mdlNameSpace: selected}, nil
}

// presentation is what the conformance client sends in one DeviceResponse.
type presentation struct {
	Version    string
	NameSpaces map[string][]cbor.RawMessage
	IssuerAuth cbor.RawMessage
}

// defaultPresentation discloses the requested elements under the issuer's
// unchanged IssuerAuth, in a version "1.0" DeviceResponse.
func (h *mdlHolder) defaultPresentation() (presentation, error) {
	nameSpaces, err := h.disclosed()
	if err != nil {
		return presentation{}, err
	}
	return presentation{Version: "1.0", NameSpaces: nameSpaces, IssuerAuth: h.Signed.IssuerAuth}, nil
}

// mdlQuery is the DCQL Credential Query for an mDL with the requested
// elements (OID4VP 1.0 Section 6 and Appendix B.2.3).
func mdlQuery() map[string]any {
	claims := make([]map[string]any, 0, len(requestedElements))
	for _, element := range requestedElements {
		claims = append(claims, map[string]any{"path": []string{mdlNameSpace, element}})
	}
	return map[string]any{
		"id":     mdlQueryID,
		"format": "mso_mdoc",
		"meta":   map[string]any{"doctype_value": mdlDocType},
		"claims": claims,
	}
}

// deviceResponse builds the DeviceResponse (ISO/IEC 18013-5 Section
// 8.3.2.1.2.2) for one request object, signing device authentication over
// the OID4VP 1.0 Appendix B.2.6.1 SessionTranscript.
func (h *mdlHolder) deviceResponse(object *capture.RequestObject, p presentation) ([]byte, error) {
	thumbprint, err := responseKeyThumbprint(object)
	if err != nil {
		return nil, err
	}
	responseURI := object.Claim("response_uri")
	clientID := object.Claim("client_id")
	nonce := object.Claim("nonce")
	if responseURI == "" || clientID == "" || nonce == "" {
		return nil, fmt.Errorf("request object lacks client_id, nonce or response_uri")
	}
	// OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
	handoverInfo, err := encMode.Marshal([]any{clientID, nonce, thumbprint, responseURI})
	if err != nil {
		return nil, err
	}
	handoverInfoHash := sha256.Sum256(handoverInfo)
	// SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover],
	// with both engagement members null.
	sessionTranscript, err := encMode.Marshal([]any{nil, nil, []any{"OpenID4VPHandover", handoverInfoHash[:]}})
	if err != nil {
		return nil, err
	}
	// DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces); the
	// conformance client returns no device-signed elements.
	deviceNameSpaces, err := encMode.Marshal(map[string]any{})
	if err != nil {
		return nil, err
	}
	deviceNameSpacesBytes, err := encMode.Marshal(cbor.Tag{Number: 24, Content: deviceNameSpaces})
	if err != nil {
		return nil, err
	}
	// DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication",
	// SessionTranscript, DocType, DeviceNameSpacesBytes]).
	deviceAuthentication, err := encMode.Marshal([]any{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		mdlDocType,
		cbor.RawMessage(deviceNameSpacesBytes),
	})
	if err != nil {
		return nil, err
	}
	deviceAuthenticationBytes, err := encMode.Marshal(cbor.Tag{Number: 24, Content: deviceAuthentication})
	if err != nil {
		return nil, err
	}
	deviceSignature, err := h.signDetached(deviceAuthenticationBytes)
	if err != nil {
		return nil, err
	}
	document := map[string]any{
		"docType": mdlDocType,
		"issuerSigned": map[string]any{
			"nameSpaces": p.NameSpaces,
			"issuerAuth": p.IssuerAuth,
		},
		"deviceSigned": map[string]any{
			"nameSpaces": cbor.RawMessage(deviceNameSpacesBytes),
			"deviceAuth": map[string]any{"deviceSignature": deviceSignature},
		},
	}
	return encMode.Marshal(map[string]any{
		"version":   p.Version,
		"documents": []any{document},
		"status":    0,
	})
}

// signDetached makes the untagged ES256 COSE_Sign1 deviceSignature over a
// detached payload (RFC 9052 Sections 4.2 and 4.4).
func (h *mdlHolder) signDetached(payload []byte) (cbor.RawMessage, error) {
	protected, err := encMode.Marshal(map[int]int{1: -7})
	if err != nil {
		return nil, err
	}
	toBeSigned, err := encMode.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(toBeSigned)
	r, s, err := ecdsa.Sign(rand.Reader, h.Key.PrivateKey, digest[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return encMode.Marshal([]any{protected, map[int]any{}, nil, signature})
}

// responseKeyThumbprint is the RFC 7638 SHA-256 thumbprint of the verifier's
// response encryption key, or nil when the request asks for no encryption.
func responseKeyThumbprint(object *capture.RequestObject) ([]byte, error) {
	if !strings.HasSuffix(object.Claim("response_mode"), ".jwt") {
		return nil, nil
	}
	metadata, _ := object.Claims["client_metadata"].(map[string]any)
	jwks, _ := metadata["jwks"].(map[string]any)
	keys, _ := jwks["keys"].([]any)
	if len(keys) != 1 {
		return nil, fmt.Errorf("request object client_metadata.jwks carries %d keys, want 1", len(keys))
	}
	rawKey, err := json.Marshal(keys[0])
	if err != nil {
		return nil, err
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(rawKey); err != nil {
		return nil, fmt.Errorf("parse client_metadata.jwks key: %w", err)
	}
	return key.Thumbprint(crypto.SHA256)
}

// present has the verifier create a direct_post.jwt request for an mDL,
// fetches its request object (recorded), answers it with the DeviceResponse
// that build returns (recorded) and reads the verifier's decision (recorded).
func (h *mdlHolder) present(ctx context.Context, env *capture.Env, build func(*mdlHolder) (presentation, error)) (*capture.Policy, error) {
	p, err := build(h)
	if err != nil {
		return nil, err
	}
	requestID, requestURI, err := capture.CreateRequest(ctx, env, capture.RequestOptions{ResponseMode: "direct_post.jwt", Credential: mdlQuery()})
	if err != nil {
		return nil, err
	}
	object, err := capture.FetchRequestObject(ctx, env, requestURI)
	if err != nil {
		return nil, err
	}
	deviceResponse, err := h.deviceResponse(object, p)
	if err != nil {
		return nil, err
	}
	// OID4VP 1.0 Appendix B.2.5: the vp_token value is the base64url-encoded
	// DeviceResponse, keyed by the Credential Query id.
	vpToken, err := json.Marshal(map[string][]string{mdlQueryID: {base64.RawURLEncoding.EncodeToString(deviceResponse)}})
	if err != nil {
		return nil, err
	}
	response, err := capture.EncryptResponse(object, map[string]any{"vp_token": json.RawMessage(vpToken), "state": object.Claim("state")})
	if err != nil {
		return nil, err
	}
	resp, err := capture.PostResponse(ctx, env, object, url.Values{"response": {response}})
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("response_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	return capture.FetchResult(ctx, env, requestID)
}
