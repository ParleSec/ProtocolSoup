package mdoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// The following golden vectors are the non-normative examples in OID4VP 1.0
// Appendix B.2.6.1. They are the byte-exact pin for the OpenID4VPHandover
// construction; if the implementation drifts from the targeted spec version,
// these vectors fail. The inputs are the spec's documented example values.
const (
	specVectorClientID    = "x509_san_dns:example.com"
	specVectorNonce       = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
	specVectorResponseURI = "https://example.com/response"
	// RFC 7638 thumbprint of the example verifier encryption JWK (raw bytes).
	specVectorThumbprintHex = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
	// SHA-256(CBOR(OpenID4VPHandoverInfo)).
	specVectorInfoHashHex = "048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
	// CBOR of the full OpenID4VPHandover ["OpenID4VPHandover", infoHash].
	specVectorHandoverHex = "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
	// CBOR of the SessionTranscript [null, null, OpenID4VPHandover].
	specVectorTranscriptHex = "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// TestOpenID4VPHandoverSpecVector pins the handover bytes to the OID4VP 1.0
// Appendix B.2.6.1 non-normative example. This regression vector ensures a
// handover that is plausible but not byte-exact fails here before it ever
// reaches an external verifier.
func TestOpenID4VPHandoverSpecVector(t *testing.T) {
	thumbprint := mustHex(t, specVectorThumbprintHex)

	handover, err := NewOpenID4VPHandover(specVectorClientID, specVectorNonce, thumbprint, specVectorResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	if got := hex.EncodeToString(handover); got != specVectorHandoverHex {
		t.Fatalf("OpenID4VPHandover mismatch\n got: %s\nwant: %s", got, specVectorHandoverHex)
	}

	// The embedded hash must be SHA-256 over the CBOR of the info array.
	info := []any{specVectorClientID, specVectorNonce, thumbprint, specVectorResponseURI}
	infoBytes, err := intcose.MarshalDeterministic(info)
	if err != nil {
		t.Fatalf("encode info: %v", err)
	}
	infoHash := sha256.Sum256(infoBytes)
	if got := hex.EncodeToString(infoHash[:]); got != specVectorInfoHashHex {
		t.Fatalf("OpenID4VPHandoverInfoHash mismatch\n got: %s\nwant: %s", got, specVectorInfoHashHex)
	}
}

// TestOpenID4VPSessionTranscriptSpecVector pins the full [null, null, Handover]
// SessionTranscript bytes to the spec example.
func TestOpenID4VPSessionTranscriptSpecVector(t *testing.T) {
	thumbprint := mustHex(t, specVectorThumbprintHex)

	st, err := NewOpenID4VPSessionTranscript(specVectorClientID, specVectorNonce, thumbprint, specVectorResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript: %v", err)
	}
	encoded, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	if got := hex.EncodeToString(encoded); got != specVectorTranscriptHex {
		t.Fatalf("SessionTranscript mismatch\n got: %s\nwant: %s", got, specVectorTranscriptHex)
	}
}

// TestOpenID4VPHandoverUnencryptedNull verifies that, for an unencrypted
// response (no encryption key), the third element of OpenID4VPHandoverInfo is
// CBOR null rather than an empty byte string, as the spec requires.
func TestOpenID4VPHandoverUnencryptedNull(t *testing.T) {
	handover, err := NewOpenID4VPHandover(specVectorClientID, specVectorNonce, nil, specVectorResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	encrypted, err := NewOpenID4VPHandover(specVectorClientID, specVectorNonce, mustHex(t, specVectorThumbprintHex), specVectorResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover (encrypted): %v", err)
	}
	if bytes.Equal(handover, encrypted) {
		t.Fatalf("unencrypted handover must differ from encrypted handover")
	}

	// Reconstruct the null-thumbprint info and confirm element 3 is CBOR null (0xf6).
	info := []any{specVectorClientID, specVectorNonce, nil, specVectorResponseURI}
	infoBytes, err := intcose.MarshalDeterministic(info)
	if err != nil {
		t.Fatalf("encode null info: %v", err)
	}
	if !bytes.Contains(infoBytes, []byte{0xf6}) {
		t.Fatalf("null thumbprint must encode a CBOR null (0xf6); got % x", infoBytes)
	}
}

// TestOpenID4VPHandoverRequiresInputs guards the required-field validation so a
// caller cannot silently build a handover missing client_id, nonce, or
// response_uri (which would otherwise produce a transcript that fails interop).
func TestOpenID4VPHandoverRequiresInputs(t *testing.T) {
	cases := []struct {
		name                          string
		clientID, nonce, responseURI  string
	}{
		{"missing client_id", "", specVectorNonce, specVectorResponseURI},
		{"missing nonce", specVectorClientID, "", specVectorResponseURI},
		{"missing response_uri", specVectorClientID, specVectorNonce, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewOpenID4VPHandover(tc.clientID, tc.nonce, nil, tc.responseURI); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

// TestOpenID4VPHandoverIdentifierString sanity-checks the fixed identifier so a
// rename cannot silently change the wire format.
func TestOpenID4VPHandoverIdentifierString(t *testing.T) {
	if openID4VPHandoverContext != "OpenID4VPHandover" {
		t.Fatalf("handover identifier must be the spec literal, got %q", openID4VPHandoverContext)
	}
	handover, err := NewOpenID4VPHandover(specVectorClientID, specVectorNonce, nil, specVectorResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	if !strings.Contains(string(handover), "OpenID4VPHandover") {
		t.Fatalf("encoded handover must contain the fixed identifier text")
	}
}

// The following golden vectors are the non-normative examples in OID4VP 1.0
// Appendix B.2.6.2 (the W3C Digital Credentials API handover). They are the
// byte-exact pin for the OpenID4VPDCAPIHandover construction used by HAIP 1.0
// Section 5.2. The encryption JWK is the same as the redirect example, so the
// RFC 7638 thumbprint matches specVectorThumbprintHex above.
const (
	dcapiVectorOrigin = "https://example.com"
	// SHA-256(CBOR(OpenID4VPDCAPIHandoverInfo)).
	dcapiVectorInfoHashHex = "fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
	// CBOR of OpenID4VPDCAPIHandover ["OpenID4VPDCAPIHandover", infoHash].
	dcapiVectorHandoverHex = "82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
	// CBOR of the SessionTranscript [null, null, OpenID4VPDCAPIHandover].
	dcapiVectorTranscriptHex = "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
)

// TestOpenID4VPDCAPIHandoverSpecVector pins the DC API handover bytes to the
// OID4VP 1.0 Appendix B.2.6.2 non-normative example. This regression vector
// for the net-new HAIP DC API path: the info array is [origin, nonce,
// jwkThumbprint] and the identifier is "OpenID4VPDCAPIHandover".
func TestOpenID4VPDCAPIHandoverSpecVector(t *testing.T) {
	thumbprint := mustHex(t, specVectorThumbprintHex)

	handover, err := NewOpenID4VPDCAPIHandover(dcapiVectorOrigin, specVectorNonce, thumbprint)
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPIHandover: %v", err)
	}
	if got := hex.EncodeToString(handover); got != dcapiVectorHandoverHex {
		t.Fatalf("OpenID4VPDCAPIHandover mismatch\n got: %s\nwant: %s", got, dcapiVectorHandoverHex)
	}

	info := []any{dcapiVectorOrigin, specVectorNonce, thumbprint}
	infoBytes, err := intcose.MarshalDeterministic(info)
	if err != nil {
		t.Fatalf("encode info: %v", err)
	}
	infoHash := sha256.Sum256(infoBytes)
	if got := hex.EncodeToString(infoHash[:]); got != dcapiVectorInfoHashHex {
		t.Fatalf("OpenID4VPDCAPIHandoverInfoHash mismatch\n got: %s\nwant: %s", got, dcapiVectorInfoHashHex)
	}
}

// TestOpenID4VPDCAPISessionTranscriptSpecVector pins the full [null, null,
// OpenID4VPDCAPIHandover] SessionTranscript bytes to the spec example.
func TestOpenID4VPDCAPISessionTranscriptSpecVector(t *testing.T) {
	thumbprint := mustHex(t, specVectorThumbprintHex)

	st, err := NewOpenID4VPDCAPISessionTranscript(dcapiVectorOrigin, specVectorNonce, thumbprint)
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPISessionTranscript: %v", err)
	}
	encoded, err := st.Encode()
	if err != nil {
		t.Fatalf("encode transcript: %v", err)
	}
	if got := hex.EncodeToString(encoded); got != dcapiVectorTranscriptHex {
		t.Fatalf("DC API SessionTranscript mismatch\n got: %s\nwant: %s", got, dcapiVectorTranscriptHex)
	}
}

// TestOpenID4VPDCAPIHandoverDistinctFromRedirect proves the two handover
// variants never collide: with identical nonce and thumbprint the DC API
// handover (3-element [origin, nonce, thumbprint]) differs from the redirect
// handover (4-element [client_id, nonce, thumbprint, response_uri]). Conflating
// them would silently break the DC API path.
func TestOpenID4VPDCAPIHandoverDistinctFromRedirect(t *testing.T) {
	thumbprint := mustHex(t, specVectorThumbprintHex)

	dcapi, err := NewOpenID4VPDCAPIHandover(dcapiVectorOrigin, specVectorNonce, thumbprint)
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPIHandover: %v", err)
	}
	redirect, err := NewOpenID4VPHandover(specVectorClientID, specVectorNonce, thumbprint, specVectorResponseURI)
	if err != nil {
		t.Fatalf("NewOpenID4VPHandover: %v", err)
	}
	if bytes.Equal(dcapi, redirect) {
		t.Fatalf("DC API and redirect handovers must never be byte-equal")
	}
	if !strings.Contains(string(dcapi), "OpenID4VPDCAPIHandover") {
		t.Fatalf("DC API handover must contain its fixed identifier text")
	}
}

// TestOpenID4VPDCAPIHandoverUnencryptedNull verifies that the unencrypted
// dc_api mode (no encryption key) encodes the third element as CBOR null.
func TestOpenID4VPDCAPIHandoverUnencryptedNull(t *testing.T) {
	unencrypted, err := NewOpenID4VPDCAPIHandover(dcapiVectorOrigin, specVectorNonce, nil)
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPIHandover: %v", err)
	}
	encrypted, err := NewOpenID4VPDCAPIHandover(dcapiVectorOrigin, specVectorNonce, mustHex(t, specVectorThumbprintHex))
	if err != nil {
		t.Fatalf("NewOpenID4VPDCAPIHandover (encrypted): %v", err)
	}
	if bytes.Equal(unencrypted, encrypted) {
		t.Fatalf("unencrypted dc_api handover must differ from encrypted dc_api.jwt handover")
	}
	info := []any{dcapiVectorOrigin, specVectorNonce, nil}
	infoBytes, err := intcose.MarshalDeterministic(info)
	if err != nil {
		t.Fatalf("encode null info: %v", err)
	}
	if !bytes.Contains(infoBytes, []byte{0xf6}) {
		t.Fatalf("null thumbprint must encode a CBOR null (0xf6); got % x", infoBytes)
	}
}

// TestOpenID4VPDCAPIHandoverRequiresInputs guards required-field validation.
func TestOpenID4VPDCAPIHandoverRequiresInputs(t *testing.T) {
	if _, err := NewOpenID4VPDCAPIHandover("", specVectorNonce, nil); err == nil {
		t.Fatalf("expected error for missing origin")
	}
	if _, err := NewOpenID4VPDCAPIHandover(dcapiVectorOrigin, "", nil); err == nil {
		t.Fatalf("expected error for missing nonce")
	}
}
