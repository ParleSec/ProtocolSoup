package mdoc

import (
	"crypto/sha256"
	"fmt"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
)

// openID4VPHandoverContext is the fixed text identifier that is the first
// element of OpenID4VPHandover (OID4VP 1.0 Appendix B.2.6.1).
const openID4VPHandoverContext = "OpenID4VPHandover"

// openID4VPDCAPIHandoverContext is the fixed text identifier that is the first
// element of OpenID4VPDCAPIHandover, the W3C Digital Credentials API handover
// variant (OID4VP 1.0 Appendix B.2.6.2). It is deliberately distinct from
// openID4VPHandoverContext so the redirect and DC API SessionTranscripts can
// never be confused on the wire.
const openID4VPDCAPIHandoverContext = "OpenID4VPDCAPIHandover"

// SessionTranscript is the ISO/IEC 18013-5 clause 9.1.5.1 structure that binds a
// device-authentication signature to a specific session:
//
//	SessionTranscript = [
//	    DeviceEngagementBytes / null,
//	    EReaderKeyBytes / null,
//	    Handover
//	]
//
// For the OID4VP online profile (ISO/IEC 18013-7) there is no proximity
// engagement, so DeviceEngagementBytes and EReaderKeyBytes are null and the
// Handover is the OID4VP-specific OpenID4VPHandover. A SessionTranscript that
// differs between holder and verifier is the single most common mdoc
// presentation failure, so this is the one shared construction both the wallet
// and verifier both call.
//
// The Handover contents are profile-sensitive, so this
// type models the Handover as opaque, already-encoded CBOR and never bakes in a
// guessed handover. Phases 4 and 5 are exercised with a fixed test handover.
type SessionTranscript struct {
	// DeviceEngagementBytes is the proximity device-engagement, tag-24 wrapped.
	// Nil encodes as CBOR null, which is what the OID4VP online profile uses.
	DeviceEngagementBytes intcose.RawCBOR
	// EReaderKeyBytes is the reader ephemeral key, tag-24 wrapped. Nil encodes
	// as CBOR null (OID4VP online profile).
	EReaderKeyBytes intcose.RawCBOR
	// Handover is the transport-specific handover as pre-encoded CBOR. Required.
	Handover intcose.RawCBOR
}

// cborNull is the canonical encoding of a CBOR null (RFC 8949 Section 3.3,
// major type 7, value 22). It fills the absent SessionTranscript slots.
var cborNull = intcose.RawCBOR{0xf6}

// NewOID4VPSessionTranscript builds the [null, null, Handover] SessionTranscript
// for the OID4VP online profile (ISO/IEC 18013-7). The handover bytes are pinned
// by the OID4VP online profile; callers supply them here.
func NewOID4VPSessionTranscript(handover []byte) (SessionTranscript, error) {
	if len(handover) == 0 {
		return SessionTranscript{}, fmt.Errorf("mdoc: SessionTranscript handover is required")
	}
	return SessionTranscript{Handover: intcose.RawCBOR(handover)}, nil
}

// NewOpenID4VPHandover builds the real OID4VP 1.0 Appendix B.2.6.1
// OpenID4VPHandover (the redirect / direct_post profile), replacing the fixed
// test handover used to bootstrap Phases 4 and 5. Because the SessionTranscript
// is shared, both the wallet (producer) and the verifier (reconstruction) call
// this single implementation, so they cannot drift.
//
//	OpenID4VPHandover = ["OpenID4VPHandover", OpenID4VPHandoverInfoHash]
//	OpenID4VPHandoverInfoHash = SHA-256( CBOR(OpenID4VPHandoverInfo) )
//	OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
//
// jwkThumbprint is the RFC 7638 SHA-256 thumbprint (raw 32 bytes) of the
// Verifier's response-encryption public key when the response is encrypted
// (direct_post.jwt); pass nil for an unencrypted response, which encodes the
// third element as CBOR null. This thumbprint is the coupling between the
// handover and the JWE: it MUST be the thumbprint of the key actually used to
// encrypt the response (OID4VP 1.0 Appendix B.2.6, anti-substitution).
//
// The returned bytes are the encoded OpenID4VPHandover, suitable as the Handover
// argument to NewOID4VPSessionTranscript.
func NewOpenID4VPHandover(clientID, nonce string, jwkThumbprint []byte, responseURI string) ([]byte, error) {
	if clientID == "" {
		return nil, fmt.Errorf("mdoc: OpenID4VPHandover requires client_id")
	}
	if nonce == "" {
		return nil, fmt.Errorf("mdoc: OpenID4VPHandover requires nonce")
	}
	if responseURI == "" {
		return nil, fmt.Errorf("mdoc: OpenID4VPHandover requires response_uri/redirect_uri")
	}
	// Third element: bstr thumbprint when encrypted, CBOR null otherwise. A nil
	// any encodes as CBOR null; a []byte encodes as a CBOR byte string.
	var thumbprint any
	if len(jwkThumbprint) > 0 {
		thumbprint = jwkThumbprint
	}
	info := []any{clientID, nonce, thumbprint, responseURI}
	infoBytes, err := intcose.MarshalDeterministic(info)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode OpenID4VPHandoverInfo: %w", err)
	}
	infoHash := sha256.Sum256(infoBytes)
	handover := []any{openID4VPHandoverContext, infoHash[:]}
	encoded, err := intcose.MarshalDeterministic(handover)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode OpenID4VPHandover: %w", err)
	}
	return encoded, nil
}

// NewOpenID4VPSessionTranscript composes NewOpenID4VPHandover and
// NewOID4VPSessionTranscript into the full [null, null, OpenID4VPHandover]
// SessionTranscript for the OID4VP 1.0 redirect / direct_post profile.
func NewOpenID4VPSessionTranscript(clientID, nonce string, jwkThumbprint []byte, responseURI string) (SessionTranscript, error) {
	handover, err := NewOpenID4VPHandover(clientID, nonce, jwkThumbprint, responseURI)
	if err != nil {
		return SessionTranscript{}, err
	}
	return NewOID4VPSessionTranscript(handover)
}

// NewOpenID4VPDCAPIHandover builds the OID4VP 1.0 Appendix B.2.6.2
// OpenID4VPDCAPIHandover, the second handover variant used when the presentation
// is invoked over the W3C Digital Credentials API (HAIP 1.0 Section 5.2). It is
// structurally distinct from the redirect handover: the info array is
// [origin, nonce, jwkThumbprint] (the Verifier's Origin replaces client_id and
// response_uri) and the fixed identifier is "OpenID4VPDCAPIHandover".
//
//	OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", OpenID4VPDCAPIHandoverInfoHash]
//	OpenID4VPDCAPIHandoverInfoHash = SHA-256( CBOR(OpenID4VPDCAPIHandoverInfo) )
//	OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint]
//
// origin is the Verifier's Origin exactly as authenticated by the platform and
// MUST NOT carry the "origin:" prefix (Appendix B.2.6.2). jwkThumbprint is the
// RFC 7638 SHA-256 thumbprint (raw 32 bytes) of the Verifier's
// response-encryption public key for Response Mode dc_api.jwt; pass nil for the
// unencrypted dc_api mode, which encodes the third element as CBOR null.
//
// Because both the wallet (producer) and the verifier (reconstruction) call this
// single shared implementation, the DC API SessionTranscript cannot drift.
func NewOpenID4VPDCAPIHandover(origin, nonce string, jwkThumbprint []byte) ([]byte, error) {
	if origin == "" {
		return nil, fmt.Errorf("mdoc: OpenID4VPDCAPIHandover requires origin")
	}
	if nonce == "" {
		return nil, fmt.Errorf("mdoc: OpenID4VPDCAPIHandover requires nonce")
	}
	// Third element: bstr thumbprint when encrypted (dc_api.jwt), CBOR null
	// otherwise (dc_api). A nil any encodes as CBOR null; a []byte encodes as a
	// CBOR byte string.
	var thumbprint any
	if len(jwkThumbprint) > 0 {
		thumbprint = jwkThumbprint
	}
	info := []any{origin, nonce, thumbprint}
	infoBytes, err := intcose.MarshalDeterministic(info)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode OpenID4VPDCAPIHandoverInfo: %w", err)
	}
	infoHash := sha256.Sum256(infoBytes)
	handover := []any{openID4VPDCAPIHandoverContext, infoHash[:]}
	encoded, err := intcose.MarshalDeterministic(handover)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode OpenID4VPDCAPIHandover: %w", err)
	}
	return encoded, nil
}

// NewOpenID4VPDCAPISessionTranscript composes NewOpenID4VPDCAPIHandover and
// NewOID4VPSessionTranscript into the full [null, null, OpenID4VPDCAPIHandover]
// SessionTranscript for the OID4VP 1.0 DC API profile (OID4VP Appendix B.2.6.2,
// HAIP 1.0 Section 5.2).
func NewOpenID4VPDCAPISessionTranscript(origin, nonce string, jwkThumbprint []byte) (SessionTranscript, error) {
	handover, err := NewOpenID4VPDCAPIHandover(origin, nonce, jwkThumbprint)
	if err != nil {
		return SessionTranscript{}, err
	}
	return NewOID4VPSessionTranscript(handover)
}

// Encode produces the canonical CBOR of the 3-element SessionTranscript array.
// Absent DeviceEngagementBytes/EReaderKeyBytes are emitted as CBOR null. This is
// the exact byte string that both the holder and the verifier embed into
// DeviceAuthentication, so it must be produced identically on both sides.
func (st SessionTranscript) Encode() ([]byte, error) {
	if len(st.Handover) == 0 {
		return nil, fmt.Errorf("mdoc: SessionTranscript handover is required")
	}
	array := []intcose.RawCBOR{
		nullableRaw(st.DeviceEngagementBytes),
		nullableRaw(st.EReaderKeyBytes),
		intcose.RawCBOR(st.Handover),
	}
	encoded, err := intcose.MarshalDeterministic(array)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode SessionTranscript: %w", err)
	}
	return encoded, nil
}

// EncodeHandover canonical-encodes an arbitrary value into CBOR for use as the
// SessionTranscript Handover element. The online profile uses
// the pinned OpenID4VPHandover; this helper only provides deterministic CBOR so
// Phases 4 and 5 can exercise the construction with a fixed test handover.
func EncodeHandover(value any) ([]byte, error) {
	encoded, err := intcose.MarshalDeterministic(value)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode handover: %w", err)
	}
	return encoded, nil
}

func nullableRaw(raw intcose.RawCBOR) intcose.RawCBOR {
	if len(raw) == 0 {
		return cborNull
	}
	return raw
}
