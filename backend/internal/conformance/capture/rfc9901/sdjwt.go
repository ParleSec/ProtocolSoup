package rfc9901

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// The conformance client's reading and alteration of an issued SD-JWT
// (RFC 9901 Section 4). It is written here, independently of the product's
// credential libraries, so the verifier is never checked by its own code.

// sdJWT is an SD-JWT without a Key Binding JWT, split at its tildes.
type sdJWT struct {
	IssuerSignedJWT string
	Disclosures     []string
}

// splitSDJWT splits an issued SD-JWT, which must end in "~" because it
// carries no Key Binding JWT.
func splitSDJWT(serialized string) (*sdJWT, error) {
	if !strings.HasSuffix(serialized, "~") {
		return nil, fmt.Errorf("issued SD-JWT does not end in a tilde")
	}
	parts := strings.Split(strings.TrimSuffix(serialized, "~"), "~")
	if strings.Count(parts[0], ".") != 2 {
		return nil, fmt.Errorf("issued SD-JWT does not start with a compact JWS")
	}
	return &sdJWT{IssuerSignedJWT: parts[0], Disclosures: parts[1:]}, nil
}

// serialize joins the parts in the RFC 9901 Section 4 order, ending in "~".
func (s *sdJWT) serialize() string {
	return strings.Join(append([]string{s.IssuerSignedJWT}, s.Disclosures...), "~") + "~"
}

// payload decodes the Issuer-signed JWT payload, keeping numbers exact.
func (s *sdJWT) payload() (map[string]any, error) {
	segments := strings.Split(s.IssuerSignedJWT, ".")
	raw, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("decode issuer-signed JWT payload: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("parse issuer-signed JWT payload: %w", err)
	}
	return payload, nil
}

// replacePayload re-encodes the Issuer-signed JWT payload after alter has
// changed it, keeping the issuer's header and signature as they were. The
// signature then no longer covers the payload it sits beside.
func (s *sdJWT) replacePayload(alter func(payload map[string]any) error) error {
	payload, err := s.payload()
	if err != nil {
		return err
	}
	if err := alter(payload); err != nil {
		return err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return err
	}
	segments := strings.Split(s.IssuerSignedJWT, ".")
	segments[1] = base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
	s.IssuerSignedJWT = strings.Join(segments, ".")
	return nil
}

// sdDigests reads the top-level _sd array of the Issuer-signed JWT payload.
func sdDigests(payload map[string]any) ([]string, error) {
	raw, _ := payload["_sd"].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("issuer-signed JWT payload has no top-level _sd digests")
	}
	digests := make([]string, 0, len(raw))
	for _, value := range raw {
		digest, ok := value.(string)
		if !ok || digest == "" {
			return nil, fmt.Errorf("issuer-signed JWT payload _sd carries a non-string digest")
		}
		digests = append(digests, digest)
	}
	return digests, nil
}

// objectDisclosure is a decoded [salt, claim name, claim value] Disclosure
// (RFC 9901 Section 4.2.1).
type objectDisclosure struct {
	ClaimName  string
	ClaimValue any
}

// decodeObjectDisclosure decodes an issued object-property Disclosure.
func decodeObjectDisclosure(encoded string) (*objectDisclosure, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode disclosure: %w", err)
	}
	var elements []any
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil, fmt.Errorf("parse disclosure: %w", err)
	}
	if len(elements) != 3 {
		return nil, fmt.Errorf("issued disclosure has %d elements, want 3", len(elements))
	}
	name, ok := elements[1].(string)
	if !ok || name == "" {
		return nil, fmt.Errorf("issued disclosure has no claim name")
	}
	return &objectDisclosure{ClaimName: name, ClaimValue: elements[2]}, nil
}

// newObjectDisclosure builds a [salt, claim name, claim value] Disclosure
// with a fresh 128-bit salt (RFC 9901 Sections 4.2.1 and 9.3).
func newObjectDisclosure(claimName string, claimValue any) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	raw, err := json.Marshal([]any{base64.RawURLEncoding.EncodeToString(salt), claimName, claimValue})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// sha256Digest is the RFC 9901 Section 4.2.3 digest of a Disclosure under
// sha-256.
func sha256Digest(disclosure string) string {
	sum := sha256.Sum256([]byte(disclosure))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// sha384Digest is the same digest under sha-384.
func sha384Digest(disclosure string) string {
	sum := sha512.Sum384([]byte(disclosure))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
