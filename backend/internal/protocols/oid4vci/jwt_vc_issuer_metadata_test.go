package oid4vci

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
)

func fetchJWTVCIssuerMetadata(t *testing.T, p *Plugin, path string) (*httptest.ResponseRecorder, map[string]json.RawMessage) {
	t.Helper()
	rr := httptest.NewRecorder()
	p.handleJWTVCIssuerMetadata(rr, httptest.NewRequest(http.MethodGet, path, nil))
	var document map[string]json.RawMessage
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &document); err != nil {
			t.Fatalf("decode JWT VC Issuer Metadata: %v", err)
		}
	}
	return rr, document
}

// SD-JWT VC draft 11 Section 5: the configuration is at the location formed
// by inserting /.well-known/jwt-vc-issuer between the host and the path of
// the iss value, is returned as application/json, names the issuer, and
// "MUST include either jwks_uri or jwks ... but not both."
func TestJWTVCIssuerMetadataIsServedAtTheIssuersWellKnownLocation(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	rr, document := fetchJWTVCIssuerMetadata(t, env.Plugin, env.Plugin.jwtVCIssuerMetadataPath())
	if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, Content-Type = %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var issuer string
	if err := json.Unmarshal(document["issuer"], &issuer); err != nil || issuer != env.Plugin.issuerID() {
		t.Fatalf("issuer = %s, want %q", document["issuer"], env.Plugin.issuerID())
	}
	if _, byValue := document["jwks"]; !byValue {
		t.Fatal("the configuration must carry the keys in jwks")
	}
	if _, byReference := document["jwks_uri"]; byReference {
		t.Fatal("the configuration must not carry both jwks and jwks_uri")
	}

	for _, path := range []string{jwtVCIssuerWellKnown, jwtVCIssuerWellKnown + "/someone-else", "/oid4vci" + jwtVCIssuerWellKnown} {
		if path == env.Plugin.jwtVCIssuerMetadataPath() {
			continue
		}
		if rr, _ := fetchJWTVCIssuerMetadata(t, env.Plugin, path); rr.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", path, rr.Code)
		}
	}
}

// SD-JWT VC draft 11 Section 3.5 defines two Issuer Signature Mechanisms, the
// chain in x5c and JWT VC Issuer Metadata. Every SD-JWT VC this Issuer signs
// must validate by both, and both must lead to the same key.
func TestEverySDJWTVCValidatesByBothIssuerSignatureMechanisms(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	_, document := fetchJWTVCIssuerMetadata(t, env.Plugin, env.Plugin.jwtVCIssuerMetadataPath())
	var metadataIssuer string
	var keys crypto.JWKS
	if err := json.Unmarshal(document["issuer"], &metadataIssuer); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(document["jwks"], &keys); err != nil {
		t.Fatal(err)
	}

	for id, wantStatus := range map[string]bool{"UniversityDegreeCredentialSDJWT": false, "UniversityDegreeCredentialSDJWTHAIP": true} {
		t.Run(id, func(t *testing.T) {
			configuration := env.Plugin.credentialConfigurations[id]
			if !reflect.DeepEqual(configuration.CredentialSigningAlgs, []interface{}{"ES256"}) {
				t.Fatalf("advertised credential signing algorithms = %v, want [ES256]", configuration.CredentialSigningAlgs)
			}
			issued, err := (&sdJWTCredentialIssuerDriver{plugin: env.Plugin}).IssueCredential(
				"wallet-subject", configuration, &walletIdentity{GivenName: "Alice", FamilyName: "Holder"}, nil)
			if err != nil {
				t.Fatalf("IssueCredential: %v", err)
			}
			envelope, err := vc.ParseSDJWTEnvelope(issued.Credential.(string))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Header["alg"] != "ES256" || decoded.Header["typ"] != "dc+sd-jwt" {
				t.Fatalf("header = %v", decoded.Header)
			}

			// X.509: leaf first, no trust anchor, chaining to the Issuer's root.
			chain, err := crypto.ParseX5CCertificateChain(decoded.Header["x5c"])
			if err != nil {
				t.Fatalf("x5c: %v", err)
			}
			if len(chain) != 1 || chain[0].IsCA {
				t.Fatalf("x5c must carry the end-entity certificate and not the trust anchor, got %d certificates", len(chain))
			}
			if _, err := crypto.ValidateCertificateChainAgainstRoots(chain, env.Plugin.mdocPKI.TrustAnchors(), time.Now()); err != nil {
				t.Fatalf("x5c does not chain to the Issuer's trust anchor: %v", err)
			}

			// JWT VC Issuer Metadata: issuer equals iss, kid selects one key.
			if decoded.Payload["iss"] != metadataIssuer {
				t.Fatalf("iss = %v, JWT VC Issuer Metadata issuer = %q", decoded.Payload["iss"], metadataIssuer)
			}
			var selected []crypto.JWK
			for _, key := range keys.Keys {
				if key.Kid != "" && key.Kid == decoded.Header["kid"] {
					selected = append(selected, key)
				}
			}
			if len(selected) != 1 {
				t.Fatalf("kid %v selects %d keys in the JWT VC Issuer Metadata, want 1", decoded.Header["kid"], len(selected))
			}
			publicKey, err := selected[0].ToPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := crypto.VerifySignatureWithKey(envelope.IssuerSignedJWT, publicKey); err != nil || !valid {
				t.Fatalf("the signature does not verify under the JWT VC Issuer Metadata key: valid=%v err=%v", valid, err)
			}
			if valid, err := crypto.VerifySignatureWithKey(envelope.IssuerSignedJWT, chain[0].PublicKey); err != nil || !valid {
				t.Fatalf("the signature does not verify under the x5c end-entity key: valid=%v err=%v", valid, err)
			}

			if _, hasStatus := decoded.Payload["status"]; hasStatus != wantStatus {
				t.Fatalf("status claim present = %v, want %v", hasStatus, wantStatus)
			}
		})
	}
}
