package oid4vci

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	intcose "github.com/ParleSec/ProtocolSoup/internal/cose"
	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/mdoc"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
)

// TestMsoMdocStoredInWalletStore confirms the issued mso_mdoc IssuerSigned (plus
// MSO) is persisted in the shared wallet credential store, keyed by the holder
// subject and the mDL doctype -- the wallet storage requirement exercised
// against the real store.
func TestMsoMdocStoredInWalletStore(t *testing.T) {
	server, _, _ := newMdocTestEnv(t)
	defer server.Close()
	store := vc.DefaultWalletCredentialStore()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{mdocConfigurationID},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	walletSubject := asString(t, offerPayload["wallet_subject"])

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	cNonce := asString(t, tokenPayload["c_nonce"])

	// Use a persistent device key, reload it, and confirm the same key survives
	// the reload before binding it at issuance.
	keyPath := filepath.Join(t.TempDir(), "device_key.pem")
	deviceKey, err := crypto.LoadOrCreateDeviceKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceKey: %v", err)
	}
	reloaded, err := crypto.LoadOrCreateDeviceKey(keyPath)
	if err != nil {
		t.Fatalf("reload device key: %v", err)
	}
	if !reloaded.PublicKey.Equal(&deviceKey.PublicKey) {
		t.Fatal("persistent device key changed across reload")
	}

	proofJWT := createECDeviceProof(t, deviceKey, cNonce, walletSubject, testIssuerAudience)
	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": mdocConfigurationID,
			"format":                      "mso_mdoc",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)

	record, ok := store.FindByConfiguration(walletSubject, mdocConfigurationID)
	if !ok {
		t.Fatalf("issued mso_mdoc credential not found in wallet store for subject %q", walletSubject)
	}
	if record.Format != "mso_mdoc" {
		t.Fatalf("stored format = %q, want mso_mdoc", record.Format)
	}
	if record.Doctype != mdoc.DocTypeMDL {
		t.Fatalf("stored doctype = %q, want %q", record.Doctype, mdoc.DocTypeMDL)
	}

	// The stored artifact must decode to the IssuerSigned bound to the device key.
	raw, err := base64.RawURLEncoding.DecodeString(record.IssuerSignedJWT)
	if err != nil {
		t.Fatalf("decode stored IssuerSigned: %v", err)
	}
	issuerSigned, err := mdoc.DecodeIssuerSigned(raw)
	if err != nil {
		t.Fatalf("DecodeIssuerSigned from store: %v", err)
	}
	msoBytes, _, err := mdoc.ParseIssuerAuth(issuerSigned.IssuerAuth)
	if err != nil {
		t.Fatalf("ParseIssuerAuth: %v", err)
	}
	mso, err := mdoc.DecodeMSOBytes(msoBytes)
	if err != nil {
		t.Fatalf("DecodeMSOBytes: %v", err)
	}
	boundKey, err := intcose.COSEKeyToECPublicKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		t.Fatalf("COSEKeyToECPublicKey: %v", err)
	}
	if !boundKey.Equal(&deviceKey.PublicKey) {
		t.Fatal("stored credential is not bound to the persistent device key")
	}
}
