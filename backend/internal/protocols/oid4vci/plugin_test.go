package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/ParleSec/ProtocolSoup/pkg/models"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

const testIssuerAudience = "http://localhost:8080/oid4vci"

func TestIssuerInitiatedOfferTracksRealLifecycle(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	offerResp := postJSONWithHeaders(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	}, map[string]string{"X-Looking-Glass-Session": "issuer-session"})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	issuerState := asString(t, offer["issuer_state"])
	statusURI, err := url.Parse(asString(t, offer["status_uri"]))
	if err != nil {
		t.Fatalf("parse status_uri: %v", err)
	}

	readStatus := func() map[string]interface{} {
		resp, err := http.Get(env.Server.URL + statusURI.Path)
		if err != nil {
			t.Fatalf("get issuer-initiated status: %v", err)
		}
		assertStatus(t, resp, http.StatusOK)
		return decodeJSONMap(t, resp)
	}
	if got := asString(t, readStatus()["status"]); got != issuerInitiatedStatusWaitingForWallet {
		t.Fatalf("initial status = %q, want %q", got, issuerInitiatedStatusWaitingForWallet)
	}

	transaction, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		issuerState,
		"attested-wallet",
		[]string{"MobileDrivingLicenceMsoMdocHAIP"},
	)
	if err != nil {
		t.Fatalf("accept issuer_state: %v", err)
	}
	if transaction.SessionID != "issuer-session" {
		t.Fatalf("session ID = %q, want issuer-session", transaction.SessionID)
	}
	if got := asString(t, readStatus()["status"]); got != issuerInitiatedStatusAuthorizationRequestReceived {
		t.Fatalf("PAR status = %q, want %q", got, issuerInitiatedStatusAuthorizationRequestReceived)
	}
	// Multi-client happy flow reuses the same issuer_state for a
	// consecutive second client. The offer context stays redeemable until TTL.
	second, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		issuerState,
		"attested-wallet-2",
		[]string{"MobileDrivingLicenceMsoMdocHAIP"},
	)
	if err != nil {
		t.Fatalf("second-client issuer_state reuse: %v", err)
	}
	if second.ClientID != "attested-wallet-2" {
		t.Fatalf("second client ID = %q, want attested-wallet-2", second.ClientID)
	}

	env.Plugin.updateIssuerInitiatedTransaction(issuerState, issuerInitiatedStatusTokenIssued)
	if got := asString(t, readStatus()["status"]); got != issuerInitiatedStatusTokenIssued {
		t.Fatalf("token status = %q, want %q", got, issuerInitiatedStatusTokenIssued)
	}
	env.Plugin.updateIssuerInitiatedTransaction(issuerState, issuerInitiatedStatusCredentialIssued)
	completed := readStatus()
	if got := asString(t, completed["status"]); got != issuerInitiatedStatusCredentialIssued {
		t.Fatalf("terminal status = %q, want %q", got, issuerInitiatedStatusCredentialIssued)
	}
	if terminal, ok := completed["terminal"].(bool); !ok || !terminal {
		t.Fatalf("terminal = %v, want true", completed["terminal"])
	}
}

func TestIssuerInitiatedOfferDeliversToWalletCredentialOfferEndpoint(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	var receivedOffer string
	wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("wallet endpoint method = %s, want GET", r.Method)
		}
		receivedOffer = r.URL.Query().Get("credential_offer")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer wallet.Close()

	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
		"credential_offer_endpoint":    wallet.URL + "/credential_offer",
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	if delivered, ok := offer["credential_offer_delivered"].(bool); !ok || !delivered {
		t.Fatalf("credential_offer_delivered = %v, want true", offer["credential_offer_delivered"])
	}
	if asString(t, offer["credential_offer_endpoint"]) != wallet.URL+"/credential_offer" {
		t.Fatalf("unexpected credential_offer_endpoint %v", offer["credential_offer_endpoint"])
	}
	if receivedOffer == "" {
		t.Fatal("wallet credential_offer_endpoint was not invoked with credential_offer")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(receivedOffer), &parsed); err != nil {
		t.Fatalf("decode delivered credential_offer: %v", err)
	}
	if asString(t, parsed["credential_issuer"]) == "" {
		t.Fatal("delivered credential_offer missing credential_issuer")
	}
	if _, present := parsed["created_at"]; present {
		t.Fatal("delivered credential_offer must omit non-spec created_at")
	}
}

func TestIssuerInitiatedOfferDeliveryAcceptsRedirectWithoutFollowing(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	var hits int
	wallet := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/after" {
			t.Fatal("issuer followed credential_offer_endpoint redirect")
		}
		if r.URL.Query().Get("credential_offer") == "" {
			t.Fatal("wallet credential_offer_endpoint missing credential_offer")
		}
		http.Redirect(w, r, "/after", http.StatusFound)
	}))
	defer wallet.Close()

	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
		"credential_offer_endpoint":    wallet.URL + "/credential_offer",
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	if delivered, ok := offer["credential_offer_delivered"].(bool); !ok || !delivered {
		t.Fatalf("credential_offer_delivered = %v, want true", offer["credential_offer_delivered"])
	}
	if status, ok := offer["credential_offer_delivery_status"].(float64); !ok || int(status) != http.StatusFound {
		t.Fatalf("credential_offer_delivery_status = %v, want %d", offer["credential_offer_delivery_status"], http.StatusFound)
	}
	if hits != 1 {
		t.Fatalf("wallet endpoint hits = %d, want 1", hits)
	}
}

func TestIssuerInitiatedScopeIntersectsOfferedConfigurations(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	issuerState := asString(t, offer["issuer_state"])

	fromScope := env.Plugin.credentialConfigurationIDsForScope("vc:mdl")
	if len(fromScope) < 2 {
		t.Fatalf("scope vc:mdl mapped to %v, want both educational and HAIP mdoc configs", fromScope)
	}
	offered := env.Plugin.issuerInitiatedOfferedConfigurationIDs(issuerState)
	bound := intersectCredentialConfigurationIDs(fromScope, offered)
	if len(bound) != 1 || bound[0] != "MobileDrivingLicenceMsoMdocHAIP" {
		t.Fatalf("intersection = %v, want [MobileDrivingLicenceMsoMdocHAIP]", bound)
	}
	transaction, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		issuerState,
		"attested-wallet",
		bound,
	)
	if err != nil {
		t.Fatalf("accept intersected issuer_state: %v", err)
	}
	if len(transaction.CredentialConfigurationIDs) != 1 || transaction.CredentialConfigurationIDs[0] != "MobileDrivingLicenceMsoMdocHAIP" {
		t.Fatalf("bound configurations = %v", transaction.CredentialConfigurationIDs)
	}
}

func TestIssuerInitiatedOfferRejectsPrivateCredentialOfferEndpoint(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
		"credential_offer_endpoint":    "https://10.0.0.8/credential_offer",
	})
	assertStatus(t, offerResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, offerResp)
	if asString(t, payload["error"]) != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", asString(t, payload["error"]))
	}
}

func TestIssuerInitiatedOfferAllowsConsecutiveClientReuseUntilExpiry(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	issuerState := asString(t, offer["issuer_state"])

	if _, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		issuerState,
		"client-1",
		[]string{"MobileDrivingLicenceMsoMdocHAIP"},
	); err != nil {
		t.Fatalf("client-1 accept: %v", err)
	}
	env.Plugin.updateIssuerInitiatedTransaction(issuerState, issuerInitiatedStatusCredentialIssued)

	// Suite second-client step appends ?dummy1=lorem&dummy2=ipsum to redirect_uri
	// and reuses the same issuer_state after client 1 has already obtained a credential.
	second, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		issuerState,
		"client-2",
		[]string{"MobileDrivingLicenceMsoMdocHAIP"},
	)
	if err != nil {
		t.Fatalf("client-2 reuse after credential_issued: %v", err)
	}
	if second.Status != issuerInitiatedStatusAuthorizationRequestReceived {
		t.Fatalf("status after client-2 PAR = %q, want %q", second.Status, issuerInitiatedStatusAuthorizationRequestReceived)
	}
	if second.ClientID != "client-2" {
		t.Fatalf("client ID = %q, want client-2", second.ClientID)
	}
}

func TestIssuerInitiatedOfferRejectsInjectedOrMismatchedIssuerState(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	if _, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		"attacker-injected",
		"attested-wallet",
		[]string{"MobileDrivingLicenceMsoMdocHAIP"},
	); err == nil {
		t.Fatal("unknown issuer_state was accepted")
	}

	offerResp := postJSON(t, env.Server.URL+"/oid4vci/offers/authorization-code", map[string]interface{}{
		"credential_configuration_ids": []string{"MobileDrivingLicenceMsoMdocHAIP"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	if _, err := env.Plugin.acceptIssuerInitiatedAuthorizationRequest(
		asString(t, offer["issuer_state"]),
		"attested-wallet",
		[]string{"UniversityDegreeCredentialSDJWTHAIP"},
	); err == nil {
		t.Fatal("issuer_state was accepted for a Credential Configuration not present in the offer")
	}
}

func TestPreAuthorizedGrantRejectsUnexpectedTxCode(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)

	resp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offer["pre_authorized_code"])},
		"tx_code":             {"unexpected"},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if got := asString(t, payload["error"]); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

func TestPreAuthorizedGrantDistinguishesMissingAndWrongTxCode(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
		"tx_code_required":             true,
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	code := asString(t, offer["pre_authorized_code"])

	request := func(txCode string) map[string]interface{} {
		values := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {code},
		}
		if txCode != "" {
			values.Set("tx_code", txCode)
		}
		resp, err := http.PostForm(server.URL+"/oid4vci/token", values)
		if err != nil {
			t.Fatalf("token request failed: %v", err)
		}
		assertStatus(t, resp, http.StatusBadRequest)
		return decodeJSONMap(t, resp)
	}
	if got := asString(t, request("")["error"]); got != "invalid_request" {
		t.Fatalf("missing tx_code error = %q, want invalid_request", got)
	}
	if got := asString(t, request("wrong")["error"]); got != "invalid_grant" {
		t.Fatalf("wrong tx_code error = %q, want invalid_grant", got)
	}
}

func TestPreAuthorizedGrantExchangeIsAtomic(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	code := asString(t, offer["pre_authorized_code"])

	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			resp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
				"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
				"pre-authorized_code": {code},
			})
			if err != nil {
				statuses <- 0
				return
			}
			defer resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	counts := map[int]int{<-statuses: 1}
	counts[<-statuses]++
	if counts[http.StatusOK] != 1 || counts[http.StatusBadRequest] != 1 {
		t.Fatalf("concurrent exchange statuses = %#v, want one 200 and one 400", counts)
	}
}

func TestCredentialNonceConsumptionIsAtomic(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offer["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	token := asString(t, decodeJSONMap(t, tokenResp)["access_token"])
	nonce := fetchCNonce(t, server.URL, token)
	proof := createWalletProofJWT(t, nonce, asString(t, offer["wallet_subject"]), testIssuerAudience)
	body, err := json.Marshal(map[string]interface{}{
		"credential_configuration_id": "UniversityDegreeCredential",
		"proofs":                      map[string]interface{}{"jwt": []string{proof}},
	})
	if err != nil {
		t.Fatalf("marshal credential request: %v", err)
	}

	statuses := make(chan int, 2)
	for range 2 {
		go func() {
			req, requestErr := http.NewRequest(http.MethodPost, server.URL+"/oid4vci/credential", bytes.NewReader(body))
			if requestErr != nil {
				statuses <- 0
				return
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, requestErr := http.DefaultClient.Do(req)
			if requestErr != nil {
				statuses <- 0
				return
			}
			defer resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	counts := map[int]int{<-statuses: 1}
	counts[<-statuses]++
	if counts[http.StatusOK] != 1 || counts[http.StatusBadRequest] != 1 {
		t.Fatalf("concurrent credential statuses = %#v, want one 200 and one 400", counts)
	}
}

func TestPreAuthorizedFlowWithTxCodeAndProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	if got := asString(t, offerPayload["credential_issuer"]); got != testIssuerAudience {
		t.Fatalf("create-offer credential_issuer = %q, want %q", got, testIssuerAudience)
	}
	preAuthCode := asString(t, offerPayload["pre_authorized_code"])
	offerURI := asString(t, offerPayload["credential_offer_uri"])
	walletSubject := asString(t, offerPayload["wallet_subject"])

	offerURL, err := url.Parse(offerURI)
	if err != nil {
		t.Fatalf("parse offer URI: %v", err)
	}
	offerGetResp, err := http.Get(server.URL + offerURL.Path)
	if err != nil {
		t.Fatalf("get credential offer: %v", err)
	}
	assertStatus(t, offerGetResp, http.StatusOK)
	_ = offerGetResp.Body.Close()

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthCode},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])
	assertTokenResponseHasNoCredentialNonce(t, tokenPayload)
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	credentialPayload := decodeJSONMap(t, credentialResp)
	if asString(t, firstCredential(t, credentialPayload)) == "" {
		t.Fatalf("expected credential in response")
	}
}

func TestCredentialIssuerMetadataWellKnown(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/openid-credential-issuer")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)

	if asString(t, payload["credential_issuer"]) == "" {
		t.Fatalf("expected credential_issuer in metadata")
	}
	if asString(t, payload["credential_endpoint"]) == "" {
		t.Fatalf("expected credential_endpoint in metadata")
	}
	if asString(t, payload["nonce_endpoint"]) == "" {
		t.Fatalf("expected nonce_endpoint in metadata")
	}
	if asString(t, payload["notification_endpoint"]) == "" {
		t.Fatalf("expected notification_endpoint in metadata")
	}
	if _, stale := payload["token_endpoint"]; stale {
		t.Fatal("Final Credential Issuer Metadata must not contain draft token_endpoint")
	}
	if _, advertised := payload["batch_credential_endpoint"]; advertised {
		t.Fatal("issuer must not advertise an unsupported Batch Credential Endpoint")
	}
	batchIssuance, ok := payload["batch_credential_issuance"].(map[string]interface{})
	if !ok {
		t.Fatal("issuer must advertise batch_credential_issuance for multi-proof Credential Endpoint issuance")
	}
	batchSize, ok := batchIssuance["batch_size"].(float64)
	if !ok || int(batchSize) != batchCredentialIssuanceBatchSize {
		t.Fatalf("batch_credential_issuance.batch_size = %#v, want %d", batchIssuance["batch_size"], batchCredentialIssuanceBatchSize)
	}

	authorizationServers, ok := payload["authorization_servers"].([]interface{})
	if !ok || len(authorizationServers) != 1 {
		t.Fatalf("authorization_servers = %#v, want one issuer identifier", payload["authorization_servers"])
	}
	asResp, err := http.Get(server.URL + "/oid4vci/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("authorization server metadata request failed: %v", err)
	}
	assertStatus(t, asResp, http.StatusOK)
	asMetadata := decodeJSONMap(t, asResp)
	if asString(t, asMetadata["issuer"]) != asString(t, authorizationServers[0]) {
		t.Fatalf("authorization server issuer %q does not match advertised identity %q", asString(t, asMetadata["issuer"]), asString(t, authorizationServers[0]))
	}
}

func TestCredentialIssuerMetadataIncludesMultiFormatConfigurations(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/openid-credential-issuer")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)

	configurations, ok := payload["credential_configurations_supported"].(map[string]interface{})
	if !ok || len(configurations) == 0 {
		t.Fatalf("expected credential_configurations_supported map")
	}
	// HAIP issuer profiles only accept dc+sd-jwt and mso_mdoc in metadata.
	// W3C formats remain issuable via the registry but are not advertised here.
	expectedFormats := map[string]string{
		"UniversityDegreeCredential":          "dc+sd-jwt",
		"UniversityDegreeCredentialSDJWT":     "dc+sd-jwt",
		"UniversityDegreeCredentialSDJWTHAIP": "dc+sd-jwt",
		"MobileDrivingLicenceMsoMdoc":         "mso_mdoc",
		"MobileDrivingLicenceMsoMdocHAIP":     "mso_mdoc",
	}
	for configurationID, expectedFormat := range expectedFormats {
		rawConfiguration, ok := configurations[configurationID]
		if !ok {
			t.Fatalf("expected configuration %q in metadata", configurationID)
		}
		configuration, ok := rawConfiguration.(map[string]interface{})
		if !ok {
			t.Fatalf("expected configuration %q to be object", configurationID)
		}
		if asString(t, configuration["format"]) != expectedFormat {
			t.Fatalf("expected configuration %q format %q, got %q", configurationID, expectedFormat, asString(t, configuration["format"]))
		}
		if _, present := configuration["claims"]; present {
			t.Fatalf("configuration %q must nest claims under credential_metadata (OID4VCI 1.0 Final)", configurationID)
		}
		if expectedFormat == credentialFormatDCSdJWT {
			if _, present := configuration["credential_definition"]; present {
				t.Fatalf("dc+sd-jwt configuration %q must use vct, not credential_definition", configurationID)
			}
			if asString(t, configuration["vct"]) == "" {
				t.Fatalf("dc+sd-jwt configuration %q missing vct", configurationID)
			}
		}
	}
	for _, configurationID := range []string{
		"UniversityDegreeCredentialJWT",
		"UniversityDegreeCredentialJWTLD",
		"UniversityDegreeCredentialLDP",
	} {
		if _, present := configurations[configurationID]; present {
			t.Fatalf("W3C configuration %q must not be advertised in Credential Issuer Metadata", configurationID)
		}
	}
	for _, configurationID := range []string{"MobileDrivingLicenceMsoMdoc", "MobileDrivingLicenceMsoMdocHAIP"} {
		configuration, ok := configurations[configurationID].(map[string]interface{})
		if !ok {
			t.Fatalf("expected mdoc configuration %q to be object", configurationID)
		}
		algorithms, ok := configuration["credential_signing_alg_values_supported"].([]interface{})
		if !ok || len(algorithms) != 1 || algorithms[0] != float64(-7) {
			t.Fatalf(
				"mdoc configuration %q credential signing algorithms = %#v, want COSE algorithm -7",
				configurationID,
				configuration["credential_signing_alg_values_supported"],
			)
		}
		if _, present := configuration["claims"]; present {
			t.Fatalf("mdoc configuration %q must nest claims under credential_metadata", configurationID)
		}
		credentialMetadata, ok := configuration["credential_metadata"].(map[string]interface{})
		if !ok {
			t.Fatalf("mdoc configuration %q credential_metadata = %#v", configurationID, configuration["credential_metadata"])
		}
		claims, ok := credentialMetadata["claims"].([]interface{})
		if !ok || len(claims) == 0 {
			t.Fatalf("mdoc configuration %q credential_metadata.claims = %#v", configurationID, credentialMetadata["claims"])
		}
	}
}

func TestCredentialIssuanceSupportsMultipleFormats(t *testing.T) {
	testCases := []struct {
		name                      string
		credentialConfigurationID string
		format                    string
	}{
		{name: "sd-jwt", credentialConfigurationID: "UniversityDegreeCredential", format: "dc+sd-jwt"},
		{name: "jwt-vc-json", credentialConfigurationID: "UniversityDegreeCredentialJWT", format: "jwt_vc_json"},
		{name: "jwt-vc-json-ld", credentialConfigurationID: "UniversityDegreeCredentialJWTLD", format: "jwt_vc_json-ld"},
		{name: "ldp-vc", credentialConfigurationID: "UniversityDegreeCredentialLDP", format: "ldp_vc"},
	}
	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			server := newTestServer(t)
			defer server.Close()

			offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
				"credential_configuration_ids": []string{testCase.credentialConfigurationID},
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
			cNonce := fetchCNonce(t, server.URL, accessToken)
			proofAlgorithm := "RS256"
			if testCase.credentialConfigurationID == "UniversityDegreeCredentialLDP" {
				proofAlgorithm = "ES256"
			}
			proofJWT := createWalletProofJWTWithAlgorithm(t, cNonce, walletSubject, testIssuerAudience, proofAlgorithm)

			credentialResp := postJSONWithHeaders(
				t,
				server.URL+"/oid4vci/credential",
				map[string]interface{}{
					"credential_configuration_id": testCase.credentialConfigurationID,
					"format":                      testCase.format,
					"proofs": map[string]interface{}{
						"jwt": []string{proofJWT},
					},
				},
				map[string]string{
					"Authorization": "Bearer " + accessToken,
				},
			)
			assertStatus(t, credentialResp, http.StatusOK)
			credentialPayload := decodeJSONMap(t, credentialResp)
			credential := asString(t, firstCredential(t, credentialPayload))
			if credential == "" {
				t.Fatalf("expected credential in response")
			}
			if testCase.format == "dc+sd-jwt" {
				// RFC 9901 Sections 4.1 and 4.1.1 require the no-KB compact
				// form to end in "~" and _sd_alg to occur only at payload
				// top level. SD-JWT VC Section 2.2.1 requires typ dc+sd-jwt.
				if !strings.HasSuffix(credential, "~") {
					t.Fatalf("issued sd-jwt compact serialization missing trailing tilde: %q", credential)
				}
				envelope, err := vc.ParseSDJWTEnvelope(credential)
				if err != nil {
					t.Fatalf("ParseSDJWTEnvelope: %v", err)
				}
				if envelope.HasKeyBindingJWT() {
					t.Fatal("issuer returned an SD-JWT+KB to the holder")
				}
				decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
				if err != nil {
					t.Fatalf("decode issuer-signed jwt: %v", err)
				}
				if got := asString(t, decoded.Header["typ"]); got != "dc+sd-jwt" {
					t.Fatalf("issuer typ = %q, want dc+sd-jwt", got)
				}
				if got := asString(t, decoded.Payload["_sd_alg"]); got != "sha-256" {
					t.Fatalf("top-level _sd_alg = %q, want sha-256", got)
				}
				if _, legacy := decoded.Payload["vc"]; legacy {
					t.Fatal("dc+sd-jwt payload must not use the legacy vc claim")
				}
				if _, ok := decoded.Payload["_sd"].([]interface{}); !ok {
					t.Fatalf("top-level _sd = %#v, want disclosure digest array", decoded.Payload["_sd"])
				}
				cnf, _ := decoded.Payload["cnf"].(map[string]interface{})
				if _, unexpected := cnf["jkt"]; unexpected {
					t.Fatal("dc+sd-jwt cnf must carry jwk without the redundant jkt extension")
				}
				if _, _, err := vc.ProcessSDJWTDisclosures(
					map[string]interface{}(decoded.Payload),
					envelope.Disclosures,
				); err != nil {
					t.Fatalf("issued sd-jwt disclosures do not process: %v", err)
				}
			}
		})
	}
}

func TestCredentialIssuanceIgnoresRemovedFormatParameter(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredentialLDP"},
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
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofJWT := createWalletProofJWTWithAlgorithm(t, cNonce, walletSubject, testIssuerAudience, "ES256")

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredentialLDP",
			"format":                      "jwt_vc_json",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusOK)
}

func TestCredentialIssuerMetadataRejectsUnexpectedPathSuffix(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/oid4vci/.well-known/openid-credential-issuer/unexpected")
	if err != nil {
		t.Fatalf("metadata request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestDeferredIssuanceFlow(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized/deferred", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
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
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusAccepted)
	credentialPayload := decodeJSONMap(t, credentialResp)
	transactionID := asString(t, credentialPayload["transaction_id"])
	if transactionID == "" {
		t.Fatalf("expected deferred transaction_id")
	}
	if _, found := credentialPayload["notification_id"]; found {
		t.Fatal("notification_id must not be returned before credentials are present")
	}

	time.Sleep(deferredReadyDelay + 200*time.Millisecond)

	type pollResult struct {
		Status  int
		Payload map[string]interface{}
		Err     error
	}
	results := make(chan pollResult, 2)
	var pollers sync.WaitGroup
	for range 2 {
		pollers.Add(1)
		go func() {
			defer pollers.Done()
			body, marshalErr := json.Marshal(map[string]string{"transaction_id": transactionID})
			if marshalErr != nil {
				results <- pollResult{Err: marshalErr}
				return
			}
			req, requestErr := http.NewRequest(http.MethodPost, server.URL+"/oid4vci/deferred_credential", bytes.NewReader(body))
			if requestErr != nil {
				results <- pollResult{Err: requestErr}
				return
			}
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")
			resp, requestErr := http.DefaultClient.Do(req)
			if requestErr != nil {
				results <- pollResult{Err: requestErr}
				return
			}
			defer resp.Body.Close()
			payload := make(map[string]interface{})
			decodeErr := json.NewDecoder(resp.Body).Decode(&payload)
			results <- pollResult{Status: resp.StatusCode, Payload: payload, Err: decodeErr}
		}()
	}
	pollers.Wait()
	close(results)

	successes := 0
	rejections := 0
	for result := range results {
		if result.Err != nil {
			t.Fatalf("deferred poll failed: %v", result.Err)
		}
		switch result.Status {
		case http.StatusOK:
			successes++
			if asString(t, firstCredential(t, result.Payload)) == "" {
				t.Fatal("expected deferred credential")
			}
			if asString(t, result.Payload["notification_id"]) == "" {
				t.Fatal("expected notification_id only after deferred credential issuance completed")
			}
		case http.StatusBadRequest:
			rejections++
			if asString(t, result.Payload["error"]) != "invalid_transaction_id" {
				t.Fatalf("concurrent loser error = %v, want invalid_transaction_id", result.Payload["error"])
			}
		default:
			t.Fatalf("unexpected concurrent deferred status %d", result.Status)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("concurrent deferred results: successes=%d rejections=%d, want 1 each", successes, rejections)
	}
}

func TestDeferredIssuancePendingReturnsRetryHints(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized/deferred", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
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
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusAccepted)
	credentialPayload := decodeJSONMap(t, credentialResp)
	transactionID := asString(t, credentialPayload["transaction_id"])
	if transactionID == "" {
		t.Fatalf("expected deferred transaction_id")
	}
	initialRetry, ok := credentialPayload["interval"].(float64)
	if !ok || int(initialRetry) < 1 {
		t.Fatalf("expected interval >= 1, got %v", credentialPayload["interval"])
	}

	pendingResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/deferred_credential",
		map[string]interface{}{
			"transaction_id": transactionID,
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, pendingResp, http.StatusAccepted)
	retryAfterHeader := strings.TrimSpace(pendingResp.Header.Get("Retry-After"))
	if retryAfterHeader == "" {
		t.Fatalf("expected Retry-After header on pending deferred response")
	}
	pendingPayload := decodeJSONMap(t, pendingResp)
	if asString(t, pendingPayload["transaction_id"]) != transactionID {
		t.Fatalf("expected transaction_id %q, got %v", transactionID, pendingPayload["transaction_id"])
	}
	pendingRetry, ok := pendingPayload["interval"].(float64)
	if !ok || int(pendingRetry) < 1 {
		t.Fatalf("expected interval >= 1, got %v", pendingPayload["interval"])
	}
}

func TestCredentialRequestRejectsNonceMismatchProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
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
	_ = fetchCNonce(t, server.URL, accessToken)

	proofJWT := createWalletProofJWT(t, "wrong-nonce", walletSubject, testIssuerAudience)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	credentialPayload := decodeJSONMap(t, credentialResp)
	if asString(t, credentialPayload["error"]) != "invalid_nonce" {
		t.Fatalf("expected invalid_nonce error, got %v", credentialPayload["error"])
	}
}

func TestCredentialRequestRejectsReplayOfPreviousProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
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
	cNonce := fetchCNonce(t, server.URL, accessToken)

	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)

	firstCredentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, firstCredentialResp, http.StatusOK)
	_ = firstCredentialResp.Body.Close()

	replayCredentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, replayCredentialResp, http.StatusBadRequest)
	replayPayload := decodeJSONMap(t, replayCredentialResp)
	if asString(t, replayPayload["error"]) != "invalid_nonce" {
		t.Fatalf("expected invalid_nonce on replay, got %v", replayPayload["error"])
	}
}

func TestCredentialRequestRejectsMissingProof(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)

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

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof error, got %v", payload["error"])
	}
}

func TestCredentialRequestRejectsArrayProofsShape(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offerPayload["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": []map[string]interface{}{
				{"proof_type": "jwt", "jwt": "not-a-proof"},
			},
		},
		map[string]string{"Authorization": "Bearer " + asString(t, tokenPayload["access_token"])},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof for array-shaped proofs, got %v", payload["error"])
	}
}

func TestCredentialRequestIgnoresUnknownSingularProofWhenProofsPresent(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
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
	proofJWT := createWalletProofJWT(
		t,
		fetchCNonce(t, server.URL, accessToken),
		asString(t, offerPayload["wallet_subject"]),
		testIssuerAudience,
	)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proof": map[string]interface{}{
				"proof_type": "jwt",
				"jwt":        "invalid-singular-proof",
			},
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, firstCredential(t, payload)) == "" {
		t.Fatal("expected standard proofs to be processed while unknown proof is ignored")
	}
}

func TestCredentialRequestIgnoresUnknownSingularProofWithoutProofs(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offerPayload := decodeJSONMap(t, offerResp)
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

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proof": map[string]interface{}{
				"proof_type": "jwt",
				"jwt":        "ignored-legacy-value",
			},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof because standard proofs is absent, got %v", payload["error"])
	}
}

func TestCredentialRequestRejectsProofSignedByDifferentWallet(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	aliceOfferResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id":               "alice",
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, aliceOfferResp, http.StatusCreated)
	aliceOffer := decodeJSONMap(t, aliceOfferResp)

	bobOfferResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"wallet_user_id":               "bob",
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	assertStatus(t, bobOfferResp, http.StatusCreated)
	bobOffer := decodeJSONMap(t, bobOfferResp)

	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, aliceOffer["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	accessToken := asString(t, tokenPayload["access_token"])

	proofJWT := createWalletProofJWT(
		t,
		fetchCNonce(t, server.URL, accessToken),
		asString(t, bobOffer["wallet_subject"]),
		testIssuerAudience,
	)

	credentialResp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "UniversityDegreeCredential",
			"proofs": map[string]interface{}{
				"jwt": []string{proofJWT},
			},
		},
		map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
	)
	assertStatus(t, credentialResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, payload["error"]) != "invalid_proof" {
		t.Fatalf("expected invalid_proof error, got %v", payload["error"])
	}
}

func TestAuthorizationDetailsIssuesTokenBoundCredentialIdentifiers(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	accessToken, walletSubject, credentialIdentifier, tokenPayload := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		env.Server.URL,
		[]string{"UniversityDegreeCredential", "UniversityDegreeCredentialJWT"},
		[]string{"UniversityDegreeCredential"},
	)
	details, ok := tokenPayload["authorization_details"].([]interface{})
	if !ok || len(details) != 1 {
		t.Fatalf("expected one authorization_details response item, got %v", tokenPayload["authorization_details"])
	}
	cNonce := fetchCNonce(t, env.Server.URL, accessToken)
	proofJWT := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)
	credentialResp := postJSONWithHeaders(
		t,
		env.Server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_identifier": credentialIdentifier,
			"proofs":                map[string]interface{}{"jwt": []string{proofJWT}},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, credentialResp, http.StatusOK)
	payload := decodeJSONMap(t, credentialResp)
	if asString(t, firstCredential(t, payload)) == "" {
		t.Fatal("expected credential issued through credential_identifier")
	}
	if asString(t, payload["notification_id"]) == "" {
		t.Fatal("expected access-grant-bound notification_id")
	}
	if _, legacy := payload["credential"]; legacy {
		t.Fatal("Final Credential Response must not use singular credential")
	}
}

func TestCredentialRejectsUnknownConfigurationBeforeIdentifierRequirement(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	accessToken, walletSubject, _, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)
	proofJWT := createWalletProofJWT(t, fetchCNonce(t, server.URL, accessToken), walletSubject, testIssuerAudience)
	resp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "DoesNotExistInIssuerMetadata",
			"proofs":                      map[string]interface{}{"jwt": []string{proofJWT}},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["error"]) != "unknown_credential_configuration" {
		t.Fatalf("error = %q, want unknown_credential_configuration (OID4VCI precedence over missing credential_identifier)", payload["error"])
	}
}

func TestCredentialRejectsUnknownConfigurationWithoutAuthorizationDetails(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSONWithHeaders(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	}, nil)
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	preAuthorizedCode := asString(t, offer["pre_authorized_code"])
	walletSubject := asString(t, offer["wallet_subject"])
	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {preAuthorizedCode},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	accessToken := asString(t, decodeJSONMap(t, tokenResp)["access_token"])
	proofJWT := createWalletProofJWT(t, fetchCNonce(t, server.URL, accessToken), walletSubject, testIssuerAudience)
	resp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_configuration_id": "DoesNotExistInIssuerMetadata",
			"proofs":                      map[string]interface{}{"jwt": []string{proofJWT}},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, resp, http.StatusBadRequest)
	if asString(t, decodeJSONMap(t, resp)["error"]) != "unknown_credential_configuration" {
		t.Fatalf("expected unknown_credential_configuration")
	}
}

func TestCredentialIdentifierRejectsMixedUnknownAndCrossTokenValues(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()

	tokenA, subjectA, identifierA, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t, env.Server.URL, []string{"UniversityDegreeCredential"}, []string{"UniversityDegreeCredential"},
	)
	_, _, identifierB, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t, env.Server.URL, []string{"UniversityDegreeCredential"}, []string{"UniversityDegreeCredential"},
	)
	proofJWT := createWalletProofJWT(t, fetchCNonce(t, env.Server.URL, tokenA), subjectA, testIssuerAudience)
	tests := []struct {
		name    string
		payload map[string]interface{}
		error   string
	}{
		{
			name: "mixed identifiers",
			payload: map[string]interface{}{
				"credential_identifier":       identifierA,
				"credential_configuration_id": "UniversityDegreeCredential",
				"proofs":                      map[string]interface{}{"jwt": []string{proofJWT}},
			},
			error: "invalid_credential_request",
		},
		{
			name: "unknown identifier",
			payload: map[string]interface{}{
				"credential_identifier": "unknown-credential-dataset",
				"proofs":                map[string]interface{}{"jwt": []string{proofJWT}},
			},
			error: "unknown_credential_identifier",
		},
		{
			name: "identifier from another token",
			payload: map[string]interface{}{
				"credential_identifier": identifierB,
				"proofs":                map[string]interface{}{"jwt": []string{proofJWT}},
			},
			error: "unknown_credential_identifier",
		},
		{
			name: "configuration id after identifiers returned",
			payload: map[string]interface{}{
				"credential_configuration_id": "UniversityDegreeCredential",
				"proofs":                      map[string]interface{}{"jwt": []string{proofJWT}},
			},
			error: "invalid_credential_request",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			resp := postJSONWithHeaders(
				t,
				env.Server.URL+"/oid4vci/credential",
				testCase.payload,
				map[string]string{"Authorization": "Bearer " + tokenA},
			)
			assertStatus(t, resp, http.StatusBadRequest)
			payload := decodeJSONMap(t, resp)
			if asString(t, payload["error"]) != testCase.error {
				t.Fatalf("expected %s, got %v", testCase.error, payload["error"])
			}
		})
	}
}

func TestCredentialIdentifierUnknownWithoutTokenAuthorizationDetails(t *testing.T) {
	// OID4VCI §8.3.1.2 unknown_credential_identifier: an unbound
	// credential_identifier yields unknown_credential_identifier even when the
	// Token Response never returned credential_identifiers.
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	offer := decodeJSONMap(t, offerResp)
	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code": {asString(t, offer["pre_authorized_code"])},
	})
	if err != nil {
		t.Fatal(err)
	}
	token := decodeJSONMap(t, tokenResp)
	resp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{"credential_identifier": "unknown:" + t.Name()},
		map[string]string{"Authorization": "Bearer " + asString(t, token["access_token"])},
	)
	assertStatus(t, resp, http.StatusBadRequest)
	payload := decodeJSONMap(t, resp)
	if asString(t, payload["error"]) != "unknown_credential_identifier" {
		t.Fatalf("expected unknown_credential_identifier, got %v", payload["error"])
	}
}

func TestAuthorizationCodeGrantReturnsCredentialIdentifiers(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	clientID := "oid4vci-authorization-details-client"
	redirectURI := "https://wallet.example/callback"
	env.IDP.RegisterClient(&models.Client{
		ID:           clientID,
		Public:       true,
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"vc:issue"},
	})
	authCode, err := env.IDP.CreateAuthorizationCode(
		clientID, "alice", redirectURI, "vc:issue", "", "", "", "", "", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.IDP.BindCredentialAuthorizationDetails(authCode.Code, []string{"UniversityDegreeCredential"}); err != nil {
		t.Fatal(err)
	}
	tokenResp, err := http.PostForm(env.Server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	credentialIdentifier := credentialIdentifierFromTokenResponse(t, tokenPayload)
	accessToken := asString(t, tokenPayload["access_token"])
	env.Plugin.mu.RLock()
	grant := env.Plugin.accessGrants[accessToken]
	env.Plugin.mu.RUnlock()
	if grant == nil || grant.CredentialIdentifiers[credentialIdentifier] != "UniversityDegreeCredential" {
		t.Fatal("authorization-code credential_identifier was not bound to the real access grant")
	}

	replayResp, err := http.PostForm(env.Server.URL+"/oid4vci/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authCode.Code},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, replayResp, http.StatusBadRequest)
	_ = decodeJSONMap(t, replayResp)
	if !env.IDP.IsTokenRevoked(accessToken) {
		t.Fatal("authorization-code replay did not revoke the previously issued OID4VCI access token")
	}

	// FAPI2 attempt-reuse-authorization-code: the resource endpoint MUST reject
	// the revoked access token with HTTP 4xx (RFC 6749 §4.1.2 SHOULD + RFC 6750).
	resourceResp := postJSONWithHeaders(
		t,
		env.Server.URL+"/oid4vci/credential",
		map[string]interface{}{"credential_identifier": credentialIdentifier},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	if resourceResp.StatusCode < 400 || resourceResp.StatusCode > 499 {
		t.Fatalf("credential endpoint status = %d after code replay, want 4xx", resourceResp.StatusCode)
	}
	resourcePayload := decodeJSONMap(t, resourceResp)
	if asString(t, resourcePayload["error"]) != "invalid_token" {
		t.Fatalf("credential endpoint error = %v, want invalid_token", resourcePayload["error"])
	}
}

func TestTokenAuthorizationDetailsRejectsMissingIssuerLocation(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	offerResp := postJSON(t, server.URL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": []string{"UniversityDegreeCredential"},
	})
	offer := decodeJSONMap(t, offerResp)
	rawDetails, err := json.Marshal([]map[string]interface{}{{
		"type":                        "openid_credential",
		"credential_configuration_id": "UniversityDegreeCredential",
	}})
	if err != nil {
		t.Fatal(err)
	}
	tokenResp, err := http.PostForm(server.URL+"/oid4vci/token", url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code":   {asString(t, offer["pre_authorized_code"])},
		"authorization_details": {string(rawDetails)},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, tokenResp, http.StatusBadRequest)
	payload := decodeJSONMap(t, tokenResp)
	if asString(t, payload["error"]) != "invalid_request" {
		t.Fatalf("expected invalid_request, got %v", payload["error"])
	}
}

func TestNotificationEndpointMutatesStateAndIsIdempotent(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	accessToken, notificationID := issueCredentialForNotification(t, env)
	session, _, err := env.LookingGlass.CreateSession("oid4vci", "notification")
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{
		"Authorization":           "Bearer " + accessToken,
		"X-Looking-Glass-Session": session.ID,
	}
	payload := map[string]interface{}{
		"notification_id": notificationID,
		"event":           "credential_accepted",
	}
	for attempt := 0; attempt < 2; attempt++ {
		resp := postJSONWithHeaders(t, env.Server.URL+"/oid4vci/notification", payload, headers)
		assertStatus(t, resp, http.StatusNoContent)
		_ = resp.Body.Close()
	}
	env.Plugin.mu.RLock()
	record := env.Plugin.notifications[notificationID]
	eventCount := len(record.Events)
	env.Plugin.mu.RUnlock()
	if eventCount != 1 {
		t.Fatalf("idempotent retry mutated state %d times, want 1", eventCount)
	}
	storedSession, ok := env.LookingGlass.GetSession(session.ID)
	if !ok || len(storedSession.Events) != 2 {
		t.Fatalf("expected Looking Glass events for initial notification and retry, got %#v", storedSession)
	}
	if retry, _ := storedSession.Events[1].Data["idempotent_retry"].(bool); !retry {
		t.Fatal("expected retry Looking Glass event to identify idempotent processing")
	}
}

func TestNotificationEndpointRejectsInvalidRequestsAndCrossTokenID(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	accessToken, notificationID := issueCredentialForNotification(t, env)
	otherToken, _, _, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t, env.Server.URL, []string{"UniversityDegreeCredential"}, []string{"UniversityDegreeCredential"},
	)
	tests := []struct {
		name    string
		token   string
		payload map[string]interface{}
		status  int
		error   string
	}{
		{
			name:    "unknown event",
			token:   accessToken,
			payload: map[string]interface{}{"notification_id": notificationID, "event": "Credential_Accepted"},
			status:  http.StatusBadRequest, error: "invalid_notification_request",
		},
		{
			name:    "invalid description characters",
			token:   accessToken,
			payload: map[string]interface{}{"notification_id": notificationID, "event": "credential_failure", "event_description": "bad\nvalue"},
			status:  http.StatusBadRequest, error: "invalid_notification_request",
		},
		{
			name:    "unknown notification id",
			token:   accessToken,
			payload: map[string]interface{}{"notification_id": "unknown", "event": "credential_deleted"},
			status:  http.StatusBadRequest, error: "invalid_notification_id",
		},
		{
			name:    "cross token notification id",
			token:   otherToken,
			payload: map[string]interface{}{"notification_id": notificationID, "event": "credential_accepted"},
			status:  http.StatusBadRequest, error: "invalid_notification_id",
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			resp := postJSONWithHeaders(
				t,
				env.Server.URL+"/oid4vci/notification",
				testCase.payload,
				map[string]string{"Authorization": "Bearer " + testCase.token},
			)
			assertStatus(t, resp, testCase.status)
			payload := decodeJSONMap(t, resp)
			if asString(t, payload["error"]) != testCase.error {
				t.Fatalf("expected %s, got %v", testCase.error, payload["error"])
			}
		})
	}

	unauthorized := postJSON(t, env.Server.URL+"/oid4vci/notification", map[string]interface{}{
		"notification_id": notificationID,
		"event":           "credential_accepted",
	})
	assertStatus(t, unauthorized, http.StatusUnauthorized)
	_ = decodeJSONMap(t, unauthorized)
}

func TestDecodeNotificationRequestRejectsDuplicatesAndIgnoresUnknownParameters(t *testing.T) {
	if _, err := decodeNotificationRequest(strings.NewReader(
		`{"notification_id":"one","notification_id":"two","event":"credential_accepted"}`,
	)); err == nil {
		t.Fatal("expected repeated notification_id to be rejected")
	}
	req, err := decodeNotificationRequest(strings.NewReader(
		`{"notification_id":"one","event":"credential_accepted","extension":{"value":true}}`,
	))
	if err != nil {
		t.Fatalf("unknown notification parameter must be ignored: %v", err)
	}
	if req.NotificationID != "one" || req.Event != "credential_accepted" {
		t.Fatalf("decoded notification request = %#v", req)
	}
}

func TestCredentialAndTokenEndpointsRequireExactMediaTypes(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	tokenReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/oid4vci/token",
		strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code"),
	)
	if err != nil {
		t.Fatal(err)
	}
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, tokenResp, http.StatusBadRequest)
	if errorCode := asString(t, decodeJSONMap(t, tokenResp)["error"]); errorCode != "invalid_request" {
		t.Fatalf("token media-type error = %q, want invalid_request", errorCode)
	}

	accessToken, _, _, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)
	credentialReq, err := http.NewRequest(
		http.MethodPost,
		server.URL+"/oid4vci/credential",
		strings.NewReader(`{"credential_identifier":"unused"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	credentialReq.Header.Set("Authorization", "Bearer "+accessToken)
	credentialReq.Header.Set("Content-Type", "application/json-patch+json")
	credentialResp, err := http.DefaultClient.Do(credentialReq)
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, credentialResp, http.StatusBadRequest)
	if errorCode := asString(t, decodeJSONMap(t, credentialResp)["error"]); errorCode != "invalid_credential_request" {
		t.Fatalf("credential media-type error = %q, want invalid_credential_request", errorCode)
	}
}

func TestCredentialMalformedJSONUsesCredentialErrorCode(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	accessToken, _, _, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)

	for name, body := range map[string]string{
		"malformed JSON":        "{",
		"repeated parameter":    `{"credential_identifier":"one","credential_identifier":"two"}`,
		"non-object JSON value": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, server.URL+"/oid4vci/credential", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+accessToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			assertStatus(t, resp, http.StatusBadRequest)
			if errorCode := asString(t, decodeJSONMap(t, resp)["error"]); errorCode != "invalid_credential_request" {
				t.Fatalf("malformed credential request error = %q, want invalid_credential_request", errorCode)
			}
		})
	}
}

func TestCredentialIssuesBatchBoundToDistinctProofKeys(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	accessToken, walletSubject, identifier, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofA := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)
	proofB := createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience)
	resp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_identifier": identifier,
			"proofs":                map[string]interface{}{"jwt": []string{proofA, proofB}},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)
	credentials, ok := payload["credentials"].([]interface{})
	if !ok || len(credentials) != 2 {
		t.Fatalf("credentials = %#v, want 2 issued credentials", payload["credentials"])
	}

	thumbprints := make(map[string]struct{}, 2)
	subjects := make(map[string]struct{}, 2)
	vcts := make(map[string]struct{}, 2)
	for _, entry := range credentials {
		entryMap, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatalf("credential entry = %#v", entry)
		}
		compact := asString(t, entryMap["credential"])
		envelope, err := vc.ParseSDJWTEnvelope(compact)
		if err != nil {
			t.Fatalf("ParseSDJWTEnvelope: %v", err)
		}
		decoded, err := crypto.DecodeTokenWithoutValidation(envelope.IssuerSignedJWT)
		if err != nil {
			t.Fatalf("decode issuer-signed jwt: %v", err)
		}
		subjects[asString(t, decoded.Payload["sub"])] = struct{}{}
		vcts[asString(t, decoded.Payload["vct"])] = struct{}{}
		cnf, _ := decoded.Payload["cnf"].(map[string]interface{})
		jwkRaw, ok := cnf["jwk"]
		if !ok {
			t.Fatal("batch credential missing cnf.jwk binding")
		}
		raw, err := json.Marshal(jwkRaw)
		if err != nil {
			t.Fatalf("marshal cnf.jwk: %v", err)
		}
		var holder crypto.JWK
		if err := json.Unmarshal(raw, &holder); err != nil {
			t.Fatalf("decode cnf.jwk: %v", err)
		}
		thumbprints[holder.Thumbprint()] = struct{}{}
	}
	if len(thumbprints) != 2 {
		t.Fatalf("expected distinct cnf.jwk bindings, got %d unique thumbprints", len(thumbprints))
	}
	if len(subjects) != 1 || len(vcts) != 1 {
		t.Fatalf("batch credentials must share subject/vct dataset; subjects=%v vcts=%v", subjects, vcts)
	}
}

func TestCredentialRejectsDuplicateProofKeysInBatch(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	accessToken, walletSubject, identifier, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)
	proofJWT := createWalletProofJWT(t, fetchCNonce(t, server.URL, accessToken), walletSubject, testIssuerAudience)
	resp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_identifier": identifier,
			"proofs":                map[string]interface{}{"jwt": []string{proofJWT, proofJWT}},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, resp, http.StatusBadRequest)
	if errorCode := asString(t, decodeJSONMap(t, resp)["error"]); errorCode != "invalid_proof" {
		t.Fatalf("duplicate proof key error = %q, want invalid_proof", errorCode)
	}
}

func TestCredentialRejectsProofsExceedingBatchSize(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()
	accessToken, walletSubject, identifier, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)
	cNonce := fetchCNonce(t, server.URL, accessToken)
	proofs := make([]string, 0, batchCredentialIssuanceBatchSize+1)
	for i := 0; i < batchCredentialIssuanceBatchSize+1; i++ {
		proofs = append(proofs, createWalletProofJWT(t, cNonce, walletSubject, testIssuerAudience))
	}
	resp := postJSONWithHeaders(
		t,
		server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_identifier": identifier,
			"proofs":                map[string]interface{}{"jwt": proofs},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, resp, http.StatusBadRequest)
	if errorCode := asString(t, decodeJSONMap(t, resp)["error"]); errorCode != "invalid_proof" {
		t.Fatalf("oversize batch error = %q, want invalid_proof", errorCode)
	}
}

func TestProofJWKRejectsAllPrivateMaterial(t *testing.T) {
	for name, privateMember := range map[string]interface{}{
		"d":   "private",
		"p":   "prime",
		"q":   "prime",
		"dp":  "crt",
		"dq":  "crt",
		"qi":  "crt",
		"oth": []map[string]string{{"r": "factor"}},
		"k":   "symmetric-secret",
	} {
		t.Run(name, func(t *testing.T) {
			jwk := map[string]interface{}{
				"kty": "RSA",
				"n":   "AQAB",
				"e":   "AQAB",
				name:  privateMember,
			}
			if _, err := parseProofJWK(jwk); err == nil {
				t.Fatalf("expected private JWK member %q to be rejected", name)
			}
		})
	}
}

func TestProofJOSEHeaderRequiresExactlyOneSupportedKeyReference(t *testing.T) {
	publicJWK := map[string]interface{}{
		"kty": "RSA",
		"n":   "AQAB",
		"e":   "AQAB",
	}
	for name, header := range map[string]map[string]interface{}{
		"missing": {},
		"multiple": {
			"jwk": publicJWK,
			"kid": "did:example:holder#key-1",
		},
		"unsupported kid": {
			"kid": "did:example:holder#key-1",
		},
		"unsupported x5c": {
			"x5c": []string{"certificate"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := proofVerificationKeyFromHeader(header); err == nil {
				t.Fatalf("expected JOSE key-reference header %#v to be rejected", header)
			}
		})
	}
}

func TestDeferredRequestIgnoresUnknownParametersAndRejectsDuplicates(t *testing.T) {
	var decoded deferredCredentialRequest
	if err := decodeRequestObject(
		strings.NewReader(`{"transaction_id":"tx-1","extension":{"value":true}}`),
		&decoded,
		"deferred credential request",
	); err != nil {
		t.Fatalf("unknown deferred request parameter must be ignored: %v", err)
	}
	if decoded.TransactionID != "tx-1" {
		t.Fatalf("transaction_id = %q, want tx-1", decoded.TransactionID)
	}
	if err := decodeRequestObject(
		strings.NewReader(`{"transaction_id":"tx-1","transaction_id":"tx-2"}`),
		&decoded,
		"deferred credential request",
	); err == nil {
		t.Fatal("expected repeated deferred request parameter to be rejected")
	}
}

func TestProofAlgorithmMustBeAdvertisedForConfiguration(t *testing.T) {
	plugin := NewPlugin()
	proofJWT := createWalletProofJWT(t, "nonce", "did:example:wallet:alice", testIssuerAudience)
	_, _, _, _, err := plugin.validateProofJWT(
		credentialProof{ProofType: "jwt", JWT: proofJWT},
		testIssuerAudience,
		"did:example:wallet:alice",
		[]string{"ES256"},
	)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected unadvertised proof algorithm rejection, got %v", err)
	}
}

func TestNotificationRejectsConflictingTerminalEvent(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	accessToken, notificationID := issueCredentialForNotification(t, env)
	headers := map[string]string{"Authorization": "Bearer " + accessToken}

	accepted := postJSONWithHeaders(t, env.Server.URL+"/oid4vci/notification", map[string]interface{}{
		"notification_id": notificationID,
		"event":           "credential_accepted",
	}, headers)
	assertStatus(t, accepted, http.StatusNoContent)
	_ = accepted.Body.Close()

	conflict := postJSONWithHeaders(t, env.Server.URL+"/oid4vci/notification", map[string]interface{}{
		"notification_id": notificationID,
		"event":           "credential_failure",
	}, headers)
	assertStatus(t, conflict, http.StatusBadRequest)
	if errorCode := asString(t, decodeJSONMap(t, conflict)["error"]); errorCode != "invalid_notification_request" {
		t.Fatalf("notification conflict error = %q, want invalid_notification_request", errorCode)
	}

	deleted := postJSONWithHeaders(t, env.Server.URL+"/oid4vci/notification", map[string]interface{}{
		"notification_id": notificationID,
		"event":           "credential_deleted",
	}, headers)
	assertStatus(t, deleted, http.StatusNoContent)
	_ = deleted.Body.Close()
}

func TestAuthorizationCodeRedemptionIsAtomic(t *testing.T) {
	env := newTestEnvironment(t)
	defer env.Server.Close()
	clientID := "oid4vci-concurrent-code-client"
	redirectURI := "https://wallet.example/callback"
	env.IDP.RegisterClient(&models.Client{
		ID:           clientID,
		Public:       true,
		RedirectURIs: []string{redirectURI},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"vc:issue"},
	})
	authCode, err := env.IDP.CreateAuthorizationCode(
		clientID, "alice", redirectURI, "vc:issue", "", "", "", "", "", time.Now(),
	)
	if err != nil {
		t.Fatal(err)
	}

	type redemptionResult struct {
		Status int
		Error  string
	}
	results := make(chan redemptionResult, 2)
	var redeemers sync.WaitGroup
	for range 2 {
		redeemers.Add(1)
		go func() {
			defer redeemers.Done()
			resp, requestErr := http.PostForm(env.Server.URL+"/oid4vci/token", url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {authCode.Code},
				"client_id":    {clientID},
				"redirect_uri": {redirectURI},
			})
			if requestErr != nil {
				results <- redemptionResult{}
				return
			}
			defer resp.Body.Close()
			payload := make(map[string]interface{})
			_ = json.NewDecoder(resp.Body).Decode(&payload)
			results <- redemptionResult{Status: resp.StatusCode, Error: strings.TrimSpace(fmt.Sprint(payload["error"]))}
		}()
	}
	redeemers.Wait()
	close(results)
	successes := 0
	rejections := 0
	for result := range results {
		switch result.Status {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			rejections++
			if result.Error != "invalid_grant" {
				t.Fatalf("authorization code replay error = %q, want invalid_grant", result.Error)
			}
		default:
			t.Fatalf("unexpected authorization code redemption status %d", result.Status)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("authorization code redemptions: successes=%d rejections=%d, want 1 each", successes, rejections)
	}
}

func issuePreAuthorizedGrantWithAuthorizationDetails(
	t *testing.T,
	serverURL string,
	offeredConfigurationIDs []string,
	requestedConfigurationIDs []string,
) (string, string, string, map[string]interface{}) {
	t.Helper()
	offerResp := postJSON(t, serverURL+"/oid4vci/offers/pre-authorized", map[string]interface{}{
		"credential_configuration_ids": offeredConfigurationIDs,
	})
	assertStatus(t, offerResp, http.StatusCreated)
	offer := decodeJSONMap(t, offerResp)
	details := make([]map[string]interface{}, 0, len(requestedConfigurationIDs))
	for _, configurationID := range requestedConfigurationIDs {
		details = append(details, map[string]interface{}{
			"type":                        "openid_credential",
			"credential_configuration_id": configurationID,
			"locations":                   []string{testIssuerAudience},
		})
	}
	rawDetails, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	tokenResp, err := http.PostForm(serverURL+"/oid4vci/token", url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"pre-authorized_code":   {asString(t, offer["pre_authorized_code"])},
		"authorization_details": {string(rawDetails)},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertStatus(t, tokenResp, http.StatusOK)
	tokenPayload := decodeJSONMap(t, tokenResp)
	return asString(t, tokenPayload["access_token"]),
		asString(t, offer["wallet_subject"]),
		credentialIdentifierFromTokenResponse(t, tokenPayload),
		tokenPayload
}

func credentialIdentifierFromTokenResponse(t *testing.T, payload map[string]interface{}) string {
	t.Helper()
	details, ok := payload["authorization_details"].([]interface{})
	if !ok || len(details) == 0 {
		t.Fatalf("token response missing authorization_details: %v", payload)
	}
	detail, ok := details[0].(map[string]interface{})
	if !ok {
		t.Fatalf("authorization_details item is %T", details[0])
	}
	identifiers, ok := detail["credential_identifiers"].([]interface{})
	if !ok || len(identifiers) == 0 {
		t.Fatalf("authorization_details missing credential_identifiers: %v", detail)
	}
	return asString(t, identifiers[0])
}

func issueCredentialForNotification(t *testing.T, env *oid4vciTestEnvironment) (string, string) {
	t.Helper()
	accessToken, walletSubject, identifier, _ := issuePreAuthorizedGrantWithAuthorizationDetails(
		t,
		env.Server.URL,
		[]string{"UniversityDegreeCredential"},
		[]string{"UniversityDegreeCredential"},
	)
	proofJWT := createWalletProofJWT(
		t,
		fetchCNonce(t, env.Server.URL, accessToken),
		walletSubject,
		testIssuerAudience,
	)
	resp := postJSONWithHeaders(
		t,
		env.Server.URL+"/oid4vci/credential",
		map[string]interface{}{
			"credential_identifier": identifier,
			"proofs":                map[string]interface{}{"jwt": []string{proofJWT}},
		},
		map[string]string{"Authorization": "Bearer " + accessToken},
	)
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)
	_ = firstCredential(t, payload)
	notificationID := asString(t, payload["notification_id"])
	if notificationID == "" {
		t.Fatal("credential response missing notification_id")
	}
	return accessToken, notificationID
}

func createWalletProofJWT(t *testing.T, nonce string, subject string, audience string) string {
	return createWalletProofJWTWithAlgorithm(t, nonce, subject, audience, "RS256")
}

func createWalletProofJWTWithAlgorithm(t *testing.T, nonce string, subject string, audience string, algorithm string) string {
	t.Helper()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("create wallet key set: %v", err)
	}
	keyID := keySet.RSAKeyID()
	var signingMethod jwt.SigningMethod = jwt.SigningMethodRS256
	signingKey := interface{}(keySet.RSAPrivateKey())
	if algorithm == "ES256" {
		keyID = keySet.ECKeyID()
		signingMethod = jwt.SigningMethodES256
		signingKey = keySet.ECPrivateKey()
	}
	publicJWK, found := keySet.GetJWKByID(keyID)
	if !found {
		t.Fatalf("wallet %s jwk is unavailable", algorithm)
	}
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   subject,
		"sub":   subject,
		"aud":   audience,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(3 * time.Minute).Unix(),
		"jti":   "proof-" + subject,
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = publicJWK
	signed, err := token.SignedString(signingKey)
	if err != nil {
		t.Fatalf("sign proof jwt: %v", err)
	}
	return signed
}

func fetchCNonce(t *testing.T, serverURL string, _ string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, serverURL+"/oid4vci/nonce", nil)
	if err != nil {
		t.Fatalf("build nonce request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("nonce request failed: %v", err)
	}
	assertStatus(t, resp, http.StatusOK)
	payload := decodeJSONMap(t, resp)
	cNonce := asString(t, payload["c_nonce"])
	if cNonce == "" {
		t.Fatal("nonce response missing c_nonce")
	}
	return cNonce
}

func assertTokenResponseHasNoCredentialNonce(t *testing.T, payload map[string]interface{}) {
	t.Helper()
	if _, found := payload["c_nonce"]; found {
		t.Fatal("token response must not contain c_nonce")
	}
	if _, found := payload["c_nonce_expires_in"]; found {
		t.Fatal("token response must not contain c_nonce_expires_in")
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newTestEnvironment(t).Server
}

type oid4vciTestEnvironment struct {
	Server       *httptest.Server
	Plugin       *Plugin
	IDP          *mockidp.MockIdP
	LookingGlass *lookingglass.Engine
}

func newTestEnvironment(t *testing.T) *oid4vciTestEnvironment {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()
	keySet, err := crypto.NewKeySet()
	if err != nil {
		t.Fatalf("new key set: %v", err)
	}
	idp := mockidp.NewMockIdP(keySet)
	lookingGlass := lookingglass.NewEngine()
	testPlugin := NewPlugin()
	if err := testPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL:      "http://localhost:8080",
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lookingGlass,
	}); err != nil {
		t.Fatalf("initialize plugin: %v", err)
	}

	router := chi.NewRouter()
	router.Route("/oid4vci", func(r chi.Router) {
		testPlugin.RegisterRoutes(r)
	})
	return &oid4vciTestEnvironment{
		Server:       httptest.NewServer(router),
		Plugin:       testPlugin,
		IDP:          idp,
		LookingGlass: lookingGlass,
	}
}

func postJSON(t *testing.T, endpoint string, payload map[string]interface{}) *http.Response {
	t.Helper()
	return postJSONWithHeaders(t, endpoint, payload, nil)
}

func postJSONWithHeaders(t *testing.T, endpoint string, payload map[string]interface{}, headers map[string]string) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("expected status %d, got %d", status, resp.StatusCode)
	}
}

func decodeJSONMap(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return payload
}

func firstCredential(t *testing.T, payload map[string]interface{}) interface{} {
	t.Helper()
	credentials, ok := payload["credentials"].([]interface{})
	if !ok || len(credentials) == 0 {
		t.Fatalf("expected non-empty credentials array, got %v", payload["credentials"])
	}
	credentialObject, ok := credentials[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected credentials element to be an object, got %T", credentials[0])
	}
	credential, found := credentialObject["credential"]
	if !found {
		t.Fatal("credentials element is missing credential")
	}
	return credential
}

func asString(t *testing.T, value interface{}) string {
	t.Helper()
	switch typed := value.(type) {
	case string:
		return typed
	case map[string]interface{}, []interface{}:
		serialized, err := json.Marshal(typed)
		if err != nil {
			t.Fatalf("marshal json value: %v", err)
		}
		return string(serialized)
	default:
		return fmt.Sprint(value)
	}
}
