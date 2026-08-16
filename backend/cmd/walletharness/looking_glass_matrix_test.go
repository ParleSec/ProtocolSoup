package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	intcrypto "github.com/ParleSec/ProtocolSoup/internal/crypto"
	"github.com/ParleSec/ProtocolSoup/internal/lookingglass"
	"github.com/ParleSec/ProtocolSoup/internal/mockidp"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vci"
	"github.com/ParleSec/ProtocolSoup/internal/protocols/oid4vp"
	"github.com/ParleSec/ProtocolSoup/internal/vc"
	"github.com/go-chi/chi/v5"
)

type lookingGlassVCIProfile struct {
	ID     string
	Format string
	HAIP   bool
}

var lookingGlassVCIProfiles = []lookingGlassVCIProfile{
	{ID: "MobileDrivingLicenceMsoMdoc", Format: "mso_mdoc"},
	{ID: "UniversityDegreeCredential", Format: "dc+sd-jwt"},
	{ID: "MobileDrivingLicenceMsoMdocHAIP", Format: "mso_mdoc", HAIP: true},
	{ID: "UniversityDegreeCredentialSDJWTHAIP", Format: "dc+sd-jwt", HAIP: true},
}

type lookingGlassMatrixEnv struct {
	baseURL    string
	walletURL  string
	httpClient *http.Client
}

func TestLookingGlassOID4VCIAndOID4VPPermutations(t *testing.T) {
	env := startLookingGlassMatrixEnv(t)

	for _, profile := range lookingGlassVCIProfiles {
		profile := profile
		t.Run("issuer-initiated/"+profile.ID, func(t *testing.T) {
			status, payload := env.postJSON(t, env.baseURL+"/oid4vci/offers/authorization-code", map[string]interface{}{
				"credential_configuration_ids": []string{profile.ID},
			})
			if status != http.StatusCreated {
				t.Fatalf("authorization-code offer status %d: %v", status, payload)
			}
			if strings.TrimSpace(asString(payload["issuer_state"])) == "" {
				t.Fatal("expected issuer_state")
			}
			if strings.TrimSpace(asString(payload["status_uri"])) == "" {
				t.Fatal("expected status_uri for Looking Glass Check Result")
			}
		})
	}

	issued := map[string]string{}
	for _, profile := range lookingGlassVCIProfiles {
		for _, flow := range []string{"pre-authorized", "pre-authorized-tx-code", "deferred"} {
			profile, flow := profile, flow
			t.Run(flow+"/"+profile.ID, func(t *testing.T) {
				credentialJWT := env.importLookingGlassOffer(t, profile, flow)
				if credentialJWT != "" && flow == "pre-authorized" {
					issued[profile.ID] = credentialJWT
				}
			})
		}
	}

	mdlSubject := "did:example:lg:MobileDrivingLicenceMsoMdoc"
	sdjwtSubject := "did:example:lg:UniversityDegreeCredential"
	if issued["MobileDrivingLicenceMsoMdoc"] == "" {
		t.Fatal("expected issued mDL credential for VP permutations")
	}
	if issued["UniversityDegreeCredential"] == "" {
		t.Fatal("expected issued SD-JWT credential for VP permutations")
	}

	mdlDCQL := map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "mdl",
				"format": "mso_mdoc",
				"meta":   map[string]interface{}{"doctype_value": "org.iso.18013.5.1.mDL"},
				"claims": []map[string]interface{}{
					{"path": []string{"org.iso.18013.5.1", "family_name"}},
					{"path": []string{"org.iso.18013.5.1", "document_number"}},
				},
			},
		},
	}
	sdjwtDCQL := map[string]interface{}{
		"credentials": []map[string]interface{}{
			{
				"id":     "university_degree",
				"format": "dc+sd-jwt",
				"meta":   map[string]interface{}{"vct_values": []string{"https://protocolsoup.com/credentials/university_degree"}},
				"claims": []map[string]interface{}{{"path": []string{"degree"}}, {"path": []string{"graduation_year"}}},
			},
		},
	}

	type vpCredential struct {
		name     string
		format   string
		configID string
		subject  string
		dcql     map[string]interface{}
	}
	credentials := []vpCredential{
		{name: "mdl", format: "mso_mdoc", configID: "MobileDrivingLicenceMsoMdoc", subject: mdlSubject, dcql: mdlDCQL},
		{name: "sdjwt", format: "dc+sd-jwt", configID: "UniversityDegreeCredential", subject: sdjwtSubject, dcql: sdjwtDCQL},
	}
	schemes := []string{"redirect_uri", "verifier_attestation", "x509_san_dns", "x509_hash"}
	modes := []string{"direct_post", "direct_post.jwt"}
	methods := []string{"get", "post"}
	walletModes := []string{"one-click", "stepwise"}

	for _, cred := range credentials {
		for _, scheme := range schemes {
			for _, mode := range modes {
				for _, method := range methods {
					for _, walletMode := range walletModes {
						cred, scheme, mode, method, walletMode := cred, scheme, mode, method, walletMode
						name := cred.name + "/" + scheme + "/" + mode + "/" + method + "/" + walletMode
						t.Run("vp-submit/dcql/"+name, func(t *testing.T) {
							env.submitLookingGlassVP(t, lookingGlassVPSubmit{
								scheme:        scheme,
								mode:          mode,
								method:        method,
								dcql:          cred.dcql,
								subject:       cred.subject,
								format:        cred.format,
								configID:      cred.configID,
								credentialJWT: issued[cred.configID],
								stepwise:      walletMode == "stepwise",
							})
						})
					}
				}
			}
		}
	}

	scopeSchemes := []string{"redirect_uri", "verifier_attestation", "x509_san_dns"}
	for _, cred := range credentials {
		for _, scheme := range scopeSchemes {
			for _, mode := range modes {
				cred, scheme, mode := cred, scheme, mode
				name := cred.name + "/" + scheme + "/" + mode + "/get/one-click"
				t.Run("vp-submit/scope/"+name, func(t *testing.T) {
					env.submitLookingGlassVP(t, lookingGlassVPSubmit{
						scheme:        scheme,
						mode:          mode,
						method:        "get",
						scope:         "openid",
						subject:       cred.subject,
						format:        cred.format,
						configID:      cred.configID,
						credentialJWT: issued[cred.configID],
					})
				})
			}
		}
	}
}

func TestLookingGlassOID4VPHAIPConfigWithoutAttestationPresentsEducationalMdoc(t *testing.T) {
	env := startLookingGlassMatrixEnv(t)
	credentialJWT := env.importLookingGlassOffer(t, lookingGlassVCIProfile{
		ID:     "MobileDrivingLicenceMsoMdoc",
		Format: "mso_mdoc",
	}, "pre-authorized")
	if credentialJWT == "" {
		t.Fatal("expected issued educational mDL")
	}
	env.submitLookingGlassVP(t, lookingGlassVPSubmit{
		scheme: "x509_hash",
		mode:   "direct_post.jwt",
		method: "get",
		dcql: map[string]interface{}{
			"credentials": []map[string]interface{}{
				{
					"id":     "mdl",
					"format": "mso_mdoc",
					"meta":   map[string]interface{}{"doctype_value": "org.iso.18013.5.1.mDL"},
					"claims": []map[string]interface{}{
						{"path": []string{"org.iso.18013.5.1", "family_name"}},
						{"path": []string{"org.iso.18013.5.1", "document_number"}},
					},
				},
			},
		},
		subject:       "did:example:lg:MobileDrivingLicenceMsoMdoc",
		format:        "mso_mdoc",
		configID:      "MobileDrivingLicenceMsoMdocHAIP",
		credentialJWT: credentialJWT,
	})
}

func (env *lookingGlassMatrixEnv) importLookingGlassOffer(t *testing.T, profile lookingGlassVCIProfile, flow string) string {
	t.Helper()
	endpoint := env.baseURL + "/oid4vci/offers/pre-authorized"
	if flow == "deferred" {
		endpoint = env.baseURL + "/oid4vci/offers/pre-authorized/deferred"
	}
	status, offer := env.postJSON(t, endpoint, map[string]interface{}{
		"tx_code_required":             flow == "pre-authorized-tx-code",
		"credential_configuration_ids": []string{profile.ID},
	})
	if status != http.StatusCreated {
		t.Fatalf("offer create status %d: %v", status, offer)
	}
	offerInput := strings.TrimSpace(asString(offer["credential_offer_uri"]))
	if rawOffer, ok := offer["credential_offer"]; ok && rawOffer != nil {
		encoded, err := json.Marshal(rawOffer)
		if err != nil {
			t.Fatalf("marshal credential_offer: %v", err)
		}
		offerInput = string(encoded)
	}
	if offerInput == "" {
		t.Fatal("offer response missing credential_offer and credential_offer_uri")
	}
	importBody := map[string]interface{}{
		"offer":                       offerInput,
		"credential_format":           profile.Format,
		"credential_configuration_id": profile.ID,
		"wallet_subject":              "did:example:lg:" + profile.ID,
		"looking_glass_session_id":    "lg-" + profile.ID + "-" + flow,
	}
	if txCode := strings.TrimSpace(asString(offer["tx_code_oob_value"])); txCode != "" {
		importBody["tx_code"] = txCode
	}
	status, imported := env.postJSON(t, env.walletURL+"/api/import", importBody)
	if profile.HAIP {
		if status == http.StatusOK {
			t.Fatal("HAIP Looking Glass import succeeded without attestation material")
		}
		description := strings.ToLower(asString(imported["error_description"]) + " " + asString(imported["error"]))
		if !strings.Contains(description, "haip") && !strings.Contains(description, "attestation") {
			t.Fatalf("HAIP import status %d, want attestation error, got %v", status, imported)
		}
		return ""
	}
	if status != http.StatusOK {
		t.Fatalf("wallet import status %d: %v", status, imported)
	}
	credentialJWT := strings.TrimSpace(asString(imported["credential_jwt"]))
	if credentialJWT == "" {
		t.Fatalf("wallet import missing credential_jwt: %v", imported)
	}
	return credentialJWT
}

type lookingGlassVPSubmit struct {
	scheme        string
	mode          string
	method        string
	dcql          map[string]interface{}
	scope         string
	subject       string
	format        string
	configID      string
	credentialJWT string
	stepwise      bool
}

func (env *lookingGlassMatrixEnv) submitLookingGlassVP(t *testing.T, tc lookingGlassVPSubmit) {
	t.Helper()
	effectiveMode := tc.mode
	if tc.scheme == "x509_hash" {
		effectiveMode = "direct_post.jwt"
	}
	createBody := map[string]interface{}{
		"response_mode":    effectiveMode,
		"response_uri":     env.baseURL + "/oid4vp/response",
		"client_id_scheme": tc.scheme,
	}
	if tc.scheme == "x509_hash" {
		createBody["profile"] = "haip"
		createBody["dcql_query"] = tc.dcql
		if createBody["dcql_query"] == nil {
			createBody["dcql_query"] = map[string]interface{}{
				"credentials": []map[string]interface{}{
					{
						"id":     "mdl",
						"format": "mso_mdoc",
						"meta":   map[string]interface{}{"doctype_value": "org.iso.18013.5.1.mDL"},
					},
				},
			}
		}
	} else if strings.TrimSpace(tc.scope) != "" {
		createBody["scope"] = tc.scope
	} else {
		createBody["dcql_query"] = tc.dcql
	}
	if tc.method == "post" {
		createBody["request_uri_method"] = "post"
	}
	status, created := env.postJSON(t, env.baseURL+"/oid4vp/request/create", createBody)
	if status != http.StatusCreated {
		t.Fatalf("VP create status %d: %v", status, created)
	}
	requestID := strings.TrimSpace(asString(created["request_id"]))
	requestJWT := strings.TrimSpace(asString(created["request"]))
	if requestID == "" || requestJWT == "" {
		t.Fatalf("VP create missing request_id/request: %v", created)
	}

	baseSubmit := map[string]interface{}{
		"request_id":                  requestID,
		"request":                     requestJWT,
		"request_uri":                 strings.TrimSpace(asString(created["request_uri"])),
		"response_mode":               asString(created["response_mode"]),
		"wallet_subject":              tc.subject,
		"credential_format":           tc.format,
		"credential_configuration_id": tc.configID,
		"looking_glass_session_id":    "lg-vp-" + tc.format,
	}
	if strings.TrimSpace(tc.credentialJWT) != "" {
		baseSubmit["credential_jwt"] = tc.credentialJWT
	}
	if tc.stepwise {
		for _, step := range []string{"bootstrap", "issue_credential", "build_presentation", "submit_response"} {
			body := map[string]interface{}{}
			for key, value := range baseSubmit {
				body[key] = value
			}
			body["mode"] = "stepwise"
			body["step"] = step
			status, submitted := env.postJSON(t, env.walletURL+"/submit", body)
			if status != http.StatusOK {
				t.Fatalf("wallet stepwise %s status %d: %v", step, status, submitted)
			}
			if step == "build_presentation" {
				if vpToken := strings.TrimSpace(asString(submitted["vp_token"])); vpToken != "" {
					baseSubmit["vp_token"] = vpToken
				}
			}
		}
		return
	}
	body := map[string]interface{}{}
	for key, value := range baseSubmit {
		body[key] = value
	}
	body["mode"] = "one_click"
	status, submitted := env.postJSON(t, env.walletURL+"/submit", body)
	if status != http.StatusOK {
		t.Fatalf("wallet submit status %d: %v", status, submitted)
	}
}

func (env *lookingGlassMatrixEnv) postJSON(t *testing.T, endpoint string, payload map[string]interface{}) (int, map[string]interface{}) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := env.httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	decoded := map[string]interface{}{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &decoded)
	}
	if len(decoded) == 0 && len(raw) > 0 {
		decoded["raw"] = string(raw)
	}
	return resp.StatusCode, decoded
}

func startLookingGlassMatrixEnv(t *testing.T) *lookingGlassMatrixEnv {
	t.Helper()
	store := vc.DefaultWalletCredentialStore()
	store.DisablePersistence()
	store.Reset()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	dataDir := t.TempDir()

	keySet, err := intcrypto.NewKeySet()
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	idp := mockidp.NewMockIdP(keySet)
	lg := lookingglass.NewEngine()
	vciPlugin := oid4vci.NewPlugin()
	if err := vciPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL:      baseURL,
		DataDir:      dataDir,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lg,
	}); err != nil {
		t.Fatalf("initialize oid4vci: %v", err)
	}
	vpPlugin := oid4vp.NewPlugin()
	if err := vpPlugin.Initialize(context.Background(), plugin.PluginConfig{
		BaseURL:      baseURL,
		DataDir:      dataDir,
		KeySet:       keySet,
		MockIdP:      idp,
		LookingGlass: lg,
	}); err != nil {
		t.Fatalf("initialize oid4vp: %v", err)
	}

	vciRouter := chi.NewRouter()
	vciPlugin.RegisterRoutes(vciRouter)
	vpRouter := chi.NewRouter()
	vpPlugin.RegisterRoutes(vpRouter)
	root := chi.NewRouter()
	root.Mount("/oid4vci", vciRouter)
	root.Mount("/oid4vp", vpRouter)
	root.Get("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	root.Method(http.MethodGet, "/.well-known/openid-credential-issuer/*", vciRouter)
	root.Method(http.MethodGet, "/.well-known/oauth-authorization-server/*", vciRouter)
	root.Get("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, keySet.PublicJWKS())
	})
	root.Get("/api/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, keySet.PublicJWKS())
	})

	vcServer := &http.Server{Handler: root, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		_ = vcServer.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = vcServer.Close()
		_ = vciPlugin.Shutdown(context.Background())
		_ = vpPlugin.Shutdown(context.Background())
	})

	iacaPEM, err := os.ReadFile(filepath.Join(dataDir, "mdoc", "iaca_root.pem"))
	if err != nil {
		t.Fatalf("read IACA: %v", err)
	}
	mdocRoots, err := explicitRootsFromPEM(string(iacaPEM))
	if err != nil {
		t.Fatalf("parse IACA: %v", err)
	}
	chainPEM, err := os.ReadFile(filepath.Join(dataDir, "oid4vp", "x509_request_signer_chain.pem"))
	if err != nil {
		t.Fatalf("read verifier chain: %v", err)
	}
	verifierRoots, err := explicitRootsFromPEM(lastPEMCertificate(string(chainPEM)))
	if err != nil {
		t.Fatalf("parse verifier CA: %v", err)
	}
	deviceKey, err := intcrypto.LoadOrCreateDeviceKey("")
	if err != nil {
		t.Fatalf("device key: %v", err)
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse base URL: %v", err)
	}

	wallet := &walletHarnessServer{
		httpClient:                        &http.Client{Timeout: 45 * time.Second},
		jwksFetcher:                       intcrypto.NewJWKSFetcher(5 * time.Minute),
		targetBaseURL:                     baseURL,
		targetHost:                        parsedBase.Host,
		targetResponseURI:                 baseURL + "/oid4vp/response",
		issuerBaseURL:                     baseURL,
		allowExternal:                     false,
		walletSessionTTL:                  10 * time.Minute,
		strictIsolation:                   false,
		deviceKey:                         deviceKey,
		deviceKeyID:                       intcrypto.JWKFromECPublicKey(&deviceKey.PublicKey, "").Thumbprint(),
		verifierX509Roots:                 verifierRoots,
		mdocIssuerRoots:                   mdocRoots,
		trustedVerifierAttestationIssuers: map[string]struct{}{baseURL + "/oid4vp/verifier-attestation": {}},
		wallets:                           make(map[string]*walletMaterial),
		oid4vciAuthStates:                 make(map[string]*pendingOID4VCIAuthState),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/import", wallet.handleAPIImport)
	mux.HandleFunc("/submit", wallet.handleSubmit)
	walletServer := httptest.NewServer(mux)
	t.Cleanup(walletServer.Close)

	return &lookingGlassMatrixEnv{
		baseURL:    baseURL,
		walletURL:  walletServer.URL,
		httpClient: &http.Client{Timeout: 45 * time.Second},
	}
}

func lastPEMCertificate(raw string) string {
	var last string
	var buf []string
	for _, line := range strings.Split(raw, "\n") {
		buf = append(buf, line)
		if strings.Contains(line, "END CERTIFICATE") {
			last = strings.Join(buf, "\n") + "\n"
			buf = nil
		}
	}
	return last
}
