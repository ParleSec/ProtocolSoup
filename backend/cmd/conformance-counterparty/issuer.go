package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// The issuer and authorization server roles. Each scenario is a Credential
// Issuer identified by https://<host>/scenarios/<scenario>, so its metadata
// sits where OpenID4VCI 1.0 Section 12.2.2 and RFC 8414 Section 3 insert the
// well-known path: /.well-known/openid-credential-issuer/scenarios/<scenario>
// and /.well-known/oauth-authorization-server/scenarios/<scenario>. No
// scenario issues a real Credential, so the counterparty holds no
// credential-signing key.

const counterpartyConfigurationID = "ConformanceCounterpartySDJWT"

// issuerScenarios maps each issuer scenario to the change it makes to the
// common Credential Issuer metadata.
var issuerScenarios = map[string]func(c *counterparty, metadata map[string]interface{}){
	// CI-010: an otherwise ordinary issuer whose Credential Endpoint answers
	// with an empty credentials array.
	"ci-010": nil,
	// CW-006: an offer whose pre-authorized_code grant carries an empty
	// tx_code object.
	"cw-006": nil,
	// CW-010: metadata listing one authorization server, while the offer
	// hints another.
	"cw-010": func(c *counterparty, metadata map[string]interface{}) {
		metadata["authorization_servers"] = []string{c.scenarioURL("cw-010") + "/as-listed"}
	},
	// CW-024: credential_issuer differs from the identifier the metadata was
	// fetched for by a trailing slash, which only normalization would erase.
	"cw-024": func(c *counterparty, metadata map[string]interface{}) {
		metadata["credential_issuer"] = c.scenarioURL("cw-024") + "/"
	},
	// CW-072: Credential Request and Response encryption required with
	// ECDH-ES and A256GCM; the Credential Endpoint then encrypts its response
	// with a different algorithm.
	"cw-072": requireEncryption,
	// CW-072, second case: the same metadata, but the Credential Endpoint
	// answers the encrypted request in plaintext application/json.
	"cw-072-plaintext": requireEncryption,
	// CW-H003: an authorization server that requires PAR but offers only the
	// plain PKCE method (see its authorization server metadata).
	"cw-h003": nil,
	// CW-H004: an authorization server that advertises DPoP and attestation-
	// based client authentication, whose Token Endpoint challenges the
	// wallet's DPoP proof with use_dpop_nonce but supplies no DPoP-Nonce
	// header (see handleCWH004Token).
	"cw-h004": nil,
	// CW-101: a configuration whose key_attestations_required demands ISO/IEC
	// 18045 levels a software wallet cannot back.
	"cw-101": func(c *counterparty, metadata map[string]interface{}) {
		configurations := metadata["credential_configurations_supported"].(map[string]interface{})
		configuration := configurations[counterpartyConfigurationID].(map[string]interface{})
		configuration["proof_types_supported"] = map[string]interface{}{
			"jwt": map[string]interface{}{
				"proof_signing_alg_values_supported": []string{"ES256"},
				"key_attestations_required": map[string]interface{}{
					"key_storage":         []string{"iso_18045_high"},
					"user_authentication": []string{"iso_18045_high"},
				},
			},
		}
	},
}

// preAuthorizedScenarios run a pre-authorized_code grant whose code the
// counterparty's Token Endpoint redeems.
var preAuthorizedScenarios = map[string]bool{"ci-010": true, "cw-072": true, "cw-072-plaintext": true, "cw-h004": true, "cw-101": true}

// requireEncryption advertises Credential Request and Response encryption as
// required, with ECDH-ES and A256GCM (OpenID4VCI 1.0 Sections 11.2.3 and
// 12.2), so a wallet encrypts its Credential Request and asks for an
// encrypted response.
func requireEncryption(c *counterparty, metadata map[string]interface{}) {
	metadata["credential_response_encryption"] = map[string]interface{}{
		"alg_values_supported": []string{"ECDH-ES"},
		"enc_values_supported": []string{"A256GCM"},
		"encryption_required":  true,
	}
	metadata["credential_request_encryption"] = map[string]interface{}{
		"jwks":                 map[string]interface{}{"keys": []jose.JSONWebKey{c.encryptionJWK}},
		"enc_values_supported": []string{"A256GCM"},
		"encryption_required":  true,
	}
}

func (c *counterparty) registerIssuerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-credential-issuer/scenarios/{scenario}", c.handleIssuerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/scenarios/{scenario}", c.handleAuthorizationServerMetadata)
	mux.HandleFunc("GET /scenarios/{scenario}/credential-offer", c.handleCredentialOffer)
	mux.HandleFunc("POST /scenarios/{scenario}/token", c.handleToken)
	mux.HandleFunc("POST /scenarios/ci-010/credential", c.handleCI010Credential)
	mux.HandleFunc("POST /scenarios/cw-072/credential", c.handleCW072Credential)
	mux.HandleFunc("POST /scenarios/cw-072-plaintext/credential", c.handleCW072PlaintextCredential)
	for _, endpoint := range []string{"authorize", "par"} {
		mux.HandleFunc("/scenarios/cw-h003/"+endpoint, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "conformance counterparty: this endpoint is advertised but not used",
			})
		})
	}
}

func (c *counterparty) handleIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	scenario := r.PathValue("scenario")
	alter, ok := issuerScenarios[scenario]
	if !ok {
		http.NotFound(w, r)
		return
	}
	issuer := c.scenarioURL(scenario)
	metadata := map[string]interface{}{
		"credential_issuer":   issuer,
		"credential_endpoint": issuer + "/credential",
		"credential_configurations_supported": map[string]interface{}{
			counterpartyConfigurationID: map[string]interface{}{
				"format": "dc+sd-jwt",
				"vct":    issuer + "/vct",
			},
		},
		"display": []map[string]string{{"name": "ProtocolSoup Conformance Counterparty", "locale": "en-US"}},
	}
	if alter != nil {
		alter(c, metadata)
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (c *counterparty) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	scenario := r.PathValue("scenario")
	issuer := c.scenarioURL(scenario)
	switch {
	case scenario == "cw-h004":
		// HAIP 1.0 Section 4: the wallet "MUST support DPoP as defined in
		// [RFC9449]" and authenticates with attestation-based client
		// authentication, so advertising both puts it on its attested DPoP
		// path for the Token Request.
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"issuer":                                issuer,
			"token_endpoint":                        issuer + "/token",
			"dpop_signing_alg_values_supported":     []string{"ES256"},
			"token_endpoint_auth_methods_supported": []string{"attest_jwt_client_auth"},
		})
	case preAuthorizedScenarios[scenario]:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"issuer":         issuer,
			"token_endpoint": issuer + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
		})
	case scenario == "cw-h003":
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"issuer":                                         issuer,
			"authorization_endpoint":                         issuer + "/authorize",
			"token_endpoint":                                 issuer + "/token",
			"pushed_authorization_request_endpoint":          issuer + "/par",
			"require_pushed_authorization_requests":          true,
			"code_challenge_methods_supported":               []string{"plain"},
			"authorization_response_iss_parameter_supported": true,
		})
	default:
		http.NotFound(w, r)
	}
}

func (c *counterparty) handleCredentialOffer(w http.ResponseWriter, r *http.Request) {
	scenario := r.PathValue("scenario")
	grant := map[string]interface{}{}
	switch {
	case preAuthorizedScenarios[scenario]:
		grant["pre-authorized_code"] = c.issue(scenario, preAuthorizedCodeLifetime)
	case scenario == "cw-006":
		// OpenID4VCI 1.0 Section 4.1.1: a tx_code object, "including if
		// empty", obliges the wallet to send a Transaction Code.
		grant["pre-authorized_code"] = randomToken()
		grant["tx_code"] = map[string]interface{}{}
	case scenario == "cw-010":
		grant["pre-authorized_code"] = randomToken()
		grant["authorization_server"] = c.scenarioURL("cw-010") + "/as-unlisted"
	default:
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"credential_issuer":            c.scenarioURL(scenario),
		"credential_configuration_ids": []string{counterpartyConfigurationID},
		"grants": map[string]interface{}{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": grant,
		},
	})
}

// handleToken redeems a pre-authorized code the scenario's offer issued
// (OpenID4VCI 1.0 Section 6) for a Bearer access token.
func (c *counterparty) handleToken(w http.ResponseWriter, r *http.Request) {
	scenario := r.PathValue("scenario")
	if !preAuthorizedScenarios[scenario] {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "conformance counterparty: this endpoint is advertised but not used",
		})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if scenario == "cw-h004" {
		c.handleCWH004Token(w, r)
		return
	}
	if !c.redeem(scenario, r.PostForm.Get("pre-authorized_code")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "pre-authorized_code is unknown, used or expired"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": c.issue(scenario, accessTokenLifetime),
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenLifetime.Seconds()),
	})
}

// handleCWH004Token answers a DPoP-bound Token Request for a live cw-h004
// pre-authorized code with the RFC 9449 Section 8 nonce challenge, minus the
// header that carries the nonce. Section 8: "the authorization server
// responds to requests that do not include a nonce with an HTTP 400 (Bad
// Request) error response per Section 5.2 of [RFC6749] using use_dpop_nonce
// as the error code value. The authorization server includes a DPoP-Nonce
// HTTP header in the response supplying a nonce value to be used when
// sending the subsequent request." Without that header the wallet has no
// nonce to put in a proof, so a wallet that handles DPoP-Nonce stops here
// instead of repeating the request. The code is never consumed: a real
// nonce challenge leaves the grant for the retry, and no retry can follow.
func (c *counterparty) handleCWH004Token(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("DPoP")) == "" {
		// RFC 9449 Section 5: "the client MUST provide a valid DPoP proof
		// JWT in a DPoP header when making an access token request to the
		// authorization server's token endpoint".
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "a DPoP proof JWT in the DPoP header is required (RFC 9449 Section 5)",
		})
		return
	}
	if !c.holds("cw-h004", r.PostForm.Get("pre-authorized_code")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "pre-authorized_code is unknown or expired"})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":             "use_dpop_nonce",
		"error_description": "Authorization server requires nonce in DPoP proof",
	})
}

// bearer checks the Authorization header carries an access token the
// scenario's Token Endpoint issued.
func (c *counterparty) bearer(w http.ResponseWriter, r *http.Request, scenario string) bool {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || !c.holds(scenario, strings.TrimSpace(token)) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return false
	}
	return true
}

// handleCI010Credential answers an immediate Credential Response with an
// empty credentials array, which OpenID4VCI 1.0 Section 8.3 does not allow.
func (c *counterparty) handleCI010Credential(w http.ResponseWriter, r *http.Request) {
	if !c.bearer(w, r, "ci-010") {
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"credentials": []interface{}{}})
}

// decryptCredentialRequest reads and decrypts the wallet's encrypted
// Credential Request for scenario and returns the response encryption key it
// supplied. It writes the error response itself and returns false when the
// request is not the encrypted request the scenario's metadata demanded.
func (c *counterparty) decryptCredentialRequest(w http.ResponseWriter, r *http.Request, scenario string) (*jose.JSONWebKey, bool) {
	if !c.bearer(w, r, scenario) {
		return nil, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": err.Error()})
		return nil, false
	}
	encrypted, err := jose.ParseEncrypted(strings.TrimSpace(string(raw)), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_encryption_parameters", "error_description": err.Error()})
		return nil, false
	}
	plaintext, err := encrypted.Decrypt(c.encryptionKey)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_encryption_parameters", "error_description": err.Error()})
		return nil, false
	}
	var request struct {
		CredentialResponseEncryption struct {
			JWK json.RawMessage `json:"jwk"`
			Enc string          `json:"enc"`
		} `json:"credential_response_encryption"`
	}
	if err := json.Unmarshal(plaintext, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_credential_request", "error_description": err.Error()})
		return nil, false
	}
	var walletKey jose.JSONWebKey
	if err := walletKey.UnmarshalJSON(request.CredentialResponseEncryption.JWK); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_encryption_parameters", "error_description": "credential_response_encryption.jwk: " + err.Error()})
		return nil, false
	}
	return &walletKey, true
}

// handleCW072PlaintextCredential decrypts the wallet's encrypted Credential
// Request, which asked for an encrypted response, and answers it in
// plaintext application/json. OpenID4VCI 1.0 Section 8.3: "If the Client
// requested an encrypted response by including the
// credential_response_encryption object in the request, the Credential
// Issuer MUST encode the information in the Credential Response as specified
// by Section 10". Section 10: "When encryption of a message was required but
// the received message is unencrypted, it SHOULD be rejected." The answer
// defers issuance rather than issue a Credential, so it carries nothing a
// wallet could store if it failed to reject it.
func (c *counterparty) handleCW072PlaintextCredential(w http.ResponseWriter, r *http.Request) {
	if _, ok := c.decryptCredentialRequest(w, r, "cw-072-plaintext"); !ok {
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"transaction_id":           randomToken(),
		"interval":                 86400,
		"conformance_counterparty": "this Credential Response is plaintext application/json although the Credential Request asked for an encrypted response, and no Credential will be issued",
	})
}

// handleCW072Credential decrypts the wallet's encrypted Credential Request,
// reads the response encryption key it supplied, and encrypts the response
// with ECDH-ES+A256KW instead of the negotiated ECDH-ES.
func (c *counterparty) handleCW072Credential(w http.ResponseWriter, r *http.Request) {
	walletKey, ok := c.decryptCredentialRequest(w, r, "cw-072")
	if !ok {
		return
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.ECDH_ES_A256KW,
		Key:       walletKey.Key,
		KeyID:     walletKey.KeyID,
	}, nil)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_encryption_parameters", "error_description": err.Error()})
		return
	}
	body, _ := json.Marshal(map[string]string{
		"conformance_counterparty": "this Credential Response is encrypted with ECDH-ES+A256KW, not the negotiated ECDH-ES, and carries no Credential",
	})
	object, err := encrypter.Encrypt(body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": err.Error()})
		return
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = w.Write([]byte(compact))
}
