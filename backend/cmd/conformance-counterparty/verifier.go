package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The verifier role: request objects the hosted wallet fetches by
// request_uri. Each is signed ES256 by the counterparty's own key under the
// decentralized_identifier Client Identifier Prefix (OpenID4VP 1.0 Section
// 5.9.3), with a did:web DID Document per scenario, so a wallet can verify
// it; each scenario then breaks exactly one rule.

// requestObjectLifetime is how long a served request object stays valid.
const requestObjectLifetime = 5 * time.Minute

// verifierScenarios lists the scenarios that publish a DID Document.
var verifierScenarios = map[string]bool{
	"vp-001": true, "vp-002": true, "vp-003": true, "vp-004": true,
	"vp-011": true, "vp-012": true, "cw-h017": true,
}

func (c *counterparty) registerVerifierRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /scenarios/{scenario}/did.json", c.handleDIDDocument)
	// VP-001: a Client Identifier Prefix that OpenID4VP 1.0 does not define,
	// with the removed client_id_scheme parameter claiming pre-registration.
	mux.HandleFunc("GET /scenarios/vp-001/request", c.serveRequestObject("vp-001", func(claims jwt.MapClaims) {
		claims["client_id"] = "entity_id:" + c.scenarioURL("vp-001")
		claims["client_id_scheme"] = "pre-registered"
	}))
	// VP-002: an unrecognized Client Identifier Prefix.
	mux.HandleFunc("GET /scenarios/vp-002/request", c.serveRequestObject("vp-002", func(claims jwt.MapClaims) {
		claims["client_id"] = "unregistered_prefix:" + c.scenarioURL("vp-002")
	}))
	// VP-003: a valid, verifiable request carrying parameters the wallet does
	// not recognize, answered at /response.
	mux.HandleFunc("GET /scenarios/vp-003/request", c.serveRequestObject("vp-003", func(claims jwt.MapClaims) {
		claims["x_protocolsoup_extension"] = map[string]interface{}{"note": "a parameter no specification defines"}
		claims["client_id_scheme"] = "redirect_uri"
		claims["presentation_definition"] = map[string]interface{}{"id": "removed-draft-parameter", "input_descriptors": []interface{}{}}
		c.rememberState("vp-003", claims["state"].(string))
	}))
	mux.HandleFunc("POST /scenarios/vp-003/response", c.handleVP003Response)
	// VP-004: the signed request wrapped in JSON and served as
	// application/json instead of application/oauth-authz-req+jwt.
	mux.HandleFunc("GET /scenarios/vp-004/request", c.handleVP004Request)
	// VP-011: a transaction_data entry of a type the wallet cannot support.
	mux.HandleFunc("GET /scenarios/vp-011/request", c.serveRequestObject("vp-011", func(claims jwt.MapClaims) {
		transaction, _ := json.Marshal(map[string]interface{}{
			"type":           c.scenarioURL("vp-011") + "/transaction-type",
			"credential_ids": []string{dcqlCredentialID},
		})
		claims["transaction_data"] = []string{base64.RawURLEncoding.EncodeToString(transaction)}
	}))
	// VP-012: POST retrieval answered with a wallet_nonce other than the one
	// the wallet sent.
	mux.HandleFunc("POST /scenarios/vp-012/request", c.serveRequestObject("vp-012", func(claims jwt.MapClaims) {
		claims["wallet_nonce"] = "conformance-counterparty-mismatched-nonce"
	}))
	// CW-H017: an ES256 request object whose signature does not verify.
	mux.HandleFunc("GET /scenarios/cw-h017/request", c.handleCWH017Request)
}

// dcqlCredentialID names the one Credential Query in every request.
const dcqlCredentialID = "degree"

// productionDegreeVCT is the vct of the University Degree SD-JWT VC the
// production issuer issues; requests ask for it so the hosted wallet can
// present a Credential it really holds.
const productionDegreeVCT = "https://protocolsoup.com/credentials/university_degree"

func (c *counterparty) scenarioURL(scenario string) string {
	return c.baseURL + "/scenarios/" + scenario
}

// scenarioDID is the did:web identifier whose DID Document is served at
// /scenarios/<scenario>/did.json, as the did:web method resolves it.
func (c *counterparty) scenarioDID(scenario string) string {
	return "did:web:" + strings.ReplaceAll(c.host, ":", "%3A") + ":scenarios:" + scenario
}

func (c *counterparty) handleDIDDocument(w http.ResponseWriter, r *http.Request) {
	scenario := r.PathValue("scenario")
	if !verifierScenarios[scenario] {
		http.NotFound(w, r)
		return
	}
	did := c.scenarioDID(scenario)
	methodID := did + "#request-signing"
	document := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":       did,
		"verificationMethod": []map[string]interface{}{{
			"id":           methodID,
			"type":         "JsonWebKey2020",
			"controller":   did,
			"publicKeyJwk": c.signingJWK,
		}},
		"assertionMethod": []string{methodID},
		"authentication":  []string{methodID},
	}
	body, err := json.Marshal(document)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	_, _ = w.Write(body)
}

// requestClaims is a well-formed OpenID4VP 1.0 request for one dc+sd-jwt
// University Degree Credential, answered by direct_post to the scenario's
// /response route.
func (c *counterparty) requestClaims(scenario string) jwt.MapClaims {
	now := time.Now().UTC()
	clientID := "decentralized_identifier:" + c.scenarioDID(scenario)
	return jwt.MapClaims{
		"iss":           clientID,
		"aud":           "https://self-issued.me/v2",
		"client_id":     clientID,
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  c.scenarioURL(scenario) + "/response",
		"nonce":         randomToken(),
		"state":         randomToken(),
		"jti":           randomToken(),
		"iat":           now.Unix(),
		"exp":           now.Add(requestObjectLifetime).Unix(),
		"dcql_query": map[string]interface{}{"credentials": []map[string]interface{}{{
			"id":     dcqlCredentialID,
			"format": "dc+sd-jwt",
			"meta":   map[string]interface{}{"vct_values": []string{productionDegreeVCT}},
		}}},
		"client_metadata": map[string]interface{}{
			"client_name": "ProtocolSoup Conformance Counterparty",
			"vp_formats_supported": map[string]interface{}{
				"dc+sd-jwt": map[string]interface{}{
					"sd-jwt_alg_values": []string{"ES256"},
					"kb-jwt_alg_values": []string{"ES256"},
				},
			},
		},
	}
}

// signRequestObject signs claims as an oauth-authz-req+jwt with the key the
// scenario's DID Document publishes.
func (c *counterparty) signRequestObject(scenario string, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-authz-req+jwt"
	token.Header["kid"] = c.scenarioDID(scenario) + "#request-signing"
	return token.SignedString(c.signingKey)
}

// serveRequestObject answers a request_uri retrieval with the scenario's
// request object, built from the template and changed by alter.
func (c *counterparty) serveRequestObject(scenario string, alter func(jwt.MapClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		claims := c.requestClaims(scenario)
		alter(claims)
		signed, err := c.signRequestObject(scenario, claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeRequestObject(w, signed)
	}
}

func writeRequestObject(w http.ResponseWriter, compact string) {
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	_, _ = w.Write([]byte(compact))
}

func (c *counterparty) handleVP004Request(w http.ResponseWriter, _ *http.Request) {
	signed, err := c.signRequestObject("vp-004", c.requestClaims("vp-004"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"request": signed})
}

func (c *counterparty) handleCWH017Request(w http.ResponseWriter, _ *http.Request) {
	claims := c.requestClaims("cw-h017")
	signed, err := c.signRequestObject("cw-h017", claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Change one claim after signing, so the ES256 signature no longer
	// covers the payload.
	claims["state"] = "altered-after-signing"
	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	parts := strings.Split(signed, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	writeRequestObject(w, strings.Join(parts, "."))
}

// handleVP003Response receives the wallet's Authorization Response to the
// VP-003 request (OpenID4VP 1.0 Section 8.2). The counterparty only checks
// that state names a request it served; it does not verify the presentation.
func (c *counterparty) handleVP003Response(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
		return
	}
	if !c.consumeState("vp-003", r.PostForm.Get("state")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "state does not name a request this counterparty served"})
		return
	}
	if strings.TrimSpace(r.PostForm.Get("vp_token")) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "vp_token is required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{})
}

func randomToken() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// hostOf returns the host[:port] of an origin.
func hostOf(origin string) string {
	parsed, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return parsed.Host
}
