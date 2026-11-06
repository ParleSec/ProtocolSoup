package haipwallet

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/golang-jwt/jwt/v5"
)

// The wallet's Pushed Authorization Request and the client authentication it
// presents there and at the Token Endpoint (HAIP 1.0 Sections 4, 4.3 and
// 4.4.1).

const (
	stepPAR   = "Pushed Authorization Request"
	stepToken = "Token Request"

	typClientAttestation    = "oauth-client-attestation+jwt"
	typClientAttestationPoP = "oauth-client-attestation-pop+jwt"
	typDPoP                 = "dpop+jwt"
)

// pushedAuthorization imports an authorization_code offer for the HAIP
// configuration and returns the PAR hop the authorization server accepted,
// together with the wallet's answer.
func pushedAuthorization(ctx context.Context, env *capture.Env) (*capture.WalletResult, *capture.WalletHop, error) {
	link, err := authorizationCodeOfferLink(ctx, env, haipConfigurationID)
	if err != nil {
		return nil, nil, err
	}
	result, err := importCredential(ctx, env, map[string]any{"offer": link})
	if err != nil {
		return nil, nil, err
	}
	if result.Status != http.StatusOK || result.Body["authorization_required"] != true {
		return nil, nil, fmt.Errorf("wallet /api/import answered %s: %s", capture.WalletStatusText(result.Status), walletError(result))
	}
	par, err := completedHop(result, stepPAR)
	if err != nil {
		return nil, nil, err
	}
	return result, par, nil
}

// parWithPKCES256 checks the HAIP 1.0 Section 4 PKCE and PAR provisions on
// the recorded PAR request and the authorization URL built from it.
func parWithPKCES256(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, par, err := pushedAuthorization(ctx, env)
	if err != nil {
		return "", err
	}
	form, err := hopForm(par)
	if err != nil {
		return "", err
	}
	if method := form.Get("code_challenge_method"); method != "S256" {
		return "", fmt.Errorf("PAR request carries code_challenge_method %q, not S256", method)
	}
	// RFC 7636 Section 4.2: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), 43 characters.
	if challenge := form.Get("code_challenge"); len(challenge) != 43 {
		return "", fmt.Errorf("PAR request carries code_challenge %q, not a 43-character S256 challenge", challenge)
	}
	requestURI, _ := hopJSON(par.ResponseBody)["request_uri"].(string)
	if requestURI == "" {
		return "", fmt.Errorf("PAR response carries no request_uri: %s", capture.Truncate([]byte(par.ResponseBody)))
	}
	rawURL, _ := result.Body["authorization_url"].(string)
	authorizationURL, err := url.Parse(rawURL)
	if err != nil || rawURL == "" {
		return "", fmt.Errorf("wallet returned no usable authorization_url: %q", rawURL)
	}
	query := authorizationURL.Query()
	if len(query) != 2 || query.Get("request_uri") != requestURI || query.Get("client_id") != form.Get("client_id") {
		return "", fmt.Errorf("authorization_url query is %q; RFC 9126 Section 4 allows only client_id and request_uri", authorizationURL.RawQuery)
	}
	return conformance.OutcomeAccepted, nil
}

// counterpartyWithoutS256 points the wallet at the counterparty's cw-h003
// issuer, whose authorization server requires PAR but advertises only the
// plain code challenge method.
func counterpartyWithoutS256(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	if env.CounterpartyURL == "" {
		return "", fmt.Errorf("this run has no counterparty")
	}
	result, err := importCredential(ctx, env, map[string]any{
		"credential_issuer":           env.CounterpartyURL + "/scenarios/cw-h003",
		"credential_configuration_id": counterpartyConfigurationID,
	})
	if err != nil {
		return "", err
	}
	if result.Hop(stepPAR) != nil {
		return "", fmt.Errorf("the wallet pushed an Authorization Request to a server that advertises no S256")
	}
	return refused(result, "does not advertise PKCE S256")
}

// clientAuthentication is what one request presented as HAIP client
// authentication: the decoded Client Attestation JWT, its proof of
// possession, the DPoP proof and the form client_id.
type clientAuthentication struct {
	Attestation       string
	AttestationHeader map[string]any
	AttestationClaims map[string]any
	PoPClaims         map[string]any
	DPoPClaims        map[string]any
	ClientID          string
}

// readClientAuthentication decodes the three authentication headers of a
// recorded form request and checks client_id against the attestation sub,
// which HAIP 1.0 Section 4.4.1 requires for PAR.
func readClientAuthentication(hop *capture.WalletHop) (*clientAuthentication, error) {
	auth := &clientAuthentication{}
	for _, header := range []struct {
		name   string
		typ    string
		header *map[string]any
		claims *map[string]any
	}{
		{"OAuth-Client-Attestation", typClientAttestation, &auth.AttestationHeader, &auth.AttestationClaims},
		{"OAuth-Client-Attestation-PoP", typClientAttestationPoP, nil, &auth.PoPClaims},
		{"DPoP", typDPoP, nil, &auth.DPoPClaims},
	} {
		compact := hopHeader(hop.RequestHeaders, header.name)
		if compact == "" {
			return nil, fmt.Errorf("%s request carries no %s header", hop.Step, header.name)
		}
		decodedHeader, claims, err := capture.JWTParts(compact)
		if err != nil {
			return nil, fmt.Errorf("%s %s header: %w", hop.Step, header.name, err)
		}
		if decodedHeader["typ"] != header.typ {
			return nil, fmt.Errorf("%s %s header has typ %v, want %s", hop.Step, header.name, decodedHeader["typ"], header.typ)
		}
		if header.header != nil {
			*header.header = decodedHeader
			auth.Attestation = compact
		}
		*header.claims = claims
	}
	form, err := hopForm(hop)
	if err != nil {
		return nil, err
	}
	auth.ClientID = form.Get("client_id")
	sub, _ := auth.AttestationClaims["sub"].(string)
	if sub == "" {
		return nil, fmt.Errorf("%s Client Attestation JWT has no sub", hop.Step)
	}
	if auth.ClientID != sub {
		return nil, fmt.Errorf("%s client_id %q differs from the Client Attestation sub %q", hop.Step, auth.ClientID, sub)
	}
	if iss, _ := auth.PoPClaims["iss"].(string); iss != sub {
		return nil, fmt.Errorf("%s Client Attestation PoP iss %q differs from the attestation sub %q", hop.Step, iss, sub)
	}
	// RFC 6749 Section 2.3: "MUST NOT use more than one authentication
	// method in each request". Attestation is the method; a client_secret or
	// a client_assertion beside it would be a second one.
	for _, parameter := range []string{"client_secret", "client_assertion"} {
		if form.Has(parameter) {
			return nil, fmt.Errorf("%s request authenticates with client attestation and also %s", hop.Step, parameter)
		}
	}
	return auth, nil
}

// sameClientAuthentication compares the client authentication of the PAR
// request and of a Token Request (HAIP 1.0 Section 4.3).
func sameClientAuthentication(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	_, par, err := pushedAuthorization(ctx, env)
	if err != nil {
		return "", err
	}
	parAuth, err := readClientAuthentication(par)
	if err != nil {
		return "", err
	}
	tokenResult, err := preAuthorizedHAIPImport(ctx, env)
	if err != nil {
		return "", err
	}
	token, err := completedHop(tokenResult, stepToken)
	if err != nil {
		return "", err
	}
	tokenAuth, err := readClientAuthentication(token)
	if err != nil {
		return "", err
	}
	if parAuth.ClientID != tokenAuth.ClientID {
		return "", fmt.Errorf("PAR client_id %q differs from Token Request client_id %q", parAuth.ClientID, tokenAuth.ClientID)
	}
	for _, claim := range []string{"iss", "sub"} {
		if parAuth.AttestationClaims[claim] != tokenAuth.AttestationClaims[claim] {
			return "", fmt.Errorf("the Client Attestation %s differs: PAR %v, Token Request %v", claim, parAuth.AttestationClaims[claim], tokenAuth.AttestationClaims[claim])
		}
	}
	if parAuth.PoPClaims["aud"] != tokenAuth.PoPClaims["aud"] {
		return "", fmt.Errorf("the Client Attestation PoP aud differs: PAR %v, Token Request %v", parAuth.PoPClaims["aud"], tokenAuth.PoPClaims["aud"])
	}
	return conformance.OutcomeAccepted, nil
}

// walletAttestation checks the HAIP 1.0 Section 4.4.1 rules on the Wallet
// Attestation across two PAR requests.
func walletAttestation(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	var attestations []*clientAuthentication
	for range 2 {
		_, par, err := pushedAuthorization(ctx, env)
		if err != nil {
			return "", err
		}
		auth, err := readClientAuthentication(par)
		if err != nil {
			return "", err
		}
		if err := verifyAttestationChain(auth); err != nil {
			return "", err
		}
		if cnf, _ := auth.AttestationClaims["cnf"].(map[string]any); cnf["jwk"] == nil {
			return "", fmt.Errorf("the Client Attestation JWT has no cnf.jwk")
		}
		if _, ok := auth.AttestationClaims["exp"].(float64); !ok {
			return "", fmt.Errorf("the Client Attestation JWT has no exp")
		}
		attestations = append(attestations, auth)
	}
	first, second := attestations[0], attestations[1]
	if first.AttestationClaims["sub"] != second.AttestationClaims["sub"] {
		return "", fmt.Errorf("the two attestations carry different sub values %v and %v; HAIP requires one shared by every instance of the wallet", first.AttestationClaims["sub"], second.AttestationClaims["sub"])
	}
	if first.Attestation == second.Attestation {
		return "", fmt.Errorf("the wallet reused one Client Attestation JWT across two requests")
	}
	firstKey, _ := first.AttestationClaims["cnf"].(map[string]any)
	secondKey, _ := second.AttestationClaims["cnf"].(map[string]any)
	if fmt.Sprint(firstKey["jwk"]) == fmt.Sprint(secondKey["jwk"]) {
		return "", fmt.Errorf("the two attestations bind the same cnf.jwk; the wallet did not mint a fresh client instance key per request")
	}
	return conformance.OutcomeAccepted, nil
}

// verifyAttestationChain checks the attestation is ES256-signed under the
// leaf of its x5c chain, and that the chain holds no self-signed certificate
// (HAIP 1.0 Section 4.4.1: the chain is included "excluding the trust
// anchor").
func verifyAttestationChain(auth *clientAuthentication) error {
	if auth.AttestationHeader["alg"] != "ES256" {
		return fmt.Errorf("the Client Attestation JWT alg is %v, want ES256", auth.AttestationHeader["alg"])
	}
	chain, _ := auth.AttestationHeader["x5c"].([]any)
	if len(chain) == 0 {
		return fmt.Errorf("the Client Attestation JWT has no x5c header")
	}
	certificates := make([]*x509.Certificate, 0, len(chain))
	for _, raw := range chain {
		encoded, _ := raw.(string)
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return fmt.Errorf("decode x5c entry: %w", err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse x5c entry: %w", err)
		}
		if certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil {
			return fmt.Errorf("the Client Attestation x5c includes the self-signed certificate %q, which HAIP excludes as the trust anchor", certificate.Subject.String())
		}
		certificates = append(certificates, certificate)
	}
	for i := 0; i+1 < len(certificates); i++ {
		if err := certificates[i].CheckSignatureFrom(certificates[i+1]); err != nil {
			return fmt.Errorf("x5c entry %d is not signed by entry %d: %w", i, i+1, err)
		}
	}
	_, err := jwt.Parse(auth.Attestation, func(*jwt.Token) (any, error) {
		return certificates[0].PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	if err != nil {
		return fmt.Errorf("the Client Attestation signature does not verify under the x5c leaf key: %w", err)
	}
	return nil
}
