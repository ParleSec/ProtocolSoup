package haipwallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

// The wallet's authorization_code issuance from the Pushed Authorization
// Request to the Credential it stores, and the Refresh Token it keeps. The
// End-User between the two is played by the conformance client
// (capture.AuthorizeAsEndUser).

// Authorization is an authorization_code import the hosted wallet has pushed
// to the issuer's authorization server and the End-User has yet to complete.
type Authorization struct {
	// Session is the wallet session the import runs in.
	Session string
	// Import is the wallet's authorization_required answer, with the hops
	// up to and including the PAR.
	Import *capture.WalletResult
	// PAR is the Pushed Authorization Request the authorization server
	// accepted.
	PAR *capture.WalletHop
}

// PushedAuthorization has the issuer create an authorization_code offer for
// the HAIP configuration and asks the hosted wallet to import it in a fresh
// session. The wallet pushes its Authorization Request and stops at the
// authorization URL the End-User must open.
func PushedAuthorization(ctx context.Context, env *capture.Env) (*Authorization, error) {
	link, err := authorizationCodeOfferLink(ctx, env, haipConfigurationID)
	if err != nil {
		return nil, err
	}
	session := capture.NewWalletSession()
	result, err := importCredentialIn(ctx, env, session, map[string]any{"offer": link})
	if err != nil {
		return nil, err
	}
	if result.Status != http.StatusOK || result.Body["authorization_required"] != true {
		return nil, fmt.Errorf("wallet /api/import answered %s: %s", capture.WalletStatusText(result.Status), walletError(result))
	}
	par, err := completedHop(result, stepPAR)
	if err != nil {
		return nil, err
	}
	return &Authorization{Session: session, Import: result, PAR: par}, nil
}

// AuthorizationURL is the URL the wallet asks the End-User to open.
func (a *Authorization) AuthorizationURL() string {
	rawURL, _ := a.Import.Body["authorization_url"].(string)
	return rawURL
}

// Complete plays the End-User at the Mock IdP and delivers the Authorization
// Response to the wallet's callback. It returns the wallet's answer, whose
// hops are the Token Request and the Credential Request that followed, and
// the Authorization Response parameters as delivered, having checked that
// the wallet stored a Credential.
func (a *Authorization) Complete(ctx context.Context, env *capture.Env) (*capture.WalletResult, url.Values, error) {
	result, response, err := capture.AuthorizeAsEndUser(ctx, env, a.AuthorizationURL(), a.Session)
	if err != nil {
		return nil, nil, err
	}
	if result.Status != http.StatusOK {
		return nil, nil, fmt.Errorf("the wallet's callback answered %s: %s", capture.WalletStatusText(result.Status), walletError(result))
	}
	if credential, _ := result.Body["credential_jwt"].(string); credential == "" {
		return nil, nil, fmt.Errorf("the wallet's callback answered 200 OK without a credential_jwt")
	}
	return result, response, nil
}

// credentialIdentifiersUsed checks OpenID4VCI 1.0 Section 6.2 on the
// authorization_code issuance: the Token Response's authorization_details
// carry credential_identifiers, and the Credential Request names one of them
// with the Access Token of that response.
func credentialIdentifiersUsed(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	authorization, err := PushedAuthorization(ctx, env)
	if err != nil {
		return "", err
	}
	callback, _, err := authorization.Complete(ctx, env)
	if err != nil {
		return "", err
	}
	token, err := completedHop(callback, stepToken)
	if err != nil {
		return "", err
	}
	tokenResponse := hopJSON(token.ResponseBody)
	accessToken, _ := tokenResponse["access_token"].(string)
	tokenType, _ := tokenResponse["token_type"].(string)
	identifiers := map[string]bool{}
	details, _ := tokenResponse["authorization_details"].([]any)
	for _, raw := range details {
		detail, _ := raw.(map[string]any)
		listed, _ := detail["credential_identifiers"].([]any)
		for _, identifier := range listed {
			if value, _ := identifier.(string); value != "" {
				identifiers[value] = true
			}
		}
	}
	if len(identifiers) == 0 {
		return "", fmt.Errorf("the Token Response carries no authorization_details with credential_identifiers: %s", capture.Truncate([]byte(token.ResponseBody)))
	}
	credential, err := completedHop(callback, stepCredential)
	if err != nil {
		return "", err
	}
	request, err := requestJSON(credential)
	if err != nil {
		return "", err
	}
	identifier, _ := request["credential_identifier"].(string)
	if !identifiers[identifier] {
		return "", fmt.Errorf("the Credential Request names credential_identifier %q, which the Token Response did not return", identifier)
	}
	if _, present := request["credential_configuration_id"]; present {
		return "", fmt.Errorf("the Credential Request carries credential_configuration_id beside credential_identifier")
	}
	if got := hopHeader(credential.RequestHeaders, "Authorization"); got != tokenType+" "+accessToken {
		return "", fmt.Errorf("the Credential Request's Authorization header %q does not present the Token Response's %s Access Token", got, tokenType)
	}
	return conformance.OutcomeAccepted, nil
}

// refreshedWithRefreshToken checks OpenID4VCI 1.0 Section 14.5: the wallet
// keeps the Refresh Token the authorization_code Token Response returned and,
// asked to refresh the Credential, obtains a fresh Access Token with it at
// the Token Endpoint (RFC 6749 Section 6) before requesting the Credential
// again.
func refreshedWithRefreshToken(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	authorization, err := PushedAuthorization(ctx, env)
	if err != nil {
		return "", err
	}
	callback, _, err := authorization.Complete(ctx, env)
	if err != nil {
		return "", err
	}
	issued, err := completedHop(callback, stepToken)
	if err != nil {
		return "", err
	}
	issuedResponse := hopJSON(issued.ResponseBody)
	refreshToken, _ := issuedResponse["refresh_token"].(string)
	if refreshToken == "" {
		return "", fmt.Errorf("the authorization_code Token Response carries no refresh_token: %s", capture.Truncate([]byte(issued.ResponseBody)))
	}
	// The Refresh Token outlives the run. It is published only because the
	// issuer bound it to this wallet instance: the Token Response is DPoP
	// sender-constrained, and the issuer redeems a refresh_token only with
	// client attestation under the same Client Instance Key. Either missing
	// would make the artefact a usable credential, so the capture stops.
	if tokenType, _ := issuedResponse["token_type"].(string); !strings.EqualFold(tokenType, "DPoP") {
		return "", fmt.Errorf("the Token Response's token_type is %q, not DPoP; its refresh_token would be redeemable by a reader", tokenType)
	}
	if _, err := readClientAuthentication(issued); err != nil {
		return "", err
	}

	refreshed, err := capture.CallWallet(ctx, env, capture.WalletCall{Path: "/api/refresh", Body: map[string]any{}, Session: authorization.Session})
	if err != nil {
		return "", err
	}
	if refreshed.Status != http.StatusOK {
		return "", fmt.Errorf("wallet /api/refresh answered %s: %s", capture.WalletStatusText(refreshed.Status), walletError(refreshed))
	}
	refresh, err := completedHop(refreshed, stepToken)
	if err != nil {
		return "", err
	}
	form, err := hopForm(refresh)
	if err != nil {
		return "", err
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != refreshToken {
		return "", fmt.Errorf("the refresh Token Request has grant_type %q and does not present the Refresh Token the issuer returned", form.Get("grant_type"))
	}
	if _, err := readClientAuthentication(refresh); err != nil {
		return "", err
	}
	refreshResponse := hopJSON(refresh.ResponseBody)
	fresh, _ := refreshResponse["access_token"].(string)
	previous, _ := issuedResponse["access_token"].(string)
	if fresh == "" || fresh == previous {
		return "", fmt.Errorf("the refresh Token Response did not return a fresh access_token")
	}
	credential, err := completedHop(refreshed, stepCredential)
	if err != nil {
		return "", err
	}
	if got := hopHeader(credential.RequestHeaders, "Authorization"); !strings.HasSuffix(got, " "+fresh) {
		return "", fmt.Errorf("the Credential Request after the refresh presents %q, not the fresh Access Token", got)
	}
	if stored, _ := refreshed.Body["credential_jwt"].(string); stored == "" {
		return "", fmt.Errorf("wallet /api/refresh answered 200 OK without a credential_jwt")
	}
	return conformance.OutcomeAccepted, nil
}

// requestJSON decodes a hop's request as a JSON object, from the plaintext
// the wallet recorded it encrypted when the body is a JWE.
func requestJSON(hop *capture.WalletHop) (map[string]any, error) {
	body := hop.RequestBody
	if hop.RequestPlaintext != "" {
		body = hop.RequestPlaintext
	} else if hop.RequestBodyEncoding != "" {
		return nil, fmt.Errorf("%s request body is %s-encoded, not JSON text", hop.Step, hop.RequestBodyEncoding)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return nil, fmt.Errorf("decode %s request: %w", hop.Step, err)
	}
	return out, nil
}
