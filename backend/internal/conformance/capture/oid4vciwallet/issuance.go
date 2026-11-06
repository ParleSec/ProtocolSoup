package oid4vciwallet

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

// How the conformance client drives the hosted wallet through an OpenID4VCI
// issuance and reads what the wallet did. The wallet call is the recorded
// exchange; the wallet's own hops arrive with it and are read here to decide
// whether the requirement was met.

// Hop step names as the hosted wallet labels its OpenID4VCI hops
// (cmd/walletharness classifyOID4VCIProtocolHop).
const (
	stepCredentialOffer = "Fetch Credential Offer"
	stepIssuerMetadata  = "Fetch Credential Issuer Metadata"
	stepASMetadata      = "Fetch Authorization Server Metadata"
	stepToken           = "Token Request"
	stepNonce           = "Nonce Request"
	stepCredential      = "Credential Request"
	stepDeferredPoll    = "Deferred Credential Poll"
	stepNotification    = "Credential Status Notification"
)

// preAuthorizedGrant is the Section 4.1.1 grant type key of a Credential Offer.
const preAuthorizedGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// offer is a pre-authorized Credential Offer the production issuer created,
// by reference.
type offer struct {
	// URI is the credential_offer_uri the wallet fetches the offer from.
	URI string
	// TxCode is the out-of-band Transaction Code of a tx_code offer, else "".
	TxCode string
}

// createOffer has the production issuer create a pre-authorized offer and
// returns its credential_offer_uri. capture.CreatePreAuthorizedOffer reads
// the same response for its pre_authorized_code only; the wallet is handed
// the offer by reference, so it needs the URI.
func createOffer(ctx context.Context, env *capture.Env, opts capture.OfferOptions) (*offer, error) {
	path := "/oid4vci/offers/pre-authorized"
	if opts.Deferred {
		path += "/deferred"
	}
	configuration := opts.ConfigurationID
	if configuration == "" {
		configuration = capture.IssuedConfiguration
	}
	request := map[string]any{"credential_configuration_ids": []string{configuration}}
	if opts.TxCode {
		request["tx_code_required"] = true
	}
	req, err := capture.NewJSON(env.BaseURL+path, request)
	if err != nil {
		return nil, err
	}
	body, err := capture.SetupJSON(ctx, env, req, http.StatusCreated, "offer creation")
	if err != nil {
		return nil, err
	}
	created := &offer{}
	if created.URI, _ = body["credential_offer_uri"].(string); created.URI == "" {
		return nil, fmt.Errorf("offer response has no credential_offer_uri")
	}
	if opts.TxCode {
		if created.TxCode, _ = body["tx_code_oob_value"].(string); created.TxCode == "" {
			return nil, fmt.Errorf("offer response has no tx_code_oob_value")
		}
	}
	// Until it is redeemed, the code is usable by anyone holding the URI
	// (and the tx_code, when there is one).
	env.NoteExpiry(capture.PreAuthorizedOfferLifetime)
	return created, nil
}

// fetchOffer reads the Credential Offer object the issuer serves at uri, as
// the Section 4.1.3 retrieval does, and returns its exact JSON.
func fetchOffer(ctx context.Context, env *capture.Env, uri string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("credential_offer_uri answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	return resp.Body, nil
}

// offerLink is the Section 4.1 Credential Offer link that carries the offer
// by reference.
func offerLink(offerURI string) string {
	return "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURI)
}

// importOffer hands the hosted wallet a Credential Offer link, with the
// Transaction Code when the End-User has one, in a fresh wallet session.
func importOffer(ctx context.Context, env *capture.Env, link, txCode string) (*capture.WalletResult, error) {
	body := map[string]any{"offer": link}
	if txCode != "" {
		body["tx_code"] = txCode
	}
	return capture.CallWallet(ctx, env, capture.WalletCall{Path: "/api/import", Body: body, Session: capture.NewWalletSession()})
}

// discoverIssuer has the hosted wallet start a wallet-initiated issuance
// from a Credential Issuer Identifier alone, which makes it fetch the
// Credential Issuer Metadata and answer with the configurations to choose
// from.
func discoverIssuer(ctx context.Context, env *capture.Env, credentialIssuer string) (*capture.WalletResult, error) {
	return capture.CallWallet(ctx, env, capture.WalletCall{
		Path:    "/api/import",
		Body:    map[string]any{"credential_issuer": credentialIssuer},
		Session: capture.NewWalletSession(),
	})
}

// issuedImport creates a pre-authorized offer at the production issuer and
// has the hosted wallet import it. It returns only when the wallet answered
// HTTP 200 with a bound Credential; anything else is an error naming the
// wallet's refusal.
func issuedImport(ctx context.Context, env *capture.Env, opts capture.OfferOptions) (*capture.WalletResult, *offer, error) {
	created, err := createOffer(ctx, env, opts)
	if err != nil {
		return nil, nil, err
	}
	result, err := importOffer(ctx, env, offerLink(created.URI), created.TxCode)
	if err != nil {
		return nil, nil, err
	}
	if err := requireIssued(result); err != nil {
		return nil, nil, err
	}
	return result, created, nil
}

// requireIssued checks the wallet completed the import and bound a Credential.
func requireIssued(result *capture.WalletResult) error {
	if result.Status != http.StatusOK {
		return fmt.Errorf("wallet answered %s", refusalText(result))
	}
	if id, _ := result.Body["credential_id"].(string); id == "" {
		return fmt.Errorf("wallet answered 200 OK without a credential_id")
	}
	return nil
}

// refusalText describes the wallet's answer for an error message.
func refusalText(result *capture.WalletResult) string {
	text := capture.WalletStatusText(result.Status)
	if code := result.Error(); code != "" {
		text += " " + code
	}
	if description := result.ErrorDescription(); description != "" {
		text += ": " + description
	}
	return text
}

// requireHop returns the wallet's first hop labelled step that carries the
// endpoint's own answer, or an error when the wallet recorded none. The
// hosted wallet's requests are DPoP-bound, so an endpoint may first answer
// with an RFC 9449 nonce challenge, which the wallet retries; that challenge
// hop is not the endpoint's answer.
func requireHop(result *capture.WalletResult, step string) (*capture.WalletHop, error) {
	hop := result.CompletedHop(step)
	if hop == nil {
		return nil, fmt.Errorf("the wallet recorded no completed %q hop", step)
	}
	return hop, nil
}

// requestJSON decodes a hop's request as a JSON object. When the wallet sent
// the body as a JWE, as the hosted wallet does for Credential Requests, the
// object is the plaintext the wallet recorded it encrypted.
func requestJSON(hop *capture.WalletHop) (map[string]any, error) {
	if hop.RequestPlaintext != "" {
		return hopJSON(hop.RequestPlaintext, "", hop.Step+" request plaintext")
	}
	return hopJSON(hop.RequestBody, hop.RequestBodyEncoding, hop.Step+" request")
}

// responseJSON decodes a hop's response as a JSON object, from the plaintext
// the wallet recorded it decrypted when the body is a JWE.
func responseJSON(hop *capture.WalletHop) (map[string]any, error) {
	if hop.ResponsePlaintext != "" {
		return hopJSON(hop.ResponsePlaintext, "", hop.Step+" response plaintext")
	}
	return hopJSON(hop.ResponseBody, hop.ResponseBodyEncoding, hop.Step+" response")
}

func hopJSON(body, encoding, what string) (map[string]any, error) {
	if encoding != "" {
		return nil, fmt.Errorf("%s body is %s-encoded, not JSON text", what, encoding)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return nil, fmt.Errorf("decode %s body: %w: %s", what, err, capture.Truncate([]byte(body)))
	}
	return out, nil
}

// requestForm decodes a hop's form-encoded request body.
func requestForm(hop *capture.WalletHop) (url.Values, error) {
	if hop.RequestBodyEncoding != "" {
		return nil, fmt.Errorf("%s request body is %s-encoded, not a form", hop.Step, hop.RequestBodyEncoding)
	}
	form, err := url.ParseQuery(hop.RequestBody)
	if err != nil {
		return nil, fmt.Errorf("decode %s form: %w", hop.Step, err)
	}
	return form, nil
}

// jwtProofs returns the jwt proofs of a Credential Request body, checking the
// Section 8.2 shape as it does: proofs is an object with exactly one member,
// named after the proof type, whose value is a non-empty array.
func jwtProofs(request map[string]any) ([]string, error) {
	proofs, ok := request["proofs"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("credential request proofs is not an object: %v", request["proofs"])
	}
	if len(proofs) != 1 {
		return nil, fmt.Errorf("credential request proofs has %d members, want exactly one proof type", len(proofs))
	}
	raw, ok := proofs["jwt"].([]any)
	if !ok {
		return nil, fmt.Errorf("credential request proofs has no jwt array; members: %v", keys(proofs))
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("credential request proofs.jwt is empty")
	}
	out := make([]string, 0, len(raw))
	for i, entry := range raw {
		compact, _ := entry.(string)
		if compact == "" {
			return nil, fmt.Errorf("credential request proofs.jwt[%d] is not a string", i)
		}
		out = append(out, compact)
	}
	return out, nil
}

// proof is one jwt key proof, decoded without verification: the scenario
// checks what the wallet put in it, not whether the issuer should accept it.
type proof struct {
	Header map[string]any
	Claims map[string]any
}

func decodeProofs(compacts []string) ([]proof, error) {
	out := make([]proof, 0, len(compacts))
	for i, compact := range compacts {
		header, claims, err := capture.JWTParts(compact)
		if err != nil {
			return nil, fmt.Errorf("proofs.jwt[%d]: %w", i, err)
		}
		out = append(out, proof{Header: header, Claims: claims})
	}
	return out, nil
}

// keyReferences counts the kid, jwk and x5c header parameters of a proof;
// Appendix F.1 allows exactly one.
func (p proof) keyReferences() []string {
	var present []string
	for _, name := range []string{"kid", "jwk", "x5c"} {
		if _, ok := p.Header[name]; ok {
			present = append(present, name)
		}
	}
	return present
}

// counterpartyScenario is the counterparty's identifier for scenario id,
// which is also the Credential Issuer Identifier its issuer scenarios use.
func counterpartyScenario(env *capture.Env, id string) (string, error) {
	if env.CounterpartyURL == "" {
		return "", fmt.Errorf("this run has no counterparty")
	}
	return env.CounterpartyURL + "/scenarios/" + id, nil
}

// refusal decides a counterparty scenario from the wallet's answer: rejected
// when the wallet refused with HTTP 400 and an error_description naming this
// row's check (text); accepted when it completed the import regardless; any
// other answer is an error, because it does not show this requirement.
func refusal(result *capture.WalletResult, text string) (conformance.ArtefactOutcome, error) {
	switch {
	case result.Status == http.StatusBadRequest && strings.Contains(result.ErrorDescription(), text):
		return conformance.OutcomeRejected, nil
	case result.Status == http.StatusOK && result.Error() == "":
		return conformance.OutcomeAccepted, nil
	default:
		return "", fmt.Errorf("wallet answered %s; want a refusal naming %q", refusalText(result), text)
	}
}

// wellKnownURL inserts /.well-known/<name> between the host and path of an
// identifier, as OID4VCI 1.0 Section 12.2.2 and RFC 8414 Section 3.1 do.
func wellKnownURL(identifier, name string) (string, error) {
	parsed, err := url.Parse(identifier)
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("identifier %q has no scheme or host", identifier)
	}
	return parsed.Scheme + "://" + parsed.Host + "/.well-known/" + name + parsed.EscapedPath(), nil
}

// stringField reads a string member of a JSON object.
func stringField(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}

func keys(object map[string]any) []string {
	out := make([]string, 0, len(object))
	for key := range object {
		out = append(out, key)
	}
	return out
}
