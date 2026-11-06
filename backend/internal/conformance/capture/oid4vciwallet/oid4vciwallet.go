// Package oid4vciwallet captures the hosted wallet's side of the OpenID4VCI
// 1.0 requirements outside the HAIP profile: the conformance client calls the
// wallet's API, and the wallet's own hops to the production issuer, or to the
// conformance counterparty it refuses, join the artefact.
package oid4vciwallet

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
)

func init() {
	capture.Register("CI-005", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "proofs-single-jwt-array",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. The wallet's Credential Request to /oid4vci/credential carries proofs as an object with the single member jwt holding a non-empty array of key proofs, and the issuer answers 200.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         proofsShape,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet always sends proofs as an object whose single member jwt holds a non-empty array, so it never sends a Credential Request with another proofs shape.",
		},
	})
	capture.Register("CI-010", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "credentials-array-stored",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. The issuer's immediate Credential Response is HTTP 200 with a non-empty credentials array of objects, and the wallet stores the Credential it finds there.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         credentialsArray,
		},
		Failing: &capture.Scenario{
			Name:        "empty-credentials-array",
			Description: "The conformance client hands the hosted wallet an offer from the conformance counterparty, whose Credential Endpoint answers HTTP 200 with an empty credentials array. The wallet refuses the response instead of treating the issuance as complete.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run:         emptyCredentialsArray,
		},
	})
	capture.Register("CI-011", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "credential-accepted-notification",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. After storing the Credential, the wallet POSTs the notification_id from the Credential Response to /oid4vci/notification with event credential_accepted, under the same Access Token.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         acceptedNotification,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet sends credential_accepted whenever the Credential Response carries a notification_id and the metadata advertises a notification_endpoint, so no exchange shows it skipping the report.",
		},
	})
	capture.Register("CI-013", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "single-jwk-key-reference",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. Every proof in the wallet's Credential Request names its key with jwk alone, with no kid or x5c, and carries no cnf. The proof's iss follows the Token Request: when the wallet redeemed the code as a client, as the hosted wallet does with its client attestation, iss is that client_id; when it redeemed the code without a client_id, iss is omitted.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         anonymousProofKeyReference,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet names its proof key only by jwk and sets iss to its client_id only when its Token Request carried one, so it never sends a proof that breaks this rule.",
		},
	})
	capture.Register("CW-001", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "offer-by-reference",
			Description: "The conformance client hands the hosted wallet an openid-credential-offer:// link whose only parameter is credential_offer_uri. The wallet fetches the offer from the production issuer and completes the issuance.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         offerByReference,
		},
		Failing: &capture.Scenario{
			Name:        "offer-by-value-and-by-reference",
			Description: "The conformance client fetches a real Credential Offer from the production issuer, then hands the hosted wallet a link carrying that offer as credential_offer and its URL as credential_offer_uri at once. The wallet refuses the link before fetching anything.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run:         offerByValueAndReference,
		},
	})
	capture.Register("CW-006", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "tx-code-in-token-request",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer whose grant carries a tx_code object, with the Transaction Code the production issuer delivered out of band. The wallet's Token Request to /oid4vci/token carries that code as tx_code.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         txCodeSent,
		},
		Failing: &capture.Scenario{
			Name:        "empty-tx-code-object-without-code",
			Description: "The conformance client hands the hosted wallet an offer from the conformance counterparty whose pre-authorized grant carries an empty tx_code object, and supplies no Transaction Code. The wallet stops before any Token Request rather than send one without tx_code.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run:         emptyTxCodeObject,
		},
	})
	capture.Register("CW-010", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "offer-issuer-validated-from-metadata",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. The wallet fetches the Credential Issuer Metadata at the well-known location of the offered credential_issuer, requires its credential_issuer to name that identifier, fetches the Authorization Server Metadata it lists, and takes the offered configuration from the metadata, as it does for a wallet-initiated flow.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         offerValidatedAgainstMetadata,
		},
		Failing: &capture.Scenario{
			Name:        "unlisted-authorization-server-hint",
			Description: "The conformance client hands the hosted wallet an offer from the conformance counterparty whose pre-authorized grant names an authorization_server that the issuer's metadata does not list. The wallet fetches the metadata, finds no match and stops.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run:         unlistedAuthorizationServer,
		},
	})
	capture.Register("CW-020", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "well-known-inserted-after-host",
			Description: "The conformance client gives the hosted wallet the production Credential Issuer Identifier alone. The wallet GETs the metadata from the identifier with /.well-known/openid-credential-issuer inserted between its host and path, and answers with the configurations to choose from.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         wellKnownInserted,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet builds the metadata URL only by inserting /.well-known/openid-credential-issuer between host and path, so it never requests metadata from another location.",
		},
	})
	capture.Register("CW-024", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "credential-issuer-identical",
			Description: "The conformance client gives the hosted wallet the production Credential Issuer Identifier alone. The metadata the wallet fetches carries a credential_issuer identical to that identifier, and the wallet uses it.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         credentialIssuerIdentical,
		},
		Failing: &capture.Scenario{
			Name:        "credential-issuer-trailing-slash",
			Description: "The conformance client gives the hosted wallet a conformance counterparty issuer identifier whose metadata names a credential_issuer differing from it only by a trailing slash. The wallet compares the two strings without normalisation and uses nothing from the metadata.",
			Actor:       conformance.ActorCounterparty,
			Expected:    conformance.OutcomeRejected,
			Run:         credentialIssuerTrailingSlash,
		},
	})
	capture.Register("CW-044", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "The production issuer returns credential_identifiers only for an authorization_details request, which the hosted wallet sends only in the authorization_code flow; that flow needs an End-User login at the Mock IdP, and the wallet's authorization callback records none of its Token or Credential Requests.",
			conformance.KindFailing: "When a Token Response returns credential_identifiers the hosted wallet requests by credential_identifier, so it never sends a Credential Request that ignores them.",
		},
	})
	capture.Register("CW-065", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "proof-typ-alg-aud-iat-nonce",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. The wallet obtains a c_nonce from /oid4vci/nonce, and every proof in its Credential Request has typ openid4vci-proof+jwt, an asymmetric alg, aud equal to the Credential Issuer Identifier, iat, that nonce and a single jwk key reference.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         proofClaims,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet builds every proof with typ openid4vci-proof+jwt, an asymmetric alg, aud, iat, the c_nonce and only a jwk header, so it never sends a proof missing these.",
		},
	})
	capture.Register("CW-070", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "configuration-id-without-identifiers",
			Description: "The conformance client hands the hosted wallet a pre-authorized Credential Offer from the production issuer. The Token Response returns no authorization_details, and the wallet's Credential Request carries credential_configuration_id and no credential_identifier.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         configurationSelector,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet puts exactly one selector in each Credential Request, chosen from the Token Response, so it never sends both or the wrong one.",
		},
	})
	capture.Register("CW-081", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "deferred-poll-after-interval",
			Description: "The conformance client hands the hosted wallet a pre-authorized offer the production issuer answers with HTTP 202, a transaction_id and an interval. The wallet waits the interval, then POSTs the transaction_id to /oid4vci/deferred_credential with the Access Token it used at the Credential Endpoint; the issuer, which answers 202 again to any earlier poll, returns the Credential.",
			Actor:       conformance.ActorHostedWallet,
			Expected:    conformance.OutcomeAccepted,
			Run:         deferredPoll,
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "The hosted wallet waits interval seconds and presents the Access Token it used at the Credential Endpoint, so it sends no Deferred Credential Request that could show otherwise.",
		},
	})
	capture.Register("CW-089", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "The production issuer returns a refresh_token on the authorization_code grant only, which needs an End-User login at the Mock IdP that the capture cannot perform, and the hosted wallet's authorization callback records none of its hops, so no recorded exchange shows a Credential refreshed with a Refresh Token.",
			conformance.KindFailing: "The hosted wallet keeps every refresh_token a Token Response carries and redeems it at the Token Endpoint on /api/refresh, so it never discards a Refresh Token or refreshes without one.",
		},
	})
	capture.Register("CW-100", capture.Entry{
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindPassing: "Credential storage happens inside the wallet process; no protocol message carries it.",
			conformance.KindFailing: "Credential storage happens inside the wallet process; no protocol message carries it.",
		},
	})
}

// proofsShape is CI-005 passing: proofs is {"jwt": [<one or more proofs>]}.
func proofsShape(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	hop, err := requireHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	request, err := requestJSON(hop)
	if err != nil {
		return "", err
	}
	if _, err := jwtProofs(request); err != nil {
		return "", err
	}
	if hop.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("credential endpoint answered %d to the wallet", hop.ResponseStatus)
	}
	return conformance.OutcomeAccepted, nil
}

// credentialsArray is CI-010 passing: the 200 Credential Response has a
// non-empty credentials array of objects, and the wallet stored from it.
func credentialsArray(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	hop, err := requireHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	if hop.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("credential endpoint answered %d to the wallet", hop.ResponseStatus)
	}
	response, err := responseJSON(hop)
	if err != nil {
		return "", err
	}
	issued, err := capture.IssuedCredentials(response)
	if err != nil {
		return "", err
	}
	stored, _ := result.Body["credential_jwt"].(string)
	for _, credential := range issued {
		if credential == stored {
			return conformance.OutcomeAccepted, nil
		}
	}
	return "", fmt.Errorf("the wallet stored a credential_jwt that is not one of the %d credentials entries", len(issued))
}

// emptyCredentialsArray is CI-010 failing: the counterparty's Credential
// Endpoint answers 200 {"credentials":[]}.
func emptyCredentialsArray(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	issuer, err := counterpartyScenario(env, "ci-010")
	if err != nil {
		return "", err
	}
	result, err := importOffer(ctx, env, offerLink(issuer+"/credential-offer"), "")
	if err != nil {
		return "", err
	}
	hop, err := requireHop(result, stepCredential)
	if err != nil {
		return "", fmt.Errorf("%w; wallet answered %s", err, refusalText(result))
	}
	if hop.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("counterparty credential endpoint answered %d, want 200 with an empty credentials array", hop.ResponseStatus)
	}
	return refusal(result, "credential response credentials must be a non-empty array")
}

// acceptedNotification is CI-011 passing: the wallet reports
// credential_accepted for the notification_id it received.
func acceptedNotification(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	credential, err := requireHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	response, err := responseJSON(credential)
	if err != nil {
		return "", err
	}
	notificationID := stringField(response, "notification_id")
	if notificationID == "" {
		return "", fmt.Errorf("the credential response carries no notification_id")
	}
	notification, err := requireHop(result, stepNotification)
	if err != nil {
		return "", err
	}
	request, err := requestJSON(notification)
	if err != nil {
		return "", err
	}
	if got := stringField(request, "notification_id"); got != notificationID {
		return "", fmt.Errorf("notification names notification_id %q, want %q", got, notificationID)
	}
	if event := stringField(request, "event"); event != "credential_accepted" {
		return "", fmt.Errorf("notification event is %q, want credential_accepted", event)
	}
	if notification.RequestHeaders["Authorization"] == "" || notification.RequestHeaders["Authorization"] != credential.RequestHeaders["Authorization"] {
		return "", fmt.Errorf("the notification does not carry the Access Token the Credential Request used")
	}
	if notification.ResponseStatus < 200 || notification.ResponseStatus > 299 {
		return "", fmt.Errorf("notification endpoint answered %d to the wallet", notification.ResponseStatus)
	}
	return conformance.OutcomeAccepted, nil
}

// anonymousProofKeyReference is CI-013 passing: jwk alone names the key, and
// iss follows the Token Request. OpenID4VCI 1.0 Appendix F.1: "The value of
// this claim MUST be the client_id of the Client making the Credential
// request. This claim MUST be omitted if the access token authorizing the
// issuance call was obtained from a Pre-Authorized Code Flow through
// anonymous access to the token endpoint."
func anonymousProofKeyReference(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	token, err := requireHop(result, stepToken)
	if err != nil {
		return "", err
	}
	form, err := requestForm(token)
	if err != nil {
		return "", err
	}
	clientID := form.Get("client_id")
	proofs, err := credentialRequestProofs(result)
	if err != nil {
		return "", err
	}
	for i, p := range proofs {
		if refs := p.keyReferences(); len(refs) != 1 || refs[0] != "jwk" {
			return "", fmt.Errorf("proofs.jwt[%d] header key references are %v, want jwk alone", i, refs)
		}
		if _, present := p.Claims["cnf"]; present {
			return "", fmt.Errorf("proofs.jwt[%d] carries cnf", i)
		}
		iss, present := p.Claims["iss"]
		switch {
		case clientID == "" && present:
			return "", fmt.Errorf("proofs.jwt[%d] carries iss %v although the Token Request had no client_id", i, iss)
		case clientID != "" && iss != clientID:
			return "", fmt.Errorf("proofs.jwt[%d] iss is %v, want the Token Request's client_id %q", i, iss, clientID)
		}
	}
	return conformance.OutcomeAccepted, nil
}

// offerByReference is CW-001 passing: a link with credential_offer_uri alone
// is fetched and the issuance completes.
func offerByReference(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, created, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	hop, err := requireHop(result, stepCredentialOffer)
	if err != nil {
		return "", err
	}
	if hop.Method != http.MethodGet || hop.URL != created.URI {
		return "", fmt.Errorf("the wallet fetched %s %s, want GET %s", hop.Method, hop.URL, created.URI)
	}
	if hop.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("credential_offer_uri answered %d to the wallet", hop.ResponseStatus)
	}
	return conformance.OutcomeAccepted, nil
}

// offerByValueAndReference is CW-001 failing: the same real offer by value
// and by reference in one link.
func offerByValueAndReference(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	created, err := createOffer(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	offerJSON, err := fetchOffer(ctx, env, created.URI)
	if err != nil {
		return "", err
	}
	link := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)) +
		"&credential_offer_uri=" + url.QueryEscape(created.URI)
	result, err := importOffer(ctx, env, link, "")
	if err != nil {
		return "", err
	}
	if len(result.Hops) > 0 && result.Status != http.StatusOK {
		return "", fmt.Errorf("the wallet made %d hops before refusing: %s", len(result.Hops), refusalText(result))
	}
	return refusal(result, "credential_offer and credential_offer_uri cannot both be present")
}

// txCodeSent is CW-006 passing: the Token Request carries the out-of-band
// Transaction Code when the offer's grant had a tx_code object.
func txCodeSent(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, created, err := issuedImport(ctx, env, capture.OfferOptions{TxCode: true})
	if err != nil {
		return "", err
	}
	offerHop, err := requireHop(result, stepCredentialOffer)
	if err != nil {
		return "", err
	}
	offered, err := responseJSON(offerHop)
	if err != nil {
		return "", err
	}
	if _, ok := preAuthorizedGrantOf(offered)["tx_code"].(map[string]any); !ok {
		return "", fmt.Errorf("the fetched offer's pre-authorized grant carries no tx_code object")
	}
	token, err := requireHop(result, stepToken)
	if err != nil {
		return "", err
	}
	form, err := requestForm(token)
	if err != nil {
		return "", err
	}
	if got := form.Get("tx_code"); got != created.TxCode {
		return "", fmt.Errorf("the Token Request carries tx_code %q, want the out-of-band code", got)
	}
	if token.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("token endpoint answered %d to the wallet", token.ResponseStatus)
	}
	return conformance.OutcomeAccepted, nil
}

// emptyTxCodeObject is CW-006 failing: the counterparty's grant has
// "tx_code": {} and no code is supplied.
func emptyTxCodeObject(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	issuer, err := counterpartyScenario(env, "cw-006")
	if err != nil {
		return "", err
	}
	result, err := importOffer(ctx, env, offerLink(issuer+"/credential-offer"), "")
	if err != nil {
		return "", err
	}
	if _, err := requireHop(result, stepCredentialOffer); err != nil {
		return "", fmt.Errorf("%w; wallet answered %s", err, refusalText(result))
	}
	if result.Hop(stepToken) != nil {
		return "", fmt.Errorf("the wallet sent a Token Request although no Transaction Code was supplied")
	}
	return refusal(result, "tx_code is required when tx_code object is present in credential offer")
}

// offerValidatedAgainstMetadata is CW-010 passing: every value the wallet
// relies on comes from metadata fetched for the offered identifier.
func offerValidatedAgainstMetadata(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	offerHop, err := requireHop(result, stepCredentialOffer)
	if err != nil {
		return "", err
	}
	offered, err := responseJSON(offerHop)
	if err != nil {
		return "", err
	}
	offeredIssuer := stringField(offered, "credential_issuer")
	if offeredIssuer == "" {
		return "", fmt.Errorf("the fetched offer names no credential_issuer")
	}
	metadataHop, err := requireHop(result, stepIssuerMetadata)
	if err != nil {
		return "", err
	}
	wantURL, err := wellKnownURL(offeredIssuer, "openid-credential-issuer")
	if err != nil {
		return "", err
	}
	if metadataHop.Method != http.MethodGet || metadataHop.URL != wantURL {
		return "", fmt.Errorf("the wallet fetched metadata with %s %s, want GET %s", metadataHop.Method, metadataHop.URL, wantURL)
	}
	metadata, err := responseJSON(metadataHop)
	if err != nil {
		return "", err
	}
	if got := stringField(metadata, "credential_issuer"); got != offeredIssuer {
		return "", fmt.Errorf("metadata credential_issuer %q differs from the offered %q", got, offeredIssuer)
	}
	configurations, _ := metadata["credential_configurations_supported"].(map[string]any)
	offeredIDs, _ := offered["credential_configuration_ids"].([]any)
	for _, raw := range offeredIDs {
		id, _ := raw.(string)
		if _, described := configurations[id]; !described {
			return "", fmt.Errorf("offered configuration %q is not described by the metadata", id)
		}
	}
	authorizationServer := offeredIssuer
	if listed, _ := metadata["authorization_servers"].([]any); len(listed) > 0 {
		authorizationServer, _ = listed[0].(string)
	}
	asHop, err := requireHop(result, stepASMetadata)
	if err != nil {
		return "", err
	}
	asMetadata, err := responseJSON(asHop)
	if err != nil {
		return "", err
	}
	if got := stringField(asMetadata, "issuer"); got != authorizationServer {
		return "", fmt.Errorf("authorization server metadata issuer %q differs from the server %q the metadata lists", got, authorizationServer)
	}
	return conformance.OutcomeAccepted, nil
}

// unlistedAuthorizationServer is CW-010 failing: the offer's
// authorization_server hint is not in the metadata's authorization_servers.
func unlistedAuthorizationServer(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	issuer, err := counterpartyScenario(env, "cw-010")
	if err != nil {
		return "", err
	}
	result, err := importOffer(ctx, env, offerLink(issuer+"/credential-offer"), "")
	if err != nil {
		return "", err
	}
	if _, err := requireHop(result, stepIssuerMetadata); err != nil {
		return "", fmt.Errorf("%w; wallet answered %s", err, refusalText(result))
	}
	return refusal(result, "does not match any authorization_servers entry in the Credential Issuer metadata")
}

// wellKnownInserted is CW-020 passing: wallet-initiated discovery GETs the
// inserted well-known URL.
func wellKnownInserted(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, hop, err := productionDiscovery(ctx, env)
	if err != nil {
		return "", err
	}
	want := capture.IssuerMetadataURL(env)
	if hop.Method != http.MethodGet || hop.URL != want {
		return "", fmt.Errorf("the wallet fetched metadata with %s %s, want GET %s", hop.Method, hop.URL, want)
	}
	if !strings.Contains(hop.RequestHeaders["Accept"], "application/json") {
		return "", fmt.Errorf("the metadata request Accept header is %q", hop.RequestHeaders["Accept"])
	}
	if hop.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("metadata endpoint answered %d to the wallet", hop.ResponseStatus)
	}
	if selection, _ := result.Body["configuration_selection_required"].(bool); !selection {
		return "", fmt.Errorf("the wallet did not offer the discovered configurations for selection")
	}
	return conformance.OutcomeAccepted, nil
}

// credentialIssuerIdentical is CW-024 passing: the metadata's
// credential_issuer is character for character the identifier fetched for.
func credentialIssuerIdentical(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, hop, err := productionDiscovery(ctx, env)
	if err != nil {
		return "", err
	}
	metadata, err := responseJSON(hop)
	if err != nil {
		return "", err
	}
	identifier := productionIssuer(env)
	if got := stringField(metadata, "credential_issuer"); got != identifier {
		return "", fmt.Errorf("metadata credential_issuer %q is not the identifier %q", got, identifier)
	}
	if got := stringField(result.Body, "credential_issuer"); got != identifier {
		return "", fmt.Errorf("the wallet reports credential_issuer %q, want %q", got, identifier)
	}
	return conformance.OutcomeAccepted, nil
}

// credentialIssuerTrailingSlash is CW-024 failing: the counterparty's
// metadata names the identifier with a trailing slash.
func credentialIssuerTrailingSlash(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	issuer, err := counterpartyScenario(env, "cw-024")
	if err != nil {
		return "", err
	}
	result, err := discoverIssuer(ctx, env, issuer)
	if err != nil {
		return "", err
	}
	hop, err := requireHop(result, stepIssuerMetadata)
	if err != nil {
		return "", fmt.Errorf("%w; wallet answered %s", err, refusalText(result))
	}
	if hop.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("counterparty metadata endpoint answered %d", hop.ResponseStatus)
	}
	return refusal(result, fmt.Sprintf("metadata credential_issuer %q does not match offer %q", issuer+"/", issuer))
}

// proofClaims is CW-065 passing: typ, alg, aud, iat, nonce and one key
// reference in every proof.
func proofClaims(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	metadataHop, err := requireHop(result, stepIssuerMetadata)
	if err != nil {
		return "", err
	}
	metadata, err := responseJSON(metadataHop)
	if err != nil {
		return "", err
	}
	issuer := stringField(metadata, "credential_issuer")
	nonceHop, err := requireHop(result, stepNonce)
	if err != nil {
		return "", err
	}
	nonceResponse, err := responseJSON(nonceHop)
	if err != nil {
		return "", err
	}
	cNonce := stringField(nonceResponse, "c_nonce")
	if cNonce == "" {
		return "", fmt.Errorf("the nonce response carries no c_nonce")
	}
	proofs, err := credentialRequestProofs(result)
	if err != nil {
		return "", err
	}
	for i, p := range proofs {
		if typ := stringField(p.Header, "typ"); typ != "openid4vci-proof+jwt" {
			return "", fmt.Errorf("proofs.jwt[%d] typ is %q", i, typ)
		}
		alg := stringField(p.Header, "alg")
		if alg == "" || strings.EqualFold(alg, "none") || strings.HasPrefix(strings.ToUpper(alg), "HS") {
			return "", fmt.Errorf("proofs.jwt[%d] alg is %q", i, alg)
		}
		if refs := p.keyReferences(); len(refs) != 1 {
			return "", fmt.Errorf("proofs.jwt[%d] header key references are %v, want exactly one", i, refs)
		}
		if aud := stringField(p.Claims, "aud"); aud != issuer {
			return "", fmt.Errorf("proofs.jwt[%d] aud is %q, want the Credential Issuer Identifier %q", i, aud, issuer)
		}
		if _, ok := p.Claims["iat"].(float64); !ok {
			return "", fmt.Errorf("proofs.jwt[%d] has no numeric iat", i)
		}
		if nonce := stringField(p.Claims, "nonce"); nonce != cNonce {
			return "", fmt.Errorf("proofs.jwt[%d] nonce is %q, want the c_nonce %q", i, nonce, cNonce)
		}
	}
	return conformance.OutcomeAccepted, nil
}

// configurationSelector is CW-070 passing: with no credential_identifiers
// returned, the request carries credential_configuration_id alone.
func configurationSelector(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{})
	if err != nil {
		return "", err
	}
	token, err := requireHop(result, stepToken)
	if err != nil {
		return "", err
	}
	tokenResponse, err := responseJSON(token)
	if err != nil {
		return "", err
	}
	if _, returned := tokenResponse["authorization_details"]; returned {
		return "", fmt.Errorf("the Token Response returned authorization_details, so this run does not show the configuration-id case")
	}
	credential, err := requireHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	request, err := requestJSON(credential)
	if err != nil {
		return "", err
	}
	if got := stringField(request, "credential_configuration_id"); got != capture.IssuedConfiguration {
		return "", fmt.Errorf("credential request credential_configuration_id is %q, want %q", got, capture.IssuedConfiguration)
	}
	if _, present := request["credential_identifier"]; present {
		return "", fmt.Errorf("credential request carries credential_identifier although none was returned")
	}
	return conformance.OutcomeAccepted, nil
}

// deferredPoll is CW-081 passing: a first poll answered 200 after a 202 shows
// the wait, and it carries the Credential Request's Access Token.
func deferredPoll(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
	result, _, err := issuedImport(ctx, env, capture.OfferOptions{Deferred: true})
	if err != nil {
		return "", err
	}
	credential, err := requireHop(result, stepCredential)
	if err != nil {
		return "", err
	}
	if credential.ResponseStatus != http.StatusAccepted {
		return "", fmt.Errorf("credential endpoint answered %d, want 202 for a deferred issuance", credential.ResponseStatus)
	}
	deferred, err := responseJSON(credential)
	if err != nil {
		return "", err
	}
	transactionID := stringField(deferred, "transaction_id")
	interval, _ := deferred["interval"].(float64)
	if transactionID == "" || interval <= 0 {
		return "", fmt.Errorf("the 202 response lacks transaction_id or a positive interval: %s", capture.Truncate([]byte(credential.ResponseBody)))
	}
	poll, err := requireHop(result, stepDeferredPoll)
	if err != nil {
		return "", err
	}
	pollRequest, err := requestJSON(poll)
	if err != nil {
		return "", err
	}
	if got := stringField(pollRequest, "transaction_id"); got != transactionID {
		return "", fmt.Errorf("the deferred poll names transaction_id %q, want %q", got, transactionID)
	}
	if poll.RequestHeaders["Authorization"] == "" || poll.RequestHeaders["Authorization"] != credential.RequestHeaders["Authorization"] {
		return "", fmt.Errorf("the deferred poll does not carry the Access Token the Credential Request used")
	}
	if poll.ResponseStatus != http.StatusOK {
		return "", fmt.Errorf("the first deferred poll was answered %d, so the wallet polled before the Credential was ready", poll.ResponseStatus)
	}
	pollResponse, err := responseJSON(poll)
	if err != nil {
		return "", err
	}
	if _, err := capture.IssuedCredentials(pollResponse); err != nil {
		return "", err
	}
	return conformance.OutcomeAccepted, nil
}

// credentialRequestProofs decodes the proofs of the wallet's Credential Request.
func credentialRequestProofs(result *capture.WalletResult) ([]proof, error) {
	hop, err := requireHop(result, stepCredential)
	if err != nil {
		return nil, err
	}
	request, err := requestJSON(hop)
	if err != nil {
		return nil, err
	}
	compacts, err := jwtProofs(request)
	if err != nil {
		return nil, err
	}
	return decodeProofs(compacts)
}

// preAuthorizedGrantOf returns the pre-authorized grant object of an offer.
func preAuthorizedGrantOf(offered map[string]any) map[string]any {
	grants, _ := offered["grants"].(map[string]any)
	grant, _ := grants[preAuthorizedGrant].(map[string]any)
	return grant
}

// productionIssuer is the production Credential Issuer Identifier.
func productionIssuer(env *capture.Env) string {
	return env.BaseURL + "/oid4vci"
}

// productionDiscovery runs wallet-initiated discovery of the production
// issuer and returns the wallet's answer with its metadata hop.
func productionDiscovery(ctx context.Context, env *capture.Env) (*capture.WalletResult, *capture.WalletHop, error) {
	result, err := discoverIssuer(ctx, env, productionIssuer(env))
	if err != nil {
		return nil, nil, err
	}
	if result.Status != http.StatusOK {
		return nil, nil, fmt.Errorf("wallet answered %s", refusalText(result))
	}
	hop, err := requireHop(result, stepIssuerMetadata)
	if err != nil {
		return nil, nil, err
	}
	return result, hop, nil
}
