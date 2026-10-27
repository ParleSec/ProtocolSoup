package rfc9449

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/conformance/capture"
	"github.com/golang-jwt/jwt/v5"
)

// iatOffset puts a proof's iat well outside the server's 60-second
// freshness window, with room for clock difference between the capture
// runner and the server.
const iatOffset = 5 * time.Minute

func init() {
	capture.Register("DP-001", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "one-dpop-header",
			Description: "The conformance client requests a client_credentials token from /oauth2/token with exactly one DPoP header field, answering a use_dpop_nonce challenge if the server issues one.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return dpopTokenRequest(ctx, env, 1)
			},
		},
		Failing: &capture.Scenario{
			Name:        "two-dpop-headers",
			Description: "The conformance client sends the same token request with two DPoP header fields, each carrying a valid proof.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return dpopTokenRequest(ctx, env, 2)
			},
		},
	})

	capture.Register("DP-002", capture.Entry{
		Passing: conformantTokenScenario("all-required-claims",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof whose payload carries jti, htm, htu and iat, plus the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("missing-required-claim",
			"The conformance client sends four client_credentials token requests to /oauth2/token, each with a correctly signed DPoP proof that carries the server-provided nonce but omits one of jti, htm, htu and iat.",
			withoutClaim("jti"), withoutClaim("htm"), withoutClaim("htu"), withoutClaim("iat")),
	})

	capture.Register("DP-003", capture.Entry{
		Passing: conformantTokenScenario("typ-dpop-jwt",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof whose JOSE header typ is dpop+jwt. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("typ-not-dpop-jwt",
			"The conformance client sends two client_credentials token requests to /oauth2/token with otherwise valid DPoP proofs, the first with the JOSE header typ set to JWT and the second with no typ header parameter.",
			withHeader("typ", "JWT"), withHeader("typ", nil)),
	})

	capture.Register("DP-004", capture.Entry{
		Passing: conformantTokenScenario("alg-es256",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof signed with ES256, one of the algorithms the server lists in dpop_signing_alg_values_supported. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("alg-none-mac-or-unlisted",
			"The conformance client sends three client_credentials token requests to /oauth2/token: one with an unsigned proof whose alg is none, one with a proof whose alg is HS256 and whose MAC uses a secret only the client holds, and one signed with ES384, a registered asymmetric algorithm the server does not list in dpop_signing_alg_values_supported.",
			algNone, algHS256, algES384),
	})

	capture.Register("DP-005", capture.Entry{
		Passing: conformantTokenScenario("signed-by-jwk-key",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof signed by the private key that matches the public key in its jwk header. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("signed-by-other-key",
			"The conformance client sends a client_credentials token request to /oauth2/token with a DPoP proof whose jwk header carries one P-256 public key but whose signature was made with a different P-256 private key.",
			signedByOtherKey),
	})

	capture.Register("DP-006", capture.Entry{
		Passing: conformantTokenScenario("public-jwk",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof whose jwk header carries only the public members kty, crv, x and y. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("jwk-with-private-d",
			"The conformance client sends a client_credentials token request to /oauth2/token with a DPoP proof whose jwk header also carries the private member d. The key was generated for this request alone, and the proof is correctly signed with it.",
			privateJWK),
	})

	capture.Register("DP-007", capture.Entry{
		Passing: conformantTokenScenario("htm-post",
			"The conformance client POSTs a client_credentials token request to /oauth2/token with a DPoP proof whose htm is POST. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("htm-mismatch",
			"The conformance client POSTs two client_credentials token requests to /oauth2/token with otherwise valid DPoP proofs, the first with htm GET and the second with htm post in lower case.",
			withClaim("htm", http.MethodGet), withClaim("htm", "post")),
	})

	capture.Register("DP-008", capture.Entry{
		Passing: conformantTokenScenario("htu-token-endpoint",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof whose htu is the token endpoint URI. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("htu-other-endpoint",
			"The conformance client sends a client_credentials token request to /oauth2/token with an otherwise valid DPoP proof whose htu names /oauth2/introspect on the same server.",
			htuOtherEndpoint),
	})

	capture.Register("DP-009", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "server-provided-nonce",
			Description: "The conformance client sends a client_credentials token request to /oauth2/token with a DPoP proof that has no nonce claim, receives a use_dpop_nonce error with a DPoP-Nonce header, and retries with a new proof whose nonce claim is that value.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return tokenNonce(ctx, env, presentIssuedNonce)
			},
		},
		Failing: &capture.Scenario{
			Name:        "nonce-mismatch",
			Description: "After receiving a DPoP-Nonce from /oauth2/token in a use_dpop_nonce error, the conformance client sends two more client_credentials token requests: one whose proof carries a nonce value the server never issued, and one whose proof has no nonce claim.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return tokenNonce(ctx, env, presentOtherNonce)
			},
		},
	})

	capture.Register("DP-010", capture.Entry{
		Passing: conformantTokenScenario("iat-now",
			"The conformance client requests a client_credentials token from /oauth2/token with a DPoP proof whose iat is the current time. The proof carries the nonce the token endpoint issued in an earlier use_dpop_nonce challenge."),
		Failing: brokenTokenScenario("iat-outside-window",
			"The conformance client sends two client_credentials token requests to /oauth2/token with otherwise valid DPoP proofs, one whose iat is five minutes in the past and one whose iat is five minutes in the future, both outside the server's 60-second window.",
			withClaim("iat", func() any { return time.Now().Add(-iatOffset).Unix() }),
			withClaim("iat", func() any { return time.Now().Add(iatOffset).Unix() })),
	})

	capture.Register("DP-011", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "ath-matches-token",
			Description: "The conformance client presents a DPoP-bound access token to GET /oauth2/resource with Authorization: DPoP and a DPoP proof whose ath is the base64url-encoded SHA-256 hash of that token. The proof carries the nonce the resource issued in an earlier use_dpop_nonce challenge.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return resourceATH(ctx, env, false)
			},
		},
		Failing: &capture.Scenario{
			Name:        "ath-mismatch",
			Description: "The conformance client presents a DPoP-bound access token to GET /oauth2/resource twice, each time with a proof signed by the token's own key and carrying the resource's DPoP-Nonce: one whose ath is the hash of a second access token bound to the same key, and one with no ath claim.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeRejected,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return resourceATH(ctx, env, true)
			},
		},
	})

	capture.Register("DP-012", capture.Entry{
		Passing: &capture.Scenario{
			Name:        "nonce-within-lifetime",
			Description: "The conformance client receives a DPoP-Nonce from /oauth2/token in a use_dpop_nonce error, then sends two client_credentials token requests whose proofs carry that nonce, both well within its five-minute lifetime.",
			Actor:       conformance.ActorConformanceClient,
			Expected:    conformance.OutcomeAccepted,
			Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
				return tokenNonce(ctx, env, reuseIssuedNonce)
			},
		},
		Unavailable: map[conformance.ArtefactKind]string{
			conformance.KindFailing: "A nonce can only be shown being refused after the server has dropped it, which takes up to 15 minutes from issue, longer than a capture run waits, and a failed random read inside the server cannot be caused over HTTP.",
		},
	})
}

// tokenClient is the demo machine-client calling the token endpoint.
type tokenClient struct {
	id, secret, endpoint string
}

func newTokenClient(ctx context.Context, env *capture.Env) (*tokenClient, error) {
	id, secret, endpoint, err := capture.MachineClient(ctx, env)
	if err != nil {
		return nil, err
	}
	return &tokenClient{id: id, secret: secret, endpoint: endpoint}, nil
}

// request is a client_credentials token request with one DPoP header field
// per proof.
func (c *tokenClient) request(proofs ...string) (*http.Request, error) {
	req, err := capture.NewForm(c.endpoint, url.Values{"grant_type": {"client_credentials"}})
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.id, c.secret)
	if len(proofs) > 0 {
		req.Header["DPoP"] = proofs
	}
	return req, nil
}

// conformantProof is a valid ES256 proof for this token endpoint.
func (c *tokenClient) conformantProof(key *proofKey, nonce string) (string, error) {
	spec, err := newProofSpec(key, http.MethodPost, c.endpoint, nonce, "")
	if err != nil {
		return "", err
	}
	return spec.signES256(key)
}

// serverNonce asks the token endpoint for its current DPoP-Nonce with an
// unrecorded request carrying a valid proof without a nonce claim. The
// endpoint challenges before it records the proof's jti, so the request
// consumes nothing. It returns "" when the endpoint issues no nonces.
func (c *tokenClient) serverNonce(ctx context.Context, env *capture.Env, key *proofKey) (string, error) {
	proof, err := c.conformantProof(key, "")
	if err != nil {
		return "", err
	}
	req, err := c.request(proof)
	if err != nil {
		return "", err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", err
	}
	switch {
	case resp.Status == http.StatusBadRequest && resp.Error() == "use_dpop_nonce":
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce == "" {
			return "", fmt.Errorf("use_dpop_nonce without a DPoP-Nonce header")
		}
		return nonce, nil
	case resp.Status == http.StatusOK:
		_, err := c.retire(ctx, env, resp)
		return "", err
	default:
		return "", fmt.Errorf("token endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// boundToken obtains, without recording, an access token bound to key.
// The caller retires it with retireToken.
func (c *tokenClient) boundToken(ctx context.Context, env *capture.Env, key *proofKey) (token string, expiresIn time.Duration, err error) {
	nonce, err := c.serverNonce(ctx, env, key)
	if err != nil {
		return "", 0, err
	}
	proof, err := c.conformantProof(key, nonce)
	if err != nil {
		return "", 0, err
	}
	req, err := c.request(proof)
	if err != nil {
		return "", 0, err
	}
	resp, err := env.Setup(ctx, req)
	if err != nil {
		return "", 0, err
	}
	if resp.Status != http.StatusOK {
		return "", 0, fmt.Errorf("token endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
	return dpopToken(resp)
}

// dpopToken reads a DPoP token response (RFC 9449 Section 5).
func dpopToken(resp *capture.Response) (string, time.Duration, error) {
	body, err := resp.JSON()
	if err != nil {
		return "", 0, err
	}
	if body["token_type"] != "DPoP" {
		return "", 0, fmt.Errorf("token_type %v, want DPoP", body["token_type"])
	}
	token, _ := body["access_token"].(string)
	expiresIn, _ := body["expires_in"].(float64)
	return token, time.Duration(expiresIn) * time.Second, nil
}

// retire revokes the token in a 200 token response, so the artefact never
// publishes a usable token.
func (c *tokenClient) retire(ctx context.Context, env *capture.Env, resp *capture.Response) (string, error) {
	token, expiresIn, err := dpopToken(resp)
	if err != nil {
		return "", err
	}
	c.retireToken(ctx, env, token, expiresIn)
	return token, nil
}

// retireToken revokes token; if revocation fails, publication waits until
// the token expires.
func (c *tokenClient) retireToken(ctx context.Context, env *capture.Env, token string, expiresIn time.Duration) {
	if err := capture.RevokeAccessToken(ctx, env, c.id, c.secret, token); err != nil {
		env.NoteExpiry(expiresIn)
	}
}

// outcome classifies a token endpoint response. RFC 9449 Section 5 gives
// invalid_dpop_proof for a proof that fails validation; when nonceRejects
// is set, Section 8's use_dpop_nonce is the expected rejection too.
func (c *tokenClient) outcome(ctx context.Context, env *capture.Env, resp *capture.Response, nonceRejects bool) (conformance.ArtefactOutcome, error) {
	switch {
	case resp.Status == http.StatusOK:
		if _, err := c.retire(ctx, env, resp); err != nil {
			return "", err
		}
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusBadRequest && resp.Error() == "invalid_dpop_proof":
		return conformance.OutcomeRejected, nil
	case resp.Status == http.StatusBadRequest && resp.Error() == "use_dpop_nonce" && nonceRejects:
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("token endpoint answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}

// dpopTokenRequest sends a client_credentials token request carrying proofs
// DPoP header fields. RFC 9449 Section 4.3 check 1 is "There is not more
// than one DPoP HTTP request header field."
func dpopTokenRequest(ctx context.Context, env *capture.Env, proofs int) (conformance.ArtefactOutcome, error) {
	client, err := newTokenClient(ctx, env)
	if err != nil {
		return "", err
	}
	key, err := newProofKey(elliptic.P256())
	if err != nil {
		return "", err
	}
	send := func(nonce string) (*capture.Response, error) {
		values := make([]string, 0, proofs)
		for i := 0; i < proofs; i++ {
			proof, err := client.conformantProof(key, nonce)
			if err != nil {
				return nil, err
			}
			values = append(values, proof)
		}
		req, err := client.request(values...)
		if err != nil {
			return nil, err
		}
		return env.Do(ctx, req)
	}

	resp, err := send("")
	if err != nil {
		return "", err
	}
	// RFC 9449 Section 8: a server requiring a nonce answers use_dpop_nonce
	// with a DPoP-Nonce header, and the client retries with it.
	if resp.Status == http.StatusBadRequest && resp.Error() == "use_dpop_nonce" {
		nonce := resp.Header.Get("DPoP-Nonce")
		if nonce == "" {
			return "", fmt.Errorf("use_dpop_nonce without a DPoP-Nonce header")
		}
		if resp, err = send(nonce); err != nil {
			return "", err
		}
	}
	return client.outcome(ctx, env, resp, false)
}

// conformantTokenScenario is a passing scenario: one valid proof, carrying
// the server-provided nonce, at the token endpoint.
func conformantTokenScenario(name, description string) *capture.Scenario {
	return &capture.Scenario{
		Name:        name,
		Description: description,
		Actor:       conformance.ActorConformanceClient,
		Expected:    conformance.OutcomeAccepted,
		Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
			client, err := newTokenClient(ctx, env)
			if err != nil {
				return "", err
			}
			key, err := newProofKey(elliptic.P256())
			if err != nil {
				return "", err
			}
			nonce, err := client.serverNonce(ctx, env, key)
			if err != nil {
				return "", err
			}
			send := func(nonce string) (*capture.Response, error) {
				proof, err := client.conformantProof(key, nonce)
				if err != nil {
					return nil, err
				}
				req, err := client.request(proof)
				if err != nil {
					return nil, err
				}
				return env.Do(ctx, req)
			}
			resp, err := send(nonce)
			if err != nil {
				return "", err
			}
			// The nonce can rotate between preparation and this request.
			if resp.Status == http.StatusBadRequest && resp.Error() == "use_dpop_nonce" && resp.Header.Get("DPoP-Nonce") != "" {
				if resp, err = send(resp.Header.Get("DPoP-Nonce")); err != nil {
					return "", err
				}
			}
			return client.outcome(ctx, env, resp, false)
		},
	}
}

// brokenProof builds a token endpoint proof that breaks one RFC 9449
// Section 4.3 check and is otherwise valid.
type brokenProof func(key *proofKey, endpoint, nonce string) (string, error)

// brokenTokenScenario is a failing scenario: each proof is sent in its own
// token request, and the server is recorded as accepting the scenario if it
// accepts any of them.
func brokenTokenScenario(name, description string, proofs ...brokenProof) *capture.Scenario {
	return &capture.Scenario{
		Name:        name,
		Description: description,
		Actor:       conformance.ActorConformanceClient,
		Expected:    conformance.OutcomeRejected,
		Run: func(ctx context.Context, env *capture.Env) (conformance.ArtefactOutcome, error) {
			client, err := newTokenClient(ctx, env)
			if err != nil {
				return "", err
			}
			key, err := newProofKey(elliptic.P256())
			if err != nil {
				return "", err
			}
			// The proofs carry the current nonce so that the check under
			// test is the only one they fail.
			nonce, err := client.serverNonce(ctx, env, key)
			if err != nil {
				return "", err
			}
			outcome := conformance.OutcomeRejected
			for _, build := range proofs {
				proof, err := build(key, client.endpoint, nonce)
				if err != nil {
					return "", err
				}
				req, err := client.request(proof)
				if err != nil {
					return "", err
				}
				resp, err := env.Do(ctx, req)
				if err != nil {
					return "", err
				}
				got, err := client.outcome(ctx, env, resp, false)
				if err != nil {
					return "", err
				}
				if got == conformance.OutcomeAccepted {
					outcome = conformance.OutcomeAccepted
				}
			}
			return outcome, nil
		},
	}
}

// edited is a valid ES256 proof with one edit applied before signing.
func edited(edit func(spec *proofSpec)) brokenProof {
	return func(key *proofKey, endpoint, nonce string) (string, error) {
		spec, err := newProofSpec(key, http.MethodPost, endpoint, nonce, "")
		if err != nil {
			return "", err
		}
		edit(spec)
		return spec.signES256(key)
	}
}

func withoutClaim(name string) brokenProof {
	return edited(func(spec *proofSpec) { delete(spec.claims, name) })
}

// withClaim sets claim name to value, or to value() when value is a func.
func withClaim(name string, value any) brokenProof {
	return edited(func(spec *proofSpec) {
		if compute, ok := value.(func() any); ok {
			spec.claims[name] = compute()
			return
		}
		spec.claims[name] = value
	})
}

// withHeader sets JOSE header parameter name; nil removes it.
func withHeader(name string, value any) brokenProof {
	return edited(func(spec *proofSpec) { spec.header[name] = value })
}

func htuOtherEndpoint(key *proofKey, endpoint, nonce string) (string, error) {
	other := strings.TrimSuffix(endpoint, "/token") + "/introspect"
	if other == endpoint+"/introspect" {
		return "", fmt.Errorf("token endpoint %q does not end in /token", endpoint)
	}
	return withClaim("htu", other)(key, endpoint, nonce)
}

// algNone is an unsigned proof (RFC 7515 Appendix A.5 style) with alg none.
func algNone(key *proofKey, endpoint, nonce string) (string, error) {
	spec, err := newProofSpec(key, http.MethodPost, endpoint, nonce, "")
	if err != nil {
		return "", err
	}
	return spec.sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
}

// algHS256 MACs the proof with a random secret the client never shares,
// while the jwk header carries the client's EC public key.
func algHS256(key *proofKey, endpoint, nonce string) (string, error) {
	spec, err := newProofSpec(key, http.MethodPost, endpoint, nonce, "")
	if err != nil {
		return "", err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return spec.sign(jwt.SigningMethodHS256, secret)
}

// algES384 signs with a P-384 key whose public key is in the jwk header:
// a registered asymmetric algorithm outside the server's allowlist.
func algES384(_ *proofKey, endpoint, nonce string) (string, error) {
	key, err := newProofKey(elliptic.P384())
	if err != nil {
		return "", err
	}
	spec, err := newProofSpec(key, http.MethodPost, endpoint, nonce, "")
	if err != nil {
		return "", err
	}
	return spec.sign(jwt.SigningMethodES384, key.private)
}

// signedByOtherKey carries key's public jwk but is signed by another key.
func signedByOtherKey(key *proofKey, endpoint, nonce string) (string, error) {
	other, err := newProofKey(elliptic.P256())
	if err != nil {
		return "", err
	}
	spec, err := newProofSpec(key, http.MethodPost, endpoint, nonce, "")
	if err != nil {
		return "", err
	}
	return spec.signES256(other)
}

// privateJWK puts key's private member d in the jwk header. Each scenario
// generates its own key, so the exposed key is used for nothing else.
func privateJWK(key *proofKey, endpoint, nonce string) (string, error) {
	spec, err := newProofSpec(key, http.MethodPost, endpoint, nonce, "")
	if err != nil {
		return "", err
	}
	jwk, err := key.privateJWK()
	if err != nil {
		return "", err
	}
	spec.header["jwk"] = jwk
	return spec.signES256(key)
}

// nonceUse is what tokenNonce does with the server-provided nonce.
type nonceUse int

const (
	// presentIssuedNonce retries once with the issued nonce.
	presentIssuedNonce nonceUse = iota
	// reuseIssuedNonce sends two requests carrying the issued nonce.
	reuseIssuedNonce
	// presentOtherNonce sends a nonce the server never issued, then no nonce.
	presentOtherNonce
)

// tokenNonce records the token endpoint providing a nonce (RFC 9449
// Section 8) and then the requests that use it. Section 4.3 check 10 is
// "If the server provided a nonce value to the client, the nonce claim
// matches the server-provided nonce value."
func tokenNonce(ctx context.Context, env *capture.Env, use nonceUse) (conformance.ArtefactOutcome, error) {
	client, err := newTokenClient(ctx, env)
	if err != nil {
		return "", err
	}
	key, err := newProofKey(elliptic.P256())
	if err != nil {
		return "", err
	}
	send := func(nonce string) (*capture.Response, error) {
		proof, err := client.conformantProof(key, nonce)
		if err != nil {
			return nil, err
		}
		req, err := client.request(proof)
		if err != nil {
			return nil, err
		}
		return env.Do(ctx, req)
	}

	challenge, err := send("")
	if err != nil {
		return "", err
	}
	if challenge.Status == http.StatusOK {
		if _, err := client.retire(ctx, env, challenge); err != nil {
			return "", err
		}
		return "", fmt.Errorf("token endpoint accepted a proof without a nonce claim, so it is not issuing DPoP nonces")
	}
	if challenge.Status != http.StatusBadRequest || challenge.Error() != "use_dpop_nonce" {
		return "", fmt.Errorf("token endpoint answered %d %s", challenge.Status, capture.Truncate(challenge.Body))
	}
	issued := challenge.Header.Get("DPoP-Nonce")
	if issued == "" {
		return "", fmt.Errorf("use_dpop_nonce without a DPoP-Nonce header")
	}

	var nonces []string
	switch use {
	case presentIssuedNonce:
		nonces = []string{issued}
	case reuseIssuedNonce:
		nonces = []string{issued, issued}
	case presentOtherNonce:
		raw := make([]byte, 24)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		nonces = []string{base64.RawURLEncoding.EncodeToString(raw), ""}
	}

	outcome := conformance.OutcomeRejected
	if use != presentOtherNonce {
		outcome = conformance.OutcomeAccepted
	}
	for _, nonce := range nonces {
		resp, err := send(nonce)
		if err != nil {
			return "", err
		}
		got, err := client.outcome(ctx, env, resp, use == presentOtherNonce)
		if err != nil {
			return "", err
		}
		switch {
		case use == presentOtherNonce && got == conformance.OutcomeAccepted:
			outcome = conformance.OutcomeAccepted
		case use != presentOtherNonce && got == conformance.OutcomeRejected:
			outcome = conformance.OutcomeRejected
		}
	}
	return outcome, nil
}

// resourceATH presents a DPoP-bound token to the OAuth 2.0 protected
// resource. Section 4.3 check 12 requires the server to "ensure that the
// value of the ath claim equals the hash of that access token".
func resourceATH(ctx context.Context, env *capture.Env, failing bool) (conformance.ArtefactOutcome, error) {
	client, err := newTokenClient(ctx, env)
	if err != nil {
		return "", err
	}
	key, err := newProofKey(elliptic.P256())
	if err != nil {
		return "", err
	}
	token, lifetime, err := client.boundToken(ctx, env, key)
	if err != nil {
		return "", err
	}
	defer client.retireToken(ctx, env, token, lifetime)

	resource := env.BaseURL + "/oauth2/resource"
	get := func(spec *proofSpec, record bool) (*capture.Response, error) {
		proof, err := spec.signES256(key)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodGet, resource, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("DPoP", proof)
		if record {
			return env.Do(ctx, req)
		}
		return env.Setup(ctx, req)
	}
	proofFor := func(nonce, athToken string) (*proofSpec, error) {
		return newProofSpec(key, http.MethodGet, resource, nonce, athToken)
	}

	// The resource's nonce space is separate from the token endpoint's
	// (RFC 9449 Section 8.2). It challenges only after the proof's ath and
	// key have passed, and before it records the jti.
	spec, err := proofFor("", token)
	if err != nil {
		return "", err
	}
	first, err := get(spec, false)
	if err != nil {
		return "", err
	}
	nonce := ""
	switch {
	case first.Status == http.StatusUnauthorized && first.Error() == "use_dpop_nonce":
		if nonce = first.Header.Get("DPoP-Nonce"); nonce == "" {
			return "", fmt.Errorf("use_dpop_nonce without a DPoP-Nonce header")
		}
	case first.Status != http.StatusOK:
		return "", fmt.Errorf("protected resource answered %d %s", first.Status, capture.Truncate(first.Body))
	}

	if !failing {
		if spec, err = proofFor(nonce, token); err != nil {
			return "", err
		}
		resp, err := get(spec, true)
		if err != nil {
			return "", err
		}
		// The nonce can rotate between preparation and this request.
		if resp.Status == http.StatusUnauthorized && resp.Error() == "use_dpop_nonce" && resp.Header.Get("DPoP-Nonce") != "" {
			if spec, err = proofFor(resp.Header.Get("DPoP-Nonce"), token); err != nil {
				return "", err
			}
			if resp, err = get(spec, true); err != nil {
				return "", err
			}
		}
		return resourceOutcome(resp)
	}

	other, otherLifetime, err := client.boundToken(ctx, env, key)
	if err != nil {
		return "", err
	}
	defer client.retireToken(ctx, env, other, otherLifetime)

	wrongATH, err := proofFor(nonce, other)
	if err != nil {
		return "", err
	}
	noATH, err := proofFor(nonce, "")
	if err != nil {
		return "", err
	}
	outcome := conformance.OutcomeRejected
	for _, spec := range []*proofSpec{wrongATH, noATH} {
		resp, err := get(spec, true)
		if err != nil {
			return "", err
		}
		got, err := resourceOutcome(resp)
		if err != nil {
			return "", err
		}
		if got == conformance.OutcomeAccepted {
			outcome = conformance.OutcomeAccepted
		}
	}
	return outcome, nil
}

// resourceOutcome classifies a protected resource response: a rejected
// proof gets 401 invalid_token with a DPoP WWW-Authenticate challenge.
func resourceOutcome(resp *capture.Response) (conformance.ArtefactOutcome, error) {
	switch {
	case resp.Status == http.StatusOK:
		return conformance.OutcomeAccepted, nil
	case resp.Status == http.StatusUnauthorized && resp.Error() == "invalid_token" &&
		strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "DPoP "):
		return conformance.OutcomeRejected, nil
	default:
		return "", fmt.Errorf("protected resource answered %d %s", resp.Status, capture.Truncate(resp.Body))
	}
}
