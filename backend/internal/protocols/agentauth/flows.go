package agentauth

import "github.com/ParleSec/ProtocolSoup/internal/plugin"

// GetInspectors returns the protocol's inspectors.
func (p *Plugin) GetInspectors() []plugin.Inspector {
	return []plugin.Inspector{
		{
			ID:          "agentauth-identity-assertion",
			Name:        "Identity Assertion Inspector",
			Description: "Decode a service-signed agent identity assertion and check it against the RFC 7523 Section 3 claim requirements",
			Type:        "token",
		},
		{
			ID:          "agentauth-metadata",
			Name:        "Agent Auth Metadata Inspector",
			Description: "Read the agent_auth block from authorization server metadata and resolve every endpoint it advertises",
			Type:        "response",
		},
	}
}

// GetFlowDefinitions returns the protocol's flow definitions.
//
// Both flows are documented but not marked executable: the claim ceremony
// needs a person at a browser partway through, and no Looking Glass executor
// drives these endpoints yet. Claiming otherwise would put a run button in
// front of a flow that cannot complete.
func (p *Plugin) GetFlowDefinitions() []plugin.FlowDefinition {
	return []plugin.FlowDefinition{
		{
			ID:          "agent_anonymous_registration",
			Name:        "Anonymous Agent Registration",
			Description: "An agent with no human behind it registers itself, receives a service-signed identity assertion, and exchanges that assertion for an access token using the RFC 7523 JWT bearer grant. The token carries the pre-claim scope because nothing yet proves who runs the agent.",
			Executable:  false,
			Category:    "registration",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Discover the agent_auth block",
					Description: "The agent reads authorization server metadata and finds the agent_auth extension, which names the identity, claim, token and revocation endpoints. Discovery is what lets an agent register without anything hardcoded.",
					From:        "Agent",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "/.well-known/oauth-authorization-server/agentauth",
						"reads":    "agent_auth.register_uri, agent_auth.identity_types_supported",
					},
					Security: []string{
						"Metadata is public and cacheable, but MUST be fetched over TLS",
						"Only identity types listed in identity_types_supported will be accepted",
					},
				},
				{
					Order:       2,
					Name:        "Register at the identity endpoint",
					Description: "The agent posts type=anonymous and receives an identity assertion plus a claim_token. The assertion is a signed JWT; the claim_token is the handle it will need if a person later takes ownership.",
					From:        "Agent",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "POST /agentauth/identity",
						"body":     `{"type":"anonymous"}`,
						"returns":  "identity_assertion, claim_token, agent_id",
					},
					Security: []string{
						"The assertion is a bearer credential - anyone holding it can redeem it",
						"Store the claim_token; it cannot be recovered from the assertion",
					},
				},
				{
					Order:       3,
					Name:        "Exchange the assertion for a token",
					Description: "The agent presents the assertion at the token endpoint under the RFC 7523 JWT bearer grant. The server verifies the signature, issuer, audience, expiry and jti before issuing anything.",
					From:        "Agent",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint":   "POST /agentauth/token",
						"grant_type": grantTypeJWTBearer,
						"assertion":  "The identity assertion from step 2",
					},
					Security: []string{
						"The assertion is single-use - its jti is recorded and a replay is refused",
						"aud MUST identify this authorization server (RFC 7523 Section 3)",
					},
				},
				{
					Order:       4,
					Name:        "Access token issued",
					Description: "The agent receives a bearer token scoped to agent:read. Without an owner it gets read access and nothing more.",
					From:        "Authorization Server",
					To:          "Agent",
					Type:        "response",
					Parameters: map[string]string{
						"access_token": "Signed JWT, one hour lifetime",
						"scope":        scopePreClaim,
						"token_type":   "Bearer",
					},
				},
			},
		},
		{
			ID:          "agent_claim_ceremony",
			Name:        "Agent Claim Ceremony",
			Description: "A person takes ownership of an already registered agent. The agent shows a user_code, the person approves it in a browser the agent does not control, and the agent polls until it is handed a new assertion and a wider scope. The two-channel structure is borrowed from the RFC 8628 device authorization grant.",
			Executable:  false,
			Category:    "registration",
			Steps: []plugin.FlowStep{
				{
					Order:       1,
					Name:        "Start the claim",
					Description: "The agent posts its claim_token and the email of the person it believes should own it. The server returns a short user_code and the URI where that code is entered.",
					From:        "Agent",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint": "POST /agentauth/identity/claim",
						"returns":  "user_code, verification_uri, verification_uri_complete, interval",
					},
					Security: []string{
						"A new attempt invalidates any outstanding user_code for this agent",
					},
				},
				{
					Order:       2,
					Name:        "Surface the code to a person",
					Description: "The agent displays the user_code and verification URI. It cannot complete this step itself, which is the entire point of the ceremony.",
					From:        "Agent",
					To:          "User",
					Type:        "internal",
					Security: []string{
						"The agent MUST NOT open the verification URI on the person's behalf",
					},
				},
				{
					Order:       3,
					Name:        "Person approves in a browser",
					Description: "The person opens the verification URI, enters the code, and approves. A production deployment authenticates the person first and binds the agent to that account.",
					From:        "User",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint":  "POST /agentauth/identity/claim/complete",
						"user_code": "The code the agent displayed",
					},
					Security: []string{
						"user_code has low entropy, so it is single-use and expires in ten minutes",
						"This sandbox does not sign the person in - a real deployment MUST",
					},
				},
				{
					Order:       4,
					Name:        "Agent polls the token endpoint",
					Description: "While waiting the agent receives authorization_pending, or slow_down if it polls faster than the advertised interval. Once approval lands it receives a new assertion carrying claimed=true and a token scoped to agent:read agent:write.",
					From:        "Agent",
					To:          "Authorization Server",
					Type:        "request",
					Parameters: map[string]string{
						"endpoint":   "POST /agentauth/token",
						"grant_type": grantTypeClaim,
						"errors":     "authorization_pending, slow_down, expired_token",
					},
					Security: []string{
						"Respect the interval - polling faster is answered with slow_down",
						"The user_code is retired on success so it cannot be redeemed twice",
					},
				},
			},
		},
	}
}

// GetDemoScenarios returns the protocol's demo scenarios.
func (p *Plugin) GetDemoScenarios() []plugin.DemoScenario {
	return []plugin.DemoScenario{
		{
			ID:          "agent_registration_walkthrough",
			Name:        "Register an Agent End to End",
			Description: "Register anonymously, exchange the assertion for a token, then claim the agent and watch the scope widen",
			Steps: []plugin.DemoStep{
				{Order: 1, Name: "Read agent_auth metadata", Description: "Discover the registration endpoints", Auto: true},
				{Order: 2, Name: "Register anonymously", Description: "Obtain an identity assertion and claim token", Auto: true},
				{Order: 3, Name: "Redeem the assertion", Description: "Exchange it for a pre-claim access token", Auto: true},
				{Order: 4, Name: "Start a claim", Description: "Request a user_code", Auto: true},
				{Order: 5, Name: "Approve the code", Description: "Enter the code in the verification page", Auto: false},
				{Order: 6, Name: "Poll to completion", Description: "Receive the claimed assertion and wider scope", Auto: true},
			},
		},
	}
}
