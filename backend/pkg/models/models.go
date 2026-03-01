package models

import "time"

// User represents a user in the system
type User struct {
	ID        string            `json:"id"`
	Email     string            `json:"email"`
	Name      string            `json:"name"`
	Password  string            `json:"-"` // Never serialized
	Roles     []string          `json:"roles"`
	Claims    map[string]string `json:"claims,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// Client represents an OAuth client application
type Client struct {
	ID           string    `json:"client_id"`
	Secret       string    `json:"-"` // Never serialized in responses
	Name         string    `json:"name"`
	RedirectURIs []string  `json:"redirect_uris"`
	GrantTypes   []string  `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	Public       bool      `json:"public"` // Public clients (no secret)
	CreatedAt    time.Time `json:"created_at"`
}

// AuthorizationCode represents an OAuth authorization code
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               string    `json:"state"`
	Nonce               string    `json:"nonce,omitempty"` // For OIDC
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}

// TokenResponse represents an OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // For OIDC
	Scope        string `json:"scope,omitempty"`
}

// Session represents an authentication session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RefreshToken represents a refresh token
type RefreshToken struct {
	Token     string    `json:"token"`
	ClientID  string    `json:"client_id"`
	UserID    string    `json:"user_id"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// IntrospectionResponse represents token introspection response
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

// OIDCClaims represents standard OIDC claims
type OIDCClaims struct {
	// Standard claims
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`

	// Profile claims
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`

	// Custom claims
	Roles []string `json:"roles,omitempty"`
}

// DiscoveryDocument represents OIDC discovery document
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

// VCCredentialOffer represents an OpenID4VCI credential offer envelope.
type VCCredentialOffer struct {
	CredentialIssuer           string                  `json:"credential_issuer"`
	CredentialConfigurationIDs []string                `json:"credential_configuration_ids"`
	Grants                     VCCredentialOfferGrants `json:"grants,omitempty"`
	CreatedAt                  time.Time               `json:"created_at"`
}

// VCCredentialOfferGrants describes supported grant options in a credential offer.
type VCCredentialOfferGrants struct {
	AuthorizationCode *VCAuthorizationCodeGrant `json:"authorization_code,omitempty"`
	PreAuthorizedCode *VCPreAuthorizedCodeGrant `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

// VCAuthorizationCodeGrant models credential offer parameters for authorization_code.
type VCAuthorizationCodeGrant struct {
	IssuerState         string `json:"issuer_state,omitempty"`
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// VCPreAuthorizedCodeGrant models credential offer parameters for pre-authorized code flow.
type VCPreAuthorizedCodeGrant struct {
	PreAuthorizedCode string    `json:"pre-authorized_code"`
	TxCode            *VCTxCode `json:"tx_code,omitempty"`
}

// VCTxCode describes transaction code constraints in pre-authorized issuance.
type VCTxCode struct {
	Description string `json:"description,omitempty"`
	Length      int    `json:"length,omitempty"`
	InputMode   string `json:"input_mode,omitempty"`
}

// VCNonce represents a c_nonce challenge lifecycle.
type VCNonce struct {
	Value     string    `json:"value"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// VCIssuanceTransaction tracks issuance and deferred issuance state.
type VCIssuanceTransaction struct {
	TransactionID             string    `json:"transaction_id"`
	CredentialConfigurationID string    `json:"credential_configuration_id"`
	AccessTokenID             string    `json:"access_token_id"`
	Deferred                  bool      `json:"deferred"`
	Status                    string    `json:"status"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// OID4VPRequestContract captures query contract inputs for OID4VP authorization requests.
type OID4VPRequestContract struct {
	DCQLQuery  string `json:"dcql_query,omitempty"`
	ScopeAlias string `json:"scope_alias,omitempty"`
	Nonce      string `json:"nonce"`
}

// OID4VPPolicyDecision stores verifier policy outcomes for Looking Glass visibility.
type OID4VPPolicyDecision struct {
	Allowed     bool      `json:"allowed"`
	Code        string    `json:"code,omitempty"`
	Message     string    `json:"message,omitempty"`
	Reasons     []string  `json:"reasons,omitempty"`
	ReasonCodes []string  `json:"reason_codes,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// OID4VPCredentialEvidence captures verifier claim visibility for SD-JWT presentations.
type OID4VPCredentialEvidence struct {
	Subject            string                 `json:"subject,omitempty"`
	VCT                string                 `json:"vct,omitempty"`
	Issuer             string                 `json:"issuer,omitempty"`
	RequiredClaimPaths []string               `json:"required_claim_paths,omitempty"`
	DisclosedClaims    map[string]interface{} `json:"disclosed_claims,omitempty"`
	FullClaims         map[string]interface{} `json:"full_claims,omitempty"`
}

// OID4VPVerificationResult stores structured verification output for VP processing.
type OID4VPVerificationResult struct {
	NonceValidated        bool                 `json:"nonce_validated"`
	AudienceValidated     bool                 `json:"audience_validated"`
	ExpiryValidated       bool                 `json:"expiry_validated"`
	HolderBindingVerified bool                 `json:"holder_binding_verified"`
	CredentialEvidence    *OID4VPCredentialEvidence `json:"credential_evidence,omitempty"`
	Policy                OID4VPPolicyDecision `json:"policy"`
}
