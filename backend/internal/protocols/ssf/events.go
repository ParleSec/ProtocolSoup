package ssf

import "time"

// SSF Framework event types
const (
	// Verification event per SSF §7
	EventTypeVerification = "https://schemas.openid.net/secevent/ssf/event-type/verification"
)

// Event URIs for CAEP (Continuous Access Evaluation Profile)
const (
	// CAEP Event Types - Session and Access Events
	EventTypeSessionRevoked         = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	EventTypeTokenClaimsChange      = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
	EventTypeCredentialChange       = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
	EventTypeAssuranceLevelChange   = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
	EventTypeDeviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
)

// Event URIs for RISC (Risk Incident Sharing and Coordination)
const (
	// RISC Event Types - Account Security Events
	EventTypeCredentialCompromise            = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
	EventTypeAccountPurged                   = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
	EventTypeAccountDisabled                 = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	EventTypeAccountEnabled                  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	EventTypeIdentifierChanged               = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
	EventTypeIdentifierRecycled              = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
	EventTypeAccountCredentialChangeRequired = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
	EventTypeSessionsRevoked                 = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
)

// Subject identifier formats per SSF spec
const (
	SubjectFormatEmail     = "email"
	SubjectFormatPhone     = "phone_number"
	SubjectFormatIssuerSub = "iss_sub"
	SubjectFormatOpaque    = "opaque"
	SubjectFormatDID       = "did"
	SubjectFormatURI       = "uri"
	SubjectFormatAliases   = "aliases"
)

// SubjectIdentifier represents a subject in SSF events
type SubjectIdentifier struct {
	Format string `json:"format"`
	// For email format
	Email string `json:"email,omitempty"`
	// For phone_number format
	PhoneNumber string `json:"phone_number,omitempty"`
	// For iss_sub format
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	// For opaque format
	ID string `json:"id,omitempty"`
	// For uri format
	URI string `json:"uri,omitempty"`
}

// EventCategory represents the category of SSF event
type EventCategory string

const (
	CategoryCAEP EventCategory = "CAEP"
	CategoryRISC EventCategory = "RISC"
)

// EventMetadata contains metadata about an event type
type EventMetadata struct {
	URI             string        `json:"uri"`
	Name            string        `json:"name"`
	Description     string        `json:"description"`
	Category        EventCategory `json:"category"`
	ResponseActions []string      `json:"response_actions"`
	ZeroTrustImpact string        `json:"zero_trust_impact"`
}

// GetEventMetadata returns metadata for a given event type URI
func GetEventMetadata(eventURI string) EventMetadata {
	metadata, ok := eventMetadataRegistry[eventURI]
	if !ok {
		return EventMetadata{
			URI:         eventURI,
			Name:        "Unknown Event",
			Description: "Unknown event type",
			Category:    CategoryCAEP,
		}
	}
	return metadata
}

// eventMetadataRegistry contains all supported event types with their metadata
var eventMetadataRegistry = map[string]EventMetadata{
	// CAEP Events
	EventTypeSessionRevoked: {
		URI:         EventTypeSessionRevoked,
		Name:        "Session Revoked",
		Description: "A session for the subject has been revoked",
		Category:    CategoryCAEP,
		ResponseActions: []string{
			"Terminate all active sessions",
			"Invalidate session tokens",
			"Force re-authentication",
		},
		ZeroTrustImpact: "Immediate session termination enforces continuous verification",
	},
	EventTypeTokenClaimsChange: {
		URI:         EventTypeTokenClaimsChange,
		Name:        "Token Claims Change",
		Description: "Claims in an active token have changed",
		Category:    CategoryCAEP,
		ResponseActions: []string{
			"Re-evaluate access policies",
			"Update cached claims",
			"Trigger policy re-evaluation",
		},
		ZeroTrustImpact: "Dynamic policy enforcement based on real-time claim changes",
	},
	EventTypeCredentialChange: {
		URI:         EventTypeCredentialChange,
		Name:        "Credential Change",
		Description: "A credential for the subject has been changed",
		Category:    CategoryCAEP,
		ResponseActions: []string{
			"Revoke existing access tokens",
			"Invalidate refresh tokens",
			"Require re-authentication",
		},
		ZeroTrustImpact: "Credential rotation triggers access re-validation",
	},
	EventTypeAssuranceLevelChange: {
		URI:         EventTypeAssuranceLevelChange,
		Name:        "Assurance Level Change",
		Description: "The authentication assurance level has changed",
		Category:    CategoryCAEP,
		ResponseActions: []string{
			"Re-evaluate resource access",
			"Enforce step-up authentication if needed",
			"Update session risk score",
		},
		ZeroTrustImpact: "Continuous trust evaluation based on authentication strength",
	},
	EventTypeDeviceComplianceChange: {
		URI:         EventTypeDeviceComplianceChange,
		Name:        "Device Compliance Change",
		Description: "Device compliance status has changed",
		Category:    CategoryCAEP,
		ResponseActions: []string{
			"Isolate affected systems",
			"Restrict network access",
			"Trigger compliance workflow",
			"Quarantine device",
		},
		ZeroTrustImpact: "Device trust impacts access decisions in real-time",
	},

	// RISC Events
	EventTypeCredentialCompromise: {
		URI:         EventTypeCredentialCompromise,
		Name:        "Credential Compromise",
		Description: "Credentials for the subject may have been compromised",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Force immediate password reset",
			"Revoke all access tokens and API keys",
			"Terminate all active sessions",
			"Enable additional MFA",
			"Alert security team",
		},
		ZeroTrustImpact: "Automated threat containment prevents lateral movement",
	},
	EventTypeAccountPurged: {
		URI:         EventTypeAccountPurged,
		Name:        "Account Purged",
		Description: "The account has been permanently deleted",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Remove all access across systems",
			"Offboard identity from all connected apps",
			"Revoke all tokens and certificates",
			"Archive audit logs",
		},
		ZeroTrustImpact: "Complete identity removal across the ecosystem",
	},
	EventTypeAccountDisabled: {
		URI:         EventTypeAccountDisabled,
		Name:        "Account Disabled",
		Description: "The account has been disabled",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Suspend all active sessions",
			"Block new authentication attempts",
			"Revoke access tokens",
			"Disable API keys",
		},
		ZeroTrustImpact: "Immediate access suspension across all connected systems",
	},
	EventTypeAccountEnabled: {
		URI:         EventTypeAccountEnabled,
		Name:        "Account Enabled",
		Description: "A previously disabled account has been re-enabled",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Restore access permissions",
			"Allow authentication",
			"Re-enable API keys",
			"Log reactivation event",
		},
		ZeroTrustImpact: "Controlled re-enablement with audit trail",
	},
	EventTypeIdentifierChanged: {
		URI:         EventTypeIdentifierChanged,
		Name:        "Identifier Changed",
		Description: "A subject identifier (email, username) has changed",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Update identity records",
			"Re-map access policies",
			"Notify connected systems",
			"Update audit trail",
		},
		ZeroTrustImpact: "Cross-platform identity synchronization",
	},
	EventTypeIdentifierRecycled: {
		URI:         EventTypeIdentifierRecycled,
		Name:        "Identifier Recycled",
		Description: "An identifier previously used by one subject is now used by another",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Clear all cached data for identifier",
			"Reset permissions to default",
			"Alert administrators",
			"Audit previous identifier usage",
		},
		ZeroTrustImpact: "Prevents unauthorized access through identifier reuse",
	},
	EventTypeAccountCredentialChangeRequired: {
		URI:         EventTypeAccountCredentialChangeRequired,
		Name:        "Credential Change Required",
		Description: "The subject must change their credentials",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Force password change on next login",
			"Send credential reset notification",
			"Limit access until change completed",
		},
		ZeroTrustImpact: "Proactive credential hygiene enforcement",
	},
	EventTypeSessionsRevoked: {
		URI:         EventTypeSessionsRevoked,
		Name:        "All Sessions Revoked",
		Description: "All sessions for the subject have been revoked",
		Category:    CategoryRISC,
		ResponseActions: []string{
			"Terminate all active sessions globally",
			"Clear session caches",
			"Force re-authentication everywhere",
		},
		ZeroTrustImpact: "Global session termination for incident response",
	},
}

// GetAllEventTypes returns all supported event types grouped by category
func GetAllEventTypes() map[EventCategory][]EventMetadata {
	result := map[EventCategory][]EventMetadata{
		CategoryCAEP: {},
		CategoryRISC: {},
	}
	for _, meta := range eventMetadataRegistry {
		result[meta.Category] = append(result[meta.Category], meta)
	}
	return result
}

// GetSupportedEventURIs returns all supported event type URIs
func GetSupportedEventURIs() []string {
	uris := make([]string, 0, len(eventMetadataRegistry))
	for uri := range eventMetadataRegistry {
		uris = append(uris, uri)
	}
	return uris
}

// SecurityEvent represents a complete SSF event
type SecurityEvent struct {
	ID             string            `json:"id"`
	EventType      string            `json:"event_type"`
	Subject        SubjectIdentifier `json:"subject"`
	EventTimestamp time.Time         `json:"event_timestamp"`
	IssuedAt       time.Time         `json:"issued_at"`
	Issuer         string            `json:"issuer"`
	Audience       []string          `json:"audience"`
	TransactionID  string            `json:"txn,omitempty"`

	// Session isolation - used to namespace state changes per user session
	SessionID string `json:"ssf_session_id,omitempty"`

	// Event-specific data
	Reason           string      `json:"reason,omitempty"`
	InitiatingEntity string      `json:"initiating_entity,omitempty"`
	ReasonAdmin      *ReasonInfo `json:"reason_admin,omitempty"`
	ReasonUser       *ReasonInfo `json:"reason_user,omitempty"`

	// For credential events (CAEP §3.2)
	CredentialType string `json:"credential_type,omitempty"`
	ChangeType     string `json:"change_type,omitempty"` // create | revoke | update (REQUIRED by CAEP §3.2)

	// For compliance/status events
	CurrentStatus  string `json:"current_status,omitempty"`
	PreviousStatus string `json:"previous_status,omitempty"`

	// For assurance level change events (CAEP §3.3 -- distinct field names from status)
	CurrentLevel  string `json:"current_level,omitempty"`
	PreviousLevel string `json:"previous_level,omitempty"`

	// For identifier events
	NewValue string `json:"new_value,omitempty"`
	OldValue string `json:"old_value,omitempty"`

	// For verification events (SSF §7)
	State string `json:"state,omitempty"`
}

// ReasonInfo provides human-readable reason information
type ReasonInfo struct {
	EN string `json:"en,omitempty"`
}

// InitiatingEntity constants
const (
	InitiatingEntityAdmin  = "admin"
	InitiatingEntityUser   = "user"
	InitiatingEntityPolicy = "policy"
	InitiatingEntitySystem = "system"
)

// CredentialType constants per CAEP §3.2
const (
	CredentialTypePassword             = "password"
	CredentialTypePIN                  = "pin"
	CredentialTypeX509                 = "x509"
	CredentialTypeFIDO2Platform        = "fido2-platform"
	CredentialTypeFIDO2Roaming         = "fido2-roaming"
	CredentialTypeFIDOU2F              = "fido-u2f"
	CredentialTypeVerifiableCredential = "verifiable-credential"
	CredentialTypePhoneVoice           = "phone-voice"
	CredentialTypePhoneSMS             = "phone-sms"
	CredentialTypeApp                  = "app"
)

// ComplianceStatus constants
const (
	ComplianceStatusCompliant    = "compliant"
	ComplianceStatusNonCompliant = "non-compliant"
)
