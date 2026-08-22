package ssf

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// ErrSubjectNotInStream is returned when a SET would be transmitted for a
// subject the Receiver removed (SSF §7.1 default_subjects / §8.1.3).
var ErrSubjectNotInStream = errors.New("subject is not in this stream")

// SubjectFormatComplex is the SSF Complex Subject format (SSF §3 Complex Subject Members).
const SubjectFormatComplex = "complex"

// complexMemberNames are the named Simple Subject Members in a Complex Subject
// (SSF §3). Additional names MAY appear; matching treats every object member
// other than "format" as a field.
var complexMemberNames = []string{
	"user", "device", "session", "application", "tenant", "org_unit", "group",
}

// subjectClaim is an RFC 9493 / SSF Subject Identifier as a JSON object.
type subjectClaim map[string]interface{}

func subjectToClaim(s SubjectIdentifier) subjectClaim {
	if s.Format == SubjectFormatComplex || nestedSubjectPresent(s) {
		claim := subjectClaim{"format": SubjectFormatComplex}
		putNested := func(name string, nested *SubjectIdentifier) {
			if nested != nil {
				claim[name] = map[string]interface{}(subjectToClaim(*nested))
			}
		}
		putNested("user", s.User)
		putNested("device", s.Device)
		putNested("session", s.Session)
		putNested("application", s.Application)
		putNested("tenant", s.Tenant)
		putNested("org_unit", s.OrgUnit)
		putNested("group", s.Group)
		return claim
	}

	claim := subjectClaim{"format": normalizeSubjectFormat(s.Format)}
	switch normalizeSubjectFormat(s.Format) {
	case SubjectFormatEmail:
		claim["email"] = s.Email
	case SubjectFormatPhone:
		claim["phone_number"] = s.PhoneNumber
	case SubjectFormatIssuerSub:
		claim["iss"] = s.Issuer
		claim["sub"] = s.Subject
	case SubjectFormatOpaque:
		claim["id"] = s.ID
	case SubjectFormatURI, SubjectFormatDID:
		if s.URI != "" {
			claim["uri"] = s.URI
		}
		if s.ID != "" && s.URI == "" {
			claim["url"] = s.ID
		}
	}
	return claim
}

func nestedSubjectPresent(s SubjectIdentifier) bool {
	return s.User != nil || s.Device != nil || s.Session != nil ||
		s.Application != nil || s.Tenant != nil || s.OrgUnit != nil || s.Group != nil
}

func claimToSubject(claim subjectClaim) SubjectIdentifier {
	format, _ := claim["format"].(string)
	s := SubjectIdentifier{Format: normalizeSubjectFormat(format)}
	if s.Format == SubjectFormatComplex {
		s.User = nestedClaim(claim, "user")
		s.Device = nestedClaim(claim, "device")
		s.Session = nestedClaim(claim, "session")
		s.Application = nestedClaim(claim, "application")
		s.Tenant = nestedClaim(claim, "tenant")
		s.OrgUnit = nestedClaim(claim, "org_unit")
		s.Group = nestedClaim(claim, "group")
		return s
	}
	s.Email, _ = claim["email"].(string)
	s.PhoneNumber, _ = claim["phone_number"].(string)
	if s.PhoneNumber == "" {
		s.PhoneNumber, _ = claim["phone"].(string)
	}
	s.Issuer, _ = claim["iss"].(string)
	s.Subject, _ = claim["sub"].(string)
	s.ID, _ = claim["id"].(string)
	s.URI, _ = claim["uri"].(string)
	if s.URI == "" {
		s.URI, _ = claim["url"].(string)
	}
	return s
}

func nestedClaim(claim subjectClaim, name string) *SubjectIdentifier {
	raw, ok := claim[name]
	if !ok || raw == nil {
		return nil
	}
	nested, ok := asSubjectClaim(raw)
	if !ok {
		return nil
	}
	s := claimToSubject(nested)
	return &s
}

func asSubjectClaim(raw interface{}) (subjectClaim, bool) {
	switch v := raw.(type) {
	case subjectClaim:
		return v, true
	case map[string]interface{}:
		return subjectClaim(v), true
	default:
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, false
		}
		var claim subjectClaim
		if err := json.Unmarshal(b, &claim); err != nil {
			return nil, false
		}
		return claim, true
	}
}

func parseSubjectClaim(raw json.RawMessage) (subjectClaim, error) {
	var claim subjectClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return nil, err
	}
	if format, _ := claim["format"].(string); format == "phone" {
		claim["format"] = SubjectFormatPhone
		if _, ok := claim["phone_number"]; !ok {
			if phone, _ := claim["phone"].(string); phone != "" {
				claim["phone_number"] = phone
			}
		}
	}
	return claim, nil
}

func normalizeSubjectFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "phone":
		return SubjectFormatPhone
	default:
		return format
	}
}

// subjectsMatch implements SSF §8.1.3 Subject Matching.
// Simple Subjects match if they are exactly identical. Complex Subjects match
// if, for all fields, at least one of: subject 1's field is not defined,
// subject 2's field is not defined, or the fields are identical.
func subjectsMatch(a, b subjectClaim) bool {
	if a == nil || b == nil {
		return false
	}
	af := normalizeSubjectFormat(stringClaim(a, "format"))
	bf := normalizeSubjectFormat(stringClaim(b, "format"))
	if af != SubjectFormatComplex && bf != SubjectFormatComplex {
		return simpleSubjectsEqual(a, b)
	}
	if af != SubjectFormatComplex || bf != SubjectFormatComplex {
		return false
	}
	names := complexFieldNames(a, b)
	for _, name := range names {
		fa, aok := a[name]
		fb, bok := b[name]
		if !aok || fa == nil || !bok || fb == nil {
			continue
		}
		if !reflect.DeepEqual(normalizeClaimValue(fa), normalizeClaimValue(fb)) {
			return false
		}
	}
	return true
}

func simpleSubjectsEqual(a, b subjectClaim) bool {
	return reflect.DeepEqual(normalizeClaimValue(a), normalizeClaimValue(b))
}

func complexFieldNames(a, b subjectClaim) []string {
	seen := map[string]struct{}{}
	var names []string
	add := func(claim subjectClaim) {
		for k := range claim {
			if k == "format" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			names = append(names, k)
		}
	}
	add(a)
	add(b)
	if len(names) == 0 {
		return complexMemberNames
	}
	return names
}

func normalizeClaimValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			if k == "format" {
				out[k] = normalizeSubjectFormat(fmtString(val))
				continue
			}
			out[k] = normalizeClaimValue(val)
		}
		return out
	case subjectClaim:
		return normalizeClaimValue(map[string]interface{}(t))
	default:
		return v
	}
}

func fmtString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func stringClaim(claim subjectClaim, key string) string {
	s, _ := claim[key].(string)
	return s
}

func (s SubjectIdentifier) email() string {
	if s.Email != "" {
		return s.Email
	}
	if s.User != nil && s.User.Email != "" {
		return s.User.Email
	}
	return ""
}

func (s SubjectIdentifier) deviceID() string {
	if s.Device == nil {
		return ""
	}
	if s.Device.Subject != "" {
		return s.Device.Subject
	}
	return s.Device.ID
}

func setSubjectFromClaim(claim subjectClaim) *SETSubject {
	if claim == nil {
		return nil
	}
	s := claimToSubject(claim)
	return subjectIdentifierToSET(s)
}

func subjectIdentifierToSET(s SubjectIdentifier) *SETSubject {
	out := &SETSubject{
		Format:      s.Format,
		Email:       s.Email,
		PhoneNumber: s.PhoneNumber,
		Issuer:      s.Issuer,
		Subject:     s.Subject,
		ID:          s.ID,
		URI:         s.URI,
	}
	if s.User != nil {
		out.User = subjectIdentifierToSET(*s.User)
	}
	if s.Device != nil {
		out.Device = subjectIdentifierToSET(*s.Device)
	}
	if s.Session != nil {
		out.Session = subjectIdentifierToSET(*s.Session)
	}
	if s.Tenant != nil {
		out.Tenant = subjectIdentifierToSET(*s.Tenant)
	}
	if s.Application != nil {
		out.Application = subjectIdentifierToSET(*s.Application)
	}
	if s.OrgUnit != nil {
		out.OrgUnit = subjectIdentifierToSET(*s.OrgUnit)
	}
	if s.Group != nil {
		out.Group = subjectIdentifierToSET(*s.Group)
	}
	return out
}

func deviceComplianceSubject(email, issuer string) SubjectIdentifier {
	deviceSub := "device:" + email
	return SubjectIdentifier{
		Format: SubjectFormatComplex,
		User: &SubjectIdentifier{
			Format: SubjectFormatEmail,
			Email:  email,
		},
		Device: &SubjectIdentifier{
			Format:  SubjectFormatIssuerSub,
			Issuer:  issuer,
			Subject: deviceSub,
		},
	}
}
