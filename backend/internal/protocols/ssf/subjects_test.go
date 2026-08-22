package ssf

import "testing"

func TestSubjectsMatchSSFSection813(t *testing.T) {
	tenantOnly := subjectClaim{
		"format": SubjectFormatComplex,
		"tenant": map[string]interface{}{"format": SubjectFormatOpaque, "id": "example-a38h4792-uw2"},
	}
	tenantAndUser := subjectClaim{
		"format": SubjectFormatComplex,
		"tenant": map[string]interface{}{"format": SubjectFormatOpaque, "id": "example-a38h4792-uw2"},
		"user":   map[string]interface{}{"format": SubjectFormatEmail, "email": "jdoe@example.com"},
	}
	if !subjectsMatch(tenantOnly, tenantAndUser) {
		t.Fatal("less-restrictive added subject MUST match a more specific event subject [SSF §8.1.3]")
	}

	restrictive := subjectClaim{
		"format": SubjectFormatComplex,
		"user":   map[string]interface{}{"format": SubjectFormatEmail, "email": "jdoe@example.com"},
		"device": map[string]interface{}{"format": "ip-addresses", "ip-addresses": []interface{}{"10.29.37.75"}},
	}
	userOnly := subjectClaim{
		"format": SubjectFormatComplex,
		"user":   map[string]interface{}{"format": SubjectFormatEmail, "email": "jdoe@example.com"},
	}
	if !subjectsMatch(restrictive, userOnly) {
		t.Fatal("more-restrictive added subject MUST match an event that omits device [SSF §8.1.3]")
	}

	groupA := subjectClaim{
		"format": SubjectFormatComplex,
		"user":   map[string]interface{}{"format": SubjectFormatEmail, "email": "jdoe@example.com"},
		"group":  map[string]interface{}{"format": "did", "url": "did:example:123456"},
	}
	groupB := subjectClaim{
		"format": SubjectFormatComplex,
		"user":   map[string]interface{}{"format": SubjectFormatEmail, "email": "jdoe@example.com"},
		"group":  map[string]interface{}{"format": "did", "url": "did:example:9999999"},
	}
	if subjectsMatch(groupA, groupB) {
		t.Fatal("conflicting group members MUST NOT match [SSF §8.1.3]")
	}

	simpleA := subjectClaim{"format": SubjectFormatEmail, "email": "alice@example.com"}
	simpleB := subjectClaim{"format": SubjectFormatEmail, "email": "alice@example.com"}
	if !subjectsMatch(simpleA, simpleB) {
		t.Fatal("simple subjects match if exactly identical")
	}
	if subjectsMatch(simpleA, tenantAndUser) {
		t.Fatal("simple and complex subjects are not exactly identical")
	}
}
