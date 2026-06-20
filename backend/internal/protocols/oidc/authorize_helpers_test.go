package oidc

import (
	"net/url"
	"testing"
	"time"
)

func TestDefaultResponseMode(t *testing.T) {
	cases := map[string]string{
		"code":                "query",
		"token":               "fragment",
		"id_token":            "fragment",
		"code id_token":       "fragment",
		"code token":          "fragment",
		"id_token token":      "fragment",
		"code id_token token": "fragment",
	}
	for rt, want := range cases {
		if got := defaultResponseMode(rt); got != want {
			t.Errorf("defaultResponseMode(%q) = %q, want %q", rt, got, want)
		}
	}
}

func TestResolveResponseMode(t *testing.T) {
	type tc struct {
		responseType string
		requested    string
		wantMode     string
		wantErr      bool
	}
	cases := []tc{
		{"code", "", "query", false},
		{"id_token", "", "fragment", false},
		{"code", "query", "query", false},
		{"code", "fragment", "fragment", false},
		{"id_token", "fragment", "fragment", false},
		// query MUST NOT carry front-channel tokens.
		{"id_token", "query", "", true},
		{"code id_token", "query", "", true},
		{"token", "query", "", true},
		// unknown modes are rejected rather than silently defaulted.
		{"code", "form_post", "", true},
	}
	for _, c := range cases {
		mode, errCode, _ := resolveResponseMode(c.responseType, c.requested)
		if c.wantErr {
			if errCode == "" {
				t.Errorf("resolveResponseMode(%q,%q) expected error, got mode=%q", c.responseType, c.requested, mode)
			}
			continue
		}
		if errCode != "" {
			t.Errorf("resolveResponseMode(%q,%q) unexpected error %q", c.responseType, c.requested, errCode)
		}
		if mode != c.wantMode {
			t.Errorf("resolveResponseMode(%q,%q) = %q, want %q", c.responseType, c.requested, mode, c.wantMode)
		}
	}
}

func TestValidatePrompt(t *testing.T) {
	if code, _ := validatePrompt([]string{"none"}); code != "" {
		t.Errorf("prompt=none alone must be valid, got %q", code)
	}
	if code, _ := validatePrompt([]string{"login", "consent"}); code != "" {
		t.Errorf("prompt=login consent must be valid, got %q", code)
	}
	if code, _ := validatePrompt([]string{"none", "login"}); code == "" {
		t.Errorf("prompt=none combined with login must be invalid (OIDC Core 3.1.2.1)")
	}
	// Unknown values are ignored per spec, not errors.
	if code, _ := validatePrompt([]string{"login", "unknown_value"}); code != "" {
		t.Errorf("unknown prompt values must be ignored, got %q", code)
	}
}

func TestParseMaxAge(t *testing.T) {
	if _, present, errDesc := parseMaxAge(""); present || errDesc != "" {
		t.Errorf("empty max_age should be absent with no error")
	}
	if n, present, errDesc := parseMaxAge("0"); !present || errDesc != "" || n != 0 {
		t.Errorf("max_age=0 should be present, value 0, no error; got n=%d present=%v err=%q", n, present, errDesc)
	}
	if n, present, errDesc := parseMaxAge("3600"); !present || errDesc != "" || n != 3600 {
		t.Errorf("max_age=3600 mis-parsed: n=%d present=%v err=%q", n, present, errDesc)
	}
	for _, bad := range []string{"-1", "abc", "1.0", "  "} {
		if _, _, errDesc := parseMaxAge(bad); errDesc == "" {
			t.Errorf("max_age=%q should be rejected", bad)
		}
	}
}

func TestReauthRequired(t *testing.T) {
	now := time.Now()
	authTime := now.Add(-100 * time.Second)

	if !reauthRequired([]string{"login"}, 0, false, authTime, now) {
		t.Errorf("prompt=login must force re-authentication")
	}
	if reauthRequired(nil, 0, false, authTime, now) {
		t.Errorf("no prompt and no max_age must not force re-authentication")
	}
	if !reauthRequired(nil, 30, true, authTime, now) {
		t.Errorf("session older than max_age must force re-authentication")
	}
	if reauthRequired(nil, 1000, true, authTime, now) {
		t.Errorf("session within max_age must not force re-authentication")
	}
}

func TestBuildErrorRedirectQueryAndFragment(t *testing.T) {
	// Query mode preserves an existing query and appends error params.
	target, err := buildErrorRedirect("https://rp.example/cb?foo=bar", "query", "st8", "invalid_scope", "bad scope")
	if err != nil {
		t.Fatalf("buildErrorRedirect query: %v", err)
	}
	u, _ := url.Parse(target)
	q := u.Query()
	if q.Get("foo") != "bar" {
		t.Errorf("existing query parameter dropped: %q", target)
	}
	if q.Get("error") != "invalid_scope" || q.Get("state") != "st8" {
		t.Errorf("query error params wrong: %q", target)
	}
	if u.Fragment != "" {
		t.Errorf("query mode must not use fragment: %q", target)
	}

	// Fragment mode places params in the fragment.
	target, err = buildErrorRedirect("https://rp.example/cb", "fragment", "st9", "login_required", "")
	if err != nil {
		t.Fatalf("buildErrorRedirect fragment: %v", err)
	}
	u, _ = url.Parse(target)
	if u.Fragment == "" {
		t.Fatalf("fragment mode must populate fragment: %q", target)
	}
	fr, _ := url.ParseQuery(u.Fragment)
	if fr.Get("error") != "login_required" || fr.Get("state") != "st9" {
		t.Errorf("fragment error params wrong: %q", target)
	}
	if fr.Get("error_description") != "" {
		t.Errorf("empty error_description should be omitted: %q", target)
	}
}
