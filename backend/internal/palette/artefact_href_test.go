package palette

import "testing"

// TestDefaultHref_InlineOnlyTypesReturnEmpty locks the rule that
// concept, walkthrough, and spec-assertion artefacts are inline-only:
// their canonical surface is the palette's expanded row, not a dedicated
// page route. Without this rule the frontend would emit /concept/{id} and
// similar links that 404 because no matching Next.js route exists.
func TestDefaultHref_InlineOnlyTypesReturnEmpty(t *testing.T) {
	cases := []Artefact{
		{ID: "pkce", Type: ArtefactConcept},
		{ID: "oauth2-tour", Type: ArtefactWalkthrough},
		{ID: "must-use-pkce", Type: ArtefactSpecAssertion},
	}
	for _, a := range cases {
		t.Run(a.Type, func(t *testing.T) {
			if got := a.DefaultHref(); got != "" {
				t.Errorf("DefaultHref for %s = %q; want empty (inline-only types)", a.Type, got)
			}
		})
	}
}

// TestDefaultHref_InlineOnlyIgnoresExplicitHref guards against stale
// content frontmatter (older concept files baked href: /concept/{id} in
// before the inline-only design was finalised). Even when Href is set,
// inline-only types must return empty so the frontend never ships a
// link to a phantom route.
func TestDefaultHref_InlineOnlyIgnoresExplicitHref(t *testing.T) {
	a := Artefact{ID: "pkce", Type: ArtefactConcept, Href: "/concept/pkce"}
	if got := a.DefaultHref(); got != "" {
		t.Errorf("DefaultHref with explicit Href on concept = %q; want empty", got)
	}
}

// TestDefaultHref_LinkableTypes pins the canonical routes for the
// artefact types that do have pages, so a future refactor of route shapes
// breaks loudly here rather than producing silent 404s in the palette.
func TestDefaultHref_LinkableTypes(t *testing.T) {
	cases := []struct {
		name string
		a    Artefact
		want string
	}{
		{
			name: "protocol",
			a:    Artefact{ID: "oauth2", Type: ArtefactProtocol},
			want: "/protocol/oauth2",
		},
		{
			name: "flow with protocol",
			a:    Artefact{ID: "authorization-code", Type: ArtefactFlow, Protocol: "oauth2"},
			want: "/protocol/oauth2/flow/authorization-code",
		},
		{
			name: "flow without protocol falls back to looking-glass",
			a:    Artefact{ID: "ad-hoc", Type: ArtefactFlow},
			want: "/looking-glass",
		},
		{
			name: "protocol with explicit href honours it",
			a:    Artefact{ID: "oauth2", Type: ArtefactProtocol, Href: "/protocols/oauth2"},
			want: "/protocols/oauth2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.DefaultHref(); got != tc.want {
				t.Errorf("DefaultHref = %q; want %q", got, tc.want)
			}
		})
	}
}
