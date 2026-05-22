package palette

import "testing"

// TestRunURLForFlow_DeepLinkContract pins the wire shape of the Looking Glass deep-link URL emitted on PaletteResult.run_url.
//
// The shape `/looking-glass?protocol=X&flow=Y` is the contract that the frontend's `parseFlowDeepLink` (and the LookingGlass deep-link effect) depend on.
// Changing the path or the parameter names here withoutpdating the frontend would silently break:
//
//   - Cmd+K palette dispatch to a runnable flow.
//   - Shared/bookmarked /looking-glass URLs.
//   - In-page palette re-dispatch while already on /looking-glass.
//
// This test makes that contract 'loud' rather than letting it drift.
func TestRunURLForFlow_DeepLinkContract(t *testing.T) {
	cases := []struct {
		name string
		in   ArtefactPayload
		want string
	}{
		{
			name: "protocol + id, no backend_id",
			in: ArtefactPayload{
				ID:       "authorization-code",
				Protocol: "oauth2",
			},
			want: "/looking-glass?protocol=oauth2&flow=authorization-code",
		},
		{
			name: "backend_id overrides id when set",
			in: ArtefactPayload{
				ID:        "authorization-code-pkce",
				Protocol:  "oauth2",
				BackendID: "authorization_code_pkce",
			},
			want: "/looking-glass?protocol=oauth2&flow=authorization_code_pkce",
		},
		{
			name: "single-element Protocols falls back when Protocol empty",
			in: ArtefactPayload{
				ID:        "issue-credential",
				Protocols: []string{"oid4vci"},
			},
			want: "/looking-glass?protocol=oid4vci&flow=issue-credential",
		},
		{
			name: "no protocol resolves to empty (frontend skips dispatch)",
			in: ArtefactPayload{
				ID: "orphan-flow",
			},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runURLFor(tc.in); got != tc.want {
				t.Errorf("runURLFor = %q; want %q", got, tc.want)
			}
		})
	}
}
