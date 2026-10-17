// Package gel gives server-rendered pages the ProtocolSoup Global Expression
// Language. tokens.css is a generated copy of design/tokens.css (run
// `node design/sync-tokens.mjs` from the repo root; never edit it here), so
// these pages use the same --ps-* roles as the app and carry no literal
// colours of their own.
package gel

import (
	_ "embed"
	"html/template"
)

//go:embed tokens.css
var tokensCSS string

// pageCSS styles a server-rendered page with the token roles: indigo-black
// canvas, raised bordered panels, the mono voice, cyan interactive controls
// with visible focus, and status as icon + label + colour.
const pageCSS = `
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  padding: 24px 16px;
  background: var(--ps-bg-base);
  color: var(--ps-fg);
  font-family: var(--ps-font-mono);
  font-size: var(--ps-text-body);
  line-height: 1.6;
}
main { max-width: 720px; margin: 0 auto; }
h1 { font-size: var(--ps-text-heading); letter-spacing: var(--ps-tracking-heading); margin: 0 0 4px; }
h2 { font-size: var(--ps-text-body); color: var(--ps-fg-muted); text-transform: uppercase; letter-spacing: 0.08em; margin: 24px 0 8px; }
p { margin: 0 0 8px; }
.muted { color: var(--ps-fg-muted); }
.panel {
  background: var(--ps-bg-raised);
  border: 1px solid var(--ps-border-default);
  border-radius: var(--ps-radius-panel);
  padding: 16px;
  margin: 0 0 16px;
}
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0; }
dt { color: var(--ps-fg-muted); }
dd { margin: 0; overflow-wrap: anywhere; }
label { display: block; color: var(--ps-fg-muted); margin: 12px 0 4px; }
input {
  width: 100%;
  padding: 10px 12px;
  font: inherit;
  color: var(--ps-fg);
  background: var(--ps-bg-base);
  border: 1px solid var(--ps-border-default);
  border-radius: var(--ps-radius-control);
}
button {
  width: 100%;
  min-height: 44px;
  padding: 10px 12px;
  font: inherit;
  text-align: left;
  color: var(--ps-fg);
  background: color-mix(in srgb, var(--ps-interactive) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--ps-interactive) 30%, transparent);
  border-radius: var(--ps-radius-control);
  cursor: pointer;
  transition: background var(--ps-duration-hover) var(--ps-ease-out);
}
button:hover { background: color-mix(in srgb, var(--ps-interactive) 20%, transparent); }
button:focus-visible, input:focus-visible {
  outline: 2px solid var(--ps-focus-ring);
  outline-offset: 2px;
}
form { margin: 0 0 8px; }
.user-email { color: var(--ps-fg-muted); }
.status { display: inline-flex; align-items: center; gap: 8px; font-weight: 600; }
.status svg { width: 18px; height: 18px; flex: none; }
.status-success { color: var(--ps-status-success); }
.status-danger { color: var(--ps-status-danger); }
.status-info { color: var(--ps-status-info); }
ul.checks { list-style: none; margin: 0; padding: 0; }
ul.checks li { padding: 8px 0; border-top: 1px solid var(--ps-border-subtle); }
ul.checks li:first-child { border-top: none; }
.check-detail { display: block; overflow-wrap: anywhere; }
.check-ref { display: block; color: var(--ps-fg-muted); font-size: var(--ps-text-caption); }
pre {
  margin: 0;
  padding: 12px;
  overflow-x: auto;
  font: inherit;
  font-size: var(--ps-text-data);
  background: var(--ps-bg-base);
  border: 1px solid var(--ps-border-subtle);
  border-radius: var(--ps-radius-control);
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
`

// PageCSS is the stylesheet for a server-rendered page: the tokens followed
// by the shared page rules.
func PageCSS() template.CSS {
	return template.CSS(tokensCSS + pageCSS)
}

// Lucide icon bodies (lucide.dev, ISC licence) for status shown as icon +
// label + colour. Each is drawn in a 24x24 viewBox with currentColor strokes.
var (
	IconSuccess = template.HTML(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>`)
	IconDanger  = template.HTML(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>`)
	IconInfo    = template.HTML(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>`)
)
