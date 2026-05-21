package palette

import (
	"strings"
	"unicode"
)

// ParsedQuery is the structured form of a request after tokenisation and
// alias resolution. Every field is deterministic given the same input and
// catalog state.
type ParsedQuery struct {
	Original string

	// LowerNormalised is the query lower-cased with extraneous whitespace
	// collapsed. Used both for substring lookups and for record-keeping.
	LowerNormalised string

	// Scope and Filters are forwarded from the request after validation.
	Scope   string
	Filters []Filter

	// PhraseMatches contains exact-phrase requirements extracted from
	// double-quoted spans in the query.
	PhraseMatches []string

	// FreeTokens are tokens that did not participate in an alias match.
	FreeTokens []string

	// Resolved is the list of alias resolutions hit by the query. Each
	// resolution carries the original substring that matched so the ranker
	// can attach it to a result row as a match reason.
	Resolved []ResolvedAlias
}

// ResolvedAlias is one alias hit. Either (Axis,Value) or Artefact is set,
// matching the AliasCanonical shape on disk.
type ResolvedAlias struct {
	MatchedToken string `json:"matched_token"`
	Axis         string `json:"axis,omitempty"`
	Value        string `json:"value,omitempty"`
	Artefact     string `json:"artefact,omitempty"`
}

// IsVague reports whether the runnable boost applies. A query is "vague"
// when the user clearly has no specific concept in mind: no scope filter,
// no explicit phrase, and no resolved canonical value.
func (p ParsedQuery) IsVague() bool {
	if p.Scope != "" {
		return false
	}
	if len(p.Filters) > 0 {
		return false
	}
	if len(p.PhraseMatches) > 0 {
		return false
	}
	if len(p.Resolved) > 0 {
		return false
	}
	if len(p.FreeTokens) == 0 {
		return false
	}
	return true
}

// parseQuery tokenises and resolves the request. Resolution proceeds via a
// greedy longest-match scan over up to 4-gram windows so multi-word aliases
// such as "single sign-on" win over their component tokens.
func parseQuery(req Request, cat catalog) ParsedQuery {
	out := ParsedQuery{
		Original: req.Q,
		Scope:    sanitiseScope(req.Scope),
		Filters:  filterValidFilters(req.Filters),
	}

	q := req.Q
	q, phrases := extractPhrases(q)
	out.PhraseMatches = phrases

	q = strings.ToLower(q)
	out.LowerNormalised = strings.TrimSpace(collapseSpaces(q))

	q, prefixScope := extractScopePrefix(q)
	if out.Scope == "" && prefixScope != "" {
		out.Scope = prefixScope
	}

	tokens := tokenise(q)

	used := make([]bool, len(tokens))
	for windowSize := 4; windowSize >= 1; windowSize-- {
		for start := 0; start+windowSize <= len(tokens); start++ {
			if anyUsed(used, start, windowSize) {
				continue
			}
			phrase := strings.Join(tokens[start:start+windowSize], " ")
			rows, ok := cat.aliases[phrase]
			if !ok {
				continue
			}
			for _, r := range rows {
				out.Resolved = append(out.Resolved, ResolvedAlias{
					MatchedToken: phrase,
					Axis:         r.Axis,
					Value:        canonicalValue(r),
					Artefact:     canonicalArtefact(r),
				})
			}
			markUsed(used, start, windowSize)
		}
	}

	for i, tok := range tokens {
		if used[i] {
			continue
		}
		if isStopword(tok) {
			continue
		}
		out.FreeTokens = append(out.FreeTokens, tok)
	}
	return out
}

func canonicalValue(r aliasRow) string {
	if r.Axis != "" {
		return r.Canonical
	}
	return ""
}

func canonicalArtefact(r aliasRow) string {
	if r.Axis != "" {
		return ""
	}
	return r.Canonical
}

// scopePrefixMap defines accepted "kind:" prefixes in the free-form query.
var scopePrefixMap = map[string]string{
	"flow":     ScopeFlow,
	"protocol": ScopeProtocol,
	"spec":     ScopeSpec,
	"concept":  ScopeConcept,
}

// extractScopePrefix consumes a leading "kind:" token if present and returns
// the remaining query and the inferred scope. The check is performed on
// already-lowercased input.
func extractScopePrefix(q string) (string, string) {
	q = strings.TrimSpace(q)
	for prefix, scope := range scopePrefixMap {
		if strings.HasPrefix(q, prefix+":") {
			return strings.TrimSpace(q[len(prefix)+1:]), scope
		}
	}
	return q, ""
}

// extractPhrases pulls out every double-quoted span. The returned query has
// those spans replaced with spaces so subsequent tokenisation does not see
// them again.
func extractPhrases(q string) (string, []string) {
	var phrases []string
	var builder strings.Builder
	builder.Grow(len(q))

	inside := false
	start := 0
	for i, r := range q {
		if r == '"' {
			if inside {
				phrase := strings.TrimSpace(q[start:i])
				if phrase != "" {
					phrases = append(phrases, phrase)
				}
				inside = false
			} else {
				inside = true
				start = i + 1
			}
			builder.WriteByte(' ')
			continue
		}
		if !inside {
			builder.WriteRune(r)
		}
	}
	return builder.String(), phrases
}

// tokenise splits on whitespace and strips trailing punctuation. Hyphens and
// underscores stay so values like "did:web" or "openid-configuration" survive
// (after the colon is also rewritten to a space — see explicit handling).
func tokenise(q string) []string {
	q = strings.ReplaceAll(q, "/", " ")
	q = strings.ReplaceAll(q, ":", " ")
	q = strings.ReplaceAll(q, ",", " ")
	q = strings.ReplaceAll(q, ";", " ")
	q = strings.ReplaceAll(q, "?", " ")
	q = strings.ReplaceAll(q, "!", " ")
	q = strings.ReplaceAll(q, ".", " ")
	fields := strings.Fields(q)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimFunc(f, func(r rune) bool {
			return unicode.IsPunct(r) && r != '-' && r != '_'
		})
		if f == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// stopwords is intentionally small — the corpus is too domain-specific to
// drop most "common" words.
var stopwords = map[string]struct{}{
	"a": {}, "an": {}, "the": {}, "of": {}, "to": {}, "for": {},
	"with": {}, "and": {}, "or": {}, "in": {}, "on": {}, "at": {},
	"my": {}, "our": {}, "your": {}, "their": {}, "this": {}, "that": {},
	"how": {}, "what": {}, "where": {}, "when": {}, "do": {}, "does": {},
	"i": {}, "me": {}, "we": {}, "is": {}, "are": {},
}

func isStopword(t string) bool {
	_, ok := stopwords[t]
	return ok
}

func collapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func anyUsed(used []bool, start, n int) bool {
	for i := start; i < start+n; i++ {
		if used[i] {
			return true
		}
	}
	return false
}

func markUsed(used []bool, start, n int) {
	for i := start; i < start+n; i++ {
		used[i] = true
	}
}

func sanitiseScope(scope string) string {
	if _, ok := scopeToType[scope]; ok {
		return scope
	}
	return ""
}

// filterValidFilters drops filter entries with empty axis or value and
// rejects any with an unknown axis name.
func filterValidFilters(filters []Filter) []Filter {
	out := make([]Filter, 0, len(filters))
	for _, f := range filters {
		if f.Axis == "" || f.Value == "" {
			continue
		}
		if !axisAllowed(f.Axis) {
			continue
		}
		out = append(out, f)
	}
	return out
}
