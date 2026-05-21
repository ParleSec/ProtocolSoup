package palette

import (
	"strings"
	"unicode"
)

// buildSnippet returns a query-aware excerpt of body containing the
// first sentence (or two) that mention any of tokens. Matching tokens
// are wrapped in <mark>...</mark> spans. The frontend renders these as
// highlighted text — no other HTML is ever shipped from the backend so
// the renderer can treat <mark> as the only special token.
//
// Returns an empty string when no token hits the body. Callers fall back
// to the static BodyPreview in that case.
//
// Deterministic: same body + same tokens always produces the same snippet.
func buildSnippet(body string, tokens []string) string {
	if body == "" || len(tokens) == 0 {
		return ""
	}
	// Normalise: lowercase tokens and keep only meaningful ones (>=3 chars).
	clean := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.ToLower(strings.TrimSpace(t))
		if len(t) < 3 {
			continue
		}
		clean = append(clean, t)
	}
	if len(clean) == 0 {
		return ""
	}

	sentences := splitSentences(body)
	if len(sentences) == 0 {
		return ""
	}

	// Pick the first sentence that contains any token.
	best := -1
	for i, s := range sentences {
		lower := strings.ToLower(s)
		for _, tok := range clean {
			if strings.Contains(lower, tok) {
				best = i
				break
			}
		}
		if best >= 0 {
			break
		}
	}
	if best < 0 {
		return ""
	}

	// Include one sentence of trailing context when available; the snippet
	// then averages ~2 sentences which is what reads well in a result row.
	end := best + 1
	if end < len(sentences) {
		end++
	}
	excerpt := strings.TrimSpace(strings.Join(sentences[best:end], " "))

	// Cap the excerpt length so a runaway paragraph cannot inflate
	// response payloads.
	const maxLen = 360
	if len(excerpt) > maxLen {
		cut := excerpt[:maxLen]
		if sp := strings.LastIndex(cut, " "); sp > maxLen/2 {
			cut = cut[:sp]
		}
		excerpt = strings.TrimRight(cut, " ,.;:") + "..."
	}

	return highlightTokens(excerpt, clean)
}

// splitSentences slices a markdown body into rough sentences. The corpus
// uses standard English punctuation; we split on '.', '!', '?' followed by
// whitespace. We do not attempt to handle abbreviations because the corpus
// does not need it; if that changes, add a small exception list here.
func splitSentences(body string) []string {
	body = strings.ReplaceAll(body, "\r", "")
	// Treat blank-line paragraph breaks the same as sentence breaks so a
	// preceding paragraph that ends mid-sentence (rare in our corpus) does
	// not get glued to the next.
	body = strings.ReplaceAll(body, "\n\n", ". ")
	body = strings.ReplaceAll(body, "\n", " ")

	var sentences []string
	var b strings.Builder
	runes := []rune(body)
	for i, r := range runes {
		b.WriteRune(r)
		if r == '.' || r == '!' || r == '?' {
			if i+1 >= len(runes) || unicode.IsSpace(runes[i+1]) {
				s := strings.TrimSpace(b.String())
				if s != "" {
					sentences = append(sentences, s)
				}
				b.Reset()
			}
		}
	}
	if rem := strings.TrimSpace(b.String()); rem != "" {
		sentences = append(sentences, rem)
	}
	return sentences
}

// highlightTokens wraps each case-insensitive occurrence of any token with
// <mark>...</mark>. Token matches are case-insensitive but the original
// casing in body is preserved. Existing literal "<mark>" / "</mark>" in
// the body (none in the current corpus) would be passed through unchanged;
// we accept that because we control the corpus.
func highlightTokens(body string, tokens []string) string {
	if len(tokens) == 0 {
		return body
	}
	lower := strings.ToLower(body)
	type match struct{ start, end int }
	var matches []match
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		from := 0
		for {
			idx := strings.Index(lower[from:], tok)
			if idx < 0 {
				break
			}
			start := from + idx
			end := start + len(tok)
			matches = append(matches, match{start, end})
			from = end
		}
	}
	if len(matches) == 0 {
		return body
	}

	// Sort by start, then merge overlapping ranges so we never emit nested
	// <mark> tags.
	for i := 1; i < len(matches); i++ {
		for j := i; j > 0 && matches[j-1].start > matches[j].start; j-- {
			matches[j-1], matches[j] = matches[j], matches[j-1]
		}
	}
	merged := matches[:0]
	for _, m := range matches {
		if len(merged) == 0 || m.start > merged[len(merged)-1].end {
			merged = append(merged, m)
			continue
		}
		if m.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = m.end
		}
	}

	var out strings.Builder
	out.Grow(len(body) + len(merged)*15)
	last := 0
	for _, m := range merged {
		out.WriteString(body[last:m.start])
		out.WriteString("<mark>")
		out.WriteString(body[m.start:m.end])
		out.WriteString("</mark>")
		last = m.end
	}
	out.WriteString(body[last:])
	return out.String()
}
