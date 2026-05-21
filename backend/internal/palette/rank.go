package palette

import (
	"sort"
)

// scored is a candidate that has been through the ranker. It carries the
// final score plus the chosen match reasons in display order.
type scored struct {
	cand    *candidate
	payload ArtefactPayload
	score   float64
	reasons []MatchReason
}

// rankCandidates applies the deterministic scoring function, picks the top
// reasons per row, and assembles the final result + refinement chip lists.
func rankCandidates(cands map[string]*candidate, parsed ParsedQuery, cat catalog, weights Weights, limit int) ([]Result, []RefinementChip) {
	var scoredAll []scored

	for id, c := range cands {
		payload, ok := cat.artefacts[id]
		if !ok {
			continue
		}
		if !passScope(payload, parsed) {
			continue
		}
		if !passFilters(payload, parsed) {
			continue
		}

		s := score(c, payload, parsed, weights)
		scoredAll = append(scoredAll, s)
	}

	// Stable sort: by descending score, then by id ascending for
	// determinism when scores tie.
	sort.SliceStable(scoredAll, func(i, j int) bool {
		if scoredAll[i].score != scoredAll[j].score {
			return scoredAll[i].score > scoredAll[j].score
		}
		return scoredAll[i].cand.ID < scoredAll[j].cand.ID
	})

	if len(scoredAll) > limit {
		scoredAll = scoredAll[:limit]
	}

	results := make([]Result, 0, len(scoredAll))
	for _, s := range scoredAll {
		results = append(results, toResult(s, cat, parsed))
	}

	chips := detectRefinementChips(scoredAll, parsed)
	return results, chips
}

// passScope keeps only artefacts of the requested type, mapping the public
// scope name to the artefact type used in the index.
func passScope(p ArtefactPayload, parsed ParsedQuery) bool {
	if parsed.Scope == "" {
		return true
	}
	wantType, ok := scopeToType[parsed.Scope]
	if !ok {
		return true
	}
	return p.Type == wantType
}

func passFilters(p ArtefactPayload, parsed ParsedQuery) bool {
	for _, f := range parsed.Filters {
		if !payloadHasAxisValue(p, f.Axis, f.Value) {
			return false
		}
	}
	return true
}

func payloadHasAxisValue(p ArtefactPayload, axis, value string) bool {
	values := axisValues(p, axis)
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func axisValues(p ArtefactPayload, axis string) []string {
	switch axis {
	case AxisUseCases:
		return p.UseCases
	case AxisActors:
		return p.Actors
	case AxisPatterns:
		return p.Patterns
	case AxisProblemDomains:
		return p.ProblemDomains
	}
	return nil
}

// score assigns a numeric score and selects up to two visible match reasons
// for the row.
//
//	score = w_bm25 * bm25_norm
//	      + w_axis * sum(axis weights of matched axis values)
//	      + w_edge * edge_proximity
//	      + w_runnable * runnable_boost (only when query is vague)
//	      + w_alias_artefact * alias-artefact hit
//	      + w_protocol_name * protocol-name hit
//	      + w_status_live * status pref
//
// Use-case axis matches outweigh other axes by construction; protocol-name
// alias hits land between use-case and pattern/actor.
func score(c *candidate, payload ArtefactPayload, parsed ParsedQuery, weights Weights) scored {
	var total float64
	var reasons []MatchReason

	if c.BM25 > 0 {
		w := weights.BM25 * c.BM25
		total += w
		reasons = append(reasons, MatchReason{
			Kind:          "fts",
			MatchedPhrase: c.BM25Phrase,
			Weight:        w,
		})
	}

	axisSeen := make(map[string]struct{})
	for _, hit := range c.axisHits {
		key := hit.axis + "::" + hit.value
		if _, dup := axisSeen[key]; dup {
			continue
		}
		axisSeen[key] = struct{}{}
		w := weightForAxis(weights, hit.axis)
		total += w
		reasons = append(reasons, MatchReason{
			Kind:         "axis",
			Axis:         hit.axis,
			Value:        hit.value,
			MatchedToken: hit.matchedToken,
			Weight:       w,
		})
	}

	if c.protocolHit != nil {
		w := weights.ProtocolName
		total += w
		reasons = append(reasons, MatchReason{
			Kind:         "protocol-name",
			Artefact:     payload.ID,
			MatchedToken: c.protocolHit.matchedToken,
			Weight:       w,
		})
	}

	aliasArtefactSeen := make(map[string]struct{})
	for _, h := range c.aliasHits {
		if h.artefact == "" {
			continue
		}
		if _, dup := aliasArtefactSeen[h.artefact]; dup {
			continue
		}
		aliasArtefactSeen[h.artefact] = struct{}{}
		if h.artefact != payload.ID {
			continue
		}
		w := weights.AliasArtefact
		total += w
		reasons = append(reasons, MatchReason{
			Kind:         "alias",
			Artefact:     h.artefact,
			MatchedToken: h.matchedToken,
			Weight:       w,
		})
	}

	if len(c.edgeHits) > 0 {
		w := weights.Edge * float64(len(c.edgeHits)) / float64(1+len(c.edgeHits))
		total += w
		reasons = append(reasons, MatchReason{
			Kind:     "edge",
			Artefact: c.edgeHits[0].via,
			EdgeKind: c.edgeHits[0].kind,
			Weight:   w,
		})
	}

	if parsed.IsVague() && payload.Runnable {
		w := weights.RunnableBoost
		total += w
		reasons = append(reasons, MatchReason{
			Kind:   "runnable",
			Weight: w,
		})
	}

	if payload.Status == StatusLive {
		total += weights.StatusLivePref
	}

	// Pick at most two visible reasons by weight, descending.
	sort.SliceStable(reasons, func(i, j int) bool {
		if reasons[i].Weight != reasons[j].Weight {
			return reasons[i].Weight > reasons[j].Weight
		}
		// Tie-breaker so the choice is deterministic.
		return reasonKey(reasons[i]) < reasonKey(reasons[j])
	})
	if len(reasons) > 2 {
		reasons = reasons[:2]
	}

	return scored{cand: c, payload: payload, score: total, reasons: reasons}
}

func reasonKey(r MatchReason) string {
	return r.Kind + "|" + r.Axis + "|" + r.Value + "|" + r.Artefact + "|" + r.MatchedToken + "|" + r.EdgeKind
}

func weightForAxis(w Weights, axis string) float64 {
	switch axis {
	case AxisUseCases:
		return w.UseCase
	case AxisProblemDomains:
		return w.ProblemDomain
	case AxisActors:
		return w.Actor
	case AxisPatterns:
		return w.Pattern
	}
	return 0
}

// toResult turns a scored candidate into the externally-visible Result row.
// AxisChips prioritises matched axis values (so they appear first) and then
// fills with the artefact's remaining axis values.
func toResult(s scored, cat catalog, parsed ParsedQuery) Result {
	matched := make(map[string]struct{})
	for _, r := range s.reasons {
		if r.Axis == "" || r.Value == "" {
			continue
		}
		matched[r.Axis+"::"+r.Value] = struct{}{}
	}

	var chips []AxisChip
	addChip := func(axis, value string) {
		chips = append(chips, AxisChip{Axis: axis, Value: value})
	}

	// Matched chips first, in axis order.
	for _, axis := range AllAxes {
		for _, v := range axisValues(s.payload, axis) {
			if _, ok := matched[axis+"::"+v]; ok {
				addChip(axis, v)
			}
		}
	}
	// Remaining axis values up to a sensible cap.
	for _, axis := range AllAxes {
		for _, v := range axisValues(s.payload, axis) {
			if _, ok := matched[axis+"::"+v]; ok {
				continue
			}
			if len(chips) >= 6 {
				break
			}
			addChip(axis, v)
		}
		if len(chips) >= 6 {
			break
		}
	}

	result := Result{
		ID:               s.payload.ID,
		Type:             s.payload.Type,
		Name:             s.payload.Name,
		Summary:          s.payload.Summary,
		Protocol:         s.payload.Protocol,
		AxisChips:        chips,
		MatchReasons:     s.reasons,
		Runnable:         s.payload.Runnable,
		Href:             s.payload.Href,
		Score:            s.score,
		Status:           s.payload.Status,
		Body:             s.payload.Body,
		BodyPreview:      s.payload.BodyPreview,
		NormativeAnchors: s.payload.NormativeAnchors,
		RelatedConcepts:  s.payload.RelatedConcepts,
	}
	if result.Runnable && s.payload.Type == ArtefactFlow {
		result.RunURL = runURLFor(s.payload)
	}
	if s.payload.Type == ArtefactSpecAssertion {
		result.SpecAssertion = &SpecAssertionDetails{
			NormativeLevel: s.payload.NormativeLevel,
			AssertionText:  s.payload.AssertionText,
			Anchors:        s.payload.NormativeAnchors,
		}
	}
	if snip := buildSnippet(s.payload.Body, snippetTokens(parsed)); snip != "" {
		result.Snippet = snip
	}
	return result
}

// snippetTokens returns the union of tokens that should highlight in body
// snippets: free tokens, alias-matched tokens (which would otherwise be
// consumed out of FreeTokens), and explicit quoted phrases. Without alias
// tokens, a query like "pkce" — which the parser resolves entirely as an
// alias to the PKCE artefact — would produce zero free tokens and no
// snippet highlighting in the rendered result.
func snippetTokens(p ParsedQuery) []string {
	out := make([]string, 0, len(p.FreeTokens)+len(p.Resolved)+len(p.PhraseMatches))
	out = append(out, p.FreeTokens...)
	seen := make(map[string]struct{}, len(out))
	for _, t := range out {
		seen[t] = struct{}{}
	}
	for _, r := range p.Resolved {
		if r.MatchedToken == "" {
			continue
		}
		if _, ok := seen[r.MatchedToken]; ok {
			continue
		}
		seen[r.MatchedToken] = struct{}{}
		out = append(out, r.MatchedToken)
	}
	for _, phr := range p.PhraseMatches {
		if phr == "" {
			continue
		}
		if _, ok := seen[phr]; ok {
			continue
		}
		seen[phr] = struct{}{}
		out = append(out, phr)
	}
	return out
}

// runURLFor returns the Looking Glass run URL for a runnable flow. The
// frontend POSTs to /api/protocols/{protocol}/demo/{backend_id} via the
// Looking Glass page; the URL itself is what the palette navigates to.
func runURLFor(p ArtefactPayload) string {
	protocol := p.Protocol
	if protocol == "" && len(p.Protocols) == 1 {
		protocol = p.Protocols[0]
	}
	backend := p.BackendID
	if backend == "" {
		backend = p.ID
	}
	if protocol == "" {
		return ""
	}
	return "/looking-glass?protocol=" + protocol + "&flow=" + backend
}

// refinementChipMinDistinct sets how many distinct values an axis must show
// across the top results before we surface refinement chips for it. Below
// this threshold the axis is not interestingly ambiguous.
const refinementChipMinDistinct = 3

// detectRefinementChips counts distinct axis values across the top results
// and emits chips for any axis whose distinct-value count meets the
// threshold. The chips are ordered by descending count then ascending value
// for determinism.
func detectRefinementChips(top []scored, parsed ParsedQuery) []RefinementChip {
	if len(top) == 0 {
		return nil
	}
	counts := make(map[string]map[string]int)
	for _, axis := range AllAxes {
		counts[axis] = make(map[string]int)
	}
	for _, s := range top {
		for _, axis := range AllAxes {
			for _, v := range axisValues(s.payload, axis) {
				counts[axis][v]++
			}
		}
	}

	existingFilters := make(map[string]struct{})
	for _, f := range parsed.Filters {
		existingFilters[f.Axis+"::"+f.Value] = struct{}{}
	}

	var chips []RefinementChip
	for _, axis := range AllAxes {
		if len(counts[axis]) < refinementChipMinDistinct {
			continue
		}
		for value, n := range counts[axis] {
			if _, applied := existingFilters[axis+"::"+value]; applied {
				continue
			}
			chips = append(chips, RefinementChip{Axis: axis, Value: value, Count: n})
		}
	}

	sort.SliceStable(chips, func(i, j int) bool {
		if chips[i].Count != chips[j].Count {
			return chips[i].Count > chips[j].Count
		}
		if chips[i].Axis != chips[j].Axis {
			return chips[i].Axis < chips[j].Axis
		}
		return chips[i].Value < chips[j].Value
	})

	// Cap chip list. Too many chips just clutter the UI.
	if len(chips) > 8 {
		chips = chips[:8]
	}
	return chips
}
