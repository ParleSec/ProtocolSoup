package dpop

// WithCnfJKT returns a copy of claims with an RFC 7800 cnf.jkt member added,
// binding an access token to a DPoP proof key (RFC 9449 Section 4.1). claims
// may be nil; the original map is never mutated, so callers can safely pass
// a map they still hold a reference to elsewhere.
func WithCnfJKT(claims map[string]interface{}, jkt string) map[string]interface{} {
	merged := make(map[string]interface{}, len(claims)+1)
	for k, v := range claims {
		merged[k] = v
	}
	merged["cnf"] = map[string]interface{}{"jkt": jkt}
	return merged
}

// TokenType returns the RFC 9449 Section 5 token_type for a token response:
// "DPoP" when jkt is non-empty (the token is key-bound), "Bearer" otherwise.
// Shared by every token-issuing endpoint (AS or RS) that supports DPoP, so
// the two token_type strings this codebase ever emits stay in one place.
func TokenType(jkt string) string {
	if jkt != "" {
		return "DPoP"
	}
	return "Bearer"
}
