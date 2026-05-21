package palette

import (
	"encoding/json"
	"net/http"
	"time"
)

// Handler returns the HTTP handler for POST /api/palette/query. The handler
// rejects non-POST methods, decodes the request body, dispatches to
// Service.Query, and JSON-encodes the response. Errors map to 400 (bad
// request shape) or 500 (server failure).
func (s *Service) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}

		start := time.Now()
		resp, err := s.Query(r.Context(), req)
		if err != nil {
			http.Error(w, `{"error":"query_failed"}`, http.StatusInternalServerError)
			return
		}
		resp.ElapsedMicros = time.Since(start).Microseconds()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
