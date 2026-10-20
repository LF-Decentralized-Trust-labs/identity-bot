package server

import (
	"net/http"

	"identity-agent-core/schemas"

	"github.com/go-chi/chi/v5"
)

// handlePublicSchemaServe serves a credential schema exactly as its identifier
// was computed over, so a verifier can recompute the digest and confirm it is
// the schema a credential names. Only schemas whose identifier is a real digest
// are served; a placeholder identifier proves nothing, so it is not offered as
// though it did.
func (s *CoreServer) handlePublicSchemaServe(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	for _, g := range schemas.AssetGrants {
		if g.Schema.SAID == said {
			w.Header().Set("Content-Type", "application/schema+json")
			_, _ = w.Write([]byte(g.Schema.JSON))
			return
		}
	}
	http.NotFound(w, r)
}
