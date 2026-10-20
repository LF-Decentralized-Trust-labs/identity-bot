package server

import (
	"net/http"

	"identity-agent-core/schemas"

	"github.com/go-chi/chi/v5"
	keri "github.com/grapeid/keri-go"
)

// handlePublicSchemaServe serves a credential schema exactly as its identifier
// was computed over, so a verifier can recompute the digest and confirm it is
// the schema a credential names. Only schemas whose identifier is a real digest
// are served; a placeholder identifier proves nothing, so it is not offered as
// though it did.
func (s *CoreServer) handlePublicSchemaServe(w http.ResponseWriter, r *http.Request) {
	said := chi.URLParam(r, "said")
	sch := schemas.Get(said)
	if sch == nil {
		http.NotFound(w, r)
		return
	}
	// Served only if the document digests to the identifier it is asked for by,
	// which is what a placeholder identifier fails. Checked here, from the
	// catalog every schema is registered in, so a schema made real later is
	// served without anybody remembering to add it to a list.
	if got, err := keri.VerifySchema([]byte(sch.JSON)); err != nil || got != said {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/schema+json")
	_, _ = w.Write([]byte(sch.JSON))
}
