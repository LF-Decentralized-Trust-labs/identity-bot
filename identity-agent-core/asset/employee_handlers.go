package asset

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// HandleCreateEmployeeInvite mints an org-scoped employee invite. `max_uses` of 1
// is a single named hire; 0 is an open (multi-use) link. The org app renders the
// returned token as a QR code + copyable link.
func (h *Handler) HandleCreateEmployeeInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role    string `json:"role"`
		Label   string `json:"label"`
		MaxUses int    `json:"max_uses"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	inv := EmployeeInvite{
		Token:     genID(),
		Role:      body.Role,
		Label:     body.Label,
		MaxUses:   body.MaxUses,
		CreatedAt: time.Now().UTC(),
	}
	if err := h.Store.CreateEmployeeInvite(inv); err != nil {
		h.writeJSON(w, map[string]string{"error": err.Error()}, http.StatusInternalServerError)
		return
	}
	h.writeJSON(w, inv, http.StatusCreated)
}

func (h *Handler) HandleListEmployeeInvites(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, h.Store.ListEmployeeInvites(), http.StatusOK)
}

func (h *Handler) HandleRevokeEmployeeInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	h.Store.RevokeEmployeeInvite(token)
	h.writeJSON(w, map[string]string{"status": "revoked"}, http.StatusOK)
}

// HandleGetEmployeeInviteInfo is the unauthenticated lookup the accepting employee's
// agent calls (via the universal decoder) to preview what the invite is for.
func (h *Handler) HandleGetEmployeeInviteInfo(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	inv, ok := h.Store.GetEmployeeInvite(token)
	if !ok || inv.Revoked {
		h.writeJSON(w, map[string]string{"error": "invalid"}, http.StatusBadRequest)
		return
	}
	if inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses {
		h.writeJSON(w, map[string]string{"error": "exhausted"}, http.StatusBadRequest)
		return
	}
	h.writeJSON(w, inv, http.StatusOK)
}

func (h *Handler) HandleListEmployees(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, h.Store.ListEmployees(), http.StatusOK)
}
