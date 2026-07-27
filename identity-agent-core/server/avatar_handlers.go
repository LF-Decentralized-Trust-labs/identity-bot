package server

import (
	"encoding/json"
	"log"
	"net/http"

	"identity-agent-core/avatar"
	"identity-agent-core/store"
)

// The avatar endpoints, and the guarantee that there is always one.
//
// Everything here runs on the device. Generating a mark, scaling a photo and
// turning a photo into a drawing are all local computation — no model, no
// upload, no service. That is what lets the onboarding screen say your picture
// never leaves your phone and have it be literally true.

// ensureAvatar gives a profile an avatar if it has none, and reports whether it
// had to. Called after identity creation so no profile is ever without one, and
// safe to call repeatedly.
func (s *CoreServer) ensureAvatar() (created bool, err error) {
	if s.DataStore == nil {
		return false, nil
	}
	profile, err := s.DataStore.GetProfile()
	if err != nil {
		return false, err
	}
	if profile == nil {
		profile = &store.ProfileData{}
	}
	if profile.Photo != "" {
		return false, nil
	}
	generated, err := avatar.Generate()
	if err != nil {
		return false, err
	}
	profile.Photo = generated
	if err := s.DataStore.SaveProfile(*profile); err != nil {
		return false, err
	}
	return true, nil
}

// handleGenerateAvatar hands back a fresh generated avatar without saving it,
// so the user can look at it and ask for another before committing. Rerolling
// costs nothing and touches nothing.
func (s *CoreServer) handleGenerateAvatar(w http.ResponseWriter, r *http.Request) {
	generated, err := avatar.Generate()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not generate an avatar", err.Error())
		return
	}
	writeJSONOK(w, map[string]string{"avatar": generated})
}

// handleStylizeAvatar turns a submitted photo into a drawing of itself. The
// image is processed in memory and never stored by this call — saving is the
// user's separate, deliberate act through the profile.
func (s *CoreServer) handleStylizeAvatar(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Image string `json:"image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Image == "" {
		writeError(w, http.StatusBadRequest, "Missing image", "send {\"image\": \"<data URI or base64>\"}")
		return
	}
	raw, err := avatar.DecodeDataURI(req.Image)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Unreadable image", err.Error())
		return
	}
	drawn, err := avatar.Stylize(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Could not stylize that image", err.Error())
		return
	}
	writeJSONOK(w, map[string]string{"avatar": drawn})
}

// normalizeProfileAvatar squares and scales whatever the user saved, so one
// oversized camera original cannot end up travelling inside every introduction.
// A value we produced ourselves is already the right shape and is left alone.
func normalizeProfileAvatar(profile *store.ProfileData) {
	if profile.Photo == "" {
		return
	}
	raw, err := avatar.DecodeDataURI(profile.Photo)
	if err != nil {
		log.Printf("[identity-agent-core] avatar: keeping the value as sent — %v", err)
		return
	}
	normalized, err := avatar.Normalize(raw)
	if err != nil {
		log.Printf("[identity-agent-core] avatar: could not normalize, keeping as sent — %v", err)
		return
	}
	profile.Photo = normalized
}

func writeJSONOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
