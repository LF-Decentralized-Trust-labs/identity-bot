package server

import (
	"encoding/json"
	"net/http"

	"identity-agent-core/provider"

	"github.com/go-chi/chi/v5"
)

// Showing somebody which operators they depend on, and letting them change it.
//
// The registry is only half the privacy argument. The other half is that a
// person can see the answer: "three services, one operator" is a sentence
// somebody can act on, and a policy engine deciding it silently on their behalf
// is not.

func (s *CoreServer) mountProviderRoutes(r chi.Router) {
	r.Get("/providers", s.handleListProviders)
	r.Post("/providers", s.handleAddProvider)
}

type providerView struct {
	ID           string   `json:"id"`
	Operator     string   `json:"operator"`
	Jurisdiction string   `json:"jurisdiction,omitempty"`
	Capabilities []string `json:"capabilities"`
	Source       string   `json:"source"`
}

// handleListProviders reports every known operator and what it offers.
//
// Owner-only. The list itself is not secret — it ships with the binary — but
// which operators an agent knows about is a hint at what it uses, and there is
// no reason to volunteer it.
func (s *CoreServer) handleListProviders(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "internal route")
		return
	}
	reg := s.Providers
	if reg == nil {
		reg = provider.Load(s.DataDir)
	}
	var out []providerView
	for _, p := range reg.All() {
		caps := p.Capabilities()
		names := make([]string, 0, len(caps))
		for _, c := range caps {
			names = append(names, string(c))
		}
		out = append(out, providerView{
			ID: p.ID, Operator: p.Operator, Jurisdiction: p.Jurisdiction,
			Capabilities: names, Source: p.Source,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"providers": out, "count": len(out)})
}

// handleAddProvider installs or replaces one operator at runtime.
//
// Runtime rather than restart-only because the whole point of the registry
// being data is that the set of operators grows. Owner-only, and recorded as
// coming from the owner rather than from anything that verified it — until who
// may sign a registry is settled, saying "you added this" is the honest
// provenance.
func (s *CoreServer) handleAddProvider(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only",
			"which operators this agent relies on is the owner's decision")
		return
	}
	var p provider.Provider
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if s.Providers == nil {
		s.Providers = provider.Load(s.DataDir)
	}
	if err := s.Providers.Add(p, "added by the owner"); err != nil {
		writeError(w, http.StatusBadRequest, "could not add provider", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"added": true, "id": p.ID})
}
