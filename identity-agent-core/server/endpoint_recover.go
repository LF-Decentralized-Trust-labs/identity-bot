package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// Finding somebody whose address has stopped working.
//
// This is the consuming half of endpoint publication, and without it the
// publishing side is decoration: records reach witnesses and nothing ever asks
// for them.
//
// The situation it exists for is ordinary rather than exotic. A contact was
// added months ago and their OOBI was stored. Since then their relay changed
// hands, shut down, or their allocation lapsed. The stored URL now resolves to
// nothing. Neither party did anything wrong and nothing about the identity has
// changed — only where it answers.
//
// The way out is already on disk. Resolving that contact stored their KEL, and
// the inception event names their witnesses, so there is somewhere to ask that
// does not depend on the address that just died. Witness endpoints are stable
// by construction: for a commercial witness that is the service being sold.
//
// A witness cannot lie usefully here. Every record it serves is signed by the
// controller it describes, so the worst a hostile or confused witness can do is
// withhold or serve something stale — never redirect a relationship somewhere
// its owner did not sign for.

// recoveredEndpoint is a current address for a contact, and where it was found.
//
// The witness is reported because "we found this somewhere other than where you
// looked" is part of the answer. A caller that cannot see which witness
// answered cannot judge how much to trust a surprising result.
type recoveredEndpoint struct {
	ControllerAID string `json:"controller_aid"`
	URL           string `json:"url"`
	Scheme        string `json:"scheme,omitempty"`
	Role          string `json:"role,omitempty"`
	SAID          string `json:"said"`
	Stamp         string `json:"stamp,omitempty"`
	Signature     string `json:"signature,omitempty"`
	FoundVia      string `json:"found_via"`
}

// witnessesFromStoredKEL reads a contact's witness list out of the KEL we
// already hold.
//
// This is the step that makes recovery possible without a working address: the
// inception event's `b` field names the witnesses, so nothing here needs to
// reach the contact first. A later rotation may change the set, so the LAST
// event that carries one wins.
func witnessesFromStoredKEL(kel []map[string]interface{}) []string {
	var witnesses []string
	for _, event := range kel {
		raw, ok := event["b"]
		if !ok {
			continue
		}
		list, ok := raw.([]interface{})
		if !ok {
			continue
		}
		var current []string
		for _, w := range list {
			if aid, ok := w.(string); ok && aid != "" {
				current = append(current, aid)
			}
		}
		// An empty `b` on a rotation means the witness set was cleared, which
		// is different from the event not mentioning witnesses at all. Only a
		// present field replaces what came before.
		witnesses = current
	}
	return witnesses
}

// witnessBaseURL turns a witness's OOBI into the base we can query.
func witnessBaseURL(oobi string) string {
	base := oobi
	if idx := strings.Index(oobi, "/public/oobi/"); idx != -1 {
		base = oobi[:idx]
	}
	return strings.TrimRight(base, "/")
}

// RecoverContactEndpoint asks a contact's witnesses where that contact is now.
//
// Returns the first usable answer rather than polling everything. A counterparty
// needs somewhere that works, not a survey — and each extra query is another
// operator learning that this agent is looking for that contact.
func (s *CoreServer) RecoverContactEndpoint(contactAID string) (*recoveredEndpoint, error) {
	if s.DataStore == nil {
		return nil, fmt.Errorf("no data store")
	}

	kelRecord, err := s.DataStore.GetContactKEL(contactAID)
	if err != nil {
		return nil, fmt.Errorf("read stored KEL: %w", err)
	}
	if kelRecord == nil || len(kelRecord.KEL) == 0 {
		// Nothing to work from. First contact genuinely needs a working
		// address; there is no way to bootstrap from an identity never seen.
		return nil, fmt.Errorf("no stored KEL for %s — recovery needs a contact resolved at least once", contactAID)
	}

	witnessAIDs := witnessesFromStoredKEL(kelRecord.KEL)
	if len(witnessAIDs) == 0 {
		return nil, fmt.Errorf("%s named no witnesses, so there is nowhere to ask", contactAID)
	}

	contacts, err := s.DataStore.GetContacts()
	if err != nil {
		return nil, fmt.Errorf("read contacts: %w", err)
	}
	known := map[string]store.ContactRecord{}
	for _, c := range contacts {
		known[c.AID] = c
	}

	var lastErr error
	for _, witnessAID := range witnessAIDs {
		// A witness we have never resolved has no URL on file. Skipping is
		// correct: guessing one would at best fail and at worst send this query
		// to a stranger.
		w, ok := known[witnessAID]
		if !ok || w.OobiURL == "" {
			lastErr = fmt.Errorf("no address on file for witness %s", witnessAID)
			continue
		}
		found, err := s.askWitnessForEndpoint(witnessBaseURL(w.OobiURL), contactAID)
		if err != nil {
			lastErr = err
			log.Printf("[endpoint] witness %s could not answer for %s: %v", witnessAID, contactAID, err)
			continue
		}
		if found != nil {
			found.FoundVia = witnessAID
			return found, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("no witness of %s had a current address: %w", contactAID, lastErr)
	}
	return nil, fmt.Errorf("no witness of %s holds a current address", contactAID)
}

// askWitnessForEndpoint queries one witness and returns the newest location it
// holds.
//
// Location records are what a caller can act on; a role record says who serves
// an identity but not where, so it cannot answer "where do I reach this now".
// An empty URL is respected rather than skipped — the controller published it to
// say "not here", and treating it as absent would hand back an older address
// they had deliberately withdrawn.
func (s *CoreServer) askWitnessForEndpoint(base, contactAID string) (*recoveredEndpoint, error) {
	url := base + "/api/witness/endpoint/" + contactAID
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("witness returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var payload struct {
		Records []struct {
			SAID      string `json:"said"`
			CID       string `json:"cid"`
			Route     string `json:"route"`
			Role      string `json:"role"`
			Scheme    string `json:"scheme"`
			URL       string `json:"url"`
			Stamp     string `json:"stamp"`
			Signature string `json:"signature"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("unreadable witness response: %w", err)
	}

	// Records arrive newest first. The first location record is the current
	// answer; older ones are kept by the witness so a caller can tell "moved"
	// from "never said", but they are not what to act on.
	for _, r := range payload.Records {
		if r.Route != "/loc/scheme" {
			continue
		}
		if r.CID != "" && r.CID != contactAID {
			// A witness serving records for a different controller under this
			// AID is either confused or hostile. Either way it is not an answer.
			continue
		}
		return &recoveredEndpoint{
			ControllerAID: contactAID,
			URL:           r.URL,
			Scheme:        r.Scheme,
			Role:          r.Role,
			SAID:          r.SAID,
			Stamp:         r.Stamp,
			Signature:     r.Signature,
		}, nil
	}
	return nil, nil
}

// mountEndpointRoutes exposes publication and recovery.
//
// Both are owner-only. Publication moves where this agent claims to be, and
// recovery discloses which contacts this agent is trying to reach — the second
// is the quieter of the two and the easier to leave open by accident.
func (s *CoreServer) mountEndpointRoutes(r chi.Router) {
	r.Post("/endpoint/publish", s.handlePublishEndpoint)
	r.Get("/endpoint/recover/{contact_aid}", s.handleRecoverEndpoint)
}

// handlePublishEndpoint signs and publishes where one of this agent's own
// pairwise identities can currently be reached.
func (s *CoreServer) handlePublishEndpoint(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "publishing an address is the owner's decision")
		return
	}
	var req struct {
		AID string `json:"aid"`
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.AID == "" {
		writeError(w, http.StatusBadRequest, "aid required", "")
		return
	}
	// An empty URL is allowed and meaningful: it withdraws the address rather
	// than leaving a dead one standing as the current answer.
	if err := s.PublishEndpointLocation(r.Context(), req.AID, req.URL); err != nil {
		writeError(w, http.StatusBadRequest, "could not publish", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"published": true, "aid": req.AID, "url": req.URL})
}

// handleRecoverEndpoint asks a contact's witnesses where that contact is now,
// for use when the address on file has stopped working.
func (s *CoreServer) handleRecoverEndpoint(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only",
			"which contacts this agent is looking for is the owner's business")
		return
	}
	contactAID := chi.URLParam(r, "contact_aid")
	if contactAID == "" {
		writeError(w, http.StatusBadRequest, "contact_aid required", "")
		return
	}
	found, err := s.RecoverContactEndpoint(contactAID)
	if err != nil {
		writeError(w, http.StatusNotFound, "no current address found", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(found)
}
