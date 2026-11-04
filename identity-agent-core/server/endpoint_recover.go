package server

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/endpointrecord"
	"identity-agent-core/iacrypto"
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
// looked" is part of the answer ("remembered" when no witness had anything newer
// than what this agent had already verified). Every field but FoundVia is the
// contact's own signed record, which RecoverContactEndpoint has already checked
// against the contact's verified key log.
type recoveredEndpoint struct {
	ControllerAID string `json:"controller_aid"`
	// Origin is scheme://host:port, the one origin the contact signed.
	Origin    string `json:"origin"`
	Issued    string `json:"issued"`
	Signature string `json:"signature"`
	FoundVia  string `json:"found_via"`
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
// Asks every witness the contact names and returns the newest record any of them
// holds that the contact signed. Asking only the first would let one stale or
// hostile witness serve an older address the contact really did sign; the cost
// is that each of the contact's own witnesses learns this agent is looking.
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

	// WHAT THE CONTACT SIGNED IS CHECKED AGAINST THE KEY ITS VERIFIED LOG NAMES,
	// not against anything a witness says. Without a verified log there is
	// nothing to check a record against, so there is no answer: an address
	// nobody can prove is the contact's is the one a reverse proxy would offer.
	key, err := s.ownerKeyFromAVerifiedLog(contactAID)
	if err != nil {
		return nil, fmt.Errorf("%s's key log is not verified, so no record can be checked against it: %w", contactAID, err)
	}
	raw, _, err := iacrypto.DecodeEd25519Key(key, false)
	if err != nil {
		return nil, fmt.Errorf("%s's current key is not an Ed25519 key: %w", contactAID, err)
	}

	// THE NEWEST VERIFIED RECORD WINS, FROM EVERY WITNESS ASKED AND FROM WHAT THIS
	// AGENT HAS ALREADY SEEN. Taking the first witness that answers would let one
	// witness, the contact's own or a stale one, hand back an older address the
	// contact really did sign: a rollback to a host that has since lapsed or been
	// taken over. So every witness the contact names is asked, a withdrawal
	// outranks the address records before it, and nothing older than the newest
	// record this agent has verified is ever returned.
	seen, err := s.newestEndpointRecord(store.EndpointRecordSeen, contactAID, ed25519.PublicKey(raw))
	if err != nil {
		return nil, fmt.Errorf("read what was seen before: %w", err)
	}
	best, foundVia := seen, "remembered"
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
		found, err := s.askWitnessForEndpoint(witnessBaseURL(w.OobiURL), contactAID, ed25519.PublicKey(raw))
		if err != nil {
			lastErr = err
			log.Printf("[endpoint] witness %s could not answer for %s: %v", witnessAID, contactAID, err)
			continue
		}
		if found != nil && (best == nil || endpointrecord.Newer(*found, *best)) {
			best, foundVia = found, witnessAID
		}
	}

	if best == nil {
		if lastErr != nil {
			return nil, fmt.Errorf("no witness of %s had a current address: %w", contactAID, lastErr)
		}
		return nil, fmt.Errorf("no witness of %s holds a current address", contactAID)
	}
	if foundVia != "remembered" {
		// Kept, so an older record is refused from now on whoever offers it.
		if err := s.keepEndpointRecord(store.EndpointRecordSeen, *best, endpointRecordObject(*best)); err != nil {
			log.Printf("[endpoint] could not remember %s's record: %v", contactAID, err)
		}
	}
	if best.Withdrawn() {
		// The contact said it is nowhere, after anything it said before. That is
		// an answer, but not an address, and no older address stands in for it.
		return nil, fmt.Errorf("the contact has said it is not reachable anywhere now")
	}
	return &recoveredEndpoint{
		ControllerAID: contactAID,
		Origin:        best.Origin,
		Issued:        best.Issued,
		Signature:     best.Signature,
		FoundVia:      foundVia,
	}, nil
}

func endpointRecordObject(r endpointrecord.Record) map[string]any {
	return map[string]any{"type": r.Type, "aid": r.AID, "origin": r.Origin, "issued": r.Issued, "signature": r.Signature}
}

// askWitnessForEndpoint queries one witness and returns the contact's newest
// signed record it holds, once it has been checked against key.
//
// A withdrawal comes back like an address record. The controller published it
// to say "not here", and treating it as absent would hand back an older address
// they had deliberately withdrawn.
func (s *CoreServer) askWitnessForEndpoint(base, contactAID string, key ed25519.PublicKey) (*endpointrecord.Record, error) {
	url := base + "/api/witness/endpoint/" + contactAID
	// A witness's address is the one a contact recorded, and its name may have
	// been pointed somewhere internal since: held to the address dialled.
	resp, err := s.peerClient(10*time.Second, url).Get(url)
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
		Record map[string]any `json:"record"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("unreadable witness response: %w", err)
	}
	record, err := endpointrecord.Parse(payload.Record)
	if err != nil {
		return nil, fmt.Errorf("the witness's answer is not an endpoint record: %w", err)
	}
	// A record for a different controller, one not signed by the contact's
	// current key, or one outside the form is not an answer, whoever served it.
	if record.AID != contactAID {
		return nil, fmt.Errorf("the witness answered with a record for somebody else")
	}
	if err := record.Verify(key, time.Now()); err != nil {
		return nil, fmt.Errorf("the witness's record is not the contact's statement: %w", err)
	}
	// A withdrawal is returned like any other record: it is the contact's
	// newest word, and RecoverContactEndpoint weighs it against the rest.
	return &record, nil
}

// mountEndpointRoutes exposes publication and recovery.
//
// Both are for the owner and the machines the owner authorised, and nobody
// else. Publication moves where one of this agent's pairwise identities claims
// to be, and recovery discloses which contacts this agent is trying to reach —
// the second is the quieter of the two and the easier to leave open by accident.
func (s *CoreServer) mountEndpointRoutes(r chi.Router) {
	r.Post("/endpoint/publish", s.handlePublishEndpoint)
	r.Get("/endpoint/recover/{contact_aid}", s.handleRecoverEndpoint)
}

// handlePublishEndpoint signs and publishes where one of this agent's own
// pairwise identities can currently be reached.
func (s *CoreServer) handlePublishEndpoint(w http.ResponseWriter, r *http.Request) {
	if !s.isOwnerOrItsController(r) {
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
	if !s.isOwnerOrItsController(r) {
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
