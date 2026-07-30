package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// Asking the device that holds the keys.
//
// Some things can only be signed by the device the root keys live on. In a
// phone-plus-computer setup that is the phone; the always-on computer cannot do
// it and should not be able to. Publishing where the root identity currently
// reaches is the first case, and it will not be the last.
//
// The awkward part is timing rather than authority. The computer is awake and
// knows the thing needs signing; the phone is in a pocket. So the request waits
// where the phone will find it, and is signed the next time somebody opens the
// app.
//
// THREE TIERS, along one axis: how much of the person's attention this is worth.
//
//   - CONSENT. A real decision, shown properly, refusable. Signing something on
//     somebody's behalf because it was convenient is how consent becomes a
//     formality.
//   - NOTIFY. Already agreed in principle, blocked only on the key being
//     elsewhere. Shown, but as one tap with a plain explanation of why the
//     phone has to do this rather than the computer.
//   - AUTOMATIC. Not shown at all. The app signs it the next time it runs and
//     records that it did. For work where asking would be pure interruption —
//     the answer is always yes, the person gains nothing by being consulted,
//     and the only reason it waited is that the key lives on this device.
//
// The tiers share one queue rather than being separate mechanisms, because the
// difficult parts are identical: the payload cannot change after it is shown,
// an answered request cannot be answered twice, a refusal is recorded. Splitting
// them would mean two copies of the security-critical half, which is how two
// copies drift.
//
// AUTOMATIC IS NOT THE CALLER'S CHOICE. It is allowed only for kinds on an
// explicit list, and anything else asking for it is quietly downgraded to
// notify. Without that, every new caller has an incentive to mark its own work
// automatic — each one reasonably, and the mechanism ends up meaning nothing.
// Adding to the list should feel like a decision, which is why it is a
// hand-written list and not a flag.
//
// What is NOT here is any way for this core to sign these itself. That is the
// point: if it could, the request would not exist. Automatic still needs the
// phone; it just does not need the person.

const (
	// signingRequestTTL bounds how long a request waits. A thing that needed
	// signing a month ago usually needs re-deciding rather than signing, and a
	// queue that only grows is one nobody reads.
	signingRequestTTL = 14 * 24 * time.Hour

	// PresentationConsent asks a question. The person may say no.
	PresentationConsent = "consent"
	// PresentationNotify tells them, and needs one tap.
	PresentationNotify = "notify"
	// PresentationAutomatic does not interrupt: the app signs it next time it
	// runs and records that it did.
	PresentationAutomatic = "automatic"

	SigningStatusPending = "pending"
	SigningStatusSigned  = "signed"
	SigningStatusRefused = "refused"
	SigningStatusExpired = "expired"
)

// autoSignableKinds is the list of work that may be signed without asking.
//
// Deliberately short, and deliberately a list rather than a flag. Everything on
// it has to be something where the answer is always yes and the person gains
// nothing by being consulted — republishing your own address when a relay moves
// is the case it was written for: they already decided to be reachable, and the
// alternative to signing is being unreachable.
//
// Anything not named here is downgraded to notify, so a caller cannot promote
// its own work by asking nicely.
var autoSignableKinds = map[string]bool{
	// Where this identity currently answers. Republishing is maintenance of a
	// decision already made, not a new one.
	"endpoint-location": true,
}

// EnqueueSigningRequest records something the controller device must sign.
//
// Returns the request ID. Idempotency is the caller's business: this will
// happily queue the same thing twice, because it cannot tell a genuine repeat
// from a retry, and a duplicate request is a smaller harm than a dropped one.
func (s *CoreServer) EnqueueSigningRequest(aid, kind, summary, detail string,
	payload []byte, presentation string) (string, error) {

	if s.DataStore == nil {
		return "", fmt.Errorf("no data store")
	}
	if aid == "" || kind == "" || len(payload) == 0 {
		return "", fmt.Errorf("a signing request needs an aid, a kind and something to sign")
	}
	if summary == "" {
		// A request nobody can read is a request nobody will action. Better an
		// awkward default than a blank prompt on somebody's phone.
		summary = "Your phone needs to sign something"
	}

	// Downgrade rather than refuse. A caller asking for automatic on work that
	// is not on the list has made a judgement error, not a fatal one, and
	// failing the whole request would turn a presentation mistake into an
	// outage. It is logged so the mistake is visible.
	switch presentation {
	case PresentationConsent, PresentationNotify:
	case PresentationAutomatic:
		if !autoSignableKinds[kind] {
			log.Printf("[signing] %q asked to be signed without asking; it is not on the "+
				"automatic list, so it will be shown instead", kind)
			presentation = PresentationNotify
		}
	default:
		presentation = PresentationNotify
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	req := store.SigningRequest{
		ID:           base64.RawURLEncoding.EncodeToString(idBytes),
		AID:          aid,
		Kind:         kind,
		Summary:      summary,
		Detail:       detail,
		PayloadB64:   base64.StdEncoding.EncodeToString(payload),
		Presentation: presentation,
		Status:       SigningStatusPending,
		CreatedAt:    now.Format(time.RFC3339),
		ExpiresAt:    now.Add(signingRequestTTL).Format(time.RFC3339),
	}
	if err := s.DataStore.SaveSigningRequest(req); err != nil {
		return "", err
	}
	log.Printf("[signing] queued %s for %s: %s", req.Kind, req.AID, req.Summary)
	return req.ID, nil
}

func (s *CoreServer) mountSigningRequestRoutes(r chi.Router) {
	r.Get("/signing-requests", s.handleListSigningRequests)
	r.Post("/signing-requests/{id}/fulfil", s.handleFulfilSigningRequest)
	r.Post("/signing-requests/{id}/refuse", s.handleRefuseSigningRequest)
}

// handleListSigningRequests returns what is waiting for the controller device.
//
// Owner-only. The list says what this identity is about to assert and why,
// which is not something to hand to anybody who asks.
func (s *CoreServer) handleListSigningRequests(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "internal route")
		return
	}
	pending, err := s.DataStore.GetPendingSigningRequests()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read signing requests", err.Error())
		return
	}

	// Expiry is applied on read as well as on a sweep, so a stale request is
	// never shown as actionable just because no sweep has run yet.
	now := time.Now().UTC()
	var live []store.SigningRequest
	for _, req := range pending {
		if req.ExpiresAt != "" {
			if exp, perr := time.Parse(time.RFC3339, req.ExpiresAt); perr == nil && exp.Before(now) {
				req.Status = SigningStatusExpired
				req.ResolvedAt = now.Format(time.RFC3339)
				_ = s.DataStore.SaveSigningRequest(req)
				continue
			}
		}
		live = append(live, req)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"requests": live, "count": len(live)})
}

// handleFulfilSigningRequest accepts the signature the controller device made.
//
// The signature is stored and the request closed; what to DO with it belongs to
// whoever queued it, which is why the kind is recorded. Splitting it this way
// keeps this endpoint from having to know about endpoints, credentials, or
// whatever comes next.
func (s *CoreServer) handleFulfilSigningRequest(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "only this agent's owner can sign for it")
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if body.Signature == "" {
		writeError(w, http.StatusBadRequest, "signature required", "")
		return
	}

	req, err := s.DataStore.GetSigningRequest(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the request", err.Error())
		return
	}
	if req == nil {
		writeError(w, http.StatusNotFound, "no such signing request", "")
		return
	}
	if req.Status != SigningStatusPending {
		// Refused rather than overwritten. A request that has already been
		// answered should not be answerable again, or a stale client could
		// silently replace a refusal with a signature.
		writeError(w, http.StatusConflict, "already resolved",
			"this request was "+req.Status)
		return
	}

	req.Signature = body.Signature
	req.Status = SigningStatusSigned
	req.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.DataStore.SaveSigningRequest(*req); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record the signature", err.Error())
		return
	}
	log.Printf("[signing] %s for %s was signed", req.Kind, req.AID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"fulfilled": true, "id": id, "kind": req.Kind})
}

// handleRefuseSigningRequest records that the owner declined.
//
// Recorded rather than deleted. "You were asked and said no" is a different
// state from "you were never asked", and only the first should stop the agent
// asking again about the same thing.
func (s *CoreServer) handleRefuseSigningRequest(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "owner only", "internal route")
		return
	}
	id := chi.URLParam(r, "id")
	req, err := s.DataStore.GetSigningRequest(id)
	if err != nil || req == nil {
		writeError(w, http.StatusNotFound, "no such signing request", "")
		return
	}
	if req.Status != SigningStatusPending {
		writeError(w, http.StatusConflict, "already resolved", "this request was "+req.Status)
		return
	}
	req.Status = SigningStatusRefused
	req.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.DataStore.SaveSigningRequest(*req); err != nil {
		writeError(w, http.StatusInternalServerError, "could not record the refusal", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"refused": true, "id": id})
}
