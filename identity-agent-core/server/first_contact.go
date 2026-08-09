package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/store"
)

// Meeting somebody who has never written to you before.
//
// An envelope from an unknown sender cannot be opened: opening it needs that
// sender's keys, and the only record of whose keys are whose is the peer list,
// which a stranger is by definition not in. So a first message was refused, and
// the only way two agents could ever meet was a separate plaintext endpoint
// where an introduction arrived unencrypted and was believed.
//
// The obvious repair is to look the stranger up — take an address from the
// message and fetch their keys. That hands an unauthenticated caller the power
// to make this agent fetch a URL of their choosing, which is a worse thing to
// own than the problem it solves.
//
// It is also unnecessary, because everything needed is self-certifying. An
// identifier IS the digest of its own inception event, and since that event now
// commits to the messaging keys, a sender can simply CARRY the proof: here is
// my key history, check that it digests to the identifier I am claiming, and
// take my keys out of it. Nothing is fetched, so there is nothing to point
// anywhere, and a forged history fails on arithmetic rather than on trust.
//
// What this establishes is identity, not welcome. A stranger who proves who
// they are gets a request placed in front of the owner and nothing else: no
// peer registered, no keys minted, no message stored, no reply. Proving your
// name has never been the same as being agreed to.

// firstContactMaxKEL bounds the key history a stranger may present.
//
// An inception carrying post-quantum keys is a few kilobytes; anything far
// larger is either not a key history or is an attempt to make this agent do
// expensive work. Bounded before it is parsed, not after.
const firstContactMaxKEL = 64 * 1024

// firstContactWindow and firstContactBurst bound how often strangers are
// entertained at all.
//
// Verifying a presented history costs real work — a driver call and signature
// checks — and it happens before anybody has been agreed to. Without a bound,
// the cheapest possible request buys the most expensive possible response.
const (
	firstContactWindow = time.Minute
	firstContactBurst  = 5
)

var firstContact = struct {
	sync.Mutex
	seen []time.Time
}{}

// allowFirstContactAttempt reports whether another stranger may be verified now.
//
// Deliberately global rather than per-sender: a sender identity is free to
// invent, so counting per-sender would count nothing. The owner sees a queue of
// requests either way, and a queue is the point at which flooding becomes
// visible to a person.
func allowFirstContactAttempt(now time.Time) bool {
	firstContact.Lock()
	defer firstContact.Unlock()
	kept := firstContact.seen[:0]
	for _, t := range firstContact.seen {
		if now.Sub(t) < firstContactWindow {
			kept = append(kept, t)
		}
	}
	firstContact.seen = kept
	if len(firstContact.seen) >= firstContactBurst {
		return false
	}
	firstContact.seen = append(firstContact.seen, now)
	return true
}

// identifyStranger turns a presented key history into keys that provably belong
// to the identifier the sender claims.
//
// The claim is checked in this order deliberately: the history must be sound and
// signed before anything is read out of it, and the identifier it derives must
// be the one the envelope named before those keys are used to open anything.
func (s *CoreServer) identifyStranger(claimedAID string, kel []map[string]interface{}) (*didcomm.DID, error) {
	if s.KeriDriver == nil {
		return nil, fmt.Errorf("this agent cannot check a key history, so it cannot meet anybody new")
	}
	if len(kel) == 0 {
		return nil, fmt.Errorf("no key history was presented")
	}

	val, err := s.KeriDriver.ValidateKEL(claimedAID, kel)
	if err != nil {
		return nil, fmt.Errorf("the presented key history could not be checked: %w", err)
	}
	if !val.KelVerified {
		reason := "it does not check out"
		if len(val.ValidationErrors) > 0 {
			reason = val.ValidationErrors[0]
		}
		return nil, fmt.Errorf("the presented key history is not sound: %s", reason)
	}

	// The identifier has to be derived from the history presented, not merely
	// mentioned by it. ValidateKEL binds the two — an inception whose digest is
	// not the identifier is refused — so reaching here means the claim holds.
	x, kem, err := iacrypto.AnchoredAgreementKeys(kel[0])
	if err != nil {
		return nil, fmt.Errorf("%s does not commit to any messaging keys, so there is nothing "+
			"here that ties it to the message it sent: %w", claimedAID, err)
	}
	ed, dsa, err := iacrypto.AnchoredSigningKeys(kel[0])
	if err != nil {
		return nil, fmt.Errorf("%s does not commit to the keys that sign for it: %w", claimedAID, err)
	}

	return didcomm.DIDFromRawKeys(claimedAID, ed, dsa, x, kem)
}

// tryFirstContact handles an envelope from a sender this agent does not know.
//
// Returns true when it has answered the request. The result is never delivery:
// at most, a request appears in the owner's list. Nothing here registers a peer,
// mints a keyset, stores a message, or replies to the sender with anything they
// could learn from.
func (s *CoreServer) tryFirstContact(w http.ResponseWriter, r *http.Request,
	claimedAID string, env *didcomm.Envelope) bool {

	if len(env.SenderKEL) == 0 {
		// Nothing presented, so there is nothing to check. Left to the caller's
		// existing refusal, which says the sender is not a peer.
		return false
	}
	// Bounded before it is parsed. The envelope as a whole is already capped,
	// but a key history is the expensive part to check and deserves its own
	// limit rather than inheriting one meant for a message.
	if raw, merr := json.Marshal(env.SenderKEL); merr != nil || len(raw) > firstContactMaxKEL {
		jsonError(w, "the key history presented is too large to consider", http.StatusRequestEntityTooLarge)
		return true
	}
	if !allowFirstContactAttempt(time.Now()) {
		jsonError(w, "too many introductions just now; try again shortly", http.StatusTooManyRequests)
		return true
	}

	did, err := s.identifyStranger(claimedAID, env.SenderKEL)
	if err != nil {
		log.Printf("[first-contact] refused an introduction from %s: %v", claimedAID, err)
		jsonError(w, "the key history presented does not establish who you are", http.StatusForbidden)
		return true
	}

	// Only now, with keys that provably belong to the identifier, is the
	// envelope opened — and only to learn whether this is a request to connect.
	if len(env.Recipients) == 0 {
		jsonError(w, "no recipient", http.StatusBadRequest)
		return true
	}
	kid := env.Recipients[0].Header.Kid
	if !s.hasKeySet(kid) {
		jsonError(w, "unknown_recipient_aid", http.StatusNotFound)
		return true
	}
	rcpt, err := s.keySetFor(kid)
	if err != nil {
		jsonError(w, "recipient keyset error", http.StatusInternalServerError)
		return true
	}
	jwm, err := didcomm.UnpackAuthcrypt(rcpt, did, env)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return true
	}
	if jwm.Type != didcomm.TypeContactRequest {
		// A stranger may ask to connect. They may not deliver anything else,
		// however well they have proved who they are — being identifiable is not
		// being known, and this agent has agreed to nothing yet.
		jsonError(w, "a first message may only be a request to connect", http.StatusForbidden)
		return true
	}

	if err := s.recordConnectionRequest(claimedAID, jwm); err != nil {
		log.Printf("[first-contact] could not record a request from %s: %v", claimedAID, err)
		jsonError(w, "could not record the request", http.StatusInternalServerError)
		return true
	}

	log.Printf("[first-contact] %s asked to connect; waiting for the owner", claimedAID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{"status": "pending_owner_approval"})
	return true
}

// recordConnectionRequest puts a proven stranger in front of the owner.
//
// Stored as a contact awaiting a decision, never as one that has been accepted:
// everything downstream keys off that status, and the whole point is that
// identifying yourself is not the same as being agreed to.
func (s *CoreServer) recordConnectionRequest(aid string, jwm *didcomm.JWM) error {
	if s.DataStore == nil {
		return fmt.Errorf("no store")
	}
	if existing, _ := s.DataStore.GetContact(aid); existing != nil {
		// Already known in some state. A repeat request must not quietly reset
		// a contact the owner has already judged — including one they rejected.
		return nil
	}

	var body struct {
		Alias   string `json:"alias"`
		OobiURL string `json:"oobi_url"`
	}
	_ = json.Unmarshal(jwm.Body, &body)

	alias := body.Alias
	if alias == "" {
		alias = aid
		if len(alias) > 12 {
			alias = alias[:12]
		}
	}
	rec := store.ContactRecord{
		AID:          aid,
		Alias:        alias,
		OobiURL:      body.OobiURL,
		Status:       "pending_inbound",
		DiscoveredAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.DataStore.SaveContact(rec); err != nil {
		return err
	}
	s.EventHub.Broadcast(AgentEvent{
		Type:    "contact_request_received",
		Payload: map[string]interface{}{"aid": aid, "alias": alias},
	})
	return nil
}

// ownKELForIntroduction returns this agent's key history, for presenting to
// somebody who has no record of us.
//
// Public information: a key history is what an OOBI serves to anyone who asks.
// Sending it saves the recipient a fetch and, more to the point, saves them
// having to decide whether to make one on a stranger's say-so.
func (s *CoreServer) ownKELForIntroduction(aid string) []map[string]interface{} {
	if s.DataStore == nil || aid == "" {
		return nil
	}
	events, err := s.DataStore.GetEvents(aid)
	if err != nil || len(events) == 0 {
		return nil
	}
	out := make([]map[string]interface{}, 0, len(events))
	for _, e := range events {
		var ev map[string]interface{}
		if json.Unmarshal([]byte(e.EventJSON), &ev) != nil {
			return nil
		}
		// The canonical bytes travel with it where they were kept, since that
		// is what the far side checks the event's own digest against.
		rec := map[string]interface{}{
			"event_json":      e.EventJSON,
			"cesr_signature":  e.CesrSignature,
			"public_key":      e.PublicKey,
			"event_type":      e.EventType,
			"sequence_number": e.SequenceNumber,
		}
		if e.RawBytesB64 != "" {
			rec["raw_bytes_b64"] = e.RawBytesB64
		}
		out = append(out, rec)
	}
	return out
}
