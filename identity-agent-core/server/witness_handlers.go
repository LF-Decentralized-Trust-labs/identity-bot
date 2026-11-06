package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"identity-agent-core/endpointrecord"
	"identity-agent-core/store"
	"identity-agent-core/witness"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/internal/jsonreply"
)

func (s *CoreServer) mountWitnessRoutes(r chi.Router) {
	if s.WitnessService == nil {
		return
	}
	r.Post("/witness/event", s.handleWitnessEvent)
	r.Get("/witness/kel/{signer_aid}", s.handleWitnessKel)
	r.Get("/witness/kel/{signer_aid}/tip", s.handleWitnessKelTip)
	r.Get("/witness/kel/{signer_aid}/event/{sn}", s.handleWitnessKelEvent)
	r.Get("/witness/status", s.handleWitnessStatus)
	r.Post("/witness/endpoint", s.handleWitnessEndpointRecord)
	r.Get("/witness/endpoint/{controller_aid}", s.handleWitnessEndpointLookup)
	r.Get("/witness/tel/{issuer_aid}", s.handleWitnessTELRead)
	r.Get("/witness/tel/{issuer_aid}/head", s.handleWitnessTELHead)
	r.Post("/witness/tel/{issuer_aid}", s.handleWitnessTELSubmit)
	s.withdrawalRoutes(r)
}

func (s *CoreServer) handleWitnessEvent(w http.ResponseWriter, r *http.Request) {
	// The event arrives as the bytes it was published as, with the controller's
	// signature over them.
	//
	// It used to arrive as a parsed object and nothing else, which made a
	// receipt unearnable: an identifier is a digest over an exact byte sequence
	// in an exact field order, so a re-encoded event is a different event, and
	// with no signature there was nothing to check authorship against. A
	// witness could only attest that somebody sent it a JSON object.
	var req struct {
		AID           string `json:"aid"`
		EventB64      string `json:"event_b64"`
		CesrSignature string `json:"cesr_signature"`
		// Every controller signature, for an identity with several signers:
		// the whole list, with cesr_signature its first. A sender that
		// sends only extra signatures here is read the same way; the same
		// signature twice counts once.
		CesrSignatures []string `json:"cesr_signatures"`
	}
	// Open to peers, so bounded: each event costs a validation of the whole key
	// log, so the caller is rate limited, and the body is bounded as a key event
	// sent to the core is: the event and a signature per signer.
	if !s.witnessReadLimiter().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "Rate limited", "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxKeyEventBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.EventB64 == "" {
		writeError(w, http.StatusBadRequest, "event_bytes_required",
			"send the event as the bytes it was published as; a witness cannot receipt "+
				"an event it cannot verify")
		return
	}
	rawEvent, err := base64.StdEncoding.DecodeString(req.EventB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_event_bytes", err.Error())
		return
	}
	sigs := req.CesrSignatures
	if req.CesrSignature != "" {
		sigs = append([]string{req.CesrSignature}, sigs...)
	}
	result, err := s.WitnessService.ReceiveSignedEvent(req.AID, rawEvent, sigs)
	if err != nil {
		switch err.Error() {
		case "unsigned_event":
			writeError(w, http.StatusBadRequest, "unsigned_event",
				"the event carried no controller signature; a witness that receipts unsigned "+
					"events can be made to attest to anything")
		case "missing_event_bytes":
			writeError(w, http.StatusBadRequest, "missing_event_bytes", "no event was supplied")
		case "not_witnessing":
			writeError(w, http.StatusForbidden, "not_witnessing", "unknown signer or no active witness relationship")
		case "sequence_gap":
			writeError(w, http.StatusConflict, "sequence_gap", "sequence must be last_stored+1")
		case "duplicate_sequence":
			writeError(w, http.StatusConflict, "duplicate_sequence", "event already stored")
		default:
			if len(err.Error()) > 9 && err.Error()[:9] == "rejected:" {
				writeError(w, http.StatusBadRequest, "rejected", err.Error())
			} else {
				writeError(w, http.StatusBadRequest, "rejected", err.Error())
			}
		}
		return
	}
	jsonreply.Write(w, http.StatusOK, result)
}

// The three reads of a key log below answer from what this witness holds only
// to the identity itself or the one it is delegated from (witness.MayRead).
// Anybody else gets exactly the answer for a log not held: these routes are
// open to peers, and a different answer for a held log would tell a stranger
// who this agent witnesses. That matters most for a root identity, which is
// witnessed by the owner's contacts and is never published at /{aid}/kel
// (errNotPublishable).

// notHeld is the one answer to a read of a log that is not held, or that the
// asker may not see.
func notHeld(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "kel not found", "not_found")
}

func (s *CoreServer) handleWitnessKel(w http.ResponseWriter, r *http.Request) {
	signerAID := chi.URLParam(r, "signer_aid")
	if !s.witnessReadAllowed(w, r, signerAID) {
		return
	}
	kel, err := s.WitnessService.GetKelReplica(signerAID)
	if err != nil {
		notHeld(w)
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"aid": signerAID, "kel": kel, "count": len(kel),
	})
}

// handleWitnessKelTip answers how far this witness holds an identity's key log,
// signed with its key together with the asker's nonce, so the answer is fresh
// and its own.
func (s *CoreServer) handleWitnessKelTip(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	if nonce == "" || len(nonce) > 128 {
		writeError(w, http.StatusBadRequest, "a nonce is required", "")
		return
	}
	if !s.witnessReadLimiter().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "Rate limited", "")
		return
	}
	aid := chi.URLParam(r, "signer_aid")
	tip, err := s.WitnessService.KelTip(aid, nonce, s.WitnessService.MayRead(aid, r))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "the tip could not be signed", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, tip)
}

func (s *CoreServer) handleWitnessStatus(w http.ResponseWriter, r *http.Request) {
	if !s.isOwnerOrItsController(r) {
		writeError(w, http.StatusForbidden, "owner only", "internal route")
		return
	}
	st, err := s.WitnessService.BuildStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status failed", err.Error())
		return
	}
	jsonreply.Write(w, http.StatusOK, st)
}

// handleWitnessTELRead serves the registry logs of an identity this witness
// witnesses: every event anchored after since_sn in the identity's key log, and
// anchored_sn, how far that key log is held. It is asked for by issuer only;
// there is no way to ask by credential or by registry (witness.AnchoredTEL).
//
// Answered on the same terms as a read of the key log (witness.MayRead): the
// identity, its delegator, or a verifier who presents the log's inception.
// Anybody else is told it is not held.
func (s *CoreServer) handleWitnessTELRead(w http.ResponseWriter, r *http.Request) {
	issuer := chi.URLParam(r, "issuer_aid")
	if !s.witnessReadAllowed(w, r, issuer) {
		return
	}
	since := -1
	if v := r.URL.Query().Get("since_sn"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < -1 {
			writeError(w, http.StatusBadRequest, "since_sn is a place in the key log, or -1 for all of it", "")
			return
		}
		since = n
	}
	ans, err := s.WitnessService.ServeTEL(issuer, since)
	if err != nil {
		writeNoTEL(w, err)
		return
	}
	writeTELJSON(w, ans)
}

// handleWitnessTELHead is where the registry log of an identity is held to and
// the digest of its latest event, without the log (SEAM-13 §2). Answered on the
// same terms as the log itself.
func (s *CoreServer) handleWitnessTELHead(w http.ResponseWriter, r *http.Request) {
	issuer := chi.URLParam(r, "issuer_aid")
	if !s.witnessReadAllowed(w, r, issuer) {
		return
	}
	head, err := s.WitnessService.ServeTELHead(issuer)
	if err != nil {
		writeNoTEL(w, err)
		return
	}
	writeTELJSON(w, head)
}

// writeNoTEL answers a read the asker may make but there is nothing to give:
// 404 {"error":"no_tel"} (SEAM-13 §5 T-1), which a reader tells apart from an
// unreachable witness. Any other failure is a server error.
func writeNoTEL(w http.ResponseWriter, err error) {
	if errors.Is(err, witness.ErrNoTEL) {
		jsonreply.Write(w, http.StatusNotFound, map[string]string{"error": "no_tel"})
		return
	}
	writeError(w, http.StatusInternalServerError, "registry log unreadable", "")
}

// writeTELJSON writes an answer carrying events as published. The events are
// KERI events whose bytes are what their digests are over, so the encoder must
// not rewrite "<", ">" or "&" inside them, which the default one does.
func writeTELJSON(w http.ResponseWriter, v interface{}) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		writeError(w, http.StatusInternalServerError, "registry log unreadable", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// handleWitnessTELSubmit takes registry events from the issuer that made them.
// Nothing is trusted on who sends it: each event is stored only when the key
// log this witness holds for the issuer seals exactly that event
// (witness.ReceiveTEL). A witness that does not hold the log, and one that
// holds it and does not seal the events, give the same answer (notHeld).
func (s *CoreServer) handleWitnessTELSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.witnessReadLimiter().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "Rate limited", "")
		return
	}
	var req struct {
		Events []string `json:"events"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	n, err := s.WitnessService.ReceiveTEL(chi.URLParam(r, "issuer_aid"), req.Events)
	if err != nil {
		switch {
		case errors.Is(err, witness.ErrBadSubmission):
			// Wrong whoever it is for, so it says nothing about what is held.
			writeError(w, http.StatusBadRequest, "rejected", err.Error())
		case errors.Is(err, witness.ErrTELNotAccepted):
			// No log held for the identity, and a log held that does not seal
			// these events, get the one answer: the route is open to anybody,
			// and telling them apart would say which identities this witness
			// witnesses, which the read routes hide through MayRead.
			notHeld(w)
		default:
			writeError(w, http.StatusInternalServerError, "registry events could not be stored", "")
		}
		return
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{"stored": n})
}

// handleWitnessRequest handles inbound witness enrollment from a remote agent.
func (s *CoreServer) handleWitnessRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RequesterAID  string `json:"requester_aid"`
		RequesterOOBI string `json:"requester_oobi"`
		BackendType   string `json:"backend_type"`
		EventJSON     string `json:"event_json"`
		// CoversDelegates asks for the identities the requester delegates to
		// be witnessed too.
		CoversDelegates bool   `json:"covers_delegates"`
		RequestID       string `json:"request_id"`
		Stamp           string `json:"stamp"`
		Signature       string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid witness request body", err.Error())
		return
	}
	if req.RequesterAID == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields", "requester_aid required")
		return
	}
	if s.WitnessService == nil {
		writeError(w, http.StatusServiceUnavailable, "witness service unavailable", "")
		return
	}
	ctx := r.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	result := s.WitnessService.ProcessInboundRequest(ctx, witness.WitnessRequest{
		RequesterAID: req.RequesterAID, RequesterOOBI: req.RequesterOOBI, BackendType: req.BackendType,
		CoversDelegates: req.CoversDelegates, RequestID: req.RequestID, Stamp: req.Stamp, Signature: req.Signature,
	})
	status := "declined"
	if result.Accepted {
		status = "accepted"
	}
	jsonreply.Write(w, http.StatusOK, map[string]interface{}{
		"status": status, "reason": result.Reason, "task_id": result.TaskID,
		// Whether, after this, the identities the requester delegates are
		// witnessed too.
		"covers_delegates": result.Accepted && s.WitnessService.DelegatesWitnessedFor(req.RequesterAID),
	})
}

// handleWitnessAccept handles the accept/decline POST-back from a remote agent.
func (s *CoreServer) handleWitnessAccept(w http.ResponseWriter, r *http.Request) {
	var req witness.AcceptCallback
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid witness accept body", err.Error())
		return
	}
	if req.RequesterAID == "" || req.ResponderAID == "" || req.Decision == "" {
		writeError(w, http.StatusBadRequest, "Missing required fields",
			"requester_aid, responder_aid, and decision are required")
		return
	}
	if s.WitnessService != nil {
		if err := s.WitnessService.ApplyAcceptCallback(req); err != nil {
			log.Printf("[witness] accept callback error: %v", err)
			writeError(w, http.StatusBadRequest, "accept_failed", err.Error())
			return
		}
	}
	jsonreply.Write(w, http.StatusOK, map[string]string{"status": "received", "decision": req.Decision})
}

func (s *CoreServer) triggerWitnessBroadcast(signerAID string, rawEvent []byte, cesrSigs ...string) {
	if s.WitnessService == nil || len(rawEvent) == 0 {
		return
	}
	ctx := s.AppCtx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.WitnessService.BroadcastEvent(ctx, signerAID, rawEvent, cesrSigs...); err != nil {
		log.Printf("[witness] broadcast failed: %v", err)
	}
}

// handleWitnessEndpointRecord accepts a controller's signed statement of where
// it currently is, and holds it on that controller's behalf.
//
// This is the half of the design that makes a changed address survivable. An
// OOBI handed to somebody persists in their store long after it stops working,
// so when a relay is left or an allocation expires, every counterparty holding
// that string is stranded. A witness is the natural place to keep the current
// answer, because it is already named in the KEL and is already the thing that
// does not change when infrastructure does.
//
// THE ROUTE IS OPEN TO ANYBODY, SO NOTHING IN IT IS TRUSTED ON WHO SENT IT.
// A record is kept only when it is the identifier's own statement
// (endpointrecord): signed by the key the key log this witness holds for the
// identifier names now, in the one spelling of the form, issued after the one
// already held. A witness that stored what it was handed would let a stranger
// say where an organisation is, which is exactly what a computer that follows a
// moved organisation must not be made to believe. An identifier this witness
// holds no log for is refused outright, so the store cannot be filled with
// records under identifiers nobody asked it to witness.
func (s *CoreServer) handleWitnessEndpointRecord(w http.ResponseWriter, r *http.Request) {
	if !s.witnessReadLimiter().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "Rate limited", "")
		return
	}
	var req struct {
		AID    string         `json:"aid"`
		Record map[string]any `json:"record"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body", err.Error())
		return
	}
	if req.AID == "" || req.Record == nil {
		writeError(w, http.StatusBadRequest, "aid and record required", "")
		return
	}
	record, err := endpointrecord.Parse(req.Record)
	if err != nil {
		writeError(w, http.StatusBadRequest, "not an endpoint record", err.Error())
		return
	}
	// The envelope's AID is not trusted over the record's own: a record signed
	// by one identifier must not be filed under another's name.
	if record.AID != req.AID {
		writeError(w, http.StatusBadRequest, "aid mismatch",
			"the record speaks for a different identifier than the request")
		return
	}
	// ONE ANSWER FOR EVERY REASON THE RECORD IS NOT KEPT THAT DEPENDS ON THIS
	// WITNESS'S KEY LOG. An identifier this witness holds no log for and one it
	// holds but whose record does not verify are told apart only by somebody who
	// holds the identifier's key: anybody else is told the same thing, as the
	// key log reads are, so the route cannot be used to learn who this agent
	// witnesses (witness.MayRead).
	notAccepted := func() {
		writeError(w, http.StatusForbidden, "not_accepted",
			"this witness does not hold a record from this identifier's current key")
	}
	key, err := s.WitnessService.CurrentVerifiedKey(req.AID)
	if err != nil {
		notAccepted()
		return
	}
	if err := record.Verify(key, time.Now()); err != nil {
		notAccepted()
		return
	}

	// Checked and stored in one step, so two records arriving together cannot
	// both pass the check against the one held.
	s.endpointRecordMu.Lock()
	defer s.endpointRecordMu.Unlock()
	held, err := s.newestEndpointRecord(store.EndpointRecordHeld, req.AID, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint records", err.Error())
		return
	}
	if held != nil {
		if *held == record {
			// The same statement again changes nothing.
			writeJSON(w, map[string]any{"stored": true, "unchanged": true})
			return
		}
		if !endpointrecord.Newer(record, *held) {
			writeError(w, http.StatusConflict, "stale_record",
				"a record issued at "+held.Issued+" is already held; a record replaces it only when issued later")
			return
		}
	}
	if err := s.keepEndpointRecord(store.EndpointRecordHeld, record, req.Record); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store endpoint record", err.Error())
		return
	}
	writeJSON(w, map[string]any{"stored": true, "issued": record.Issued})
}

// keepEndpointRecord holds record as the only one of its kind for its
// identifier. Held records are not accumulated: a route open to anybody must not
// keep a row for every record ever sent, and the one that is newest is the only
// one anybody asks for.
func (s *CoreServer) keepEndpointRecord(kind string, record endpointrecord.Record, raw map[string]any) error {
	return s.DataStore.ReplaceEndpointRecord(store.EndpointRecord{
		SAID:       record.Signature,
		CID:        record.AID,
		Route:      kind,
		URL:        record.Origin,
		Signature:  record.Signature,
		Stamp:      record.Issued,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
		Record:     raw,
	})
}

// newestEndpointRecord is the record issued latest among those of one kind held
// for an identifier that is that identifier's own statement under key, or nil.
// Ordered by when each says it was issued, never by when it arrived: arrival
// order is the order an attacker replaying old records picks. A record signed by
// a key the identifier has since rotated away from is not ranked at all, so it
// cannot keep a legitimate newer one out. Rows of any other form (the unsigned
// records this route used to keep) are not records and are passed over.
func (s *CoreServer) newestEndpointRecord(kind, aid string, key ed25519.PublicKey) (*endpointrecord.Record, error) {
	held, err := s.DataStore.GetEndpointRecords(aid)
	if err != nil {
		return nil, err
	}
	var newest *endpointrecord.Record
	for _, h := range held {
		if h.Route != kind {
			continue
		}
		rec, err := endpointrecord.Parse(h.Record)
		if err != nil || rec.AID != aid || rec.Verify(key, time.Now()) != nil {
			continue
		}
		if newest == nil || endpointrecord.Newer(rec, *newest) {
			r := rec
			newest = &r
		}
	}
	return newest, nil
}

// handleWitnessEndpointLookup answers "where is this identity now" for somebody
// whose stored address has stopped working: the newest signed record held for
// it, exactly as its controller signed it.
//
// Public on purpose. A counterparty holding a dead URL has, by definition, no
// authenticated channel left to ask through — requiring one would make this
// reachable only by people who do not need it. It discloses nothing the
// controller did not choose to publish, and nothing here is believed on this
// witness's word: the asker checks the record against the identifier's own
// verified key log (endpointrecord.Record.Verify), so a witness that withholds
// or serves an old record can fail the asker but cannot move it — and an asker
// that asks every witness and keeps what it has seen (RecoverContactEndpoint)
// cannot be rolled back to an old address either.
func (s *CoreServer) handleWitnessEndpointLookup(w http.ResponseWriter, r *http.Request) {
	if !s.witnessReadLimiter().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "Rate limited", "")
		return
	}
	cid := chi.URLParam(r, "controller_aid")
	if cid == "" {
		writeError(w, http.StatusBadRequest, "controller_aid required", "")
		return
	}
	// Not held, not witnessed and no record from the current key are one
	// answer.
	key, err := s.WitnessService.CurrentVerifiedKey(cid)
	if err != nil {
		writeError(w, http.StatusNotFound, "no endpoint record held", "not_found")
		return
	}
	newest, err := s.newestEndpointRecord(store.EndpointRecordHeld, cid, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read endpoint records", err.Error())
		return
	}
	if newest == nil {
		writeError(w, http.StatusNotFound, "no endpoint record held", "not_found")
		return
	}
	writeJSON(w, map[string]any{"controller_aid": cid, "record": newest})
}

// handleWitnessKelEvent answers one event of a key log this witness holds,
// as its controller published and signed it.
func (s *CoreServer) handleWitnessKelEvent(w http.ResponseWriter, r *http.Request) {
	sn, err := strconv.Atoi(chi.URLParam(r, "sn"))
	if err != nil || sn < 0 {
		writeError(w, http.StatusBadRequest, "a place in the key log is a number", "")
		return
	}
	aid := chi.URLParam(r, "signer_aid")
	if !s.witnessReadAllowed(w, r, aid) {
		return
	}
	ev, err := s.WitnessService.EventAt(aid, sn)
	if err != nil {
		notHeld(w)
		return
	}
	jsonreply.Write(w, http.StatusOK, ev)
}

// witnessReadAllowed rate limits a read of a key log and answers an asker who
// may not read it as for a log not held. It reports whether to go on.
func (s *CoreServer) witnessReadAllowed(w http.ResponseWriter, r *http.Request, aid string) bool {
	if !s.witnessReadLimiter().allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "Rate limited", "")
		return false
	}
	if !s.WitnessService.MayRead(aid, r) {
		notHeld(w)
		return false
	}
	return true
}

// witnessReadLimiter is the one bounded limiter every peer-facing witness
// route that costs work (a validation, a signature, a read) answers to.
func (s *CoreServer) witnessReadLimiter() *ipRateLimiter {
	s.witnessLimiterOnce.Do(func() { s.witnessLimiter = newIPRateLimiter(120, time.Minute) })
	return s.witnessLimiter
}
