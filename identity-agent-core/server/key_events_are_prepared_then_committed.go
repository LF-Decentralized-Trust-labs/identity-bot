package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/backup"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"

	keri "github.com/grapeid/keri-go"
)

// A key event is prepared here and committed signed (ADR-061 section 3).
//
// POST /api/events/prepare builds an event and returns its bytes; it adds
// nothing and sends nothing anywhere. POST /api/events/commit takes those bytes
// with their signatures and adds the event only if the log it makes is one
// that verifies, then sends it to the identity's witnesses. A signer that holds
// the identity's key outside this Identity Agent, an app or each owner of an
// identity with several, signs between the two, after checking the bytes
// itself. Both routes are the owner's and closed to controllers: a key event
// writes the state that decides who the owner is.

// eventCommitter is an engine that prepares and commits events.
type eventCommitter interface {
	Prepare(keriengine.PrepareRequest) (*keriengine.Prepared, error)
	Commit(name string, raw []byte, sigs []string, keep func(drivers.KELKeep) error) (*keriengine.CommitResult, error)
}

// maxKeyEventBody bounds a prepare or commit request. A key event with several
// owners and their post-quantum keys revealed is a few tens of kilobytes; this
// leaves room for that and no more.
const maxKeyEventBody = 256 << 10

type prepareEventRequest struct {
	AID      string            `json:"aid"`
	T        string            `json:"t"`
	K        []string          `json:"k"`
	Kt       json.RawMessage   `json:"kt"`
	N        []string          `json:"n"`
	Nt       json.RawMessage   `json:"nt"`
	A        []json.RawMessage `json:"a"`
	OwnerAID string            `json:"owner_aid"`
	Owners   []string          `json:"owners"`
	B        []string          `json:"b"`
	Br       []string          `json:"br"`
	Ba       []string          `json:"ba"`
	Bt       *json.RawMessage  `json:"bt"`
	After    *struct {
		S string `json:"s"`
		D string `json:"d"`
	} `json:"after"`
}

type prepareEventResponse struct {
	RawB64 string          `json:"raw_b64"`
	Hint   keriengine.Hint `json:"hint"`
}

type commitEventRequest struct {
	RawB64 string   `json:"raw_b64"`
	Sigs   []string `json:"sigs"`
}

func (s *CoreServer) committer(w http.ResponseWriter) (eventCommitter, bool) {
	c, ok := s.KeriDriver.(eventCommitter)
	if !ok || s.KeriDriver == nil {
		writeError(w, http.StatusServiceUnavailable, "No KERI engine here prepares events",
			"key events are prepared and committed by the in-process engine")
		return nil, false
	}
	return c, true
}

// sequenceFromHex reads a sequence number in its one spelling, as KERI writes
// it (iacrypto.ParseHexCount).
func sequenceFromHex(s string) (int, error) {
	n, err := iacrypto.ParseHexCount(s)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// witnessThresholdOf reads bt, which KERI writes as a hexadecimal string.
func witnessThresholdOf(raw *json.RawMessage) (*int, error) {
	if raw == nil {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(*raw, &s); err != nil {
		return nil, fmt.Errorf("bt is a hexadecimal string, as KERI writes it")
	}
	n, err := sequenceFromHex(s)
	if err != nil {
		return nil, fmt.Errorf("bt: %w", err)
	}
	return &n, nil
}

func (s *CoreServer) handlePrepareEvent(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "Key events are the owner's", "only the owner prepares a key event")
		return
	}
	c, ok := s.committer(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxKeyEventBody)
	var req prepareEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	toad, err := witnessThresholdOf(req.Bt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid witness threshold", err.Error())
		return
	}
	pr := keriengine.PrepareRequest{Ilk: req.T, Keys: req.K, Kt: req.Kt, Next: req.N, Nt: req.Nt,
		Anchors: req.A, Witnesses: req.B, Cuts: req.Br, Adds: req.Ba, Toad: toad}

	switch req.T {
	case "icp":
		if !s.mayFoundHere(w, req.OwnerAID) {
			return
		}
		if req.AID != "" || req.After != nil {
			writeError(w, http.StatusBadRequest, "A founding extends nothing", "aid and after are not given for a founding")
			return
		}
		if req.OwnerAID != "" {
			seal, err := keriengine.OwnerSeal(req.OwnerAID)
			if err != nil {
				writeError(w, http.StatusBadRequest, "Invalid owner", err.Error())
				return
			}
			pr.Anchors = append([]json.RawMessage{seal}, req.A...)
		}
	case "rot", "ixn":
		own, err := s.DataStore.GetIdentity()
		if err != nil || own == nil {
			writeError(w, http.StatusConflict, "There is no identity here to extend", "found one first")
			return
		}
		if req.AID != own.AID {
			writeError(w, http.StatusBadRequest, "That is not this Identity Agent's identity",
				fmt.Sprintf("this Identity Agent keeps the log of %s", own.AID))
			return
		}
		// A signer outside the core always names the event it follows, from
		// the key state it verified itself. Taking the core's tip on trust
		// would let a core that hid an establishment event have a competing
		// one signed.
		if req.After == nil {
			writeError(w, http.StatusBadRequest, "after is required",
				"name the event this one follows, from the key state you verified")
			return
		}
		sn, err := sequenceFromHex(req.After.S)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid after", err.Error())
			return
		}
		pr.Name = own.AID
		pr.After = &keriengine.Place{SN: sn, SAID: req.After.D}
	default:
		writeError(w, http.StatusBadRequest, "Unknown event type", "t is icp, rot or ixn")
		return
	}

	p, err := c.Prepare(pr)
	if err != nil {
		writeEventError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(prepareEventResponse{RawB64: base64.StdEncoding.EncodeToString(p.Raw), Hint: p.Hint})
}

// mayFoundHere is the founding gate the inception route applies.
func (s *CoreServer) mayFoundHere(w http.ResponseWriter, ownerAID string) bool {
	if s.refuseIfThisComputerMayNotFound(w) {
		return false
	}
	if existing, _ := s.DataStore.GetIdentity(); existing != nil {
		writeError(w, http.StatusConflict, "Identity already exists", "AID: "+existing.AID)
		return false
	}
	if s.requireOwnerAtInception && ownerAID == "" {
		writeError(w, http.StatusBadRequest, "This agent will not found an identity that names no owner",
			"owner_aid is required. An owner is written into the founding event and cannot be added afterwards.")
		return false
	}
	return true
}

func (s *CoreServer) handleCommitEvent(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		writeError(w, http.StatusForbidden, "Key events are the owner's", "only the owner commits a key event")
		return
	}
	c, ok := s.committer(w)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxKeyEventBody)
	var req commitEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(req.RawB64)
	if err != nil || len(raw) == 0 {
		writeError(w, http.StatusBadRequest, "raw_b64 is not the event", "standard base64 of the event's bytes")
		return
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "The event does not parse", err.Error())
		return
	}

	name := ""
	switch ev.Ilk {
	case "icp":
		s.founding.Lock()
		defer s.founding.Unlock()
		// The founding of the identity already kept here may be committed
		// again, for further signatures; any other founding passes the gate.
		if own, _ := s.DataStore.GetIdentity(); own != nil && own.AID == ev.Identifier {
			name = own.AID
		} else if !s.mayFoundHere(w, ownerNamedIn(raw)) {
			return
		}
	case "rot", "ixn":
		own, err := s.DataStore.GetIdentity()
		if err != nil || own == nil || own.AID != ev.Identifier {
			writeError(w, http.StatusBadRequest, "That is not this Identity Agent's identity",
				"an event is committed only to the log of the identity kept here")
			return
		}
		name = own.AID
	default:
		writeError(w, http.StatusBadRequest, "Unknown event type", "an event is icp, rot or ixn")
		return
	}

	res, err := c.Commit(name, raw, req.Sigs, func(k drivers.KELKeep) error {
		return s.keepCommittedEvent(k, ev)
	})
	if err != nil {
		writeEventError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch res.Status {
	case "waiting_for_signatures":
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"status": res.Status, "s": fmt.Sprintf("%x", res.SN),
			"d": res.SAID, "signed": res.Signed, "keys": res.Keys, "expires": res.Expires.UTC().Format(time.RFC3339)})
		return
	case "already_recorded":
		json.NewEncoder(w).Encode(map[string]any{"status": res.Status, "s": fmt.Sprintf("%x", res.SN), "d": res.SAID})
		return
	}
	s.afterCommit(ev)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"status": res.Status, "s": fmt.Sprintf("%x", res.SN), "d": res.SAID})
}

// ownerNamedIn is the owner a founding's first seal names, if it names one.
func ownerNamedIn(raw []byte) string {
	var m struct {
		A []map[string]any `json:"a"`
	}
	if json.Unmarshal(raw, &m) != nil || len(m.A) == 0 {
		return ""
	}
	if i, _ := m.A[0]["i"].(string); i != "" && m.A[0]["d"] == i && m.A[0]["s"] == "0" {
		return i
	}
	return ""
}

// keepCommittedEvent persists a committed event, with its signatures, before
// the engine adds it: superseded interactions moved aside first, signatures
// obtained for earlier events kept with them, and the identity's record moved
// on.
func (s *CoreServer) keepCommittedEvent(k drivers.KELKeep, ev *keri.Event) error {
	if len(k.Earlier) > 0 {
		events, err := s.DataStore.GetEvents(k.AID)
		if err != nil {
			return err
		}
		for _, rec := range events {
			if sigs, ok := k.Earlier[rec.SequenceNumber]; ok && len(rec.ControllerSignatures()) == 0 {
				rec.Signatures, rec.CesrSignature = sigs, sigs[0]
				if err := s.DataStore.SaveEvent(rec); err != nil {
					return err
				}
			}
		}
	}
	rec, err := eventRecordOf(k.AID, k.SN, k.Raw, k.Signatures)
	if err != nil {
		return err
	}
	save := s.DataStore.SaveEvent
	if k.Supersedes > 0 {
		save = s.DataStore.SaveSupersedingEvent
	}
	if err := save(rec); err != nil {
		return err
	}
	own, err := s.DataStore.GetIdentity()
	if err != nil {
		return err
	}
	switch {
	case ev.Ilk == "icp" && own == nil:
		return s.DataStore.SaveIdentity(store.IdentityState{AID: ev.Identifier, PublicKey: rec.PublicKey,
			NextKeyDigest: rec.NextKeyDigest, Created: rec.Timestamp, EventCount: 1})
	case own == nil:
		return fmt.Errorf("no identity record to move on")
	case k.Supersedes == 0 && k.SN+1 < own.EventCount, ev.Ilk == "icp":
		// More signatures for an event already in the log: the record of
		// where the log stands does not move back to it.
		return nil
	default:
		if ev.Ilk == "rot" {
			// Where this Identity Agent derives the key rotated to, its
			// record follows the generation, as a rotation here does.
			if _, gen, err := s.ownKeyAt(rec.PublicKey); err == nil {
				own.KeyGeneration = gen
			}
			own.PublicKey, own.NextKeyDigest = rec.PublicKey, rec.NextKeyDigest
		}
		own.EventCount = k.SN + 1
		return s.DataStore.SaveIdentity(*own)
	}
}

// eventRecordOf is the stored form of an event and its signatures.
func eventRecordOf(aid string, sn int, raw []byte, sigs []string) (store.EventRecord, error) {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return store.EventRecord{}, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return store.EventRecord{}, err
	}
	body, _ := json.Marshal(parsed)
	rec := store.EventRecord{AID: aid, SequenceNumber: sn, EventType: ev.Ilk, EventJSON: string(body),
		Timestamp: time.Now().UTC().Format(time.RFC3339), RawBytesB64: base64.StdEncoding.EncodeToString(raw),
		Signatures: sigs}
	if len(sigs) > 0 {
		rec.CesrSignature = sigs[0]
	}
	if len(ev.Keys) > 0 {
		rec.PublicKey = ev.Keys[0]
	}
	if len(ev.NextDigest) > 0 {
		rec.NextKeyDigest = ev.NextDigest[0]
	}
	return rec, nil
}

// afterCommit sends the identity's witnesses what they lack, now the event is
// in the log, and records that a backup is due after a rotation.
func (s *CoreServer) afterCommit(ev *keri.Event) {
	go s.witnessOwnLog()
	if ev.Ilk == "rot" {
		s.notifyBackupEvent(backup.EventKeyRotation)
	}
	log.Printf("[keri] %s at sequence number %d of %s committed signed", ev.Ilk, ev.SN, ev.Identifier)
}

// writeEventError answers a refused prepare or commit with what the signer
// needs to act on it.
func writeEventError(w http.ResponseWriter, err error) {
	var (
		moved      *keriengine.ErrTipMoved
		notCommit  *keriengine.ErrNotCommitted
		taken      *keriengine.ErrPlaceTaken
		notAuth    *keriengine.ErrNotAuthorised
		unsignedLg *keriengine.ErrUnsignedHistory
	)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.As(err, &moved):
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "tip_moved", "details": err.Error(),
			"tip": map[string]string{"s": fmt.Sprintf("%x", moved.Tip.SN), "d": moved.Tip.SAID}})
	case errors.As(err, &taken):
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "place_taken", "details": err.Error(),
			"s": fmt.Sprintf("%x", taken.Held.SN), "d": taken.Held.SAID})
	case errors.As(err, &notCommit):
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{"error": "not_committed", "details": err.Error()})
	case errors.As(err, &unsignedLg):
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "unsigned_history", "details": err.Error(),
			"unsigned": unsignedLg.SNs})
	case errors.As(err, &notAuth):
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "not_authorised", "details": err.Error()})
	default:
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "refused", "details": err.Error()})
	}
}

// handleEventReceipts returns the witness receipts this Identity Agent holds
// for its identity's event at s. A convenience: a signer outside the core
// reads the witnesses and verifies each receipt itself. Reading it changes
// nothing, so it is left to the router's gate, which admits the owner and the
// owner's controllers.
func (s *CoreServer) handleEventReceipts(w http.ResponseWriter, r *http.Request) {
	sn, err := sequenceFromHex(chi.URLParam(r, "s"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid sequence number", err.Error())
		return
	}
	own, err := s.DataStore.GetIdentity()
	if err != nil || own == nil {
		writeError(w, http.StatusNotFound, "There is no identity here", "")
		return
	}
	rec, err := s.eventAt(own.AID, sn)
	if err != nil {
		writeError(w, http.StatusNotFound, "No such event", err.Error())
		return
	}
	var parsed struct {
		D string `json:"d"`
	}
	_ = json.Unmarshal([]byte(rec.EventJSON), &parsed)
	receipts, err := s.DataStore.GetWitnessReceipts(parsed.D)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the receipts", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"s": fmt.Sprintf("%x", sn), "d": parsed.D, "receipts": receipts})
}
