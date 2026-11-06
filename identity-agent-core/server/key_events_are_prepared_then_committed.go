package server

import (
	"context"
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
	"identity-agent-core/internal/jsonreply"
	"identity-agent-core/keriengine"
	"identity-agent-core/store"
	"identity-agent-core/witness"

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
	if !s.theOwnerAsks(r) {
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
	pr, err := req.engineRequest()
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid witness threshold", err.Error())
		return
	}

	switch req.T {
	case "icp":
		var ok bool
		if pr, ok = s.foundingRequest(w, req, pr, false); !ok {
			return
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
	jsonreply.Write(w, http.StatusOK, prepareEventResponse{RawB64: base64.StdEncoding.EncodeToString(p.Raw), Hint: p.Hint})
}

// handleWitnessesForAFounding answers who this Identity Agent would name as
// the witnesses of a new root identity, and how many must receipt its
// founding: each one's key, the address it is reached at, and the threshold.
// A signer that founds the identity itself asks, confirms each witness by its
// own signed answer, and names the ones that answer in the founding it signs.
// An empty list is a real answer: it would found the identity unwitnessed.
func (s *CoreServer) handleWitnessesForAFounding(w http.ResponseWriter, r *http.Request) {
	if !s.theOwnerAsks(r) {
		writeError(w, http.StatusForbidden, "Key events are the owner's", "only the owner asks who would witness a founding")
		return
	}
	// The first step of a founding, so it is refused where a founding is.
	if s.refuseIfThisComputerMayNotFound(w) {
		return
	}
	type proposed struct {
		AID     string `json:"aid"`
		Address string `json:"address"`
	}
	out := struct {
		Witnesses []proposed `json:"witnesses"`
		Toad      int        `json:"toad"`
	}{Witnesses: []proposed{}}
	if s.WitnessService != nil {
		ws, toad := s.WitnessService.ProposedWitnessesForNewIdentity(witness.AidKindRoot, "")
		for _, p := range ws {
			out.Witnesses = append(out.Witnesses, proposed{AID: p.Key, Address: p.Address})
		}
		out.Toad = toad
	}
	jsonreply.Write(w, http.StatusOK, out)
}

// engineRequest is what the engine prepares req from.
func (req prepareEventRequest) engineRequest() (keriengine.PrepareRequest, error) {
	toad, err := witnessThresholdOf(req.Bt)
	if err != nil {
		return keriengine.PrepareRequest{}, err
	}
	return keriengine.PrepareRequest{Ilk: req.T, Keys: req.K, Kt: req.Kt, Next: req.N, Nt: req.Nt,
		Anchors: req.A, Witnesses: req.B, Cuts: req.Br, Adds: req.Ba, Toad: toad}, nil
}

// foundingRequest is how a founding is prepared, whichever route asks for one:
// the founding gate, the owner's seal ahead of the anchors the app asks for,
// and the witnesses and threshold it names. pr is req as engineRequest read it.
// A route that founds a new root beside an identity kept here, the break-glass
// rotation, says replacing, and the gate then does not refuse for the identity
// already here. A refusal is answered here; ok is false then.
func (s *CoreServer) foundingRequest(w http.ResponseWriter, req prepareEventRequest, pr keriengine.PrepareRequest,
	replacing bool) (keriengine.PrepareRequest, bool) {

	if !s.mayFound(w, req.OwnerAID, replacing) {
		return pr, false
	}
	if req.AID != "" || req.After != nil {
		writeError(w, http.StatusBadRequest, "A founding extends nothing", "aid and after are not given for a founding")
		return pr, false
	}
	if req.OwnerAID != "" {
		seal, err := keriengine.OwnerSeal(req.OwnerAID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid owner", err.Error())
			return pr, false
		}
		pr.Anchors = append([]json.RawMessage{seal}, req.A...)
	}
	return pr, true
}

// mayFoundHere is the founding gate the inception route applies.
func (s *CoreServer) mayFoundHere(w http.ResponseWriter, ownerAID string) bool {
	return s.mayFound(w, ownerAID, false)
}

// mayFound is mayFoundHere, or, for a new root that replaces the identity kept
// here, the same gate without the refusal for that identity.
func (s *CoreServer) mayFound(w http.ResponseWriter, ownerAID string, replacing bool) bool {
	if s.refuseIfThisComputerMayNotFound(w) {
		return false
	}
	if existing, _ := s.DataStore.GetIdentity(); existing != nil && !replacing {
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
	if !s.theOwnerAsks(r) {
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

	res, ok := s.commitOwnEvent(w, c, name, raw, ev, req.Sigs)
	if !ok {
		return
	}
	switch res.Status {
	case "waiting_for_signatures":
		jsonreply.Write(w, http.StatusAccepted, map[string]any{"status": res.Status, "s": fmt.Sprintf("%x", res.SN),
			"d": res.SAID, "signed": res.Signed, "keys": res.Keys, "expires": res.Expires.UTC().Format(time.RFC3339)})
		return
	case "already_recorded":
		jsonreply.Write(w, http.StatusOK, map[string]any{"status": res.Status, "s": fmt.Sprintf("%x", res.SN), "d": res.SAID})
		return
	}
	jsonreply.Write(w, http.StatusCreated, map[string]any{"status": res.Status, "s": fmt.Sprintf("%x", res.SN), "d": res.SAID})
}

// commitOwnEvent commits raw, an event of this Identity Agent's identity, with
// sigs: the one place an event signed elsewhere is committed, whichever route
// it came by. It refuses an event anchoring messaging keys this Identity Agent
// does not hold, keeps the event before the engine adds it, and once it is
// added files the keys a founding anchors and brings the witnesses up to date.
// A refusal is answered here; ok is false then.
func (s *CoreServer) commitOwnEvent(w http.ResponseWriter, c eventCommitter, name string, raw []byte,
	ev *keri.Event, sigs []string) (*keriengine.CommitResult, bool) {

	keysFor := name
	if ev.Ilk == "icp" {
		keysFor = ev.Identifier
	}
	if s.refuseAnUnheldKeySet(w, raw, keysFor) {
		return nil, false
	}
	res, err := s.commitAndNote(c, name, raw, ev, sigs)
	if err != nil {
		writeEventError(w, err)
		return nil, false
	}
	return res, true
}

// commitAndNote is the commit and what follows an added event, without the
// answer: the engine adds the event after it is kept, then the keys it anchors
// are filed and the witnesses brought up to date.
func (s *CoreServer) commitAndNote(c eventCommitter, name string, raw []byte, ev *keri.Event,
	sigs []string) (*keriengine.CommitResult, error) {

	res, err := c.Commit(name, raw, sigs, func(k drivers.KELKeep) error {
		return s.keepCommittedEvent(k, ev)
	})
	if err != nil {
		return nil, err
	}
	if res.Status == "recorded" {
		if err := s.fileCommittedKeySet(raw, ev.Identifier); err != nil {
			log.Printf("[keri] the messaging keys %s anchors could not be filed under it: %v", ev.Identifier, err)
		}
		s.afterCommit(ev)
	}
	return res, nil
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
	if k.Supersedes > 0 && !s.alreadyKept(rec) {
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

// alreadyKept is whether the log already holds rec's event at its place: a
// superseding rotation that was kept and not added to the engine, because what
// follows it failed. Superseding again would move the rotation itself aside.
func (s *CoreServer) alreadyKept(rec store.EventRecord) bool {
	events, err := s.DataStore.GetEvents(rec.AID)
	if err != nil || rec.SequenceNumber >= len(events) {
		return false
	}
	var held, got struct {
		D string `json:"d"`
	}
	return json.Unmarshal([]byte(events[rec.SequenceNumber].EventJSON), &held) == nil &&
		json.Unmarshal([]byte(rec.EventJSON), &got) == nil && held.D != "" && held.D == got.D
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
	s.inBackground(func(context.Context) { s.witnessOwnLog() })
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
	switch {
	case errors.As(err, &moved):
		jsonreply.Write(w, http.StatusConflict, map[string]any{"error": "tip_moved", "details": err.Error(),
			"tip": map[string]string{"s": fmt.Sprintf("%x", moved.Tip.SN), "d": moved.Tip.SAID}})
	case errors.As(err, &taken):
		jsonreply.Write(w, http.StatusConflict, map[string]any{"error": "place_taken", "details": err.Error(),
			"s": fmt.Sprintf("%x", taken.Held.SN), "d": taken.Held.SAID})
	case errors.As(err, &notCommit):
		jsonreply.Write(w, http.StatusUnprocessableEntity, map[string]any{"error": "not_committed", "details": err.Error()})
	case errors.As(err, &unsignedLg):
		jsonreply.Write(w, http.StatusConflict, map[string]any{"error": "unsigned_history", "details": err.Error(),
			"unsigned": unsignedLg.SNs})
	case errors.As(err, &notAuth):
		jsonreply.Write(w, http.StatusBadRequest, map[string]any{"error": "not_authorised", "details": err.Error()})
	default:
		jsonreply.Write(w, http.StatusBadRequest, map[string]any{"error": "refused", "details": err.Error()})
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
	jsonreply.Write(w, http.StatusOK, map[string]any{"s": fmt.Sprintf("%x", sn), "d": parsed.D, "receipts": receipts})
}

// theOwnerAsks is whether r is the owner's: admitted as the owner by the gate,
// which spends an owner signature when it checks it, or the owner at this
// computer. A remote owner whose signature the gate already checked would be
// refused by asking isOwner again.
func (s *CoreServer) theOwnerAsks(r *http.Request) bool {
	return theGateAdmittedTheOwner(r) || s.isOwner(r)
}
