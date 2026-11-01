package keriengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// Building an event without adding it, and adding it only with its
// signatures (ADR-061 section 3).
//
// A signer outside this engine, an app holding the identity's key or each
// owner of an identity with several, cannot sign an event that does not exist
// yet, and an event added before it is signed is an event nobody authorised.
// So Prepare builds the event's bytes and adds nothing, and Commit adds those
// bytes only with signatures that make the log one keri-go verifies, through
// the one append path every other event takes.

// Place names an event in a key log by sequence number and digest.
type Place struct {
	SN   int    `json:"s"`
	SAID string `json:"d"`
}

// PrepareRequest is everything an event is built from. Nothing is composed
// here that the request does not say, so preparing twice gives the same bytes.
type PrepareRequest struct {
	// Name is the identity held here that the event extends; empty for a
	// founding.
	Name string
	// Ilk is "icp", "rot" or "ixn".
	Ilk string
	// Keys, Kt, Next and Nt are a founding's or rotation's keys, signing
	// threshold, next-key digests and next threshold. Thresholds are KERI JSON:
	// "1", or a weighted list.
	Keys []string
	Kt   json.RawMessage
	Next []string
	Nt   json.RawMessage
	// Anchors are the event's seals, in order.
	Anchors []json.RawMessage
	// Witnesses and Toad are a founding's witnesses and threshold; Cuts, Adds
	// and Toad a rotation's changes to them.
	Witnesses []string
	Cuts      []string
	Adds      []string
	Toad      *int
	// After is the event a rotation or interaction follows. Nil means the tip,
	// which only a path inside the core that holds the key may rely on.
	After *Place
}

// Hint describes a prepared event for display. Nothing signs on its strength:
// a signer parses the bytes.
type Hint struct {
	T       string          `json:"t"`
	I       string          `json:"i"`
	S       string          `json:"s"`
	P       string          `json:"p,omitempty"`
	D       string          `json:"d"`
	K       []string        `json:"k,omitempty"`
	Kt      json.RawMessage `json:"kt,omitempty"`
	PriorN  []string        `json:"prior_n,omitempty"`
	PriorNt json.RawMessage `json:"prior_nt,omitempty"`
}

// Prepared is an event built and not added.
type Prepared struct {
	Raw  []byte
	Hint Hint
}

// ErrTipMoved is an event that follows neither the tip nor, for a rotation, a
// point it may recover from.
type ErrTipMoved struct{ Tip Place }

func (e *ErrTipMoved) Error() string {
	return fmt.Sprintf("the event does not follow the log's tip, which is now sequence number %d (%s)",
		e.Tip.SN, e.Tip.SAID)
}

// ErrNotCommitted is a rotation whose keys could not open the last
// establishment event's commitment however they signed.
type ErrNotCommitted struct{ Err error }

func (e *ErrNotCommitted) Error() string {
	return fmt.Sprintf("the rotation's keys cannot open the commitment the last establishment event made: %v", e.Err)
}

func (e *ErrNotCommitted) Unwrap() error { return e.Err }

// ErrPlaceTaken is an establishment event refused because a different one
// already holds its place. The refused event is kept as evidence of
// duplicity when its own signatures are valid.
type ErrPlaceTaken struct {
	Held Place
	Kept bool
}

func (e *ErrPlaceTaken) Error() string {
	return fmt.Sprintf("a different event already holds sequence number %d (%s)", e.Held.SN, e.Held.SAID)
}

// Evidence is an establishment event refused because another held its place,
// with its signatures. It is kept, never sent.
type Evidence struct {
	AID        string    `json:"aid"`
	SN         int       `json:"s"`
	SAID       string    `json:"d"`
	Raw        []byte    `json:"raw"`
	Signatures []string  `json:"signatures"`
	Reason     string    `json:"reason"`
	Seen       time.Time `json:"seen"`
}

// CommitResult is what a commit did.
type CommitResult struct {
	// Status is "recorded", "already_recorded" or "waiting_for_signatures".
	Status string
	AID    string
	SN     int
	SAID   string
	// Signatures are every signature now held for the event.
	Signatures []string
	// Signed and Keys say, for an event still waiting, which of its key
	// places have signed and how many it has; Expires is when it stops
	// waiting.
	Signed  []int
	Keys    int
	Expires time.Time
	// Superseded are the interactions a recovery rotation superseded.
	Superseded [][]byte
	// Evidence is what this commit set aside as duplicity.
	Evidence []Evidence
}

// heldEvent is an event waiting for more of its signers.
type heldEvent struct {
	raw     []byte
	ev      *keri.Event
	sigs    []string
	expires time.Time
}

// Limits on what waits, so nobody can fill the hold.
const (
	heldPerPlace    = 8
	heldPerIdentity = 32
	defaultHoldFor  = 7 * 24 * time.Hour
)

// SetHoldFor sets how long an event with several signers waits for the rest.
func (e *Engine) SetHoldFor(d time.Duration) {
	e.commitMu.Lock()
	e.holdFor = d
	e.commitMu.Unlock()
}

func (e *Engine) holdDuration() time.Duration {
	e.commitMu.Lock()
	defer e.commitMu.Unlock()
	if e.holdFor > 0 {
		return e.holdFor
	}
	return defaultHoldFor
}

func (e *Engine) now() time.Time {
	if e.clock != nil {
		return e.clock()
	}
	return time.Now()
}

// Prepare builds an event and returns its bytes. It adds nothing, keeps
// nothing, and sends nothing anywhere.
func (e *Engine) Prepare(req PrepareRequest) (*Prepared, error) {
	switch req.Ilk {
	case "icp":
		return prepareFounding(req)
	case "rot", "ixn":
	default:
		return nil, fmt.Errorf("an event is a founding (icp), a rotation (rot) or an interaction (ixn), not %q", req.Ilk)
	}
	id, err := e.state.get(req.Name)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	entries := append([]kelEntry(nil), id.KEL...)
	witnesses := append([]string(nil), id.Witnesses...)
	aid := id.AID
	e.state.mu.RUnlock()

	tip, err := tipOf(entries)
	if err != nil {
		return nil, err
	}
	estAt, est, err := lastEstablishment(entries)
	if err != nil {
		return nil, err
	}
	after := tip
	if req.After != nil {
		after = *req.After
	}
	at := after.SN + 1
	if after.SN < 0 || after.SN >= len(entries) || entryDigest(entries[after.SN]) != after.SAID {
		return nil, &ErrTipMoved{Tip: tip}
	}
	// An interaction follows the tip. A rotation follows the tip or, as a
	// recovery rotation, the last establishment event or any interaction
	// after it, superseding the interactions from there to the tip.
	if req.Ilk == "ixn" && after != tip {
		return nil, &ErrTipMoved{Tip: tip}
	}
	if req.Ilk == "rot" && after.SN < estAt {
		return nil, &ErrTipMoved{Tip: tip}
	}

	var raw []byte
	hint := Hint{T: req.Ilk, I: aid, S: fmt.Sprintf("%x", at), P: after.SAID}
	switch req.Ilk {
	case "ixn":
		if len(req.Anchors) == 0 {
			return nil, fmt.Errorf("an interaction with nothing to anchor would extend the log " +
				"without recording anything")
		}
		raw, err = keri.BuildInteraction(keri.InteractionInput{
			Prefix: aid, PriorSAID: after.SAID, SN: at, Data: req.Anchors,
		})
		if err != nil {
			return nil, fmt.Errorf("building the interaction: %w", err)
		}
	case "rot":
		if len(req.Keys) == 0 {
			return nil, fmt.Errorf("a rotation must name the keys it rotates to")
		}
		in := keri.RotationInput{
			Prefix: aid, Keys: req.Keys, PriorSAID: after.SAID, SN: at,
			NextDigests: req.Next, Isith: req.Kt, Nsith: req.Nt,
			PriorWitnesses: witnesses, Cuts: req.Cuts, Adds: req.Adds, Toad: req.Toad,
			Data: req.Anchors,
		}
		raw, err = keri.BuildRotation(in)
		if err != nil {
			return nil, fmt.Errorf("building the rotation: %w", err)
		}
		// Whether these keys could ever open the commitment, decided now so a
		// signer is never asked to sign a rotation nobody could authorise.
		raws, ok := verifiable(entries[:at])
		if !ok {
			return nil, fmt.Errorf("the log of %s was kept without the bytes it was published as, "+
				"so a rotation of it cannot be checked", aid)
		}
		if err := keri.ValidateKEL(append(raws, raw)); err != nil {
			var ve *keri.ValidationError
			if errors.As(err, &ve) && ve.Has(keri.FaultKeyNotPrecommitted) {
				return nil, &ErrNotCommitted{Err: err}
			}
			return nil, fmt.Errorf("the rotation would not make a valid log: %w", err)
		}
		hint.K = req.Keys
		hint.Kt = req.Kt
		hint.PriorN = est.NextDigest
		hint.PriorNt = thresholdText(est.Raw, "nt")
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	hint.D = ev.SAID
	return &Prepared{Raw: raw, Hint: hint}, nil
}

func prepareFounding(req PrepareRequest) (*Prepared, error) {
	if req.Name != "" || req.After != nil {
		return nil, fmt.Errorf("a founding extends no identity and follows no event")
	}
	if len(req.Keys) == 0 {
		return nil, fmt.Errorf("a founding must name its keys")
	}
	for i, w := range req.Witnesses {
		if len(w) != 44 || w[0] != 'B' {
			return nil, fmt.Errorf("witness %d is %q, which is not a non-transferable identifier", i, w)
		}
	}
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: req.Keys, NextDigests: req.Next, Isith: req.Kt, Nsith: req.Nt,
		Witnesses: req.Witnesses, Toad: req.Toad, Data: req.Anchors,
		Derivation: "self-addressing",
	})
	if err != nil {
		return nil, fmt.Errorf("building the founding: %w", err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	return &Prepared{Raw: raw, Hint: Hint{T: "icp", I: ev.Identifier, S: "0", D: ev.SAID,
		K: ev.Keys, Kt: thresholdText(raw, "kt")}}, nil
}

// Commit adds raw, a prepared event, with its signatures. name is the
// identity it extends, or, for a founding, the name to hold it under (empty
// for its identifier). keep is offered the event with its signatures before
// anything changes here.
func (e *Engine) Commit(name string, raw []byte, sigs []string, keep func(drivers.KELKeep) error) (*CommitResult, error) {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, fmt.Errorf("the event does not parse: %w", err)
	}
	if err := keri.ValidateEvent(raw); err != nil {
		return nil, fmt.Errorf("the event is not well formed: %w", err)
	}
	if ev.Ilk == "icp" {
		return e.commitFounding(name, raw, ev, sigs, keep)
	}
	if ev.Ilk != "rot" && ev.Ilk != "ixn" {
		return nil, fmt.Errorf("a %s is not committed here", ev.Ilk)
	}
	id, release, err := e.holdForWriting(name)
	if err != nil {
		return nil, err
	}
	defer release()
	if ev.Identifier != id.AID {
		return nil, fmt.Errorf("the event belongs to %s, not %s", ev.Identifier, id.AID)
	}
	e.state.mu.RLock()
	entries := append([]kelEntry(nil), id.KEL...)
	e.state.mu.RUnlock()
	tip, err := tipOf(entries)
	if err != nil {
		return nil, err
	}
	sn := int(ev.SN)
	res := &CommitResult{AID: id.AID, SN: sn, SAID: ev.SAID}

	// The same event already here: any further valid signature is kept.
	if sn < len(entries) && entryDigest(entries[sn]) == ev.SAID {
		res.Status = "already_recorded"
		merged := mergeSigs(entries[sn].Sigs, sigs)
		keys, kerr := signingKeys(entries[:sn], ev)
		indexed, ierr := indexedSignatures(merged, len(keys))
		if kerr == nil && ierr == nil && len(indexed) > len(entries[sn].Sigs) {
			if _, err := e.judge(id.AID, entries[:sn], raw, ev, indexed); err == nil {
				if keep != nil {
					if err := keep(drivers.KELKeep{AID: id.AID, SN: sn, Raw: raw, Signature: indexed[0], Signatures: indexed}); err != nil {
						return nil, err
					}
				}
				e.state.mu.Lock()
				if sn < len(id.KEL) && entryDigest(id.KEL[sn]) == ev.SAID {
					id.KEL[sn].Sigs = indexed
				}
				e.state.mu.Unlock()
			}
		}
		e.state.mu.RLock()
		res.Signatures = append([]string(nil), id.KEL[sn].Sigs...)
		e.state.mu.RUnlock()
		return res, nil
	}

	if sn < 1 || sn > len(entries) || entryDigest(entries[sn-1]) != ev.PriorSAID {
		return nil, &ErrTipMoved{Tip: tip}
	}
	estAt, _, err := lastEstablishment(entries)
	if err != nil {
		return nil, err
	}
	if sn < len(entries) {
		// The place is held. A rotation may take it from interactions after
		// the last establishment event: a recovery rotation.
		if ev.Ilk != "rot" || sn-1 < estAt {
			if ev.Ilk == "rot" && entryIsEstablishment(entries[sn]) {
				return nil, e.placeTaken(id, entries, raw, ev, sigs)
			}
			return nil, &ErrTipMoved{Tip: tip}
		}
	}

	keys, err := signingKeys(entries[:sn], ev)
	if err != nil {
		return nil, err
	}
	merged := sigs
	if h := e.heldAt(id, sn, ev.SAID); h != nil {
		merged = mergeSigs(h.sigs, sigs)
	}
	indexed, err := indexedSignatures(merged, len(keys))
	if err != nil {
		return nil, &ErrNotAuthorised{AID: id.AID, SN: sn, Err: err, BadSignature: true}
	}
	if len(indexed) > len(keys) {
		return nil, &ErrNotAuthorised{AID: id.AID, SN: sn, BadSignature: true,
			Err: fmt.Errorf("%d signatures for an event %d keys sign", len(indexed), len(keys))}
	}

	var superseded [][]byte
	for _, en := range entries[sn:] {
		superseded = append(superseded, en.Raw)
	}
	err = e.place(id, entries, sn, raw, ev, indexed, keep, func(ev *keri.Event) {
		if ev.Ilk == "rot" {
			id.Witnesses = witnessesAfter(id.Witnesses, ev)
			id.Toad = witnessThreshold(ev)
		}
	})
	var na *ErrNotAuthorised
	if errors.As(err, &na) && !na.BadSignature && len(keys) > 1 {
		// Signatures that are right and too few: an event with several
		// signers waits for the rest.
		signed, ok := signaturesVerify(raw, indexed, keys)
		if ok {
			expires, herr := e.hold(id, sn, raw, ev, indexed)
			if herr != nil {
				return nil, herr
			}
			res.Status, res.Signatures, res.Signed, res.Keys, res.Expires =
				"waiting_for_signatures", indexed, signed, len(keys), expires
			return res, nil
		}
	}
	if err != nil {
		return nil, err
	}
	res.Status, res.Signatures, res.Superseded = "recorded", indexed, superseded
	res.Evidence = e.releaseHeldAt(id, sn, ev.SAID)
	return res, nil
}

func (e *Engine) commitFounding(name string, raw []byte, ev *keri.Event, sigs []string, keep func(drivers.KELKeep) error) (*CommitResult, error) {
	indexed, err := indexedSignatures(sigs, len(ev.Keys))
	if err != nil {
		return nil, &ErrNotAuthorised{AID: ev.Identifier, Err: err, BadSignature: true}
	}
	if name == "" {
		name = ev.Identifier
	}
	if held, err := e.state.get(name); err == nil {
		if held.AID == ev.Identifier && len(held.KEL) > 0 && entryDigest(held.KEL[0]) == ev.SAID {
			return &CommitResult{Status: "already_recorded", AID: ev.Identifier, SAID: ev.SAID,
				Signatures: append([]string(nil), held.KEL[0].Sigs...)}, nil
		}
		return nil, fmt.Errorf("the name %q already holds %s", name, held.AID)
	}
	if _, err := e.judge(ev.Identifier, nil, raw, ev, indexed); err != nil {
		return nil, err
	}
	first, err := entry(raw)
	if err != nil {
		return nil, err
	}
	first.Sigs = indexed
	if keep != nil {
		if err := keep(drivers.KELKeep{AID: ev.Identifier, SN: 0, Raw: raw, Signature: indexed[0], Signatures: indexed}); err != nil {
			return nil, fmt.Errorf("the founding was not kept, so it was not added: %w", err)
		}
	}
	id := &identity{
		Name: name, AID: ev.Identifier, PublicKey: ev.Keys[0],
		Witnesses: ev.Witnesses, Toad: witnessThreshold(ev),
		SN: 0, LastSAID: ev.SAID, KEL: []kelEntry{first},
		Registries: map[string]*registry{}, HistoryVerified: true,
	}
	if len(ev.NextDigest) > 0 {
		id.NextKeyDigest = ev.NextDigest[0]
	}
	if err := e.state.claim(id); err != nil {
		return nil, err
	}
	return &CommitResult{Status: "recorded", AID: ev.Identifier, SN: 0, SAID: ev.SAID, Signatures: indexed}, nil
}

// placeTaken answers a rotation at a place another establishment event holds,
// keeping the refused event as evidence when its own signatures are valid.
func (e *Engine) placeTaken(id *identity, entries []kelEntry, raw []byte, ev *keri.Event, sigs []string) error {
	sn := int(ev.SN)
	held := Place{SN: sn, SAID: entryDigest(entries[sn])}
	indexed, err := indexedSignatures(sigs, len(ev.Keys))
	if err != nil {
		return &ErrPlaceTaken{Held: held}
	}
	if _, err := e.judge(id.AID, entries[:sn], raw, ev, indexed); err != nil {
		return &ErrPlaceTaken{Held: held}
	}
	e.state.mu.Lock()
	id.evidence = append(id.evidence, Evidence{AID: id.AID, SN: sn, SAID: ev.SAID, Raw: raw,
		Signatures: indexed, Reason: "place_taken", Seen: e.now()})
	e.state.mu.Unlock()
	return &ErrPlaceTaken{Held: held, Kept: true}
}

// heldAt is the event waiting at sn with this digest, if any and not expired.
func (e *Engine) heldAt(id *identity, sn int, said string) *heldEvent {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	e.expireHeld(id)
	for _, h := range id.held[sn] {
		if h.ev.SAID == said {
			return h
		}
	}
	return nil
}

// hold keeps an event waiting for more signers, within the limits.
func (e *Engine) hold(id *identity, sn int, raw []byte, ev *keri.Event, sigs []string) (time.Time, error) {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	e.expireHeld(id)
	if id.held == nil {
		id.held = map[int][]*heldEvent{}
	}
	for _, h := range id.held[sn] {
		if h.ev.SAID == ev.SAID {
			h.sigs = sigs
			return h.expires, nil
		}
	}
	total := 0
	for _, hs := range id.held {
		total += len(hs)
	}
	if len(id.held[sn]) >= heldPerPlace || total >= heldPerIdentity {
		return time.Time{}, fmt.Errorf("too many events already wait for signatures on %s", id.AID)
	}
	h := &heldEvent{raw: raw, ev: ev, sigs: sigs, expires: e.now().Add(e.holdDuration())}
	id.held[sn] = append(id.held[sn], h)
	return h.expires, nil
}

// releaseHeldAt drops every other event waiting at sn once one is added there,
// keeping as evidence any that is a different establishment event.
func (e *Engine) releaseHeldAt(id *identity, sn int, added string) []Evidence {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	var kept []Evidence
	for _, h := range id.held[sn] {
		if h.ev.SAID == added || !h.ev.Establishment() {
			continue
		}
		ev := Evidence{AID: id.AID, SN: sn, SAID: h.ev.SAID, Raw: h.raw, Signatures: h.sigs,
			Reason: "dropped_candidate", Seen: e.now()}
		id.evidence = append(id.evidence, ev)
		kept = append(kept, ev)
	}
	delete(id.held, sn)
	return kept
}

// expireHeld drops what has waited too long. Only the hold: nothing held was
// ever in the log or sent anywhere. The caller holds the state lock.
func (e *Engine) expireHeld(id *identity) {
	now := e.now()
	for sn, hs := range id.held {
		live := hs[:0]
		for _, h := range hs {
			if now.Before(h.expires) {
				live = append(live, h)
			}
		}
		if len(live) == 0 {
			delete(id.held, sn)
		} else {
			id.held[sn] = live
		}
	}
}

// EvidenceOf is what has been kept as duplicity for an identity.
func (e *Engine) EvidenceOf(name string) ([]Evidence, error) {
	id, err := e.state.get(name)
	if err != nil {
		return nil, err
	}
	e.state.mu.RLock()
	defer e.state.mu.RUnlock()
	return append([]Evidence(nil), id.evidence...), nil
}

func mergeSigs(a, b []string) []string {
	out := append([]string(nil), a...)
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func tipOf(entries []kelEntry) (Place, error) {
	if len(entries) == 0 {
		return Place{}, fmt.Errorf("an empty log has no tip")
	}
	last := entries[len(entries)-1]
	return Place{SN: len(entries) - 1, SAID: entryDigest(last)}, nil
}

func entryDigest(en kelEntry) string {
	if d, ok := en.Parsed["d"].(string); ok {
		return d
	}
	if en.Raw != nil {
		if ev, err := keri.ParseEvent(en.Raw); err == nil {
			return ev.SAID
		}
	}
	return ""
}

func entryIsEstablishment(en kelEntry) bool {
	t, _ := en.Parsed["t"].(string)
	return t == "icp" || t == "rot" || t == "dip" || t == "drt"
}

// thresholdText is a threshold field exactly as the event carries it.
func thresholdText(raw []byte, field string) json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m[field]
}

// foundingSignatures are the installed signer's signatures over a founding
// this engine built, where its caller holds the founding keys, kept only if
// they verify. Where nobody here holds them the founding is held unsigned, as
// it always was, until its signer signs it; nothing is added after it until
// then.
func (e *Engine) foundingSignatures(ev *keri.Event, raw []byte) []string {
	sigs := e.ownSignatures(ev.Identifier, ev.Keys, raw)
	if len(sigs) == 0 {
		return nil
	}
	m, err := signedMessage(raw, sigs)
	if err != nil {
		return nil
	}
	if _, err := keri.ValidateSignedKEL([][]byte{m}); err != nil {
		return nil
	}
	return sigs
}
