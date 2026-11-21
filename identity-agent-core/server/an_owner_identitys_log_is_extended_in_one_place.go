package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"

	"identity-agent-core/drivers"
	"identity-agent-core/keriengine"
	"identity-agent-core/ownership"
	"identity-agent-core/store"
)

// An owner identity's key log is extended here and nowhere else.
//
// An owner's device holds, for each machine it owns, a pairwise owner
// identity. That identity anchors, in its own key log, the establishment
// event of the Identity Agent it owns (ADR-087): an interaction event that
// carries an event seal of that event. This file is the one writer of those
// interactions.
//
// Two different events signed at one place of an owner log are duplicity, and
// a verifier shown them treats nothing as owned by that identity. So the
// writer never signs before the place is reserved (ADR-061 section 4), in
// this order, for one owner identity at a time:
//
//  1. Finish any reservation left waiting, by signing the bytes it holds,
//     where the witnesses agree with the kept log and those bytes still
//     follow it.
//  2. Answer with the event already in the log if it anchors what is asked.
//  3. Check the kept log against the tip the witnesses hold.
//  4. Build the interaction's bytes, adding nothing to any log.
//  5. Reserve: write the place, the digest before it, the digest and the
//     bytes to the store, through to disk, with the Identity Agent anchored.
//  6. Sign the reserved bytes. The key is released for those bytes only.
//  7. Keep the signed event and mark the reservation done, together, and
//     only then let the engine hold it and queue it for the witnesses. An
//     event kept and not queued, because the device stopped or the queue
//     failed, is queued again when the core starts and when the same anchor
//     is asked for again.
//
// A device that stops anywhere after step 5 finds the reservation when it
// starts again and signs the same bytes. A device that stops before it has
// signed nothing.
//
// What the reservation guarantees, and what it does not. It is a row in this
// device's database, so it holds within that one database: across crashes,
// restarts and callers racing each other, at most one event is signed at a
// place. It cannot see another database. A device restored from a backup
// older than its last anchor, or a second copy of the Identity Agent holding
// the same root seed, finds no reservation at a place the first copy already
// used, and would sign a different event there. Only the owner identity's
// witnesses hold the log both copies extend, so the rule across copies is
// theirs to keep (ADR-087 decisions 10 and 12): the writer continues only
// from a log the witnesses' tip agrees with, and sends every event it keeps
// to them.
//
// Neither can be done yet. So the writer depends on both through
// ownerLogWitnesses, whose value in a running core is witnessesNotYetAskable:
// it refuses, and the writer signs nothing in a running core until a real
// check and a real queue replace it. Tests supply a stand-in.
//
// The check cannot be passed by. The engine holds every owner log, so that
// it can extend one, and the engine's signer is where an owner identity's
// key is found. That signer signs an owner identity's key event only with a
// permit the writer gives, in memory, under its lock and after the witness
// check, for one place and one digest, and the signing consumes it. So the
// engine asked by anything else, for any bytes, gets no signature. And the
// routes that have the engine build a key event by name (/interact,
// /rotation and a recovery's rotation) extend only this Identity Agent's own
// log, as /events/prepare and /events/commit do; /store/event writes no row
// into an owner identity's log.

// ownerLogStep is a point in the writer a test can stop it at, standing in
// for the device stopping there.
type ownerLogStep string

const (
	ownerLogBeforeReserving ownerLogStep = "before the reservation"
	ownerLogReserved        ownerLogStep = "after the reservation"
	ownerLogSigned          ownerLogStep = "after the signature"
	ownerLogSaved           ownerLogStep = "after the save"
)

// ownerLogState is what the writer holds between calls.
type ownerLogState struct {
	// writers holds one lock to an owner identity: one writer extends its log
	// at a time.
	writers sync.Map
	// stopAt, when set by a test, is asked at each step and stops the writer
	// there by returning an error.
	stopAt func(ownerLogStep) error
	// witnesses is what the writer asks of an owner identity's witnesses.
	// Left unset, as it is in a running core, it is witnessesNotYetAskable.
	// Only a test sets it.
	witnesses ownerLogWitnesses
	// permits holds, by owner identity, the one signing the writer has just
	// allowed: a place and the digest of the bytes reserved there. The signer
	// consumes it, and signs nothing as an owner identity without one. Held in
	// memory only, so nothing that outlives the writer's call can allow a
	// signature.
	permits sync.Map
}

// ownerLogPermit is a signing the writer allows: the event reserved at one
// place of one owner identity's log, named by its digest.
type ownerLogPermit struct {
	sn     int
	digest string
}

// errOwnerLogSigningNotPermitted is the signer asked to sign an owner
// identity's key event by anything other than the writer.
var errOwnerLogSigningNotPermitted = errors.New("an owner identity's key signs a key event only when the " +
	"one writer of its log asks, after the witnesses' copy of the log was checked")

// ownerLogWitnesses is what the writer needs from an owner identity's
// witnesses before it signs, and after it keeps, an event of that identity's
// log. A reservation keeps one event to a place within one database; these
// keep it across every copy of the log (ADR-087 decisions 10 and 12).
type ownerLogWitnesses interface {
	// continuesFromWhatTheyHold returns nil only when the kept log, as the
	// engine holds it, is the log the owner identity's witnesses hold: the
	// tip they answer with is its tip. With no answer from them it refuses.
	continuesFromWhatTheyHold(owner string, kept *drivers.DriverKelResponse) error
	// await queues an event kept in the owner identity's log to be sent to
	// its witnesses, and sent again across restarts until each has receipted
	// it.
	//
	// It is asked more than once for one event, and must queue that event
	// once however often it is asked. The writer asks for an event only after
	// keeping it, and a device can stop, or await can fail, between the two.
	// So every event of a kept owner log after its founding is asked for
	// again when the core starts (reloadOwnerLogs) and when an anchor already
	// in the log is asked for again (anchorInOwnerLog), by
	// queueKeptOwnerLogEvents.
	await(owner string, sn int) error
}

// errOwnerLogWitnessesNotYetAskable is why a running core extends no owner
// log yet.
var errOwnerLogWitnessesNotYetAskable = errors.New("an owner identity's key log cannot be extended " +
	"until the copy its witnesses hold can be checked and each event sent to them")

// witnessesNotYetAskable is the value of ownerLogWitnesses in a running core.
// Nothing asks an owner identity's witnesses for their tip yet, and nothing
// queues an event for them, so it refuses both, and with them every
// signature of the writer.
type witnessesNotYetAskable struct{}

func (witnessesNotYetAskable) continuesFromWhatTheyHold(string, *drivers.DriverKelResponse) error {
	return errOwnerLogWitnessesNotYetAskable
}

func (witnessesNotYetAskable) await(string, int) error { return errOwnerLogWitnessesNotYetAskable }

// ownerLogWitnesses is what the writer asks of the witnesses: the value a
// test supplied, or in a running core witnessesNotYetAskable.
func (s *CoreServer) ownerLogWitnesses() ownerLogWitnesses {
	if s.ownerLog.witnesses == nil {
		return witnessesNotYetAskable{}
	}
	return s.ownerLog.witnesses
}

// ownerLogEngine is an engine that can extend a log found by its identifier.
type ownerLogEngine interface {
	eventCommitter
	NameHolding(aid string) (name string, held bool, err error)
}

// ownerLogEvent is an event of an owner identity's key log, as signed.
type ownerLogEvent struct {
	OwnerAID   string
	SN         int
	SAID       string
	Raw        []byte
	Signatures []string
	// Written is false where the log already held the event asked for.
	Written bool
}

// errOwnerLogCannotBeExtended is a log this device will not extend because it
// cannot show the log is whole.
var errOwnerLogCannotBeExtended = errors.New("the owner identity's key log cannot be extended")

func (s *CoreServer) ownerLogStop(step ownerLogStep) error {
	if s.ownerLog.stopAt == nil {
		return nil
	}
	return s.ownerLog.stopAt(step)
}

// anchorInOwnerLog writes, in owner's key log, the interaction that seals one
// event of the Identity Agent m: the event at sequence number sealedSN whose
// digest is sealedSAID. Asked again for the same event, it writes nothing and
// returns the event it wrote.
//
// The writer checks only the shape of what it is handed: that m and
// sealedSAID look like digests, that a founding's digest is m, and that owner
// is not m. It does not see m's event at all. An anchor is never withdrawn,
// so a caller establishes all of the following before it asks, and the
// writer cannot tell whether it did.
//
// For the founding of m (ADR-087 decision 6, step 2), the caller holds the
// prepared inception's exact bytes and its signature, and has verified that:
//   - the digest of those bytes is m, its sequence number is 0 and it names
//     no prior event;
//   - it is an icp and names no delegator;
//   - its first key is the one the machine offered (and, on sealed hardware,
//     the one its attestation covers), its next-key digest matches, and the
//     signature is by that key;
//   - its owner set is exactly owner, with no other owner and no other seal;
//   - its witnesses and their threshold are ones the device accepts;
//   - owner's log anchors nothing yet, or already seals exactly these bytes
//     (a founding being resumed).
//
// For a later establishment event of m (decision 9), the caller has also
// verified m's whole key log up to and including that event, and that owner
// enters m's owner set at that event, rather than being carried over from
// the set before it.
//
// And in every case the witness check of decision 10 is a precondition: the
// log this writer continues from must be the one owner's witnesses hold.
// The writer asks ownerLogWitnesses for it itself, and refuses without it.
func (s *CoreServer) anchorInOwnerLog(owner, m string, sealedSN int, sealedSAID string) (*ownerLogEvent, error) {
	if !isASelfAddressingIdentifier(m) || !isASelfAddressingIdentifier(sealedSAID) || sealedSN < 0 {
		return nil, fmt.Errorf("an anchor names an Identity Agent, a sequence number and the digest of its event")
	}
	if sealedSN == 0 && sealedSAID != m {
		return nil, fmt.Errorf("the founding of %s has its identifier as its digest, not %s", m, sealedSAID)
	}
	if m == owner {
		return nil, fmt.Errorf("an owner identity does not anchor itself")
	}
	// The one writer of an event seal, with the sequence number in lowercase
	// hex as an event writes it.
	seal, err := drivers.EventSeal(m, fmt.Sprintf("%x", sealedSN), sealedSAID)
	if err != nil {
		return nil, err
	}

	lock, _ := s.ownerLog.writers.LoadOrStore(owner, &sync.Mutex{})
	lock.(*sync.Mutex).Lock()
	defer lock.(*sync.Mutex).Unlock()

	id, minted, err := s.DataStore.MachineOwnerIdentity(owner)
	switch {
	case err != nil:
		return nil, err
	case !minted:
		return nil, store.ErrNotAnOwnerIdentity
	case id.GivenUpFor != "":
		return nil, store.ErrOwnerIdentityGivenUp
	case id.DuplicitousAt != nil:
		return nil, store.ErrOwnerIdentityDuplicitous
	case id.AnchoredM != "" && id.AnchoredM != m:
		return nil, fmt.Errorf("%w: %s", store.ErrOwnerLogNamesAnother, id.AnchoredM)
	}

	eng, name, err := s.heldOwnerLog(owner)
	if err != nil {
		return nil, err
	}
	if _, err := s.finishReservedOwnerLogEvents(eng, name, owner); err != nil {
		return nil, err
	}
	kel, err := s.KeriDriver.GetKel(name)
	if err != nil {
		return nil, err
	}
	// The log itself is read as well as the record beside it: a device whose
	// record was rebuilt holds the log and may not hold the record.
	already, other := anchorsIn(kel, m, seal)
	if other != "" {
		return nil, fmt.Errorf("%w: %s", store.ErrOwnerLogNamesAnother, other)
	}
	if already != nil {
		// Kept, and perhaps never queued: queued again, which changes nothing
		// for an event already queued.
		if err := s.queueKeptOwnerLogEvents(owner, kel); err != nil {
			return nil, err
		}
		return already, nil
	}
	if err := s.ownerLogWitnesses().continuesFromWhatTheyHold(owner, kel); err != nil {
		return nil, err
	}
	if err := s.ownerLogStop(ownerLogBeforeReserving); err != nil {
		return nil, err
	}

	prepared, err := eng.Prepare(keriengine.PrepareRequest{Name: name, Ilk: "ixn", Anchors: []json.RawMessage{seal}})
	if err != nil {
		return nil, err
	}
	asked := store.OwnerLogReservation{
		OwnerAID: owner, SN: kel.EventCount, PriorDigest: prepared.Hint.P, Digest: prepared.Hint.D,
		RawB64: base64.StdEncoding.EncodeToString(prepared.Raw),
	}
	reserved, err := s.DataStore.ReserveOwnerLogPlace(asked, m)
	if err != nil {
		return nil, err
	}
	if reserved.Digest != asked.Digest || reserved.RawB64 != asked.RawB64 {
		// The place was reserved for another event, which the pass above
		// should have finished. Nothing is signed for this one.
		return nil, fmt.Errorf("%w: sequence number %d is reserved for another event",
			errOwnerLogCannotBeExtended, reserved.SN)
	}
	if err := s.ownerLogStop(ownerLogReserved); err != nil {
		return nil, err
	}
	return s.signAndKeepReserved(eng, name, reserved)
}

// finishReservedOwnerLogEvents signs and keeps every event of owner's log
// that was reserved and not yet kept: what a device that stopped between
// reserving and keeping left behind. The bytes signed are the bytes reserved,
// and only where the witnesses' copy of the log agrees with the kept one: a
// reservation can be left by a database restored from elsewhere.
func (s *CoreServer) finishReservedOwnerLogEvents(eng ownerLogEngine, name, owner string) (int, error) {
	reserved, err := s.DataStore.OwnerLogReservations(owner)
	if err != nil {
		return 0, err
	}
	waiting := 0
	for _, r := range reserved {
		if r.State != store.OwnerLogDone {
			waiting++
		}
	}
	if waiting == 0 {
		return 0, nil
	}
	kel, err := s.KeriDriver.GetKel(name)
	if err != nil {
		return 0, err
	}
	if err := s.ownerLogWitnesses().continuesFromWhatTheyHold(owner, kel); err != nil {
		return 0, fmt.Errorf("%d event(s) reserved in the key log of %s were not finished: %w", waiting, owner, err)
	}
	finished := 0
	for _, r := range reserved {
		if r.State == store.OwnerLogDone {
			continue
		}
		if _, err := s.signAndKeepReserved(eng, name, r); err != nil {
			return finished, fmt.Errorf("the event reserved at sequence number %d of %s could not be finished: %w",
				r.SN, owner, err)
		}
		finished++
	}
	return finished, nil
}

// signAndKeepReserved signs the bytes a reservation holds, keeps the signed
// event with the reservation marked done, and has the engine hold it.
func (s *CoreServer) signAndKeepReserved(eng ownerLogEngine, name string, r store.OwnerLogReservation) (*ownerLogEvent, error) {
	raw, err := drivers.DecodeRawBytes(r.RawB64)
	if err != nil {
		return nil, err
	}
	// Through the engine's signer, which is where an owner identity's key is
	// found from its stored index, and found only for reserved bytes. Every
	// caller of this holds the writer's lock and has had the witness check
	// pass, so this is where the one signing is allowed, for these bytes at
	// this place, and taken back whether or not it was used, a panic inside
	// the signer included.
	sig, err := s.signWithPermit(r, raw)
	if err != nil {
		return nil, err
	}
	if err := s.ownerLogStop(ownerLogSigned); err != nil {
		return nil, err
	}
	res, err := eng.Commit(name, raw, []string{sig}, func(k drivers.KELKeep) error {
		rec, err := eventRecordOf(k.AID, k.SN, k.Raw, k.Signatures)
		if err != nil {
			return err
		}
		if err := s.DataStore.KeepOwnerLogEvent(rec); err != nil {
			return err
		}
		return s.ownerLogStop(ownerLogSaved)
	})
	if err != nil {
		return nil, err
	}
	if res.Status == "waiting_for_signatures" {
		return nil, fmt.Errorf("%w: its key state needs more than this device's signature", errOwnerLogCannotBeExtended)
	}
	s.servedOwnerLogFollowsTheKeptOne(r.OwnerAID)
	if err := s.ownerLogWitnesses().await(r.OwnerAID, res.SN); err != nil {
		return nil, fmt.Errorf("the event at sequence number %d of %s is kept and was not queued for its witnesses, "+
			"and is queued again when the core starts or the same anchor is asked for: %w", res.SN, r.OwnerAID, err)
	}
	return &ownerLogEvent{OwnerAID: r.OwnerAID, SN: res.SN, SAID: res.SAID, Raw: raw,
		Signatures: res.Signatures, Written: true}, nil
}

// signWithPermit has the engine's signer sign a reservation's bytes with the
// one permit for them, and takes the permit back however the signer returns.
func (s *CoreServer) signWithPermit(r store.OwnerLogReservation, raw []byte) (string, error) {
	s.ownerLog.permits.Store(r.OwnerAID, ownerLogPermit{sn: r.SN, digest: r.Digest})
	defer s.ownerLog.permits.Delete(r.OwnerAID)
	return s.signEventFor(r.OwnerAID, "", raw)
}

// signReservedOwnerLogEvent signs raw as owner only where all of these hold:
// the writer has just allowed this one signing (a permit naming the place
// and the digest, which this consumes), raw is exactly the bytes reserved at
// that place, those bytes are the interaction the reservation describes and
// anchor the Identity Agent the owner identity is recorded as anchoring, which
// it must record
// (store.OwnerLogReservation.Anchors), and they still follow the kept log
// (reservedEventFollowsTheKeptLog). It is the one place an owner identity's
// key signs an event, reached through the engine's signer (signEventFor).
// Anything else that reaches the engine's signer for an owner identity, a
// route that has the engine build an event by name included, is refused
// whatever the bytes, so the witness check the writer makes cannot be passed
// by.
func (s *CoreServer) signReservedOwnerLogEvent(owner string, raw []byte) (string, error) {
	id, minted, err := s.DataStore.MachineOwnerIdentity(owner)
	if err != nil {
		return "", err
	}
	if !minted {
		return "", store.ErrNotAnOwnerIdentity
	}
	if id.GivenUpFor != "" {
		return "", store.ErrOwnerIdentityGivenUp
	}
	if id.DuplicitousAt != nil {
		return "", store.ErrOwnerIdentityDuplicitous
	}
	held, ok := s.ownerLog.permits.LoadAndDelete(owner)
	if !ok {
		return "", errOwnerLogSigningNotPermitted
	}
	permit := held.(ownerLogPermit)
	reserved, err := s.DataStore.OwnerLogReservations(owner)
	if err != nil {
		return "", err
	}
	rawB64 := base64.StdEncoding.EncodeToString(raw)
	for _, r := range reserved {
		if r.RawB64 != rawB64 {
			continue
		}
		if r.SN != permit.sn || r.Digest != permit.digest {
			return "", fmt.Errorf("%w: it allowed sequence number %d, and these bytes are reserved at %d",
				errOwnerLogSigningNotPermitted, permit.sn, r.SN)
		}
		// The row may have come from a backup rather than from the writer, so
		// what it holds is read before the key is released: the interaction
		// it says it is, anchoring the one Identity Agent this owner identity
		// is recorded as anchoring.
		anchored, err := r.Anchors()
		if err != nil {
			return "", fmt.Errorf("%w: %v", errOwnerLogCannotBeExtended, err)
		}
		// A place is reserved only together with recording the Identity
		// Agent anchored (ReserveOwnerLogPlace), so a record that names none
		// beside a reservation is not one this code wrote.
		if id.AnchoredM == "" || anchored != id.AnchoredM {
			return "", fmt.Errorf("%w: the event reserved at sequence number %d of %s anchors %s, "+
				"and the owner identity is recorded as anchoring %q", errOwnerLogCannotBeExtended,
				r.SN, owner, anchored, id.AnchoredM)
		}
		if err := s.reservedEventFollowsTheKeptLog(r); err != nil {
			return "", err
		}
		seed, err := s.pairwiseSigningSeed(id.KeyIndex)
		if err != nil {
			return "", err
		}
		return signEventBytes(raw, seed)
	}
	return "", fmt.Errorf("these bytes are not reserved in the key log of %s, so its key does not sign them", owner)
}

// reservedEventFollowsTheKeptLog says whether a reservation's bytes may be
// signed now: the kept log holds nothing at its place, or exactly these bytes,
// and the event kept just before it is the one the reservation follows.
//
// A database restored from elsewhere can hold a reservation that no longer
// follows the kept log. Its bytes are not signed, and the reservation stays,
// so nothing more is reserved or signed in that log until it is settled.
// Where the kept log holds a different event at the reserved place, and the
// kept log up to and including it verifies as this owner identity's log,
// signed under its key state at each event (keri.ValidateSignedKEL, the rule
// the engine appends by), two validly signed events are known at one place
// (ADR-087 decision 10), and the owner identity is recorded as duplicitous
// there. A kept row that does not verify proves nothing, so it marks nothing.
func (s *CoreServer) reservedEventFollowsTheKeptLog(r store.OwnerLogReservation) error {
	events, err := s.DataStore.GetEvents(r.OwnerAID)
	if err != nil {
		return err
	}
	var before, at *store.EventRecord
	for i := range events {
		switch events[i].SequenceNumber {
		case r.SN - 1:
			before = &events[i]
		case r.SN:
			at = &events[i]
		}
	}
	if at != nil && at.RawBytesB64 != r.RawB64 {
		if err := keptLogVerifiesTo(r.OwnerAID, events, r.SN); err != nil {
			return fmt.Errorf("%w: sequence number %d of %s holds a kept event other than the one reserved "+
				"there, and the kept log does not verify to it: %v", errOwnerLogCannotBeExtended, r.SN, r.OwnerAID, err)
		}
		if err := s.DataStore.MarkMachineOwnerIdentityDuplicitous(r.OwnerAID, r.SN); err != nil {
			return err
		}
		return fmt.Errorf("%w: sequence number %d of %s holds a kept event other than the one reserved there",
			store.ErrOwnerIdentityDuplicitous, r.SN, r.OwnerAID)
	}
	if before == nil {
		return fmt.Errorf("%w: the event reserved at sequence number %d of %s follows sequence number %d, "+
			"which the kept log does not reach", errOwnerLogCannotBeExtended, r.SN, r.OwnerAID, r.SN-1)
	}
	if kept, _ := drivers.EventIDOfRawB64(before.RawBytesB64); kept == "" || kept != r.PriorDigest {
		return fmt.Errorf("%w: the event reserved at sequence number %d of %s follows %s, "+
			"and the kept log holds %s before it", errOwnerLogCannotBeExtended, r.SN, r.OwnerAID, r.PriorDigest, kept)
	}
	return nil
}

// keptLogVerifiesTo says whether owner's kept events, from its founding up to
// and including sequence number sn, verify as owner's signed key log.
func keptLogVerifiesTo(owner string, events []store.EventRecord, sn int) error {
	var upTo []store.EventRecord
	for _, ev := range events {
		if ev.SequenceNumber <= sn {
			upTo = append(upTo, ev)
		}
	}
	signed, err := store.SignedLogOf(upTo)
	if err != nil {
		return err
	}
	messages, err := drivers.StoredLogMessages(signed)
	if err != nil {
		return err
	}
	_, err = drivers.VerifiedLogOf(owner, messages)
	return err
}

// queueKeptOwnerLogEvents asks the witnesses' queue for every event of
// owner's log after its founding, as the engine holds it in kel: the events
// this writer kept, here or on a device whose database was restored here.
// Each was queued after it was kept, if it was queued at all, so this is what
// sees that none is left unqueued (ADR-087 decision 12). An event already
// queued is not queued twice (ownerLogWitnesses.await).
func (s *CoreServer) queueKeptOwnerLogEvents(owner string, kel *drivers.DriverKelResponse) error {
	for sn := 1; sn < kel.EventCount; sn++ {
		if err := s.ownerLogWitnesses().await(owner, sn); err != nil {
			return fmt.Errorf("the event at sequence number %d of %s is kept and could not be queued for its "+
				"witnesses: %w", sn, owner, err)
		}
	}
	return nil
}

// heldOwnerLog has the engine hold owner's key log as the store keeps it, and
// returns the name it is held under. An owner identity minted since the core
// started is held already, under the name it was minted with. One minted
// before is handed to the engine from the store, as the record identity's log
// is (reloadRecordIdentity), and refused unless the whole log verifies.
func (s *CoreServer) heldOwnerLog(owner string) (ownerLogEngine, string, error) {
	eng, ok := s.KeriDriver.(ownerLogEngine)
	if !ok || s.DataStore == nil {
		return nil, "", fmt.Errorf("%w: this engine cannot extend a log it is handed", errOwnerLogCannotBeExtended)
	}
	events, err := s.DataStore.GetEvents(owner)
	if err != nil {
		return nil, "", err
	}
	if len(events) == 0 {
		return nil, "", fmt.Errorf("%w: no key log is kept for %s", errOwnerLogCannotBeExtended, owner)
	}
	name, held, err := eng.NameHolding(owner)
	if err != nil {
		return nil, "", err
	}
	if !held {
		kel, raws, lastSAID, lastSN := kelFromEvents(events)
		res, err := s.KeriDriver.ReloadIdentity(&drivers.DriverReloadIdentityRequest{
			AID: owner, SequenceNumber: lastSN, LastSAID: lastSAID, KEL: kel, RawEventsB64: raws,
			Signatures: signaturesOf(events), UnsignedAtUpgrade: markedUnsignedOf(events),
		})
		if err != nil {
			return nil, "", fmt.Errorf("%w: %v", errOwnerLogCannotBeExtended, err)
		}
		if res.Status != "reloaded" {
			return nil, "", fmt.Errorf("%w: %s", errOwnerLogCannotBeExtended, res.Status)
		}
		if name, held, err = eng.NameHolding(owner); err != nil || !held {
			return nil, "", fmt.Errorf("%w: the engine does not hold %s (%v)", errOwnerLogCannotBeExtended, owner, err)
		}
	}
	// The store is where an event is kept first, so the engine can be behind
	// it and is brought up by the signed bytes kept. It is never ahead.
	kel, err := s.KeriDriver.GetKel(name)
	if err != nil {
		return nil, "", err
	}
	if kel.EventCount > len(events) {
		return nil, "", fmt.Errorf("%w: the engine holds %d events of %s and %d are kept",
			errOwnerLogCannotBeExtended, kel.EventCount, owner, len(events))
	}
	for _, ev := range events[kel.EventCount:] {
		raw, err := drivers.DecodeRawBytes(ev.RawBytesB64)
		if err != nil {
			return nil, "", err
		}
		if _, err := eng.Commit(name, raw, ev.ControllerSignatures(), nil); err != nil {
			return nil, "", fmt.Errorf("%w: the kept event at sequence number %d: %v",
				errOwnerLogCannotBeExtended, ev.SequenceNumber, err)
		}
	}
	return eng, name, nil
}

// reloadOwnerLogs hands the engine the key log of every owner identity this
// device minted, at start, so each can be extended and its key found,
// finishes whatever was reserved and not kept when the core last stopped,
// brings the copy of each log that is served up to the kept one, which a
// restore can have replaced (servedOwnerLogFollowsTheKeptOne), and queues
// again for the witnesses every event kept after a founding
// (queueKeptOwnerLogEvents). What it cannot do it logs, and the core starts.
func (s *CoreServer) reloadOwnerLogs() {
	if s.KeriDriver == nil || s.DataStore == nil {
		return
	}
	owners, err := s.DataStore.MachineOwnerIdentities()
	if err != nil {
		log.Printf("[owner-log] the owner identities could not be listed, so none of their logs is loaded: %v", err)
		return
	}
	for _, id := range owners {
		lock, _ := s.ownerLog.writers.LoadOrStore(id.AID, &sync.Mutex{})
		lock.(*sync.Mutex).Lock()
		eng, name, err := s.heldOwnerLog(id.AID)
		if err != nil {
			log.Printf("[owner-log] the key log of %s was not loaded: %v", id.AID, err)
		} else if id.GivenUpFor == "" && id.DuplicitousAt == nil {
			if n, err := s.finishReservedOwnerLogEvents(eng, name, id.AID); err != nil {
				// Not lost: the reservation stays, and the next write to this
				// log finishes it before anything else.
				log.Printf("[owner-log] %v", err)
			} else if n > 0 {
				log.Printf("[owner-log] finished %d event(s) of %s reserved before the core stopped", n, id.AID)
			}
		}
		if err == nil {
			s.servedOwnerLogFollowsTheKeptOne(id.AID)
			if kel, err := s.KeriDriver.GetKel(name); err != nil {
				log.Printf("[owner-log] the key log of %s could not be read to queue it for its witnesses: %v", id.AID, err)
			} else if err := s.queueKeptOwnerLogEvents(id.AID, kel); err != nil {
				// Not lost: it is asked for again at the next start, and when
				// the same anchor is asked for.
				log.Printf("[owner-log] %v", err)
			}
		}
		lock.(*sync.Mutex).Unlock()
	}
}

// anchorsIn reads a held owner log for the anchor asked for. already is the
// event that carries exactly this seal, if one does. other is an Identity
// Agent other than m that an interaction of the log already anchors.
//
// An interaction is an anchor only as the ownership check reads one, from
// its bytes: its data is exactly one event seal (ownership.TheAnchorIn). An
// interaction that reader refuses is not an anchor of anything, here or to a
// verifier, so it is neither already nor other.
func anchorsIn(kel *drivers.DriverKelResponse, m string, seal json.RawMessage) (already *ownerLogEvent, other string) {
	var want struct{ I, S, D string }
	_ = json.Unmarshal(seal, &want)
	for i, ev := range kel.KEL {
		if t, _ := ev["t"].(string); t != "ixn" || i >= len(kel.RawEventsB64) {
			continue
		}
		raw, err := drivers.DecodeRawBytes(kel.RawEventsB64[i])
		if err != nil {
			continue
		}
		anchor, err := ownership.TheAnchorIn(raw)
		if err != nil {
			continue
		}
		if anchor.Identifier != m {
			return nil, anchor.Identifier
		}
		if already != nil || fmt.Sprintf("%x", anchor.SN) != want.S || anchor.SAID != want.D {
			continue
		}
		said, _ := ev["d"].(string)
		already = &ownerLogEvent{OwnerAID: kel.AID, SN: i, SAID: said, Raw: raw}
		if i < len(kel.Signatures) {
			already.Signatures = kel.Signatures[i]
		}
	}
	return already, ""
}

// servedOwnerLogFollowsTheKeptOne brings the copy of an owner identity's log
// that is served to whoever resolves it up to the kept log.
//
// That copy was taken once, when the identity was minted (rememberMinted-
// Pairwise), and kept in a file beside the database. The kept log has grown
// since, or been replaced by a restore. The kept log is the one this device
// extends and proves itself with. The served copy is a second one, and is
// refreshed here, after an event is kept and when the core starts, so the two
// never say different things. A copy that already holds the kept events is
// left as it is.
//
// At start the file has not yet been read into memory (restoreMintedPairwise
// runs after the key logs are loaded), so the key is looked for there too,
// and the file is written: what is read from it later is then the kept log.
func (s *CoreServer) servedOwnerLogFollowsTheKeptOne(owner string) {
	events, err := s.DataStore.GetEvents(owner)
	if err != nil || len(events) == 0 {
		return
	}
	kel, _, _, _ := kelFromEvents(events)
	key, known := s.getPairwiseKey(owner)
	served, _ := s.getPairwiseKEL(owner)
	if !known && s.DataDir != "" {
		s.pairwiseFileMu.Lock()
		all, _ := s.readMintedPairwise()
		s.pairwiseFileMu.Unlock()
		if m, ok := all[owner]; ok {
			key, known, served = m.PublicKey, true, m.KEL
		}
	}
	if sameEvents(served, kel) {
		return
	}
	if known {
		s.rememberMintedPairwise(owner, key, kel)
		return
	}
	s.registerPairwiseKEL(owner, kel)
}

// sameEvents says whether two copies of a key log hold the same events, by
// their digests.
func sameEvents(a, b []map[string]interface{}) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		da, _ := a[i]["d"].(string)
		db, _ := b[i]["d"].(string)
		if da == "" || da != db {
			return false
		}
	}
	return true
}

// isASelfAddressingIdentifier says whether v has the shape of a digest KERI
// uses for an identifier or an event.
func isASelfAddressingIdentifier(v string) bool {
	return len(v) == 44 && strings.HasPrefix(v, "E")
}
