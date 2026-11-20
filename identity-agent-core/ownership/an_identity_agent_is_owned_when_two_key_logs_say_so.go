// Package ownership decides, from two key logs handed to it, whether an owner
// identity owns an Identity Agent (ADR-087).
//
// An Identity Agent M names its owner X in an establishment event of its own
// log (the owner seal, ADR-032). That says who is named. It does not say X
// agreed, and anybody can found a look-alike naming somebody else's owner
// identity. X agrees by sealing that exact event in an interaction event of
// its own log. Owned is proved from the two logs together, never one.
//
// The package is arithmetic over signed bytes already in hand. It fetches
// nothing, keeps nothing and trusts nothing it is told: the caller passes each
// log, the receipts held for it, where the copy came from, and any other copy
// of it the caller holds. Log verification, the reading of owner seals, the
// writing of an event seal, the judgement of two events at one place and the
// counting of witness receipts are the ones the rest of the core uses (keri-go
// and package drivers); none is written again here. What is read here, and
// only here, is an interaction event's `a` list element by element
// (elementsOf): keri-go's reader gives up on a whole event when one element
// is not a seal, and this check must not pass over what it cannot read.
//
// The words another implementation must match are in
// contracts/owned/owned.md, with worked examples in owned-vectors.json.
package ownership

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// Grade is what the check found.
type Grade string

const (
	// OwnedConfirmed is steps 1 to 8 passing on logs the verifier took from
	// the witnesses each log names.
	OwnedConfirmed Grade = "owned_confirmed"
	// OwnedAnchored is steps 1 to 7 passing. It shows what was true of the
	// copies given, which may be old.
	OwnedAnchored Grade = "owned_anchored"
	// NamedNotOwned is an Identity Agent whose log names the owner, with no
	// agreement of the owner's that counts.
	NamedNotOwned Grade = "named_not_owned"
	// Refused is a check that could not say "owned" or "named": a log did not
	// verify or could not be checked, the owner is not named at all, or a log
	// is proven duplicitous.
	Refused Grade = "refused"
)

// Reason is the one fixed code that says why a grade was given. The codes are
// read by other implementations and shown to people by their meaning: add to
// them, never rename one.
type Reason string

const (
	// ReasonNone goes with OwnedConfirmed.
	ReasonNone Reason = ""

	// With OwnedAnchored: why it is not confirmed.

	// NotFromWitnesses is a copy of either log that came from the party being
	// checked and not from the log's own witnesses.
	NotFromWitnesses Reason = "not_from_witnesses"
	// ReceiptsShort is the anchoring event, or the sealed event, without valid
	// receipts to the threshold its log names; a log that names no witnesses,
	// or a threshold of none, is never confirmed.
	ReceiptsShort Reason = "receipts_short"

	// With NamedNotOwned.

	// Delegated is an Identity Agent whose log begins with a delegated
	// inception or names a delegator anywhere. It is never owned.
	Delegated Reason = "delegated"
	// NamedNotAnchored is no interaction event of the owner's log sealing the
	// event in which the owner entered the owner set.
	NamedNotAnchored Reason = "named_not_anchored"
	// AnchorRemoved is an anchor a recovery rotation of the owner identity
	// replaced, with no anchor made since.
	AnchorRemoved Reason = "anchor_removed"
	// SecondMachine is an owner log whose first anchor names a different
	// Identity Agent: one owner identity owns one.
	SecondMachine Reason = "second_machine"

	// With Refused.

	// LogInvalid is a log that does not verify as KERI requires, or whose
	// identifier is not the digest of its own inception.
	LogInvalid Reason = "log_invalid"
	// SameIdentifier is one identifier given as both the Identity Agent and
	// its owner. Owned is proved from two logs, never one.
	SameIdentifier Reason = "same_identifier"
	// NotNamed is an owner the Identity Agent's log does not name in the owner
	// set in force at its latest establishment event.
	NotNamed Reason = "not_named"
	// StaleCopy is a copy of a log that does not carry on from another copy
	// the verifier holds: it lacks events that copy has, or a recovery
	// rotation in that copy replaces some of its events.
	StaleCopy Reason = "stale_copy"
	// LogUnchecked is a log that could not be checked: an owner's interaction
	// at or before the anchor carries something that cannot be read as a seal,
	// or seals an event of an identifier whose log was not supplied or does
	// not reach that event; a log is longer than is judged; or another copy
	// the verifier holds cannot be judged.
	LogUnchecked Reason = "log_unchecked"
	// Duplicity is either log proven to hold two validly signed events at one
	// place, neither a recovery of the other. No Identity Agent is owned by
	// such an owner.
	Duplicity Reason = "duplicity"
)

// Source is where the verifier took a copy of a log from.
type Source int

const (
	// FromTheCheckedParty is a copy handed over by the party being checked:
	// the machine, or whoever presents the pair. Only the holder of a log's
	// key can sign its events, so such a copy cannot invent an anchor; it can
	// hide a later event that removed one. It proves anchored and no more.
	// It is the zero value, so a caller that says nothing claims nothing.
	FromTheCheckedParty Source = iota
	// FromItsWitnesses is the log's latest state as its own witnesses hold
	// it, asked for by the verifier.
	FromItsWitnesses
)

// Log is one identity's key log as the verifier holds it.
type Log struct {
	// Messages are the log's events in order, each with its controller
	// signatures attached, as keri.ValidateSignedKEL takes them.
	Messages [][]byte
	// Receipts are the witness receipts held for these events, by the event's
	// SAID, as drivers.ValidateKELInput carries them.
	Receipts map[string][]drivers.WitnessReceipt
	// Source is where Messages came from.
	Source Source
	// Kept are other copies of this log the verifier holds: one it kept
	// earlier, or one a watcher showed it. Messages must carry on from each,
	// and an event of one that differs from Messages at its place is judged
	// as ADR-075 judges any two events at one place.
	Kept [][][]byte
}

// Options are what else the caller holds.
type Options struct {
	// OtherLogs are the logs of other identifiers the owner's interactions
	// seal events of. An owner log that seals an event of an identifier whose
	// log is not here, before the anchor being judged, cannot be checked.
	OtherLogs []Log
}

// Result is the outcome of Check.
type Result struct {
	Grade  Grade  `json:"grade"`
	Reason Reason `json:"reason"`
	// Machine and Owner are the identifiers the two logs derive.
	Machine string `json:"machine,omitempty"`
	Owner   string `json:"owner,omitempty"`
	// Event is the SAID of the establishment event in which the owner entered
	// the Identity Agent's owner set, and EventSN its sequence number. They
	// are set once that event is known, whatever the grade, and absent before.
	Event   string  `json:"event,omitempty"`
	EventSN *uint64 `json:"event_sn,omitempty"`
	// AnchoredBy is the SAID of the owner's interaction event that seals
	// Event, set for the two owned grades.
	AnchoredBy string `json:"anchored_by,omitempty"`
	// Needs is the identifier whose log the verifier must supply, or supply a
	// longer copy of, before the answer can be given. Set with LogUnchecked
	// when that is why.
	Needs string `json:"needs,omitempty"`
	// Detail is words for a log or a person debugging. Nothing branches on it.
	Detail string `json:"-"`
}

// Owned is whether the grade is one of the two that mean owned.
func (r Result) Owned() bool { return r.Grade == OwnedConfirmed || r.Grade == OwnedAnchored }

// Check decides whether the Identity Agent whose log is machine is owned by
// the identity whose log is owner. It does the eight steps of ADR-087
// decision 3 and reports the first that fails, in the order 1, 2, 3, 4, 7, 5,
// 6, 8: proof of duplicity is reported ahead of a missing anchor.
func Check(machine, owner Log, opt Options) Result {
	r := Result{Grade: Refused}
	end := func(g Grade, why Reason, detail string, args ...any) Result {
		r.Grade, r.Reason, r.Detail = g, why, fmt.Sprintf(detail, args...)
		return r
	}

	// Step 1. The Identity Agent's log verifies in full, and carries on from
	// every other copy of it the verifier holds.
	m, why, err := read(machine)
	if err != nil {
		return end(Refused, why, "the Identity Agent's log: %v", err)
	}
	r.Machine = m.id

	// Who the owner is claimed to be is read from the owner log's first event.
	// Nothing rests on it until step 4 has verified that log.
	r.Owner = identifierOf(owner.Messages)
	if r.Owner == "" {
		return end(Refused, LogInvalid, "the owner's log does not begin with a readable event")
	}
	// Owned is proved from two logs, never one.
	if r.Owner == r.Machine {
		return end(Refused, SameIdentifier, "the Identity Agent and the owner are one identifier")
	}

	sets, err := drivers.OwnerSetsByEvent(m.fields)
	if err != nil {
		return end(Refused, LogInvalid, "the Identity Agent's log: %v", err)
	}
	var establishment []int
	for i, ev := range m.events {
		if ev.Establishment() {
			establishment = append(establishment, i)
		}
	}
	latest := establishment[len(establishment)-1]
	named := contains(sets[latest], r.Owner)

	// ...and passes the test of decision 2, on the whole log and not on one
	// event: its inception is an icp and no event names a delegator. (A
	// delegated rotation in a log that began with an icp never gets here: the
	// log does not verify.)
	for _, ev := range m.events {
		if delegated(ev) {
			g := Refused
			if named {
				g = NamedNotOwned
			}
			return end(g, Delegated, "the Identity Agent's log holds a %s event at %d: a delegated identity is never owned", ev.Ilk, ev.SN)
		}
	}

	// Step 2. E is the establishment event in which the owner entered the
	// owner set, and the owner is in the set in force at every establishment
	// event from E to the latest. An owner that left and came back entered at
	// the event where it came back.
	if !named {
		return end(Refused, NotNamed, "the owner set in force at the Identity Agent's latest establishment event does not name this owner")
	}
	e := latest
	for k := len(establishment) - 1; k >= 0 && contains(sets[establishment[k]], r.Owner); k-- {
		e = establishment[k]
	}
	sealed := m.events[e]
	r.Event, r.EventSN = sealed.SAID, &sealed.SN

	// Step 3. E is an event of the log just verified: it was read from it.
	// A second establishment event of the Identity Agent at E's place, in any
	// other copy the verifier holds, is duplicity, which read found and step
	// 7 reports; no recovery replaces an establishment event.

	// Step 4. The owner's log verifies in full, the same way.
	x, why, err := read(owner)
	if err != nil {
		return end(Refused, why, "the owner's log: %v", err)
	}

	// Step 7. Neither log is proven duplicitous at any place. Both logs have
	// now been read against every other copy the verifier holds, so this is
	// settled here, ahead of steps 5 and 6. All of the steps must pass either
	// way; the order decides only which reason is given when more than one
	// fails, and proof of duplicity is the one that must not be hidden behind
	// "not anchored": the way out of that is to anchor again, in the very log
	// that is proven to have two histories.
	if m.forked {
		return end(Refused, Duplicity, "the Identity Agent's log holds two validly signed events at one place")
	}
	if x.forked {
		return end(Refused, Duplicity, "the owner's log holds two validly signed events at one place")
	}

	// Step 5. An interaction event that still stands in the owner's log seals
	// E exactly: identifier, sequence number and digest all equal. The owner's
	// interactions are read in order, element by element, until that seal is
	// found. An element met on the way that cannot be read as a seal, or
	// cannot be shown not to be an event seal, stops the check: it may be an
	// earlier anchor, and step 6 cannot be answered past it.
	type placed struct {
		seal  keri.Seal
		event int
	}
	var before []placed
	anchor := -1
find:
	for i, ev := range x.events {
		if ev.Ilk != "ixn" {
			continue
		}
		for _, el := range elementsOf(x.fields[i]) {
			switch {
			case el.unreadable:
				return end(Refused, LogUnchecked, "the owner's interaction at %d carries something that cannot be read as a seal, before any seal of the event was found", ev.SN)
			case !el.eventSeal:
				continue
			case sealsExactly(el.seal, sealed):
				anchor = i
				break find
			}
			before = append(before, placed{el.seal, i})
		}
	}
	if anchor < 0 {
		// A recovery rotation of the owner identity that removed the anchoring
		// interaction removed the anchor. The verifier can tell that from a
		// plain absence only when a copy it holds still has the interaction.
		for _, gone := range x.retired {
			for _, el := range gone.elements {
				if el.eventSeal && sealsExactly(el.seal, sealed) {
					return end(NamedNotOwned, AnchorRemoved, "a recovery rotation of the owner identity replaced the interaction at %d that sealed the event, and nothing has anchored it since", gone.sn)
				}
			}
		}
		return end(NamedNotOwned, NamedNotAnchored, "no interaction event of the owner's log seals event %d of the Identity Agent (%s)", sealed.SN, sealed.SAID)
	}

	// Step 6. That anchor is the first anchor in the owner's log, or names the
	// same Identity Agent as the first. An anchor, for this count, is an event
	// seal in an interaction event of the owner whose sealed event is an
	// establishment event that carries an owner seal naming the owner. So
	// every event seal before the anchor is looked up in the log it names.
	others := map[string]*readLog{}
	for i := range opt.OtherLogs {
		id := identifierOf(opt.OtherLogs[i].Messages)
		if id == "" || id == m.id || id == x.id {
			continue // the two logs being checked are the copies in hand
		}
		if o, _, err := read(opt.OtherLogs[i]); err == nil && !o.forked {
			others[id] = o
		}
	}
first:
	for _, b := range before {
		s, at := b.seal, x.events[b.event].SN
		of, own := m, true
		switch s.Identifier {
		case m.id:
		case x.id:
			of = x // a seal of the owner's own event is looked up in its own log
		default:
			own = false
			if of = others[s.Identifier]; of == nil {
				r.Needs = s.Identifier
				return end(Refused, LogUnchecked, "the owner's interaction at %d seals an event of %s, whose log was not supplied or does not verify, so which Identity Agent the owner anchored first is not known", at, s.Identifier)
			}
		}
		is, known, err := of.anchors(s, x.id)
		switch {
		case err != nil:
			return end(Refused, LogUnchecked, "the owner's interaction at %d seals event %d of %s, whose owner seals cannot be read: %v", at, s.SN, s.Identifier, err)
		case !known && !own:
			r.Needs = s.Identifier
			return end(Refused, LogUnchecked, "the owner's interaction at %d seals event %d of %s, which the copy of that log supplied does not hold", at, s.SN, s.Identifier)
		case is && of == m:
			break first // the first anchor names this Identity Agent
		case is:
			return end(NamedNotOwned, SecondMachine, "the owner's log first anchors %s, at %d: one owner identity owns one Identity Agent", s.Identifier, at)
		}
	}

	// Steps 1 to 7 passing is anchored.
	r.AnchoredBy = x.events[anchor].SAID

	// Step 8. The anchoring event and E each carry valid witness receipts to
	// the threshold their own log names. That, on logs taken from the
	// witnesses each log names, is confirmed, and never without both.
	if machine.Source != FromItsWitnesses || owner.Source != FromItsWitnesses {
		return end(OwnedAnchored, NotFromWitnesses, "a copy of a log came from the party being checked, which can hide a later event")
	}
	if !m.witnessed(machine, sealed.SAID) || !x.witnessed(owner, r.AnchoredBy) {
		return end(OwnedAnchored, ReceiptsShort, "the anchoring event or the sealed event is not receipted to the threshold its log names")
	}
	return end(OwnedConfirmed, ReasonNone, "")
}

// element is one entry of an interaction event's `a` list, as this check
// reads it.
//
// An event seal is an object with exactly the fields i, s and d, in any
// order: i and d non-empty strings, s a sequence number in lowercase hex
// with no leading zero. The owner seal is read with the same exactness
// (drivers.OwnerFromSeal), so the two readers agree on what an event seal
// is. An object that lacks one of the three fields is some other seal, and
// is shown not to be an event seal. Everything else is unreadable: something
// that is not an object, an object with the three fields and more, or one
// whose i, s or d is not as an event seal writes it. An unreadable element
// is never skipped, because skipping it is how an earlier anchor would hide.
type element struct {
	seal       keri.Seal
	eventSeal  bool
	unreadable bool
}

// elementsOf reads the `a` list of an event, element by element. An `a` that
// is present and is not a list is one unreadable element.
func elementsOf(fields map[string]interface{}) []element {
	a, present := fields["a"]
	if !present || a == nil {
		return nil
	}
	list, ok := a.([]interface{})
	if !ok {
		return []element{{unreadable: true}}
	}
	out := make([]element, 0, len(list))
	for _, entry := range list {
		object, ok := entry.(map[string]interface{})
		if !ok {
			out = append(out, element{unreadable: true})
			continue
		}
		iRaw, hasI := object["i"]
		sRaw, hasS := object["s"]
		dRaw, hasD := object["d"]
		if !hasI || !hasS || !hasD {
			out = append(out, element{}) // another kind of seal
			continue
		}
		i, _ := iRaw.(string)
		s, _ := sRaw.(string)
		d, _ := dRaw.(string)
		sn, err := strconv.ParseUint(s, 16, 64)
		if len(object) != 3 || i == "" || d == "" || err != nil || strconv.FormatUint(sn, 16) != s {
			out = append(out, element{unreadable: true})
			continue
		}
		out = append(out, element{seal: keri.Seal{Identifier: i, SN: sn, SAID: d}, eventSeal: true})
	}
	return out
}

// readLog is a log that verified, with what judging it against the verifier's
// other copies of it found.
type readLog struct {
	id     string
	raws   [][]byte
	events []*keri.Event
	fields []map[string]interface{}
	// forked is proof of duplicity: another copy holds a validly signed event
	// at a place this log holds a different one, and neither is a recovery of
	// the other.
	forked bool
	// retired are the events of other copies that a recovery rotation of
	// this log replaced.
	retired []retiredEvent
}

// retiredEvent is an event of another copy that a recovery rotation replaced.
type retiredEvent struct {
	sn       uint64
	elements []element
}

// read verifies a log in full with the one log verifier, and judges it
// against every other copy the verifier holds. An error comes with the reason
// code it is refused for.
func read(l Log) (*readLog, Reason, error) {
	if len(l.Messages) == 0 {
		return nil, LogInvalid, errors.New("it has no events")
	}
	if err := drivers.CheckSentLogLength(len(l.Messages)); err != nil {
		return nil, LogUnchecked, err
	}
	// The identifier is the digest of the inception, each event follows the
	// one before, each is signed to the threshold of the key state in force,
	// and each rotation reveals the keys the previous establishment event
	// committed to: keri-go's verifier, which every log in the core goes to.
	verified, err := keri.ValidateSignedKEL(l.Messages)
	if err != nil {
		return nil, LogInvalid, err
	}
	out := &readLog{id: verified.Identifier}
	for i, message := range l.Messages {
		ev, fields, err := eventOf(message)
		if err != nil {
			return nil, LogInvalid, fmt.Errorf("event %d: %w", i, err)
		}
		out.raws, out.events, out.fields = append(out.raws, ev.Raw), append(out.events, ev), append(out.fields, fields)
	}
	// keri-go also verifies an identifier that is a key (basic derivation).
	// Such an identifier is not the digest of its inception, so no event seal
	// can name its inception by its identifier, and it is neither an owner nor
	// owned here.
	if out.events[0].Identifier != out.events[0].SAID {
		return nil, LogInvalid, fmt.Errorf("the identifier %s is not the digest of its inception", out.id)
	}

	for n, kept := range l.Kept {
		if len(kept) == 0 {
			continue
		}
		if err := drivers.CheckSentLogLength(len(kept)); err != nil {
			return nil, LogUnchecked, fmt.Errorf("kept copy %d: %w", n, err)
		}
		theirs, err := keri.ValidateSignedKEL(kept)
		if err != nil {
			return nil, LogUnchecked, fmt.Errorf("kept copy %d does not verify, so the log cannot be judged against it: %w", n, err)
		}
		if theirs.Identifier != out.id {
			return nil, LogUnchecked, fmt.Errorf("kept copy %d is the log of another identifier", n)
		}
		if why, err := out.judgeAgainst(verified, l.Messages, theirs, kept); err != nil {
			return nil, why, fmt.Errorf("kept copy %d: %w", n, err)
		}
	}
	return out, ReasonNone, nil
}

// eventOf is the event of a signed message, parsed, and its fields.
func eventOf(message []byte) (*keri.Event, map[string]interface{}, error) {
	raw, err := keri.EventOfMessage(message)
	if err != nil {
		return nil, nil, err
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, nil, err
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, nil, err
	}
	return ev, fields, nil
}

// judgeAgainst judges this log against another verified copy of it, event by
// event, the way ADR-075 judges a log a watcher shows: each event the log
// does not hold is put to keri-go's Admit, and one at a place already held
// goes to the judgement of two events at one place with both copies in hand
// (drivers.JudgeCopiesAtTakenPlace).
func (l *readLog) judgeAgainst(mine *keri.SignedKELResult, messages [][]byte, theirs *keri.SignedKELResult, kept [][]byte) (Reason, error) {
	for k, message := range kept {
		ev, _, err := eventOf(message)
		if err != nil {
			return LogUnchecked, err
		}
		if held := mine.StateAt(ev.SN); held != nil && held.Digest() == ev.SAID {
			continue // the same event
		}
		adm, err := mine.Admit(message)
		var refusal *keri.ValidationError
		switch {
		case err == nil && adm.Repeat:
			continue
		case err == nil:
			// The other copy goes on where this one stops, or holds a recovery
			// rotation that replaces events of this one. Either way this copy
			// is not the log's latest state and can hide what came after.
			return StaleCopy, fmt.Errorf("it holds event %d, which this copy of the log does not carry on from", ev.SN)
		case !errors.As(err, &refusal) || !refusal.Has(keri.FaultPlaceTaken):
			return LogUnchecked, fmt.Errorf("its event %d cannot be judged against this copy of the log: %w", ev.SN, err)
		}
		switch found, err := drivers.JudgeCopiesAtTakenPlace(mine, messages, theirs, kept, ev, message); found {
		case drivers.TakenFork:
			l.forked = true
			return ReasonNone, nil
		case drivers.TakenRetired:
			// This log's recovery rotation replaced the other copy's events
			// from this place on.
			for _, later := range kept[k:] {
				if gone, fields, err := eventOf(later); err == nil {
					l.retired = append(l.retired, retiredEvent{sn: gone.SN, elements: elementsOf(fields)})
				}
			}
			return ReasonNone, nil
		default:
			return LogUnchecked, fmt.Errorf("its event %d at a place already held cannot be judged: %v", ev.SN, err)
		}
	}
	return ReasonNone, nil
}

// anchors is whether seal, written in an interaction event of owner, is an
// anchor of this log: it names an establishment event of it that carries an
// owner seal naming owner. known is false when this copy of the log does not
// hold the event the seal names, so the question cannot be answered from it.
// An error is a sealed event whose owner seals cannot be read: it may name
// the owner, so it is not taken as "not an anchor".
func (l *readLog) anchors(seal keri.Seal, owner string) (is, known bool, err error) {
	if seal.SN >= uint64(len(l.events)) || l.events[seal.SN].SAID != seal.SAID {
		return false, false, nil
	}
	if !l.events[seal.SN].Establishment() {
		return false, true, nil
	}
	owners, _, err := drivers.OwnerSetFromEvent(l.fields[seal.SN])
	if err != nil {
		return false, true, err
	}
	return contains(owners, owner), true, nil
}

// witnessed is whether the event carries valid receipts from the witnesses
// its log designates for it, to the threshold the log names, by the one
// receipt count (drivers.WitnessingByEvent, ADR-070). A log that names no
// witnesses, or a threshold of none, confirms nothing.
func (l *readLog) witnessed(from Log, said string) bool {
	row, ok := drivers.WitnessingByEvent(drivers.ValidateKELInput{
		AID: l.id, RawEvents: l.raws, Receipts: from.Receipts,
	})[said]
	return ok && row.Known && row.Met && len(row.Designated) > 0 && row.Threshold > 0
}

// sealsExactly is whether a seal names event exactly: identifier, sequence
// number and digest all equal.
func sealsExactly(s keri.Seal, event *keri.Event) bool {
	return s.Identifier == event.Identifier && s.SN == event.SN && s.SAID == event.SAID
}

// identifierOf is the identifier the first event of a log states, the `i` of
// its JSON as written, or "" when there is none to read. It says only which
// identifier a log claims: read verifies the claim.
func identifierOf(messages [][]byte) string {
	if len(messages) == 0 {
		return ""
	}
	raw, err := keri.EventOfMessage(messages[0])
	if err != nil {
		return ""
	}
	var stated struct {
		I string `json:"i"`
	}
	if json.Unmarshal(raw, &stated) != nil {
		return ""
	}
	return stated.I
}

func contains(set []string, id string) bool {
	for _, s := range set {
		if s == id {
			return true
		}
	}
	return false
}
