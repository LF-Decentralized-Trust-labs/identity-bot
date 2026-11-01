package drivers

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
)

// Validating a key log from the bytes it was actually published as.
//
// There is one implementation of this and both engines use it, because
// validation is arithmetic over bytes that are already in hand. It reaches out
// to nothing, holds no state, and there is no version of it that could be right
// for one engine and wrong for the other — so a second implementation could
// only ever be a second thing to get wrong, on the check that decides whether a
// stranger's identity is who they claim.
//
// It takes canonical bytes rather than parsed events, and that is the whole
// point. Two of the checks below are impossible without them:
//
//   - An identifier is a digest over an exact byte sequence in an exact field
//     order. Re-encoding a parsed event in Go sorts its keys, producing a
//     different digest — so "does this log actually belong to this identity"
//     cannot be answered from parsed events at all.
//   - A signature is over those same bytes.
//
// Without the first check, everything else is satisfied by a wholly forged log:
// the forger supplies the keys, the signatures and the chain, and they agree
// with each other perfectly. What makes a log somebody's is that its inception
// derives their identifier.

// ValidateKELInput is a key log to check, as published.
type ValidateKELInput struct {
	// AID is who the log is claimed to belong to.
	AID string
	// RawEvents are the canonical bytes of each event, in order.
	RawEvents [][]byte
	// CesrSignatures are the controller signatures, parallel to RawEvents.
	//
	// Optional and may be sparse: an empty entry means no signature was
	// supplied for that event, which is reported rather than treated as a
	// failure. A log fetched from a stranger often arrives without them.
	CesrSignatures []string
	// Receipts are the witness receipts held for these events, keyed by the
	// event's identifier.
	//
	// Optional. Their absence means the log is unwitnessed as far as this
	// caller can see, which is reported separately from whether the log itself
	// is sound — the two answer different questions and a log can be perfectly
	// valid and uncorroborated.
	Receipts map[string][]WitnessReceipt
}

// WitnessReceipt is one witness's statement that it saw an event.
type WitnessReceipt struct {
	WitnessAID    string
	CesrSignature string
}

// EventWitnessing is how well corroborated one event is.
type EventWitnessing struct {
	SequenceNumber int      `json:"sequence_number"`
	EventSAID      string   `json:"event_said"`
	Designated     []string `json:"designated"`
	Threshold      int      `json:"threshold"`
	// Verified counts receipts from DESIGNATED witnesses whose signature
	// checked out. A receipt from anybody else is not counted, whether or not
	// it verifies: a threshold that could be met by uninvited witnesses is not
	// a threshold, since anyone can generate a key and sign.
	Verified int  `json:"verified"`
	Met      bool `json:"met"`
}

// ValidateKELFromBytes checks a key log and reports what it established.
func ValidateKELFromBytes(in ValidateKELInput) (*DriverValidateKELResponse, error) {
	out := &DriverValidateKELResponse{}
	if len(in.RawEvents) == 0 {
		out.ValidationErrors = []string{
			"an empty key log establishes nothing; this is not a verdict about the identity",
		}
		return out, nil
	}

	// Structure, ordering, the hash chain, and — the check that matters most —
	// that each event's identifier re-derives from its own bytes.
	if err := keri.ValidateKEL(in.RawEvents); err != nil {
		out.EventsValidated = len(in.RawEvents)
		out.ValidationErrors = []string{fmt.Sprintf("the log does not hold together: %v", err)}
		return out, nil
	}

	// Bind the log to the identity BEFORE trusting anything in it.
	//
	// Everything above is satisfied by a forged log, because the forger
	// supplies every part of it. What cannot be forged is that the inception
	// derives the identifier being claimed.
	first, err := keri.ParseEvent(in.RawEvents[0])
	if err != nil {
		return nil, fmt.Errorf("the first event does not parse: %w", err)
	}
	if in.AID != "" && first.Identifier != in.AID {
		out.EventsValidated = len(in.RawEvents)
		out.ValidationErrors = []string{fmt.Sprintf(
			"this log belongs to %s, not %s; a log that is not this identity's has nothing "+
				"to say about its current key", first.Identifier, in.AID)}
		return out, nil
	}

	var problems []string
	unsigned := 0
	current := ""
	// Each event's signature as KERI carries it, for the log verifier below.
	signed := make([][]byte, 0, len(in.RawEvents))
	sigs := make([]ControllerSignature, len(in.RawEvents))

	for i, raw := range in.RawEvents {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d does not parse: %v", i, err))
			continue
		}

		// The result names one current key, and every caller verifies what
		// the identity signs later against that one key. A multi-key
		// identity's log can have its thresholds judged (keri-go does, below),
		// but reporting one member's key as the identity's would let that
		// member sign for all of them afterwards under kt "2". So a multi-key
		// identity is refused here until the result carries the whole key set
		// and its threshold.
		if ev.Establishment() && len(ev.Keys) > 1 {
			problems = append(problems, fmt.Sprintf(
				"event %d declares %d keys; this check reports one current key, so a "+
					"multi-key identity is not taken as verified", i, len(ev.Keys)))
			continue
		}
		if ev.Establishment() && len(ev.Keys) > 0 {
			current = ev.Keys[0]
		}

		sig := ""
		if i < len(in.CesrSignatures) {
			sig = in.CesrSignatures[i]
		}
		if sig == "" {
			unsigned++
			continue
		}
		at, err := ReadControllerSignature(sig)
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d: %v", i, err))
			continue
		}
		sigs[i] = at
		group, err := keri.AttachControllerSigs([]string{at.QB64})
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d: %v", i, err))
			continue
		}
		signed = append(signed, append(append([]byte(nil), raw...), group...))
	}

	switch {
	case len(problems) > 0:
	case unsigned == 0:
		// Every event carries its signature, so the whole log goes to the one
		// KEL verifier: each event signed by the key state in force, meeting
		// its signing threshold, and each rotation authorised by the prior
		// commitments its signing keys open, as keripy judges it.
		if _, err := keri.ValidateSignedKEL(signed); err != nil {
			problems = append(problems, fmt.Sprintf(
				"the log's signatures do not show its controller authorised it: %v", err))
		}
	default:
		// Some events arrived unsigned, so the log is not verified whatever
		// the rest show, and the log verifier, which needs every event signed,
		// cannot judge it. What can still be caught is a signature that is
		// present and is not by the key in force: a log carrying one is not
		// sound, signed or not.
		current := ""
		for i, raw := range in.RawEvents {
			ev, err := keri.ParseEvent(raw)
			if err != nil {
				continue // reported above
			}
			if ev.Establishment() && len(ev.Keys) > 0 {
				current = ev.Keys[0]
			}
			if sigs[i].Raw == nil {
				continue
			}
			if sigs[i].At.Index != 0 || current == "" ||
				keri.VerifySignature(current, raw, sigs[i].Raw) != nil {
				problems = append(problems, fmt.Sprintf(
					"event %d is not signed by the key it declares, so it was not authorised by "+
						"the identity it claims to extend", i))
			}
		}
	}

	// How well corroborated the log is, which is a different question from
	// whether it is sound. A log with one history, correctly signed, is valid;
	// whether anybody else saw it is what decides that a SECOND correctly
	// signed history could be recognised as the forgery. Reported alongside
	// rather than folded in, so a caller cannot mistake one for the other.
	witnessing, allMet := witnessingReport(in)
	out.Witnessed = allMet
	for _, row := range witnessing {
		out.WitnessDetail = append(out.WitnessDetail, DriverWitnessedEvent{
			SequenceNumber:   row.SequenceNumber,
			Witnesses:        len(row.Designated),
			Threshold:        row.Threshold,
			ReceiptsVerified: row.Verified,
			Witnessed:        row.Met,
		})
	}
	// The set in force at the end of the log, which is what a caller deciding
	// whether to rely on this identity needs — not the set at any earlier point.
	if n := len(witnessing); n > 0 {
		out.Witnesses = witnessing[n-1].Designated
		out.WitnessThreshold = witnessing[n-1].Threshold
	}

	out.EventsValidated = len(in.RawEvents)
	out.CurrentPublicKey = current
	out.ValidationErrors = problems
	out.EventsUnsigned = unsigned

	// Two questions, two answers, because conflating them is how an
	// unauthenticated log gets treated as a proven one.
	//
	// The log holding together says the events parse and chain and the
	// inception derives the identifier. Authorship being proven says somebody
	// holding the declared key actually signed. An unsigned event fails the
	// second without touching the first, and every trust gate in this agent
	// reads KelVerified, so an unsigned log answering "verified" would let a
	// stranger establish a key state by handing over a document they wrote.
	//
	// An unsigned log is not an error, which is why it is not recorded as one:
	// a log fetched over an introduction routinely arrives this way, and
	// calling it malformed would be false. It is simply not verified.
	out.LogSound = len(problems) == 0
	out.KelVerified = len(problems) == 0 && unsigned == 0

	if out.LogSound && unsigned > 0 {
		out.ValidationErrors = []string{fmt.Sprintf(
			"the log holds together and its inception derives %s, but %d of %d events carried "+
				"no signature, so nobody has been shown to have authorised them",
			first.Identifier, unsigned, len(in.RawEvents))}
	}
	return out, nil
}

// ControllerSignature is one controller signature as KERI attaches it.
type ControllerSignature struct {
	keri.IndexedSignature
	// QB64 is the indexed form attached to the event.
	QB64 string
}

// ReadControllerSignature reads a controller signature in the forms the agent
// stores and produces, and returns it indexed as a published stream carries it.
//
// An unindexed signature (0B, or 64 raw bytes in base64) is what this agent's
// own signing path produces, for a single-key identity whose one key sits first
// in both key lists, so it is indexed there. An indexed one (A, B, 2A or 2B) is
// read as keri-go reads it, and the places it names are judged by the log
// verifier, not here.
func ReadControllerSignature(sig string) (ControllerSignature, error) {
	if raw, _, _, err := iacrypto.DecodeEd25519Signature(sig, false); err == nil {
		qb64, err := keri.EncodeIndexedSignature(raw, keri.SamePlace(0))
		if err != nil {
			return ControllerSignature{}, err
		}
		return ControllerSignature{IndexedSignature: keri.IndexedSignature{
			Code: "A", At: keri.SamePlace(0), Raw: raw}, QB64: qb64}, nil
	}
	parsed, err := keri.ParseIndexedSignature(sig)
	if err != nil {
		return ControllerSignature{}, fmt.Errorf("the signature is neither an Ed25519 signature "+
			"nor an indexed one: %w", err)
	}
	return ControllerSignature{IndexedSignature: parsed, QB64: sig}, nil
}

// DecodeRawEvents turns the base64 wire form into bytes, reporting which entry
// failed rather than which index of a slice.
func DecodeRawEvents(rawB64 []string) ([][]byte, error) {
	out := make([][]byte, 0, len(rawB64))
	for i, b := range rawB64 {
		if b == "" {
			return nil, fmt.Errorf("event %d has no canonical bytes, so the log cannot be "+
				"verified; it can only be read", i)
		}
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return nil, fmt.Errorf("event %d is not readable base64: %w", i, err)
		}
		out = append(out, raw)
	}
	return out, nil
}

// ValidateKELInputFromRecords builds validation input out of the record shape
// the agent publishes in an OOBI and keeps in its store.
//
// A published key log travels as event records rather than bare events: each
// carries the event, the canonical bytes it was published as, and the
// controller's signature over them. This pulls out the two that can be checked.
//
// ok is false when the canonical bytes are not all there — a log published by
// an older agent, or by somebody else's implementation that does not send them.
// That is not an error and must not be treated as one; it means only the
// structure can be examined, and the caller has to say so rather than reporting
// a verification it did not perform.
// WitnessReceiptsFromWire reads the receipts published alongside a key log.
//
// Shaped as the wire carries them: event identifier to the receipts covering
// that event. Nothing here is trusted — every receipt is checked against the
// witness that claims to have issued it, and against the designated set, when
// the log is validated. This only reads them.
func WitnessReceiptsFromWire(raw map[string][]map[string]interface{}) map[string][]WitnessReceipt {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string][]WitnessReceipt, len(raw))
	for said, list := range raw {
		for _, r := range list {
			aid, _ := r["witness_aid"].(string)
			sig, _ := r["cesr_signature"].(string)
			if aid == "" || sig == "" {
				continue
			}
			out[said] = append(out[said], WitnessReceipt{WitnessAID: aid, CesrSignature: sig})
		}
	}
	return out
}

func ValidateKELInputFromRecords(aid string, records []map[string]interface{}) (ValidateKELInput, bool) {
	in := ValidateKELInput{AID: aid}
	if len(records) == 0 {
		return in, false
	}
	for _, rec := range records {
		rawB64, _ := rec["raw_bytes_b64"].(string)
		if rawB64 == "" {
			return ValidateKELInput{AID: aid}, false
		}
		raw, err := base64.StdEncoding.DecodeString(rawB64)
		if err != nil {
			return ValidateKELInput{AID: aid}, false
		}
		sig, _ := rec["cesr_signature"].(string)
		in.RawEvents = append(in.RawEvents, raw)
		in.CesrSignatures = append(in.CesrSignatures, sig)
	}
	return in, true
}

// VerifyReceipt checks a witness receipt against the witness that issued it.
//
// The witness identifier IS the verifying key, because witness identifiers are
// non-transferable. So this needs nothing fetched and nothing trusted: either
// the holder of that key signed this event's digest, or it did not. A
// transferable witness would mean resolving its key log and working out which
// key was in force at the time, for every receipt and every verifier.
func VerifyReceipt(witnessAID, eventSAID, cesrSig string) error {
	if witnessAID == "" || eventSAID == "" || cesrSig == "" {
		return fmt.Errorf("a receipt needs a witness, an event and a signature")
	}
	pub, err := iacrypto.KeyFromNonTransferableAID(witnessAID)
	if err != nil {
		return fmt.Errorf("%q is not a non-transferable witness identifier, so its receipts "+
			"cannot be checked without resolving a key log first: %w", witnessAID, err)
	}
	raw, err := iacrypto.DecodeEd25519SignatureQB64(cesrSig)
	if err != nil {
		return fmt.Errorf("the receipt signature does not decode: %w", err)
	}
	if !ed25519.Verify(pub, []byte(eventSAID), raw) {
		return fmt.Errorf("the receipt was not signed by %s, so that witness did not issue it",
			witnessAID)
	}
	return nil
}

// WitnessKey is the key a witness identifier is made of, in a form to compare
// or count by, and false when it is not a canonical non-transferable
// identifier. Two names for one witness give the same key, so a witness
// counted by its key is counted once however it is written.
func WitnessKey(witnessAID string) (string, bool) {
	pub, err := iacrypto.KeyFromNonTransferableAID(witnessAID)
	if err != nil {
		return "", false
	}
	return string(pub), true
}

// WitnessingByEvent is the witnessing report for every event of a key log,
// by the event's identifier: one walk of the log for all of them, where
// WitnessingOf walks it once per event asked about.
func WitnessingByEvent(in ValidateKELInput) map[string]EventWitnessing {
	report, _ := witnessingReport(in)
	out := make(map[string]EventWitnessing, len(report))
	for _, row := range report {
		out[row.EventSAID] = row
	}
	return out
}

// WitnessingOf reports, for one event of a key log, who was designated to
// witness it, how many receipts it needs, and how many verified receipts from
// those witnesses it has. False when the event is not in the log.
func WitnessingOf(in ValidateKELInput, eventSAID string) (EventWitnessing, bool) {
	report, _ := witnessingReport(in)
	for _, row := range report {
		if row.EventSAID == eventSAID {
			return row, true
		}
	}
	return EventWitnessing{}, false
}

// witnessingReport works out, for each event, who was designated to witness it
// and how many of those actually did.
//
// The designated set is carried forward through the log rather than read off
// any single event. An inception names the set; a rotation amends it by cutting
// and adding; everything else leaves it alone. Reading only the inception would
// report a set the identity has since changed, and reading only the latest
// event would report nothing for the events before it.
//
// It fails closed. The set and threshold at any event depend on every event
// before it, so once one cannot be read — an event that does not parse, or an
// establishment event whose witness threshold is missing or too large to hold
// — nothing from there on can say who its witnesses are, and that event and
// every later one is reported as not met. Carrying on would inherit the
// previous threshold, which at inception is zero and always met.
func witnessingReport(in ValidateKELInput) ([]EventWitnessing, bool) {
	var (
		designated []string
		threshold  int
		report     []EventWitnessing
		broken     bool
	)
	allMet := true

	for _, raw := range in.RawEvents {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			broken, allMet = true, false
			continue
		}
		switch ev.Ilk {
		case "icp", "dip":
			designated = append([]string(nil), ev.Witnesses...)
		case "rot", "drt":
			designated = amendWitnesses(designated, ev.WitnessCut, ev.WitnessAdd)
		}
		if ev.Establishment() {
			if !ev.HasTOAD || ev.TOAD > math.MaxInt32 {
				broken = true
			} else {
				threshold = int(ev.TOAD)
			}
		}

		row := EventWitnessing{
			SequenceNumber: int(ev.SN),
			EventSAID:      ev.SAID,
			Designated:     append([]string(nil), designated...),
			Threshold:      threshold,
		}

		// Count each designated witness at most once, by its key. Without that
		// one witness meets any threshold by sending its receipt repeatedly, or
		// under a second spelling of its identifier, which is how a single
		// party becomes a quorum.
		counted := map[string]bool{}
		for _, r := range in.Receipts[ev.SAID] {
			if !contains(designated, r.WitnessAID) {
				continue
			}
			key, ok := WitnessKey(r.WitnessAID)
			if !ok || counted[key] {
				continue
			}
			if err := VerifyReceipt(r.WitnessAID, ev.SAID, r.CesrSignature); err != nil {
				continue
			}
			counted[key] = true
			row.Verified++
		}
		// A threshold of zero is met by definition — an identity that asked for
		// no witnesses is not failing to reach them.
		row.Met = !broken && row.Verified >= threshold
		if !row.Met {
			allMet = false
		}
		report = append(report, row)
	}
	return report, allMet
}

// amendWitnesses applies a rotation's cuts and adds to the designated set.
func amendWitnesses(current, cuts, adds []string) []string {
	out := make([]string, 0, len(current)+len(adds))
	for _, w := range current {
		if contains(cuts, w) {
			continue
		}
		out = append(out, w)
	}
	for _, w := range adds {
		if !contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
