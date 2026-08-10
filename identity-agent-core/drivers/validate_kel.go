package drivers

import (
	"encoding/base64"
	"fmt"

	keri "github.com/grapeid/keri-go"
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

	for i, raw := range in.RawEvents {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d does not parse: %v", i, err))
			continue
		}

		// Which key signed this event depends on what kind it is. An
		// establishment event is signed by a key it declares — for a rotation
		// that is the newly revealed pre-rotated key, which is what makes the
		// commitment mean anything. A non-establishment event declares no keys
		// and is signed by whatever is currently in force.
		signing := current
		if ev.Establishment() && len(ev.Keys) > 0 {
			signing = ev.Keys[0]
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
		if signing == "" {
			problems = append(problems, fmt.Sprintf(
				"event %d carries a signature and no key is in force to check it against", i))
			continue
		}
		rawSig, err := decodeCesrSignature(sig)
		if err != nil {
			problems = append(problems, fmt.Sprintf("event %d: %v", i, err))
			continue
		}
		if err := keri.VerifySignature(signing, raw, rawSig); err != nil {
			problems = append(problems, fmt.Sprintf(
				"event %d is not signed by the key it declares, so it was not authorised by "+
					"the identity it claims to extend", i))
		}
	}

	// How well corroborated the log is, which is a different question from
	// whether it is sound. A log with one history, correctly signed, is valid;
	// whether anybody else saw it is what decides that a SECOND correctly
	// signed history could be recognised as the forgery. Reported alongside
	// rather than folded in, so a caller cannot mistake one for the other.
	witnessing, allMet := witnessingReport(in)
	out.Witnessing = witnessing
	out.Witnessed = allMet

	out.EventsValidated = len(in.RawEvents)
	out.CurrentPublicKey = current
	out.ValidationErrors = problems
	out.KelVerified = len(problems) == 0

	// An unsigned log is reported for what it is. It is not a failure — a log
	// fetched from a stranger routinely arrives without controller signatures —
	// but a caller that reads "verified" and believes authorship was proven
	// would be believing something this did not check.
	if out.KelVerified && unsigned > 0 {
		out.ValidationErrors = []string{fmt.Sprintf(
			"the log holds together and its inception derives %s; %d of %d events carried no "+
				"signature, so authorship was not checked for those",
			first.Identifier, unsigned, len(in.RawEvents))}
	}
	return out, nil
}

// decodeCesrSignature accepts a controller signature in the forms the agent
// stores and produces.
//
// Both are 88 characters and neither can be told from the other by length. An
// unindexed signature (0B) is what this agent's own signing path produces; an
// indexed one (A…) is what appears in a published stream, where the index says
// which of several keys signed.
func decodeCesrSignature(sig string) ([]byte, error) {
	switch {
	case len(sig) == 88 && sig[:2] == keri.CodeEd25519Sig:
		raw, err := keri.MatterRaw(keri.CodeEd25519Sig, sig, 64)
		if err != nil {
			return nil, fmt.Errorf("the signature looks unindexed and does not decode: %w", err)
		}
		return raw, nil
	case len(sig) == 88 && sig[0] == 'A':
		// Indexed: a one-character code, one character of index, then payload.
		// The index selects a key; only single-key logs are checked here, so it
		// is decoded and the payload taken.
		raw, err := base64.RawURLEncoding.DecodeString("AA" + sig[2:])
		if err != nil {
			return nil, fmt.Errorf("the signature looks indexed and does not decode: %w", err)
		}
		if len(raw) < 64 {
			return nil, fmt.Errorf("an indexed signature decodes to %d bytes, not 64", len(raw))
		}
		return raw[len(raw)-64:], nil
	default:
		raw, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			return nil, fmt.Errorf("the signature is not a form this understands")
		}
		if len(raw) != 64 {
			return nil, fmt.Errorf("a signature decodes to %d bytes; Ed25519 signatures are 64",
				len(raw))
		}
		return raw, nil
	}
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

// ValidateKELBytes checks a log from its canonical bytes.
//
// The Python driver answers this in Go rather than over its HTTP link. That is
// deliberate: validation is arithmetic over bytes the caller already holds, so
// sending them to a subprocess would add a round trip, a serialisation, and a
// second implementation of a security check — to compute the same answer from
// the same bytes. It also means the check works on a phone, where there is no
// subprocess to ask.
func (d *KeriDriver) ValidateKELBytes(in ValidateKELInput) (*DriverValidateKELResponse, error) {
	return ValidateKELFromBytes(in)
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
	if len(witnessAID) != 44 || witnessAID[0] != 'B' {
		return fmt.Errorf("%q is not a non-transferable witness identifier, so its receipts "+
			"cannot be checked without resolving a key log first", witnessAID)
	}
	raw, err := keri.MatterRaw(keri.CodeEd25519Sig, cesrSig, 64)
	if err != nil {
		return fmt.Errorf("the receipt signature does not decode: %w", err)
	}
	if err := keri.VerifySignature(witnessAID, []byte(eventSAID), raw); err != nil {
		return fmt.Errorf("the receipt was not signed by %s, so that witness did not issue it",
			witnessAID)
	}
	return nil
}

// witnessingReport works out, for each event, who was designated to witness it
// and how many of those actually did.
//
// The designated set is carried forward through the log rather than read off
// any single event. An inception names the set; a rotation amends it by cutting
// and adding; everything else leaves it alone. Reading only the inception would
// report a set the identity has since changed, and reading only the latest
// event would report nothing for the events before it.
func witnessingReport(in ValidateKELInput) ([]EventWitnessing, bool) {
	var (
		designated []string
		threshold  int
		report     []EventWitnessing
	)
	allMet := true

	for _, raw := range in.RawEvents {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
		}
		switch ev.Ilk {
		case "icp", "dip":
			designated = append([]string(nil), ev.Witnesses...)
		case "rot", "drt":
			designated = amendWitnesses(designated, ev.WitnessCut, ev.WitnessAdd)
		}
		if ev.HasTOAD {
			threshold = int(ev.TOAD)
		}

		row := EventWitnessing{
			SequenceNumber: int(ev.SN),
			EventSAID:      ev.SAID,
			Designated:     append([]string(nil), designated...),
			Threshold:      threshold,
		}

		// Count each designated witness at most once. Without that one witness
		// meets any threshold by sending its receipt repeatedly, which is how a
		// single party becomes a quorum.
		counted := map[string]bool{}
		for _, r := range in.Receipts[ev.SAID] {
			if !contains(designated, r.WitnessAID) || counted[r.WitnessAID] {
				continue
			}
			if err := VerifyReceipt(r.WitnessAID, ev.SAID, r.CesrSignature); err != nil {
				continue
			}
			counted[r.WitnessAID] = true
			row.Verified++
		}
		// A threshold of zero is met by definition — an identity that asked for
		// no witnesses is not failing to reach them.
		row.Met = row.Verified >= threshold
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
