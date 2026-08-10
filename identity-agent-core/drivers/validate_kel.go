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
