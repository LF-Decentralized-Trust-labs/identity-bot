package witness

import (
	"encoding/base64"
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// A witness judges each event it is sent against the key log it already holds
// for that identity, with keri-go's Admit: the same rules keri-go's log
// verifier applies, one event at a time. The event either extends the log,
// repeats one the log holds (and may carry signatures the witness did not have
// yet), or is a recovery rotation that replaces the interactions after the last
// establishment event. Anything else at a place the log holds is refused, and
// kept as evidence when it is correctly signed.

var (
	// errPlaceTaken is an event at a place the log holds a different event
	// at, which may not replace it.
	errPlaceTaken = errors.New("duplicate_sequence")
	// errSequenceGap is an event past the end of the log.
	errSequenceGap = errors.New("sequence_gap")
	// errUnverifiableLog is a log stored before a witness kept the published
	// bytes: nothing can be verified to follow it.
	errUnverifiableLog = errors.New("the key log held here was stored without its published " +
		"bytes, so no event can be verified to follow it")
)

// admitted is an event judged against the log a witness holds.
type admitted struct {
	*keri.Admission
	// held is the event the log holds at the arriving event's place, for a
	// repeat or a conflict.
	held *KelEvent
	// conflict is set when the event is refused as errPlaceTaken and its
	// signatures verify against the state before its place: evidence.
	conflict *KelConflict
}

// admit judges an event and its controller signatures against the log held
// for signerAID.
func (s *Service) admit(signerAID string, raw []byte, sigs []string) (*admitted, error) {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	if ev.Identifier != signerAID {
		// A log is built for one identity out of its own events only.
		return nil, fmt.Errorf("this event belongs to %s, not %s", ev.Identifier, signerAID)
	}
	message, err := signedMessage(raw, sigs)
	if err != nil {
		return nil, err
	}
	existing, err := s.Store.GetKelEvents(signerAID)
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		v, err := keri.VerifyEvent(nil, message)
		if err != nil {
			return nil, err
		}
		v.Signatures = asSent(sigs, v.Signatures)
		return &admitted{Admission: &keri.Admission{Verified: *v}}, nil
	}
	history := make([][]byte, 0, len(existing))
	for _, e := range existing {
		if e.RawBytesB64 == "" {
			return nil, errUnverifiableLog
		}
		b, err := base64.StdEncoding.DecodeString(e.RawBytesB64)
		if err != nil {
			return nil, fmt.Errorf("stored_event_unreadable")
		}
		m, err := signedMessage(b, e.ControllerSignatures())
		if err != nil {
			return nil, fmt.Errorf("stored_event_unreadable: %w", err)
		}
		history = append(history, m)
	}
	log, err := keri.ValidateSignedKEL(history)
	if err != nil {
		return nil, fmt.Errorf("the key log held for %s no longer verifies: %w", signerAID, err)
	}

	adm, err := log.Admit(message)
	var ve *keri.ValidationError
	if errors.As(err, &ve) {
		switch {
		case ve.Has(keri.FaultPlaceTaken):
			return &admitted{held: heldAt(existing, message),
				conflict: signedConflict(log, signerAID, raw, message, sigs)}, errPlaceTaken
		case ve.Has(keri.FaultSequenceSkip) && len(ve.Faults) == 1:
			return nil, errSequenceGap
		}
	}
	if err != nil {
		return nil, err
	}
	adm.Signatures = asSent(sigs, adm.Signatures)
	out := &admitted{Admission: adm}
	if adm.Repeat {
		out.held = heldAt(existing, message)
	}
	return out, nil
}

// signedConflict is the conflict a refused event is evidence of, when its
// controller signatures verify against the state before its place; nil when
// they do not, since an unverified event is evidence of nothing.
func signedConflict(log *keri.SignedKELResult, signerAID string, raw, message []byte,
	sigs []string) *KelConflict {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil
	}
	var before *keri.KeyState
	if ev.SN > 0 {
		before = log.StateAt(ev.SN - 1)
	}
	v, err := keri.VerifyEvent(before, message)
	if err != nil {
		return nil
	}
	held := log.StateAt(ev.SN)
	if held == nil {
		return nil
	}
	return &KelConflict{
		SignerAID: signerAID, SequenceNum: int(ev.SN), EventSAID: ev.SAID,
		RawBytesB64: base64.StdEncoding.EncodeToString(raw), Signatures: asSent(sigs, v.Signatures),
		HeldSAID: held.Digest(),
	}
}

// heldAt is the stored event at message's place.
func heldAt(existing []KelEvent, message []byte) *KelEvent {
	ev, err := keri.ParseEvent(message)
	if err != nil {
		return nil
	}
	for i := range existing {
		if uint64(existing[i].SequenceNum) == ev.SN {
			return &existing[i]
		}
	}
	return nil
}

// signedMessage is an event with its controller signatures attached, as keri-go
// verifies it, from the forms the agent stores and sends them in.
func signedMessage(raw []byte, sigs []string) ([]byte, error) {
	indexed := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		if sig == "" {
			continue
		}
		at, err := drivers.ReadControllerSignature(sig)
		if err != nil {
			return nil, err
		}
		indexed = append(indexed, at.QB64)
	}
	if len(indexed) == 0 {
		return nil, fmt.Errorf("unsigned_event")
	}
	group, err := keri.AttachControllerSigs(indexed)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), raw...), group...), nil
}

// asSent is each of the signatures sent whose indexed form is among verified,
// in the form it was sent in, so what a witness keeps and hands back is what
// the controller produced. One that did not verify is not kept.
func asSent(sent, verified []string) []string {
	ok := make(map[string]bool, len(verified))
	for _, v := range verified {
		ok[v] = true
	}
	var out []string
	seen := make(map[string]bool, len(sent))
	for _, sig := range sent {
		at, err := drivers.ReadControllerSignature(sig)
		if err != nil || !ok[at.QB64] || seen[at.QB64] {
			continue
		}
		seen[at.QB64] = true
		out = append(out, sig)
	}
	return out
}

// mergeSignatures is held with each of more whose indexed form it does not
// already hold.
func mergeSignatures(held, more []string) []string {
	out := append([]string(nil), held...)
	have := make(map[string]bool, len(out)+len(more))
	for _, sig := range held {
		if at, err := drivers.ReadControllerSignature(sig); err == nil {
			have[at.QB64] = true
		}
	}
	for _, sig := range more {
		at, err := drivers.ReadControllerSignature(sig)
		if err != nil || have[at.QB64] {
			continue
		}
		have[at.QB64] = true
		out = append(out, sig)
	}
	return out
}
