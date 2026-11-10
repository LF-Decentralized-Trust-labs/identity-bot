package keymath

import (
	"encoding/json"
	"errors"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
	"identity-agent-core/messagingkeys"
)

// What an app checks for itself about what its identity's witnesses say: that a
// receipt is the named witness's signature over the event's digest, and what
// key state a copy of the log a witness holds establishes. Both are judged by
// the engine every core runs, on the app's own machine, so a core that relays
// or summarises these answers cannot change them (ADR-061 section 4, item 5).

// SignedEvent is an event's bytes with its controller signatures, as a witness
// hands it back.
type SignedEvent = drivers.SignedEventBytes

// LogState is the key state a verified log leaves, and the event it ends on.
type LogState struct {
	AID           string   `json:"aid"`
	SN            uint64   `json:"sn"`
	Digest        string   `json:"digest"`
	Ilk           string   `json:"ilk"`
	Establishment uint64   `json:"establishment"`
	Keys          []string `json:"keys"`
	Next          []string `json:"next"`
	Witnesses     []string `json:"witnesses"`
	TOAD          uint64   `json:"toad"`
	// Events are every event of the log in order, as verified: what copies
	// of one log are compared by.
	Events []LoggedEvent `json:"events"`
}

// LoggedEvent is one event of a verified log: its place, digest and type, and
// the keys, commitments and witnesses in force after it.
type LoggedEvent struct {
	SN        uint64   `json:"sn"`
	Digest    string   `json:"digest"`
	Ilk       string   `json:"ilk"`
	Keys      []string `json:"keys"`
	Next      []string `json:"next"`
	Witnesses []string `json:"witnesses"`
	TOAD      uint64   `json:"toad"`
	// MessagingKeysets are the messaging keyset anchors the event carries,
	// as it carries them.
	MessagingKeysets []json.RawMessage `json:"messaging_keysets,omitempty"`
}

// VerifyReceipt checks that sig is the witness named witness's signature over
// digest. A witness is a non-transferable identifier, so its key is its name
// and nothing has to be looked up to check it.
func VerifyReceipt(witness, digest, sig string) error {
	return drivers.VerifyReceipt(witness, digest, sig)
}

// VerifyEventReceipt is VerifyReceipt for either form of receipt: one signed
// over the serialised event, which is given in base64 and is needed to check
// it, or the earlier one over the digest.
func VerifyEventReceipt(witness, eventB64, digest, sig string) error {
	var raw []byte
	if eventB64 != "" {
		var err error
		if raw, err = drivers.DecodeRawBytes(eventB64); err != nil {
			return errors.New("the event is not readable base64")
		}
	}
	return drivers.VerifyEventReceipt(witness, raw, digest, sig, nil)
}

// VerifyLog judges events as one identity's key log, from its founding, as
// every log is judged (keri.ValidateSignedKEL), and returns the state it ends
// in. A log whose founding does not name aid is refused: an identifier is the
// digest of its founding, so a log that verifies from it is that identity's.
func VerifyLog(aid string, events []SignedEvent) (*LogState, error) {
	messages, err := drivers.LogMessages(events)
	if err != nil {
		return nil, err
	}
	res, err := drivers.VerifiedLogOf(aid, messages)
	if err != nil {
		return nil, err
	}
	st := res.State()
	out := &LogState{
		AID: aid, SN: st.SN(), Digest: st.Digest(), Ilk: st.Ilk(),
		Establishment: st.LastEstablishment(), Keys: st.Keys(), Next: st.NextDigests(),
		Witnesses: st.Witnesses(), TOAD: st.TOAD(),
	}
	for sn := uint64(0); sn <= st.SN(); sn++ {
		at := res.StateAt(sn)
		if at == nil {
			break
		}
		e := LoggedEvent{
			SN: at.SN(), Digest: at.Digest(), Ilk: at.Ilk(), Keys: at.Keys(),
			Next: at.NextDigests(), Witnesses: at.Witnesses(), TOAD: at.TOAD(),
		}
		if int(sn) < len(messages) {
			e.MessagingKeysets = messagingKeysetsOf(messages[sn])
		}
		out.Events = append(out.Events, e)
	}
	return out, nil
}

// messagingKeysetsOf are the messaging keyset anchors among the seals of the
// event a message carries.
func messagingKeysetsOf(message []byte) []json.RawMessage {
	ev, err := keri.ParseEvent(message)
	if err != nil {
		return nil
	}
	for _, f := range ev.Fields {
		if f.Name != "a" {
			continue
		}
		var seals []json.RawMessage
		if json.Unmarshal(f.Value, &seals) != nil {
			return nil
		}
		return messagingkeys.SealsAmong(seals)
	}
	return nil
}
