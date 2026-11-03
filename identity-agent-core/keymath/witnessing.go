package keymath

import "identity-agent-core/drivers"

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
}

// VerifyReceipt checks that sig is the witness named witness's signature over
// digest. A witness is a non-transferable identifier, so its key is its name
// and nothing has to be looked up to check it.
func VerifyReceipt(witness, digest, sig string) error {
	return drivers.VerifyReceipt(witness, digest, sig)
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
		out.Events = append(out.Events, LoggedEvent{
			SN: at.SN(), Digest: at.Digest(), Ilk: at.Ilk(), Keys: at.Keys(),
			Next: at.NextDigests(), Witnesses: at.Witnesses(), TOAD: at.TOAD(),
		})
	}
	return out, nil
}
