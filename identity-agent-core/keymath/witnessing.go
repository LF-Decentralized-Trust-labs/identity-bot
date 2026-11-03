package keymath

import (
	"encoding/base64"
	"errors"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// What an app checks for itself about what its identity's witnesses say: that a
// receipt is the named witness's signature over the event's digest, and what
// key state a copy of the log a witness holds establishes. Both are judged by
// the engine every core runs, on the app's own machine, so a core that relays
// or summarises these answers cannot change them (ADR-061 section 4, item 5).

// MaxLogEvents bounds a log checked here.
const MaxLogEvents = 4096

// SignedEvent is an event's bytes with its controller signatures, as a witness
// hands it back.
type SignedEvent struct {
	RawB64 string   `json:"raw_b64"`
	Sigs   []string `json:"sigs"`
}

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
	if len(events) == 0 {
		return nil, errors.New("an empty log establishes no identity")
	}
	if len(events) > MaxLogEvents {
		return nil, fmt.Errorf("the log has %d events; at most %d are checked", len(events), MaxLogEvents)
	}
	messages := make([][]byte, 0, len(events))
	for i, ev := range events {
		raw, err := base64.StdEncoding.Strict().DecodeString(ev.RawB64)
		if err != nil {
			return nil, fmt.Errorf("event %d is not standard base64", i)
		}
		m, err := drivers.SignedMessageAsSent(raw, ev.Sigs)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		messages = append(messages, m)
	}
	res, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		return nil, err
	}
	if res.Identifier != aid {
		return nil, fmt.Errorf("this log is the history of %s, not %s", res.Identifier, aid)
	}
	st := res.State()
	return &LogState{
		AID: aid, SN: st.SN(), Digest: st.Digest(), Ilk: st.Ilk(),
		Establishment: st.LastEstablishment(), Keys: st.Keys(), Next: st.NextDigests(),
		Witnesses: st.Witnesses(), TOAD: st.TOAD(),
	}, nil
}
