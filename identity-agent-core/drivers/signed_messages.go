package drivers

import (
	"encoding/base64"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// The one place an event's controller signatures are read into the indexed
// form KERI attaches, and attached to it for keri-go to verify.

// SignedMessage is an event with its controller signatures attached, as it
// travels and as keri-go verifies it.
func SignedMessage(raw []byte, sigs []string) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, fmt.Errorf("an event with no signature has nothing to attach")
	}
	group, err := keri.AttachControllerSigs(sigs)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(raw)+len(group))
	out = append(out, raw...)
	return append(out, group...), nil
}

// IndexedSignatures reads signatures over an event signed by a list of
// keyCount keys, into the indexed form KERI attaches. An unindexed signature,
// the form this agent's own signing path produces, names no key, so it is
// read as the first key's only where there is one key to sign; on an event
// several keys sign, it is refused rather than guessed at. The same signature
// twice is one signature.
func IndexedSignatures(sigs []string, keyCount int) ([]string, error) {
	out := make([]string, 0, len(sigs))
	seen := map[string]bool{}
	for i, s := range sigs {
		if s == "" {
			continue
		}
		c, err := ReadControllerSignature(s)
		if err != nil {
			return nil, fmt.Errorf("signature %d is unreadable: %w", i, err)
		}
		if c.QB64 != s && keyCount != 1 {
			return nil, fmt.Errorf("signature %d names no key, and this event is signed by %d keys, "+
				"so which one made it cannot be told; send it indexed", i, keyCount)
		}
		if !seen[c.QB64] {
			seen[c.QB64] = true
			out = append(out, c.QB64)
		}
	}
	return out, nil
}

// SignedMessageAsSent is an event with its controller signatures attached, as
// keri-go verifies it, from the forms they are stored and sent in: indexed, or
// for an event with one key, the unindexed form this agent's own signing path
// produces. An event with no signature is refused as "unsigned_event".
func SignedMessageAsSent(raw []byte, sigs []string) ([]byte, error) {
	keys := 1
	if ev, err := keri.ParseEvent(raw); err == nil && len(ev.Keys) > 1 {
		keys = len(ev.Keys)
	}
	indexed, err := IndexedSignatures(sigs, keys)
	if err != nil {
		return nil, err
	}
	if len(indexed) == 0 {
		return nil, fmt.Errorf("unsigned_event")
	}
	return SignedMessage(raw, indexed)
}

// MaxLogEvents bounds a key log judged in one go from copies somebody sent:
// an identity's whole log, but not so long that one request holds the judge
// for long.
const MaxLogEvents = 2048

// SignedEventBytes is an event's bytes, base64, with its controller
// signatures, as a copy of a log is sent to be judged.
type SignedEventBytes struct {
	RawB64 string   `json:"raw_b64"`
	Sigs   []string `json:"sigs"`
}

// LogMessages makes events into the messages keri-go judges a log by, each
// with its signatures attached as they are stored and sent.
func LogMessages(events []SignedEventBytes) ([][]byte, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("the log has no events")
	}
	if len(events) > MaxLogEvents {
		return nil, fmt.Errorf("the log has %d events; at most %d are checked", len(events), MaxLogEvents)
	}
	out := make([][]byte, 0, len(events))
	for i, ev := range events {
		raw, err := base64.StdEncoding.Strict().DecodeString(ev.RawB64)
		if err != nil {
			return nil, fmt.Errorf("event %d is not standard base64", i)
		}
		if len(ev.Sigs) == 0 {
			return nil, fmt.Errorf("event %d carries no signature", i)
		}
		m, err := SignedMessageAsSent(raw, ev.Sigs)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// VerifiedLogOf judges messages as aid's key log, from its founding, as every
// log is judged: a log that verifies but is another identity's is refused.
func VerifiedLogOf(aid string, messages [][]byte) (*keri.SignedKELResult, error) {
	if len(messages) > MaxLogEvents {
		return nil, fmt.Errorf("the log has %d events; at most %d are checked", len(messages), MaxLogEvents)
	}
	res, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		return nil, err
	}
	if res.Identifier != aid {
		return nil, fmt.Errorf("this log is the history of %s, not %s", res.Identifier, aid)
	}
	return res, nil
}
