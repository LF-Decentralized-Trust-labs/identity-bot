package drivers

import (
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
