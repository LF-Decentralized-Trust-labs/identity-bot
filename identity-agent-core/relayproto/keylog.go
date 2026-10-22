package relayproto

import (
	"crypto/ed25519"
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// CurrentKey reads a signed key event log (a CESR stream) and returns the one
// signing key it names now for aid. It is the single answer to "which key may
// speak for this identifier" that a relay, a mailbox or any other service
// provider uses, so the rules below cannot drift between them:
//
//   - the log is at most MaxKELBytes and MaxKELEvents;
//   - keri-go validates every event and its signatures;
//   - the log is aid's: its inception derives aid;
//   - it names exactly one signing key, an Ed25519 key.
//
// One key, not one of several: a service enrols a single signer. Accepting any
// member of a multi-key identity would let one member of a group act as the
// whole group, and its threshold would mean nothing.
func CurrentKey(aid string, kel []byte) (ed25519.PublicKey, error) {
	if len(kel) == 0 {
		return nil, fmt.Errorf("no key event log was given for %q", aid)
	}
	if len(kel) > MaxKELBytes {
		return nil, fmt.Errorf("the key event log is larger than %d bytes", MaxKELBytes)
	}
	messages, err := keri.ParseKELStream(kel)
	if err != nil {
		return nil, fmt.Errorf("the key event log is not readable: %w", err)
	}
	if len(messages) > MaxKELEvents {
		return nil, fmt.Errorf("the key event log has %d events; the limit is %d", len(messages), MaxKELEvents)
	}
	state, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		return nil, fmt.Errorf("the key event log does not verify: %w", err)
	}
	if state.Identifier != aid {
		return nil, fmt.Errorf("the key event log is %q's, not %q's", state.Identifier, aid)
	}
	if len(state.Keys) != 1 {
		return nil, fmt.Errorf("%q names %d signing keys; a service enrols an identifier with exactly one", aid, len(state.Keys))
	}
	raw, err := keri.MatterRaw(keri.CodeEd25519, state.Keys[0], ed25519.PublicKeySize)
	if err != nil {
		return nil, fmt.Errorf("%q's signing key is not an Ed25519 key: %w", aid, err)
	}
	return ed25519.PublicKey(raw), nil
}

// LogExtends reports whether log holds every event base holds, in the same
// order, and possibly more after them: the rule for accepting a newer log in
// place of one already held. A log that rewrites history extends nothing.
// Events are compared as keri-go reads them, by sequence number, type and
// SAID, never as bytes, so a log that gained a receipt or was re-serialised
// still extends the one it came from. An empty base is extended by anything.
func LogExtends(log, base []byte) bool { return logExtends(log, base) }
