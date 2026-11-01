package keriengine

import (
	"errors"
	"fmt"
	"sort"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// The one way an event joins a key log this engine holds.
//
// Every event, founding, rotation and interaction alike, is added only with
// controller signatures that make the log, up to and including it, one keri-go
// accepts: each event signed by the key state in force, meeting its signing
// threshold, and each rotation opening enough of the last establishment
// event's commitment (keri.ValidateSignedKEL). The rule is keri-go's and is not
// restated here, so what this engine adds and what it accepts from anybody
// else cannot drift apart.
//
// The log is judged whole, which is why an event an earlier version added
// unsigned stops anything more being added after it until it is signed: a log
// with an unsigned event in it verifies for nobody, so extending it would only
// publish more events nobody can check.

// ErrUnsignedHistory is an event refused because the log it would extend holds
// events added without signatures by an earlier version.
type ErrUnsignedHistory struct {
	AID string
	SNs []int
}

func (e *ErrUnsignedHistory) Error() string {
	return fmt.Sprintf("the key log of %s holds events added without their signatures (sequence numbers %v); "+
		"nothing more is added to it until they are signed, because a log with an unsigned event in it "+
		"verifies for nobody", e.AID, e.SNs)
}

// ErrNotAuthorised is an event whose signatures do not make the log one that
// verifies: a signature that does not verify, a threshold not met, or a
// rotation that does not open enough of the prior commitment.
type ErrNotAuthorised struct {
	AID string
	SN  int
	Err error
	// BadSignature is set when a signature named a key it does not verify
	// under, rather than the signatures falling short of a threshold.
	BadSignature bool
}

func (e *ErrNotAuthorised) Error() string {
	return fmt.Sprintf("the event at sequence number %d of %s is not authorised by its signatures, so it is "+
		"not added: %v", e.SN, e.AID, e.Err)
}

func (e *ErrNotAuthorised) Unwrap() error { return e.Err }

// signedMessage is an event with its controller signatures attached, as it
// travels and as keri-go verifies it.
func signedMessage(raw []byte, sigs []string) ([]byte, error) {
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

// indexedSignatures reads signatures over an event signed by a list of
// keyCount keys, into the indexed form KERI attaches. An unindexed signature,
// the form this agent's own signing path produces, names no key, so it is
// read as the first key's only where there is one key to sign; on an event
// several keys sign, it is refused rather than guessed at. The same signature
// twice is one signature.
func indexedSignatures(sigs []string, keyCount int) ([]string, error) {
	out := make([]string, 0, len(sigs))
	seen := map[string]bool{}
	for i, s := range sigs {
		if s == "" {
			continue
		}
		c, err := drivers.ReadControllerSignature(s)
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

// signingKeys is the key list an event's signatures index into: its own for an
// establishment event, and the last establishment event's for an interaction.
func signingKeys(before []kelEntry, ev *keri.Event) ([]string, error) {
	if ev.Establishment() {
		return ev.Keys, nil
	}
	_, est, err := lastEstablishment(before)
	if err != nil {
		return nil, err
	}
	return est.Keys, nil
}

// lastEstablishment is the most recent establishment event among entries, and
// its place.
func lastEstablishment(entries []kelEntry) (int, *keri.Event, error) {
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Raw == nil {
			return 0, nil, fmt.Errorf("event %d was kept without the bytes it was published as, so "+
				"the key state it leaves cannot be read", i)
		}
		ev, err := keri.ParseEvent(entries[i].Raw)
		if err != nil {
			return 0, nil, err
		}
		if ev.Establishment() {
			return i, ev, nil
		}
	}
	return 0, nil, fmt.Errorf("no establishment event precedes this one")
}

// signaturesVerify reports whether every signature verifies over raw under the
// key it names, and which key places signed. It decides nothing about
// thresholds or commitments, which are keri-go's; it tells a signature that is
// wrong from signatures that are right and too few.
func signaturesVerify(raw []byte, sigs []string, keys []string) (signed []int, ok bool) {
	at := map[int]bool{}
	for _, s := range sigs {
		c, err := drivers.ReadControllerSignature(s)
		if err != nil || c.At.Index < 0 || c.At.Index >= len(keys) {
			return nil, false
		}
		if keri.VerifySignature(keys[c.At.Index], raw, c.Raw) != nil {
			return nil, false
		}
		at[c.At.Index] = true
	}
	for i := range at {
		signed = append(signed, i)
	}
	sort.Ints(signed)
	return signed, true
}

// checkedSignatures reads sigs over raw, an event signed by keys, keeping one
// signature per key place, and refuses the lot if any signature does not
// verify under the key it names. keri-go drops a signature that does not
// verify and judges the rest, which is right for a log received from
// elsewhere; a log this engine keeps and publishes carries none, so nobody
// can add junk to an event by sending it beside good signatures.
func checkedSignatures(raw []byte, sigs []string, keys []string) ([]string, error) {
	indexed, err := indexedSignatures(sigs, len(keys))
	if err != nil {
		return nil, err
	}
	byPlace := map[int]bool{}
	out := make([]string, 0, len(indexed))
	for i, s := range indexed {
		c, err := drivers.ReadControllerSignature(s)
		if err != nil {
			return nil, fmt.Errorf("signature %d is unreadable: %w", i, err)
		}
		if c.At.Index < 0 || c.At.Index >= len(keys) {
			return nil, fmt.Errorf("signature %d names key %d, and the event is signed by %d keys", i, c.At.Index, len(keys))
		}
		if err := keri.VerifySignature(keys[c.At.Index], raw, c.Raw); err != nil {
			return nil, fmt.Errorf("signature %d does not verify under key %d: %w", i, c.At.Index, err)
		}
		if byPlace[c.At.Index] {
			continue
		}
		byPlace[c.At.Index] = true
		out = append(out, s)
	}
	return out, nil
}

// signHistory obtains, from the installed signer, signatures for events in
// entries that are held without them, where each was signed by one key the
// signer holds: a founding (which the core's signer signs only where the whole
// key chain is its own) or an interaction, and a rotation only where it was
// marked unsigned when this version first ran. It changes nothing: what it returns is kept only with the next
// event, once the whole log verifies with it.
func (e *Engine) signHistory(aid string, entries []kelEntry) map[int][]string {
	e.commitMu.Lock()
	f := e.eventSignature
	e.commitMu.Unlock()
	if f == nil {
		return nil
	}
	filled := map[int][]string{}
	var keys []string
	for i, en := range entries {
		if en.Raw == nil {
			return filled
		}
		ev, err := keri.ParseEvent(en.Raw)
		if err != nil {
			return filled
		}
		if ev.Establishment() {
			keys = ev.Keys
		}
		if len(en.Sigs) > 0 || len(keys) != 1 {
			continue
		}
		// A rotation moves control to the keys it names and the commitment
		// it makes, so one is signed after the fact only where an earlier
		// version of this engine added it unsigned: never one stored since,
		// which anybody able to write the store could have composed.
		if (ev.Ilk == "rot" || ev.Ilk == "drt") && !en.MarkedUnsigned {
			continue
		}
		sig, err := f(aid, keys[0], en.Raw)
		if err != nil {
			continue
		}
		if indexed, err := indexedSignatures([]string{sig}, 1); err == nil && len(indexed) == 1 {
			filled[i] = indexed
		}
	}
	return filled
}

// judge checks that before, followed by raw with sigs, is a log keri-go
// verifies. It returns signatures obtained for earlier events held without
// them, which must be kept with this event.
func (e *Engine) judge(aid string, before []kelEntry, raw []byte, ev *keri.Event, sigs []string) (map[int][]string, error) {
	filled := e.signHistory(aid, before)
	messages := make([][]byte, 0, len(before)+1)
	var unsigned []int
	for i, en := range before {
		s := en.Sigs
		if len(s) == 0 {
			s = filled[i]
		}
		if en.Raw == nil || len(s) == 0 {
			unsigned = append(unsigned, i)
			continue
		}
		m, err := signedMessage(en.Raw, s)
		if err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	if len(unsigned) > 0 {
		return nil, &ErrUnsignedHistory{AID: aid, SNs: unsigned}
	}
	if len(sigs) == 0 {
		return nil, &ErrNotAuthorised{AID: aid, SN: int(ev.SN), Err: errors.New("it carries no signature")}
	}
	m, err := signedMessage(raw, sigs)
	if err != nil {
		return nil, err
	}
	messages = append(messages, m)
	if _, err := keri.ValidateSignedKEL(messages); err != nil {
		keys, kerr := signingKeys(before, ev)
		_, ok := signaturesVerify(raw, sigs, keys)
		return nil, &ErrNotAuthorised{AID: aid, SN: int(ev.SN), Err: err, BadSignature: kerr == nil && !ok}
	}
	return filled, nil
}

// add appends raw, signed by sigs, at the tip of id's key log. The caller holds
// id for writing. keep, when given, is offered the event with its signatures
// before anything changes here; a keep that fails leaves the log as it was.
// also runs, under the state lock, for whatever else the event changes.
func (e *Engine) add(id *identity, raw []byte, sigs []string, keep func(drivers.KELKeep) error, also func(*keri.Event)) error {
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return err
	}
	e.state.mu.RLock()
	before := append([]kelEntry(nil), id.KEL...)
	e.state.mu.RUnlock()
	if int(ev.SN) != len(before) {
		return fmt.Errorf("the event is at sequence number %d and the log of %s has %d events", ev.SN, id.AID, len(before))
	}
	return e.place(id, before, len(before), raw, ev, sigs, keep, also)
}

// place adds raw at position at of id's log, superseding whatever interactions
// stood from there on. before is the log as read.
func (e *Engine) place(id *identity, before []kelEntry, at int, raw []byte, ev *keri.Event, sigs []string,
	keep func(drivers.KELKeep) error, also func(*keri.Event)) error {

	keys, err := signingKeys(before[:at], ev)
	if err != nil && at > 0 {
		return err
	}
	if ev.Ilk == "icp" || ev.Ilk == "dip" {
		keys = ev.Keys
	}
	indexed, err := checkedSignatures(raw, sigs, keys)
	if err != nil {
		return &ErrNotAuthorised{AID: id.AID, SN: int(ev.SN), Err: err, BadSignature: true}
	}
	filled, err := e.judge(id.AID, before[:at], raw, ev, indexed)
	if err != nil {
		return err
	}
	next, err := entry(raw)
	if err != nil {
		return err
	}
	next.Sigs = indexed
	if keep != nil {
		k := drivers.KELKeep{AID: id.AID, SN: int(ev.SN), Raw: raw, Signature: indexed[0],
			Signatures: indexed, Earlier: filled}
		if at < len(before) {
			k.Supersedes = at
		}
		if err := keep(k); err != nil {
			return fmt.Errorf("the event was not kept, so it was not added: %w", err)
		}
	}
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	for i, s := range filled {
		if i < len(id.KEL) && len(id.KEL[i].Sigs) == 0 {
			id.KEL[i].Sigs = s
		}
	}
	if at < len(id.KEL) {
		id.Superseded = append(id.Superseded, id.KEL[at:]...)
		id.KEL = id.KEL[:at]
	}
	if also != nil {
		also(ev)
	}
	id.SN = int(ev.SN)
	id.LastSAID = ev.SAID
	id.KEL = append(id.KEL, next)
	if ev.Establishment() && len(ev.Keys) > 0 {
		id.PublicKey = ev.Keys[0]
		if len(ev.NextDigest) > 0 {
			id.NextKeyDigest = ev.NextDigest[0]
		}
	}
	return nil
}

// ownSignatures is this engine's installed signer's signature over raw by
// each key it holds of keys, indexed where each key sits. For the paths where
// the core holds the key: a key it does not hold signs nothing here, and the
// event then waits for, or is refused without, that key's signature.
func (e *Engine) ownSignatures(aid string, keys []string, raw []byte) []string {
	e.commitMu.Lock()
	f := e.eventSignature
	e.commitMu.Unlock()
	if f == nil {
		return nil
	}
	var out []string
	for i, key := range keys {
		sig, err := f(aid, key, raw)
		if err != nil {
			continue
		}
		c, err := drivers.ReadControllerSignature(sig)
		if err != nil || keri.VerifySignature(key, raw, c.Raw) != nil {
			continue
		}
		qb64, err := keri.EncodeIndexedSignature(c.Raw, keri.SamePlace(i))
		if err != nil {
			continue
		}
		out = append(out, qb64)
	}
	return out
}

// VerifiedSignatures keeps, for each event of a log, only the signatures that
// verify under the key they name in the key state in force there, one per
// key place. A log received from elsewhere may carry signatures that verify
// nothing beside ones that do, and keri-go judges it on the ones that do; what
// this Identity Agent keeps, and publishes again, carries only those.
func VerifiedSignatures(raws [][]byte, sigs [][]string) ([][]string, error) {
	out := make([][]string, len(raws))
	var keys []string
	for i, raw := range raws {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			return nil, fmt.Errorf("event %d: %w", i, err)
		}
		if ev.Establishment() {
			keys = ev.Keys
		}
		if i >= len(sigs) {
			continue
		}
		seen := map[int]bool{}
		for _, s := range sigs[i] {
			c, err := drivers.ReadControllerSignature(s)
			if err != nil || c.At.Index < 0 || c.At.Index >= len(keys) || seen[c.At.Index] {
				continue
			}
			if c.QB64 != s && len(keys) != 1 {
				continue // names no key, among several
			}
			if keri.VerifySignature(keys[c.At.Index], raw, c.Raw) != nil {
				continue
			}
			seen[c.At.Index] = true
			out[i] = append(out[i], c.QB64)
		}
	}
	return out, nil
}
