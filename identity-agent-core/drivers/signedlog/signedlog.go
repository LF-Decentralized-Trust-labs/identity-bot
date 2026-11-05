// Package signedlog builds real, signed key event logs for tests: genuine
// inception, rotation and interaction events from keri-go, each signed by the
// key KERI says must sign it, so what a test stores is what the validator
// actually accepts and not a hand-written map that merely looks like a log.
//
// It is test support, like driverfake, and nothing in the product imports it.
package signedlog

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// Keys is a run of signing keys, each committed to by the one before it.
type Keys struct {
	signers []keri.Signer
	pubs    []string
}

// NewKeys makes n keys: key 0 founds the identity, each next one is the
// pre-rotated successor of the one before.
func NewKeys(t testing.TB, n int) *Keys {
	t.Helper()
	k := &Keys{}
	for i := 0; i < n; i++ {
		s, err := keri.GenerateSigner(true)
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		k.signers = append(k.signers, s)
		k.pubs = append(k.pubs, p)
	}
	return k
}

// KeysFromSeeds is a run of keys from fixed 32-byte seeds, for a test whose
// other fixtures already hold those seeds (to sign something with the same key).
func KeysFromSeeds(t testing.TB, seeds ...[]byte) *Keys {
	t.Helper()
	k := &Keys{}
	for _, seed := range seeds {
		s, err := keri.NewSoftwareSigner(seed, true)
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		k.signers = append(k.signers, s)
		k.pubs = append(k.pubs, p)
	}
	return k
}

// Pub is key i as the CESR text a sealed or stored key is written in.
func (k *Keys) Pub(i int) string { return k.pubs[i] }

func (k *Keys) digest(t testing.TB, i int) []string {
	if i >= len(k.pubs) {
		return nil
	}
	d, err := keri.NextDigest(k.pubs[i])
	if err != nil {
		t.Fatal(err)
	}
	return []string{d}
}

// Log is a signed log and the key currently in force at its tip.
type Log struct {
	t     testing.TB
	keys  *Keys
	cur   int
	AID   string
	Raws  [][]byte
	Sigs  []string
	saids []string
	by    []int // which key signed each event
}

// Incept founds an identity on key 0.
func Incept(t testing.TB, k *Keys) *Log {
	t.Helper()
	raw, err := keri.BuildInception(keri.InceptionInput{
		Keys: []string{k.pubs[0]}, NextDigests: k.digest(t, 1), Derivation: "self-addressing",
	})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	l := &Log{t: t, keys: k, AID: ev.Identifier}
	l.add(raw, ev.SAID, 0)
	return l
}

func (l *Log) add(raw []byte, said string, signer int) {
	l.t.Helper()
	sig, err := l.keys.signers[signer].Sign(raw)
	if err != nil {
		l.t.Fatal(err)
	}
	qb64, err := keri.MatterQB64(keri.CodeEd25519Sig, sig)
	if err != nil {
		l.t.Fatal(err)
	}
	l.Raws = append(l.Raws, raw)
	l.Sigs = append(l.Sigs, qb64)
	l.saids = append(l.saids, said)
	l.by = append(l.by, signer)
	l.cur = signer
}

// Rotate moves the log to the next key, signed by that key.
func (l *Log) Rotate() *Log {
	l.t.Helper()
	next := l.cur + 1
	raw, err := keri.BuildRotation(keri.RotationInput{
		Prefix: l.AID, Keys: []string{l.keys.pubs[next]}, PriorSAID: l.saids[len(l.saids)-1],
		SN: len(l.Raws), NextDigests: l.keys.digest(l.t, next+1),
	})
	if err != nil {
		l.t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		l.t.Fatal(err)
	}
	l.add(raw, ev.SAID, next)
	return l
}

// Interact appends an interaction event, signed by the key now in force. The
// label makes two interactions at the same place differ.
func (l *Log) Interact(label string) *Log {
	l.t.Helper()
	seal, _ := json.Marshal(map[string]string{"d": label})
	raw, err := keri.BuildInteraction(keri.InteractionInput{
		Prefix: l.AID, PriorSAID: l.saids[len(l.saids)-1], SN: len(l.Raws),
		Data: []json.RawMessage{seal},
	})
	if err != nil {
		l.t.Fatal(err)
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		l.t.Fatal(err)
	}
	l.add(raw, ev.SAID, l.cur)
	return l
}

// Fork is a copy of the log as it stands, to be taken a different way: what
// somebody holding a retired key can do from the event that key was current at.
func (l *Log) Fork() *Log {
	c := *l
	c.Raws = append([][]byte(nil), l.Raws...)
	c.Sigs = append([]string(nil), l.Sigs...)
	c.saids = append([]string(nil), l.saids...)
	c.by = append([]int(nil), l.by...)
	return &c
}

// Cut is the log as it was after its first n events .
func (l *Log) Cut(n int) *Log {
	c := l.Fork()
	c.Raws, c.Sigs, c.saids, c.by = c.Raws[:n], c.Sigs[:n], c.saids[:n], c.by[:n]
	c.cur = c.by[n-1]
	return c
}

// Len is the number of events.
func (l *Log) Len() int { return len(l.Raws) }

// Key is the CESR key in force at the tip.
func (l *Log) Key() string { return l.keys.pubs[l.cur] }

// KeyAt is the CESR key of key index i.
func (l *Log) KeyAt(i int) string { return l.keys.pubs[i] }

// Records is the log as an OOBI publishes it: canonical bytes and signature.
func (l *Log) Records() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(l.Raws))
	for i, raw := range l.Raws {
		out = append(out, map[string]interface{}{
			"sequence_number": i,
			"event_json":      string(raw),
			"raw_bytes_b64":   base64.StdEncoding.EncodeToString(raw),
			"cesr_signature":  l.Sigs[i],
		})
	}
	return out
}

// Verdict is what the engine's own validator says about the log.
func (l *Log) Verdict() *drivers.DriverValidateKELResponse {
	l.t.Helper()
	got, err := drivers.ValidateKELFromBytes(drivers.ValidateKELInput{
		AID: l.AID, RawEvents: l.Raws, CesrSignatures: l.Sigs,
	})
	if err != nil {
		l.t.Fatal(fmt.Errorf("validate: %w", err))
	}
	return got
}
