// Package keymath is the key arithmetic an app that holds an identity's keys
// needs, done with the core's own code (ADR-061 section 7).
//
// The app derives every key from its recovery phrase, so it needs, for a child
// seed it derived: the post-quantum next key it commits to and its digest, a
// signature with that key, the messaging keyset it anchors, and the reading of
// an event the core prepared for it to sign. Writing any of that again in the
// app would be a second implementation that has to agree with this one to the
// byte, so the app runs this instead: linked into the app on a phone, and as
// the core binary's one-shot keymath command on a desktop.
//
// It takes a 32-byte child seed, never the root, and imports nothing that
// reaches a network or storage. It zeroes its copies of a seed when done, which
// reduces how long one is held but cannot guarantee it: a garbage collector
// may have copied a buffer first.
package keymath

import (
	"encoding/json"
	"fmt"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/iacrypto"
	"identity-agent-core/messagingkeys"
)

// ChildSeedBytes is the length of every seed keymath takes.
const ChildSeedBytes = 32

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func childSeed(seed []byte) error {
	if len(seed) != ChildSeedBytes {
		return fmt.Errorf("a child seed is %d bytes", ChildSeedBytes)
	}
	return nil
}

// PostQuantumNext is the post-quantum key a child seed gives and its
// commitment: the ML-DSA-65 public key as qb64 under the proposed code, and the
// next-key digest over exactly that text.
type PostQuantumNext struct {
	Verkey string `json:"verkey"`
	Digest string `json:"digest"`
}

// PostQuantumNextKey derives the post-quantum next key at a child seed.
func PostQuantumNextKey(seed []byte) (*PostQuantumNext, error) {
	if err := childSeed(seed); err != nil {
		return nil, err
	}
	pq, err := iacrypto.PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	defer zero(pq.Seed)
	return &PostQuantumNext{Verkey: pq.Verkey, Digest: pq.Digest}, nil
}

// SignMLDSA65 is the post-quantum key's signature over msg, for the key a child
// seed gives.
func SignMLDSA65(seed, msg []byte) ([]byte, error) {
	if err := childSeed(seed); err != nil {
		return nil, err
	}
	pq, err := iacrypto.PostQuantumNextKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	defer zero(pq.Seed)
	return iacrypto.SignMLDSA65FromSeed(pq.Seed, msg)
}

// MessagingKeySet is the anchor of the messaging keyset a child seed gives.
func MessagingKeySet(seed []byte) (map[string]interface{}, error) {
	if err := childSeed(seed); err != nil {
		return nil, err
	}
	k, err := messagingkeys.Derive(seed)
	if err != nil {
		return nil, err
	}
	defer zero(k.EdPriv)
	defer func() { k.XPriv = [32]byte{} }()
	return k.Anchor()
}

// NextKeyDigest is the commitment to a next key, as written in k.
func NextKeyDigest(keyQB64 string) (string, error) {
	return keri.NextDigest(keyQB64)
}

// Field is one top-level field of an event, in the order the event carries it.
type Field struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

// Event is an event read the way the engine reads it, with its digest checked.
type Event struct {
	T      string  `json:"t"`
	D      string  `json:"d"`
	I      string  `json:"i"`
	S      uint64  `json:"s"`
	P      string  `json:"p,omitempty"`
	Fields []Field `json:"fields"`
}

// ParseEvent reads an event's bytes as the engine does: well formed, the
// fields its type defines and no others, and d the digest of the bytes (and, for
// a founding, i too). A signer compares these fields to what it expects before
// it signs the same bytes.
func ParseEvent(raw []byte) (*Event, error) {
	if err := keri.ValidateEvent(raw); err != nil {
		return nil, err
	}
	ev, err := keri.ParseEvent(raw)
	if err != nil {
		return nil, err
	}
	out := &Event{T: ev.Ilk, D: ev.SAID, I: ev.Identifier, S: ev.SN, P: ev.PriorSAID}
	for _, f := range ev.Fields {
		out.Fields = append(out.Fields, Field{Name: f.Name, Value: json.RawMessage(append([]byte(nil), f.Value...))})
	}
	return out, nil
}
