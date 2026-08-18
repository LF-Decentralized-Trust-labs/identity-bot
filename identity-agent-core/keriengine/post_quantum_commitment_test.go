package keriengine

import (
	"encoding/json"
	"testing"

	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
)

// The default engine must honour a caller's full commitment set.
//
// It did not, and nothing noticed: the fields were plumbed as far as the Python
// driver and silently dropped here, so a stock build derived a post-quantum key,
// recorded it, and then founded an identity byte-identical to one that had never
// heard of it. The feature was live only under a non-default engine.
func TestInceptCommitsToEveryNextKeyItIsGiven(t *testing.T) {
	e := New()

	pub := iacrypto.VerkeyQB64(bytes32(1))
	next := iacrypto.VerkeyQB64(bytes32(2))

	classical, err := iacrypto.NextKeyDigest(next)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := iacrypto.PostQuantumNextKeyFromSeed(bytes64(3))
	if err != nil {
		t.Fatal(err)
	}

	res, err := e.Incept(drivers.InceptionRequest{
		PublicKey:      pub,
		NextPublicKey:  next,
		NextKeyDigests: []string{classical, pq.Digest},
		NextThreshold:  "1",
	})
	if err != nil {
		t.Fatal(err)
	}

	var event map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, res.InceptionEvent)), &event); err != nil {
		t.Fatal(err)
	}
	n, _ := event["n"].([]any)
	if len(n) != 2 {
		t.Fatalf("the identity committed to %d next key(s), want 2 — the post-quantum "+
			"commitment was dropped, so this identity can never rotate to one", len(n))
	}
	if n[0] != classical || n[1] != pq.Digest {
		t.Errorf("committed digests are not the ones supplied:\n  got  %v\n  want [%s %s]",
			n, classical, pq.Digest)
	}
	if got := event["nt"]; got != "1" {
		t.Errorf("next threshold is %v, want \"1\" — at 2 an identity whose post-quantum "+
			"commitment is unsatisfiable could never rotate at all", got)
	}
}

// Unset must reproduce the single-commitment event exactly, or every existing
// caller changes behaviour.
func TestInceptWithoutDigestsIsUnchanged(t *testing.T) {
	e := New()
	pub := iacrypto.VerkeyQB64(bytes32(1))
	next := iacrypto.VerkeyQB64(bytes32(2))

	res, err := e.Incept(drivers.InceptionRequest{PublicKey: pub, NextPublicKey: next})
	if err != nil {
		t.Fatal(err)
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, res.InceptionEvent)), &event); err != nil {
		t.Fatal(err)
	}
	if n, _ := event["n"].([]any); len(n) != 1 {
		t.Errorf("committed to %d next keys, want 1", len(n))
	}
}

func bytes32(fill byte) []byte { return fillBytes(32, fill) }
func bytes64(fill byte) []byte { return fillBytes(64, fill) }
func fillBytes(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill + byte(i)
	}
	return b
}
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
