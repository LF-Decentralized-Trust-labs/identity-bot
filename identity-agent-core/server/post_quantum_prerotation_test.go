package server

import (
	"testing"

	"identity-agent-core/iacrypto"
)

// The commitment is best-effort, so the response has to report what actually
// happened rather than that an attempt was made. A screen downstream tells
// somebody their identity is ready for a post-quantum key on the strength of
// this field; if it were hardcoded true, it would say so on an agent that never
// made the commitment.
func TestPostQuantumPreRotationReportsHonestly(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}

	// No root seed in an empty data directory, so nothing can be derived.
	digests, pq := s.postQuantumPreRotation("DAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g")
	if pq != nil {
		t.Error("reported a commitment with no root seed to derive one from")
	}
	if digests != nil {
		t.Errorf("returned %d digests with no root seed; the identity must be founded "+
			"exactly as it was before", len(digests))
	}

	// And the empty next key is refused rather than committed to.
	digests, pq = s.postQuantumPreRotation("")
	if pq != nil || digests != nil {
		t.Error("committed to something for an empty next key")
	}
}

// Each generation must commit to a DIFFERENT post-quantum key.
//
// Committing the same one at every rotation would put a single key behind every
// event's commitment, so revealing it once — whenever that becomes possible —
// would spend it for the whole chain instead of for one rotation.
func TestEachGenerationCommitsToADifferentKey(t *testing.T) {
	seedA := make([]byte, 64)
	for i := range seedA {
		seedA[i] = byte(i)
	}
	// Derivation is exercised directly, because the server path needs a root
	// seed on disk and what is under test is that generation changes the key.
	first, err := iacrypto.PostQuantumNextKeyFromSeed(seedA)
	if err != nil {
		t.Fatal(err)
	}
	seedB := make([]byte, 64)
	copy(seedB, seedA)
	seedB[0] ^= 0xFF // a different branch yields different seed bytes
	second, err := iacrypto.PostQuantumNextKeyFromSeed(seedB)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Error("two generations produced the same commitment; revealing one would " +
			"spend every event's commitment at once")
	}
}
