package server

import "testing"

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
