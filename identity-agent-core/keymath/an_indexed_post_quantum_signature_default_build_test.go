//go:build !kerigo_pqtest

package keymath

import "testing"

// CESR has assigned no indexed post-quantum signature code, so a default build
// cannot write one, however it is asked.
func TestTheIndexedPostQuantumSignatureIsNotAvailableInADefaultBuild(t *testing.T) {
	const want = "not available in this build"
	if _, err := EncodeMLDSA65IndexedSignature(make([]byte, 3309), 1, 1); err == nil || err.Error() != want {
		t.Fatalf("want %q, got %v", want, err)
	}
	if _, err := Do("index_mldsa65_sig", []byte(`{"sig_b64":"AAAA","index":1,"ondex":1}`)); err == nil || err.Error() != want {
		t.Fatalf("Do: want %q, got %v", want, err)
	}
}
