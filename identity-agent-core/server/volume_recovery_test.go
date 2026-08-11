package server

import (
	"os"
	"path/filepath"
	"testing"
)

// Adoption is the first moment there is an owner to give a way back in to, so
// it is where recovery gets arranged. What matters is that it happens, and that
// failing to arrange it never costs a valid adoption.

// Most agents run on a machine their user owns. There is no encrypted volume,
// nothing to recover, and nothing to arrange — and that must not read as a
// failure.
func TestNoEncryptedVolumeIsNotAFailure(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "no-such-device")
	if err := addVolumeRecoveryVia(absent, []string{"a"}); err != nil {
		t.Fatalf("an agent with no encrypted volume reported a problem: %v", err)
	}
}

// A volume with no owner to seal to is a real problem, because it is a volume
// whose data cannot be recovered.
func TestAVolumeWithNoOwnerKeysIsRefused(t *testing.T) {
	present := filepath.Join(t.TempDir(), "device")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := addVolumeRecoveryVia(present, nil); err == nil {
		t.Fatal("a volume was left with no way back in and no complaint")
	}
}

// The one that protects an adoption. An instance that is adopted and cannot
// arrange recovery has a problem to fix later; an instance left delegated and
// ownerless has no way forward at all.
func TestAdoptionSurvivesRecoveryFailing(t *testing.T) {
	s := &CoreServer{
		volumeRecovery: func([]string) error {
			return os.ErrPermission
		},
	}
	// The handler logs and continues; the call itself returns the failure so
	// the caller can decide. What must not happen is a panic or a nil-deref
	// that takes the adoption down with it.
	if err := s.addVolumeRecovery([]string{"key"}); err == nil {
		t.Fatal("a failure was swallowed rather than reported to the caller")
	}
}

func TestRecoveryIsAttemptedWithTheOwnersKeys(t *testing.T) {
	var got []string
	s := &CoreServer{
		volumeRecovery: func(keys []string) error {
			got = keys
			return nil
		},
	}
	if err := s.addVolumeRecovery([]string{"owner-one", "owner-two"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "owner-one" || got[1] != "owner-two" {
		t.Fatalf("the owners' keys did not reach the volume: %v", got)
	}
}
