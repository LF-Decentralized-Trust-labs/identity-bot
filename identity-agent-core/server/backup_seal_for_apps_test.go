package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

func fileWithSlotFor(t *testing.T, s *CoreServer, app string, epoch uint32) (fid, bek, slot []byte) {
	t.Helper()
	pub, err := s.backupSealKeyOf(app, epoch)
	if err != nil {
		t.Fatal(err)
	}
	fid, bek = make([]byte, backup.FileIDLen), make([]byte, backup.BEKLen)
	rand.Read(fid)
	rand.Read(bek)
	slot, err = backup.SealSlotForFile(pub, bek, fid)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// The key an app's backups are sealed to is the one derived from the identity's own seed, per app and epoch.
func TestTheCoreGivesTheAppsBackupKeyAndItIsDerivedFromTheIdentitysSeed(t *testing.T) {
	s := newControllerWorld(t).s
	seed, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.backupSealKeyOf("EAppOne", 2)
	if err != nil {
		t.Fatal(err)
	}
	_, want, _ := backup.DeriveAppSealKeypair(seed, "EAppOne", 2)
	if !bytes.Equal(got, want) {
		t.Fatal("not the key derived from the identity's seed")
	}
	if other, _ := s.backupSealKeyOf("EAppOne", 1); bytes.Equal(other, got) {
		t.Fatal("two epochs gave one key")
	}
}

// With no root seed of its own, the core gives no key and makes no seed.
func TestAnIdentityWithNoSeedHereGetsNoBackupKeyAndLeavesNoSeedBehind(t *testing.T) {
	s := newControllerWorld(t).s
	if err := os.Remove(filepath.Join(s.DataDir, "secureenclave", "root_seed.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.backupSealKeyOf("EAppOne", 1); !errors.Is(err, ErrNoBackupSeed) {
		t.Fatalf("a key with no seed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.DataDir, "secureenclave", "root_seed.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("asking for a backup key left a seed behind")
	}
}

// A seed that is not the identity's (the key is held on another device) gives no key.
func TestAKeyHeldElsewhereGetsNoBackupKey(t *testing.T) {
	e := keyElsewhere(t)
	if _, err := e.s.backupSealKeyOf("EAppOne", 1); !errors.Is(err, ErrNoBackupSeed) {
		t.Fatalf("a key held elsewhere: %v", err)
	}
	if e.s.isOwnBackupSealKey(make([]byte, 32), nil) != true {
		t.Fatal("with no usable seed, the check must answer \"ours\" so it fails closed")
	}
}

// A slot opens under the app's key at its epoch or an earlier one, never another app's, and what comes out is only a
// slot for the key the caller names.
func TestTheCoreOpensAnAppsSlotsAndReturnsOnlySealedResults(t *testing.T) {
	s := newControllerWorld(t).s
	fid, bek, slot := fileWithSlotFor(t, s, "EAppOne", 1)

	if i, ok, err := s.backupSlotOpens("EAppOne", 2, fid, [][]byte{slot}); err != nil || !ok || i != 0 {
		t.Fatalf("an earlier epoch's slot at epoch 2: %d %v %v", i, ok, err)
	}
	if _, ok, err := s.backupSlotOpens("EAppTwo", 2, fid, [][]byte{slot}); err != nil || ok {
		t.Fatal("another app's key opened the slot")
	}
	other := append([]byte{}, fid...)
	other[0] ^= 1
	if _, ok, _ := s.backupSlotOpens("EAppOne", 2, other, [][]byte{slot}); ok {
		t.Fatal("a slot opened for another file")
	}

	// re-slot: the new slot opens under the destination's key, to the same content key
	moved, err := s.resealBackupSlot("EAppOne", 1, fid, [][]byte{slot}, "EAppTwo", 1)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := secureenclave.LoadRootSeed(s.DataDir)
	toPriv, _, _ := backup.DeriveAppSealKeypair(seed, "EAppTwo", 1)
	if got, err := backup.UnsealBEKForFile(toPriv, moved[:32], moved[44:], moved[32:44], fid); err != nil || !bytes.Equal(got, bek) {
		t.Fatalf("the moved slot does not hold the content key: %v", err)
	}

	// open reply: sealed to a restore key, for one request
	restorePriv, restorePub := make([]byte, 32), []byte(nil)
	rand.Read(restorePriv)
	restorePub, _ = backup.PublicFromPrivate(restorePriv)
	digest := bytes.Repeat([]byte{9}, 32)
	reply, i, err := s.sealBackupOpenReply("EAppOne", 1, fid, [][]byte{slot}, restorePub, digest)
	if err != nil || i != 0 {
		t.Fatalf("the open reply: %d %v", i, err)
	}
	if bytes.Contains(reply, bek) {
		t.Fatal("the content key is in the reply in the clear")
	}
	if _, err := s.resealBackupSlot("EAppOne", 1, fid, [][]byte{slot[:40]}, "EAppTwo", 1); err == nil {
		t.Fatal("a short slot was opened")
	}
}

// A restore key that is one of ours is told so, whichever epoch of whichever listed app it is.
func TestARestoreKeyThatIsOneOfOursIsRecognised(t *testing.T) {
	s := newControllerWorld(t).s
	seed, _ := secureenclave.LoadRootSeed(s.DataDir)
	_, person, err := backup.DeriveSealKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}
	_, appOld, err := backup.DeriveAppSealKeypair(seed, "EAppOne", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, appNext, err := backup.DeriveAppSealKeypair(seed, "EAppOne", 3)
	if err != nil {
		t.Fatal(err)
	}
	epochs := map[string]uint32{"EAppOne": 2}
	if !s.isOwnBackupSealKey(person, epochs) || !s.isOwnBackupSealKey(appOld, epochs) {
		t.Fatal("our own key was not recognised")
	}
	if s.isOwnBackupSealKey(appNext, epochs) {
		t.Fatal("an epoch the app is not at yet was recognised")
	}
	fresh := make([]byte, 32)
	rand.Read(fresh)
	if s.isOwnBackupSealKey(fresh, epochs) {
		t.Fatal("a stranger's key was taken for ours")
	}
}

// The destination of a move is an app and an epoch the core derives a key for, never a key the caller names: the move's result opens
// under that app's key and no other, and the call has no way to be given one.
func TestAMoveGoesOnlyToAKeyTheCoreDerives(t *testing.T) {
	s := newControllerWorld(t).s
	fid, bek, slot := fileWithSlotFor(t, s, "EAppOne", 1)
	seed, _ := secureenclave.LoadRootSeed(s.DataDir)
	moved, err := s.resealBackupSlot("EAppOne", 1, fid, [][]byte{slot}, "EAppThree", 2)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, _ := backup.DeriveAppSealKeypair(seed, "EAppThree", 2)
	if got, err := backup.UnsealBEKForFile(priv, moved[:32], moved[44:], moved[32:44], fid); err != nil || !bytes.Equal(got, bek) {
		t.Fatalf("the moved slot does not open under the key the core derived for the destination: %v", err)
	}
	for _, other := range []struct {
		app   string
		epoch uint32
	}{{"EAppThree", 1}, {"EAppOne", 2}, {"EAppTwo", 2}} {
		p, _, _ := backup.DeriveAppSealKeypair(seed, other.app, other.epoch)
		if _, err := backup.UnsealBEKForFile(p, moved[:32], moved[44:], moved[32:44], fid); err == nil {
			t.Fatalf("the moved slot opens under %s at epoch %d, which was not asked for", other.app, other.epoch)
		}
	}
	for _, bad := range []uint32{0, MaxBackupEpoch + 1, ^uint32(0)} {
		if _, err := s.resealBackupSlot("EAppOne", 1, fid, [][]byte{slot}, "EAppTwo", bad); !errors.Is(err, ErrBackupAsked) {
			t.Fatalf("a destination epoch of %d: %v", bad, err)
		}
	}
}

// What is asked for is bounded: an epoch past the cap is refused at once and not walked, as is a count of slots past 255, an
// epoch of 0 and a file identifier of the wrong length.
func TestBackupRequestsAreBounded(t *testing.T) {
	s := newControllerWorld(t).s
	fid, _, slot := fileWithSlotFor(t, s, "EAppOne", 1)
	start := time.Now()
	for _, e := range []uint32{0, MaxBackupEpoch + 1, ^uint32(0)} {
		if _, _, err := s.backupSlotOpens("EAppOne", e, fid, [][]byte{slot}); !errors.Is(err, ErrBackupAsked) {
			t.Fatalf("epoch %d: %v", e, err)
		}
		if _, err := s.backupSealKeyOf("EAppOne", e); !errors.Is(err, ErrBackupAsked) {
			t.Fatalf("the key of epoch %d: %v", e, err)
		}
	}
	many := make([][]byte, 256)
	for i := range many {
		many[i] = slot
	}
	if _, _, err := s.backupSlotOpens("EAppOne", 1, fid, many); !errors.Is(err, ErrBackupAsked) {
		t.Fatalf("256 slots: %v", err)
	}
	if _, _, err := s.backupSlotOpens("EAppOne", 1, fid[:8], [][]byte{slot}); !errors.Is(err, ErrBackupAsked) {
		t.Fatalf("a short file id: %v", err)
	}
	if !s.isOwnBackupSealKey(make([]byte, 32), map[string]uint32{"EAppOne": ^uint32(0)}) {
		t.Fatal("an epoch past the cap was walked and answered \"not ours\"")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("refusing the bounds took %v", d)
	}
}

// A reply is never sealed to a key this Identity Agent holds, and a malformed restore key or digest is refused.
func TestAnOpenReplyIsRefusedToAKeyTheCoreHoldsOrAMalformedOne(t *testing.T) {
	s := newControllerWorld(t).s
	fid, _, slot := fileWithSlotFor(t, s, "EAppOne", 1)
	seed, _ := secureenclave.LoadRootSeed(s.DataDir)
	_, person, _ := backup.DeriveSealKeypair(seed)
	_, ownApp, _ := backup.DeriveAppSealKeypair(seed, "EAppOne", 1)
	digest := bytes.Repeat([]byte{4}, 32)
	stranger := make([]byte, 32)
	rand.Read(stranger[:])
	priv := stranger
	strangerPub, _ := backup.PublicFromPrivate(priv)
	for name, key := range map[string][]byte{"the person's key": person, "the app's own key": ownApp, "a short key": strangerPub[:31]} {
		if _, _, err := s.sealBackupOpenReply("EAppOne", 1, fid, [][]byte{slot}, key, digest); err == nil {
			t.Fatalf("a reply was sealed to %s", name)
		}
	}
	if _, _, err := s.sealBackupOpenReply("EAppOne", 1, fid, [][]byte{slot}, strangerPub, digest[:31]); err == nil {
		t.Fatal("a short digest was accepted")
	}
	if _, _, err := s.sealBackupOpenReply("EAppOne", 1, fid, [][]byte{slot}, strangerPub, digest); err != nil {
		t.Fatalf("a stranger's restore key was refused: %v", err)
	}
	// epoch 0 and a key for epoch 0
	if _, err := s.backupSealKeyOf("EAppOne", 0); err == nil {
		t.Fatal("epoch 0 was given a key")
	}
}

// Asking after the seed file has vanished makes no seed: the check reads the seed it loaded, once.
func TestAVanishedSeedLeavesNoSeedBehind(t *testing.T) {
	s := newControllerWorld(t).s
	path := filepath.Join(s.DataDir, "secureenclave", "root_seed.key")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.backupSealKeyOf("EAppOne", 1); !errors.Is(err, ErrNoBackupSeed) {
			t.Fatalf("with no seed: %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a seed was made")
		}
	}
}
