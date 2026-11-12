package lockgate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// A profile whose gate directory was deleted is locked or broken after a
// restart, never "made before locking existed".
func TestADeletedGateDoesNotReopenTheIdentityOnRestart(t *testing.T) {
	r := newRig(t, ModePhone)
	if err := r.s.Found(); err != nil {
		t.Fatal(err)
	}
	r.storeSeed()
	if err := os.RemoveAll(filepath.Join(r.dir, "gate")); err != nil {
		t.Fatal(err)
	}
	drop(r.dir) // the restart
	p := OpenProfile(r.dir, "profile-a")
	if !p.Gated() {
		t.Fatal("a seed sealed under a gate and no gate record was taken for an ungated profile")
	}
	s := NewSession(p, &Gate{Mode: ModePhone})
	_ = s.Reopen()
	if s.State() != StateLocked {
		t.Fatalf("state after the gate was deleted: %s", s.State())
	}
	if c := p.Class(); c != ClassBroken {
		t.Fatalf("class %s, want %s", c, ClassBroken)
	}
	if _, err := secureenclave.LoadRootSeed(r.dir); err == nil {
		t.Fatal("the seed was read with the gate gone")
	}
	if _, err := p.Create(); err == nil {
		t.Fatal("a new gate was made over a seed sealed under the old one")
	}
}

func TestACorruptGateRecordIsReportedAsUnreadableNotAsNoGate(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	if err := os.WriteFile(filepath.Join(r.dir, "gate", "gate.json"), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := r.s.P.Class(); c != ClassBroken {
		t.Fatalf("class %s", c)
	}
}

func TestAProfileWithNoGateAndNoSealedSeedIsClassNone(t *testing.T) {
	r := newRig(t, ModePhone)
	if c := r.s.P.Class(); c != ClassNone {
		t.Fatalf("class %s", c)
	}
}

// The class reported matches what protects the recovery phrase and the backup
// key: secret_bound only while both sit under the gate key.
func TestSecretBoundIsReportedOnlyWhileEverythingHeldIsUnderTheGate(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	r.storeSeed()
	if err := r.s.ChangeSecret("", "a long enough secret"); err != nil {
		t.Fatal(err)
	}
	if c := r.s.P.Class(); c != ClassSecretBound {
		t.Fatalf("nothing held outside the gate: class %s", c)
	}
	phrase := []byte("abandon ability able about above absent absorb abstract absurd abuse access accident")
	if err := secureenclave.StoreRecoveryPhrase(r.dir, phrase); err != nil {
		t.Fatal(err)
	}
	cs, err := backup.NewCredentialStore(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Save("c1", backup.RemoteCredentialSecrets{OAuthRefreshToken: "1//refresh"}); err != nil {
		t.Fatal(err)
	}
	if c := r.s.P.Class(); c != ClassSecretBound {
		t.Fatalf("phrase and backup key are under the gate: class %s", c)
	}
	// A phrase held under the wrapper alone: same-user code reaches the seed.
	pf := filepath.Join(r.dir, "secureenclave", "recovery_phrase.key")
	raw, _ := os.ReadFile(pf)
	if err := os.WriteFile(pf, []byte(strings.Replace(string(raw), `"gate":"gk-aes256gcm-v1"`, `"gate":""`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := r.s.P.Class(); c != ClassAppOnly {
		t.Fatalf("a phrase without the gate layer is held: class %s, want app_only", c)
	}
	os.WriteFile(pf, raw, 0o600)
	kf := filepath.Join(r.dir, "backup", "credentials_master.key")
	kraw, _ := os.ReadFile(kf)
	os.WriteFile(kf, []byte(strings.Replace(string(kraw), "+gate", "", 1)), 0o600)
	if c := r.s.P.Class(); c != ClassAppOnly {
		t.Fatalf("a backup key without the gate layer is held: class %s, want app_only", c)
	}
}

func TestALogOutSweepsAStrayTempCopyOfTheGateKey(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	stray := filepath.Join(r.dir, "gate", "device-held.key.tmp-12345")
	if err := os.WriteFile(stray, []byte("a copy of GK"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.s.Lock(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatalf("the stray copy survived a log-out: %v", err)
	}
}

// Skipping WriteDeviceHeld in Unlock must fail a test.
func TestUnlockLeavesTheDeviceHeldCopyAndItReopensAfterARestart(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	if err := r.s.Lock(); err != nil {
		t.Fatal(err)
	}
	if r.s.P.LoggedIn() {
		t.Fatal("the device-held copy survived a log-out")
	}
	if err := r.s.Unlock(r.result(80), ""); err != nil {
		t.Fatal(err)
	}
	if !r.s.P.LoggedIn() {
		t.Fatal("Unlock did not write the device-held copy")
	}
	drop(r.dir)
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Mode: ModePhone})
	if err := s2.Reopen(); err != nil || s2.State() != StateOpen {
		t.Fatalf("a restart after a log-in must reopen: %v %s", err, s2.State())
	}
}

// A core that must be gated and could not make its gate stores nothing, rather
// than leaving a seed in an ungated profile for good.
func TestAProfileThatMustBeGatedRefusesASeedWhileItHasNoGate(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	t.Cleanup(Install())
	dir := t.TempDir()
	Require(dir)
	err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32))
	if err == nil || !strings.Contains(err.Error(), "gate") {
		t.Fatalf("a seed was stored with no gate: %v", err)
	}
	if err := secureenclave.StoreRecoveryPhrase(dir, []byte("abandon ability able about above absent")); err == nil {
		t.Fatal("a recovery phrase was stored with no gate")
	}
	s := NewSession(OpenProfile(dir, "profile-a"), &Gate{Mode: ModePhone})
	t.Cleanup(func() { drop(dir) })
	if err := s.Found(); err != nil {
		t.Fatal(err)
	}
	if err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32)); err != nil {
		t.Fatalf("once gated it stores: %v", err)
	}
}

// Android: the app registers its keystore host after the core started, so
// founding the gate failed at start. The first seed stored retries it, instead of
// refusing until the next start.
func TestAGateThatCouldNotBeFoundedAtStartIsFoundedWhenTheHostIsRegistered(t *testing.T) {
	seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, false)
	r := secureenclave.UseFoundingVerdict(func() secureenclave.FoundingVerdict {
		return secureenclave.FoundingVerdict{Permitted: true, Platform: "test"}
	})
	t.Cleanup(r)
	t.Cleanup(Install())
	dir := t.TempDir()
	s := NewSession(OpenProfile(dir, "profile-a"), &Gate{Mode: ModePhone})
	t.Cleanup(func() { drop(dir) })
	RequireFounding(dir, s)
	if err := s.Found(); !errors.Is(err, ErrHardwareLayerMissing) {
		t.Fatalf("founding with no host should fail, got %v", err)
	}
	if err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32)); err == nil {
		t.Fatal("a seed was stored with no host and no gate")
	}
	if s.P.Gated() {
		t.Fatal("gated without a host")
	}

	// The app registers its host.
	restore := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: true})
	t.Cleanup(restore)
	if err := secureenclave.StoreIdentityRootSeed(dir, make([]byte, 32)); err != nil {
		t.Fatalf("the store did not retry the founding: %v", err)
	}
	if !s.P.Gated() || s.State() != StateOpen {
		t.Fatalf("the retry did not leave an open gated profile: %s", s.State())
	}
	if !secureenclave.TheStoredSeedIsUnderAGate(dir) {
		t.Fatal("the seed was stored outside the gate")
	}
}
