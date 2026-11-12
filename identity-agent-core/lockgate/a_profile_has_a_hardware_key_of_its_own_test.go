package lockgate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/hkdf"

	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// A profile's gate copy, device-held copy and seed are wrapped under the hardware
// key named for that profile, and a second profile on the same device gets a
// different one (ADR-074 section 3). The case that fails if lockgate wrote under
// the device-wide key: the envelopes name no key.
func TestAProfilesGateKeyAndSeedAreWrappedUnderItsOwnHardwareKey(t *testing.T) {
	seedwraptest.ThisMachineHoldsAKeyPerProfile(t)
	t.Cleanup(Install())
	mk := func(id string) (*Session, string) {
		dir := t.TempDir()
		s := NewSession(OpenProfile(dir, id), &Gate{Mode: ModePhone})
		t.Cleanup(func() { drop(dir) })
		if err := s.Found(); err != nil {
			t.Fatal(err)
		}
		if err := secureenclave.StoreIdentityRootSeed(dir, bytes.Repeat([]byte{7}, 32)); err != nil {
			t.Fatal(err)
		}
		return s, dir
	}
	_, dirA := mk("profile-a")
	_, dirB := mk("profile-b")

	keyOf := func(dir, file string) string {
		raw, err := os.ReadFile(filepath.Join(dir, "gate", file))
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			WrapKey string `json:"wrap_key"`
		}
		_ = json.Unmarshal(raw, &env)
		return env.WrapKey
	}
	seedKeyOf := func(dir string) string {
		raw, _ := os.ReadFile(filepath.Join(dir, "secureenclave", "root_seed.key"))
		var env struct {
			Key string `json:"key"`
		}
		_ = json.Unmarshal(raw, &env)
		return env.Key
	}
	wantA := secureenclave.ProfileKeyName("test-seed-key", "profile-a")
	wantB := secureenclave.ProfileKeyName("test-seed-key", "profile-b")
	for _, f := range []string{gateCopyFile, deviceHeldFile} {
		if got := keyOf(dirA, f); got != wantA {
			t.Fatalf("%s of profile A is under %q, want %q", f, got, wantA)
		}
		if got := keyOf(dirB, f); got != wantB {
			t.Fatalf("%s of profile B is under %q, want %q", f, got, wantB)
		}
	}
	if got := seedKeyOf(dirA); got != wantA {
		t.Fatalf("profile A's seed is under %q, want %q", got, wantA)
	}
	// And all of it still opens: a killed phone reopens, nothing needs the old key.
	drop(dirA)
	s2 := NewSession(OpenProfile(dirA, "profile-a"), &Gate{Mode: ModePhone})
	if err := s2.Reopen(); err != nil {
		t.Fatal(err)
	}
	if got, err := secureenclave.LoadRootSeed(dirA); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("seed after reopen: %v", err)
	}
}

// The core gives the controller key's TPM authorization value as
// HKDF-SHA256(GK, "tpm-auth"), and a locked profile gives none.
func TestTheGateDerivesTheTPMAuthorizationFromGKAndRefusesWhenLocked(t *testing.T) {
	r := newRig(t, ModePhone)
	gk, err := r.s.P.Create()
	if err != nil {
		t.Fatal(err)
	}
	hold(r.dir, r.s.P.ID(), gk)
	d := sealer{dataDir: r.dir}.DeriveKey
	got, err := d("tpm-auth", 32)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, gk, nil, []byte("tpm-auth")), want); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the authorization value is not HKDF(GK, \"tpm-auth\")")
	}
	if other, _ := d("other-purpose", 32); bytes.Equal(other, got) {
		t.Fatal("two purposes share a key")
	}
	drop(r.dir) // locked: no GK in memory
	if _, err := (sealer{dataDir: r.dir}).DeriveKey("tpm-auth", 32); err == nil {
		t.Fatal("a locked profile derived a key")
	}
}

// gate.json is a plain file that same-user code can edit. Editing the profile
// name in it must not point a profile at another profile's hardware key: the
// name comes from the open gate in memory, never from the file. Before this,
// a profile whose record was edited to say "profile-b" was named profile-b.
func TestAnEditedGateRecordCannotPointAProfileAtAnotherProfilesKey(t *testing.T) {
	seedwraptest.ThisMachineHoldsAKeyPerProfile(t)
	t.Cleanup(Install())
	dir := t.TempDir()
	s := NewSession(OpenProfile(dir, "profile-a"), &Gate{Mode: ModePhone})
	t.Cleanup(func() { drop(dir) })
	if err := s.Found(); err != nil {
		t.Fatal(err)
	}
	edit := func() {
		raw, err := os.ReadFile(filepath.Join(dir, "gate", recordFile))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["profile"] = "profile-b"
		out, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "gate", recordFile), out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	edit()
	if got := profileOfDataDir(dir); got != "profile-a" {
		t.Fatalf("open, with the record edited, the profile is %q, want profile-a", got)
	}
	// What gets stored is under profile A's key, not B's.
	if err := secureenclave.StoreIdentityRootSeed(dir, bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "secureenclave", "root_seed.key"))
	var env struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(raw, &env)
	if want := secureenclave.ProfileKeyName("test-seed-key", "profile-a"); env.Key != want {
		t.Fatalf("the seed is under %q, want %q", env.Key, want)
	}
	// Locked, the file is still not believed.
	drop(dir)
	if got := profileOfDataDir(dir); got != "" {
		t.Fatalf("locked, the profile is %q from the file, want none", got)
	}
	// And a locked profile takes no write at all.
	if err := secureenclave.StoreIdentityRootSeed(dir, bytes.Repeat([]byte{9}, 32)); err == nil {
		t.Fatal("a locked profile took a seed")
	}
}
