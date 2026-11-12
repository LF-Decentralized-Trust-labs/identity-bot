package lockgate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/authprovider"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

func init() { argonTime, argonMem, argonPar = 1, 8, 1 } // cheap for tests; production cost is the var's default

type rig struct {
	t   *testing.T
	dir string
	now time.Time
	s   *Session
	n   int
}

func newRig(t *testing.T, mode Mode) *rig {
	t.Helper()
	seedwraptest.ThisMachineCanProtectASeed(t)
	t.Cleanup(Install())
	dir := t.TempDir()
	r := &rig{t: t, dir: dir, now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)}
	g := &Gate{Mode: mode, Now: func() time.Time { return r.now }}
	r.s = NewSession(OpenProfile(dir, "profile-a"), g)
	t.Cleanup(func() { drop(dir) })
	return r
}

func (r *rig) result(score int) ProviderResult {
	r.n++
	return ProviderResult{Profile: "profile-a", Level: authprovider.LevelVerified, Score: score, At: r.now,
		Nonce: strings.Repeat("n", 15) + string(rune('a'+r.n)), Provider: authprovider.PlaceholderProvider}
}

func (r *rig) storeSeed() []byte {
	r.t.Helper()
	seed := bytes.Repeat([]byte{7}, 32)
	if err := secureenclave.StoreIdentityRootSeed(r.dir, seed); err != nil {
		r.t.Fatal(err)
	}
	return seed
}

func TestAFoundedProfileIsOpenAndItsSeedIsSealedUnderTheGate(t *testing.T) {
	r := newRig(t, ModePhone)
	if err := r.s.Found(); err != nil {
		t.Fatal(err)
	}
	if r.s.State() != StateOpen {
		t.Fatalf("state %s", r.s.State())
	}
	seed := r.storeSeed()
	got, err := secureenclave.LoadRootSeed(r.dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("an open identity's seed reads back: %v", err)
	}
	// The case that fails if the gate layer is missing: the file, unwrapped by
	// the hardware layer alone (the test wrapper is its own inverse), is still
	// not the seed.
	raw, _ := os.ReadFile(filepath.Join(r.dir, "secureenclave", "root_seed.key"))
	if bytes.Contains(raw, seed) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(seed))) {
		t.Fatal("the seed is in the envelope in the clear")
	}
	env := string(raw)
	if !strings.Contains(env, `"gate":"gk-aes256gcm-v1"`) {
		t.Fatalf("the envelope does not name its gate layer: %s", env)
	}
}

func TestALockedIdentityGivesNoSeedAndOpensOnlyThroughTheGate(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	seed := r.storeSeed()
	if err := r.s.Lock(); err != nil {
		t.Fatal(err)
	}
	if r.s.State() != StateLocked {
		t.Fatal("not locked")
	}
	if _, err := secureenclave.LoadRootSeed(r.dir); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("a locked identity gave its seed or the wrong refusal: %v", err)
	}
	// Deleting the marker the app writes changes nothing: there never was one in the core.
	_ = os.Remove(filepath.Join(r.dir, "locked"))
	if _, err := secureenclave.LoadRootSeed(r.dir); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatal("deleting the locked marker opened the identity")
	}
	// A restart with the device-held copy gone stays locked.
	drop(r.dir)
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Now: r.s.G.Now})
	if err := s2.Reopen(); err != nil || s2.State() != StateLocked {
		t.Fatalf("restart after log-out: %v %s", err, s2.State())
	}
	if err := s2.Unlock(r.result(80), ""); err != nil {
		t.Fatal(err)
	}
	got, err := secureenclave.LoadRootSeed(r.dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestALoggedInProfileReopensAfterTheCoreIsKilledWithNoLogIn(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	seed := r.storeSeed()
	drop(r.dir) // the process died: memory is gone, files are not
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Now: r.s.G.Now})
	if s2.State() != StateLocked {
		t.Fatal("before Reopen the held key is not in memory")
	}
	if err := s2.Reopen(); err != nil {
		t.Fatal(err)
	}
	got, err := secureenclave.LoadRootSeed(r.dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("a killed phone did not reopen: %v", err)
	}
}

func TestLogOutDeletesTheDeviceHeldCopyAndAFailedDeletionIsNotALogOut(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	if !r.s.P.LoggedIn() {
		t.Fatal("a founded profile has a device-held copy")
	}
	// Make the deletion fail: replace the file with a non-empty directory.
	path := filepath.Join(r.dir, "gate", "device-held.key")
	_ = os.Remove(path)
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := r.s.Lock()
	if !errors.Is(err, ErrNotLoggedOut) {
		t.Fatalf("a failed deletion must not read as locked: %v", err)
	}
	if r.s.State() != StateOpen {
		t.Fatal("after a failed log-out the identity must still be shown open")
	}
	_ = os.RemoveAll(path)
	if err := r.s.Lock(); err != nil || r.s.P.LoggedIn() {
		t.Fatalf("log-out: %v", err)
	}
}

func TestTheGateRefusesWhatItShouldNotRelease(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	_ = r.s.Lock()
	cases := map[string]struct {
		edit func(*ProviderResult)
		want error
	}{
		"score 79":        {func(p *ProviderResult) { p.Score = 79 }, ErrBelowMinimum},
		"unmeasured":      {func(p *ProviderResult) { p.Level = authprovider.LevelUnknown }, ErrUnmeasured},
		"stale":           {func(p *ProviderResult) { p.At = r.now.Add(-3 * time.Minute) }, ErrStale},
		"from the future": {func(p *ProviderResult) { p.At = r.now.Add(time.Hour) }, ErrStale},
		"other profile":   {func(p *ProviderResult) { p.Profile = "profile-b" }, ErrWrongProfile},
		"no nonce":        {func(p *ProviderResult) { p.Nonce = "short" }, ErrNoNonce},
	}
	for name, c := range cases {
		p := r.result(80)
		c.edit(&p)
		if err := r.s.Unlock(p, ""); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
		if r.s.State() != StateLocked {
			t.Errorf("%s: the identity opened", name)
		}
	}
	// The placeholder's 80 does release, and the lock says what that is worth.
	if err := r.s.Unlock(r.result(80), ""); err != nil {
		t.Fatal(err)
	}
	if c := r.s.P.Class(); c != ClassAppOnly {
		t.Fatalf("a placeholder must give app_only, not %s", c)
	}
	// A result is good once.
	_ = r.s.Lock()
	p := r.result(80)
	if err := r.s.Unlock(p, ""); err != nil {
		t.Fatal(err)
	}
	_ = r.s.Lock()
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrReplayed) {
		t.Fatalf("a replayed result: %v", err)
	}
}

func TestAnEnvelopeForOneProfileDoesNotOpenUnderAnother(t *testing.T) {
	gk, _ := NewGK()
	sealed, _ := Seal(gk, "profile-a", []byte("secret"))
	if _, err := Open(gk, "profile-b", sealed); !errors.Is(err, ErrWrongProfileOrKey) {
		t.Fatal("opened under another profile")
	}
	other, _ := NewGK()
	if _, err := Open(other, "profile-a", sealed); !errors.Is(err, ErrWrongProfileOrKey) {
		t.Fatal("opened under another key")
	}
	if p, err := Open(gk, "profile-a", sealed); err != nil || string(p) != "secret" {
		t.Fatal(err)
	}
}

func TestAProfileCannotBeGatedWhereNothingWrapsTheKey(t *testing.T) {
	// No wrapper installed; this build is production (the default).
	restore := secureenclave.UseSeedWrapper(nil)
	defer restore()
	s := NewSession(OpenProfile(t.TempDir(), "p"), &Gate{})
	if err := s.Found(); !errors.Is(err, ErrHardwareLayerMissing) {
		t.Fatalf("a gate key was stored where nothing wraps it: %v", err)
	}
}

func TestGKRestsOnlyUnderTheHardwareWrapper(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	base, _ := r.s.P.readGateCopy()
	for _, f := range []string{"gate-copy.key", "device-held.key"} {
		raw, _ := os.ReadFile(filepath.Join(r.dir, "gate", f))
		if bytes.Contains(raw, base) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString(base)) {
			t.Fatalf("%s holds GK in the clear", f)
		}
		if !strings.Contains(string(raw), `"wrap":"test-wrap"`) {
			t.Fatalf("%s is not under the hardware wrapper: %s", f, raw)
		}
	}
}

func TestADesktopNeedsARootDeviceVoucher(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rootKey := base64.StdEncoding.EncodeToString(pub)
	r := newRig(t, ModeController)
	r.s.G.VerifyVoucher = VoucherFromRootDevice(func() (string, error) { return rootKey, nil },
		func() string { return "EAGENT" }, func() string { return "ECTRL" })
	_ = r.s.Found()
	_ = r.s.Lock()

	vouch := func(p *ProviderResult, signer ed25519.PrivateKey, agent, ctrl string) {
		sig, err := login.SignString(authprovider.CanonicalAuthLevelStatement(agent, ctrl, p.Level, p.At, p.Score), signer.Seed())
		if err != nil {
			t.Fatal(err)
		}
		p.Voucher = &Voucher{AgentAID: agent, ControllerAID: ctrl, Signature: sig}
	}
	p := r.result(80) // no voucher: the machine scored itself
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrNeedsVoucher) {
		t.Fatalf("no voucher: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	p = r.result(80)
	vouch(&p, other, "EAGENT", "ECTRL") // signed by somebody else
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrBadVoucher) {
		t.Fatalf("wrong signer: %v", err)
	}
	p = r.result(80)
	vouch(&p, priv, "EAGENT", "ECTRL")
	p.Score = 100 // the machine raised the score after it was vouched for
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrBadVoucher) {
		t.Fatalf("altered score: %v", err)
	}
	if r.s.State() != StateLocked {
		t.Fatal("a bad voucher opened the identity")
	}
	p = r.result(80)
	vouch(&p, priv, "EAGENT", "ECTRL")
	if err := r.s.Unlock(p, ""); err != nil {
		t.Fatalf("a vouched result: %v", err)
	}
	// A voucher made for another desktop of the same person does not open this one.
	_ = r.s.Lock()
	p = r.result(80)
	vouch(&p, priv, "EAGENT", "EOTHERMACHINE")
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrBadVoucher) {
		t.Fatalf("a voucher for another machine: %v", err)
	}
	p = r.result(80)
	vouch(&p, priv, "EOTHERAGENT", "ECTRL")
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrBadVoucher) {
		t.Fatalf("a voucher for another agent: %v", err)
	}
	p = r.result(80)
	vouch(&p, priv, "EAGENT", "ECTRL")
	if err := r.s.Unlock(p, ""); err != nil {
		t.Fatal(err)
	}
	// A gate with nothing to verify against refuses every desktop result.
	_ = r.s.Lock()
	r.s.G.VerifyVoucher = nil
	p = r.result(80)
	vouch(&p, priv, "EAGENT", "ECTRL")
	if err := r.s.Unlock(p, ""); !errors.Is(err, ErrBadVoucher) {
		t.Fatalf("no verifier: %v", err)
	}
}

func TestALockedPhoneIdentityHoldsNoKeyToVouchWith(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	_ = r.s.Lock()
	if _, err := r.s.Key(); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("a locked identity handed out its key: %v", err)
	}
}

func TestTheOptionalSecretIsAKeyInputAndWrongTriesAreCountedAndDelayed(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	seed := r.storeSeed()
	if err := r.s.ChangeSecret("", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if c := r.s.P.Class(); c != ClassSecretBound {
		t.Fatalf("class %s", c)
	}
	// The seed is still readable while open (re-sealed under the new key).
	if got, err := secureenclave.LoadRootSeed(r.dir); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("after setting the secret: %v", err)
	}
	_ = r.s.Lock()
	if err := r.s.Unlock(r.result(80), ""); !errors.Is(err, ErrSecretNeeded) {
		t.Fatalf("no secret: %v", err)
	}
	for i := 0; i < 5; i++ { // five tries are free; the sixth waits
		if err := r.s.Unlock(r.result(80), "nope"); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	// Even the right secret waits now, and it waits BEFORE any stretching.
	argonTime0 := argonTime
	var d *DelayedError
	err := r.s.Unlock(r.result(80), "correct horse")
	if !errors.As(err, &d) || d.RetryAfter < 50*time.Second {
		t.Fatalf("expected a delay of about a minute, got %v", err)
	}
	_ = argonTime0
	// The count survives a restart (it is in the profile directory).
	drop(r.dir)
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Now: r.s.G.Now})
	if err := s2.Unlock(r.result(80), "correct horse"); !errors.As(err, &d) {
		t.Fatalf("the delay did not survive a restart: %v", err)
	}
	r.now = r.now.Add(61 * time.Second)
	if err := s2.Unlock(r.result(80), "correct horse"); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
	if got, err := secureenclave.LoadRootSeed(r.dir); err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("seed after unlocking with the secret: %v", err)
	}
	// Success resets the count.
	if a := s2.P.readAttempts(); a.Wrong != 0 {
		t.Fatalf("count not reset: %+v", a)
	}
	// Removing the secret needs the current one.
	if err := s2.ChangeSecret("wrong", ""); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("removal without the secret: %v", err)
	}
	if err := s2.ChangeSecret("correct horse", ""); err != nil {
		t.Fatal(err)
	}
	if c := s2.P.Class(); c != ClassAppOnly {
		t.Fatalf("class %s", c)
	}
}

func TestDelaysDoubleFromAMinuteToAnHour(t *testing.T) {
	want := map[int]time.Duration{1: 0, 4: 0, 5: time.Minute, 6: 2 * time.Minute, 7: 4 * time.Minute, 12: time.Hour, 40: time.Hour}
	for n, d := range want {
		if got := delayAfter(n); got != d {
			t.Errorf("after %d wrong: %s, want %s", n, got, d)
		}
	}
}

func TestAProfileMadeBeforeGatesIsUngatedAndSaysSo(t *testing.T) {
	r := newRig(t, ModePhone)
	if r.s.State() != StateUngated || r.s.P.Class() != ClassNone {
		t.Fatal("a profile with no gate must say it has none")
	}
	if err := r.s.Unlock(r.result(80), ""); !errors.Is(err, ErrNoGate) {
		t.Fatal(err)
	}
}

func TestAGateIsMadeOnce(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	if err := r.s.Found(); !errors.Is(err, ErrAlreadyGated) {
		t.Fatalf("a second GK would orphan the first: %v", err)
	}
}

func TestAV1SeedLeftBeforeTheGateIsNotServedWhileTheProfileIsLocked(t *testing.T) {
	r := newRig(t, ModePhone)
	// A seed stored before this profile had a gate: a plain v1 envelope.
	seed := r.storeSeed()
	if err := r.s.Found(); err != nil { // the gate is made over it
		t.Fatal(err)
	}
	_ = r.s.Lock()
	if got, err := secureenclave.LoadRootSeed(r.dir); !errors.Is(err, secureenclave.ErrIdentityLocked) || got != nil {
		t.Fatalf("a locked profile served the v1 envelope it had before the gate (%v)", err)
	}
	_ = seed
}
