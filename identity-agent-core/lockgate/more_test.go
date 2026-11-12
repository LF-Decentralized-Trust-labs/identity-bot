package lockgate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"identity-agent-core/authprovider"
	"identity-agent-core/backup"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestParallelWrongSecretsAreEachCounted(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	if err := r.s.ChangeSecret("", "correct horse"); err != nil {
		t.Fatal(err)
	}
	_ = r.s.Lock()
	var wg sync.WaitGroup
	var wrong int32
	results := make([]ProviderResult, 12)
	for i := range results {
		results[i] = r.result(80)
	}
	for i := range results {
		wg.Add(1)
		go func(p ProviderResult) {
			defer wg.Done()
			if err := r.s.Unlock(p, "nope"); errors.Is(err, ErrWrongSecret) {
				atomic.AddInt32(&wrong, 1)
			}
		}(results[i])
	}
	wg.Wait()
	if a := r.s.P.readAttempts(); a.Wrong != int(wrong) {
		t.Fatalf("%d wrong secrets were tried and %d were counted", wrong, a.Wrong)
	}
}

func TestAnUnreadableGateRecordIsNotTakenForNoGate(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	// stat on gate/gate.json fails with ENOTDIR, which is not "does not exist".
	if err := os.Rename(filepath.Join(r.dir, "gate"), filepath.Join(r.dir, "gate.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "gate"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !r.s.P.Gated() {
		t.Fatal("a stat error that is not 'does not exist' made the profile look ungated")
	}
}

func TestOutOfRangeStretchingParametersAreRefusedNotRun(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	_ = r.s.ChangeSecret("", "correct horse")
	rec, _ := r.s.P.readRecord()
	rec.Secret.MemKB = 1 << 30
	_ = r.s.P.writeRecord(rec)
	_ = r.s.Lock()
	if err := r.s.Unlock(r.result(80), "correct horse"); err == nil {
		t.Fatal("ran Argon2 with a memory size read from disk")
	}
}

func TestACrashInTheMiddleOfChangingTheSecretIsFinishedNotLost(t *testing.T) {
	for _, crashAfter := range []string{"journalled", "seed", "record", "device-held"} {
		t.Run(crashAfter, func(t *testing.T) {
			r := newRig(t, ModePhone)
			_ = r.s.Found()
			seed := r.storeSeed()
			crash := errors.New("power cut")
			afterStep = func(s string) error {
				if s == crashAfter {
					return crash
				}
				return nil
			}
			t.Cleanup(func() { afterStep = nil })
			if err := r.s.ChangeSecret("", "correct horse"); !errors.Is(err, crash) {
				t.Fatalf("the change did not stop where told: %v", err)
			}
			afterStep = nil
			// The process dies: nothing in memory survives, a new one starts.
			drop(r.dir)
			s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Mode: ModePhone, Now: r.s.G.Now})
			if err := s2.Reopen(); err != nil {
				t.Fatalf("reopen after the crash: %v", err)
			}
			got, err := secureenclave.LoadRootSeed(r.dir)
			if err != nil || !bytes.Equal(got, seed) {
				t.Fatalf("the seed is not readable after a crash in the change: %v", err)
			}
			if !s2.P.HasSecret() {
				t.Fatal("the change was dropped instead of finished")
			}
			if _, err := os.Stat(filepath.Join(r.dir, "gate", changeJournalFile)); err == nil {
				t.Fatal("the journal is still there after it was finished")
			}
			// And the secret now in force is the one asked for.
			_ = s2.Lock()
			r.s = s2
			if err := s2.Unlock(r.result(80), "correct horse"); err != nil {
				t.Fatalf("the new secret does not open it: %v", err)
			}
			if got, err := secureenclave.LoadRootSeed(r.dir); err != nil || !bytes.Equal(got, seed) {
				t.Fatalf("seed after unlock: %v", err)
			}
		})
	}
}

func TestACrashWhileRemovingTheSecretIsFinishedToo(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	seed := r.storeSeed()
	if err := r.s.ChangeSecret("", "correct horse"); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("power cut")
	afterStep = func(s string) error {
		if s == "seed" {
			return crash
		}
		return nil
	}
	t.Cleanup(func() { afterStep = nil })
	if err := r.s.ChangeSecret("correct horse", ""); !errors.Is(err, crash) {
		t.Fatal(err)
	}
	afterStep = nil
	drop(r.dir)
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Mode: ModePhone, Now: r.s.G.Now})
	if err := s2.Reopen(); err != nil {
		t.Fatal(err)
	}
	if got, err := secureenclave.LoadRootSeed(r.dir); err != nil || !bytes.Equal(got, seed) || s2.P.HasSecret() {
		t.Fatalf("removal not finished: err=%v secret=%v", err, s2.P.HasSecret())
	}
}

func TestAVoucherIsGoodForOneLogInOnly(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rootKey := base64.StdEncoding.EncodeToString(pub)
	r := newRig(t, ModeController)
	r.s.G.VerifyVoucher = VoucherFromRootDevice(func() (string, error) { return rootKey, nil },
		func() string { return "EAGENT" }, func() string { return "ECTRL" })
	_ = r.s.Found()
	_ = r.s.Lock()
	p := r.result(80)
	sig, _ := login.SignString(authprovider.CanonicalUnlockVoucherStatement("EAGENT", "ECTRL", p.Level, p.At, p.Score, p.Nonce), priv.Seed())
	p.Voucher = &Voucher{AgentAID: "EAGENT", ControllerAID: "ECTRL", Signature: sig}
	// The same voucher under a fresh nonce: what a machine does to reuse it.
	reused := p
	reused.Nonce = strings.Repeat("z", 16)
	if err := r.s.Unlock(reused, ""); !errors.Is(err, ErrBadVoucher) {
		t.Fatalf("a voucher was reused under a different nonce: %v", err)
	}
	if err := r.s.Unlock(p, ""); err != nil {
		t.Fatalf("the voucher for this nonce: %v", err)
	}
}

func TestASpentResultStaysSpentAcrossARestart(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
	_ = r.s.Lock()
	p := r.result(80)
	if err := r.s.Unlock(p, ""); err != nil {
		t.Fatal(err)
	}
	_ = r.s.Lock()
	drop(r.dir) // the core restarts: nothing in memory survives
	s2 := NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Mode: ModePhone, Now: r.s.G.Now})
	if err := s2.Unlock(p, ""); !errors.Is(err, ErrReplayed) {
		t.Fatalf("a result already used opened the identity after a restart: %v", err)
	}
	if err := s2.Unlock(r.result(80), ""); err != nil {
		t.Fatalf("a fresh result: %v", err)
	}
}

func TestTheRecoveryPhraseAndTheBackupKeyAreUnreadableWhileLocked(t *testing.T) {
	r := newRig(t, ModePhone)
	_ = r.s.Found()
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
	// On disk, neither holds what it says it does in the clear or under the
	// wrapper alone: the phrase file names the gate, and the key file is the
	// gate-layer form.
	raw, _ := os.ReadFile(filepath.Join(r.dir, "secureenclave", "recovery_phrase.key"))
	if !strings.Contains(string(raw), `"gate":"gk-aes256gcm-v1"`) {
		t.Fatalf("the recovery phrase has no gate layer: %s", raw)
	}
	keyRaw, _ := os.ReadFile(filepath.Join(r.dir, "backup", "credentials_master.key"))
	if !strings.Contains(string(keyRaw), "backup-credentials+gate") {
		t.Fatalf("the backup key has no gate layer: %s", keyRaw)
	}

	_ = r.s.Lock()
	if _, err := secureenclave.LoadRecoveryPhrase(r.dir); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("a locked identity gave up its recovery phrase: %v", err)
	}
	if err := secureenclave.StoreRecoveryPhrase(r.dir, []byte("another phrase")); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("a locked identity took a recovery phrase: %v", err)
	}
	cs2, err := backup.NewCredentialStore(r.dir) // a core starting while locked still starts
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs2.Load("c1"); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("a locked identity opened its backup credentials: %v", err)
	}
	if err := cs2.Save("c2", backup.RemoteCredentialSecrets{AccessKey: "a"}); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("a locked identity sealed a backup credential: %v", err)
	}

	if err := r.s.Unlock(r.result(80), ""); err != nil {
		t.Fatal(err)
	}
	if got, err := secureenclave.LoadRecoveryPhrase(r.dir); err != nil || !bytes.Equal(got, phrase) {
		t.Fatalf("an open identity's phrase: %v", err)
	}
	if got, err := cs2.Load("c1"); err != nil || got.OAuthRefreshToken != "1//refresh" {
		t.Fatalf("an open identity's backup credential: %+v %v", got, err)
	}

	// Changing the secret moves both under the new key, through a crash too.
	for _, crashAfter := range []string{"", "journalled", "seed"} {
		crash := errors.New("power cut")
		afterStep = func(s string) error {
			if crashAfter != "" && s == crashAfter {
				return crash
			}
			return nil
		}
		secret, cur := "correct horse", ""
		if r.s.P.HasSecret() {
			secret, cur = "", "correct horse"
		}
		err := r.s.ChangeSecret(cur, secret)
		afterStep = nil
		if crashAfter != "" && !errors.Is(err, crash) || crashAfter == "" && err != nil {
			t.Fatalf("change (crash after %q): %v", crashAfter, err)
		}
		drop(r.dir)
		r.s = NewSession(OpenProfile(r.dir, "profile-a"), &Gate{Mode: ModePhone, Now: r.s.G.Now})
		if err := r.s.Reopen(); err != nil {
			t.Fatal(err)
		}
		if got, err := secureenclave.LoadRecoveryPhrase(r.dir); err != nil || !bytes.Equal(got, phrase) {
			t.Fatalf("phrase after a change (crash after %q): %v", crashAfter, err)
		}
		if got, err := cs2.Load("c1"); err != nil || got.OAuthRefreshToken != "1//refresh" {
			t.Fatalf("backup credential after a change (crash after %q): %+v %v", crashAfter, got, err)
		}
	}
}

func TestACredentialKeyHeldBeforeTheGateIsMovedUnderIt(t *testing.T) {
	r := newRig(t, ModePhone)
	// A key held the old way (wrapper only), then the identity gets a gate.
	cs, err := backup.NewCredentialStore(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Save("c1", backup.RemoteCredentialSecrets{AccessKey: "ak"}); err != nil {
		t.Fatal(err)
	}
	_ = r.s.Found()
	if got, err := cs.Load("c1"); err != nil || got.AccessKey != "ak" {
		t.Fatalf("a credential sealed before the gate: %+v %v", got, err)
	}
	keyRaw, _ := os.ReadFile(filepath.Join(r.dir, "backup", "credentials_master.key"))
	if !strings.Contains(string(keyRaw), "+gate") {
		t.Fatalf("the key was not moved under the gate when it was next used: %s", keyRaw)
	}
	_ = r.s.Lock()
	if _, err := cs.Load("c1"); !errors.Is(err, secureenclave.ErrIdentityLocked) {
		t.Fatalf("locked: %v", err)
	}
}
