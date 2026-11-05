package recovery

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/buildmode"
	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

func archiveWithARootSeed(t *testing.T) (*backup.PayloadBundle, []byte) {
	t.Helper()
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(7 * (i + 1))
	}
	return &backup.PayloadBundle{Sections: map[string][]byte{
		"root_seed":           seed,
		"login_relationships": []byte(`{"a":1}`),
	}}, seed
}

// A machine that would be refused founding an identity is refused recovering
// one, and nothing is written: not the seed, not the file sections beside it.
func TestRecoveryOntoAMachineThatCannotProtectASeedIsRefusedAndWritesNothing(t *testing.T) {
	cases := map[string]struct {
		cap     secureenclave.Capability
		wrapper bool
	}{
		"no key hardware":             {secureenclave.Capability{Status: secureenclave.Absent, Reason: "no_tpm_chip"}, true},
		"hardware present, unusable":  {secureenclave.Capability{Status: secureenclave.Present}, true},
		"nobody has looked":           {secureenclave.Capability{Status: secureenclave.Unknown}, true},
		"zero-value capability":       {secureenclave.Capability{}, true},
		"hardware usable, no wrapper": {secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, false},
		// A production Windows or Linux desktop: a TPM, and no wrapper written.
		"production desktop": {secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindTPM2}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			seedwraptest.ThisMachineCannot(t, c.cap, c.wrapper)
			bundle, _ := archiveWithARootSeed(t)
			dir := t.TempDir()
			svc := &Service{DataDir: dir}

			err := svc.applyPayload(&RestoredPayload{Bundle: bundle})
			if err == nil {
				t.Fatal("recovery onto a machine that cannot protect a root seed succeeded")
			}
			if !secureenclave.IsRootSeedRefusal(err) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
			var again *ErrRestoreCanBeRetried
			if errors.As(err, &again) {
				t.Fatalf("a refusal about this machine must not read as a retryable file error")
			}
			if _, lerr := secureenclave.LoadRootSeed(dir); !errors.Is(lerr, secureenclave.ErrNoRootSeed) {
				t.Fatalf("a root seed was written despite the refusal: %v", lerr)
			}
			entries, _ := filepath.Glob(filepath.Join(dir, "*"))
			if len(entries) != 0 {
				t.Fatalf("refused recovery still wrote to the data directory: %v", entries)
			}
		})
	}
}

// And a machine that can protect a seed is unaffected: the seed lands wrapped.
func TestRecoveryOntoAMachineThatCanProtectASeedStillWorks(t *testing.T) {
	seedwraptest.ThisMachineCanProtectASeed(t)
	bundle, seed := archiveWithARootSeed(t)
	dir := t.TempDir()
	if err := (&Service{DataDir: dir}).applyPayload(&RestoredPayload{Bundle: bundle}); err != nil {
		t.Fatalf("recovery onto a capable machine failed: %v", err)
	}
	got, err := secureenclave.LoadRootSeed(dir)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("seed not reseated: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "secureenclave", "root_seed.key"))
	if !bytes.Contains(raw, []byte(`"wrap":"test-wrap"`)) {
		t.Fatalf("the restored seed was not wrapped: %s", raw)
	}
}

// The black box and an Android phone whose app supplies its Keystore key are
// where a root identity is meant to live: recovery onto either succeeds, and the
// envelope records what protects the seed.
func TestRecoveryOntoASealedHostOrAPhoneWorksAndRecordsTheProtection(t *testing.T) {
	for name, c := range map[string]struct {
		stand      func(testing.TB)
		protection string
	}{
		"sealed host": {seedwraptest.ThisMachineIsASealedHost, secureenclave.ProtectionSealedVolume},
		"android phone with its key": {func(t testing.TB) {
			seedwraptest.ThisMachineCannot(t, secureenclave.Capability{Status: secureenclave.Usable, Kind: secureenclave.KindAndroidTEE}, true)
		}, secureenclave.ProtectionHardwareWrapped},
	} {
		t.Run(name, func(t *testing.T) {
			c.stand(t)
			bundle, seed := archiveWithARootSeed(t)
			dir := t.TempDir()
			if err := (&Service{DataDir: dir}).applyPayload(&RestoredPayload{Bundle: bundle}); err != nil {
				t.Fatalf("recovery was refused: %v", err)
			}
			got, err := secureenclave.LoadRootSeed(dir)
			if err != nil || !bytes.Equal(got, seed) {
				t.Fatalf("seed not reseated: %v", err)
			}
			p, _, why, err := secureenclave.RootSeedProtection(dir)
			if err != nil || p != c.protection {
				t.Fatalf("envelope records %q (%v), want %q", p, err, c.protection)
			}
			if p == secureenclave.ProtectionUnwrapped && why == "" {
				t.Fatal("an unwrapped seed must record why")
			}
		})
	}
}

// A production Mac has a usable Secure Enclave and a working wrapper, and is
// still refused: the rule is the one founding uses, not "can it wrap a key". An
// iPhone, which differs only in being able to prove its software, is not.
func TestRecoveryOntoAProductionMacIsRefusedAndAnIPhoneIsNot(t *testing.T) {
	seedwraptest.ThisMachineIsAProductionMac(t)
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	bundle, _ := archiveWithARootSeed(t)
	macDir := t.TempDir()
	if err := (&Service{DataDir: macDir}).applyPayload(&RestoredPayload{Bundle: bundle}); !secureenclave.IsRootSeedRefusal(err) {
		t.Fatalf("a production Mac must be refused, got %v", err)
	}
	if _, lerr := secureenclave.LoadRootSeed(macDir); !errors.Is(lerr, secureenclave.ErrNoRootSeed) {
		t.Fatalf("a root seed was written on a Mac: %v", lerr)
	}

	seedwraptest.ThisMachineIsAnIPhone(t)
	if err := (&Service{DataDir: t.TempDir()}).applyPayload(&RestoredPayload{Bundle: bundle}); err != nil {
		t.Fatalf("an iPhone was refused: %v", err)
	}
}

// A recovery refused because THIS machine may not hold the seed is not burned:
// the session is not marked failed and keeps its archive, so the person can
// finish it on a machine that may.
func TestARefusedActivationOnTheWrongMachineLeavesTheSessionToFinishElsewhere(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	dir := t.TempDir()
	svc := NewService(dir, nil, nil)
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(3*i + 1)
	}
	archive := buildTestArchiveWith(t, testMnemonic, nil, map[string][]byte{"root_seed": seed})
	sess, err := svc.Start(StartRequest{ArchiveB64: base64.StdEncoding.EncodeToString(archive), Mnemonic: testMnemonic})
	if err != nil {
		t.Fatal(err)
	}
	svc.CancelGate.Now = func() time.Time { return time.Now().Add(96 * time.Hour) }
	svc.Rotation.MarkCompleted(sess.ID, RotationResult{})

	// The wrong machine.
	seedwraptest.ThisMachineIsAProductionMac(t)
	_, err = svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if !secureenclave.IsRootSeedRefusal(err) {
		t.Fatalf("want the root-seed refusal, got %v", err)
	}
	got, gerr := svc.GetSession(sess.ID)
	if gerr != nil || got.State == SessionFailed || got.State == SessionActivated || got.Error != "" {
		t.Fatalf("the refusal burned the session: %+v (%v)", got, gerr)
	}
	if _, lerr := secureenclave.LoadRootSeed(dir); !errors.Is(lerr, secureenclave.ErrNoRootSeed) {
		t.Fatalf("a seed was written by the refused activation: %v", lerr)
	}

	// The right machine, same session.
	seedwraptest.ThisMachineIsAnIPhone(t)
	done, err := svc.Activate(sess.ID, ActivateRequest{Mnemonic: testMnemonic})
	if err != nil {
		t.Fatalf("the preserved session could not be activated on a machine that may hold the seed: %v", err)
	}
	if after, _ := secureenclave.LoadRootSeed(dir); !bytes.Equal(after, seed) {
		t.Fatal("the seed was not installed by the later activation")
	}
	if done == nil || done.State != SessionActivated {
		t.Fatalf("session not activated: %+v", done)
	}
}

// An Android app that registers no seed wrapper gets no exemption in a
// production build: recovery onto it is refused, nothing is written, and the
// refusal is the sentence the app shows. (Fails if the old-app allowance returns.)
func TestRecoveryOntoAPhoneWhoseAppSuppliesNoKeyIsRefusedInProduction(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("a development build is exempt")
	}
	seedwraptest.ThisMachineIsAPhoneWithNoWrapper(t)
	bundle, _ := archiveWithARootSeed(t)
	dir := t.TempDir()
	err := (&Service{DataDir: dir}).applyPayload(&RestoredPayload{Bundle: bundle})
	if !secureenclave.IsRootSeedRefusal(err) {
		t.Fatalf("want refusal, got %v", err)
	}
	if _, lerr := secureenclave.LoadRootSeed(dir); !errors.Is(lerr, secureenclave.ErrNoRootSeed) {
		t.Fatalf("a seed was written despite the refusal: %v", lerr)
	}
}
