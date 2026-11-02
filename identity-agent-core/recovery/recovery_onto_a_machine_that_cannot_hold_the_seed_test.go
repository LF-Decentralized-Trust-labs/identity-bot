package recovery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"identity-agent-core/backup"
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

// The black box and an Android phone are where a root identity is meant to
// live: recovery onto either succeeds, and the envelope records what protects
// the seed.
func TestRecoveryOntoASealedHostOrAPhoneWorksAndRecordsTheProtection(t *testing.T) {
	for name, c := range map[string]struct {
		stand      func(testing.TB)
		protection string
	}{
		"sealed host":        {seedwraptest.ThisMachineIsASealedHost, secureenclave.ProtectionSealedVolume},
		"android-like phone": {seedwraptest.ThisMachineIsAPhoneWithNoWrapper, secureenclave.ProtectionUnwrapped},
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
