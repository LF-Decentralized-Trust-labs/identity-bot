package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/secureenclave"
	"identity-agent-core/secureenclave/seedwraptest"
)

// hardwareBacked is whether the root seed is under hardware: the seed
// wrapper's answer, on every platform. These run on every host because the
// decisions are untagged; an android- or windows-tagged test could only run
// there.

var (
	wrapped    = seedWrapFacts{Wrapped: true, Scheme: "test-wrap"}
	notWrapped = seedWrapFacts{Wrapped: false, Scheme: "none"}
)

// A phone whose app supplies a working Keystore key reports hardware backing,
// with the wrapper's scheme and no TPM fields.
func TestAPhoneWithAWorkingKeystoreKeyReportsHardwareBacking(t *testing.T) {
	restore := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: true})
	t.Cleanup(restore)

	got := androidEnclaveStatus(readSeedWrap())
	if !got.HardwareBacked || got.BackingType != "test-wrap" {
		t.Fatalf("a working wrapper read as hardwareBacked=%v backingType=%q", got.HardwareBacked, got.BackingType)
	}
	if got.TpmPresent != nil || got.TpmEnabled != nil {
		t.Fatalf("a phone reported TPM fields: present=%v enabled=%v", got.TpmPresent, got.TpmEnabled)
	}
}

func TestAPhoneWhoseKeystoreKeyIsRefusedIsNotHardwareBacked(t *testing.T) {
	restore := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: false})
	t.Cleanup(restore)

	got := androidEnclaveStatus(readSeedWrap())
	if got.HardwareBacked || got.BackingType != "none" {
		t.Fatalf("a refused wrapper read as hardwareBacked=%v backingType=%q", got.HardwareBacked, got.BackingType)
	}
}

// The label names the level the attestation proved, and nothing it did not.
func TestAPhoneNamesTheHardwareItsKeyWasAttestedIn(t *testing.T) {
	for scheme, want := range map[string]string{
		"android-keystore-strongbox-rsa2048oaep-aes256gcm":  "Android StrongBox",
		"android-keystore-tee-rsa2048oaep-aes256gcm":        "Android TEE",
		"android-keystore-unattested-rsa2048oaep-aes256gcm": "Android Keystore",
		"test-wrap": "Android Keystore",
	} {
		got := androidEnclaveStatus(seedWrapFacts{Wrapped: true, Scheme: scheme})
		if got.BackingLabel != want {
			t.Errorf("scheme %q: label %q, want %q", scheme, got.BackingLabel, want)
		}
	}
}

// An Apple-silicon Mac whose Secure Enclave key fails, or whose build has no
// Secure Enclave seed wrapper, is not hardware backed: the CPU having the
// hardware is not the seed being under it.
func TestAMacIsHardwareBackedOnlyWhenItsSeedIsWrapped(t *testing.T) {
	if got := macEnclaveStatus(true, notWrapped); got.HardwareBacked {
		t.Fatalf("an Apple-silicon Mac with no working wrapper read as hardware backed: %+v", got)
	}
	if got := macEnclaveStatus(false, notWrapped); got.HardwareBacked {
		t.Fatalf("an Intel Mac with no working wrapper read as hardware backed: %+v", got)
	}
	got := macEnclaveStatus(true, wrapped)
	if !got.HardwareBacked || got.BackingType != "secure_enclave" {
		t.Fatalf("a Mac whose seed is wrapped read as %+v", got)
	}
}

// A PC whose registry lists an enabled TPM, but whose TPM key does not work,
// is not hardware backed. The TPM fields still say what the registry found.
func TestAWindowsPCIsHardwareBackedOnlyWhenItsSeedIsWrapped(t *testing.T) {
	got := windowsEnclaveStatus(true, true, notWrapped)
	if got.HardwareBacked || got.BackingType != "dpapi" {
		t.Fatalf("a TPM in the registry with no working key read as %+v", got)
	}
	if got.TpmPresent == nil || !*got.TpmPresent || got.TpmEnabled == nil || !*got.TpmEnabled {
		t.Fatalf("the registry's TPM facts were lost: present=%v enabled=%v", got.TpmPresent, got.TpmEnabled)
	}
	got = windowsEnclaveStatus(true, true, wrapped)
	if !got.HardwareBacked || got.BackingType != "tpm2" {
		t.Fatalf("a PC whose seed is wrapped read as %+v", got)
	}
	got = windowsEnclaveStatus(false, false, notWrapped)
	if got.HardwareBacked || got.TpmPresent == nil || *got.TpmPresent {
		t.Fatalf("a PC with no TPM read as %+v", got)
	}
}

func TestAnIPhoneIsHardwareBackedOnlyWhenItsSeedIsWrapped(t *testing.T) {
	if got := iosEnclaveStatus(wrapped); !got.HardwareBacked || got.BackingType != "secure_enclave" {
		t.Fatalf("an iPhone whose seed is wrapped read as %+v", got)
	}
	if got := iosEnclaveStatus(notWrapped); got.HardwareBacked {
		t.Fatalf("an iPhone with no working wrapper read as hardware backed: %+v", got)
	}
}

// The endpoint, on whichever host runs it: hardwareBacked and seedWrapped follow
// the seed wrapper whatever attestation signer the runner holds, and a refusal
// says why in seedProtection.
func TestTheEnclaveEndpointFollowsTheSeedWrapperNotTheSigner(t *testing.T) {
	for _, works := range []bool{true, false} {
		for name, signer := range map[string]func(string) secureenclave.PlatformSigner{
			"software": secureenclave.NewSoftwareSigner,
			"hardware": func(string) secureenclave.PlatformSigner { return fakeHardwareSigner{} },
		} {
			restore := secureenclave.UseSeedWrapper(seedwraptest.Wrapper{Works: works})
			dir := t.TempDir()
			s := &CoreServer{DataDir: dir, AttestationRunner: secureenclave.NewRunner(secureenclave.RunnerConfig{
				DataDir: dir,
				Signer:  signer(dir),
			})}
			w := httptest.NewRecorder()
			s.handleSecurityEnclave(w, httptest.NewRequest(http.MethodGet, "/", nil))
			restore()
			var got EnclaveStatusResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("%v: %s", err, w.Body.String())
			}
			if got.HardwareBacked != works || got.KeyProtection == nil || got.KeyProtection.SeedWrapped != works {
				t.Errorf("wrapper works=%v, %s signer: hardwareBacked=%v keyProtection=%+v",
					works, name, got.HardwareBacked, got.KeyProtection)
				continue
			}
			sp := got.KeyProtection.SeedProtection
			if !works && (sp == nil || sp.NotProtectedWhy == "") {
				t.Errorf("a refused wrapper, %s signer: no reason in seedProtection: %+v", name, sp)
			}
		}
	}
}

// A signer that reports itself as hardware, to show it does not decide the
// answer.
type fakeHardwareSigner struct{}

func (fakeHardwareSigner) Available() bool            { return true }
func (fakeHardwareSigner) Platform() string           { return "secure_enclave" }
func (fakeHardwareSigner) Label() string              { return "Test Secure Enclave" }
func (fakeHardwareSigner) PublicKey() ([]byte, error) { return nil, secureenclave.ErrSignerUnavailable }
func (fakeHardwareSigner) Sign([]byte) ([]byte, error) {
	return nil, secureenclave.ErrSignerUnavailable
}
