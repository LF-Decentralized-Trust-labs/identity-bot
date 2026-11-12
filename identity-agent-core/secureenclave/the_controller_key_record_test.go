package secureenclave

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func aStoredMachineKeyFile(t *testing.T, dir, body string) {
	t.Helper()
	p := controllerKeyPath(dir, theMachineKeyFileOnDisk)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func asIfThisWereAMac(t *testing.T) {
	t.Helper()
	prev := controllerKeyIsHardwareHere
	controllerKeyIsHardwareHere = func() (string, string) { return "secure_enclave", "Apple Secure Enclave" }
	t.Cleanup(func() { controllerKeyIsHardwareHere = prev })
}

// The case that fails before the fix: a desktop holds no seed, so with gate.json
// deleted the only thing that says it was gated is its own controller key.
func TestAControllerKeyMadeUnderAGateMarksTheProfileGated(t *testing.T) {
	t.Run("a Mac's key sealed under the gate", func(t *testing.T) {
		dir := t.TempDir()
		aStoredMachineKeyFile(t, dir, `{"v":1,"kind":"sep-p256-signing","len":3,"blob":"AAAA","gate":"`+gateScheme+`"}`)
		if !TheControllerKeyIsUnderAGate(dir, "profile-a") {
			t.Fatal("a profile whose machine key is sealed under a gate was taken for ungated")
		}
	})
	t.Run("a key made before the profile had a gate does not", func(t *testing.T) {
		dir := t.TempDir()
		aStoredMachineKeyFile(t, dir, `{"v":1,"kind":"sep-p256-signing","len":3,"blob":"AAAA"}`)
		if TheControllerKeyIsUnderAGate(dir, "profile-a") {
			t.Fatal("an old ungated key was called gated, so it could never be sealed")
		}
	})
	t.Run("a damaged key file is not evidence of no gate", func(t *testing.T) {
		dir := t.TempDir()
		aStoredMachineKeyFile(t, dir, `{"v":1,"ki`)
		if !TheControllerKeyIsUnderAGate(dir, "profile-a") {
			t.Fatal("damaging the key file turned a profile ungated")
		}
	})
	t.Run("a Windows record of the key the core made", func(t *testing.T) {
		dir := t.TempDir()
		theGateIs(t, dir, aTestGate{"profile-a", true})
		if err := recordTheControllerKey(dir, "tpm2", "k", []byte("pub")); err != nil {
			t.Fatal(err)
		}
		if !TheControllerKeyIsUnderAGate(dir, "profile-a") {
			t.Fatal("a recorded gated controller key was not taken as gated")
		}
	})
	t.Run("a key the provider holds under the profile's own name", func(t *testing.T) {
		dir := t.TempDir()
		prev := aHardwareKeyOfThisProfileExists
		aHardwareKeyOfThisProfileExists = func(_, id string) bool { return id == "profile-a" }
		defer func() { aHardwareKeyOfThisProfileExists = prev }()
		if !TheControllerKeyIsUnderAGate(dir, "profile-a") || TheControllerKeyIsUnderAGate(dir, "profile-b") {
			t.Fatal("the profile's own hardware key is what marks it, and no other profile's")
		}
	})
	t.Run("nothing at all", func(t *testing.T) {
		if TheControllerKeyIsUnderAGate(t.TempDir(), "profile-a") {
			t.Fatal("an empty profile was called gated")
		}
	})
}

// The second half of the first HIGH: a hardware key that exists and will not open
// is a refusing signer. Never the software one, and no software key is minted.
func TestAHardwareControllerKeyThatWillNotOpenGivesARefusingSignerNotTheSoftwareOne(t *testing.T) {
	asIfThisWereAMac(t)
	for name, setup := range map[string]func(t *testing.T, dir string){
		"a Mac's key file this build cannot open": func(t *testing.T, dir string) {
			aStoredMachineKeyFile(t, dir, `{"v":1,"kind":"sep-p256-signing","len":3,"blob":"AAAA","gate":"`+gateScheme+`"}`)
		},
		"a key file of an ungated profile that no enclave here opens": func(t *testing.T, dir string) {
			aStoredMachineKeyFile(t, dir, `{"v":1,"kind":"sep-p256-signing","len":3,"blob":"AAAA"}`)
		},
		"a damaged key file": func(t *testing.T, dir string) { aStoredMachineKeyFile(t, dir, `{"v":1,"ki`) },
		"a Windows key record": func(t *testing.T, dir string) {
			theGateIs(t, dir, aTestGate{"profile-a", true})
			if err := recordTheControllerKey(dir, "tpm2", "k", []byte("pub")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)
			s := NewPlatformSigner(dir)
			if s.Platform() == "software" {
				t.Fatal("a controller key that would not open fell through to the software signer")
			}
			if _, err := s.Sign([]byte("x")); err == nil {
				t.Fatal("a refusing signer signed")
			}
			if _, err := s.PublicKey(); err == nil {
				t.Fatal("a refusing signer gave a public key")
			}
			if _, err := os.Stat(filepath.Join(dir, "secureenclave", "software_signer.key")); err == nil {
				t.Fatal("a software key was minted beside a hardware key that would not open")
			}
		})
	}
	t.Run("a machine that never had a hardware key gets whatever its own hardware offers, else the software signer", func(t *testing.T) {
		// Independent of the machine this runs on: a Mac with a Secure Enclave
		// (built with sepblob) rightly gets the enclave signer.
		want := "software"
		if hw := newDarwinSecureEnclaveSigner(t.TempDir()); hw != nil && hw.Available() {
			want = hw.Platform()
		}
		if s := NewPlatformSigner(t.TempDir()); s.Platform() != want {
			t.Fatalf("got %s, want %s", s.Platform(), want)
		}
	})
}

func TestTheCoreRefusesAControllerKeyItCannotShowItMade(t *testing.T) {
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	pub := bytes.Repeat([]byte{4}, 65)

	if err := theControllerKeyIsTheOneWeMade(dir, "k", pub); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a key with no record was accepted (planted under the computable name): %v", err)
	}
	if err := recordTheControllerKey(dir, "tpm2", "k", pub); err != nil {
		t.Fatal(err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, "k", pub); err != nil {
		t.Fatalf("the key it made was refused: %v", err)
	}
	other := bytes.Repeat([]byte{5}, 65)
	if err := theControllerKeyIsTheOneWeMade(dir, "k", other); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a different public key was accepted: %v", err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, "another-name", pub); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a record for another key name was accepted: %v", err)
	}
	b, err := os.ReadFile(controllerKeyPath(dir, controllerKeyRecordFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, pub) || strings.Contains(string(b), "BAQEBAQE") {
		t.Fatal("the public key sits in the record unsealed, so a planted key's record could be forged")
	}
	// A record whose public key was not sealed under the gate key does not open.
	if err := os.WriteFile(controllerKeyPath(dir, controllerKeyRecordFile), []byte(`{"v":1,"platform":"tpm2","name":"k","gate":"`+gateScheme+`","public":"AAAA"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, "k", pub); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a record that does not open under the gate key was accepted: %v", err)
	}
	// Locked: nothing is read or written.
	theGateIs(t, dir, aTestGate{"profile-a", false})
	if err := theControllerKeyIsTheOneWeMade(dir, "k", pub); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("locked: %v", err)
	}
	if err := recordTheControllerKey(dir, "tpm2", "k", pub); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile recorded a key: %v", err)
	}
	// An ungated profile writes no record and accepts the key it has always used.
	free := t.TempDir()
	if err := recordTheControllerKey(free, "tpm2", "k", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(controllerKeyPath(free, controllerKeyRecordFile)); err == nil {
		t.Fatal("an ungated profile got a record")
	}
	if err := theControllerKeyIsTheOneWeMade(free, "k", pub); err != nil {
		t.Fatalf("an ungated profile's key was refused: %v", err)
	}
}

// A Mac's key found under a gate is checked against the record, as a Windows key
// is: the key the profile recorded is accepted, a different blob is refused (a
// planted key file must not be adopted and sealed), a record that was deleted is
// written again for a key that opened, and a damaged record is a refusal.
func TestAMacControllerKeyIsCheckedAgainstItsRecord(t *testing.T) {
	pub := bytes.Repeat([]byte{4}, 65)
	other := bytes.Repeat([]byte{5}, 65)
	const mk, plat = theMachineKeyFileOnDisk, "secure_enclave"

	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	if err := settleAnExistingControllerKey(dir, plat, mk, pub); err != nil {
		t.Fatalf("a sealed key with no record was refused: %v", err)
	}
	if err := settleAnExistingControllerKey(dir, plat, mk, pub); err != nil {
		t.Fatalf("the recorded key was refused: %v", err)
	}
	if err := settleAnExistingControllerKey(dir, plat, mk, other); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a different key was adopted over the recorded one: %v", err)
	}
	if err := os.WriteFile(controllerKeyPath(dir, controllerKeyRecordFile), []byte(`{"v":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := settleAnExistingControllerKey(dir, plat, mk, pub); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a damaged record was taken for none: %v", err)
	}
	theGateIs(t, dir, aTestGate{"profile-a", false})
	if err := settleAnExistingControllerKey(dir, plat, mk, pub); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("locked: %v", err)
	}
	free := t.TempDir()
	if err := settleAnExistingControllerKey(free, plat, mk, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(controllerKeyPath(free, controllerKeyRecordFile)); err == nil {
		t.Fatal("an ungated profile got a record")
	}
}

// A key just made is recorded; a record of the same key that is gone is replaced;
// a record of a key of another name or platform is not this signer's to replace.
func TestANewControllerKeyReplacesItsOwnRecordAndNeverAnotherKeys(t *testing.T) {
	pub := bytes.Repeat([]byte{4}, 65)
	other := bytes.Repeat([]byte{5}, 65)
	const mk, plat = theMachineKeyFileOnDisk, "secure_enclave"
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	if err := recordANewControllerKey(dir, plat, mk, pub); err != nil {
		t.Fatal(err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, mk, pub); err != nil {
		t.Fatalf("the new key is not recorded: %v", err)
	}
	if err := recordANewControllerKey(dir, plat, mk, other); err != nil {
		t.Fatalf("a new key could not replace its own gone key's record: %v", err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, mk, other); err != nil {
		t.Fatalf("the replacement is not recorded: %v", err)
	}
	if err := recordANewControllerKey(dir, "tpm2", "k", pub); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("another platform's record was replaced: %v", err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, mk, other); err != nil {
		t.Fatalf("the refused replacement changed the record: %v", err)
	}
	theGateIs(t, dir, aTestGate{"profile-a", false})
	if err := recordANewControllerKey(dir, plat, mk, pub); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("locked: %v", err)
	}
}

// openFromTheGate with a blob sealed under a gate and no gate key to open it: the
// stored bytes are never handed back as the key. (Fails if it returns them.)
func TestASealedBlobWithNoGateKeyIsNeverServedAsTheKey(t *testing.T) {
	dir := t.TempDir()
	theGateIs(t, dir, aTestGate{"profile-a", true})
	sealed, scheme, err := sealForTheGate(dir, []byte("the blob"))
	if err != nil || scheme != gateScheme {
		t.Fatalf("seal: %v %q", err, scheme)
	}
	for name, gate := range map[string]func(t *testing.T){
		"a locked profile": func(t *testing.T) { theGateIs(t, dir, aTestGate{"profile-a", false}) },
		"a profile that has no gate": func(t *testing.T) {
			t.Cleanup(UseGate(func(string) (GateSealer, bool) { return nil, false }))
		},
	} {
		t.Run(name, func(t *testing.T) {
			gate(t)
			blob, needs, err := openFromTheGate(dir, sealed, gateScheme)
			if !errors.Is(err, ErrIdentityLocked) || blob != nil || needs {
				t.Fatalf("got %q needs=%v err=%v", blob, needs, err)
			}
		})
	}
}
