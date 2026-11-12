//go:build darwin && cgo && sepblob

package secureenclave

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// THE MACHINE KEY UNDER THE GATE, ON A MAC (ADR-074 section 3).
//
// A Mac's controller key is a Secure Enclave blob the core holds itself, sealed
// under the profile's gate key. What these prove is the sealing, not the enclave:
// every test that does not need a real enclave key runs on any Mac, and the ones
// that do skip where there is none, as the test beside them does.

// aKeyedGate is a gate whose Open fails under a different key, which the shared
// test gate (one XOR for everybody) cannot model: a wrong GK is the case.
type aKeyedGate struct {
	key     byte
	profile string
	open    bool
}

func (g aKeyedGate) tag(body []byte) []byte {
	sum := sha256.Sum256(append([]byte{g.key}, body...))
	return sum[:8]
}

func (g aKeyedGate) Seal(p []byte) ([]byte, error) {
	body := make([]byte, len(p))
	for i, b := range p {
		body[i] = b ^ g.key
	}
	return append(append([]byte("kg1:"), body...), g.tag(body)...), nil
}

func (g aKeyedGate) Open(s []byte) ([]byte, error) {
	if len(s) < 12 || !bytes.HasPrefix(s, []byte("kg1:")) {
		return nil, errors.New("not sealed under a gate key")
	}
	body, tag := s[4:len(s)-8], s[len(s)-8:]
	if !bytes.Equal(tag, g.tag(body)) {
		return nil, errors.New("sealed under a different gate key")
	}
	out := make([]byte, len(body))
	for i, b := range body {
		out[i] = b ^ g.key
	}
	return out, nil
}

func theKeyedGateIs(t *testing.T, dir string, g aKeyedGate) {
	t.Helper()
	r1 := UseGate(func(d string) (GateSealer, bool) {
		if d != dir {
			return nil, false
		}
		if !g.open {
			return nil, true
		}
		return g, true
	})
	r2 := UseProfileLookup(func(d string) string {
		if d == dir {
			return g.profile
		}
		return ""
	})
	t.Cleanup(func() { r2(); r1() })
}

func theStoredEnvelope(t *testing.T, dir string) (sepEnvelope, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "secureenclave", "machine_key.sep"))
	if err != nil {
		t.Fatal(err)
	}
	var env sepEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	inside, err := base64.StdEncoding.DecodeString(env.Blob)
	if err != nil {
		t.Fatal(err)
	}
	return env, inside
}

// aBlobLike is stand-in key bytes, long enough to be found by a search of the file.
func aBlobLike() []byte { return bytes.Repeat([]byte("ENCLAVE-KEY-BLOB"), 8) }

// A sealed file is ciphertext: neither the key's bytes nor a run of them is on
// disk, and the envelope says which gate holds it and how long the blob inside is.
func TestAGatedMachineKeyIsCiphertextOnDisk(t *testing.T) {
	dir := t.TempDir()
	theKeyedGateIs(t, dir, aKeyedGate{key: 0x5a, profile: "profile-a", open: true})
	s := newSepSigner(dir).(*sepSigner)
	blob := aBlobLike()

	if err := s.write(blob); err != nil {
		t.Fatal(err)
	}
	env, inside := theStoredEnvelope(t, dir)
	if env.Gate != gateScheme {
		t.Fatalf("the envelope does not name the gate it is sealed under: %q", env.Gate)
	}
	if env.Len != len(blob) {
		t.Fatalf("Len is %d, the blob inside is %d", env.Len, len(blob))
	}
	raw, _ := os.ReadFile(s.path())
	if bytes.Contains(inside, blob[:16]) || bytes.Contains(raw, blob[:16]) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(blob)[:24])) {
		t.Fatal("the enclave key blob is readable in the file")
	}
	// And it opens again under the same gate key.
	got, needs, err := openFromTheGate(dir, inside, env.Gate)
	if err != nil || needs || !bytes.Equal(got, blob) {
		t.Fatalf("it does not open under its own gate key: %v needs=%v", err, needs)
	}
}

// With no gate nothing changes: the file is the blob, as every machine's key was.
func TestAnUngatedMachineKeyIsWrittenAsItAlwaysWas(t *testing.T) {
	dir := t.TempDir()
	s := newSepSigner(dir).(*sepSigner)
	blob := aBlobLike()
	if err := s.write(blob); err != nil {
		t.Fatal(err)
	}
	env, inside := theStoredEnvelope(t, dir)
	if env.Gate != "" || !bytes.Equal(inside, blob) {
		t.Fatalf("an ungated key changed: gate %q", env.Gate)
	}
}

// A locked profile refuses: it reads no blob, writes none, and the file on disk
// is not touched, whether the signer is new or loaded the key before the lock.
func TestALockedProfileRefusesItsMachineKey(t *testing.T) {
	dir := t.TempDir()
	theKeyedGateIs(t, dir, aKeyedGate{key: 0x5a, profile: "profile-a", open: true})
	s := newSepSigner(dir).(*sepSigner)
	if err := s.write(aBlobLike()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.path())

	theKeyedGateIs(t, dir, aKeyedGate{key: 0x5a, profile: "profile-a", open: false})
	if _, _, err := newSepSigner(dir).(*sepSigner).read(); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile read its machine key: %v", err)
	}
	if err := newSepSigner(dir).(*sepSigner).ensure(); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile's signer set itself up: %v", err)
	}
	if err := s.write(aBlobLike()); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile wrote its machine key: %v", err)
	}
	if _, err := s.envelopeFor(aBlobLike()); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile made an envelope: %v", err)
	}
	after, _ := os.ReadFile(s.path())
	if !bytes.Equal(before, after) {
		t.Fatal("the key file changed while the profile was locked")
	}
	if _, err := os.Stat(s.path() + ".not-this-machine"); err == nil {
		t.Fatal("a locked profile's key was set aside as if it belonged to another machine")
	}
}

// A wrong gate key refuses, as an error that is not "locked" and gives no blob.
func TestAWrongGateKeyRefusesTheMachineKey(t *testing.T) {
	dir := t.TempDir()
	theKeyedGateIs(t, dir, aKeyedGate{key: 0x5a, profile: "profile-a", open: true})
	s := newSepSigner(dir).(*sepSigner)
	if err := s.write(aBlobLike()); err != nil {
		t.Fatal(err)
	}
	theKeyedGateIs(t, dir, aKeyedGate{key: 0x33, profile: "profile-a", open: true})
	blob, _, err := newSepSigner(dir).(*sepSigner).read()
	if err == nil || errors.Is(err, ErrIdentityLocked) || blob != nil {
		t.Fatalf("a different gate key opened the machine key: %v (%d bytes)", err, len(blob))
	}
}

// envelopeFor: sealed when gated, plain when not, refusing when locked.
func TestTheMachineKeyEnvelopeFollowsTheGate(t *testing.T) {
	blob := aBlobLike()
	free := newSepSigner(t.TempDir()).(*sepSigner)
	data, err := free.envelopeFor(blob)
	if err != nil {
		t.Fatal(err)
	}
	var env sepEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.Gate != "" {
		t.Fatalf("an ungated envelope: %v %q", err, env.Gate)
	}
	dir := t.TempDir()
	theKeyedGateIs(t, dir, aKeyedGate{key: 1, profile: "profile-a", open: true})
	gated := newSepSigner(dir).(*sepSigner)
	data, err = gated.envelopeFor(blob)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, blob[:16]) {
		t.Fatal("the envelope carries the blob in the clear")
	}
	if err := json.Unmarshal(data, &env); err != nil || env.Gate != gateScheme {
		t.Fatalf("a gated envelope: %v %q", err, env.Gate)
	}
}

// stillOpen is what stops a signer that loaded its key before the lock.
func TestAMachineKeySignerStopsWhenTheProfileLocks(t *testing.T) {
	dir := t.TempDir()
	s := newSepSigner(dir).(*sepSigner)
	if err := s.stillOpen(); err != nil {
		t.Fatalf("an ungated profile: %v", err)
	}
	theKeyedGateIs(t, dir, aKeyedGate{key: 1, profile: "profile-a", open: true})
	if err := s.stillOpen(); err != nil {
		t.Fatalf("an open profile: %v", err)
	}
	theKeyedGateIs(t, dir, aKeyedGate{key: 1, profile: "profile-a", open: false})
	if err := s.stillOpen(); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile: %v", err)
	}
	// Pretend it loaded a key earlier: it still refuses to use it.
	s.blob, s.loaded = aBlobLike(), true
	if _, err := s.PublicKey(); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("PublicKey after the lock: %v", err)
	}
	if _, err := s.Sign([]byte("x")); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("Sign after the lock: %v", err)
	}
}

// ensure, with a real enclave key: a key made before the profile had a gate is
// served, then sealed, and is the same key afterwards.
func TestAMachineKeyMadeBeforeTheGateIsSealedWhenTheProfileHasOne(t *testing.T) {
	dir := t.TempDir()
	first := newSepSigner(dir).(*sepSigner)
	if !first.Available() {
		t.Skip("no usable Secure Enclave on this machine")
	}
	pub, err := first.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if env, _ := theStoredEnvelope(t, dir); env.Gate != "" {
		t.Fatal("the key was sealed before the profile had a gate")
	}

	theKeyedGateIs(t, dir, aKeyedGate{key: 0x21, profile: "profile-a", open: true})
	second := newSepSigner(dir).(*sepSigner)
	if err := second.ensure(); err != nil {
		t.Fatalf("a key made before the gate was not served: %v", err)
	}
	env, inside := theStoredEnvelope(t, dir)
	if env.Gate != gateScheme {
		t.Fatal("the key made before the gate was served and not sealed")
	}
	if bytes.Contains(inside, second.blob[:16]) {
		t.Fatal("the key is sealed in name only: its bytes are in the file")
	}
	again, err := newSepSigner(dir).(*sepSigner).PublicKey()
	if err != nil || !bytes.Equal(pub, again) {
		t.Fatalf("sealing changed the machine's key: %v", err)
	}
}

// ensure, with a real enclave key, under a gate from the start, then locked.
func TestAGatedMachineKeyIsMadeSealedAndRefusedWhenLocked(t *testing.T) {
	dir := t.TempDir()
	theKeyedGateIs(t, dir, aKeyedGate{key: 0x42, profile: "profile-a", open: true})
	s := newSepSigner(dir).(*sepSigner)
	if !s.Available() {
		t.Skip("no usable Secure Enclave on this machine")
	}
	env, inside := theStoredEnvelope(t, dir)
	if env.Gate != gateScheme || bytes.Contains(inside, s.blob[:16]) {
		t.Fatalf("a key made under a gate is not ciphertext on disk (gate %q)", env.Gate)
	}
	if _, err := s.Sign([]byte("hello")); err != nil {
		t.Fatalf("an open profile could not sign: %v", err)
	}

	theKeyedGateIs(t, dir, aKeyedGate{key: 0x42, profile: "profile-a", open: false})
	if _, err := s.Sign([]byte("hello")); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("the signer that held the key signed after the lock: %v", err)
	}
	later := newSepSigner(dir).(*sepSigner)
	if later.Available() {
		t.Fatal("a new signer was available while the profile was locked")
	}
	if _, err := later.PublicKey(); !errors.Is(err, ErrIdentityLocked) {
		t.Fatalf("a locked profile gave its public key: %v", err)
	}
	// And the platform's choice is the refusing signer, never the software one.
	asIfThisWereAMac(t)
	if got := NewPlatformSigner(dir); got.Platform() == "software" {
		t.Fatal("a locked Mac fell through to the software signer")
	}
}

// With a real enclave: a gated profile's key file swapped for another key's is
// refused, never adopted and sealed, and the profile's own record still names its
// own key. A deleted key file is replaced by a new key and the record follows.
func TestAGatedMacRefusesAKeyItsRecordDoesNotNameAndRecordsANewOne(t *testing.T) {
	dir := t.TempDir()
	theKeyedGateIs(t, dir, aKeyedGate{key: 0x42, profile: "profile-a", open: true})
	s := newSepSigner(dir).(*sepSigner)
	if !s.Available() {
		t.Skip("no usable Secure Enclave on this machine")
	}
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, theMachineKeyFileOnDisk, pub); err != nil {
		t.Fatalf("the key it made is not recorded: %v", err)
	}

	// Planted: an un-sealed file holding some other enclave key of this machine.
	planter := newSepSigner(t.TempDir()).(*sepSigner)
	if !planter.Available() {
		t.Skip("no usable Secure Enclave on this machine")
	}
	planted, err := os.ReadFile(planter.path())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(), planted, 0o600); err != nil {
		t.Fatal(err)
	}
	refused := newSepSigner(dir).(*sepSigner)
	if err := refused.ensure(); !errors.Is(err, ErrControllerKeyNotOurs) {
		t.Fatalf("a key file swapped for another key was adopted: %v", err)
	}
	if env, _ := theStoredEnvelope(t, dir); env.Gate != "" {
		t.Fatal("the planted key was sealed under the gate key")
	}

	// Deleted: the key file is gone and the record is of this signer's own key.
	if err := os.Remove(s.path()); err != nil {
		t.Fatal(err)
	}
	fresh := newSepSigner(dir).(*sepSigner)
	newPub, err := fresh.PublicKey()
	if err != nil || bytes.Equal(newPub, pub) {
		t.Fatalf("a new key was not made after the old one was deleted: %v", err)
	}
	if err := theControllerKeyIsTheOneWeMade(dir, theMachineKeyFileOnDisk, newPub); err != nil {
		t.Fatalf("the new key is not recorded: %v", err)
	}
}
