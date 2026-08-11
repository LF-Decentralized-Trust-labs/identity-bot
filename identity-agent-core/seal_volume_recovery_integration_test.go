package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/backup"
)

// Against a real encrypted volume, with real cryptsetup.
//
// Everything else about recovery is tested at the sealing layer, which is where
// the cryptography is. This is where the integration is: how the keys are
// handed to cryptsetup, whether the header record is accepted, and whether what
// comes back out of luksDump can be read. Those are the parts that have failed
// repeatedly in this work, and none of them can be checked without a device.
//
// Needs root and a loop device, so it runs only when asked:
//
//	sudo SNP_LUKS_INTEGRATION=1 go test -run Integration ./...
func TestOwnerRecoveryAgainstARealVolume(t *testing.T) {
	if os.Getenv("SNP_LUKS_INTEGRATION") != "1" {
		t.Skip("set SNP_LUKS_INTEGRATION=1 and run as root to exercise real cryptsetup")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to attach a loop device")
	}

	dir := t.TempDir()
	backing := filepath.Join(dir, "volume.img")
	if err := exec.Command("truncate", "-s", "64M", backing).Run(); err != nil {
		t.Fatalf("could not make a backing file: %v", err)
	}

	out, err := exec.Command("losetup", "--find", "--show", backing).Output()
	if err != nil {
		t.Fatalf("could not attach a loop device: %v", err)
	}
	device := strings.TrimSpace(string(out))
	defer exec.Command("losetup", "-d", device).Run()

	// The key an instance would have derived from its measurement.
	instanceKey := make([]byte, 32)
	for i := range instanceKey {
		instanceKey[i] = byte(i + 1)
	}

	if err := run(instanceKey, "cryptsetup", "luksFormat", "--type", "luks2",
		"--batch-mode", "--key-file", "-", device); err != nil {
		t.Fatalf("could not create the volume: %v", err)
	}

	// The owner, holding a seed this machine never sees.
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	ownerPriv, ownerPub, err := backup.DeriveSealKeypair(seed)
	if err != nil {
		t.Fatal(err)
	}

	if err := addOwnerRecovery(device, []string{base64.StdEncoding.EncodeToString(ownerPub)}, instanceKey); err != nil {
		t.Fatalf("could not add the recovery slot: %v", err)
	}

	// It records itself, so a second attempt does not add another.
	present, err := hasOwnerRecovery(device)
	if err != nil || !present {
		t.Fatalf("the recovery record was not found afterwards (%v, %v)", present, err)
	}
	if err := addOwnerRecoveryCommandFor(device, []string{base64.StdEncoding.EncodeToString(ownerPub)}, instanceKey); err != nil {
		t.Fatalf("a second attempt was not a no-op: %v", err)
	}

	// THE POINT: the owner recovers the secret from the header and opens the
	// volume with it, using nothing this machine holds.
	dump, err := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", device).Output()
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Tokens map[string]json.RawMessage `json:"tokens"`
	}
	if err := json.Unmarshal(dump, &meta); err != nil {
		t.Fatal(err)
	}

	var recovered []byte
	for _, raw := range meta.Tokens {
		var slot ownerRecoverySlot
		if json.Unmarshal(raw, &slot) != nil || slot.Type != recoveryTokenType {
			continue
		}
		for _, o := range slot.Owners {
			epk, _ := base64.StdEncoding.DecodeString(o.EphemeralPublicKeyB64)
			wrapped, _ := base64.StdEncoding.DecodeString(o.WrappedSecretB64)
			nonce, _ := base64.StdEncoding.DecodeString(o.NonceB64)
			if got, err := backup.UnsealBEK(ownerPriv, epk, wrapped, nonce); err == nil {
				recovered = got
			}
		}
	}
	if len(recovered) == 0 {
		t.Fatal("the owner could not recover a secret from the volume's own header")
	}

	// Opened with the recovered secret alone — not the instance's key.
	name := "recovery-test-" + filepath.Base(dir)
	if err := run(recovered, "cryptsetup", "open", "--key-file", "-", device, name); err != nil {
		t.Fatalf("the recovered secret did not open the volume, so an owner could not "+
			"get their data back after a firmware update: %v", err)
	}
	_ = exec.Command("cryptsetup", "close", name).Run()

	// And a wrong secret must not.
	wrong := make([]byte, 32)
	if err := run(wrong, "cryptsetup", "open", "--key-file", "-", device, name+"-wrong"); err == nil {
		exec.Command("cryptsetup", "close", name+"-wrong").Run()
		t.Fatal("an arbitrary secret opened the volume")
	}
}
