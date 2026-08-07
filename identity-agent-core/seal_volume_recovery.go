package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
)

// A way back in when the processor stops handing over the key.
//
// The volume opens with a key derived from this software's measurement, which
// is what keeps the operator out. It is also what makes the volume fragile: the
// measurement moves whenever the image is rebuilt, and the key the processor
// derives moves with the firmware level — so an ordinary security patch from
// the processor's manufacturer, applied by an operator who has done nothing
// wrong, leaves every volume on the machine unopenable.
//
// Without a second way in, that is not an outage. It is permanent data loss on
// a maintenance event nobody chose.
//
// So a second key slot holds a random secret, and that secret is sealed to the
// owner's public key. The instance keeps no copy: it can create the way back in
// and can never use it. Only the owner can, from a seed phrase that never
// touches this machine.
//
// The sealed secret lives in the volume's own header, outside the encrypted
// area, because it is needed precisely when the encrypted area cannot be
// opened. Storing it inside would be a key locked in the box it opens.

// recoveryTokenType marks the header entry as ours.
const recoveryTokenType = "identity-agent-owner-recovery-v1"

// ownerRecoverySlot is what is written into the volume header.
//
// Everything here is safe in the clear: the sealed secret is useless without
// the owner's private half, and the header is readable by anyone holding the
// volume — which is the point, since recovery happens when nothing else works.
type ownerRecoverySlot struct {
	Type string `json:"type"`
	// Keyslots is the LUKS field naming which slots this token unlocks.
	Keyslots []string `json:"keyslots"`
	// Owners holds one sealed copy per owner, any of which recovers alone. An
	// organisation has an owner per signer, and requiring several to agree
	// would mean losing the data when one is unreachable.
	Owners []sealedForOwner `json:"owners"`
}

type sealedForOwner struct {
	// No owner is named. An organisation's list of owners is not something to
	// publish on every copy of its volume, and trying a handful of slots costs
	// nothing.
	EphemeralPublicKeyB64 string `json:"epk_b64"`
	WrappedSecretB64      string `json:"wrapped_b64"`
	NonceB64              string `json:"nonce_b64"`
}

// addOwnerRecovery gives the owner a way to open this volume.
//
// Called once the owner is known, which is at adoption rather than at first
// boot: before that there is no owner to seal anything to. The window between
// the two is the one time a volume exists with no way back in, and it is short
// by construction because an instance is adopted before it is used.
func addOwnerRecovery(device string, sealPublicKeysB64 []string, currentKey []byte) error {
	if len(sealPublicKeysB64) == 0 {
		return fmt.Errorf("no owner keys supplied, so there is nobody to give a way back in to")
	}

	// The secret that opens the second slot. Random, used once, and never
	// stored anywhere this machine can read it afterwards.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("could not generate a recovery secret: %w", err)
	}
	defer zero(secret)

	slot := ownerRecoverySlot{
		Type:     recoveryTokenType,
		Keyslots: []string{"1"},
	}
	for i, pubB64 := range sealPublicKeysB64 {
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubB64))
		if err != nil {
			return fmt.Errorf("owner key %d is not valid base64: %w", i, err)
		}
		epk, wrapped, nonce, err := backup.SealBEK(pub, secret)
		if err != nil {
			return fmt.Errorf("could not seal the recovery secret to owner key %d: %w", i, err)
		}
		slot.Owners = append(slot.Owners, sealedForOwner{
			EphemeralPublicKeyB64: base64.StdEncoding.EncodeToString(epk),
			WrappedSecretB64:      base64.StdEncoding.EncodeToString(wrapped),
			NonceB64:              base64.StdEncoding.EncodeToString(nonce),
		})
	}

	// The slot is added using the key that already opens the volume, which is
	// the only key this instance has. Adding it before sealing would leave a
	// volume with a slot nobody can reach if the sealing then failed.
	if err := addKeySlot(device, currentKey, secret); err != nil {
		return err
	}

	body, err := json.Marshal(slot)
	if err != nil {
		return fmt.Errorf("could not encode the recovery record: %w", err)
	}
	if err := importToken(device, body); err != nil {
		// The slot exists and its secret is sealed, but nothing records how to
		// find it — which is the same as having no way back in, and worse
		// because it looks like there is one. Removed rather than left.
		_ = removeKeySlot(device, currentKey, secret)
		return fmt.Errorf("could not record how to use the recovery slot, so it was removed "+
			"rather than left looking usable: %w", err)
	}
	return nil
}

// hasOwnerRecovery reports whether a way back in already exists.
//
// Checked before adding one, because adding a second would consume a key slot
// on every adoption attempt and leave secrets nobody holds.
func hasOwnerRecovery(device string) (bool, error) {
	out, err := exec.Command("cryptsetup", "luksDump", "--dump-json-metadata", device).Output()
	if err != nil {
		return false, fmt.Errorf("could not read the volume's header: %w", err)
	}
	var meta struct {
		Tokens map[string]struct {
			Type string `json:"type"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(out, &meta); err != nil {
		return false, fmt.Errorf("the volume's header could not be read as JSON: %w", err)
	}
	for _, t := range meta.Tokens {
		if t.Type == recoveryTokenType {
			return true, nil
		}
	}
	return false, nil
}

func addKeySlot(device string, existing, added []byte) error {
	cmd := exec.Command("cryptsetup", "luksAddKey", "--batch-mode",
		"--key-file", "-", "--keyfile-size", fmt.Sprint(len(existing)),
		device, "/dev/stdin")
	// Both keys go in on the same pipe: the one that proves we may add a slot,
	// then the one being added. Neither is ever an argument, which every
	// process on the machine could read.
	cmd.Stdin = strings.NewReader(string(existing) + string(added))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not add the recovery slot: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeKeySlot(device string, existing, remove []byte) error {
	cmd := exec.Command("cryptsetup", "luksRemoveKey", "--batch-mode", device, "/dev/stdin")
	cmd.Stdin = strings.NewReader(string(remove))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not remove the recovery slot: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	_ = existing
	return nil
}

func importToken(device string, body []byte) error {
	cmd := exec.Command("cryptsetup", "token", "import", device)
	cmd.Stdin = strings.NewReader(string(body))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not write the recovery record into the volume header: %w (%s)",
			err, strings.TrimSpace(string(out)))
	}
	return nil
}

// addOwnerRecoveryCommand is the operator-facing entry point.
//
//	identity-agent-core add-owner-recovery /dev/vdb <owner-seal-key-b64>...
//
// Idempotent: a volume that already has a way back in is left alone rather than
// given a second one, because each attempt would consume a key slot and leave a
// secret nobody holds.
func addOwnerRecoveryCommand(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: identity-agent-core add-owner-recovery <device> <owner-seal-key-b64>...")
	}
	device := args[0]

	already, err := hasOwnerRecovery(device)
	if err != nil {
		return err
	}
	if already {
		// Not an error. Adoption can be retried, and a retry must not keep
		// adding slots.
		return nil
	}

	key, err := secureenclave.DeriveKey("tenant-data-volume-v1")
	if err != nil {
		return fmt.Errorf("could not derive this volume's current key, so no recovery slot "+
			"can be added to it: %w", err)
	}
	defer zero(key)

	return addOwnerRecovery(device, args[1:], key)
}

// addOwnerRecoveryCommandFor is addOwnerRecoveryCommand with the volume key
// supplied rather than derived, so the idempotence can be exercised off a
// processor that can derive one.
func addOwnerRecoveryCommandFor(device string, sealPublicKeysB64 []string, currentKey []byte) error {
	already, err := hasOwnerRecovery(device)
	if err != nil {
		return err
	}
	if already {
		return nil
	}
	return addOwnerRecovery(device, sealPublicKeysB64, currentKey)
}
