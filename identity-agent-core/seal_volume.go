package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"identity-agent-core/secureenclave"
)

// Preparing the volume an agent's data lives on, so that the machine's operator
// cannot read it.
//
// Run before anything mounts that volume. It asks the processor for a key
// derived from this software's measurement, and uses it to open the volume — or
// to create it, the first time.
//
// The key is never written down, never printed, and never passed as an
// argument. It exists in this process's memory for as long as it takes to hand
// it to cryptsetup on a pipe, and is asked for again on the next boot. There is
// nothing for an operator to find, because there is nothing stored: the
// processor will only hand this key to software that measures the same, and the
// operator cannot ask for it at all.
//
// What this protects, honestly: the disk, at rest and in the operator's hands.
// What it does not protect: an operator who launches this exact software and
// lets it decrypt the volume itself. That is a different problem and a harder
// one, and saying so is better than implying otherwise.
//
//	identity-agent-core seal-volume /dev/vdb tenant-data
func sealVolume(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: identity-agent-core seal-volume <device> [mapper-name]")
	}
	device := args[0]
	name := "tenant-data"
	if len(args) > 1 && args[1] != "" {
		name = args[1]
	}

	if _, err := os.Stat(device); err != nil {
		return fmt.Errorf("no volume at %s to prepare: %w", device, err)
	}

	// Bound to the measurement, so only this software can open the volume. A
	// different agent on the same machine derives a different key and simply
	// cannot read it.
	key, err := secureenclave.DeriveKey("tenant-data-volume-v1")
	if err != nil {
		return fmt.Errorf("could not derive the volume key, so this volume cannot be "+
			"protected from the machine's operator: %w", err)
	}
	defer zero(key)

	formatted, err := isLUKS(device)
	if err != nil {
		return err
	}
	if !formatted {
		// First boot. An unformatted volume is the only safe moment to do this:
		// formatting one that already carries data destroys an identity, so the
		// check above is what stands between a new instance and a wiped one.
		if err := run(key, "cryptsetup", "luksFormat", "--type", "luks2",
			"--batch-mode", "--key-file", "-", device); err != nil {
			return fmt.Errorf("could not encrypt the volume: %w", err)
		}
		if err := run(key, "cryptsetup", "open", "--key-file", "-", device, name); err != nil {
			return fmt.Errorf("could not open the volume just created: %w", err)
		}
		if out, err := exec.Command("mkfs.ext4", "-q", "/dev/mapper/"+name).CombinedOutput(); err != nil {
			return fmt.Errorf("could not put a filesystem on the encrypted volume: %w (%s)",
				err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if err := run(key, "cryptsetup", "open", "--key-file", "-", device, name); err != nil {
		// The volume exists and this software cannot open it. That means the
		// software changed: a different measurement derives a different key.
		// Said plainly, because the instinct is to reformat and that would
		// destroy the identity this volume exists to keep.
		return fmt.Errorf("this volume was encrypted by different software and cannot be "+
			"opened by this build. Its data is intact; recovering it needs the owner's key, "+
			"not a reformat: %w", err)
	}
	return nil
}

// isLUKS reports whether a volume has already been prepared.
func isLUKS(device string) (bool, error) {
	err := exec.Command("cryptsetup", "isLuks", device).Run()
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		// A clean "no" from cryptsetup. Any other failure is not an answer and
		// must not be read as one, because reading it as "no" reformats.
		return false, nil
	}
	return false, fmt.Errorf("could not tell whether %s is already encrypted, and "+
		"guessing would risk reformatting a volume that holds an identity: %w", device, err)
}

// run passes the key on a pipe.
//
// Not an argument and not a file: an argument is visible in the process list to
// every process on the machine, and a file is visible to whoever can read the
// filesystem — which on the volume's own disk is the operator.
func run(key []byte, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = bytes.NewReader(key)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// zero overwrites a key once it is no longer needed.
//
// Not a guarantee — Go may have copied it during a garbage collection — but the
// copy this code holds is the one it can do something about.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
