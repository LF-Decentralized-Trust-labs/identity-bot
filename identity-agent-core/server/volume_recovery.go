package server

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Asking this instance's own binary to add the owner's way back into the
// encrypted volume.
//
// Out of process rather than inline, and that is deliberate. The work needs the
// key the processor derives, and adding a key slot needs cryptsetup — neither
// belongs in the middle of an HTTP handler serving an adoption. Running it as a
// separate command keeps the key out of a long-lived process's memory, and
// keeps the handler's failure modes to "it worked" or "it did not".
//
// Silently absent where there is no encrypted volume, which is every agent on a
// machine its user owns. Nothing to recover means nothing to arrange.
type volumeRecoveryRunner func(keysB64 []string) error

// tenantVolumeDevice is the volume an agent's data lives on where one exists.
const tenantVolumeDevice = "/dev/vdb"

func (s *CoreServer) addVolumeRecovery(keysB64 []string) error {
	if s.volumeRecovery != nil {
		return s.volumeRecovery(keysB64)
	}
	return addVolumeRecoveryVia(tenantVolumeDevice, keysB64)
}

func addVolumeRecoveryVia(device string, keysB64 []string) error {
	if _, err := os.Stat(device); err != nil {
		// No encrypted volume on this machine. Ordinary, and not a failure.
		return nil
	}
	if len(keysB64) == 0 {
		return fmt.Errorf("no owner keys, so there is nobody to give a way back in to")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find this binary to run its recovery command: %w", err)
	}

	args := append([]string{"add-owner-recovery", device}, keysB64...)
	out, err := exec.Command(self, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
