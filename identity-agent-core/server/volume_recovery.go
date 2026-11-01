package server

import (
	"errors"
	"fmt"
	"identity-agent-core/childenv"
	"os"
	"os/exec"
	"strings"
	"testing"
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

// recoveryChildEnv marks the process addVolumeRecoveryVia starts. A binary that
// does not know the command would run the Identity Agent again, reach this
// code again, and start another, without end; the mark stops the second.
const recoveryChildEnv = "IDENTITY_AGENT_VOLUME_RECOVERY_CHILD"

var (
	errRecoveryChild     = errors.New("this is already the recovery command's process, so it will not start another")
	errRecoveryUnderTest = errors.New("a test reached the real volume; set CoreServer.volumeRecovery")
)

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

	if os.Getenv(recoveryChildEnv) != "" {
		return errRecoveryChild
	}
	// Under go test, os.Executable is the test binary, which does not know the
	// command and would run the whole suite again, to reach here again. A test
	// that means to arrange recovery sets CoreServer.volumeRecovery.
	if testing.Testing() {
		return errRecoveryUnderTest
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find this binary to run its recovery command: %w", err)
	}

	args := append([]string{"add-owner-recovery", device}, keysB64...)
	cmd := exec.Command(self, args...)
	cmd.Env = append(childenv.Environ(), recoveryChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
