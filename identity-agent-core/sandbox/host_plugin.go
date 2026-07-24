package sandbox

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
)

// Host plug-ins (manifest isolation: "host") run deliberately WITHOUT the sandbox
// because their job is the host itself — the first case is a native computer-use
// driver, whose primitives must reach the real screen and input. They are
// constrained differently, not less:
//
//   - dumb executors: single deterministic primitives per request, no agentic loop
//     (governance targets the BRAIN that calls them; simplicity secures the hands);
//   - the binary's hash is pinned in the manifest and verified before EVERY launch
//     (verifyHostBinary), so the unsandboxed thing that runs is exactly what the
//     manifest was written for;
//   - their host_control capabilities are never remote-invocable (structural rule
//     in the Authorizer) and are serialized per capability by hostControlLock —
//     one screen = one driver, so concurrent invocations queue rather than fight.

// verifyHostBinary checks a host plug-in's resolved binary against its pinned hash.
// Called at launch; a mismatch (or a missing pin) refuses the launch.
func verifyHostBinary(manifest *AppManifest) error {
	if manifest.EffectiveIsolation() != "host" {
		return nil
	}
	if manifest.Binary == nil || manifest.Binary.Path == "" {
		return fmt.Errorf("host plug-in %q has no resolved binary for this platform", manifest.ID)
	}
	pinned := manifest.Binary.Hash
	if pinned == "" {
		return fmt.Errorf("host plug-in %q binary has no pinned hash — refusing to launch unsandboxed", manifest.ID)
	}
	want, ok := strings.CutPrefix(pinned, "blake3:")
	if !ok {
		return fmt.Errorf("host plug-in %q: unsupported hash format %q (want blake3:<hex>)", manifest.ID, pinned)
	}
	data, err := os.ReadFile(manifest.Binary.Path)
	if err != nil {
		return fmt.Errorf("host plug-in %q: cannot read binary for verification: %w", manifest.ID, err)
	}
	sum := blake3.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, want) {
		return fmt.Errorf("host plug-in %q: binary hash mismatch (manifest pins blake3:%s, file is blake3:%s) — refusing to launch", manifest.ID, want, got)
	}
	return nil
}

// hostControlLocks serializes invocations per host_control capability: one screen =
// one driver. Callers queue; they never interleave primitives on the same machine.
var (
	hostControlMu    sync.Mutex
	hostControlLocks = map[string]*sync.Mutex{}
)

func hostControlLock(capabilityID string) *sync.Mutex {
	hostControlMu.Lock()
	defer hostControlMu.Unlock()
	l, ok := hostControlLocks[capabilityID]
	if !ok {
		l = &sync.Mutex{}
		hostControlLocks[capabilityID] = l
	}
	return l
}
