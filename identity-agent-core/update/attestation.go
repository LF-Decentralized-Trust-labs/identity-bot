package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"github.com/zeebo/blake3"
)

// GenuinenessAxis reports code-plane binary attestation (SEAM-20 §5.3).
// Trust gates on blake3_256; sha256 fields are interop-only.
type GenuinenessAxis struct {
	Status             string `json:"status"` // verified | mismatch | unknown
	RunningBlake3_256  string `json:"running_blake3_256,omitempty"`
	ExpectedBlake3_256 string `json:"expected_blake3_256,omitempty"`
	RunningSHA256      string `json:"running_sha256,omitempty"`
	ExpectedSHA256     string `json:"expected_sha256,omitempty"`
	InstalledVersion   string `json:"installed_version,omitempty"`
	Message            string `json:"message,omitempty"`
}

// CurrencyAxis reports version currency (warn-only; never hard-gates trust).
type CurrencyAxis struct {
	Status           string `json:"status"` // current | outdated | unknown
	InstalledVersion string `json:"installed_version,omitempty"`
	LatestVersion    string `json:"latest_version,omitempty"`
	Message          string `json:"message,omitempty"`
}

// Attestation provides continuous genuineness checks against the verified manifest.
type Attestation struct {
	mu sync.RWMutex

	binaryPath       string
	installedVersion map[string]string
	manifest         *Manifest
	platform         string
}

func NewAttestation(binaryPath, platform string) *Attestation {
	return &Attestation{
		binaryPath:       binaryPath,
		installedVersion: make(map[string]string),
		platform:         platform,
	}
}

func (a *Attestation) SetInstalledVersions(v map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.installedVersion = copyStringMap(v)
}

func (a *Attestation) SetManifest(m *Manifest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.manifest = m
}

// Genuineness compares running binary Blake3-256 to manifest-published blake3_256.
// SHA-256 is surfaced for interop only and never gates verification.
func (a *Attestation) Genuineness() GenuinenessAxis {
	a.mu.RLock()
	defer a.mu.RUnlock()

	runningBlake, runningSHA, err := hashFileDigests(a.binaryPath)
	if err != nil {
		return GenuinenessAxis{
			Status:  "unknown",
			Message: fmt.Sprintf("cannot hash running binary: %v", err),
		}
	}

	if a.manifest == nil {
		return GenuinenessAxis{
			Status:            "unknown",
			RunningBlake3_256: runningBlake,
			RunningSHA256:     runningSHA,
			Message:           "no verified manifest cached",
		}
	}

	entry, ok := a.manifest.Components["go_backend"]
	if !ok {
		return GenuinenessAxis{
			Status:            "unknown",
			RunningBlake3_256: runningBlake,
			RunningSHA256:     runningSHA,
			Message:           "manifest has no go_backend component",
		}
	}

	installed := a.installedVersion["go_backend"]
	if installed == "" {
		installed = entry.Version
	}

	art, err := entry.ComponentForPlatform(a.platform)
	if err != nil {
		return GenuinenessAxis{
			Status:            "unknown",
			RunningBlake3_256: runningBlake,
			RunningSHA256:     runningSHA,
			Message:           err.Error(),
		}
	}

	if art.Blake3_256 == "" {
		return GenuinenessAxis{
			Status:             "unknown",
			RunningBlake3_256:  runningBlake,
			RunningSHA256:      runningSHA,
			InstalledVersion:   installed,
			Message:            "manifest artifact missing blake3_256 (trust gate field)",
		}
	}

	axis := GenuinenessAxis{
		RunningBlake3_256:  runningBlake,
		ExpectedBlake3_256: art.Blake3_256,
		RunningSHA256:      runningSHA,
		ExpectedSHA256:     art.SHA256,
		InstalledVersion:   installed,
	}

	if runningBlake == art.Blake3_256 {
		axis.Status = "verified"
		return axis
	}

	axis.Status = "mismatch"
	axis.Message = "running binary does not match signed manifest blake3_256"
	return axis
}

// Currency compares installed component versions to the cached manifest (warn-only).
func (a *Attestation) Currency() CurrencyAxis {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.manifest == nil {
		return CurrencyAxis{
			Status:  "unknown",
			Message: "no verified manifest cached",
		}
	}

	entry, ok := a.manifest.Components["go_backend"]
	if !ok {
		return CurrencyAxis{
			Status:  "unknown",
			Message: "manifest has no go_backend component",
		}
	}

	installed := a.installedVersion["go_backend"]
	if installed == "" {
		installed = "0"
	}

	axis := CurrencyAxis{
		InstalledVersion: installed,
		LatestVersion:    entry.Version,
	}

	if CompareVersion(installed, entry.Version) < 0 {
		axis.Status = "outdated"
		axis.Message = fmt.Sprintf("installed %s is behind manifest %s", installed, entry.Version)
		return axis
	}

	axis.Status = "current"
	return axis
}

func hashFileDigests(path string) (blake3Hex, sha256Hex string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	blake := blake3.Sum256(data)
	sha := sha256.Sum256(data)
	return hex.EncodeToString(blake[:]), hex.EncodeToString(sha[:]), nil
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}