package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
)

// GenuinenessAxis reports code-plane binary attestation (SEAM-20 §5.3).
type GenuinenessAxis struct {
	Status          string `json:"status"`           // verified | mismatch | unknown
	RunningSHA256   string `json:"running_sha256,omitempty"`
	ExpectedSHA256  string `json:"expected_sha256,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`
	Message         string `json:"message,omitempty"`
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

// Genuineness compares running binary SHA-256 to manifest-published SHA-256.
func (a *Attestation) Genuineness() GenuinenessAxis {
	a.mu.RLock()
	defer a.mu.RUnlock()

	running, err := hashFileSHA256(a.binaryPath)
	if err != nil {
		return GenuinenessAxis{
			Status:  "unknown",
			Message: fmt.Sprintf("cannot hash running binary: %v", err),
		}
	}

	if a.manifest == nil {
		return GenuinenessAxis{
			Status:        "unknown",
			RunningSHA256: running,
			Message:       "no verified manifest cached",
		}
	}

	entry, ok := a.manifest.Components["go_backend"]
	if !ok {
		return GenuinenessAxis{
			Status:        "unknown",
			RunningSHA256: running,
			Message:       "manifest has no go_backend component",
		}
	}

	installed := a.installedVersion["go_backend"]
	if installed == "" {
		installed = entry.Version
	}

	art, err := entry.ComponentForPlatform(a.platform)
	if err != nil {
		return GenuinenessAxis{
			Status:        "unknown",
			RunningSHA256: running,
			Message:       err.Error(),
		}
	}

	if art.SHA256 == "" {
		return GenuinenessAxis{
			Status:           "unknown",
			RunningSHA256:    running,
			InstalledVersion: installed,
			Message:          "manifest artifact missing sha256 (interop field)",
		}
	}

	if running == art.SHA256 {
		return GenuinenessAxis{
			Status:           "verified",
			RunningSHA256:    running,
			ExpectedSHA256:   art.SHA256,
			InstalledVersion: installed,
		}
	}

	return GenuinenessAxis{
		Status:           "mismatch",
		RunningSHA256:    running,
		ExpectedSHA256:   art.SHA256,
		InstalledVersion: installed,
		Message:          "running binary does not match signed manifest sha256",
	}
}

func hashFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}