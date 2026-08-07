package update

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const healthCheckTimeout = 60 * time.Second

// Applier downloads, verifies, and applies artifacts (UM-4, UM-6, UM-7, UM-12).
type Applier struct {
	HTTPClient     *http.Client
	StagingDir     string
	HealthCheckURL string
	Platform       string
	OnHealthCheck  func() error
}

// ApplyResult describes the outcome of an apply attempt.
type ApplyResult struct {
	Component  string `json:"component"`
	Version    string `json:"version"`
	Applied    bool   `json:"applied"`
	RolledBack bool   `json:"rolled_back"`
	Message    string `json:"message,omitempty"`
}

func NewApplier(stagingDir, healthCheckURL, platform string) *Applier {
	return &Applier{
		HTTPClient:     &http.Client{Timeout: 10 * time.Minute},
		StagingDir:     stagingDir,
		HealthCheckURL: healthCheckURL,
		Platform:       platform,
	}
}

// ApplyComponent downloads and applies a component artifact.
// Code-plane only: never writes config-plane (KERI-governed) state (UM-12).
func (a *Applier) ApplyComponent(component string, entry ComponentEntry, targetPath string) (*ApplyResult, error) {
	art, err := entry.ComponentForPlatform(a.Platform)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(a.StagingDir, 0755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return nil, err
	}

	tmpPath := filepath.Join(a.StagingDir, component+"-"+entry.Version+".tmp")
	finalPath := targetPath
	prevPath := targetPath + ".prev"

	data, err := a.download(art.URL)
	if err != nil {
		return nil, err
	}
	if err := VerifyArtifactBytes(data, *art, false); err != nil {
		return nil, err
	}

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return nil, err
	}

	// Verify-then-atomic-rename (UM-6): verified file moves to final location atomically.
	if _, err := os.Stat(finalPath); err == nil {
		_ = os.Remove(prevPath)
		if err := os.Rename(finalPath, prevPath); err != nil {
			return nil, fmt.Errorf("backup failed: %w", err)
		}
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = a.tryRestore(prevPath, finalPath)
		return nil, fmt.Errorf("atomic rename failed: %w", err)
	}

	healthErr := a.waitForHealth()
	if healthErr != nil {
		restored := a.tryRestore(prevPath, finalPath)
		return &ApplyResult{
			Component:  component,
			Version:    entry.Version,
			Applied:    false,
			RolledBack: restored,
			Message:    fmt.Sprintf("health check failed: %v", healthErr),
		}, nil
	}

	_ = os.Remove(prevPath)
	return &ApplyResult{
		Component: component,
		Version:   entry.Version,
		Applied:   true,
	}, nil
}

func (a *Applier) download(url string) ([]byte, error) {
	resp, err := a.HTTPClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20))
}

func (a *Applier) waitForHealth() error {
	deadline := time.Now().Add(healthCheckTimeout)
	for time.Now().Before(deadline) {
		var err error
		if a.OnHealthCheck != nil {
			err = a.OnHealthCheck()
		} else if a.HealthCheckURL != "" {
			resp, getErr := a.HTTPClient.Get(a.HealthCheckURL)
			if getErr == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
				err = fmt.Errorf("health status %d", resp.StatusCode)
			} else {
				err = getErr
			}
		} else {
			return nil
		}
		time.Sleep(2 * time.Second)
		if err != nil {
			continue
		}
	}
	if a.OnHealthCheck != nil {
		return a.OnHealthCheck()
	}
	return fmt.Errorf("health check timed out after %s", healthCheckTimeout)
}

func (a *Applier) tryRestore(prevPath, finalPath string) bool {
	if _, err := os.Stat(prevPath); err != nil {
		return false
	}
	_ = os.Remove(finalPath)
	if err := os.Rename(prevPath, finalPath); err != nil {
		return false
	}
	return true
}
