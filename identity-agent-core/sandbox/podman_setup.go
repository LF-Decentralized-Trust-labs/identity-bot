package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

type PodmanSetupStatus struct {
	Step     string `json:"step"`
	Status   string `json:"status"`
	Message  string `json:"message"`
	Error    string `json:"error,omitempty"`
	Done     bool   `json:"done"`
	Platform string `json:"platform"`
}

var (
	podmanSetupMu     sync.Mutex
	podmanSetupStatus *PodmanSetupStatus
	setupInProgress   bool
)

func TryStartSetup() bool {
	podmanSetupMu.Lock()
	defer podmanSetupMu.Unlock()
	if setupInProgress {
		return false
	}
	setupInProgress = true
	return true
}

func FinishSetup() {
	podmanSetupMu.Lock()
	defer podmanSetupMu.Unlock()
	setupInProgress = false
}

func GetPodmanSetupStatus() *PodmanSetupStatus {
	podmanSetupMu.Lock()
	defer podmanSetupMu.Unlock()
	if podmanSetupStatus == nil {
		return &PodmanSetupStatus{
			Step:     "idle",
			Status:   "idle",
			Message:  "No setup in progress",
			Platform: runtime.GOOS,
		}
	}
	cp := *podmanSetupStatus
	return &cp
}

func setSetupStatus(step, status, message string) {
	podmanSetupMu.Lock()
	defer podmanSetupMu.Unlock()
	podmanSetupStatus = &PodmanSetupStatus{
		Step:     step,
		Status:   status,
		Message:  message,
		Platform: runtime.GOOS,
	}
}

func setSetupError(step, errMsg string) {
	podmanSetupMu.Lock()
	defer podmanSetupMu.Unlock()
	podmanSetupStatus = &PodmanSetupStatus{
		Step:     step,
		Status:   "error",
		Message:  "Setup failed",
		Error:    errMsg,
		Platform: runtime.GOOS,
	}
}

func setSetupDone() {
	podmanSetupMu.Lock()
	defer podmanSetupMu.Unlock()
	podmanSetupStatus = &PodmanSetupStatus{
		Step:     "done",
		Status:   "complete",
		Message:  "Podman is ready",
		Done:     true,
		Platform: runtime.GOOS,
	}
}

func RunPodmanSetup(action string) error {
	switch action {
	case "install":
		return runPodmanInstall()
	case "init-machine":
		return runPodmanMachineInit()
	case "start-machine":
		return runPodmanMachineStart()
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func runPodmanInstall() error {
	setSetupStatus("install", "running", "Installing Podman...")

	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pm := detectPackageManager()

	switch runtime.GOOS {
	case "windows":
		if pm != "winget" {
			setSetupError("install", "winget is not available. Please install Podman manually from https://podman-desktop.io/downloads")
			return fmt.Errorf("winget not available")
		}
		cmd = exec.CommandContext(ctx, "winget", "install", "-e", "--id", "RedHat.Podman",
			"--accept-package-agreements", "--accept-source-agreements")
	case "darwin":
		if pm != "brew" {
			setSetupError("install", "Homebrew is not installed. Please install Homebrew first (https://brew.sh) or download Podman from https://podman-desktop.io/downloads")
			return fmt.Errorf("homebrew not available")
		}
		cmd = exec.CommandContext(ctx, "brew", "install", "podman")
	case "linux":
		switch pm {
		case "apt":
			cmd = exec.CommandContext(ctx, "sudo", "apt-get", "install", "-y", "podman")
		case "dnf":
			cmd = exec.CommandContext(ctx, "sudo", "dnf", "install", "-y", "podman")
		default:
			setSetupError("install", "No supported package manager found (apt-get or dnf). Please install Podman manually from https://podman.io/docs/installation")
			return fmt.Errorf("no supported package manager found")
		}
	default:
		setSetupError("install", fmt.Sprintf("Unsupported platform: %s", runtime.GOOS))
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := fmt.Sprintf("Install command failed: %v — %s", err, strings.TrimSpace(stderr.String()))
		setSetupError("install", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	setSetupStatus("install", "complete", "Podman installed successfully")
	return nil
}

func runPodmanMachineInit() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		setSetupStatus("init-machine", "complete", "Machine init not needed on Linux")
		return nil
	}

	setSetupStatus("init-machine", "running", "Initializing Podman machine...")

	podmanBin := findPodmanCLI()
	if podmanBin == "" {
		setSetupError("init-machine", "Podman is not installed")
		return fmt.Errorf("podman not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, podmanBin, "machine", "init")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if strings.Contains(errStr, "already exists") || strings.Contains(strings.ToLower(errStr), "machine already") {
			setSetupStatus("init-machine", "complete", "Podman machine already exists")
			return nil
		}
		errMsg := fmt.Sprintf("Machine init failed: %v — %s", err, errStr)
		setSetupError("init-machine", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	setSetupStatus("init-machine", "complete", "Podman machine initialized")
	return nil
}

func runPodmanMachineStart() error {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		setSetupStatus("start-machine", "complete", "Machine start not needed on Linux")
		return nil
	}

	setSetupStatus("start-machine", "running", "Starting Podman machine...")

	podmanBin := findPodmanCLI()
	if podmanBin == "" {
		setSetupError("start-machine", "Podman is not installed")
		return fmt.Errorf("podman not installed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, podmanBin, "machine", "start")
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errStr := strings.TrimSpace(stderr.String())
		if strings.Contains(errStr, "already running") || strings.Contains(strings.ToLower(errStr), "is already running") {
			setSetupStatus("start-machine", "complete", "Podman machine is already running")
			return nil
		}
		errMsg := fmt.Sprintf("Machine start failed: %v — %s", err, errStr)
		setSetupError("start-machine", errMsg)
		return fmt.Errorf("%s", errMsg)
	}

	setSetupDone()
	return nil
}
