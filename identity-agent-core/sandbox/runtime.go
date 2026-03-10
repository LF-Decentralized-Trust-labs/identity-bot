package sandbox

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type RuntimeStatus struct {
	State       string `json:"state"`
	ContainerID string `json:"container_id,omitempty"`
	ProcessPID  int    `json:"process_pid,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
	DisplayURL  string `json:"display_url,omitempty"`
	Error       string `json:"error,omitempty"`
}

type RuntimeStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsedMB int64   `json:"memory_used_mb"`
	MemoryLimitMB int64  `json:"memory_limit_mb"`
	DiskUsedMB   int64   `json:"disk_used_mb"`
	DiskLimitMB  int64   `json:"disk_limit_mb"`
	NetworkTxKB  int64   `json:"network_tx_kb"`
	NetworkRxKB  int64   `json:"network_rx_kb"`
	EgressKbps   int64   `json:"egress_kbps"`
	IngressKbps  int64   `json:"ingress_kbps"`
}

type NetworkConfig struct {
	ProxyPort    int               `json:"proxy_port"`
	DisplayPort  int               `json:"display_port"`
	AgentAPIPort int               `json:"agent_api_port"`
	NetworkName  string            `json:"network_name"`
	HostIP       string            `json:"host_ip"`
	ProxyURL     string            `json:"proxy_url"`
	EnvVars      map[string]string `json:"env_vars"`
}

type PullProgress struct {
	Status     string  `json:"status"`
	Layer      string  `json:"layer,omitempty"`
	Progress   float64 `json:"progress"`
	TotalBytes int64   `json:"total_bytes"`
	DoneBytes  int64   `json:"done_bytes"`
}

type PullProgressCallback func(progress PullProgress)

type Runtime interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Status(ctx context.Context) (*RuntimeStatus, error)
	Stats(ctx context.Context) (*RuntimeStats, error)
	NetworkConfig() *NetworkConfig
}

type ContainerEngineStatus struct {
	Available    bool   `json:"available"`
	Installed    bool   `json:"installed"`
	Running      bool   `json:"running"`
	Version      string `json:"version,omitempty"`
	Error        string `json:"error,omitempty"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

func machineArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	case "386":
		return "i386"
	default:
		return runtime.GOARCH
	}
}

func CheckContainerEngine() *ContainerEngineStatus {
	status := &ContainerEngineStatus{
		Platform:     runtime.GOOS,
		Architecture: machineArch(),
	}

	podmanBin := findPodmanCLI()
	if podmanBin == "" {
		status.Error = "Podman is not installed. Install Podman from https://podman-desktop.io/downloads"
		return status
	}
	status.Installed = true

	running, version := checkPodmanInfo(podmanBin)
	if running {
		status.Running = true
		status.Available = true
		status.Version = version
		return status
	}

	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		machineRunning := checkPodmanMachine(podmanBin)
		if !machineRunning {
			status.Error = "Podman is installed but the machine is not running. Run 'podman machine init && podman machine start' to start it."
			return status
		}
	}

	status.Error = "Podman is installed but the engine is not responding. Please ensure Podman is fully started."
	return status
}

func findPodmanCLI() string {
	if path, err := exec.LookPath("podman"); err == nil {
		return path
	}
	return ""
}

func checkPodmanInfo(podmanBin string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, podmanBin, "info", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return false, ""
	}

	var info struct {
		Version struct {
			Version string `json:"Version"`
		} `json:"version"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return true, ""
	}
	return true, info.Version.Version
}

func checkPodmanMachine(podmanBin string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, podmanBin, "machine", "info", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return false
	}

	var machineInfo struct {
		Host struct {
			MachineState string `json:"MachineState"`
		} `json:"Host"`
	}
	if err := json.Unmarshal(out, &machineInfo); err != nil {
		return false
	}
	return strings.EqualFold(machineInfo.Host.MachineState, "Running")
}

func podmanHostIP() string {
	switch runtime.GOOS {
	case "darwin", "windows":
		return "host.containers.internal"
	default:
		return podmanBridgeGatewayIP()
	}
}

func podmanBridgeGatewayIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "10.88.0.1"
	}
	for _, iface := range ifaces {
		if iface.Name == "podman0" || iface.Name == "cni-podman0" {
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				return "10.88.0.1"
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return "10.88.0.1"
}

func agentInternalHost() string {
	switch runtime.GOOS {
	case "darwin", "windows":
		return "host-gateway"
	default:
		return podmanBridgeGatewayIP()
	}
}

func findAvailablePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
