package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
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

type DockerDaemonStatus struct {
	Available  bool   `json:"available"`
	Installed  bool   `json:"installed"`
	Running    bool   `json:"running"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
	Platform   string `json:"platform"`
	SocketPath string `json:"socket_path"`
}

func CheckDockerDaemon() *DockerDaemonStatus {
	status := &DockerDaemonStatus{
		Platform: runtime.GOOS,
	}

	socketPath := dockerSocketPath()
	status.SocketPath = socketPath

	if runtime.GOOS == "windows" {
		status.Installed = true
		status.Running = pingDockerAPI()
		status.Available = status.Running
		if status.Running {
			status.Version = getDockerVersion()
		} else {
			status.Error = "Docker Desktop is installed but the daemon is not running. Please launch Docker Desktop."
		}
		return status
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		lookPaths := []string{"/usr/bin/docker", "/usr/local/bin/docker", "/opt/homebrew/bin/docker"}
		for _, p := range lookPaths {
			if _, err := os.Stat(p); err == nil {
				status.Installed = true
				break
			}
		}
		if !status.Installed {
			status.Error = "Docker is not installed. Please install Docker Desktop from https://www.docker.com/products/docker-desktop/"
		} else {
			status.Error = "Docker is installed but the daemon is not running. Please launch Docker Desktop."
		}
		return status
	}

	status.Installed = true
	status.Running = pingDockerAPI()
	status.Available = status.Running

	if status.Running {
		status.Version = getDockerVersion()
	} else {
		status.Error = "Docker daemon is not responding. Please ensure Docker Desktop is running."
	}

	return status
}

func dockerSocketPath() string {
	switch runtime.GOOS {
	case "windows":
		return "//./pipe/docker_engine"
	default:
		return "/var/run/docker.sock"
	}
}

func newDockerHTTPClient() *http.Client {
	socketPath := dockerSocketPath()

	if runtime.GOOS == "windows" {
		return &http.Client{Timeout: 5 * time.Second}
	}

	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func newDockerHTTPClientLong() *http.Client {
	socketPath := dockerSocketPath()

	if runtime.GOOS == "windows" {
		return &http.Client{Timeout: 0}
	}

	return &http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func pingDockerAPI() bool {
	client := newDockerHTTPClient()
	resp, err := client.Get("http://localhost/_ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func getDockerVersion() string {
	client := newDockerHTTPClient()
	resp, err := client.Get("http://localhost/version")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	var result struct {
		Version string `json:"Version"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ""
	}
	return result.Version
}

func dockerHostIP() string {
	switch runtime.GOOS {
	case "darwin", "windows":
		return "host.docker.internal"
	default:
		return dockerBridgeGatewayIP()
	}
}

func dockerBridgeGatewayIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "172.17.0.1"
	}
	for _, iface := range ifaces {
		if iface.Name == "docker0" {
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				return "172.17.0.1"
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					return ipnet.IP.String()
				}
			}
		}
	}
	return "172.17.0.1"
}

func agentInternalHost() string {
	switch runtime.GOOS {
	case "darwin", "windows":
		return "host-gateway"
	default:
		return dockerBridgeGatewayIP()
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
