package sandbox

import (
        "context"
        "encoding/json"
        "io"
        "net"
        "net/http"
        "os"
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

type DockerDaemonStatus struct {
        Available    bool   `json:"available"`
        Installed    bool   `json:"installed"`
        Running      bool   `json:"running"`
        Version      string `json:"version,omitempty"`
        Error        string `json:"error,omitempty"`
        Platform     string `json:"platform"`
        Architecture string `json:"architecture"`
        SocketPath   string `json:"socket_path"`
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

func CheckDockerDaemon() *DockerDaemonStatus {
        status := &DockerDaemonStatus{
                Platform:     runtime.GOOS,
                Architecture: machineArch(),
        }

        if runtime.GOOS == "windows" {
                return checkDockerWindows(status)
        }

        return checkDockerUnix(status)
}

// findDockerCLI searches for the docker executable on Windows.
func findDockerCLI() string {
        if path, err := exec.LookPath("docker"); err == nil {
                return path
        }
        candidates := []string{
                `C:\Program Files\Docker\Docker\resources\bin\docker.exe`,
                `C:\Program Files\Docker\Docker\resources\docker.exe`,
                `C:\ProgramData\DockerDesktop\version-bin\docker.exe`,
        }
        for _, c := range candidates {
                if _, err := os.Stat(c); err == nil {
                        return c
                }
        }
        return ""
}

// runDockerInfo runs "docker info" and returns true if the daemon responds.
func runDockerInfo(dockerBin string) (bool, string) {
        ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
        defer cancel()
        var cmd *exec.Cmd
        if dockerBin != "" {
                cmd = exec.CommandContext(ctx, dockerBin, "info", "--format", "{{.ServerVersion}}")
        } else {
                cmd = exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}")
        }
        out, err := cmd.Output()
        if err != nil {
                return false, ""
        }
        return true, strings.TrimSpace(string(out))
}

func checkDockerWindows(status *DockerDaemonStatus) *DockerDaemonStatus {
        status.SocketPath = `\\.\pipe\docker_engine`
        dockerBin := findDockerCLI()
        status.Installed = dockerBin != ""

        if !status.Installed {
                status.Error = "Docker Desktop is not installed. Download it from https://www.docker.com/products/docker-desktop/"
                return status
        }

        running, version := runDockerInfo(dockerBin)
        status.Running = running
        status.Available = running
        if running {
                status.Version = version
        } else {
                status.Error = "Docker Desktop is installed but the daemon is not running. Please open Docker Desktop and wait for it to fully start, then check again."
        }
        return status
}

func checkDockerUnix(status *DockerDaemonStatus) *DockerDaemonStatus {
        socketPath := "/var/run/docker.sock"
        if runtime.GOOS == "darwin" {
                if _, err := os.Stat("/var/run/docker.sock"); os.IsNotExist(err) {
                        socketPath = os.Getenv("HOME") + "/.docker/run/docker.sock"
                }
        }
        status.SocketPath = socketPath

        if _, err := os.Stat(socketPath); os.IsNotExist(err) {
                lookPaths := []string{"/usr/bin/docker", "/usr/local/bin/docker", "/opt/homebrew/bin/docker"}
                for _, p := range lookPaths {
                        if _, err := os.Stat(p); err == nil {
                                status.Installed = true
                                break
                        }
                }
                if path, err := exec.LookPath("docker"); err == nil && path != "" {
                        status.Installed = true
                }
                if !status.Installed {
                        status.Error = "Docker is not installed. Download Docker Desktop from https://www.docker.com/products/docker-desktop/"
                } else {
                        status.Error = "Docker is installed but the daemon is not running. Please open Docker Desktop."
                }
                return status
        }

        status.Installed = true
        status.Running = pingDockerUnix(socketPath)
        status.Available = status.Running

        if status.Running {
                status.Version = getDockerVersionUnix(socketPath)
        } else {
                status.Error = "Docker daemon is not responding. Please ensure Docker Desktop is fully started."
        }
        return status
}

func dockerSocketPath() string {
        switch runtime.GOOS {
        case "windows":
                return `\\.\pipe\docker_engine`
        default:
                return "/var/run/docker.sock"
        }
}

func newDockerHTTPClientUnix(socketPath string) *http.Client {
        return &http.Client{
                Timeout: 5 * time.Second,
                Transport: &http.Transport{
                        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                                return net.Dial("unix", socketPath)
                        },
                },
        }
}

func newDockerHTTPClientUnixLong(socketPath string) *http.Client {
        return &http.Client{
                Timeout: 0,
                Transport: &http.Transport{
                        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                                return net.Dial("unix", socketPath)
                        },
                },
        }
}

// newDockerHTTPClient returns a client appropriate for the current OS.
// On Windows, Docker is reached via CLI; this is only used for pull operations on non-Windows.
func newDockerHTTPClient() *http.Client {
        if runtime.GOOS == "windows" {
                return &http.Client{Timeout: 5 * time.Second}
        }
        return newDockerHTTPClientUnix(dockerSocketPath())
}

func newDockerHTTPClientLong() *http.Client {
        if runtime.GOOS == "windows" {
                return &http.Client{Timeout: 0}
        }
        return newDockerHTTPClientUnixLong(dockerSocketPath())
}

func pingDockerUnix(socketPath string) bool {
        client := newDockerHTTPClientUnix(socketPath)
        resp, err := client.Get("http://localhost/_ping")
        if err != nil {
                return false
        }
        defer resp.Body.Close()
        return resp.StatusCode == http.StatusOK
}

func getDockerVersionUnix(socketPath string) string {
        client := newDockerHTTPClientUnix(socketPath)
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
