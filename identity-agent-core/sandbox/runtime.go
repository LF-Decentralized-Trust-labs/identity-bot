package sandbox

import (
        "context"
        "encoding/json"
        "log"
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
        Available         bool   `json:"available"`
        Installed         bool   `json:"installed"`
        Running           bool   `json:"running"`
        Version           string `json:"version,omitempty"`
        Error             string `json:"error,omitempty"`
        Platform          string `json:"platform"`
        Architecture      string `json:"architecture"`
        MachineExists     bool   `json:"machine_exists"`
        NeedsMachineInit  bool   `json:"needs_machine_init"`
        NeedsMachineStart bool   `json:"needs_machine_start"`
        SetupSupported    bool   `json:"setup_supported"`
        PackageManager    string `json:"package_manager"`
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
                Platform:       runtime.GOOS,
                Architecture:   machineArch(),
                PackageManager: detectPackageManager(),
        }
        status.SetupSupported = status.PackageManager != "none"

        podmanBin := findPodmanCLI()
        if podmanBin == "" {
                status.Error = "Podman is not installed. Install Podman from https://podman-desktop.io/downloads"
                if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
                        status.NeedsMachineInit = true
                }
                return status
        }
        status.Installed = true

        running, version := checkPodmanInfo(podmanBin)
        if running {
                status.Running = true
                status.Available = true
                status.Version = version
                if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
                        status.MachineExists = true
                }
                return status
        }

        if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
                machineExists, machineRunning := checkPodmanMachineState(podmanBin)
                status.MachineExists = machineExists
                if !machineExists {
                        status.NeedsMachineInit = true
                        status.Error = "Podman is installed but no machine exists. Run 'podman machine init' to create one."
                        return status
                }
                if !machineRunning {
                        status.NeedsMachineStart = true
                        status.Error = "Podman is installed but the machine is not running. Run 'podman machine start' to start it."
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
        _, running := checkPodmanMachineState(podmanBin)
        return running
}

func checkPodmanMachineState(podmanBin string) (exists bool, running bool) {
        ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
        defer cancel()

        cmd := exec.CommandContext(ctx, podmanBin, "machine", "list", "--format", "json")
        out, err := cmd.Output()
        if err != nil {
                return false, false
        }

        var machines []struct {
                Name    string `json:"Name"`
                Running bool   `json:"Running"`
        }
        if err := json.Unmarshal(out, &machines); err != nil {
                return false, false
        }
        if len(machines) == 0 {
                return false, false
        }

        for _, m := range machines {
                if m.Running {
                        return true, true
                }
        }
        return true, false
}

func detectPackageManager() string {
        switch runtime.GOOS {
        case "windows":
                if _, err := exec.LookPath("winget"); err == nil {
                        return "winget"
                }
        case "darwin":
                if _, err := exec.LookPath("brew"); err == nil {
                        return "brew"
                }
        case "linux":
                if _, err := exec.LookPath("apt-get"); err == nil {
                        return "apt"
                }
                if _, err := exec.LookPath("dnf"); err == nil {
                        return "dnf"
                }
        }
        return "none"
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
        case "windows":
                // On Windows with WSL2, host-gateway doesn't work reliably.
                // Dynamically detect the WSL2 bridge gateway IP by querying the Podman machine.
                return detectWSL2GatewayIP()
        case "darwin":
                // macOS Podman with OrbStack/Colima reliably supports host-gateway
                return "host-gateway"
        default:
                return podmanBridgeGatewayIP()
        }
}

func detectWSL2GatewayIP() string {
        // On Windows + Podman + WSL2, the host IP is the WSL2 bridge gateway.
        // Query it with: podman machine ssh "ip route | grep default"
        // Expected output: "default via 172.20.96.1 dev eth0 proto kernel"
        // We need the second field (the IP).
        cmd := exec.Command("podman", "machine", "ssh", "ip route | grep default")
        output, err := cmd.Output()
        if err != nil {
                log.Printf("[sandbox] Failed to detect WSL2 gateway IP: %v, falling back to host-gateway", err)
                return "host-gateway"
        }

        // Parse: "default via X.X.X.X dev eth0 proto kernel"
        parts := strings.Fields(strings.TrimSpace(string(output)))
        if len(parts) >= 3 && parts[0] == "default" && parts[1] == "via" {
                ip := parts[2]
                log.Printf("[sandbox] Detected WSL2 gateway IP: %s", ip)
                return ip
        }

        log.Printf("[sandbox] Could not parse WSL2 gateway IP from output: %s", string(output))
        return "host-gateway"
}

func findAvailablePort() (int, error) {
        listener, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
                return 0, err
        }
        defer listener.Close()
        return listener.Addr().(*net.TCPAddr).Port, nil
}
