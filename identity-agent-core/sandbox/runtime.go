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
        log.Printf("[sandbox-init] Determining agent.internal host for OS: %s", runtime.GOOS)
        
        switch runtime.GOOS {
        case "windows":
                log.Printf("[sandbox-init] Windows detected, attempting WSL2 gateway IP detection")
                // On Windows with WSL2, host-gateway doesn't work reliably.
                // Dynamically detect the WSL2 bridge gateway IP by querying the Podman machine.
                result := detectWSL2GatewayIP()
                log.Printf("[sandbox-init] Final agent.internal host for Windows: %s", result)
                return result
        case "darwin":
                log.Printf("[sandbox-init] macOS detected, using host-gateway")
                // macOS Podman with OrbStack/Colima reliably supports host-gateway
                return "host-gateway"
        default:
                log.Printf("[sandbox-init] Linux detected, using podman bridge gateway")
                result := podmanBridgeGatewayIP()
                log.Printf("[sandbox-init] Final agent.internal host for Linux: %s", result)
                return result
        }
}

func detectWSL2GatewayIP() string {
        // On Windows + Podman + WSL2, the host IP is the WSL2 bridge gateway.
        // Strategy:
        //   1. Ask the Podman machine directly: parse default route from inside WSL2.
        //   2. Fall back to scanning Windows host network interfaces for the WSL vEthernet adapter.
        //   3. Last resort: 172.17.0.1 (common WSL2 gateway). Never use "host-gateway" on Windows
        //      because --add-host host-gateway is unreliable under WSL2.

        log.Printf("[wsl2-detect] Starting WSL2 gateway IP detection")

        if ip := detectWSL2GatewayViaPodmanSSH(); ip != "" {
                log.Printf("[wsl2-detect] Detected gateway via podman machine ssh: %s", ip)
                return ip
        }

        if ip := detectWSL2GatewayViaHostInterfaces(); ip != "" {
                log.Printf("[wsl2-detect] Detected gateway via host network interfaces: %s", ip)
                return ip
        }

        log.Printf("[wsl2-detect] All detection methods failed, falling back to 172.17.0.1")
        return "172.17.0.1"
}

// detectWSL2GatewayViaPodmanSSH runs `podman machine ssh "ip route | grep default"` and
// parses the gateway IP from the output (3rd whitespace-separated token).
func detectWSL2GatewayViaPodmanSSH() string {
        log.Printf("[wsl2-detect] Trying: podman machine ssh 'ip route | grep default'")

        ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
        defer cancel()

        cmd := exec.CommandContext(ctx, "podman", "machine", "ssh", "ip route | grep default")
        output, err := cmd.Output()
        if err != nil {
                log.Printf("[wsl2-detect] podman machine ssh failed: %v", err)

                // Retry with explicit shell invocation
                cmd = exec.CommandContext(ctx, "podman", "machine", "ssh", "sh", "-c", "ip route | grep default")
                output, err = cmd.Output()
                if err != nil {
                        log.Printf("[wsl2-detect] podman machine ssh (sh -c) failed: %v", err)
                        return ""
                }
        }

        rawOutput := strings.TrimSpace(string(output))
        log.Printf("[wsl2-detect] podman machine ssh output: %q", rawOutput)
        if rawOutput == "" {
                return ""
        }

        // Parse: "default via X.X.X.X dev eth0 ..."
        parts := strings.Fields(rawOutput)
        if len(parts) >= 3 && parts[0] == "default" && parts[1] == "via" {
                ip := parts[2]
                if net.ParseIP(ip) != nil {
                        return ip
                }
                log.Printf("[wsl2-detect] Parsed token %q is not a valid IP", ip)
        }

        log.Printf("[wsl2-detect] Could not parse 'default via <IP>' from: %q", rawOutput)
        return ""
}

// detectWSL2GatewayViaHostInterfaces scans Windows host network interfaces for the
// WSL/Hyper-V virtual adapter and returns its IPv4 address, which is the gateway
// that containers inside the Podman/WSL2 machine use to reach the host.
func detectWSL2GatewayViaHostInterfaces() string {
        log.Printf("[wsl2-detect] Scanning host network interfaces for WSL adapter")

        ifaces, err := net.Interfaces()
        if err != nil {
                log.Printf("[wsl2-detect] net.Interfaces() failed: %v", err)
                return ""
        }

        wslKeywords := []string{"wsl", "hyper-v", "hyperv"}
        for _, iface := range ifaces {
                nameLower := strings.ToLower(iface.Name)
                isWSL := false
                for _, kw := range wslKeywords {
                        if strings.Contains(nameLower, kw) {
                                isWSL = true
                                break
                        }
                }
                if !isWSL {
                        continue
                }

                addrs, err := iface.Addrs()
                if err != nil {
                        continue
                }
                for _, addr := range addrs {
                        if ipnet, ok := addr.(*net.IPNet); ok {
                                if ip4 := ipnet.IP.To4(); ip4 != nil {
                                        log.Printf("[wsl2-detect] Found WSL adapter %q with IP %s", iface.Name, ip4.String())
                                        return ip4.String()
                                }
                        }
                }
        }

        log.Printf("[wsl2-detect] No WSL adapter found among %d interfaces", len(ifaces))
        return ""
}

func findAvailablePort() (int, error) {
        listener, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
                return 0, err
        }
        defer listener.Close()
        return listener.Addr().(*net.TCPAddr).Port, nil
}
