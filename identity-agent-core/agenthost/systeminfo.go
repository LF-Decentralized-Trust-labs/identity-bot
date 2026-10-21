package agenthost

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// SystemInfo is what the host tells a brain about the machine it runs on.
//
// Answered from a fixed set of commands the host runs itself, never by a
// shell the brain controls: read access plus a way to reply is a way to leak
// files, so the brain gets these facts and nothing it could steer.
type Info struct {
	OS           string            `json:"os"`
	OSVersion    string            `json:"os_version,omitempty"`
	Architecture string            `json:"architecture"`
	Hostname     string            `json:"hostname,omitempty"`
	Model        string            `json:"hardware_model,omitempty"`
	CPU          string            `json:"cpu,omitempty"`
	CPUCores     int               `json:"cpu_cores"`
	MemoryGB     float64           `json:"memory_gb,omitempty"`
	DiskFreeGB   float64           `json:"disk_free_gb,omitempty"`
	DiskTotalGB  float64           `json:"disk_total_gb,omitempty"`
	Uptime       string            `json:"uptime,omitempty"`
	Tools        map[string]string `json:"developer_tools"`
}

// SystemInfo gathers the facts, each with its own short time limit. A fact
// that cannot be read is left out rather than guessed.
func SystemInfo(ctx context.Context) (Info, error) {
	info := Info{OS: runtime.GOOS, Architecture: runtime.GOARCH, CPUCores: runtime.NumCPU(), Tools: map[string]string{}}
	info.Hostname, _ = os.Hostname()
	switch runtime.GOOS {
	case "darwin":
		info.OS = "macOS"
		info.OSVersion = run(ctx, "sw_vers", "-productVersion")
		if b := run(ctx, "sw_vers", "-buildVersion"); b != "" {
			info.OSVersion += " (" + b + ")"
		}
		info.Model = run(ctx, "sysctl", "-n", "hw.model")
		info.CPU = run(ctx, "sysctl", "-n", "machdep.cpu.brand_string")
		if n, err := strconv.ParseFloat(run(ctx, "sysctl", "-n", "hw.memsize"), 64); err == nil {
			info.MemoryGB = round1(n / (1 << 30))
		}
		if boot := run(ctx, "sysctl", "-n", "kern.boottime"); boot != "" {
			// { sec = 1700000000, usec = 0 } ...
			if i := strings.Index(boot, "sec = "); i >= 0 {
				rest := boot[i+6:]
				if j := strings.IndexAny(rest, ", "); j > 0 {
					if sec, err := strconv.ParseInt(rest[:j], 10, 64); err == nil {
						info.Uptime = time.Since(time.Unix(sec, 0)).Round(time.Minute).String()
					}
				}
			}
		}
	case "linux":
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "PRETTY_NAME=") {
					info.OSVersion = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
				}
			}
		}
		if b, err := os.ReadFile("/sys/devices/virtual/dmi/id/product_name"); err == nil {
			info.Model = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "model name") {
					if i := strings.Index(l, ":"); i > 0 {
						info.CPU = strings.TrimSpace(l[i+1:])
						break
					}
				}
			}
		}
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
					if kb, err := strconv.ParseFloat(f[1], 64); err == nil {
						info.MemoryGB = round1(kb / (1 << 20))
					}
				}
			}
		}
		if b, err := os.ReadFile("/proc/uptime"); err == nil {
			if f := strings.Fields(string(b)); len(f) > 0 {
				if sec, err := strconv.ParseFloat(f[0], 64); err == nil {
					info.Uptime = (time.Duration(sec) * time.Second).Round(time.Minute).String()
				}
			}
		}
	case "windows":
		info.OS = "Windows"
		ps := func(expr string) string {
			return run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", expr)
		}
		info.OSVersion = ps("(Get-CimInstance Win32_OperatingSystem | ForEach-Object { $_.Caption + ' ' + $_.Version })")
		info.Model = ps("(Get-CimInstance Win32_ComputerSystem).Model")
		info.CPU = ps("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name")
		if n, err := strconv.ParseFloat(ps("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"), 64); err == nil {
			info.MemoryGB = round1(n / (1 << 30))
		}
		if up := ps("((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds"); up != "" {
			if sec, err := strconv.ParseFloat(up, 64); err == nil {
				info.Uptime = (time.Duration(sec) * time.Second).Round(time.Minute).String()
			}
		}
	}
	info.DiskFreeGB, info.DiskTotalGB = diskSpace()
	for name, args := range map[string][]string{
		"git": {"--version"}, "go": {"version"}, "node": {"--version"}, "python3": {"--version"},
		"flutter": {"--version"}, "xcodebuild": {"-version"}, "docker": {"--version"}, "podman": {"--version"},
		"claude": {"--version"}, "grok": {"--version"},
	} {
		if p, err := exec.LookPath(name); err == nil {
			v := run(ctx, p, args...)
			if i := strings.IndexByte(v, '\n'); i > 0 {
				v = v[:i]
			}
			info.Tools[name] = v
		}
	}
	return info, nil
}

// run runs one fixed command and returns its trimmed output, or nothing.
func run(ctx context.Context, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
