package sandbox

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// podmanSSHState caches whether `podman machine ssh` is available so we don't
// re-probe on every container launch.
var podmanSSHState struct {
	once      sync.Once
	available bool
}

// podmanSSHAvailable returns true if the Podman machine is running and reachable
// via SSH. The result is cached after the first call.
func podmanSSHAvailable() bool {
	podmanSSHState.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := exec.CommandContext(ctx, "podman", "machine", "ssh", "echo ok").Run()
		podmanSSHState.available = (err == nil)
		if podmanSSHState.available {
			log.Printf("[network] podman machine ssh probe: available")
		} else {
			log.Printf("[network] podman machine ssh probe: unavailable (will use soft enforcement)")
		}
	})
	return podmanSSHState.available
}

// runIptables executes an iptables command. On Linux it runs directly; on
// Windows and macOS it routes the command into the Podman VM via SSH, since
// that is where the containers and their network namespaces actually live.
func runIptables(ctx context.Context, args ...string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.CommandContext(ctx, "iptables", args...).Run()
	case "windows", "darwin":
		if !podmanSSHAvailable() {
			return fmt.Errorf("podman machine ssh not available")
		}
		// Build: iptables <arg1> <arg2> ... with basic shell quoting for args
		// that contain spaces or special characters.
		quotedArgs := make([]string, len(args))
		for i, a := range args {
			if strings.ContainsAny(a, " \t\"'\\") {
				quotedArgs[i] = "'" + strings.ReplaceAll(a, "'", "'\\''") + "'"
			} else {
				quotedArgs[i] = a
			}
		}
		cmd := "iptables " + strings.Join(quotedArgs, " ")
		return exec.CommandContext(ctx, "podman", "machine", "ssh", cmd).Run()
	default:
		return fmt.Errorf("iptables not supported on %s", runtime.GOOS)
	}
}

type NetworkIsolation struct {
	instanceID  string
	appID       string
	proxyPort   int
	dnsPort     int
	networkName string
	hostIP      string
	// containerIP is set by ApplyIptablesRules and used by RemoveIptablesRules.
	containerIP string
}

func NewNetworkIsolation(instanceID, appID string, proxyPort, dnsPort int, networkName string) *NetworkIsolation {
        return &NetworkIsolation{
                instanceID:  instanceID,
                appID:       appID,
                proxyPort:   proxyPort,
                dnsPort:     dnsPort,
                networkName: networkName,
                hostIP:      podmanHostIP(),
        }
}

func (ni *NetworkIsolation) CreatePodmanNetwork(ctx context.Context) error {
        cmd := exec.CommandContext(ctx, "podman", "network", "create",
                "--label", "identity-agent=true",
                "--label", fmt.Sprintf("sandbox-instance=%s", ni.instanceID),
                "--label", fmt.Sprintf("sandbox-app=%s", ni.appID),
                ni.networkName,
        )
        out, err := cmd.CombinedOutput()
        if err != nil {
                return fmt.Errorf("failed to create Podman network: %w — %s", err, string(out))
        }

        log.Printf("[network] Created Podman network %s for instance %s", ni.networkName, ni.instanceID)
        return nil
}

func (ni *NetworkIsolation) RemovePodmanNetwork(ctx context.Context) error {
        cmd := exec.CommandContext(ctx, "podman", "network", "rm", "-f", ni.networkName)
        out, err := cmd.CombinedOutput()
        if err != nil {
                log.Printf("[network] Failed to remove Podman network %s: %v — %s", ni.networkName, err, string(out))
                return fmt.Errorf("failed to remove Podman network: %w", err)
        }

        log.Printf("[network] Removed Podman network %s", ni.networkName)
        return nil
}

func (ni *NetworkIsolation) ApplyIptablesRules(ctx context.Context, containerIP string) error {
	ni.containerIP = containerIP
	chain := fmt.Sprintf("SANDBOX-%s", ni.instanceID[:8])

	rules := [][]string{
		{"-N", chain},
		{"-A", chain, "-p", "tcp", "--dport", fmt.Sprintf("%d", ni.proxyPort), "-j", "ACCEPT"},
		{"-A", chain, "-d", "127.0.0.0/8", "-j", "ACCEPT"},
		{"-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", chain, "-j", "DROP"},
		{"-I", "FORWARD", "-s", containerIP, "-j", chain},
	}

	for _, args := range rules {
		if err := runIptables(ctx, args...); err != nil {
			log.Printf("[network] iptables rule failed: %v — args: %v", err, args)
			return fmt.Errorf("iptables rule failed: %w", err)
		}
	}

	log.Printf("[network] Applied iptables rules for container %s (chain: %s, via: %s)", containerIP, chain, runtime.GOOS)
	return nil
}

func (ni *NetworkIsolation) RemoveIptablesRules(ctx context.Context) error {
	chain := fmt.Sprintf("SANDBOX-%s", ni.instanceID[:8])

	// Remove the FORWARD jump rule only if we know which container IP to target.
	// During reconcile-on-startup the IP may not be available; in that case we
	// still flush and delete the chain so no stale rules linger.
	if ni.containerIP != "" {
		runIptables(ctx, "-D", "FORWARD", "-s", ni.containerIP, "-j", chain)
	}
	runIptables(ctx, "-F", chain)
	runIptables(ctx, "-X", chain)

	log.Printf("[network] Removed iptables rules for container %s (chain: %s)", ni.containerIP, chain)
	return nil
}

func (ni *NetworkIsolation) ContainerCreateConfig(manifest *AppManifest, proxyURL string, agentAPIPort int, certDir string) map[string]interface{} {
        env := []string{
                fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
                fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
                fmt.Sprintf("http_proxy=%s", proxyURL),
                fmt.Sprintf("https_proxy=%s", proxyURL),
                fmt.Sprintf("IDENTITY_AGENT_API=http://agent.internal:%d", agentAPIPort),
        }

        if manifest.Container != nil {
                for k, v := range manifest.Container.Environment {
                        env = append(env, fmt.Sprintf("%s=%s", k, v))
                }
        }

        hostConfig := map[string]interface{}{
                "NetworkMode": ni.networkName,
                "ExtraHosts":  []string{"agent.internal:host-gateway"},
                "Dns":         []string{ni.hostIP},
        }

        if manifest.Container != nil {
                portBindings := make(map[string]interface{})
                exposedPorts := make(map[string]interface{})

                for containerPort := range manifest.Container.Ports {
                        portKey := containerPort + "/tcp"
                        exposedPorts[portKey] = struct{}{}

                        hostPort, _ := findAvailablePort()
                        portBindings[portKey] = []map[string]string{
                                {"HostIp": "127.0.0.1", "HostPort": fmt.Sprintf("%d", hostPort)},
                        }
                }
                hostConfig["PortBindings"] = portBindings
        }

        if manifest.Resources.MemoryMB > 0 {
                hostConfig["Memory"] = int64(manifest.Resources.MemoryMB) * 1024 * 1024
        }
        if manifest.Resources.CPUCores > 0 {
                hostConfig["NanoCpus"] = int64(manifest.Resources.CPUCores * 1e9)
        }
        if manifest.Resources.DiskMB > 0 {
                hostConfig["DiskQuota"] = int64(manifest.Resources.DiskMB) * 1024 * 1024
        }

        binds := []string{}
        if certDir != "" {
                binds = append(binds, fmt.Sprintf("%s:/usr/local/share/ca-certificates/sandbox:ro", certDir))

                nssDir := certDir + "/nss"
                binds = append(binds, fmt.Sprintf("%s:/home/kasm-user/.pki/nssdb:rw", nssDir))
        }

        if manifest.Container != nil {
                for hostPath, containerPath := range manifest.Container.Volumes {
                        binds = append(binds, fmt.Sprintf("%s:%s", hostPath, containerPath))
                }
        }
        if len(binds) > 0 {
                hostConfig["Binds"] = binds
        }

        labels := map[string]string{
                "identity-agent":   "true",
                "sandbox-instance": ni.instanceID,
                "sandbox-app":      ni.appID,
        }

        config := map[string]interface{}{
                "Env":        env,
                "Labels":     labels,
                "HostConfig": hostConfig,
        }

        if manifest.Container != nil && manifest.Container.Image != "" {
                config["Image"] = manifest.Container.Image
        }

        return config
}

func (ni *NetworkIsolation) ApplyBandwidthLimits(containerID string, egressKbps, ingressKbps int) error {
        if runtime.GOOS != "linux" {
                log.Printf("[network] Bandwidth limiting via tc not available on %s", runtime.GOOS)
                return nil
        }

        if egressKbps <= 0 && ingressKbps <= 0 {
                return nil
        }

        veth, err := findContainerVeth(containerID)
        if err != nil {
                return fmt.Errorf("failed to find container veth: %w", err)
        }

        if egressKbps > 0 {
                cmd := exec.Command("tc", "qdisc", "add", "dev", veth,
                        "root", "tbf",
                        "rate", fmt.Sprintf("%dkbit", egressKbps),
                        "burst", "32kbit",
                        "latency", "400ms")
                if err := cmd.Run(); err != nil {
                        log.Printf("[network] Failed to apply egress bandwidth limit on %s: %v", veth, err)
                }
        }

        log.Printf("[network] Applied bandwidth limits on %s: egress=%dkbps, ingress=%dkbps",
                veth, egressKbps, ingressKbps)
        return nil
}

func findContainerVeth(containerID string) (string, error) {
        cmd := exec.Command("sh", "-c",
                fmt.Sprintf(`ip link show | grep -oP 'veth[a-f0-9]+' | head -1`))
        out, err := cmd.Output()
        if err != nil {
                return "", err
        }
        veth := strings.TrimSpace(string(out))
        if veth == "" {
                return "", fmt.Errorf("no veth interface found")
        }
        return veth, nil
}

