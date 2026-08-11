package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type ContainerRuntime struct {
	manifest    *AppManifest
	instance    *Instance
	store       *SandboxStore
	netCfg      *NetworkConfig
	dataDir     string
	containerID string
	networkID   string
	startedAt   time.Time
}

func NewContainerRuntime(manifest *AppManifest, instance *Instance, store *SandboxStore, proxyURL string, proxyPort int, dataDir string) (*ContainerRuntime, error) {
	displayPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find display port: %w", err)
	}

	agentAPIPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find agent API port: %w", err)
	}

	hostIP := podmanHostIP()

	netCfg := &NetworkConfig{
		ProxyPort:    proxyPort,
		DisplayPort:  displayPort,
		AgentAPIPort: agentAPIPort,
		NetworkName:  fmt.Sprintf("sandbox-%s-%s", manifest.ID, instance.ID[:8]),
		HostIP:       hostIP,
		ProxyURL:     proxyURL,
		EnvVars: map[string]string{
			"HTTP_PROXY":  proxyURL,
			"HTTPS_PROXY": proxyURL,
			"http_proxy":  proxyURL,
			"https_proxy": proxyURL,
			// agent.internal must bypass the MITM proxy — it is the host itself.
			// Without NO_PROXY the container routes these requests through the proxy,
			// which holds them pending operator approval (unknown domain) and models
			// never load in Open WebUI.
			"NO_PROXY":           "agent.internal",
			"no_proxy":           "agent.internal",
			"IDENTITY_AGENT_API": fmt.Sprintf("http://agent.internal:%d", agentAPIPort),
		},
	}

	return &ContainerRuntime{
		manifest: manifest,
		instance: instance,
		store:    store,
		netCfg:   netCfg,
		dataDir:  dataDir,
	}, nil
}

func runPodmanCmd(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "podman", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("podman %s failed: %w\noutput: %s", args[0], err, string(out))
	}
	return out, nil
}

func PullImage(ctx context.Context, image string, callback PullProgressCallback) error {
	cmd := exec.CommandContext(ctx, "podman", "pull", "--quiet=false", image)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start podman pull: %w", err)
	}

	if callback != nil {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			callback(PullProgress{
				Status:   line,
				Progress: 0,
			})
		}
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("podman pull failed: %w", err)
	}

	if callback != nil {
		callback(PullProgress{
			Status:   "Pull complete",
			Progress: 1.0,
		})
	}

	return nil
}

func GetImageSize(ctx context.Context, image string) (int64, error) {
	out, err := runPodmanCmd(ctx, "inspect", "--type=image", "--format={{.Size}}", image)
	if err != nil {
		return 0, fmt.Errorf("failed to inspect image: %w", err)
	}

	var size int64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &size); err != nil {
		return 0, fmt.Errorf("failed to parse image size: %w", err)
	}
	return size, nil
}

func RemoveImage(ctx context.Context, image string) error {
	_, err := runPodmanCmd(ctx, "rmi", "--force", image)
	return err
}

func (d *ContainerRuntime) Start(ctx context.Context) error {
	log.Printf("[container-runtime] Starting container for app %s (instance %s)", d.manifest.ID, d.instance.ID)

	if err := d.createNetwork(ctx); err != nil {
		return fmt.Errorf("failed to create network: %w", err)
	}

	if err := d.createContainer(ctx); err != nil {
		d.removeNetwork(ctx)
		return fmt.Errorf("failed to create container: %w", err)
	}

	if err := d.startContainer(ctx); err != nil {
		d.removeContainer(ctx)
		d.removeNetwork(ctx)
		return fmt.Errorf("failed to start container: %w", err)
	}

	d.startedAt = time.Now()

	d.instance.ContainerID = &d.containerID
	d.instance.Status = "running"
	d.instance.ProxyPort = &d.netCfg.ProxyPort
	d.instance.DisplayPort = &d.netCfg.DisplayPort
	d.instance.AgentAPIPort = &d.netCfg.AgentAPIPort
	d.instance.NetworkName = &d.netCfg.NetworkName
	now := time.Now().UTC().Format(time.RFC3339)
	d.instance.StartedAt = &now

	if err := d.store.SaveInstance(*d.instance); err != nil {
		log.Printf("[container-runtime] Failed to update instance in store: %v", err)
	}

	appID := d.manifest.ID
	d.store.InsertEvent(Event{
		InstanceID: &d.instance.ID,
		AppID:      &appID,
		EventType:  "container_started",
		EventData:  strPtr(fmt.Sprintf(`{"container_id":"%s","network":"%s"}`, d.containerID, d.netCfg.NetworkName)),
	})

	log.Printf("[container-runtime] Container %s started (display port: %d)", d.containerID[:12], d.netCfg.DisplayPort)
	return nil
}

func (d *ContainerRuntime) Stop(ctx context.Context) error {
	log.Printf("[container-runtime] Stopping container %s for app %s", d.containerID[:min(12, len(d.containerID))], d.manifest.ID)

	if d.containerID != "" {
		if err := d.stopContainer(ctx); err != nil {
			log.Printf("[container-runtime] Stop container warning: %v", err)
		}
		if err := d.removeContainer(ctx); err != nil {
			log.Printf("[container-runtime] Remove container warning: %v", err)
		}
	}

	if d.networkID != "" {
		if err := d.removeNetwork(ctx); err != nil {
			log.Printf("[container-runtime] Remove network warning: %v", err)
		}
	}

	d.instance.Status = "stopped"
	now := time.Now().UTC().Format(time.RFC3339)
	d.instance.StoppedAt = &now
	if err := d.store.SaveInstance(*d.instance); err != nil {
		log.Printf("[container-runtime] Failed to update instance in store: %v", err)
	}

	appID := d.manifest.ID
	d.store.InsertEvent(Event{
		InstanceID: &d.instance.ID,
		AppID:      &appID,
		EventType:  "container_stopped",
	})

	log.Printf("[container-runtime] Container stopped and cleaned up")
	return nil
}

func (d *ContainerRuntime) Status(ctx context.Context) (*RuntimeStatus, error) {
	if d.containerID == "" {
		return &RuntimeStatus{State: "stopped"}, nil
	}

	out, err := runPodmanCmd(ctx, "inspect", "--format={{.State.Status}}", d.containerID)
	if err != nil {
		return &RuntimeStatus{State: "unknown", Error: err.Error()}, nil
	}

	state := strings.TrimSpace(string(out))
	displayPath := ""
	if d.manifest.Container != nil && d.manifest.Container.DisplayPath != "" {
		displayPath = d.manifest.Container.DisplayPath
	}
	displayURL := fmt.Sprintf("http://127.0.0.1:%d%s", d.netCfg.DisplayPort, displayPath)

	return &RuntimeStatus{
		State:       state,
		ContainerID: d.containerID,
		Uptime:      time.Since(d.startedAt).Round(time.Second).String(),
		DisplayURL:  displayURL,
	}, nil
}

func (d *ContainerRuntime) Stats(ctx context.Context) (*RuntimeStats, error) {
	if d.containerID == "" {
		return &RuntimeStats{}, nil
	}

	out, err := runPodmanCmd(ctx, "stats", "--no-stream", "--format=json", d.containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	var stats []struct {
		CPUPerc   string `json:"cpu_percent"`
		CPUPerc2  string `json:"CPU"`
		MemUsage  string `json:"mem_usage"`
		MemUsage2 string `json:"MemUsage"`
		MemPerc   string `json:"mem_percent"`
		MemPerc2  string `json:"MemPerc"`
		NetIO     string `json:"net_io"`
		NetIO2    string `json:"NetIO"`
	}

	if err := json.Unmarshal(out, &stats); err != nil {
		return nil, fmt.Errorf("failed to parse stats: %w", err)
	}

	var cpuPercent float64
	var memUsedMB, memLimitMB int64
	var txKB, rxKB int64

	if len(stats) > 0 {
		s := stats[0]
		cpuStr := s.CPUPerc
		if cpuStr == "" {
			cpuStr = s.CPUPerc2
		}
		fmt.Sscanf(strings.TrimSuffix(cpuStr, "%"), "%f", &cpuPercent)

		memStr := s.MemUsage
		if memStr == "" {
			memStr = s.MemUsage2
		}
		parts := strings.Split(memStr, "/")
		if len(parts) == 2 {
			memUsedMB = parseMemValue(strings.TrimSpace(parts[0]))
			memLimitMB = parseMemValue(strings.TrimSpace(parts[1]))
		}

		netStr := s.NetIO
		if netStr == "" {
			netStr = s.NetIO2
		}
		netParts := strings.Split(netStr, "/")
		if len(netParts) == 2 {
			txKB = parseNetValue(strings.TrimSpace(netParts[0]))
			rxKB = parseNetValue(strings.TrimSpace(netParts[1]))
		}
	}

	if d.manifest.Resources.MemoryMB > 0 {
		memLimitMB = int64(d.manifest.Resources.MemoryMB)
	}

	return &RuntimeStats{
		CPUPercent:    cpuPercent,
		MemoryUsedMB:  memUsedMB,
		MemoryLimitMB: memLimitMB,
		DiskUsedMB:    0,
		DiskLimitMB:   int64(d.manifest.Resources.DiskMB),
		NetworkTxKB:   txKB,
		NetworkRxKB:   rxKB,
		EgressKbps:    int64(d.manifest.Resources.EgressKbps),
		IngressKbps:   int64(d.manifest.Resources.IngressKbps),
	}, nil
}

func parseMemValue(s string) int64 {
	s = strings.TrimSpace(s)
	var val float64
	if strings.HasSuffix(s, "GiB") || strings.HasSuffix(s, "GB") {
		fmt.Sscanf(s, "%f", &val)
		return int64(val * 1024)
	}
	if strings.HasSuffix(s, "MiB") || strings.HasSuffix(s, "MB") {
		fmt.Sscanf(s, "%f", &val)
		return int64(val)
	}
	if strings.HasSuffix(s, "KiB") || strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "kB") {
		fmt.Sscanf(s, "%f", &val)
		return int64(val / 1024)
	}
	fmt.Sscanf(s, "%f", &val)
	return int64(val)
}

func parseNetValue(s string) int64 {
	s = strings.TrimSpace(s)
	var val float64
	if strings.HasSuffix(s, "GB") {
		fmt.Sscanf(s, "%f", &val)
		return int64(val * 1024 * 1024)
	}
	if strings.HasSuffix(s, "MB") {
		fmt.Sscanf(s, "%f", &val)
		return int64(val * 1024)
	}
	if strings.HasSuffix(s, "kB") || strings.HasSuffix(s, "KB") {
		fmt.Sscanf(s, "%f", &val)
		return int64(val)
	}
	fmt.Sscanf(s, "%f", &val)
	return int64(val)
}

func (d *ContainerRuntime) NetworkConfig() *NetworkConfig {
	return d.netCfg
}

func (d *ContainerRuntime) createNetwork(ctx context.Context) error {
	args := []string{
		"network", "create",
		"--label", "identity-agent=true",
		"--label", fmt.Sprintf("app-id=%s", d.manifest.ID),
		"--label", fmt.Sprintf("instance-id=%s", d.instance.ID),
		d.netCfg.NetworkName,
	}

	out, err := runPodmanCmd(ctx, args...)
	if err != nil {
		if strings.Contains(string(out), "already exists") {
			log.Printf("[container-runtime] Network %s already exists, reusing", d.netCfg.NetworkName)
			d.networkID = d.netCfg.NetworkName
			return nil
		}
		return fmt.Errorf("create network failed: %w", err)
	}

	d.networkID = strings.TrimSpace(string(out))
	log.Printf("[container-runtime] Created network %s", d.netCfg.NetworkName)
	return nil
}

func (d *ContainerRuntime) createContainer(ctx context.Context) error {
	args := []string{"create"}

	args = append(args, "--name", fmt.Sprintf("sandbox-%s-%s", d.manifest.ID, d.instance.ID[:8]))
	args = append(args, "--network", d.netCfg.NetworkName)

	reservedKeys := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true,
		"http_proxy": true, "https_proxy": true,
		"NO_PROXY": true, "no_proxy": true,
		"IDENTITY_AGENT_API": true,
	}

	if d.manifest.Container != nil {
		for k, v := range d.manifest.Container.Environment {
			if reservedKeys[k] {
				log.Printf("[container-runtime] Ignoring manifest override of reserved env var: %s", k)
				continue
			}
			args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
		}
	}
	for k, v := range d.netCfg.EnvVars {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	if d.manifest.Container != nil {
		for containerPort, role := range d.manifest.Container.Ports {
			hostPort := d.netCfg.DisplayPort
			if role != "display" {
				p, err := findAvailablePort()
				if err != nil {
					continue
				}
				hostPort = p
			}
			args = append(args, "-p", fmt.Sprintf("%d:%s", hostPort, containerPort))
		}
	}

	memoryBytes := int64(d.manifest.Resources.MemoryMB) * 1024 * 1024
	nanoCPUs := int64(d.manifest.Resources.CPUCores * 1e9)
	args = append(args, "--memory", fmt.Sprintf("%d", memoryBytes))
	args = append(args, "--cpus", fmt.Sprintf("%.2f", float64(nanoCPUs)/1e9))

	agentHost := agentInternalHost()
	hostIP := podmanHostIP()
	dnsIP := hostIP
	if dnsIP == "host.containers.internal" {
		dnsIP = "8.8.8.8"
	}

	log.Printf("[container-create] Container %s: Using --add-host agent.internal:%s", d.manifest.ID, agentHost)
	log.Printf("[container-create] Container %s: Using --dns %s", d.manifest.ID, dnsIP)

	args = append(args, "--add-host", fmt.Sprintf("agent.internal:%s", agentHost))
	args = append(args, "--dns", dnsIP)

	args = append(args, "--label", "identity-agent=true")
	args = append(args, "--label", fmt.Sprintf("app-id=%s", d.manifest.ID))
	args = append(args, "--label", fmt.Sprintf("instance-id=%s", d.instance.ID))

	args = append(args, "--restart", "no")

	if d.manifest.Container != nil {
		for hostPath, containerPath := range d.manifest.Container.Volumes {
			resolvedHost := d.expandVolumePath(hostPath)
			args = append(args, "-v", fmt.Sprintf("%s:%s", resolvedHost, containerPath))
		}
	}

	args = append(args, d.manifest.Container.Image)

	out, err := runPodmanCmd(ctx, args...)
	if err != nil {
		return fmt.Errorf("create container failed: %w", err)
	}

	d.containerID = strings.TrimSpace(string(out))
	containerName := fmt.Sprintf("sandbox-%s-%s", d.manifest.ID, d.instance.ID[:8])
	log.Printf("[container-runtime] Created container %s (%s)", containerName, d.containerID[:12])
	return nil
}

func (d *ContainerRuntime) startContainer(ctx context.Context) error {
	_, err := runPodmanCmd(ctx, "start", d.containerID)
	return err
}

func (d *ContainerRuntime) stopContainer(ctx context.Context) error {
	_, err := runPodmanCmd(ctx, "stop", "-t", "10", d.containerID)
	return err
}

// expandVolumePath resolves template tokens in manifest volume host paths.
// Supported tokens:
//
//	{DATA_DIR}  → the agent's data directory (AGENT_DATA_DIR env / ./data default)
//
// The resolved directory is created if it does not exist, so Podman never
// fails on a missing mount source.
func (d *ContainerRuntime) expandVolumePath(hostPath string) string {
	expanded := strings.ReplaceAll(hostPath, "{DATA_DIR}", d.dataDir)
	// Ensure the directory exists so Podman doesn't error on a missing source.
	// Ignore the error — if it fails, Podman will surface a clearer message.
	if !strings.Contains(expanded, ".") { // rough heuristic: likely a directory, not a file
		_ = os.MkdirAll(expanded, 0755)
	} else {
		_ = os.MkdirAll(filepath.Dir(expanded), 0755)
	}
	return expanded
}

func (d *ContainerRuntime) removeContainer(ctx context.Context) error {
	_, err := runPodmanCmd(ctx, "rm", "--force", "--volumes", d.containerID)
	return err
}

func (d *ContainerRuntime) removeNetwork(ctx context.Context) error {
	_, err := runPodmanCmd(ctx, "network", "rm", "--force", d.netCfg.NetworkName)
	return err
}

func ListAgentContainers(ctx context.Context) ([]map[string]interface{}, error) {
	out, err := runPodmanCmd(ctx, "ps", "-a", "--filter", "label=identity-agent=true", "--format=json")
	if err != nil {
		return nil, err
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "[]" || trimmed == "null" {
		return nil, nil
	}

	var containers []map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &containers); err != nil {
		return nil, fmt.Errorf("failed to parse container list: %w", err)
	}
	return containers, nil
}

func CleanupOrphanedContainers(ctx context.Context, store *SandboxStore) error {
	containers, err := ListAgentContainers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list agent containers: %w", err)
	}

	for _, c := range containers {
		containerID := ""
		if id, ok := c["Id"].(string); ok {
			containerID = id
		} else if id, ok := c["id"].(string); ok {
			containerID = id
		}
		if containerID == "" {
			continue
		}

		state, _ := c["State"].(string)
		if state == "" {
			if s, ok := c["state"].(string); ok {
				state = s
			}
		}

		labels, _ := c["Labels"].(map[string]interface{})
		if labels == nil {
			if l, ok := c["labels"].(map[string]interface{}); ok {
				labels = l
			}
		}

		var instanceID string
		if labels != nil {
			instanceID, _ = labels["instance-id"].(string)
		}

		if instanceID == "" {
			log.Printf("[container-runtime] Orphaned container %s (no instance-id label), stopping", containerID[:min(12, len(containerID))])
			stopAndRemoveContainer(ctx, containerID)
			continue
		}

		instance, err := store.GetInstance(instanceID)
		if err != nil {
			continue
		}

		if instance == nil {
			log.Printf("[container-runtime] Container %s has no matching instance record, stopping", containerID[:min(12, len(containerID))])
			stopAndRemoveContainer(ctx, containerID)
			continue
		}

		if instance.Status == "stopped" || instance.Status == "error" {
			log.Printf("[container-runtime] Container %s running but instance marked %s, stopping", containerID[:min(12, len(containerID))], instance.Status)
			stopAndRemoveContainer(ctx, containerID)
			continue
		}

		if state != "running" && (instance.Status == "running" || instance.Status == "starting") {
			log.Printf("[container-runtime] Container %s not running but instance marked %s, updating to stopped", containerID[:min(12, len(containerID))], instance.Status)
			store.UpdateInstanceStatus(instanceID, "stopped")
		}
	}

	running, err := store.GetRunningInstances()
	if err != nil {
		return err
	}

	containerIDs := make(map[string]bool)
	for _, c := range containers {
		if labels, ok := c["Labels"].(map[string]interface{}); ok {
			if iid, ok := labels["instance-id"].(string); ok {
				containerIDs[iid] = true
			}
		}
		if labels, ok := c["labels"].(map[string]interface{}); ok {
			if iid, ok := labels["instance-id"].(string); ok {
				containerIDs[iid] = true
			}
		}
	}

	for _, inst := range running {
		if !containerIDs[inst.ID] {
			log.Printf("[container-runtime] Instance %s marked running but no container found, marking stopped", inst.ID)
			store.UpdateInstanceStatus(inst.ID, "stopped")
		}
	}

	return nil
}

func stopAndRemoveContainer(ctx context.Context, containerID string) {
	exec.CommandContext(ctx, "podman", "stop", "-t", "5", containerID).Run()
	exec.CommandContext(ctx, "podman", "rm", "--force", "--volumes", containerID).Run()
}

func strPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getContainerIP returns the container's IP address on the given Podman network.
// It first queries the network-specific address, then falls back to any attached
// network. Returns an empty string if the IP cannot be determined.
func getContainerIP(ctx context.Context, containerID, networkName string) string {
	// Try the specific sandbox network first.
	out, err := runPodmanCmd(ctx,
		"inspect", "--format",
		fmt.Sprintf(`{{(index .NetworkSettings.Networks "%s").IPAddress}}`, networkName),
		containerID,
	)
	if err == nil {
		ip := strings.TrimSpace(string(out))
		if ip != "" && ip != "<no value>" {
			return ip
		}
	}

	// Fallback: take the first IP across all attached networks.
	out, err = runPodmanCmd(ctx,
		"inspect", "--format",
		`{{range .NetworkSettings.Networks}}{{if .IPAddress}}{{.IPAddress}}{{end}}{{end}}`,
		containerID,
	)
	if err == nil {
		ip := strings.TrimSpace(string(out))
		if ip != "" {
			return ip
		}
	}

	return ""
}

func CleanupOrphanedNetworks(ctx context.Context) error {
	out, err := runPodmanCmd(ctx, "network", "ls", "--filter", "label=identity-agent=true", "--format=json")
	if err != nil {
		return err
	}

	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" || trimmed == "[]" || trimmed == "null" {
		return nil
	}

	var networks []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(trimmed), &networks); err != nil {
		return fmt.Errorf("failed to parse network list: %w", err)
	}

	for _, n := range networks {
		if strings.HasPrefix(n.Name, "sandbox-") {
			log.Printf("[container-runtime] Cleaning up orphaned network %s", n.Name)
			exec.CommandContext(ctx, "podman", "network", "rm", "--force", n.Name).Run()
		}
	}

	return nil
}
