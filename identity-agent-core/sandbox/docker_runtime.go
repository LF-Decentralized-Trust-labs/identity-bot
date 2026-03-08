package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type DockerRuntime struct {
	manifest    *AppManifest
	instance    *Instance
	store       *SandboxStore
	netCfg      *NetworkConfig
	containerID string
	networkID   string
	startedAt   time.Time
}

func NewDockerRuntime(manifest *AppManifest, instance *Instance, store *SandboxStore) (*DockerRuntime, error) {
	proxyPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find proxy port: %w", err)
	}

	displayPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find display port: %w", err)
	}

	agentAPIPort, err := findAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to find agent API port: %w", err)
	}

	hostIP := dockerHostIP()
	proxyURL := fmt.Sprintf("http://%s:%d", hostIP, proxyPort)

	netCfg := &NetworkConfig{
		ProxyPort:    proxyPort,
		DisplayPort:  displayPort,
		AgentAPIPort: agentAPIPort,
		NetworkName:  fmt.Sprintf("sandbox-%s-%s", manifest.ID, instance.ID[:8]),
		HostIP:       hostIP,
		ProxyURL:     proxyURL,
		EnvVars: map[string]string{
			"HTTP_PROXY":           proxyURL,
			"HTTPS_PROXY":         proxyURL,
			"http_proxy":          proxyURL,
			"https_proxy":         proxyURL,
			"IDENTITY_AGENT_API":  fmt.Sprintf("http://agent.internal:%d", agentAPIPort),
		},
	}

	return &DockerRuntime{
		manifest: manifest,
		instance: instance,
		store:    store,
		netCfg:   netCfg,
	}, nil
}

func PullImage(ctx context.Context, image string, callback PullProgressCallback) error {
	client := newDockerHTTPClientLong()

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("http://localhost/images/create?fromImage=%s", image), nil)
	if err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("image pull failed (status %d): %s", resp.StatusCode, string(body))
	}

	scanner := bufio.NewScanner(resp.Body)
	layerProgress := make(map[string]int64)
	layerTotal := make(map[string]int64)

	for scanner.Scan() {
		var event struct {
			Status         string `json:"status"`
			ID             string `json:"id"`
			ProgressDetail struct {
				Current int64 `json:"current"`
				Total   int64 `json:"total"`
			} `json:"progressDetail"`
			Error string `json:"error"`
		}

		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		if event.Error != "" {
			return fmt.Errorf("pull error: %s", event.Error)
		}

		if event.ID != "" && event.ProgressDetail.Total > 0 {
			layerProgress[event.ID] = event.ProgressDetail.Current
			layerTotal[event.ID] = event.ProgressDetail.Total
		}

		if callback != nil {
			var totalBytes, doneBytes int64
			for id, t := range layerTotal {
				totalBytes += t
				if d, ok := layerProgress[id]; ok {
					doneBytes += d
				}
			}

			progress := float64(0)
			if totalBytes > 0 {
				progress = float64(doneBytes) / float64(totalBytes)
			}

			callback(PullProgress{
				Status:     event.Status,
				Layer:      event.ID,
				Progress:   progress,
				TotalBytes: totalBytes,
				DoneBytes:  doneBytes,
			})
		}
	}

	return scanner.Err()
}

func GetImageSize(ctx context.Context, image string) (int64, error) {
	client := newDockerHTTPClient()
	resp, err := client.Get(fmt.Sprintf("http://localhost/images/%s/json", image))
	if err != nil {
		return 0, fmt.Errorf("failed to inspect image: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("image not found: %s", image)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var result struct {
		Size int64 `json:"Size"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, err
	}
	return result.Size, nil
}

func RemoveImage(ctx context.Context, image string) error {
	client := newDockerHTTPClient()
	req, err := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("http://localhost/images/%s?force=true", image), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to remove image (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

func (d *DockerRuntime) Start(ctx context.Context) error {
	log.Printf("[docker-runtime] Starting container for app %s (instance %s)", d.manifest.ID, d.instance.ID)

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
		log.Printf("[docker-runtime] Failed to update instance in store: %v", err)
	}

	appID := d.manifest.ID
	d.store.InsertEvent(Event{
		InstanceID: &d.instance.ID,
		AppID:      &appID,
		EventType:  "container_started",
		EventData:  strPtr(fmt.Sprintf(`{"container_id":"%s","network":"%s"}`, d.containerID, d.netCfg.NetworkName)),
	})

	log.Printf("[docker-runtime] Container %s started (display port: %d)", d.containerID[:12], d.netCfg.DisplayPort)
	return nil
}

func (d *DockerRuntime) Stop(ctx context.Context) error {
	log.Printf("[docker-runtime] Stopping container %s for app %s", d.containerID[:min(12, len(d.containerID))], d.manifest.ID)

	if d.containerID != "" {
		if err := d.stopContainer(ctx); err != nil {
			log.Printf("[docker-runtime] Stop container warning: %v", err)
		}
		if err := d.removeContainer(ctx); err != nil {
			log.Printf("[docker-runtime] Remove container warning: %v", err)
		}
	}

	if d.networkID != "" {
		if err := d.removeNetwork(ctx); err != nil {
			log.Printf("[docker-runtime] Remove network warning: %v", err)
		}
	}

	d.instance.Status = "stopped"
	now := time.Now().UTC().Format(time.RFC3339)
	d.instance.StoppedAt = &now
	if err := d.store.SaveInstance(*d.instance); err != nil {
		log.Printf("[docker-runtime] Failed to update instance in store: %v", err)
	}

	appID := d.manifest.ID
	d.store.InsertEvent(Event{
		InstanceID: &d.instance.ID,
		AppID:      &appID,
		EventType:  "container_stopped",
	})

	log.Printf("[docker-runtime] Container stopped and cleaned up")
	return nil
}

func (d *DockerRuntime) Status(ctx context.Context) (*RuntimeStatus, error) {
	if d.containerID == "" {
		return &RuntimeStatus{State: "stopped"}, nil
	}

	client := newDockerHTTPClient()
	resp, err := client.Get(fmt.Sprintf("http://localhost/containers/%s/json", d.containerID))
	if err != nil {
		return &RuntimeStatus{State: "unknown", Error: err.Error()}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &RuntimeStatus{State: "unknown", Error: fmt.Sprintf("status %d", resp.StatusCode)}, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var info struct {
		State struct {
			Status string `json:"Status"`
		} `json:"State"`
	}
	json.Unmarshal(body, &info)

	displayURL := fmt.Sprintf("http://localhost:%d", d.netCfg.DisplayPort)

	return &RuntimeStatus{
		State:       info.State.Status,
		ContainerID: d.containerID,
		Uptime:      time.Since(d.startedAt).Round(time.Second).String(),
		DisplayURL:  displayURL,
	}, nil
}

func (d *DockerRuntime) Stats(ctx context.Context) (*RuntimeStats, error) {
	if d.containerID == "" {
		return &RuntimeStats{}, nil
	}

	client := newDockerHTTPClient()
	resp, err := client.Get(fmt.Sprintf("http://localhost/containers/%s/stats?stream=false", d.containerID))
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stats request failed with status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)

	var stats struct {
		CPUStats struct {
			CPUUsage struct {
				TotalUsage int64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage int64 `json:"system_cpu_usage"`
			OnlineCPUs     int   `json:"online_cpus"`
		} `json:"cpu_stats"`
		PreCPUStats struct {
			CPUUsage struct {
				TotalUsage int64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage int64 `json:"system_cpu_usage"`
		} `json:"precpu_stats"`
		MemoryStats struct {
			Usage int64 `json:"usage"`
			Limit int64 `json:"limit"`
		} `json:"memory_stats"`
		Networks map[string]struct {
			TxBytes int64 `json:"tx_bytes"`
			RxBytes int64 `json:"rx_bytes"`
		} `json:"networks"`
	}

	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, fmt.Errorf("failed to parse stats: %w", err)
	}

	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemCPUUsage - stats.PreCPUStats.SystemCPUUsage)
	cpuPercent := 0.0
	if systemDelta > 0 && cpuDelta > 0 {
		cpuPercent = (cpuDelta / systemDelta) * float64(stats.CPUStats.OnlineCPUs) * 100.0
	}

	var txBytes, rxBytes int64
	for _, net := range stats.Networks {
		txBytes += net.TxBytes
		rxBytes += net.RxBytes
	}

	memLimitMB := stats.MemoryStats.Limit / (1024 * 1024)
	if d.manifest.Resources.MemoryMB > 0 {
		memLimitMB = int64(d.manifest.Resources.MemoryMB)
	}

	return &RuntimeStats{
		CPUPercent:    cpuPercent,
		MemoryUsedMB: stats.MemoryStats.Usage / (1024 * 1024),
		MemoryLimitMB: memLimitMB,
		DiskUsedMB:   0,
		DiskLimitMB:  int64(d.manifest.Resources.DiskMB),
		NetworkTxKB:  txBytes / 1024,
		NetworkRxKB:  rxBytes / 1024,
		EgressKbps:   int64(d.manifest.Resources.EgressKbps),
		IngressKbps:  int64(d.manifest.Resources.IngressKbps),
	}, nil
}

func (d *DockerRuntime) NetworkConfig() *NetworkConfig {
	return d.netCfg
}

func (d *DockerRuntime) createNetwork(ctx context.Context) error {
	client := newDockerHTTPClient()

	body, _ := json.Marshal(map[string]interface{}{
		"Name":   d.netCfg.NetworkName,
		"Driver": "bridge",
		"Labels": map[string]string{
			"identity-agent": "true",
			"app-id":         d.manifest.ID,
			"instance-id":    d.instance.ID,
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", "http://localhost/networks/create", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create network failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Id string `json:"Id"`
	}
	respBody, _ := io.ReadAll(resp.Body)
	json.Unmarshal(respBody, &result)
	d.networkID = result.Id

	log.Printf("[docker-runtime] Created network %s (%s)", d.netCfg.NetworkName, d.networkID[:12])
	return nil
}

func (d *DockerRuntime) createContainer(ctx context.Context) error {
	client := newDockerHTTPClient()

	env := []string{}

	for k, v := range d.netCfg.EnvVars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	if d.manifest.Docker != nil {
		for k, v := range d.manifest.Docker.Environment {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	portBindings := map[string]interface{}{}
	exposedPorts := map[string]interface{}{}

	if d.manifest.Docker != nil {
		for containerPort, role := range d.manifest.Docker.Ports {
			portKey := containerPort + "/tcp"
			exposedPorts[portKey] = struct{}{}
			hostPort := d.netCfg.DisplayPort
			if role != "display" {
				p, err := findAvailablePort()
				if err != nil {
					continue
				}
				hostPort = p
			}
			portBindings[portKey] = []map[string]string{
				{"HostPort": fmt.Sprintf("%d", hostPort)},
			}
		}
	}

	memoryBytes := int64(d.manifest.Resources.MemoryMB) * 1024 * 1024
	nanoCPUs := int64(d.manifest.Resources.CPUCores * 1e9)

	agentHost := agentInternalHost()
	hostIP := dockerHostIP()
	dnsIP := hostIP
	if dnsIP == "host.docker.internal" {
		dnsIP = "8.8.8.8"
	}

	extraHosts := []string{
		fmt.Sprintf("agent.internal:%s", agentHost),
	}

	binds := []string{}
	if d.manifest.Docker != nil {
		for hostPath, containerPath := range d.manifest.Docker.Volumes {
			binds = append(binds, fmt.Sprintf("%s:%s", hostPath, containerPath))
		}
	}

	containerConfig := map[string]interface{}{
		"Image":        d.manifest.Docker.Image,
		"Env":          env,
		"ExposedPorts": exposedPorts,
		"Labels": map[string]string{
			"identity-agent": "true",
			"app-id":         d.manifest.ID,
			"instance-id":    d.instance.ID,
		},
	}

	hostConfig := map[string]interface{}{
		"PortBindings": portBindings,
		"NetworkMode":  d.netCfg.NetworkName,
		"ExtraHosts":   extraHosts,
		"Dns":          []string{dnsIP},
		"Memory":       memoryBytes,
		"NanoCpus":     nanoCPUs,
		"Binds":        binds,
		"RestartPolicy": map[string]interface{}{
			"Name":              "no",
			"MaximumRetryCount": 0,
		},
	}

	createBody := map[string]interface{}{
		"HostConfig": hostConfig,
	}
	for k, v := range containerConfig {
		createBody[k] = v
	}

	bodyBytes, _ := json.Marshal(createBody)

	containerName := fmt.Sprintf("sandbox-%s-%s", d.manifest.ID, d.instance.ID[:8])
	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("http://localhost/containers/create?name=%s", containerName),
		bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create container failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	respBody, _ := io.ReadAll(resp.Body)
	var result struct {
		Id string `json:"Id"`
	}
	json.Unmarshal(respBody, &result)
	d.containerID = result.Id

	log.Printf("[docker-runtime] Created container %s (%s)", containerName, d.containerID[:12])
	return nil
}

func (d *DockerRuntime) startContainer(ctx context.Context) error {
	client := newDockerHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("http://localhost/containers/%s/start", d.containerID), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("start container failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func (d *DockerRuntime) stopContainer(ctx context.Context) error {
	client := newDockerHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("http://localhost/containers/%s/stop?t=10", d.containerID), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusNotModified {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("stop container failed (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func (d *DockerRuntime) removeContainer(ctx context.Context) error {
	client := newDockerHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("http://localhost/containers/%s?force=true&v=true", d.containerID), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (d *DockerRuntime) removeNetwork(ctx context.Context) error {
	client := newDockerHTTPClient()

	req, err := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("http://localhost/networks/%s", d.netCfg.NetworkName), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func ListAgentContainers(ctx context.Context) ([]map[string]interface{}, error) {
	client := newDockerHTTPClient()

	filtersJSON, _ := json.Marshal(map[string][]string{
		"label": {"identity-agent=true"},
	})

	resp, err := client.Get(fmt.Sprintf("http://localhost/containers/json?all=true&filters=%s", string(filtersJSON)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var containers []map[string]interface{}
	json.Unmarshal(body, &containers)
	return containers, nil
}

func CleanupOrphanedContainers(ctx context.Context, store *SandboxStore) error {
	containers, err := ListAgentContainers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list agent containers: %w", err)
	}

	for _, c := range containers {
		containerID, _ := c["Id"].(string)
		if containerID == "" {
			continue
		}

		state, _ := c["State"].(string)
		labels, _ := c["Labels"].(map[string]interface{})
		instanceID, _ := labels["instance-id"].(string)

		if instanceID == "" {
			log.Printf("[docker-runtime] Orphaned container %s (no instance-id label), stopping", containerID[:12])
			stopAndRemoveContainer(ctx, containerID)
			continue
		}

		instance, err := store.GetInstance(instanceID)
		if err != nil {
			continue
		}

		if instance == nil {
			log.Printf("[docker-runtime] Container %s has no matching instance record, stopping", containerID[:12])
			stopAndRemoveContainer(ctx, containerID)
			continue
		}

		if instance.Status == "stopped" || instance.Status == "error" {
			log.Printf("[docker-runtime] Container %s running but instance marked %s, stopping", containerID[:12], instance.Status)
			stopAndRemoveContainer(ctx, containerID)
			continue
		}

		if state != "running" && (instance.Status == "running" || instance.Status == "starting") {
			log.Printf("[docker-runtime] Container %s not running but instance marked %s, updating to stopped", containerID[:12], instance.Status)
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
	}

	for _, inst := range running {
		if !containerIDs[inst.ID] {
			log.Printf("[docker-runtime] Instance %s marked running but no container found, marking stopped", inst.ID)
			store.UpdateInstanceStatus(inst.ID, "stopped")
		}
	}

	return nil
}

func stopAndRemoveContainer(ctx context.Context, containerID string) {
	client := newDockerHTTPClient()

	req, _ := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("http://localhost/containers/%s/stop?t=5", containerID), nil)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}

	req, _ = http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("http://localhost/containers/%s?force=true&v=true", containerID), nil)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
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

func CleanupOrphanedNetworks(ctx context.Context) error {
	client := newDockerHTTPClient()

	filtersJSON, _ := json.Marshal(map[string][]string{
		"label": {"identity-agent=true"},
	})

	resp, err := client.Get(fmt.Sprintf("http://localhost/networks?filters=%s", string(filtersJSON)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var networks []struct {
		Id   string `json:"Id"`
		Name string `json:"Name"`
	}
	json.Unmarshal(body, &networks)

	for _, n := range networks {
		if strings.HasPrefix(n.Name, "sandbox-") {
			log.Printf("[docker-runtime] Cleaning up orphaned network %s", n.Name)
			req, _ := http.NewRequestWithContext(ctx, "DELETE",
				fmt.Sprintf("http://localhost/networks/%s", n.Id), nil)
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}

	return nil
}
