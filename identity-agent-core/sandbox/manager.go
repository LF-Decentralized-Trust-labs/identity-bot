package sandbox

import (
        "context"
        "encoding/json"
        "fmt"
        "log"
        "os"
        "os/exec"
        "strings"
        "sync"
        "syscall"
        "time"
)

// InstallProgressInfo tracks in-progress container image pulls.
type InstallProgressInfo struct {
        AppID    string  `json:"app_id"`
        Status   string  `json:"status"`
        Layer    string  `json:"layer,omitempty"`
        Progress float64 `json:"progress"`
        Done     bool    `json:"done"`
        Error    string  `json:"error,omitempty"`
}

type Manager struct {
        store               *SandboxStore
        policy              *PolicyEngine
        eventBus            *EventBus
        credentials         *CredentialVault
        proxy               *ProxyManager
        tracer              *Tracer
        manifests           map[string]*AppManifest
        runtimes            map[string]Runtime
        agentAPIs           map[string]*AgentAPIServer
        monitors            map[string]*ResourceMonitor
        networks            map[string]*NetworkIsolation
        dataDir             string
        manifestsDir        string
        mu                  sync.RWMutex
        installProgressMap  sync.Map // map[appID string]*InstallProgressInfo
}

type ManagerConfig struct {
        DataDir      string
        ManifestsDir string
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
        store, err := NewSandboxStore(cfg.DataDir)
        if err != nil {
                return nil, fmt.Errorf("failed to initialize sandbox store: %w", err)
        }

        eventBus := NewEventBus()
        policy := NewPolicyEngine(store, eventBus)
        credentials := NewCredentialVault(cfg.DataDir)
        tracer := NewTracer(2000)

        proxyMgr, err := NewProxyManager(ProxyManagerConfig{
                ListenAddr: "0.0.0.0:0",
                DataDir:    cfg.DataDir,
                Store:      store,
                PolicyCheck: func(instanceID, appID, domain, method, urlStr string) (string, string) {
                        return policy.CheckDomain(instanceID, appID, domain, method, urlStr)
                },
                DNSListenAddr: "127.0.0.1:0",
                Tracer:        tracer,
        })
        if err != nil {
                store.Close()
                return nil, fmt.Errorf("failed to initialize proxy manager: %w", err)
        }

        policy.tracer = tracer
        credentials.tracer = tracer

        m := &Manager{
                store:        store,
                policy:       policy,
                eventBus:     eventBus,
                credentials:  credentials,
                proxy:        proxyMgr,
                tracer:       tracer,
                manifests:    make(map[string]*AppManifest),
                runtimes:     make(map[string]Runtime),
                agentAPIs:    make(map[string]*AgentAPIServer),
                monitors:     make(map[string]*ResourceMonitor),
                networks:     make(map[string]*NetworkIsolation),
                dataDir:      cfg.DataDir,
                manifestsDir: cfg.ManifestsDir,
        }

        return m, nil
}

func (m *Manager) Start() error {
        if err := m.proxy.Start(); err != nil {
                return fmt.Errorf("failed to start proxy: %w", err)
        }

        if m.manifestsDir != "" {
                if err := m.LoadManifests(); err != nil {
                        log.Printf("[sandbox-manager] Failed to load manifests (non-fatal): %v", err)
                }
        }

        if err := m.ReconcileOnStartup(); err != nil {
                log.Printf("[sandbox-manager] Startup reconciliation warning: %v", err)
        }

        log.Printf("[sandbox-manager] Started (proxy on %s)", m.proxy.ListenAddr())
        return nil
}

func (m *Manager) Stop() {
        m.mu.Lock()
        defer m.mu.Unlock()

        for id, rt := range m.runtimes {
                ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
                if err := rt.Stop(ctx); err != nil {
                        log.Printf("[sandbox-manager] Failed to stop runtime %s: %v", id, err)
                }
                cancel()
        }

        for id, api := range m.agentAPIs {
                api.Stop()
                log.Printf("[sandbox-manager] Stopped agent API for %s", id)
        }

        for id, mon := range m.monitors {
                mon.Stop()
                log.Printf("[sandbox-manager] Stopped monitor for %s", id)
        }

        for _, net := range m.networks {
                ctx := context.Background()
                net.RemovePodmanNetwork(ctx)
        }

        m.proxy.Stop()
        m.store.Close()

        log.Printf("[sandbox-manager] Stopped")
}

func (m *Manager) LoadManifests() error {
        manifests, err := LoadManifestsFromDir(m.manifestsDir)
        if err != nil {
                return err
        }

        m.mu.Lock()
        defer m.mu.Unlock()

        for _, manifest := range manifests {
                m.manifests[manifest.ID] = manifest
                m.policy.RegisterManifest(manifest)

                manifestJSON, _ := manifest.ToJSON()
                app := App{
                        ID:            manifest.ID,
                        Name:          manifest.Name,
                        Description:   &manifest.Description,
                        Version:       &manifest.Version,
                        ExecutionType: manifest.ExecutionType,
                        DisplayMethod: manifest.DisplayMethod,
                        NetworkMode:   manifest.NetworkMode,
                        ManifestJSON:  manifestJSON,
                        InstallStatus: "available",
                }
                if manifest.Container != nil {
                        app.ContainerImage = &manifest.Container.Image
                }
                if manifest.Binary != nil {
                        app.BinaryPath = &manifest.Binary.Path
                }
                m.store.SaveApp(app)

                log.Printf("[sandbox-manager] Loaded manifest: %s (%s)", manifest.Name, manifest.ID)
        }

        return nil
}

func (m *Manager) ListApps() ([]App, error) {
        return m.store.ListApps()
}

func (m *Manager) GetApp(id string) (*App, error) {
        return m.store.GetApp(id)
}

func (m *Manager) InstallApp(ctx context.Context, id string, progressCb PullProgressCallback) error {
        m.mu.RLock()
        manifest, ok := m.manifests[id]
        m.mu.RUnlock()
        if !ok {
                return fmt.Errorf("unknown app: %s", id)
        }

        info := &InstallProgressInfo{AppID: id, Status: "starting", Progress: 0}
        m.installProgressMap.Store(id, info)
        m.store.UpdateAppStatus(id, "installing")

        if manifest.IsContainer() && manifest.Container != nil {
                wrappedCb := func(p PullProgress) {
                        info.Status = p.Status
                        info.Layer = p.Layer
                        info.Progress = p.Progress
                        if progressCb != nil {
                                progressCb(p)
                        }
                }
                if err := PullImage(ctx, manifest.Container.Image, wrappedCb); err != nil {
                        info.Done = true
                        info.Error = err.Error()
                        m.store.UpdateAppStatus(id, "available")
                        go func() {
                                time.Sleep(30 * time.Second)
                                m.installProgressMap.Delete(id)
                        }()
                        return fmt.Errorf("failed to pull image: %w", err)
                }
        }

        info.Done = true
        info.Progress = 100
        info.Status = "complete"
        m.store.UpdateAppStatus(id, "installed")
        m.policy.SyncManifestRules(manifest)

        m.store.InsertEvent(Event{
                AppID:     &id,
                EventType: "app_installed",
                EventData: strPtr(fmt.Sprintf(`{"app":"%s"}`, manifest.Name)),
        })

        m.eventBus.Publish(SandboxEvent{
                Type:  "app_installed",
                AppID: id,
        })

        go func() {
                time.Sleep(30 * time.Second)
                m.installProgressMap.Delete(id)
        }()

        log.Printf("[sandbox-manager] Installed app: %s", manifest.Name)
        return nil
}

// GetInstallProgress returns the current install progress for an app, or nil if not installing.
func (m *Manager) GetInstallProgress(id string) *InstallProgressInfo {
        val, ok := m.installProgressMap.Load(id)
        if !ok {
                return nil
        }
        return val.(*InstallProgressInfo)
}

func (m *Manager) UninstallApp(id string) error {
        instances, err := m.store.GetInstancesByApp(id)
        if err != nil {
                return err
        }
        for _, inst := range instances {
                if inst.Status == "running" || inst.Status == "starting" {
                        if err := m.StopApp(context.Background(), id); err != nil {
                                log.Printf("[sandbox-manager] Failed to stop instance before uninstall: %v", err)
                        }
                }
        }

        m.store.UpdateAppStatus(id, "available")
        m.policy.UnregisterManifest(id)

        m.store.InsertEvent(Event{
                AppID:     &id,
                EventType: "app_uninstalled",
        })

        m.eventBus.Publish(SandboxEvent{
                Type:  "app_uninstalled",
                AppID: id,
        })

        return nil
}

func (m *Manager) LaunchApp(ctx context.Context, id string) (*Instance, error) {
        m.mu.Lock()
        defer m.mu.Unlock()

        manifest, ok := m.manifests[id]
        if !ok {
                return nil, fmt.Errorf("unknown app: %s", id)
        }

        instanceID := NewInstanceID()
        instance := &Instance{
                ID:      instanceID,
                AppID:   id,
                Status:  "starting",
                TLSMode: manifest.Network.TLSMode,
                LogLevel: manifest.LogLevel,
        }

        memMB := manifest.Resources.MemoryMB
        cpuLimit := manifest.Resources.CPUCores
        diskMB := manifest.Resources.DiskMB
        egressKbps := manifest.Resources.EgressKbps
        ingressKbps := manifest.Resources.IngressKbps
        instance.MemoryLimitMB = &memMB
        instance.CPULimit = &cpuLimit
        instance.DiskLimitMB = &diskMB
        instance.EgressKbps = &egressKbps
        instance.IngressKbps = &ingressKbps

        if err := m.store.SaveInstance(*instance); err != nil {
                return nil, fmt.Errorf("failed to save instance: %w", err)
        }

        var rt Runtime
        var err error

        proxyPort := m.proxy.Port()
        containerProxyURL := fmt.Sprintf("http://%s:%d", podmanHostIP(), proxyPort)
        binaryProxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)

        if manifest.IsContainer() {
                rt, err = NewContainerRuntime(manifest, instance, m.store, containerProxyURL, proxyPort)
        } else {
                rt, err = NewBinaryRuntime(manifest, instance, m.store, binaryProxyURL, proxyPort)
        }
        if err != nil {
                m.store.UpdateInstanceStatus(instanceID, "error")
                return nil, fmt.Errorf("failed to create runtime: %w", err)
        }

        netCfg := rt.NetworkConfig()

        if manifest.IsContainer() {
                ni := NewNetworkIsolation(instanceID, id, netCfg.ProxyPort, 0, netCfg.NetworkName)
                if err := ni.CreatePodmanNetwork(ctx); err != nil {
                        log.Printf("[sandbox-manager] Network creation failed (non-fatal): %v", err)
                }
                m.networks[instanceID] = ni
        }

        agentAPI := NewAgentAPIServer(instanceID, id, netCfg.AgentAPIPort, m.store, m.policy, m.eventBus, m.tracer)
        if err := agentAPI.Start(); err != nil {
                m.store.UpdateInstanceStatus(instanceID, "error")
                return nil, fmt.Errorf("failed to start agent API: %w", err)
        }
        m.agentAPIs[instanceID] = agentAPI

        m.proxy.AddRoute(ProxyRoute{
                InstanceID: instanceID,
                AppID:      id,
                TLSMode:    manifest.Network.TLSMode,
                LogLevel:   manifest.LogLevel,
                TargetHost: netCfg.HostIP,
                TargetPort: netCfg.ProxyPort,
        })

        if err := rt.Start(ctx); err != nil {
                agentAPI.Stop()
                m.proxy.RemoveRoute(instanceID)
                m.store.UpdateInstanceStatus(instanceID, "error")
                return nil, fmt.Errorf("failed to start runtime: %w", err)
        }
        m.runtimes[instanceID] = rt

        mon := NewResourceMonitor(rt, manifest, instance, m.store, func(alert ResourceAlert) {
                if m.eventBus != nil {
                        m.eventBus.Publish(SandboxEvent{
                                Type:       "resource_" + alert.Resource + "_alert",
                                AppID:      alert.AppID,
                                InstanceID: alert.InstanceID,
                                Data: map[string]interface{}{
                                        "level":   alert.Level,
                                        "current": alert.Current,
                                        "limit":   alert.Limit,
                                        "percent": alert.Percent,
                                        "message": alert.Message,
                                },
                        })
                }
        })
        mon.Start(ctx)
        m.monitors[instanceID] = mon

        instance.ProxyPort = &netCfg.ProxyPort
        instance.DisplayPort = &netCfg.DisplayPort
        instance.AgentAPIPort = &netCfg.AgentAPIPort
        if netCfg.NetworkName != "" {
                instance.NetworkName = &netCfg.NetworkName
        }
        m.store.SaveInstance(*instance)

        displayURL := ""
        if netCfg.DisplayPort > 0 {
                displayURL = fmt.Sprintf("http://127.0.0.1:%d", netCfg.DisplayPort)
        }

        m.store.InsertEvent(Event{
                InstanceID: &instanceID,
                AppID:      &id,
                EventType:  "container_started",
                EventData:  strPtr(fmt.Sprintf(`{"display_url":"%s"}`, displayURL)),
        })

        m.eventBus.Publish(SandboxEvent{
                Type:       "app_launched",
                AppID:      id,
                InstanceID: instanceID,
                Data: map[string]interface{}{
                        "display_url": displayURL,
                },
        })

        log.Printf("[sandbox-manager] Launched %s (instance: %s, display: %s)", manifest.Name, instanceID, displayURL)

        return instance, nil
}

func (m *Manager) StopApp(ctx context.Context, appID string) error {
        m.mu.Lock()
        defer m.mu.Unlock()

        instances, _ := m.store.GetInstancesByApp(appID)

        for _, inst := range instances {
                if inst.Status != "running" && inst.Status != "starting" {
                        continue
                }

                if mon, ok := m.monitors[inst.ID]; ok {
                        mon.Stop()
                        delete(m.monitors, inst.ID)
                }

                if rt, ok := m.runtimes[inst.ID]; ok {
                        if err := rt.Stop(ctx); err != nil {
                                log.Printf("[sandbox-manager] Failed to stop runtime %s: %v", inst.ID, err)
                        }
                        delete(m.runtimes, inst.ID)
                }

                m.proxy.RemoveRoute(inst.ID)

                if api, ok := m.agentAPIs[inst.ID]; ok {
                        api.Stop()
                        delete(m.agentAPIs, inst.ID)
                }

                if ni, ok := m.networks[inst.ID]; ok {
                        ni.RemovePodmanNetwork(ctx)
                        delete(m.networks, inst.ID)
                }

                m.store.UpdateInstanceStatus(inst.ID, "stopped")

                m.store.InsertEvent(Event{
                        InstanceID: &inst.ID,
                        AppID:      &appID,
                        EventType:  "container_stopped",
                        EventData:  strPtr(`{"reason":"user_stop"}`),
                })

                m.eventBus.Publish(SandboxEvent{
                        Type:       "app_stopped",
                        AppID:      appID,
                        InstanceID: inst.ID,
                })

                log.Printf("[sandbox-manager] Stopped instance %s of app %s", inst.ID, appID)
        }

        return nil
}

func (m *Manager) GetAppStatus(appID string) (*RuntimeStatus, error) {
        m.mu.RLock()
        defer m.mu.RUnlock()

        instances, _ := m.store.GetInstancesByApp(appID)
        for _, inst := range instances {
                if inst.Status == "running" || inst.Status == "starting" {
                        if rt, ok := m.runtimes[inst.ID]; ok {
                                return rt.Status(context.Background())
                        }
                }
        }

        return &RuntimeStatus{State: "stopped"}, nil
}

func (m *Manager) GetAppStats(appID string) (*RuntimeStats, error) {
        m.mu.RLock()
        defer m.mu.RUnlock()

        instances, _ := m.store.GetInstancesByApp(appID)
        for _, inst := range instances {
                if inst.Status == "running" {
                        if rt, ok := m.runtimes[inst.ID]; ok {
                                return rt.Stats(context.Background())
                        }
                }
        }

        return &RuntimeStats{}, nil
}

func (m *Manager) GetProxyLogs(appID string, filter ProxyLogFilter) ([]ProxyLog, error) {
        instances, _ := m.store.GetInstancesByApp(appID)
        if len(instances) == 0 {
                return []ProxyLog{}, nil
        }

        var allLogs []ProxyLog
        for _, inst := range instances {
                f := filter
                f.InstanceID = inst.ID
                logs, err := m.store.QueryProxyLogs(f)
                if err != nil {
                        return nil, err
                }
                allLogs = append(allLogs, logs...)
        }

        if allLogs == nil {
                allLogs = []ProxyLog{}
        }
        return allLogs, nil
}

func (m *Manager) GetHeldRequests(appID string) ([]ProxyLog, error) {
        instances, _ := m.store.GetInstancesByApp(appID)
        var held []ProxyLog
        for _, inst := range instances {
                logs, err := m.store.GetHeldProxyLogs(inst.ID)
                if err != nil {
                        return nil, err
                }
                held = append(held, logs...)
        }
        if held == nil {
                held = []ProxyLog{}
        }
        return held, nil
}

func (m *Manager) ApproveHeldRequest(logID int64, appID string) error {
        return m.policy.ApproveHeldRequest(logID, appID)
}

func (m *Manager) BlockHeldRequest(logID int64, appID string) error {
        return m.policy.BlockHeldRequest(logID, appID)
}

func (m *Manager) GetPendingResourceRequests(appID string) ([]ResourceRequest, error) {
        return m.store.GetPendingResourceRequests(appID)
}

func (m *Manager) ApproveResourceRequest(reqID int64) error {
        return m.store.ResolveResourceRequest(reqID, "approved", "user")
}

func (m *Manager) DenyResourceRequest(reqID int64) error {
        return m.store.ResolveResourceRequest(reqID, "denied", "user")
}

func (m *Manager) BatchResolveResourceRequests(approveIDs, denyIDs []int64) error {
        for _, id := range approveIDs {
                if err := m.store.ResolveResourceRequest(id, "approved", "user"); err != nil {
                        return err
                }
        }
        for _, id := range denyIDs {
                if err := m.store.ResolveResourceRequest(id, "denied", "user"); err != nil {
                        return err
                }
        }
        return nil
}

func (m *Manager) UpdateAppSettings(appID string, settings map[string]interface{}) error {
        m.mu.Lock()
        defer m.mu.Unlock()

        if logLevel, ok := settings["log_level"].(string); ok {
                for _, rt := range m.runtimes {
                        status, _ := rt.Status(context.Background())
                        if status != nil && status.State == "running" {
                                for id, route := range m.proxy.routes {
                                        if route.AppID == appID {
                                                route.LogLevel = logLevel
                                                m.proxy.routes[id] = route
                                        }
                                }
                        }
                }
        }

        return nil
}

func (m *Manager) GetDisplayURL(appID string) (string, error) {
        m.mu.RLock()
        defer m.mu.RUnlock()

        instances, _ := m.store.GetInstancesByApp(appID)
        for _, inst := range instances {
                if inst.Status == "running" && inst.DisplayPort != nil {
                        return fmt.Sprintf("http://127.0.0.1:%d", *inst.DisplayPort), nil
                }
        }

        return "", fmt.Errorf("no running instance for app %s", appID)
}

func (m *Manager) GetRunningInstance(appID string) (*Instance, error) {
        instances, _ := m.store.GetInstancesByApp(appID)
        for _, inst := range instances {
                if inst.Status == "running" || inst.Status == "starting" {
                        return &inst, nil
                }
        }
        return nil, nil
}

func (m *Manager) GetBinaryRuntime(instanceID string) *BinaryRuntime {
        m.mu.RLock()
        defer m.mu.RUnlock()

        if rt, ok := m.runtimes[instanceID]; ok {
                if brt, ok := rt.(*BinaryRuntime); ok {
                        return brt
                }
        }
        return nil
}

func (m *Manager) EventBus() *EventBus {
        return m.eventBus
}

func (m *Manager) Tracer() *Tracer {
        return m.tracer
}

func (m *Manager) Store() *SandboxStore {
        return m.store
}

func (m *Manager) HealthCheck() map[string]interface{} {
        containerEngine := CheckContainerEngine()

        m.mu.RLock()
        runningCount := 0
        for _, rt := range m.runtimes {
                status, _ := rt.Status(context.Background())
                if status != nil && status.State == "running" {
                        runningCount++
                }
        }
        m.mu.RUnlock()

        return map[string]interface{}{
                "container_engine": containerEngine,
                "proxy_running":    m.proxy.IsRunning(),
                "proxy_addr":       m.proxy.ListenAddr(),
                "running_apps":     runningCount,
                "loaded_manifests": len(m.manifests),
        }
}

func (m *Manager) ReconcileOnStartup() error {
        instances, err := m.store.GetRunningInstances()
        if err != nil {
                return fmt.Errorf("failed to get running instances: %w", err)
        }

        for _, inst := range instances {
                if inst.ContainerID != nil && *inst.ContainerID != "" {
                        running := isContainerRunning(*inst.ContainerID)
                        if !running {
                                log.Printf("[sandbox-manager] Reconcile: DB=running, Container=stopped → marking stopped (instance %s)", inst.ID)
                                m.store.UpdateInstanceStatus(inst.ID, "stopped")
                                m.cleanupInstanceResources(inst)
                                m.store.InsertEvent(Event{
                                        InstanceID: &inst.ID,
                                        AppID:      &inst.AppID,
                                        EventType:  "crash_recovery",
                                        EventData:  strPtr(`{"action":"marked_stopped","reason":"container_not_running"}`),
                                })
                        } else {
                                log.Printf("[sandbox-manager] Reconcile: DB=running, Container=running → killing container (instance %s)", inst.ID)
                                stopAndRemoveContainer(context.Background(), *inst.ContainerID)
                                m.store.UpdateInstanceStatus(inst.ID, "stopped")
                                m.cleanupInstanceResources(inst)
                                m.store.InsertEvent(Event{
                                        InstanceID: &inst.ID,
                                        AppID:      &inst.AppID,
                                        EventType:  "crash_recovery",
                                        EventData:  strPtr(`{"action":"killed_and_stopped","reason":"stale_running_container"}`),
                                })
                        }
                } else if inst.ProcessPID != nil && *inst.ProcessPID > 0 {
                        if !isProcessRunning(*inst.ProcessPID) {
                                log.Printf("[sandbox-manager] Reconcile: DB=running, Process=dead → marking stopped (instance %s)", inst.ID)
                                m.store.UpdateInstanceStatus(inst.ID, "stopped")
                                m.cleanupInstanceResources(inst)
                                m.store.InsertEvent(Event{
                                        InstanceID: &inst.ID,
                                        AppID:      &inst.AppID,
                                        EventType:  "crash_recovery",
                                        EventData:  strPtr(`{"action":"marked_stopped","reason":"process_not_running"}`),
                                })
                        } else {
                                log.Printf("[sandbox-manager] Reconcile: DB=running, Process=alive → killing process (instance %s, PID %d)", inst.ID, *inst.ProcessPID)
                                killProcess(*inst.ProcessPID)
                                m.store.UpdateInstanceStatus(inst.ID, "stopped")
                                m.cleanupInstanceResources(inst)
                                m.store.InsertEvent(Event{
                                        InstanceID: &inst.ID,
                                        AppID:      &inst.AppID,
                                        EventType:  "crash_recovery",
                                        EventData:  strPtr(fmt.Sprintf(`{"action":"killed_and_stopped","reason":"stale_running_process","pid":%d}`, *inst.ProcessPID)),
                                })
                        }
                } else {
                        log.Printf("[sandbox-manager] Reconcile: DB=running, no container/process → marking stopped (instance %s)", inst.ID)
                        m.store.UpdateInstanceStatus(inst.ID, "stopped")
                        m.cleanupInstanceResources(inst)
                }
        }

        cleanupOrphanContainers()

        return nil
}

func (m *Manager) cleanupInstanceResources(inst Instance) {
        if inst.NetworkName != nil && *inst.NetworkName != "" {
                ni := NewNetworkIsolation(inst.ID, inst.AppID, 0, 0, *inst.NetworkName)
                ni.RemovePodmanNetwork(context.Background())
        }
        m.proxy.RemoveRoute(inst.ID)
}

func killProcess(pid int) {
        if pid <= 0 {
                return
        }
        proc, err := os.FindProcess(pid)
        if err != nil {
                return
        }
        _ = proc.Signal(syscall.SIGTERM)
        time.Sleep(2 * time.Second)
        if isProcessRunning(pid) {
                _ = proc.Signal(syscall.SIGKILL)
        }
}

func isContainerRunning(containerID string) bool {
        out, err := exec.CommandContext(context.Background(), "podman", "inspect", "--format={{.State.Running}}", containerID).Output()
        if err != nil {
                return false
        }
        return strings.TrimSpace(string(out)) == "true"
}

func isProcessRunning(pid int) bool {
        if pid <= 0 {
                return false
        }
        proc, err := os.FindProcess(pid)
        if err != nil {
                return false
        }
        err = proc.Signal(syscall.Signal(0))
        return err == nil
}

func cleanupOrphanContainers() {
        out, err := exec.CommandContext(context.Background(), "podman", "ps", "-a", "--filter", "label=identity-agent=true", "--format=json").Output()
        if err != nil {
                return
        }

        trimmed := strings.TrimSpace(string(out))
        if trimmed == "" || trimmed == "[]" || trimmed == "null" {
                return
        }

        var containers []struct {
                ID    string `json:"Id"`
                State string `json:"State"`
        }
        if err := json.Unmarshal([]byte(trimmed), &containers); err != nil {
                return
        }

        for _, c := range containers {
                switch c.State {
                case "exited", "dead":
                        exec.CommandContext(context.Background(), "podman", "rm", "--force", c.ID).Run()
                        log.Printf("[sandbox-manager] Removed exited orphan container %s", c.ID[:12])
                case "running", "created", "restarting":
                        stopAndRemoveContainer(context.Background(), c.ID)
                        log.Printf("[sandbox-manager] Stopped and removed orphan container %s (was %s)", c.ID[:12], c.State)
                }
        }
}
