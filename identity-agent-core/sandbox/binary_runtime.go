package sandbox

import (
        "bufio"
        "context"
        "fmt"
        "io"
        "log"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "sync"
        "time"
)

type BinaryRuntime struct {
        manifest  *AppManifest
        instance  *Instance
        store     *SandboxStore
        netCfg    *NetworkConfig
        cmd       *exec.Cmd
        startedAt time.Time
        stdin     io.WriteCloser
        stdout    io.ReadCloser
        stderr    io.ReadCloser
        outputMu  sync.Mutex
        outputBuf []string
        done      chan struct{}
        cancel    context.CancelFunc // cancels the process's own lifecycle context
}

type OutputCallback func(line string, isStderr bool)

func NewBinaryRuntime(manifest *AppManifest, instance *Instance, store *SandboxStore, proxyURL string, proxyPort int) (*BinaryRuntime, error) {
        agentAPIPort, err := findAvailablePort()
        if err != nil {
                return nil, fmt.Errorf("failed to find agent API port: %w", err)
        }

        displayPort, err := findAvailablePort()
        if err != nil {
                return nil, fmt.Errorf("failed to find display port: %w", err)
        }

        env := map[string]string{
                "IDENTITY_AGENT_API": fmt.Sprintf("http://127.0.0.1:%d", agentAPIPort),
                "DISPLAY_PORT":       fmt.Sprintf("%d", displayPort),
        }
        // A host plug-in is deliberately unsandboxed — it is NOT routed through the
        // MITM egress proxy; injecting HTTP(S)_PROXY would only misdirect any host
        // calls it legitimately makes. Sandboxed plug-ins keep the proxy env.
        if manifest.EffectiveIsolation() != "host" {
                env["HTTP_PROXY"] = proxyURL
                env["HTTPS_PROXY"] = proxyURL
                env["http_proxy"] = proxyURL
                env["https_proxy"] = proxyURL
        }
        netCfg := &NetworkConfig{
                ProxyPort:    proxyPort,
                DisplayPort:  displayPort,
                AgentAPIPort: agentAPIPort,
                HostIP:       "127.0.0.1",
                ProxyURL:     proxyURL,
                EnvVars:      env,
        }

        return &BinaryRuntime{
                manifest:  manifest,
                instance:  instance,
                store:     store,
                netCfg:    netCfg,
                outputBuf: make([]string, 0, 1000),
                done:      make(chan struct{}),
        }, nil
}

func (b *BinaryRuntime) Start(ctx context.Context) error {
        if b.manifest.Binary == nil {
                return fmt.Errorf("binary config is required")
        }

        binaryPath := b.manifest.Binary.Path
        
        // Check if path exists as-is
        if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
                // Try with .exe on Windows
                if runtime.GOOS == "windows" {
                        exePath := binaryPath + ".exe"
                        if _, err2 := os.Stat(exePath); err2 == nil {
                                binaryPath = exePath
                                goto pathFound
                        }
                }
                
                // Try resolving relative paths from current working directory
                wd, _ := os.Getwd()
                altPath := filepath.Join(wd, binaryPath)
                if _, err := os.Stat(altPath); err == nil {
                        binaryPath = altPath
                        goto pathFound
                }
                
                // Try common base directories
                for _, baseDir := range []string{".", "/home/runner/workspace"} {
                        tryPath := filepath.Join(baseDir, binaryPath)
                        if _, err := os.Stat(tryPath); err == nil {
                                binaryPath = tryPath
                                goto pathFound
                        }
                }
                
                return fmt.Errorf("binary not found: %s (checked: %s, cwd: %s)", binaryPath, filepath.Join(wd, binaryPath), wd)
        }
        
pathFound:

        args := b.manifest.Binary.Args
        // The plug-in process's lifetime is owned by THIS runtime (torn down in
        // Stop, which kills it), NOT by the caller's request context — otherwise
        // the process would be killed the instant the launch HTTP request returns.
        runCtx, cancel := context.WithCancel(context.Background())
        b.cancel = cancel
        b.cmd = exec.CommandContext(runCtx, binaryPath, args...)

        reservedKeys := map[string]bool{
                "HTTP_PROXY": true, "HTTPS_PROXY": true,
                "http_proxy": true, "https_proxy": true,
                "IDENTITY_AGENT_API": true, "DISPLAY_PORT": true,
        }

        env := os.Environ()
        if b.manifest.Binary.Environment != nil {
                for k, v := range b.manifest.Binary.Environment {
                        if reservedKeys[k] {
                                log.Printf("[binary-runtime] Ignoring manifest override of reserved env var: %s", k)
                                continue
                        }
                        env = append(env, fmt.Sprintf("%s=%s", k, v))
                }
        }
        for k, v := range b.netCfg.EnvVars {
                env = append(env, fmt.Sprintf("%s=%s", k, v))
        }
        b.cmd.Env = env

        if runtime.GOOS == "linux" {
                applyLinuxIsolation(b.cmd)
        }

        var err error
        b.stdin, err = b.cmd.StdinPipe()
        if err != nil {
                return fmt.Errorf("failed to create stdin pipe: %w", err)
        }

        b.stdout, err = b.cmd.StdoutPipe()
        if err != nil {
                return fmt.Errorf("failed to create stdout pipe: %w", err)
        }

        b.stderr, err = b.cmd.StderrPipe()
        if err != nil {
                return fmt.Errorf("failed to create stderr pipe: %w", err)
        }

        if err := b.cmd.Start(); err != nil {
                return fmt.Errorf("failed to start binary: %w", err)
        }

        b.startedAt = time.Now()
        pid := b.cmd.Process.Pid

        b.instance.ProcessPID = &pid
        b.instance.Status = "running"
        b.instance.ProxyPort = &b.netCfg.ProxyPort
        b.instance.AgentAPIPort = &b.netCfg.AgentAPIPort
        now := time.Now().UTC().Format(time.RFC3339)
        b.instance.StartedAt = &now

        if err := b.store.SaveInstance(*b.instance); err != nil {
                log.Printf("[binary-runtime] Failed to update instance in store: %v", err)
        }

        go b.captureOutput(b.stdout, false)
        go b.captureOutput(b.stderr, true)

        go func() {
                err := b.cmd.Wait()
                if err != nil {
                        log.Printf("[binary-runtime] Process exited with error: %v", err)
                }
                b.instance.Status = "stopped"
                stopTime := time.Now().UTC().Format(time.RFC3339)
                b.instance.StoppedAt = &stopTime
                b.store.SaveInstance(*b.instance)

                appID := b.manifest.ID
                b.store.InsertEvent(Event{
                        InstanceID: &b.instance.ID,
                        AppID:      &appID,
                        EventType:  "container_stopped",
                        EventData:  strPtr(fmt.Sprintf(`{"pid":%d,"exit_reason":"%v"}`, pid, err)),
                })

                close(b.done)
        }()

        appID := b.manifest.ID
        b.store.InsertEvent(Event{
                InstanceID: &b.instance.ID,
                AppID:      &appID,
                EventType:  "container_started",
                EventData:  strPtr(fmt.Sprintf(`{"pid":%d,"binary":"%s"}`, pid, binaryPath)),
        })

        log.Printf("[binary-runtime] Process started (PID: %d) for app %s", pid, b.manifest.ID)
        return nil
}

func (b *BinaryRuntime) Stop(ctx context.Context) error {
        if b.cmd == nil || b.cmd.Process == nil {
                if b.cancel != nil {
                        b.cancel()
                }
                return nil
        }
        if b.cancel != nil {
                defer b.cancel()
        }

        log.Printf("[binary-runtime] Stopping process PID %d for app %s", b.cmd.Process.Pid, b.manifest.ID)

        if err := b.cmd.Process.Signal(os.Interrupt); err != nil {
                b.cmd.Process.Kill()
        }

        select {
        case <-b.done:
        case <-time.After(10 * time.Second):
                log.Printf("[binary-runtime] Process did not exit gracefully, killing")
                b.cmd.Process.Kill()
                <-b.done
        case <-ctx.Done():
                b.cmd.Process.Kill()
        }

        b.instance.Status = "stopped"
        now := time.Now().UTC().Format(time.RFC3339)
        b.instance.StoppedAt = &now
        b.store.SaveInstance(*b.instance)

        return nil
}

func (b *BinaryRuntime) Status(ctx context.Context) (*RuntimeStatus, error) {
        if b.cmd == nil || b.cmd.Process == nil {
                return &RuntimeStatus{State: "stopped"}, nil
        }

        select {
        case <-b.done:
                return &RuntimeStatus{State: "stopped"}, nil
        default:
        }

        displayURL := ""
        if b.netCfg.DisplayPort > 0 {
                displayURL = fmt.Sprintf("http://127.0.0.1:%d", b.netCfg.DisplayPort)
        }

        return &RuntimeStatus{
                State:      "running",
                ProcessPID: b.cmd.Process.Pid,
                Uptime:     time.Since(b.startedAt).Round(time.Second).String(),
                DisplayURL: displayURL,
        }, nil
}

func (b *BinaryRuntime) Stats(ctx context.Context) (*RuntimeStats, error) {
        if b.cmd == nil || b.cmd.Process == nil {
                return &RuntimeStats{}, nil
        }

        stats := &RuntimeStats{
                MemoryLimitMB: int64(b.manifest.Resources.MemoryMB),
                DiskLimitMB:   int64(b.manifest.Resources.DiskMB),
                EgressKbps:    int64(b.manifest.Resources.EgressKbps),
                IngressKbps:   int64(b.manifest.Resources.IngressKbps),
        }

        if runtime.GOOS == "linux" {
                populateLinuxProcessStats(b.cmd.Process.Pid, stats)
        }

        return stats, nil
}

func (b *BinaryRuntime) NetworkConfig() *NetworkConfig {
        return b.netCfg
}

func (b *BinaryRuntime) WriteStdin(data []byte) error {
        if b.stdin == nil {
                return fmt.Errorf("stdin not available")
        }
        _, err := b.stdin.Write(data)
        return err
}

func (b *BinaryRuntime) GetOutput() []string {
        b.outputMu.Lock()
        defer b.outputMu.Unlock()
        result := make([]string, len(b.outputBuf))
        copy(result, b.outputBuf)
        return result
}

func (b *BinaryRuntime) Done() <-chan struct{} {
        return b.done
}

func (b *BinaryRuntime) captureOutput(reader io.ReadCloser, isStderr bool) {
        scanner := bufio.NewScanner(reader)
        for scanner.Scan() {
                line := scanner.Text()
                prefix := "[stdout] "
                if isStderr {
                        prefix = "[stderr] "
                }

                b.outputMu.Lock()
                if len(b.outputBuf) >= 10000 {
                        b.outputBuf = b.outputBuf[len(b.outputBuf)-5000:]
                }
                b.outputBuf = append(b.outputBuf, prefix+line)
                b.outputMu.Unlock()
        }
}

func applyLinuxIsolation(cmd *exec.Cmd) {
        // On Linux, we can use network namespaces for stronger isolation.
        // This requires root privileges. For non-root, proxy env vars provide
        // best-effort isolation (documented limitation in ADR-012).
        //
        // Network namespace isolation via SysProcAttr is set in the
        // platform-specific file if running as root. For V1, we rely on
        // proxy env vars which are already set by the caller.
}

func populateLinuxProcessStats(pid int, stats *RuntimeStats) {
        statPath := fmt.Sprintf("/proc/%d/statm", pid)
        data, err := os.ReadFile(statPath)
        if err != nil {
                return
        }

        var size, resident int64
        fmt.Sscanf(string(data), "%d %d", &size, &resident)
        pageSize := int64(os.Getpagesize())
        stats.MemoryUsedMB = (resident * pageSize) / (1024 * 1024)
}
