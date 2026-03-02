package endpoint

import (
        "encoding/json"
        "fmt"
        "log"
        "net"
        "os"
        "path/filepath"
        "strings"
        "sync"
        "time"

        "identity-agent-core/tunnel"
)

type EndpointState struct {
        URL       string `json:"url"`
        Source    string `json:"source"`
        UpdatedAt string `json:"updated_at"`
}

type EndpointService struct {
        currentURL    string
        source        string
        updatedAt     time.Time
        tunnelManager *tunnel.Manager
        overrideURL   string
        localPort     int
        dataDir       string
        onChange      []func(newURL, source string)
        mu            sync.RWMutex
}

func New(dataDir string, localPort int) *EndpointService {
        es := &EndpointService{
                dataDir:   dataDir,
                localPort: localPort,
        }
        es.load()
        return es
}

func (es *EndpointService) SetTunnelManager(tm *tunnel.Manager) {
        es.mu.Lock()
        defer es.mu.Unlock()
        es.tunnelManager = tm
}

func (es *EndpointService) SetOverrideURL(url string) {
        es.mu.Lock()
        es.overrideURL = strings.TrimRight(url, "/")
        es.mu.Unlock()
        es.Refresh()
}

func (es *EndpointService) OnChange(cb func(newURL, source string)) {
        es.mu.Lock()
        defer es.mu.Unlock()
        es.onChange = append(es.onChange, cb)
}

func (es *EndpointService) CurrentURL() string {
        es.mu.RLock()
        defer es.mu.RUnlock()
        return es.currentURL
}

func (es *EndpointService) Source() string {
        es.mu.RLock()
        defer es.mu.RUnlock()
        return es.source
}

func (es *EndpointService) UpdatedAt() time.Time {
        es.mu.RLock()
        defer es.mu.RUnlock()
        return es.updatedAt
}

func (es *EndpointService) State() EndpointState {
        es.mu.RLock()
        defer es.mu.RUnlock()
        return EndpointState{
                URL:       es.currentURL,
                Source:    es.source,
                UpdatedAt: es.updatedAt.UTC().Format(time.RFC3339),
        }
}

func (es *EndpointService) Refresh() {
        newURL, source := es.resolve()

        es.mu.Lock()
        changed := newURL != es.currentURL
        es.currentURL = newURL
        es.source = source
        if changed {
                es.updatedAt = time.Now()
        }
        callbacks := make([]func(string, string), len(es.onChange))
        copy(callbacks, es.onChange)
        es.mu.Unlock()

        if changed {
                log.Printf("[endpoint] URL updated: %s (source: %s)", newURL, source)
                es.save()
                for _, cb := range callbacks {
                        cb(newURL, source)
                }
        }
}

func (es *EndpointService) resolve() (string, string) {
        es.mu.RLock()
        override := es.overrideURL
        tm := es.tunnelManager
        port := es.localPort
        es.mu.RUnlock()

        if override != "" {
                return override, "override"
        }

        if tm != nil {
                tunnelURL := tm.URL()
                if tunnelURL != "" {
                        status := tm.GetStatus()
                        providerName := string(status.Provider)
                        return strings.TrimRight(tunnelURL, "/"), fmt.Sprintf("tunnel:%s", providerName)
                }
        }

        if envURL := os.Getenv("PUBLIC_URL"); envURL != "" {
                return strings.TrimRight(envURL, "/"), "env:PUBLIC_URL"
        }

        if ip := detectLocalIP(); ip != "" {
                return fmt.Sprintf("http://%s:%d", ip, port), fmt.Sprintf("local:%s", ip)
        }

        return fmt.Sprintf("http://localhost:%d", port), "localhost"
}

func (es *EndpointService) filePath() string {
        return filepath.Join(es.dataDir, "endpoint.json")
}

func (es *EndpointService) save() {
        state := es.State()
        data, err := json.MarshalIndent(state, "", "  ")
        if err != nil {
                log.Printf("[endpoint] Failed to marshal state: %v", err)
                return
        }
        if err := os.MkdirAll(es.dataDir, 0755); err != nil {
                log.Printf("[endpoint] Failed to create data dir: %v", err)
                return
        }
        if err := os.WriteFile(es.filePath(), data, 0644); err != nil {
                log.Printf("[endpoint] Failed to save state: %v", err)
        }
}

func (es *EndpointService) load() {
        data, err := os.ReadFile(es.filePath())
        if err != nil {
                return
        }
        var state EndpointState
        if err := json.Unmarshal(data, &state); err != nil {
                return
        }
        es.currentURL = state.URL
        es.source = state.Source
        if t, err := time.Parse(time.RFC3339, state.UpdatedAt); err == nil {
                es.updatedAt = t
        }
        log.Printf("[endpoint] Loaded previous state: %s (source: %s)", state.URL, state.Source)
}

func detectLocalIP() string {
        addrs, err := net.InterfaceAddrs()
        if err != nil {
                return ""
        }
        for _, addr := range addrs {
                if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
                        if ipNet.IP.To4() != nil {
                                return ipNet.IP.String()
                        }
                }
        }
        return ""
}
