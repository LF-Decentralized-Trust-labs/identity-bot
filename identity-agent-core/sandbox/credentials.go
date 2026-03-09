package sandbox

import (
        "encoding/json"
        "fmt"
        "log"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "sync"
)

type CredentialEntry struct {
        Service      string            `json:"service"`
        MatchDomains []string          `json:"match_domains"`
        Headers      map[string]string `json:"headers"`
}

type CredentialVault struct {
        dataDir string
        entries []CredentialEntry
        tracer  *Tracer
        mu      sync.RWMutex
}

func NewCredentialVault(dataDir string) *CredentialVault {
        cv := &CredentialVault{
                dataDir: dataDir,
        }
        cv.Reload()
        return cv
}

func (cv *CredentialVault) Reload() {
        cv.mu.Lock()
        defer cv.mu.Unlock()

        credPath := filepath.Join(cv.dataDir, "credentials.json")
        data, err := os.ReadFile(credPath)
        if err != nil {
                settingsPath := filepath.Join(cv.dataDir, "settings.json")
                data, err = os.ReadFile(settingsPath)
                if err != nil {
                        cv.entries = nil
                        return
                }
                var settings map[string]interface{}
                if err := json.Unmarshal(data, &settings); err != nil {
                        cv.entries = nil
                        return
                }
                cv.entries = cv.extractFromSettings(settings)
                return
        }

        var entries []CredentialEntry
        if err := json.Unmarshal(data, &entries); err != nil {
                log.Printf("[credentials] Failed to parse credentials.json: %v", err)
                cv.entries = nil
                return
        }
        cv.entries = entries
}

func (cv *CredentialVault) extractFromSettings(settings map[string]interface{}) []CredentialEntry {
        var entries []CredentialEntry

        if apiKey, ok := settings["openrouter_api_key"].(string); ok && apiKey != "" {
                entries = append(entries, CredentialEntry{
                        Service:      "openrouter",
                        MatchDomains: []string{"*.openrouter.ai", "openrouter.ai"},
                        Headers: map[string]string{
                                "Authorization": "Bearer " + apiKey,
                        },
                })
        }

        if apiKey, ok := settings["openai_api_key"].(string); ok && apiKey != "" {
                entries = append(entries, CredentialEntry{
                        Service:      "openai",
                        MatchDomains: []string{"*.openai.com", "api.openai.com"},
                        Headers: map[string]string{
                                "Authorization": "Bearer " + apiKey,
                        },
                })
        }

        return entries
}

func (cv *CredentialVault) InjectCredentials(req *http.Request) bool {
        cv.mu.RLock()
        defer cv.mu.RUnlock()

        domain := req.URL.Hostname()
        if domain == "" {
                domain = req.Host
        }
        if idx := strings.Index(domain, ":"); idx > 0 {
                domain = domain[:idx]
        }

        for _, entry := range cv.entries {
                for _, pattern := range entry.MatchDomains {
                        if MatchDomain(pattern, domain) {
                                injectedHeaders := make([]string, 0, len(entry.Headers))
                                for key, value := range entry.Headers {
                                        if req.Header.Get(key) == "" {
                                                req.Header.Set(key, value)
                                                injectedHeaders = append(injectedHeaders, key)
                                        }
                                }
                                log.Printf("[credentials] Injected %s credentials for domain %s", entry.Service, domain)
                                if cv.tracer != nil && cv.tracer.IsEnabled() {
                                        cv.tracer.Emit("credentials", "inject", "egress", "", "",
                                                fmt.Sprintf("Injected %s credentials for %s", entry.Service, domain),
                                                map[string]interface{}{"service": entry.Service, "domain": domain, "pattern": pattern, "headers_injected": injectedHeaders})
                                }
                                return true
                        }
                }
        }

        if cv.tracer != nil && cv.tracer.IsEnabled() {
                cv.tracer.Emit("credentials", "no_match", "egress", "", "",
                        fmt.Sprintf("No credentials matched for %s", domain),
                        map[string]interface{}{"domain": domain, "services_checked": len(cv.entries)})
        }

        return false
}

func (cv *CredentialVault) SetCredential(service string, domains []string, headers map[string]string) error {
        cv.mu.Lock()
        defer cv.mu.Unlock()

        for i, e := range cv.entries {
                if e.Service == service {
                        cv.entries[i].MatchDomains = domains
                        cv.entries[i].Headers = headers
                        return cv.persist()
                }
        }

        cv.entries = append(cv.entries, CredentialEntry{
                Service:      service,
                MatchDomains: domains,
                Headers:      headers,
        })
        return cv.persist()
}

func (cv *CredentialVault) RemoveCredential(service string) error {
        cv.mu.Lock()
        defer cv.mu.Unlock()

        for i, e := range cv.entries {
                if e.Service == service {
                        cv.entries = append(cv.entries[:i], cv.entries[i+1:]...)
                        return cv.persist()
                }
        }
        return nil
}

func (cv *CredentialVault) ListServices() []string {
        cv.mu.RLock()
        defer cv.mu.RUnlock()

        var services []string
        for _, e := range cv.entries {
                services = append(services, e.Service)
        }
        return services
}

func (cv *CredentialVault) persist() error {
        credPath := filepath.Join(cv.dataDir, "credentials.json")
        data, err := json.MarshalIndent(cv.entries, "", "  ")
        if err != nil {
                return err
        }
        return os.WriteFile(credPath, data, 0600)
}
