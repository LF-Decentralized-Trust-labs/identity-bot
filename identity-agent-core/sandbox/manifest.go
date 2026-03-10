package sandbox

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "strings"
)

type AppManifest struct {
        ID             string            `json:"id"`
        Name           string            `json:"name"`
        Description    string            `json:"description"`
        Version        string            `json:"version"`
        Author         string            `json:"author"`
        ExecutionType  string            `json:"execution_type"`
        DisplayMethod  string            `json:"display_method"`
        NetworkMode    string            `json:"network_mode"`
        Container      *ContainerConfig  `json:"container,omitempty"`
        Binary         *BinaryConfig     `json:"binary,omitempty"`
        Resources      ResourceLimits    `json:"resources"`
        Network        NetworkPermissions `json:"network"`
        Capabilities   Capabilities      `json:"capabilities"`
        LogLevel       string            `json:"log_level"`
        Signature      *string           `json:"signature"`
        PublisherKey   *string           `json:"publisher_key"`
        SignatureAlgorithm *string       `json:"signature_algorithm"`
}

type ContainerConfig struct {
        Image       string            `json:"image"`
        Ports       map[string]string `json:"ports"`
        Environment map[string]string `json:"environment"`
        Volumes     map[string]string `json:"volumes"`
        DisplayPath string            `json:"display_path,omitempty"`
}

type BinaryConfig struct {
        Path       string            `json:"path"`
        Args       []string          `json:"args"`
        Environment map[string]string `json:"environment"`
}

type ResourceLimits struct {
        CPUCores    float64 `json:"cpu_cores"`
        MemoryMB    int     `json:"memory_mb"`
        DiskMB      int     `json:"disk_mb"`
        EgressKbps  int     `json:"egress_kbps"`
        IngressKbps int     `json:"ingress_kbps"`
}

type NetworkPermissions struct {
        TLSMode        string   `json:"tls_mode"`
        AllowedDomains []string `json:"allowed_domains"`
        BlockedDomains []string `json:"blocked_domains"`
}

type Capabilities struct {
        Allowed []string `json:"allowed"`
        Blocked []string `json:"blocked"`
}

func LoadManifest(path string) (*AppManifest, error) {
        data, err := os.ReadFile(path)
        if err != nil {
                return nil, fmt.Errorf("failed to read manifest file: %w", err)
        }

        var manifest AppManifest
        if err := json.Unmarshal(data, &manifest); err != nil {
                return nil, fmt.Errorf("failed to parse manifest: %w", err)
        }

        if err := manifest.Validate(); err != nil {
                return nil, fmt.Errorf("invalid manifest: %w", err)
        }

        return &manifest, nil
}

func LoadManifestsFromDir(dir string) ([]*AppManifest, error) {
        entries, err := os.ReadDir(dir)
        if err != nil {
                return nil, fmt.Errorf("failed to read manifests directory: %w", err)
        }

        var manifests []*AppManifest
        for _, entry := range entries {
                if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
                        continue
                }
                m, err := LoadManifest(filepath.Join(dir, entry.Name()))
                if err != nil {
                        return nil, fmt.Errorf("failed to load manifest %s: %w", entry.Name(), err)
                }
                manifests = append(manifests, m)
        }

        return manifests, nil
}

func (m *AppManifest) Validate() error {
        if m.ID == "" {
                return fmt.Errorf("id is required")
        }
        if m.Name == "" {
                return fmt.Errorf("name is required")
        }
        if m.ExecutionType != "container" && m.ExecutionType != "compiled" {
                return fmt.Errorf("execution_type must be 'container' or 'compiled', got '%s'", m.ExecutionType)
        }
        if m.DisplayMethod != "webview" && m.DisplayMethod != "terminal" {
                return fmt.Errorf("display_method must be 'webview' or 'terminal', got '%s'", m.DisplayMethod)
        }
        validNetworkModes := map[string]bool{
                "proxy_required": true,
                "proxy_optional": true,
                "isolated":       true,
                "local_only":     true,
        }
        if !validNetworkModes[m.NetworkMode] {
                return fmt.Errorf("network_mode must be one of proxy_required, proxy_optional, isolated, local_only; got '%s'", m.NetworkMode)
        }
        if m.ExecutionType == "container" && m.Container == nil {
                return fmt.Errorf("container config is required when execution_type is 'container'")
        }
        if m.ExecutionType == "compiled" && m.Binary == nil {
                return fmt.Errorf("binary config is required when execution_type is 'compiled'")
        }
        validTLSModes := map[string]bool{"mitm": true, "sni_only": true}
        if !validTLSModes[m.Network.TLSMode] {
                return fmt.Errorf("tls_mode must be 'mitm' or 'sni_only', got '%s'", m.Network.TLSMode)
        }
        validLogLevels := map[string]bool{"none": true, "metadata": true, "full": true}
        if !validLogLevels[m.LogLevel] {
                return fmt.Errorf("log_level must be 'none', 'metadata', or 'full'; got '%s'", m.LogLevel)
        }
        if m.Resources.MemoryMB <= 0 {
                return fmt.Errorf("resources.memory_mb must be positive")
        }
        return nil
}

func (m *AppManifest) ToJSON() (string, error) {
        data, err := json.MarshalIndent(m, "", "  ")
        if err != nil {
                return "", fmt.Errorf("failed to marshal manifest: %w", err)
        }
        return string(data), nil
}

func (m *AppManifest) IsContainer() bool {
        return m.ExecutionType == "container"
}

func (m *AppManifest) IsCompiled() bool {
        return m.ExecutionType == "compiled"
}

func (m *AppManifest) IsSigned() bool {
        return m.Signature != nil && *m.Signature != ""
}

func (m *AppManifest) DisplayPort() string {
        if m.Container == nil {
                return ""
        }
        for port, role := range m.Container.Ports {
                if role == "display" {
                        return port
                }
        }
        return ""
}

func MatchDomain(pattern, domain string) bool {
        pattern = strings.ToLower(pattern)
        domain = strings.ToLower(domain)

        if pattern == domain {
                return true
        }

        if strings.HasPrefix(pattern, "**.") {
                suffix := pattern[2:]
                return strings.HasSuffix(domain, suffix)
        }

        if strings.HasPrefix(pattern, "*.") {
                suffix := pattern[1:]
                if !strings.HasSuffix(domain, suffix) {
                        return false
                }
                prefix := strings.TrimSuffix(domain, suffix)
                return !strings.Contains(prefix, ".")
        }

        return false
}

func (m *AppManifest) IsDomainAllowed(domain string) (allowed bool, explicitRule bool) {
        for _, d := range m.Network.BlockedDomains {
                if MatchDomain(d, domain) {
                        return false, true
                }
        }
        for _, d := range m.Network.AllowedDomains {
                if MatchDomain(d, domain) {
                        return true, true
                }
        }
        return false, false
}
