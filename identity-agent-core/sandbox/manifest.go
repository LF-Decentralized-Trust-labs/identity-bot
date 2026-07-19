package sandbox

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "runtime"
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
        APISchema          *string       `json:"api_schema,omitempty"`

        // --- Plug-in profile extension (additive; absent on legacy manifests) ---
        Kind               string               `json:"kind,omitempty"`                // capability | bundle | app
        SubType            string               `json:"sub_type,omitempty"`            // go-binary | oci-container | web | paired-native
        Provides           []ProvidedCapability `json:"provides,omitempty"`            // functional capabilities offered (NOT device permissions)
        HostControl        *HostControlSpec     `json:"host_control,omitempty"`        // host-takeover grants (e.g. native computer use)
        SupportedPlatforms []PlatformBinary     `json:"supported_platforms,omitempty"` // per-OS binaries; resolved into Binary at load
}

// ProvidedCapability is one functional capability a plug-in offers. Distinct from
// Capabilities (device permissions); the agent surfaces these to callers via its endpoint.
type ProvidedCapability struct {
        ID               string `json:"id"`
        Name             string `json:"name"`
        Description      string `json:"description"`
        RequestContract  string `json:"request_contract"`
        Docs             string `json:"docs,omitempty"`
        ACDCScope        string `json:"acdc_scope"`
        EnabledByDefault bool   `json:"enabled_by_default"`
        HostControl      bool   `json:"host_control"`
}

// HostControlSpec declares the host-OS grants a host_control capability needs before
// it may act. The grant is OS-forced; the agent surfaces it, never asserts it.
type HostControlSpec struct {
        GrantsRequired map[string][]string `json:"grants_required"` // os -> required grants
        KillSwitch     bool                `json:"kill_switch"`
}

// PlatformBinary is one per-OS build artifact. The loader selects the entry matching
// the host (os + arch) and resolves it into Binary at load time, so the runtime can
// launch it unchanged.
type PlatformBinary struct {
        OS         string   `json:"os"`
        MinVersion string   `json:"min_version"`
        Arch       []string `json:"arch"`
        Binary     string   `json:"binary"`
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

        // Resolve the host-matching binary for plug-ins that declare per-OS artifacts
        // via supported_platforms instead of a single binary.path.
        manifest.resolveHostBinary()

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

// Validate checks an app manifest against the rules the agent enforces at load.
//
// CROSS-REPO CONTRACT: an external plug-in build tool validates manifests against
// these same rules *before* producing them, so a manifest that passes the build also
// loads here ("builds implies installs"). If you change the schema or these rules,
// the build-side validator must be updated to match — otherwise it will emit manifests
// the agent rejects, or carry fields the agent silently ignores. Until a shared schema
// package exists, keep the two validators in sync by hand.
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
                if len(m.SupportedPlatforms) > 0 {
                        return fmt.Errorf("no supported_platforms entry matches this host (%s/%s)", runtime.GOOS, runtime.GOARCH)
                }
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

        // --- Plug-in profile extension (validated only when present) ---
        if m.Kind != "" {
                validKinds := map[string]bool{"capability": true, "bundle": true, "app": true}
                if !validKinds[m.Kind] {
                        return fmt.Errorf("kind must be 'capability', 'bundle', or 'app'; got '%s'", m.Kind)
                }
        }
        if m.SubType != "" {
                validSubTypes := map[string]bool{"go-binary": true, "oci-container": true, "web": true, "paired-native": true}
                if !validSubTypes[m.SubType] {
                        return fmt.Errorf("sub_type must be one of go-binary, oci-container, web, paired-native; got '%s'", m.SubType)
                }
        }
        for i, p := range m.Provides {
                if p.ID == "" {
                        return fmt.Errorf("provides[%d].id is required", i)
                }
        }
        for i, p := range m.SupportedPlatforms {
                validOS := map[string]bool{"darwin": true, "windows": true, "linux": true}
                if !validOS[p.OS] {
                        return fmt.Errorf("supported_platforms[%d].os must be darwin, windows, or linux; got '%s'", i, p.OS)
                }
                if p.Binary == "" {
                        return fmt.Errorf("supported_platforms[%d].binary is required", i)
                }
        }
        return nil
}

// resolveHostBinary picks the supported_platforms entry matching this host and, for a
// compiled plug-in that declares per-OS binaries instead of a single binary path,
// populates Binary so the runtime launches it unchanged. No-op for legacy manifests
// (no supported_platforms) or when Binary is already set.
func (m *AppManifest) resolveHostBinary() {
        if m.Binary != nil || len(m.SupportedPlatforms) == 0 {
                return
        }
        if path, ok := m.SelectPlatformBinary(runtime.GOOS, runtime.GOARCH); ok {
                m.Binary = &BinaryConfig{Path: path}
        }
}

// SelectPlatformBinary returns the binary path for the given host os/arch if a
// supported_platforms entry matches (empty arch list matches any arch).
func (m *AppManifest) SelectPlatformBinary(goos, goarch string) (string, bool) {
        for _, p := range m.SupportedPlatforms {
                if !strings.EqualFold(p.OS, goos) {
                        continue
                }
                if len(p.Arch) == 0 {
                        return p.Binary, true
                }
                for _, a := range p.Arch {
                        if strings.EqualFold(a, goarch) {
                                return p.Binary, true
                        }
                }
        }
        return "", false
}

// ProvidedCapabilityIDs returns the ids of the functional capabilities this plug-in
// offers (the `provides` list). The agent surfaces these to callers via its endpoint.
func (m *AppManifest) ProvidedCapabilityIDs() []string {
        ids := make([]string, 0, len(m.Provides))
        for _, p := range m.Provides {
                ids = append(ids, p.ID)
        }
        return ids
}

// RequiresHostControl reports whether any provided capability takes over the host OS.
func (m *AppManifest) RequiresHostControl() bool {
        if m.HostControl != nil {
                return true
        }
        for _, p := range m.Provides {
                if p.HostControl {
                        return true
                }
        }
        return false
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
