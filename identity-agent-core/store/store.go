package store

import (
        "encoding/json"
        "fmt"
        "log"
        "os"
        "path/filepath"
        "sync"
)

type EventRecord struct {
        AID            string `json:"aid"`
        SequenceNumber int    `json:"sequence_number"`
        EventType      string `json:"event_type"`
        EventJSON      string `json:"event_json"`
        PublicKey      string `json:"public_key"`
        NextKeyDigest  string `json:"next_key_digest"`
        Timestamp      string `json:"timestamp"`
}

type IdentityState struct {
        AID           string `json:"aid"`
        PublicKey     string `json:"public_key"`
        NextKeyDigest string `json:"next_key_digest"`
        Created       string `json:"created"`
        EventCount    int    `json:"event_count"`
}

type ContactRecord struct {
        AID        string `json:"aid"`
        Alias      string `json:"alias"`
        PublicKey  string `json:"public_key"`
        OobiURL    string `json:"oobi_url"`
        Verified   bool   `json:"verified"`
        DiscoveredAt string `json:"discovered_at"`
}

type SettingsData struct {
        TunnelProvider        string `json:"tunnel_provider"`
        NgrokAuthToken        string `json:"ngrok_auth_token,omitempty"`
        CloudflareTunnelToken string `json:"cloudflare_tunnel_token,omitempty"`
}

type AppRecord struct {
        ID          string            `json:"id"`
        Name        string            `json:"name"`
        Description string            `json:"description"`
        Language    string            `json:"language"`
        EntryPoint  string            `json:"entry_point"`
        Status      string            `json:"status"`
        PolicyID    string            `json:"policy_id,omitempty"`
        RegisteredAt string           `json:"registered_at"`
        LastLaunchedAt string         `json:"last_launched_at,omitempty"`
        Metadata    map[string]string `json:"metadata,omitempty"`
}

type PolicyRecord struct {
        ID              string   `json:"id"`
        Name            string   `json:"name"`
        Description     string   `json:"description"`
        AllowedDomains  []string `json:"allowed_domains"`
        BlockedDomains  []string `json:"blocked_domains"`
        MaxSpend        float64  `json:"max_spend"`
        AllowFileWrite  bool     `json:"allow_file_write"`
        AllowNetAccess  bool     `json:"allow_net_access"`
        CreatedAt       string   `json:"created_at"`
        UpdatedAt       string   `json:"updated_at,omitempty"`
}

type AuditLogEntry struct {
        ID          string `json:"id"`
        AppID       string `json:"app_id"`
        AppName     string `json:"app_name"`
        EventType   string `json:"event_type"`
        Direction   string `json:"direction"`
        Target      string `json:"target"`
        Details     string `json:"details"`
        Action      string `json:"action"`
        Timestamp   string `json:"timestamp"`
}

type Store interface {
        SaveEvent(record EventRecord) error
        GetEvents(aid string) ([]EventRecord, error)
        GetIdentity() (*IdentityState, error)
        SaveIdentity(state IdentityState) error
        SaveContact(contact ContactRecord) error
        GetContacts() ([]ContactRecord, error)
        GetContact(aid string) (*ContactRecord, error)
        DeleteContact(aid string) error
        GetSettings() (*SettingsData, error)
        SaveSettings(settings SettingsData) error

        SaveApp(app AppRecord) error
        GetApps() ([]AppRecord, error)
        GetApp(id string) (*AppRecord, error)
        DeleteApp(id string) error

        SavePolicy(policy PolicyRecord) error
        GetPolicies() ([]PolicyRecord, error)
        GetPolicy(id string) (*PolicyRecord, error)
        DeletePolicy(id string) error

        AppendAuditLog(entry AuditLogEntry) error
        GetAuditLog(appID string, limit int) ([]AuditLogEntry, error)

        SaveSyscallEvents(events []SyscallEvent) error
        SaveNetworkEvents(events []NetworkEvent) error
        SaveFileAccessEvents(events []FileAccessEvent) error
        GetTelemetrySummary(appID string) (*TelemetrySummary, error)
        GetNetworkEvents(appID string, limit int) ([]NetworkEvent, error)
        GetSyscallEvents(appID string, limit int) ([]SyscallEvent, error)
        GetFileAccessEvents(appID string, limit int) ([]FileAccessEvent, error)

        SaveRegoPolicy(policy RegoPolicy) error
        GetRegoPolicies() ([]RegoPolicy, error)
        GetRegoPolicy(id string) (*RegoPolicy, error)
        DeleteRegoPolicy(id string) error

        Close() error
}

type FileStore struct {
        dir   string
        mu    sync.RWMutex
}

func NewFileStore(dir string) (*FileStore, error) {
        if err := os.MkdirAll(dir, 0755); err != nil {
                return nil, fmt.Errorf("failed to create store directory: %w", err)
        }
        log.Printf("[store] Initialized file store at: %s", dir)
        return &FileStore{dir: dir}, nil
}

func (s *FileStore) SaveEvent(record EventRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        events, err := s.loadEvents()
        if err != nil {
                events = []EventRecord{}
        }

        events = append(events, record)

        return s.writeJSON(filepath.Join(s.dir, "kel.json"), events)
}

func (s *FileStore) GetEvents(aid string) ([]EventRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        events, err := s.loadEvents()
        if err != nil {
                return nil, err
        }

        var filtered []EventRecord
        for _, e := range events {
                if e.AID == aid {
                        filtered = append(filtered, e)
                }
        }
        return filtered, nil
}

func (s *FileStore) GetIdentity() (*IdentityState, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        path := filepath.Join(s.dir, "identity.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return nil, nil
                }
                return nil, fmt.Errorf("failed to read identity: %w", err)
        }

        var state IdentityState
        if err := json.Unmarshal(data, &state); err != nil {
                return nil, fmt.Errorf("failed to parse identity: %w", err)
        }
        return &state, nil
}

func (s *FileStore) SaveIdentity(state IdentityState) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        return s.writeJSON(filepath.Join(s.dir, "identity.json"), state)
}

func (s *FileStore) SaveContact(contact ContactRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        contacts, err := s.loadContacts()
        if err != nil {
                contacts = []ContactRecord{}
        }

        updated := false
        for i, c := range contacts {
                if c.AID == contact.AID {
                        contacts[i] = contact
                        updated = true
                        break
                }
        }
        if !updated {
                contacts = append(contacts, contact)
        }

        return s.writeJSON(filepath.Join(s.dir, "contacts.json"), contacts)
}

func (s *FileStore) GetContacts() ([]ContactRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        return s.loadContacts()
}

func (s *FileStore) GetContact(aid string) (*ContactRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        contacts, err := s.loadContacts()
        if err != nil {
                return nil, err
        }

        for _, c := range contacts {
                if c.AID == aid {
                        return &c, nil
                }
        }
        return nil, nil
}

func (s *FileStore) DeleteContact(aid string) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        contacts, err := s.loadContacts()
        if err != nil {
                return err
        }

        var filtered []ContactRecord
        for _, c := range contacts {
                if c.AID != aid {
                        filtered = append(filtered, c)
                }
        }

        return s.writeJSON(filepath.Join(s.dir, "contacts.json"), filtered)
}

func (s *FileStore) GetSettings() (*SettingsData, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        path := filepath.Join(s.dir, "settings.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return nil, nil
                }
                return nil, fmt.Errorf("failed to read settings: %w", err)
        }

        var settings SettingsData
        if err := json.Unmarshal(data, &settings); err != nil {
                return nil, fmt.Errorf("failed to parse settings: %w", err)
        }
        return &settings, nil
}

func (s *FileStore) SaveSettings(settings SettingsData) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        return s.writeJSON(filepath.Join(s.dir, "settings.json"), settings)
}

func (s *FileStore) SaveApp(app AppRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        apps, err := s.loadApps()
        if err != nil {
                apps = []AppRecord{}
        }

        updated := false
        for i, a := range apps {
                if a.ID == app.ID {
                        apps[i] = app
                        updated = true
                        break
                }
        }
        if !updated {
                apps = append(apps, app)
        }

        return s.writeJSON(filepath.Join(s.dir, "apps.json"), apps)
}

func (s *FileStore) GetApps() ([]AppRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return s.loadApps()
}

func (s *FileStore) GetApp(id string) (*AppRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        apps, err := s.loadApps()
        if err != nil {
                return nil, err
        }
        for _, a := range apps {
                if a.ID == id {
                        return &a, nil
                }
        }
        return nil, nil
}

func (s *FileStore) DeleteApp(id string) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        apps, err := s.loadApps()
        if err != nil {
                return err
        }

        var filtered []AppRecord
        for _, a := range apps {
                if a.ID != id {
                        filtered = append(filtered, a)
                }
        }
        return s.writeJSON(filepath.Join(s.dir, "apps.json"), filtered)
}

func (s *FileStore) SavePolicy(policy PolicyRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        policies, err := s.loadPolicies()
        if err != nil {
                policies = []PolicyRecord{}
        }

        updated := false
        for i, p := range policies {
                if p.ID == policy.ID {
                        policies[i] = policy
                        updated = true
                        break
                }
        }
        if !updated {
                policies = append(policies, policy)
        }

        return s.writeJSON(filepath.Join(s.dir, "policies.json"), policies)
}

func (s *FileStore) GetPolicies() ([]PolicyRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return s.loadPolicies()
}

func (s *FileStore) GetPolicy(id string) (*PolicyRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        policies, err := s.loadPolicies()
        if err != nil {
                return nil, err
        }
        for _, p := range policies {
                if p.ID == id {
                        return &p, nil
                }
        }
        return nil, nil
}

func (s *FileStore) DeletePolicy(id string) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        policies, err := s.loadPolicies()
        if err != nil {
                return err
        }

        var filtered []PolicyRecord
        for _, p := range policies {
                if p.ID != id {
                        filtered = append(filtered, p)
                }
        }
        return s.writeJSON(filepath.Join(s.dir, "policies.json"), filtered)
}

func (s *FileStore) AppendAuditLog(entry AuditLogEntry) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        entries, err := s.loadAuditLog()
        if err != nil {
                entries = []AuditLogEntry{}
        }

        entries = append(entries, entry)

        const maxEntries = 1000
        if len(entries) > maxEntries {
                entries = entries[len(entries)-maxEntries:]
        }

        return s.writeJSON(filepath.Join(s.dir, "audit_log.json"), entries)
}

func (s *FileStore) GetAuditLog(appID string, limit int) ([]AuditLogEntry, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        entries, err := s.loadAuditLog()
        if err != nil {
                return nil, err
        }

        if appID != "" {
                var filtered []AuditLogEntry
                for _, e := range entries {
                        if e.AppID == appID {
                                filtered = append(filtered, e)
                        }
                }
                entries = filtered
        }

        if limit > 0 && len(entries) > limit {
                entries = entries[len(entries)-limit:]
        }

        return entries, nil
}

func (s *FileStore) SaveSyscallEvents(events []SyscallEvent) error {
        return fmt.Errorf("telemetry not supported in file store — use PostgresStore")
}

func (s *FileStore) SaveNetworkEvents(events []NetworkEvent) error {
        return fmt.Errorf("telemetry not supported in file store — use PostgresStore")
}

func (s *FileStore) SaveFileAccessEvents(events []FileAccessEvent) error {
        return fmt.Errorf("telemetry not supported in file store — use PostgresStore")
}

func (s *FileStore) GetTelemetrySummary(appID string) (*TelemetrySummary, error) {
        return &TelemetrySummary{AppID: appID}, nil
}

func (s *FileStore) GetNetworkEvents(appID string, limit int) ([]NetworkEvent, error) {
        return []NetworkEvent{}, nil
}

func (s *FileStore) GetSyscallEvents(appID string, limit int) ([]SyscallEvent, error) {
        return []SyscallEvent{}, nil
}

func (s *FileStore) GetFileAccessEvents(appID string, limit int) ([]FileAccessEvent, error) {
        return []FileAccessEvent{}, nil
}

func (s *FileStore) SaveRegoPolicy(policy RegoPolicy) error {
        return fmt.Errorf("rego policies not supported in file store — use PostgresStore")
}

func (s *FileStore) GetRegoPolicies() ([]RegoPolicy, error) {
        return []RegoPolicy{}, nil
}

func (s *FileStore) GetRegoPolicy(id string) (*RegoPolicy, error) {
        return nil, nil
}

func (s *FileStore) DeleteRegoPolicy(id string) error {
        return fmt.Errorf("rego policies not supported in file store — use PostgresStore")
}

func (s *FileStore) Close() error {
        return nil
}

func (s *FileStore) loadApps() ([]AppRecord, error) {
        path := filepath.Join(s.dir, "apps.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return []AppRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read apps: %w", err)
        }
        var apps []AppRecord
        if err := json.Unmarshal(data, &apps); err != nil {
                return nil, fmt.Errorf("failed to parse apps: %w", err)
        }
        return apps, nil
}

func (s *FileStore) loadPolicies() ([]PolicyRecord, error) {
        path := filepath.Join(s.dir, "policies.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return []PolicyRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read policies: %w", err)
        }
        var policies []PolicyRecord
        if err := json.Unmarshal(data, &policies); err != nil {
                return nil, fmt.Errorf("failed to parse policies: %w", err)
        }
        return policies, nil
}

func (s *FileStore) loadAuditLog() ([]AuditLogEntry, error) {
        path := filepath.Join(s.dir, "audit_log.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return []AuditLogEntry{}, nil
                }
                return nil, fmt.Errorf("failed to read audit log: %w", err)
        }
        var entries []AuditLogEntry
        if err := json.Unmarshal(data, &entries); err != nil {
                return nil, fmt.Errorf("failed to parse audit log: %w", err)
        }
        return entries, nil
}

func (s *FileStore) loadContacts() ([]ContactRecord, error) {
        path := filepath.Join(s.dir, "contacts.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return []ContactRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read contacts: %w", err)
        }

        var contacts []ContactRecord
        if err := json.Unmarshal(data, &contacts); err != nil {
                return nil, fmt.Errorf("failed to parse contacts: %w", err)
        }
        return contacts, nil
}

func (s *FileStore) loadEvents() ([]EventRecord, error) {
        path := filepath.Join(s.dir, "kel.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return []EventRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read KEL: %w", err)
        }

        var events []EventRecord
        if err := json.Unmarshal(data, &events); err != nil {
                return nil, fmt.Errorf("failed to parse KEL: %w", err)
        }
        return events, nil
}

func (s *FileStore) writeJSON(path string, v interface{}) error {
        data, err := json.MarshalIndent(v, "", "  ")
        if err != nil {
                return fmt.Errorf("failed to marshal data: %w", err)
        }
        if err := os.WriteFile(path, data, 0644); err != nil {
                return fmt.Errorf("failed to write file: %w", err)
        }
        return nil
}
