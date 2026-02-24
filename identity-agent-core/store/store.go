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

func (s *FileStore) Close() error {
        return nil
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
