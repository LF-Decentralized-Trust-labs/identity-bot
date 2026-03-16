package store

import (
        "encoding/json"
        "fmt"
        "log"
        "os"
        "path/filepath"
        "sync"
        "time"
)

type EventRecord struct {
        AID            string `json:"aid"`
        SequenceNumber int    `json:"sequence_number"`
        EventType      string `json:"event_type"`
        EventJSON      string `json:"event_json"`
        PublicKey      string `json:"public_key"`
        NextKeyDigest  string `json:"next_key_digest"`
        Timestamp      string `json:"timestamp"`
        // CesrSignature: CESR '0B...' (88-char) signature over the event body.
        // Produced by Dart local signing + /api/cesr/encode. Empty for legacy records.
        CesrSignature  string `json:"cesr_signature,omitempty"`
}

type IdentityState struct {
        AID           string `json:"aid"`
        PublicKey     string `json:"public_key"`
        NextKeyDigest string `json:"next_key_digest"`
        Created       string `json:"created"`
        EventCount    int    `json:"event_count"`
}

type ContactRecord struct {
        AID          string `json:"aid"`
        Alias        string `json:"alias"`
        PublicKey    string `json:"public_key"`
        OobiURL      string `json:"oobi_url"`
        Verified     bool   `json:"verified"`
        DiscoveredAt string `json:"discovered_at"`
        Status       string `json:"status"`
        Role         string `json:"role"`
        JCard        *JCard `json:"jcard,omitempty"`
        Photo        string `json:"photo,omitempty"`
}

type JCard struct {
        FullName     string `json:"fn"`
        FamilyName   string `json:"family_name,omitempty"`
        GivenName    string `json:"given_name,omitempty"`
        Org          string `json:"org,omitempty"`
        Title        string `json:"title,omitempty"`
        Email        string `json:"email,omitempty"`
        Tel          string `json:"tel,omitempty"`
        Note         string `json:"note,omitempty"`
        UID          string `json:"uid,omitempty"`
        XKeriAID     string `json:"x-keri-aid"`
        XKeriOOBI    string `json:"x-keri-oobi,omitempty"`
        XKeriRole    string `json:"x-keri-role"`
}

type SettingsData struct {
        TunnelProvider        string `json:"tunnel_provider"`
        NgrokAuthToken        string `json:"ngrok_auth_token,omitempty"`
        CloudflareTunnelToken string `json:"cloudflare_tunnel_token,omitempty"`
        TunnelDomain          string `json:"tunnel_domain,omitempty"`
        TunnelExtension       string `json:"tunnel_extension,omitempty"`
}

type PendingRequest struct {
        AID         string `json:"aid"`
        Alias       string `json:"alias"`
        PublicKey   string `json:"public_key"`
        OobiURL     string `json:"oobi_url"`
        ReceivedAt  string `json:"received_at"`
        ExpiresAt   string `json:"expires_at"`
        ErrorReason string `json:"error_reason,omitempty"`
        JCard       *JCard `json:"jcard,omitempty"`
}

type ProfileData struct {
        FullName   string `json:"fn"`
        FamilyName string `json:"family_name,omitempty"`
        GivenName  string `json:"given_name,omitempty"`
        Org        string `json:"org,omitempty"`
        Title      string `json:"title,omitempty"`
        Email      string `json:"email,omitempty"`
        Tel        string `json:"tel,omitempty"`
        Note       string `json:"note,omitempty"`
        Photo      string `json:"photo,omitempty"`
        UID        string `json:"uid,omitempty"`
}

func (p *ProfileData) ToJCard(aid string, oobiURL string) *JCard {
        if p == nil {
                return nil
        }
        return &JCard{
                FullName:   p.FullName,
                FamilyName: p.FamilyName,
                GivenName:  p.GivenName,
                Org:        p.Org,
                Title:      p.Title,
                Email:      p.Email,
                Tel:        p.Tel,
                Note:       p.Note,
                UID:        p.UID,
                XKeriAID:   aid,
                XKeriOOBI:  oobiURL,
        }
}

// CredentialRecord stores an issued ACDC credential anchored in the issuer's KEL.
type CredentialRecord struct {
	SAID          string `json:"said"`
	IssuerAID     string `json:"issuer_aid"`
	HolderAID     string `json:"holder_aid"`
	SchemaSAID    string `json:"schema_said"`
	AcdcJson      string `json:"acdc_json"`
	IxnSAID       string `json:"ixn_said"`
	CesrSignature string `json:"cesr_signature,omitempty"`
	IssuedAt      string `json:"issued_at"`
	Status        string `json:"status"`
}

// PresentationRecord stores a verifiable presentation created by the holder.
type PresentationRecord struct {
	SAID                string `json:"said"`
	CredentialSAID      string `json:"credential_said"`
	HolderAID           string `json:"holder_aid"`
	IssuerAID           string `json:"issuer_aid"`
	PresentationJsonB64 string `json:"presentation_json_b64"`
	CesrSignature       string `json:"cesr_signature,omitempty"`
	CreatedAt           string `json:"created_at"`
	Status              string `json:"status"`
}

// ContactKELRecord stores a contact's validated Key Event Log.
// This is the cryptographic proof of a contact's identity history.
type ContactKELRecord struct {
        AID              string                   `json:"aid"`
        // KEL events as received from the contact's OOBI endpoint.
        KEL              []map[string]interface{} `json:"kel"`
        KelVerified      bool                     `json:"kel_verified"`
        // CurrentPublicKey: the CESR Ed25519 key active after the last validated event.
        CurrentPublicKey string                   `json:"current_public_key"`
        EventsValidated  int                      `json:"events_validated"`
        ValidationErrors []string                 `json:"validation_errors,omitempty"`
        ValidatedAt      string                   `json:"validated_at"`
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
        GetContactsByStatus(status string) ([]ContactRecord, error)
        SaveContactKEL(record ContactKELRecord) error
        GetContactKEL(aid string) (*ContactKELRecord, error)
        SaveCredential(record CredentialRecord) error
        GetCredential(said string) (*CredentialRecord, error)
        GetCredentials() ([]CredentialRecord, error)
        SavePresentation(record PresentationRecord) error
        GetPresentation(said string) (*PresentationRecord, error)
        GetPresentations() ([]PresentationRecord, error)
        GetSettings() (*SettingsData, error)
        SaveSettings(settings SettingsData) error
        SavePendingRequest(req PendingRequest) error
        GetPendingRequests() ([]PendingRequest, error)
        DeletePendingRequest(aid string) error
        GetProfile() (*ProfileData, error)
        SaveProfile(profile ProfileData) error
        ResetAll() error
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

func (s *FileStore) GetContactsByStatus(status string) ([]ContactRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        contacts, err := s.loadContacts()
        if err != nil {
                return nil, err
        }

        var filtered []ContactRecord
        for _, c := range contacts {
                if c.Status == status {
                        filtered = append(filtered, c)
                }
        }
        return filtered, nil
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

func (s *FileStore) SavePendingRequest(req PendingRequest) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        requests, err := s.loadPendingRequests()
        if err != nil {
                requests = []PendingRequest{}
        }

        updated := false
        for i, r := range requests {
                if r.AID == req.AID {
                        requests[i] = req
                        updated = true
                        break
                }
        }
        if !updated {
                requests = append(requests, req)
        }

        return s.writeJSON(filepath.Join(s.dir, "pending_requests.json"), requests)
}

func (s *FileStore) GetPendingRequests() ([]PendingRequest, error) {
        s.mu.Lock()
        defer s.mu.Unlock()

        requests, err := s.loadPendingRequests()
        if err != nil {
                return nil, err
        }

        now := time.Now()
        var active []PendingRequest
        var expired []string
        for _, r := range requests {
                expiry, err := time.Parse(time.RFC3339, r.ExpiresAt)
                if err != nil || now.Before(expiry) {
                        active = append(active, r)
                } else {
                        expired = append(expired, r.AID)
                }
        }

        if len(expired) > 0 {
                s.writeJSON(filepath.Join(s.dir, "pending_requests.json"), active)
                log.Printf("[store] Auto-deleted %d expired pending requests", len(expired))
        }

        if active == nil {
                active = []PendingRequest{}
        }
        return active, nil
}

func (s *FileStore) DeletePendingRequest(aid string) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        requests, err := s.loadPendingRequests()
        if err != nil {
                return err
        }

        var filtered []PendingRequest
        for _, r := range requests {
                if r.AID != aid {
                        filtered = append(filtered, r)
                }
        }

        return s.writeJSON(filepath.Join(s.dir, "pending_requests.json"), filtered)
}

func (s *FileStore) loadPendingRequests() ([]PendingRequest, error) {
        path := filepath.Join(s.dir, "pending_requests.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return []PendingRequest{}, nil
                }
                return nil, fmt.Errorf("failed to read pending requests: %w", err)
        }

        var requests []PendingRequest
        if err := json.Unmarshal(data, &requests); err != nil {
                return nil, fmt.Errorf("failed to parse pending requests: %w", err)
        }
        return requests, nil
}

func (s *FileStore) GetProfile() (*ProfileData, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        path := filepath.Join(s.dir, "profile.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return nil, nil
                }
                return nil, fmt.Errorf("failed to read profile: %w", err)
        }

        var profile ProfileData
        if err := json.Unmarshal(data, &profile); err != nil {
                return nil, fmt.Errorf("failed to parse profile: %w", err)
        }
        return &profile, nil
}

func (s *FileStore) SaveProfile(profile ProfileData) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        return s.writeJSON(filepath.Join(s.dir, "profile.json"), profile)
}

func (s *FileStore) SavePresentation(record PresentationRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        pres, err := s.loadPresentations()
        if err != nil {
                pres = map[string]PresentationRecord{}
        }
        pres[record.SAID] = record
        return s.writeJSON(filepath.Join(s.dir, "presentations.json"), pres)
}

func (s *FileStore) GetPresentation(said string) (*PresentationRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        pres, err := s.loadPresentations()
        if err != nil {
                return nil, err
        }
        r, ok := pres[said]
        if !ok {
                return nil, nil
        }
        return &r, nil
}

func (s *FileStore) GetPresentations() ([]PresentationRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        pres, err := s.loadPresentations()
        if err != nil {
                return nil, err
        }
        list := make([]PresentationRecord, 0, len(pres))
        for _, p := range pres {
                list = append(list, p)
        }
        return list, nil
}

func (s *FileStore) loadPresentations() (map[string]PresentationRecord, error) {
        path := filepath.Join(s.dir, "presentations.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return map[string]PresentationRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read presentations: %w", err)
        }
        var pres map[string]PresentationRecord
        if err := json.Unmarshal(data, &pres); err != nil {
                return nil, fmt.Errorf("failed to parse presentations: %w", err)
        }
        return pres, nil
}

func (s *FileStore) SaveCredential(record CredentialRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        creds, err := s.loadCredentials()
        if err != nil {
                creds = map[string]CredentialRecord{}
        }
        creds[record.SAID] = record
        return s.writeJSON(filepath.Join(s.dir, "credentials.json"), creds)
}

func (s *FileStore) GetCredential(said string) (*CredentialRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        creds, err := s.loadCredentials()
        if err != nil {
                return nil, err
        }
        r, ok := creds[said]
        if !ok {
                return nil, nil
        }
        return &r, nil
}

func (s *FileStore) GetCredentials() ([]CredentialRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        creds, err := s.loadCredentials()
        if err != nil {
                return nil, err
        }
        list := make([]CredentialRecord, 0, len(creds))
        for _, c := range creds {
                list = append(list, c)
        }
        return list, nil
}

func (s *FileStore) loadCredentials() (map[string]CredentialRecord, error) {
        path := filepath.Join(s.dir, "credentials.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return map[string]CredentialRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read credentials: %w", err)
        }
        var creds map[string]CredentialRecord
        if err := json.Unmarshal(data, &creds); err != nil {
                return nil, fmt.Errorf("failed to parse credentials: %w", err)
        }
        return creds, nil
}

func (s *FileStore) SaveContactKEL(record ContactKELRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kels, err := s.loadContactKELs()
	if err != nil {
		kels = map[string]ContactKELRecord{}
	}
	kels[record.AID] = record
	return s.writeJSON(filepath.Join(s.dir, "contact_kels.json"), kels)
}

func (s *FileStore) GetContactKEL(aid string) (*ContactKELRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	kels, err := s.loadContactKELs()
	if err != nil {
		return nil, err
	}
	r, ok := kels[aid]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (s *FileStore) loadContactKELs() (map[string]ContactKELRecord, error) {
	path := filepath.Join(s.dir, "contact_kels.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]ContactKELRecord{}, nil
		}
		return nil, fmt.Errorf("failed to read contact KELs: %w", err)
	}
	var kels map[string]ContactKELRecord
	if err := json.Unmarshal(data, &kels); err != nil {
		return nil, fmt.Errorf("failed to parse contact KELs: %w", err)
	}
	return kels, nil
}

func (s *FileStore) ResetAll() error {
        s.mu.Lock()
        defer s.mu.Unlock()

        files := []string{"identity.json", "kel.json", "contacts.json", "settings.json", "pending_requests.json", "profile.json", "endpoint.json", "contact_kels.json", "credentials.json", "presentations.json"}
        for _, f := range files {
                path := filepath.Join(s.dir, f)
                if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
                        return fmt.Errorf("failed to remove %s: %w", f, err)
                }
        }
        return nil
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
