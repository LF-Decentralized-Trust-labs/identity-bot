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

// ContactRecord stores a resolved contact in the Identity Agent.
//
// Two-axis contact model:
//   - ContactSource (provenance): "keri" | "imported" | "manual"
//   - ContactCategory (user-facing label): "transactional" | "general" | "trusted" | "professional"
// Relationship AIDs are standalone icp (never dip for ordinary relationships).
// The Root AID never appears in OOBI/QR/bundle/DIDComm for relationships; a per-contact
// RelationshipAID (our local standalone P-AID) is used for outbound identity with this contact.
// A private salted-hash binding (at issuer) anchors the contact's Root to its relationship P-AID.
type ContactRecord struct {
        AID             string `json:"aid"`
        Alias           string `json:"alias"`
        PublicKey       string `json:"public_key"`
        OobiURL         string `json:"oobi_url"`
        Verified        bool   `json:"verified"`
        DiscoveredAt    string `json:"discovered_at"`
        Status          string `json:"status"`
        ContactSource   string `json:"contact_source"`   // keri | imported | manual
        ContactCategory string `json:"contact_category"` // transactional | general | trusted | professional
        RelationshipAID     string `json:"relationship_aid,omitempty"`     // our per-contact standalone icp P-AID for this contact (Root never disclosed for relationships) -- the handle/reference
        RelationshipSeedB64 string `json:"relationship_seed_b64,omitempty"` // deprecated for secrets; kept for schema compat only. Private seeds live in secureenclave storage (AID is the key). Never write raw seeds here.
        IsWitness           bool   `json:"is_witness"`     // KERI witness role — auto-managed
        JCard               *JCard `json:"jcard,omitempty"`
        Photo               string `json:"photo,omitempty"`
}

// TaskRecord represents an automated background task tracked by the Identity Agent.
// Tasks are always automated — they show system operation status, not user actions.
// Status: "pending" | "in_progress" | "completed" | "failed"
type TaskRecord struct {
        ID         string `json:"id"`
        Type       string `json:"type"`        // e.g. "witness_request_sent", "kel_sync"
        Status     string `json:"status"`
        ContactAID string `json:"contact_aid"` // related contact AID, if applicable
        Progress   int    `json:"progress"`    // 0–100
        Detail     string `json:"detail"`      // human-readable status message
        CreatedAt  string `json:"created_at"`
        UpdatedAt  string `json:"updated_at"`
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

        // Organization-specific fields (entity_type = "organization").
        // Identity Agent Protocol-level per ADR-020. Jurisdiction is free-text for now (formal spec TBD).
        EntityType   string `json:"entity_type,omitempty"`   // "individual" | "organization"
        OrgName      string `json:"org_name,omitempty"`
        OrgType      string `json:"org_type,omitempty"`      // e.g. "school", "business", "healthcare"
        Jurisdiction string `json:"jurisdiction,omitempty"`  // free-text for now
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

// CredentialRecord stores a credential held or issued by this agent.
// format: "acdc" | "w3c_vc" | "sd_jwt" | "mdl"
// For non-ACDC formats, raw_json holds the original bytes and acdc_json holds the thin ACDC wrapper
// anchored to the holder's KEL via an IXN event.
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
	Format        string `json:"format"`
	CredentialType string `json:"credential_type"`
	IssuerName    string `json:"issuer_name"`
	IssuerLogoURL string `json:"issuer_logo_url"`
	ExpiryDate    string `json:"expiry_date"`
	RawJson       string `json:"raw_json,omitempty"`
}

// CredentialSchemaRecord caches a fetched ACDC schema by its SAID.
type CredentialSchemaRecord struct {
	SAID       string `json:"said"`
	SchemaJson string `json:"schema_json"`
	FetchedAt  string `json:"fetched_at"`
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

// ShareAction defines a user-facing engagement action shown in the Share menu.
// The list is managed by the Data Manager sandbox app and persisted in identity.db.
// Actions with IsEnabled=false appear in the UI as "Coming Soon".
type ShareAction struct {
	ID        string `json:"id"`
	ActionKey string `json:"action_key"` // used as ?action= param in OOBI URLs
	Name      string `json:"name"`
	Subtitle  string `json:"subtitle"`
	Icon      string `json:"icon"`       // Material Icons name string
	IsEnabled bool   `json:"is_enabled"`
	SortOrder int    `json:"sort_order"`
	UpdatedAt string `json:"updated_at"`
}

// WitnessReceiptRecord stores one witness receipt for a specific event SAID.
// Receipts are deduplicated by (EventSAID, WitnessAID).
type WitnessReceiptRecord struct {
	EventSAID     string `json:"event_said"`
	WitnessAID    string `json:"witness_aid"`
	CesrSignature string `json:"cesr_signature"`
	ReceivedAt    string `json:"received_at"`
}

// KerlEntry is a Key Event Receipt Log entry: one event plus all its receipts.
type KerlEntry struct {
	EventSAID     string                `json:"event_said"`
	Receipts      []WitnessReceiptRecord `json:"receipts"`
	ReceiptCount  int                   `json:"receipt_count"`
	ThresholdMet  bool                  `json:"threshold_met"`
}

// ── Guardianship ────────────────────────────────────────────────────────────

type GuardianshipRecord struct {
        ID                  string             `json:"id"`
        Type                string             `json:"type"`                // minor_child|elderly|disability|temporary
        GuardianAID         string             `json:"guardian_aid"`
        DependentAID        string             `json:"dependent_aid"`
        DependentName       string             `json:"dependent_name"`
        DelegatedAIDPrefix  string             `json:"delegated_aid_prefix"`
        Status              string             `json:"status"`              // active|expired|revoked|emancipated
        HostingType         string             `json:"hosting_type"`        // cloud|device
        HostingURL          string             `json:"hosting_url"`
        CreatedAt           string             `json:"created_at"`
        UpdatedAt           string             `json:"updated_at"`
        EmancipationTrigger *EmancipationTrigger `json:"emancipation_trigger,omitempty"`
        CoGuardians         []string           `json:"co_guardians"`
        MultisigThreshold   int                `json:"multisig_threshold"`
        Metadata            map[string]string  `json:"metadata"`
        CredentialSAID      string             `json:"credential_said"` // SAID of the guardianship ACDC proving this relationship
}

type EmancipationTrigger struct {
        Type  string `json:"type"`  // age|date|manual
        Value string `json:"value"` // date string or empty for manual
}

// ── Service Providers ───────────────────────────────────────────────────────

type ServiceProviderRecord struct {
        ID              string            `json:"id"`
        ProviderName    string            `json:"provider_name"`
        ProviderAID     string            `json:"provider_aid"`
        Category        string            `json:"category"`         // infrastructure|witness|cloud_hsm|tunneling
        DisplayName     string            `json:"display_name"`
        EndpointURL     string            `json:"endpoint_url"`
        Status          string            `json:"status"`           // available|connected|disconnected|error
        Health          string            `json:"health"`           // healthy|degraded|unreachable|unknown
        HealthCheckedAt string            `json:"health_checked_at"`
        CompanyHQ       string            `json:"company_hq"`
        ServerRegion    string            `json:"server_region"`
        IdentityLevel   int               `json:"identity_level"`
        GrapeScore      int               `json:"grape_score"`
        Capabilities    []string          `json:"capabilities"`
        TermsURL        string            `json:"terms_url"`
        TermsAcceptedAt string            `json:"terms_accepted_at"`
        TermsVersion    string            `json:"terms_version"`
        ConnectedAt     string            `json:"connected_at"`
        Configuration   map[string]string `json:"configuration"`
        IsDefault       bool              `json:"is_default"`
        Source          string            `json:"source"`           // builtin|directory|manual
        CreatedAt       string            `json:"created_at"`
        UpdatedAt       string            `json:"updated_at"`
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
        GetCredentialsFiltered(role, status string) ([]CredentialRecord, error)
        UpdateCredentialStatus(said, status string) error
        DeleteCredential(said string) error
        SaveCredentialSchema(record CredentialSchemaRecord) error
        GetCredentialSchemas() ([]CredentialSchemaRecord, error)
        GetCredentialSchema(said string) (*CredentialSchemaRecord, error)
        SavePresentation(record PresentationRecord) error
        GetPresentation(said string) (*PresentationRecord, error)
        GetPresentations() ([]PresentationRecord, error)
        SaveWitnessReceipt(record WitnessReceiptRecord) error
        GetWitnessReceipts(eventSAID string) ([]WitnessReceiptRecord, error)
        GetSettings() (*SettingsData, error)
        SaveSettings(settings SettingsData) error
        SavePendingRequest(req PendingRequest) error
        GetPendingRequests() ([]PendingRequest, error)
        DeletePendingRequest(aid string) error
        GetProfile() (*ProfileData, error)
        SaveProfile(profile ProfileData) error
        SaveTask(task TaskRecord) error
        GetTasks() ([]TaskRecord, error)
        GetTask(id string) (*TaskRecord, error)
        DeleteTask(id string) error
        GetShareActions() ([]ShareAction, error)
        GetShareAction(id string) (*ShareAction, error)
        UpsertShareAction(action ShareAction) error
        DeleteShareAction(id string) error
        SaveGuardianship(record GuardianshipRecord) error
        GetGuardianships() ([]GuardianshipRecord, error)
        GetGuardianship(id string) (*GuardianshipRecord, error)
        GetGuardianshipByDependentAID(dependentAID string) (*GuardianshipRecord, error)
        DeleteGuardianship(id string) error
        SaveServiceProvider(record ServiceProviderRecord) error
        GetServiceProviders() ([]ServiceProviderRecord, error)
        GetServiceProvider(id string) (*ServiceProviderRecord, error)
        GetServiceProvidersByCategory(category string) ([]ServiceProviderRecord, error)
        GetServiceProvidersByStatus(status string) ([]ServiceProviderRecord, error)
        DeleteServiceProvider(id string) error
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

func (s *FileStore) GetCredentialsFiltered(role, status string) ([]CredentialRecord, error) {
        // FileStore is only used in tests/mobile fallback; full filtering not needed.
        return s.GetCredentials()
}

func (s *FileStore) UpdateCredentialStatus(said, status string) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        creds, err := s.loadCredentials()
        if err != nil {
                return err
        }
        if c, ok := creds[said]; ok {
                c.Status = status
                creds[said] = c
                return s.writeJSON(filepath.Join(s.dir, "credentials.json"), creds)
        }
        return nil
}

func (s *FileStore) DeleteCredential(said string) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        creds, err := s.loadCredentials()
        if err != nil {
                return err
        }
        delete(creds, said)
        return s.writeJSON(filepath.Join(s.dir, "credentials.json"), creds)
}

func (s *FileStore) SaveCredentialSchema(record CredentialSchemaRecord) error {
        s.mu.Lock()
        defer s.mu.Unlock()

        schemas, err := s.loadCredentialSchemas()
        if err != nil {
                schemas = map[string]CredentialSchemaRecord{}
        }
        schemas[record.SAID] = record
        return s.writeJSON(filepath.Join(s.dir, "credential_schemas.json"), schemas)
}

func (s *FileStore) GetCredentialSchemas() ([]CredentialSchemaRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        schemas, err := s.loadCredentialSchemas()
        if err != nil {
                return nil, err
        }
        list := make([]CredentialSchemaRecord, 0, len(schemas))
        for _, sc := range schemas {
                list = append(list, sc)
        }
        return list, nil
}

func (s *FileStore) GetCredentialSchema(said string) (*CredentialSchemaRecord, error) {
        s.mu.RLock()
        defer s.mu.RUnlock()

        schemas, err := s.loadCredentialSchemas()
        if err != nil {
                return nil, err
        }
        r, ok := schemas[said]
        if !ok {
                return nil, nil
        }
        return &r, nil
}

func (s *FileStore) loadCredentialSchemas() (map[string]CredentialSchemaRecord, error) {
        path := filepath.Join(s.dir, "credential_schemas.json")
        data, err := os.ReadFile(path)
        if err != nil {
                if os.IsNotExist(err) {
                        return map[string]CredentialSchemaRecord{}, nil
                }
                return nil, fmt.Errorf("failed to read credential schemas: %w", err)
        }
        var schemas map[string]CredentialSchemaRecord
        if err := json.Unmarshal(data, &schemas); err != nil {
                return nil, fmt.Errorf("failed to parse credential schemas: %w", err)
        }
        return schemas, nil
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

func (s *FileStore) SaveWitnessReceipt(record WitnessReceiptRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	receipts, err := s.loadWitnessReceipts()
	if err != nil {
		receipts = map[string][]WitnessReceiptRecord{}
	}
	key := record.EventSAID
	existing := receipts[key]
	for _, r := range existing {
		if r.WitnessAID == record.WitnessAID {
			return nil // already stored, deduplicate
		}
	}
	receipts[key] = append(existing, record)
	return s.writeJSON(filepath.Join(s.dir, "witness_receipts.json"), receipts)
}

func (s *FileStore) GetWitnessReceipts(eventSAID string) ([]WitnessReceiptRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	receipts, err := s.loadWitnessReceipts()
	if err != nil {
		return nil, err
	}
	return receipts[eventSAID], nil
}

func (s *FileStore) loadWitnessReceipts() (map[string][]WitnessReceiptRecord, error) {
	path := filepath.Join(s.dir, "witness_receipts.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]WitnessReceiptRecord{}, nil
		}
		return nil, fmt.Errorf("failed to read witness receipts: %w", err)
	}
	var receipts map[string][]WitnessReceiptRecord
	if err := json.Unmarshal(data, &receipts); err != nil {
		return nil, fmt.Errorf("failed to parse witness receipts: %w", err)
	}
	return receipts, nil
}

// ── Guardianship (FileStore stubs — SQLiteStore is the active implementation) ─

func (s *FileStore) SaveGuardianship(record GuardianshipRecord) error {
        return fmt.Errorf("guardianship not supported by FileStore — use SQLiteStore")
}

func (s *FileStore) GetGuardianships() ([]GuardianshipRecord, error) {
        return []GuardianshipRecord{}, nil
}

func (s *FileStore) GetGuardianship(id string) (*GuardianshipRecord, error) {
        return nil, nil
}

func (s *FileStore) GetGuardianshipByDependentAID(dependentAID string) (*GuardianshipRecord, error) {
        return nil, nil
}

func (s *FileStore) DeleteGuardianship(id string) error {
        return fmt.Errorf("guardianship not supported by FileStore — use SQLiteStore")
}

// ── Service Provider (FileStore stubs — SQLiteStore is the active implementation) ─

func (s *FileStore) SaveServiceProvider(record ServiceProviderRecord) error {
        return fmt.Errorf("service providers not supported by FileStore — use SQLiteStore")
}

func (s *FileStore) GetServiceProviders() ([]ServiceProviderRecord, error) {
        return []ServiceProviderRecord{}, nil
}

func (s *FileStore) GetServiceProvider(id string) (*ServiceProviderRecord, error) {
        return nil, nil
}

func (s *FileStore) GetServiceProvidersByCategory(category string) ([]ServiceProviderRecord, error) {
        return []ServiceProviderRecord{}, nil
}

func (s *FileStore) GetServiceProvidersByStatus(status string) ([]ServiceProviderRecord, error) {
        return []ServiceProviderRecord{}, nil
}

func (s *FileStore) DeleteServiceProvider(id string) error {
        return fmt.Errorf("service providers not supported by FileStore — use SQLiteStore")
}

func (s *FileStore) ResetAll() error {
        s.mu.Lock()
        defer s.mu.Unlock()

        files := []string{"identity.json", "kel.json", "contacts.json", "settings.json", "pending_requests.json", "profile.json", "endpoint.json", "contact_kels.json", "credentials.json", "credential_schemas.json", "presentations.json", "witness_receipts.json"}
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
