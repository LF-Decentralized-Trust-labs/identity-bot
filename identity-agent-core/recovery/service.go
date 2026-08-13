package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/secureenclave"
	"identity-agent-core/store"

	"github.com/google/uuid"
)

// RetrieveSource identifies where a recovery archive is fetched from.
type RetrieveSource string

const (
	SourceBackupOnlyDevice RetrieveSource = "backup_only_device"
	SourceLocalFile        RetrieveSource = "local_file"
	SourceCloud            RetrieveSource = "cloud"
)

// SessionState tracks an in-progress recovery workflow.
type SessionState string

const (
	SessionVerified  SessionState = "verified"
	SessionPending   SessionState = "pending_cancel_window"
	SessionRotated   SessionState = "rotation_complete"
	SessionActivated SessionState = "activated"
	SessionFailed    SessionState = "failed"
)

// Session is a recovery workflow instance.
type Session struct {
	ID              string                 `json:"id"`
	State           SessionState           `json:"state"`
	IdentityAID     string                 `json:"identity_aid,omitempty"`
	StartedAt       string                 `json:"started_at"`
	CompleteAfter   string                 `json:"complete_after"`
	CancelWindow    string                 `json:"cancel_window"`
	AssuranceBand   AssuranceBand          `json:"assurance_band"`
	RotationDone    bool                   `json:"rotation_done"`
	PairwiseChecks  []PairwiseVerification `json:"pairwise_checks,omitempty"`
	ManifestSummary map[string]interface{} `json:"manifest_summary,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// VerifyRequest opens and validates an archive without persisting state.
type VerifyRequest struct {
	ArchiveB64 string `json:"archive_b64,omitempty"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase,omitempty"`
}

// VerifyResponse is returned from the verify endpoint.
type VerifyResponse struct {
	Valid          bool                   `json:"valid"`
	IdentityAID    string                 `json:"identity_aid,omitempty"`
	SectionCount   int                    `json:"section_count"`
	PairwiseChecks []PairwiseVerification `json:"pairwise_checks,omitempty"`
}

// StartRequest begins a gated recovery session after successful verify.
type StartRequest struct {
	ArchiveB64 string `json:"archive_b64"`
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase,omitempty"`
}

// RetrieveRequest fetches an opaque archive for recovery.
type RetrieveRequest struct {
	Source      RetrieveSource `json:"source"`
	IdentityAID string         `json:"identity_aid,omitempty"`
	LocalPath   string         `json:"local_path,omitempty"`
	ArchiveName string         `json:"archive_name,omitempty"`
	CloudRef    string         `json:"cloud_ref,omitempty"`
}

// RetrieveResponse returns archive bytes for verify/start.
type RetrieveResponse struct {
	Source     RetrieveSource `json:"source"`
	Path       string         `json:"path,omitempty"`
	ArchiveB64 string         `json:"archive_b64"`
	SizeBytes  int            `json:"size_bytes"`
	Message    string         `json:"message,omitempty"`
}

// Service orchestrates recovery restore, verify, delay, and rotation gates.
type Service struct {
	DataDir       string
	Store         store.Store
	BackupService *backup.Service
	CancelGate    *CancelWindowGate
	Rotation      *RotationTracker
	AuthProvider  AuthProviderGate

	mu       sync.Mutex
	sessions map[string]*sessionRecord
}

type sessionRecord struct {
	Session  Session
	Archive  []byte
	Mnemonic string
	Payload  *RestoredPayload
}

func NewService(dataDir string, st store.Store, backupSvc *backup.Service) *Service {
	auth := NewStubAuthProviderGate()
	return &Service{
		DataDir:       dataDir,
		Store:         st,
		BackupService: backupSvc,
		CancelGate:    NewCancelWindowGate(auth),
		Rotation:      NewRotationTracker(),
		AuthProvider:  auth,
		sessions:      map[string]*sessionRecord{},
	}
}

// Verify decrypts and integrity-checks an archive, then verifies HD pairwise keys.
func (s *Service) Verify(req VerifyRequest) (*VerifyResponse, error) {
	raw, err := decodeArchiveInput(req.ArchiveB64, "")
	if err != nil {
		return nil, err
	}
	payload, err := RestoreFromArchive(raw, OpenRequest{
		Mnemonic:   req.Mnemonic,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		return nil, err
	}

	seed, err := BIP39Seed(OpenRequest{Mnemonic: req.Mnemonic, Passphrase: req.Passphrase})
	if err != nil {
		return nil, err
	}
	checks, err := VerifyPairwiseContacts(seed, payload.Contacts)
	if err != nil {
		return nil, err
	}

	aid := payload.Manifest.IdentityAID
	if payload.Identity != nil && payload.Identity.AID != "" {
		aid = payload.Identity.AID
	}
	return &VerifyResponse{
		Valid:          true,
		IdentityAID:    aid,
		SectionCount:   len(payload.Manifest.Sections),
		PairwiseChecks: checks,
	}, nil
}

// Start creates a recovery session with assurance-graduated cancel-window delay.
func (s *Service) Start(req StartRequest) (*Session, error) {
	raw, err := decodeArchiveInput(req.ArchiveB64, "")
	if err != nil {
		return nil, err
	}
	payload, err := RestoreFromArchive(raw, OpenRequest{
		Mnemonic:   req.Mnemonic,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		return nil, err
	}

	seed, err := BIP39Seed(OpenRequest{Mnemonic: req.Mnemonic})
	if err != nil {
		return nil, err
	}
	checks, err := VerifyPairwiseContacts(seed, payload.Contacts)
	if err != nil {
		return nil, err
	}

	started := time.Now().UTC()
	completeAfter, window, band, _ := s.CancelGate.Schedule(started)

	id := uuid.New().String()
	aid := payload.Manifest.IdentityAID
	if payload.Identity != nil {
		aid = payload.Identity.AID
	}

	sess := Session{
		ID:             id,
		State:          SessionPending,
		IdentityAID:    aid,
		StartedAt:      started.Format(time.RFC3339),
		CompleteAfter:  completeAfter.Format(time.RFC3339),
		CancelWindow:   window.String(),
		AssuranceBand:  band,
		PairwiseChecks: checks,
		ManifestSummary: map[string]interface{}{
			"format_version": payload.Manifest.FormatVersion,
			"tiers":          payload.Manifest.Tiers,
			"snapshot_type":  payload.Manifest.SnapshotType,
			"sections":       len(payload.Manifest.Sections),
		},
	}

	s.mu.Lock()
	s.sessions[id] = &sessionRecord{
		Session:  sess,
		Archive:  raw,
		Mnemonic: req.Mnemonic,
		Payload:  payload,
	}
	s.mu.Unlock()

	return &sess, nil
}

// GetSession returns the current session state.
func (s *Service) GetSession(id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("recovery session not found")
	}
	sess := rec.Session
	if sess.RotationDone {
		sess.State = SessionRotated
	} else if s.CancelGate.Remaining(parseTime(sess.CompleteAfter)) > 0 {
		sess.State = SessionPending
	}
	return &sess, nil
}

// RecordRotation marks mandatory post-restore rotation complete for a session.
func (s *Service) RecordRotation(sessionID string, result RotationResult) (*Session, error) {
	s.mu.Lock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("recovery session not found")
	}
	s.Rotation.MarkCompleted(sessionID, result)
	rec.Session.RotationDone = true
	rec.Session.State = SessionRotated
	sess := rec.Session
	s.mu.Unlock()
	return &sess, nil
}

// Activate applies restored payload after cancel window and mandatory rotation.
func (s *Service) Activate(sessionID string) (*Session, error) {
	s.mu.Lock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("recovery session not found")
	}
	sess := rec.Session
	payload := rec.Payload
	s.mu.Unlock()

	if remaining := s.CancelGate.Remaining(parseTime(sess.CompleteAfter)); remaining > 0 {
		return nil, &ErrCancelWindowActive{
			CompleteAfter: parseTime(sess.CompleteAfter),
			Remaining:     remaining,
		}
	}
	if err := s.Rotation.RequireCompleted(sessionID); err != nil {
		return nil, err
	}
	if err := s.applyPayload(payload); err != nil {
		s.mu.Lock()
		rec.Session.State = SessionFailed
		rec.Session.Error = err.Error()
		s.mu.Unlock()
		return nil, err
	}

	s.mu.Lock()
	rec.Session.State = SessionActivated
	sess = rec.Session
	s.mu.Unlock()
	return &sess, nil
}

func (s *Service) applyPayload(payload *RestoredPayload) error {
	if payload == nil {
		return fmt.Errorf("empty restored payload")
	}
	if payload.Identity != nil && s.Store != nil {
		if err := s.Store.SaveIdentity(*payload.Identity); err != nil {
			return fmt.Errorf("save identity: %w", err)
		}
	}
	if s.Store != nil {
		for _, ev := range payload.KelEvents {
			if err := s.Store.SaveEvent(ev); err != nil {
				return fmt.Errorf("save kel event: %w", err)
			}
		}
		for _, c := range payload.Contacts {
			if err := s.Store.SaveContact(c.ContactRecord); err != nil {
				return fmt.Errorf("save contact %s: %w", c.AID, err)
			}
		}
	}

	// Credentials, settings and pending requests.
	//
	// These were collected, encrypted, digested and shipped, and then dropped
	// here — so an archive was valid, complete against its own manifest, and
	// restored less than it contained. Nothing that inspects an archive could
	// catch that; only restoring one and looking at what arrived.
	//
	// A section that will not parse fails the restore rather than being skipped.
	// Continuing past it is how a partial restore comes to look like a whole
	// one, and this is the one moment somebody can still act on the truth.
	if raw, ok := payload.Bundle.Sections["credentials"]; ok && len(raw) > 0 && s.Store != nil {
		var creds []store.CredentialRecord
		if err := json.Unmarshal(raw, &creds); err != nil {
			return fmt.Errorf("credentials in this archive could not be read: %w", err)
		}
		for _, c := range creds {
			if err := s.Store.SaveCredential(c); err != nil {
				return fmt.Errorf("restore credential %s: %w", c.SAID, err)
			}
		}
	}

	if raw, ok := payload.Bundle.Sections["settings"]; ok && len(raw) > 0 && s.Store != nil {
		var settings store.SettingsData
		if err := json.Unmarshal(raw, &settings); err != nil {
			return fmt.Errorf("settings in this archive could not be read: %w", err)
		}
		if err := s.Store.SaveSettings(settings); err != nil {
			return fmt.Errorf("restore settings: %w", err)
		}
	}

	if raw, ok := payload.Bundle.Sections["pending_requests"]; ok && len(raw) > 0 && s.Store != nil {
		var pending []store.PendingRequest
		if err := json.Unmarshal(raw, &pending); err != nil {
			return fmt.Errorf("pending requests in this archive could not be read: %w", err)
		}
		for _, p := range pending {
			if err := s.Store.SavePendingRequest(p); err != nil {
				return fmt.Errorf("restore pending request: %w", err)
			}
		}
	}

	if raw, ok := payload.Bundle.Sections["login_relationships"]; ok && len(raw) > 0 {
		path := filepath.Join(s.DataDir, "login_relationships.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			return fmt.Errorf("write login_relationships: %w", err)
		}
	}
	// Reseat the root keystore seed so every HD-derived key (pairwise contacts,
	// login relationships, asset signing, audit signing, credential vault)
	// re-derives on this device. StoreRootSeed re-wraps it under THIS device's
	// hardware key where one is usable — the old device's secure element is
	// never needed.
	if raw, ok := payload.Bundle.Sections["root_seed"]; ok && len(raw) >= 32 {
		if err := secureenclave.StoreRootSeed(s.DataDir, raw); err != nil {
			return fmt.Errorf("reseat root seed: %w", err)
		}
	}
	// The assistant's memory. Collected into the full tier and, until now,
	// dropped here — so an agent came back having forgotten everything it had
	// been told, while every check reported a complete restore.
	if raw, ok := payload.Bundle.Sections["ai_memory_db"]; ok && len(raw) > 0 {
		aiPath := filepath.Join(s.DataDir, "ai_memory.db")
		if err := os.WriteFile(aiPath, raw, 0600); err != nil {
			return fmt.Errorf("write ai_memory.db: %w", err)
		}
	}

	if raw, ok := payload.Bundle.Sections["sqlite_identity_db"]; ok && len(raw) > 0 {
		dbPath := filepath.Join(s.DataDir, "identity.db")
		if err := os.WriteFile(dbPath, raw, 0600); err != nil {
			return fmt.Errorf("write identity.db: %w", err)
		}
	}
	return nil
}

// Retrieve loads an opaque .iab archive from backup-only device, local path, or cloud stub.
func (s *Service) Retrieve(req RetrieveRequest) (*RetrieveResponse, error) {
	switch req.Source {
	case SourceBackupOnlyDevice:
		return s.retrieveFromBackupOnly(req)
	case SourceLocalFile:
		return s.retrieveFromLocal(req)
	case SourceCloud:
		return s.retrieveFromCloud(req)
	default:
		return nil, fmt.Errorf("unknown retrieve source %q", req.Source)
	}
}

func (s *Service) retrieveFromBackupOnly(req RetrieveRequest) (*RetrieveResponse, error) {
	if s.BackupService == nil {
		return nil, fmt.Errorf("backup service not configured")
	}
	if req.IdentityAID == "" {
		return nil, fmt.Errorf("identity_aid required for backup-only retrieval")
	}
	paths, err := s.BackupService.ListReceived(req.IdentityAID)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no archives received for identity %s", req.IdentityAID)
	}
	path := paths[len(paths)-1]
	if req.ArchiveName != "" {
		path = filepath.Join(s.DataDir, "backup_receive", req.IdentityAID, req.ArchiveName)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return &RetrieveResponse{
		Source:     SourceBackupOnlyDevice,
		Path:       path,
		ArchiveB64: base64.StdEncoding.EncodeToString(raw),
		SizeBytes:  len(raw),
	}, nil
}

func (s *Service) retrieveFromLocal(req RetrieveRequest) (*RetrieveResponse, error) {
	if req.LocalPath == "" {
		return nil, fmt.Errorf("local_path required for local retrieval")
	}
	raw, err := os.ReadFile(req.LocalPath)
	if err != nil {
		return nil, err
	}
	return &RetrieveResponse{
		Source:     SourceLocalFile,
		Path:       req.LocalPath,
		ArchiveB64: base64.StdEncoding.EncodeToString(raw),
		SizeBytes:  len(raw),
	}, nil
}

func (s *Service) retrieveFromCloud(req RetrieveRequest) (*RetrieveResponse, error) {
	if s.BackupService == nil {
		return nil, fmt.Errorf("backup service not configured")
	}
	if req.CloudRef == "" {
		return nil, fmt.Errorf("cloud_ref (destination id) required for cloud retrieval")
	}
	cfg, err := s.BackupService.LoadConfig()
	if err != nil {
		return nil, err
	}
	var dest *backup.Destination
	for i := range cfg.Destinations {
		if cfg.Destinations[i].ID == req.CloudRef {
			dest = &cfg.Destinations[i]
			break
		}
	}
	if dest == nil {
		return nil, fmt.Errorf("backup destination %q not found", req.CloudRef)
	}
	if dest.Type != backup.DestCloudUser {
		return nil, fmt.Errorf("destination %q is not user-managed cloud", req.CloudRef)
	}
	raw, key, err := s.BackupService.PullLatestArchive(*dest)
	if err != nil {
		return nil, err
	}
	return &RetrieveResponse{
		Source:     SourceCloud,
		Path:       key,
		ArchiveB64: base64.StdEncoding.EncodeToString(raw),
		SizeBytes:  len(raw),
		Message:    "retrieved encrypted archive from user-managed cloud",
	}, nil
}

// FetchBackupOnlyArchive downloads opaque archive bytes from a paired backup-only agent.
func FetchBackupOnlyArchive(baseURL, identityAID, archiveName string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/backup/receive/%s/download/%s", trimSlash(baseURL), identityAID, archiveName)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backup download %d: %s", resp.StatusCode, string(b))
	}
	return io.ReadAll(resp.Body)
}

func decodeArchiveInput(archiveB64, archivePath string) ([]byte, error) {
	if archiveB64 != "" {
		return base64.StdEncoding.DecodeString(archiveB64)
	}
	if archivePath != "" {
		return os.ReadFile(archivePath)
	}
	return nil, fmt.Errorf("archive_b64 or archive path required")
}

func parseTime(ts string) time.Time {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}
	}
	return t
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// MarshalSession exports session JSON for persistence tests.
func MarshalSession(sess Session) ([]byte, error) {
	return json.Marshal(sess)
}
