package recovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"identity-agent-core/authprovider"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	// SessionCancelled is a recovery somebody stopped during its window, which
	// is what the window is for.
	SessionCancelled SessionState = "cancelled"
)

// Session is a recovery workflow instance.
type Session struct {
	ID            string        `json:"id"`
	State         SessionState  `json:"state"`
	IdentityAID   string        `json:"identity_aid,omitempty"`
	StartedAt     string        `json:"started_at"`
	CompleteAfter string        `json:"complete_after"`
	CancelWindow  string        `json:"cancel_window"`
	AssuranceBand AssuranceBand `json:"assurance_band"`
	RotationDone  bool          `json:"rotation_done"`
	// DuressApprovals are the trusted contacts who have confirmed this
	// recovery should proceed, when the identity asks for them.
	DuressApprovals []string               `json:"duress_approvals,omitempty"`
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
	// Authenticator establishes that the person completing a recovery is the
	// person the identity belongs to. The phrase proves control of the
	// identity and unlocks the data; it says nothing about who is holding it.
	//
	// The same provider feeds AuthProvider below, which turns the answer into a
	// waiting period. One question, asked once.
	Authenticator authprovider.Provider
	// RequiredLevel is how well authenticated somebody must be to complete a
	// recovery on this agent.
	//
	// LevelUnknown means the gate is not enforced, which is what an agent with
	// no provider has to do — refusing every recovery because nothing can
	// measure would lock people out of their own identities to protect them
	// from nobody. The waiting period is what stands in for it there, and an
	// unmeasured level already draws the longest one.
	RequiredLevel authprovider.Level
	Rotation      *RotationTracker
	AuthProvider  AuthProviderGate

	mu       sync.Mutex
	sessions map[string]*sessionRecord
}

type sessionRecord struct {
	Session Session
	// Archive is the sealed archive. Ciphertext this agent cannot open on its
	// own, which is why it can be kept for the length of the wait.
	Archive []byte
}

// Neither the recovery phrase nor the decrypted payload is held here.
//
// Both used to be, for the length of the cancel window — a day at minimum, two
// by default. The phrase opens everything and the payload IS everything, so
// keeping either for two days undoes the wait it is kept across. They are
// derived again at activation from the phrase the person supplies then, which
// also re-proves that whoever is completing the recovery is the one who
// started it.

func NewService(dataDir string, st store.Store, backupSvc *backup.Service) *Service {
	// One provider, read for both questions it answers: how well authenticated
	// somebody is, and therefore how long this recovery waits. An agent with no
	// provider configured says so rather than producing a level, and an
	// unmeasured level draws the longest window.
	provider := authprovider.Provider(authprovider.NotConfigured{})
	gate := FromAuthProvider{Provider: provider}
	return &Service{
		DataDir:       dataDir,
		Store:         st,
		BackupService: backupSvc,
		CancelGate:    NewCancelWindowGate(gate),
		Rotation:      NewRotationTracker(),
		AuthProvider:  gate,
		Authenticator: provider,
		// Not enforced until a provider exists. Refusing every recovery on an
		// agent that cannot measure would lock people out of their own
		// identities to protect them from nobody.
		RequiredLevel: authprovider.LevelUnknown,
		sessions:      map[string]*sessionRecord{},
	}
}

// Verify decrypts and integrity-checks an archive, then verifies HD pairwise keys.
func (s *Service) Verify(req VerifyRequest) (*VerifyResponse, error) {
	raw, err := decodeArchiveInput(req.ArchiveB64)
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
	raw, err := decodeArchiveInput(req.ArchiveB64)
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
	// The identity this session is for. Taken from the restored identity when
	// it names one, and from the manifest otherwise — an archive whose identity
	// section carries a blank AID used to blank a perfectly good manifest AID,
	// which then disabled the check in Activate that the phrase must open the
	// same identity this session was started for.
	aid := payload.Manifest.IdentityAID
	if payload.Identity != nil && payload.Identity.AID != "" {
		aid = payload.Identity.AID
	}
	if aid == "" {
		return nil, fmt.Errorf("this archive does not say which identity it belongs to, " +
			"so a recovery from it could not be bound to one")
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
	rec := &sessionRecord{Session: sess, Archive: raw}
	s.sessions[id] = rec
	s.mu.Unlock()

	// Written down before this returns. A session the caller has been told
	// about and that this agent would lose on the next restart is the defect
	// this whole file exists to fix, so the record has to exist before the id
	// does anywhere else.
	if werr := s.writeSession(rec); werr != nil {
		// The caller is being told this failed, so the agent must not go on
		// holding a session they believe does not exist — and which would
		// vanish at the next restart anyway.
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		s.forgetSession(id)
		return nil, fmt.Errorf("could not record this recovery so it survives a restart: %w", werr)
	}

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
	// A finished session keeps the state it finished in. This ran
	// unconditionally and overwrote both SessionActivated and SessionFailed
	// with SessionRotated, so a screen polling this after activating could
	// never see that it had worked — and the natural response to that is to
	// activate again.
	switch sess.State {
	case SessionActivated, SessionFailed:
	default:
		if sess.RotationDone {
			sess.State = SessionRotated
		} else if s.CancelGate.Remaining(parseTime(sess.CompleteAfter)) > 0 {
			sess.State = SessionPending
		}
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

	// Written down, because this is the other half of surviving the wait.
	//
	// The wait was made to survive a restart and this was not, so a session
	// came back after a restart having forgotten that its mandatory rotation
	// had been done — and demanded it again, on an agent where the rotation
	// route may not even be available. The session on disk is the record; the
	// tracker is a cache of it, rebuilt at startup.
	if werr := s.writeSession(rec); werr != nil {
		return nil, fmt.Errorf("the rotation was done but could not be recorded, "+
			"so it would be asked for again after a restart: %w", werr)
	}
	return &sess, nil
}

// Activate applies restored payload after cancel window and mandatory rotation.
// Cancel stops a recovery that should not complete.
//
// The cancel window is, in its own words, the time somebody who did not start
// a recovery has to stop it — and until now nothing could. Restarting the agent
// discarded the session, which was the only lever anybody had and a crude one;
// making sessions survive a restart removed even that, so the wait would have
// had no action attached to it at all.
//
// Deliberately does NOT require the recovery phrase. Somebody stopping an
// unwanted recovery is by definition not the person who started it, and
// demanding the phrase would mean only the attacker could cancel.
func (s *Service) Cancel(sessionID string) (*Session, error) {
	s.mu.Lock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("recovery session not found")
	}
	if rec.Session.State == SessionActivated {
		s.mu.Unlock()
		return nil, fmt.Errorf("this recovery has already completed and cannot be cancelled")
	}
	rec.Session.State = SessionCancelled
	rec.Archive = nil
	sess := rec.Session
	delete(s.sessions, sessionID)
	s.mu.Unlock()

	s.Rotation.Forget(sessionID)
	s.forgetSession(sessionID)
	return &sess, nil
}

// authenticationCountsFor is how recent an authentication must be to stand in
// for one taken now.
//
// Long enough that somebody is not asked twice inside one sitting, short enough
// that it cannot span the wait it is meant to be checked at the end of.
const authenticationCountsFor = 15 * time.Minute

// ErrNotAuthenticated means the recovery is controlled by somebody this agent
// cannot establish is the owner.
//
// A distinct type because it is not a failure of the recovery — the archive
// opened and the words were right. It is the second gate saying that
// controlling an identity and being its owner are different things.
type ErrNotAuthenticated struct {
	Required authprovider.Level
	Got      authprovider.Result
}

func (e *ErrNotAuthenticated) Error() string {
	if !e.Got.Measured {
		return "this recovery cannot complete because nothing here can establish who you are: " +
			e.Got.Why
	}
	return fmt.Sprintf("this recovery needs you authenticated to %q and you are %q",
		e.Required, e.Got.Level)
}

// ActivateRequest carries what finishing a recovery needs and nothing else.
type ActivateRequest struct {
	Mnemonic   string `json:"mnemonic"`
	Passphrase string `json:"passphrase,omitempty"`
}

// Activate completes a recovery once its cancel window has elapsed.
//
// Takes the recovery phrase, which is not a redundant request. The phrase is
// deliberately not kept for the length of the window — see sessionRecord — so
// the archive is opened here rather than at the start, and the payload never
// sits on disk or in memory across the wait. Asking again also re-establishes
// that the person finishing this is the one who began it, two days later.
func (s *Service) Activate(sessionID string, req ActivateRequest) (*Session, error) {
	s.mu.Lock()
	rec, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("recovery session not found")
	}
	sess := rec.Session
	archive := rec.Archive
	s.mu.Unlock()

	// A recovery happens once.
	//
	// Activation rewrites the identity, the key event log and every restored
	// file, and re-seats the root seed. Running it a second time rolls all of
	// that back to whatever the archive held — undoing key rotations and
	// everything done since. The session used to be deleted from disk and left
	// in memory with its archive, so a completed recovery could be replayed for
	// as long as the process lived.
	if sess.State == SessionActivated {
		return nil, fmt.Errorf("this recovery has already been completed")
	}

	if remaining := s.CancelGate.Remaining(parseTime(sess.CompleteAfter)); remaining > 0 {
		return nil, &ErrCancelWindowActive{
			CompleteAfter: parseTime(sess.CompleteAfter),
			Remaining:     remaining,
		}
	}
	if err := s.Rotation.RequireCompleted(sessionID); err != nil {
		return nil, err
	}
	// The second gate. Controlling the identity is not the same as being the
	// person it belongs to, and until now completing a recovery asked only the
	// first question — the phrase opened the archive and the identity was
	// written straight in.
	//
	// Checked here rather than at the start, deliberately: a recovery waits days,
	// and an authentication from the day it began is not evidence about who is
	// finishing it. This is the moment that matters.
	if s.RequiredLevel != "" && s.RequiredLevel != authprovider.LevelUnknown {
		// A requirement this package does not recognise is a typo, and a typo
		// must not quietly turn a gate off. Unrecognised levels rank alongside
		// unknown, so "verifed" would be satisfied by having measured nothing.
		if !s.RequiredLevel.Known() {
			return nil, fmt.Errorf("this agent is configured to require an authentication level "+
				"it does not recognise (%q), so it cannot tell whether anybody meets it",
				s.RequiredLevel)
		}
		res := authprovider.Of(s.Authenticator)
		// And recently. An authentication is a statement about a moment, and a
		// recovery waits days — so a provider answering with a level it
		// established last week says nothing about who is finishing this. Fresh
		// existed and was tested and nothing consulted it, which made it look
		// load-bearing when it was not.
		if !res.Fresh(authenticationCountsFor) {
			return nil, &ErrNotAuthenticated{Required: s.RequiredLevel, Got: res}
		}
		// Measured is the whole premise of this package and was checked
		// nowhere: a provider returning a high level with Measured false and no
		// error satisfied the gate. Not having measured is not a measurement.
		if !res.Measured || !res.Level.AtLeast(s.RequiredLevel) {
			return nil, &ErrNotAuthenticated{
				Required: s.RequiredLevel,
				Got:      res,
			}
		}
	}
	if len(archive) == 0 {
		return nil, fmt.Errorf("this recovery has no archive to restore from")
	}
	if req.Mnemonic == "" {
		return nil, fmt.Errorf("the recovery phrase is needed again to finish this: " +
			"it is not kept while the waiting period runs")
	}

	payload, err := RestoreFromArchive(archive, OpenRequest{
		Mnemonic:   req.Mnemonic,
		Passphrase: req.Passphrase,
	})
	if err != nil {
		// Not marked failed. A mistyped phrase is the ordinary case at this
		// point, and burning the session for it would mean starting the wait
		// again from the beginning.
		return nil, fmt.Errorf("those words do not open this archive: %w", err)
	}
	// The phrase must produce the identity this session was started for.
	// Without this, a DIFFERENT valid archive-and-phrase pair supplied here
	// would restore somebody else's identity under a session that had already
	// waited out its window.
	restoredAID := payload.Manifest.IdentityAID
	if payload.Identity != nil {
		restoredAID = payload.Identity.AID
	}
	if sess.IdentityAID != "" && restoredAID != sess.IdentityAID {
		return nil, fmt.Errorf("those words open a different identity than the one this recovery started for")
	}

	// The third gate. Whether this person is acting freely, which neither the
	// phrase nor an authentication provider can answer — somebody being forced
	// satisfies both perfectly.
	//
	// Read from the ARCHIVE, and checked here rather than earlier, because a
	// recovery by definition runs on a device that does not hold this
	// identity's data. Reading the policy off local disk meant a fresh machine
	// found none, defaulted to no protection, and let the recovery through —
	// so the gate fired only on the owner's own machine, which is the one place
	// it is not needed. An attacker with the archive and the phrase stepped
	// around it by running the recovery anywhere else.
	//
	// The policy travels with the identity because it is a property of the
	// identity, not of a machine.
	if err := duressPolicyFrom(payload).Held(parseTime(sess.StartedAt), sess.DuressApprovals, time.Now()); err != nil {
		return nil, err
	}

	if err := s.applyPayload(payload); err != nil {
		s.mu.Lock()
		rec.Session.State = SessionFailed
		rec.Session.Error = err.Error()
		sess = rec.Session
		s.mu.Unlock()
		// The recovery is over, so the sealed archive stops being held. The
		// record stays, without it, so somebody can still read what went wrong.
		s.ForgetFailed(sessionID)
		return nil, err
	}

	s.mu.Lock()
	rec.Session.State = SessionActivated
	sess = rec.Session
	// The archive has served its purpose, so it stops being held anywhere:
	// removed from disk below, and dropped from memory here. Keeping it in RAM
	// while deleting the file is not "no longer holding somebody's sealed
	// identity", which is what the comment here used to claim.
	rec.Archive = nil
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	s.Rotation.Forget(sessionID)
	s.forgetSession(sessionID)
	return &sess, nil
}

func (s *Service) applyPayload(payload *RestoredPayload) error {
	if payload == nil {
		return fmt.Errorf("empty restored payload")
	}
	if payload.Bundle == nil {
		return fmt.Errorf("this archive carries no sections")
	}

	// The key material goes down first, before anything that can fail on the
	// shape of the data.
	//
	// Everything else in an archive describes things that can be fetched,
	// re-agreed or asked for again. The root seed cannot: every pairwise,
	// login, asset and audit key re-derives from it, and if it is not written
	// there is nowhere else to get it. So it must not sit behind a step that
	// refuses a malformed table or an unreadable database — a restore that
	// fails should fail with the irreplaceable part already on disk.
	if err := s.restoreTheKeyMaterial(payload); err != nil {
		return err
	}
	if err := s.restoreTheDatabase(payload); err != nil {
		return err
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

	// Every file the archive carries, back to the path it came from.
	//
	// The collector no longer names the files it takes — it sweeps the data
	// directory — so this cannot name them either. A restore that knew only
	// the files somebody remembered to list would drop exactly the ones a
	// build on top of this core had added, which is the failure the sweep
	// exists to remove.
	//
	// A section whose name does not resolve to a path inside the data
	// directory fails the restore. An archive is opened with the owner's own
	// key, so this is not the main line of defence — but a section name is the
	// one part of an archive that becomes a filesystem path.
	for name, raw := range payload.Bundle.Sections {
		rel, ok := backup.FilePathOfSection(name)
		if !ok {
			if strings.HasPrefix(name, backup.FileSectionPrefix) {
				return fmt.Errorf("this archive names a file section with an unusable path: %q", name)
			}
			continue
		}
		dest := filepath.Join(s.DataDir, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fmt.Errorf("make room for %s: %w", rel, err)
		}
		if err := os.WriteFile(dest, raw, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", rel, err)
		}
	}

	return nil
}

// restoreTheKeyMaterial writes the parts of an archive that exist nowhere else.
//
// The root keystore seed is the HD derivation root for every pairwise contact,
// login relationship, asset signing and audit signing key, and for the
// credential vault. It is carried unwrapped inside the encrypted payload
// deliberately: the on-disk copy may be sealed to the old device's hardware,
// and a recovery onto new hardware must never need the old secure element.
// StoreRootSeed re-wraps it under THIS device's key where one is usable.
func (s *Service) restoreTheKeyMaterial(payload *RestoredPayload) error {
	if raw, ok := payload.Bundle.Sections["root_seed"]; ok && len(raw) >= 32 {
		if err := secureenclave.StoreRootSeed(s.DataDir, raw); err != nil {
			return fmt.Errorf("reseat root seed: %w", err)
		}
	}
	if raw, ok := payload.Bundle.Sections["login_relationships"]; ok && len(raw) > 0 {
		path := filepath.Join(s.DataDir, "login_relationships.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			return fmt.Errorf("write login_relationships: %w", err)
		}
	}
	return nil
}

// restoreTheDatabase brings back the identity database the archive carries.
//
// This runs FIRST, before anything is restored through the store, and that
// ordering is deliberate. The archive holds the same data twice — once as the
// database itself, once as parsed sections — and whichever is applied second
// wins. The parsed sections are the ones this code understands and can fail
// loudly on, so they go last and have the final say; the database goes first
// and carries across everything the parsed sections do not know about.
//
// See SQLiteStore.ImportSnapshot for why this is not simply a file write.
func (s *Service) restoreTheDatabase(payload *RestoredPayload) error {
	raw, ok := payload.Bundle.Sections["sqlite_identity_db"]
	if !ok || len(raw) == 0 {
		return nil
	}
	sqlStore, ok := s.Store.(*store.SQLiteStore)
	if !ok {
		return nil
	}

	// Anything a previous restore left behind when it died mid-way. Same
	// reasoning as the snapshot side: this is a plaintext copy of the whole
	// identity store, and nothing else will ever remove it.
	backup.SweepUpAbandoned(s.DataDir, ".restoring-")

	dir, err := os.MkdirTemp(s.DataDir, ".restoring-")
	if err != nil {
		return fmt.Errorf("make room for the backed-up database: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "identity.db")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return fmt.Errorf("unpack the backed-up database: %w", err)
	}
	if err := sqlStore.ImportSnapshot(path); err != nil {
		return err
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
	// The same checks the HTTP download route was given. This is the sibling
	// read path and it was left unvalidated, so it joined a caller-supplied
	// identifier and filename onto a path exactly as that one used to.
	if err := backup.AcceptableAID(req.IdentityAID); err != nil {
		return nil, err
	}
	if req.ArchiveName != "" {
		if err := backup.AcceptableArchiveName(req.ArchiveName); err != nil {
			return nil, err
		}
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

// maxArchiveOnDisk bounds what local retrieval will read into memory.
const maxArchiveOnDisk = 2 << 30 // 2 GiB

func (s *Service) retrieveFromLocal(req RetrieveRequest) (*RetrieveResponse, error) {
	if req.LocalPath == "" {
		return nil, fmt.Errorf("local_path required for local retrieval")
	}
	// It has to BE an archive. That is the check, and confining the path was
	// not.
	//
	// This read whatever absolute path it was handed and returned the bytes
	// base64-encoded, which makes it a general file-read rather than a way to
	// fetch a backup. The file that matters most is the root seed: on every
	// platform without a hardware wrapper it is stored unwrapped, and it
	// derives both the backup key and the seal keypair — so one read of it
	// opens every archive that identity has ever written, without the recovery
	// phrase ever being involved.
	//
	// Confining the path to this agent's own export directory would close that
	// and break the only situation this route exists for. Somebody restoring
	// onto a new machine has an empty data directory and their archive on a USB
	// stick or in their downloads; the export directory is written by exactly
	// one thing, which is this agent making a backup, and a fresh machine has
	// never done that.
	//
	// So the file is read and then required to be an archive. Its contents are
	// sealed, so returning one discloses nothing that holding it did not
	// already; a file that is not one is refused before any of it goes back.
	clean := filepath.Clean(req.LocalPath)

	// Followed symlinks land somewhere else by definition, and a symlink is how
	// a confined directory stops being confined.
	info, lerr := os.Lstat(clean)
	if lerr != nil {
		return nil, lerr
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("that is not a file")
	}
	if info.Size() > maxArchiveOnDisk {
		return nil, fmt.Errorf("that file is too large to be an archive")
	}

	raw, err := os.ReadFile(clean)
	if err != nil {
		return nil, err
	}
	if !backup.LooksLikeAnArchive(raw) {
		return nil, fmt.Errorf("that is not an archive: local retrieval reads backups, " +
			"and returning anything else would make this a way to read any file on this machine")
	}
	return &RetrieveResponse{
		Source:     SourceLocalFile,
		Path:       clean,
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

func decodeArchiveInput(archiveB64 string) ([]byte, error) {
	// The path branch is gone. Both callers passed an empty string, so it was
	// dead — and it was an unconstrained ReadFile of a caller-supplied path,
	// which is the exact primitive this package just removed from the two
	// routes that could reach it. A dead one is one argument away from being
	// live.
	if archiveB64 == "" {
		return nil, fmt.Errorf("archive_b64 required")
	}
	return base64.StdEncoding.DecodeString(archiveB64)
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
