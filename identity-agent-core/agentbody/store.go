package agentbody

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Binding states.
const (
	StatePending  = "pending"
	StateActive   = "active"
	StateRejected = "rejected"
	StateRevoked  = "revoked"
	// StateExpired is a request nobody decided on before its enrolment string
	// ran out. It cannot be approved: an attacker who won the race for a leaked
	// string must not be able to wait for a mistaken approval.
	StateExpired = "expired"
)

// Binding is one machine's claim to be the body of one AI agent, from first
// contact to revocation. It is kept after it ends: a message a body sent while
// its binding was live still verifies against it.
type Binding struct {
	ID string `json:"id"`
	// AgentAssetID and Agent name the AI agent this is a body of.
	AgentAssetID string `json:"agent_asset_id"`
	Agent        string `json:"agent"`
	Keys
	// Words are the six words shown for K on both screens.
	Words []string `json:"words"`
	// Grade is what the body is recorded at, never above what was checked.
	// ClaimedGrade is what it said, kept so a clamp is visible.
	Grade        string `json:"grade"`
	ClaimedGrade string `json:"claimed_grade"`
	GradeClamped bool   `json:"grade_clamped,omitempty"`
	// Platform is what the machine reported it runs (e.g. "macos/arm64");
	// Placement is where it is (computer, vm, cloud, device).
	Platform  string `json:"platform"`
	Placement string `json:"placement"`
	State     string `json:"state"`
	// CredentialSAID is the binding credential, once issued.
	CredentialSAID string    `json:"credential_said,omitempty"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	// PendingUntil is when an undecided request expires: the end of the window
	// its enrolment string was good for.
	PendingUntil time.Time `json:"pending_until"`
	DecidedAt    time.Time `json:"decided_at,omitempty"`
	// DecidedBy is the controller or owner that approved or rejected it.
	DecidedBy string    `json:"decided_by,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// invitation is an issued enrolment secret, kept only as a digest: a copy of
// the store is not a pile of usable secrets.
type invitation struct {
	SecretDigest string    `json:"secret_digest"`
	AgentAssetID string    `json:"agent_asset_id"`
	Expires      time.Time `json:"expires"`
	UsedAt       time.Time `json:"used_at,omitempty"`
	BindingID    string    `json:"binding_id,omitempty"`
	Voided       bool      `json:"voided,omitempty"`
}

type storeFile struct {
	Invitations []invitation `json:"invitations"`
	Bindings    []Binding    `json:"bindings"`
}

// Store keeps invitations and bindings in one file, under one lock, so a secret
// is claimed and its binding recorded as one step.
type Store struct {
	mu   sync.Mutex
	path string
}

// NewStore opens the store in dataDir.
func NewStore(dataDir string) *Store {
	return &Store{path: filepath.Join(dataDir, "agent_bodies.json")}
}

func (s *Store) load() (storeFile, error) {
	var f storeFile
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("the body store is unreadable: %w", err)
	}
	tidy(&f, time.Now())
	return f, nil
}

func (s *Store) save(f storeFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// tidy expires undecided requests whose window has passed, and drops
// invitations that can never be used again — spent, voided or expired — so the
// file does not grow with every string ever issued. A spent invitation's
// binding keeps its own record.
func tidy(f *storeFile, now time.Time) {
	for i := range f.Bindings {
		b := &f.Bindings[i]
		if b.State == StatePending && !b.PendingUntil.IsZero() && now.After(b.PendingUntil) {
			b.State = StateExpired
		}
	}
	kept := f.Invitations[:0]
	for _, inv := range f.Invitations {
		if inv.UsedAt.IsZero() && !inv.Voided && now.Before(inv.Expires) {
			kept = append(kept, inv)
		}
	}
	f.Invitations = kept
}

func digestSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Invite issues a fresh one-time secret for an AI agent. Any unused secret
// already issued for that AI agent is voided: one open invitation per AI agent,
// so an old string left lying around stops working the moment a new one exists.
func (s *Store) Invite(agentAssetID string, now time.Time) (secret string, expires time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return "", time.Time{}, err
	}
	for i := range f.Invitations {
		if f.Invitations[i].AgentAssetID == agentAssetID && f.Invitations[i].UsedAt.IsZero() {
			f.Invitations[i].Voided = true
		}
	}
	if secret, err = randomString(24); err != nil {
		return "", time.Time{}, err
	}
	expires = now.Add(EnrolmentWindow).UTC()
	f.Invitations = append(f.Invitations, invitation{
		SecretDigest: digestSecret(secret), AgentAssetID: agentAssetID, Expires: expires,
	})
	return secret, expires, s.save(f)
}

// ErrInvitation is every reason a secret cannot be used, given as one answer:
// a caller probing secrets learns nothing from which one it was.
var ErrInvitation = errors.New("this enrolment string cannot be used: it is unknown, expired, already used, or replaced by a newer one")

// Claim spends a secret and records the pending binding it produced, as one
// step. A secret is spent even if the binding is later rejected.
func (s *Store) Claim(secret string, b Binding, now time.Time) (Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Binding{}, err
	}
	d := digestSecret(secret)
	idx := -1
	for i, inv := range f.Invitations {
		if inv.SecretDigest == d {
			idx = i
		}
	}
	if idx < 0 {
		return Binding{}, ErrInvitation
	}
	inv := &f.Invitations[idx]
	if inv.Voided || !inv.UsedAt.IsZero() || !now.Before(inv.Expires) || inv.AgentAssetID != b.AgentAssetID {
		return Binding{}, ErrInvitation
	}
	for _, other := range f.Bindings {
		if other.Host == b.Host && (other.State == StateActive || other.State == StatePending) {
			return Binding{}, ErrHostTaken
		}
	}
	if b.ID, err = randomString(12); err != nil {
		return Binding{}, err
	}
	b.State = StatePending
	b.EnrolledAt = now.UTC()
	b.PendingUntil = inv.Expires
	inv.UsedAt = now.UTC()
	inv.BindingID = b.ID
	f.Bindings = append(f.Bindings, b)
	return b, s.save(f)
}

// Decide moves a pending binding to active or rejected. Only a pending binding
// can be decided, and only once.
func (s *Store) Decide(id, agentAssetID, state, by, credentialSAID string, now time.Time) (Binding, error) {
	if state != StateActive && state != StateRejected {
		return Binding{}, fmt.Errorf("a binding is decided as active or rejected, not %q", state)
	}
	return s.update(id, agentAssetID, func(b *Binding) error {
		if b.State == StatePending && !b.PendingUntil.IsZero() && now.After(b.PendingUntil) {
			b.State = StateExpired
		}
		if b.State != StatePending {
			return fmt.Errorf("this request is %s, not waiting for a decision", b.State)
		}
		b.State, b.DecidedBy, b.DecidedAt, b.CredentialSAID = state, by, now.UTC(), credentialSAID
		return nil
	})
}

// Revoke ends an active binding: that machine can no longer speak as the AI
// agent. The AI agent itself is unaffected and can enrol another body.
func (s *Store) Revoke(id, agentAssetID string, now time.Time) (Binding, error) {
	return s.update(id, agentAssetID, func(b *Binding) error {
		if b.State != StateActive {
			return fmt.Errorf("this binding is %s, not active", b.State)
		}
		b.State, b.RevokedAt = StateRevoked, now.UTC()
		return nil
	})
}

func (s *Store) update(id, agentAssetID string, fn func(*Binding) error) (Binding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Binding{}, err
	}
	for i := range f.Bindings {
		if f.Bindings[i].ID == id && f.Bindings[i].AgentAssetID == agentAssetID {
			if err := fn(&f.Bindings[i]); err != nil {
				return Binding{}, err
			}
			return f.Bindings[i], s.save(f)
		}
	}
	return Binding{}, fmt.Errorf("no such body for this AI agent")
}

// Get returns one binding.
func (s *Store) Get(id string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Binding{}, false
	}
	for _, b := range f.Bindings {
		if b.ID == id {
			return b, true
		}
	}
	return Binding{}, false
}

// ForAgent lists an AI agent's bindings, newest first.
func (s *Store) ForAgent(agentAssetID string) []Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil
	}
	var out []Binding
	for _, b := range f.Bindings {
		if b.AgentAssetID == agentAssetID {
			out = append(out, b)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EnrolledAt.After(out[j].EnrolledAt) })
	return out
}

// ActiveByHost finds the live binding a body's key belongs to. A machine can be
// the body of more than one AI agent only with a separate key for each, so one
// key has at most one live binding.
func (s *Store) ActiveByHost(host string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Binding{}, false
	}
	for _, b := range f.Bindings {
		if b.Host == host && b.State == StateActive {
			return b, true
		}
	}
	return Binding{}, false
}

// LatestByHost is the most recent binding for a key in any state, so a waiting
// machine can learn whether it was approved, rejected or revoked.
func (s *Store) LatestByHost(host string) (Binding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Binding{}, false
	}
	var found Binding
	ok := false
	for _, b := range f.Bindings {
		if b.Host == host && (!ok || b.EnrolledAt.After(found.EnrolledAt)) {
			found, ok = b, true
		}
	}
	return found, ok
}

// ErrHostTaken refuses a key that is already a body, or waiting to be one. One
// key speaks for one AI agent, so a key's signature always says which.
var ErrHostTaken = errors.New("this machine key is already the body of an AI agent, or waiting to be; a machine that hosts another AI agent uses another key")

// HostTaken reports whether a key already has a pending or live binding, so the
// same key cannot be offered as the body of two AI agents.
func (s *Store) HostTaken(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return true
	}
	for _, b := range f.Bindings {
		if b.Host == host && (b.State == StateActive || b.State == StatePending) {
			return true
		}
	}
	return false
}
