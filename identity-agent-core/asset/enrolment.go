package asset

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Enrolling a thing that already has its own key.
//
// Every asset until now was minted by the agent from the owner's root seed. The
// agent derived the keypair, incepted the identity and stored the record — so
// an asset was something the owner conjured, and its key was the owner's key
// wearing a different index.
//
// That works for a website or an AI agent, which have no existence apart from
// the agent that runs them. It does not describe a MACHINE. A machine already
// exists, is somewhere else, and can hold a private key the owner should never
// see — which is the whole reason to have one. Deriving its key from the
// owner's seed would put a copy on the owner's device, and an identity whose
// key material exists in two places proves less than one that does not.
//
// So this is the other direction: the device generates its own key, presents
// the public half, and the owner delegates over it. The private half never
// moves. That ceremony already exists for adopting an instance
// (server/pairing.go) and had simply never been connected to assets.
//
// An enrolment token is what makes it safe. Without one, anything that could
// reach the port could enrol itself as the owner's machine and start speaking
// with the owner's delegated authority.

// Enrolment is a token the owner issues so a specific machine can enrol itself
// once.
type Enrolment struct {
	Token string `json:"token"`
	// DisplayName and AssetType describe what is expected to turn up, so an
	// operator issuing a token knows what they authorised — and so what enrols
	// cannot rename itself into something else.
	DisplayName string `json:"display_name"`
	AssetType   string `json:"asset_type"`
	// Origin is where the machine will be reachable. Recorded on the token
	// rather than accepted at enrolment, so a machine cannot claim an address
	// the owner did not intend.
	Origin string `json:"origin,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt bounds the window. A token that never expires is a permanent
	// way to become the owner's machine, sitting in whatever file or terminal
	// scrollback it was pasted into.
	ExpiresAt time.Time `json:"expires_at"`
	// UsedAt and AssetID record the one use. Single-use rather than counted:
	// there is exactly one machine this was issued for, and a second use is
	// either a mistake or somebody else.
	UsedAt  time.Time `json:"used_at,omitempty"`
	AssetID string    `json:"asset_id,omitempty"`
	Revoked bool      `json:"revoked,omitempty"`
}

// Spent reports whether this token can still be used, and why not if it cannot.
func (e Enrolment) Spent(now time.Time) (bool, string) {
	switch {
	case e.Revoked:
		return true, "this enrolment token was revoked"
	case !e.UsedAt.IsZero():
		return true, "this enrolment token has already been used"
	case !e.ExpiresAt.IsZero() && now.After(e.ExpiresAt):
		return true, "this enrolment token has expired"
	}
	return false, ""
}

// DefaultEnrolmentWindow is how long a token is good for.
//
// Long enough to walk to another machine and paste it, short enough that one
// left in a scrollback is not still a key to the estate next month.
const DefaultEnrolmentWindow = time.Hour

// enrolmentsPath is where tokens live. Kept in its own file beside the other
// six the asset store owns, so adding this touched no existing load path.
func (s *Store) enrolmentsPath() string {
	return filepath.Join(s.dataDir, "asset_enrolments.json")
}

// loadEnrolments reads the token file. Callers hold the lock.
//
// Read per call rather than cached, matching how the rest of this store treats
// its smaller files. Tokens are issued rarely and spent once, so there is no
// hot path to protect and no cache to get out of step.
func (s *Store) loadEnrolments() map[string]Enrolment {
	out := map[string]Enrolment{}
	if b, err := os.ReadFile(s.enrolmentsPath()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// CreateEnrolment issues a single-use token.
func (s *Store) CreateEnrolment(e Enrolment) (Enrolment, error) {
	if strings.TrimSpace(e.DisplayName) == "" {
		return Enrolment{}, fmt.Errorf("an enrolment token must say what it is for")
	}
	if strings.TrimSpace(e.AssetType) == "" {
		return Enrolment{}, fmt.Errorf("an enrolment token must say what kind of thing it enrols")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Enrolment{}, err
	}
	e.Token = hex.EncodeToString(raw)
	e.CreatedAt = time.Now().UTC()
	if e.ExpiresAt.IsZero() {
		e.ExpiresAt = e.CreatedAt.Add(DefaultEnrolmentWindow)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	all[e.Token] = e
	if err := s.saveLocked(s.enrolmentsPath(), all); err != nil {
		return Enrolment{}, err
	}
	return e, nil
}

func (s *Store) GetEnrolment(token string) (Enrolment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.loadEnrolments()[token]
	return e, ok
}

func (s *Store) ListEnrolments() []Enrolment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.loadEnrolments()
	out := make([]Enrolment, 0, len(all))
	for _, e := range all {
		out = append(out, e)
	}
	return out
}

// SpendEnrolment marks a token used, refusing if it already was.
//
// One call rather than check-then-mark, so two machines racing on the same
// token cannot both pass the check before either records it. That is the
// difference between a single-use token and a token that is usually used once.
func (s *Store) SpendEnrolment(token, assetID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	all := s.loadEnrolments()
	e, ok := all[token]
	if !ok {
		return fmt.Errorf("no such enrolment token")
	}
	if spent, why := e.Spent(now); spent {
		return fmt.Errorf("%s", why)
	}
	e.UsedAt = now
	e.AssetID = assetID
	all[token] = e
	return s.saveLocked(s.enrolmentsPath(), all)
}

func (s *Store) RevokeEnrolment(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	e, ok := all[token]
	if !ok {
		return fmt.Errorf("no such enrolment token")
	}
	e.Revoked = true
	all[token] = e
	return s.saveLocked(s.enrolmentsPath(), all)
}
