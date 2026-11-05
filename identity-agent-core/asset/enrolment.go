package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/enrolsecret"
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
//
// The token itself is kept nowhere. It is shown once, in the response that
// issues it, and the store holds only its digest (package enrolsecret), which
// is also this record's ID. A copy of the data directory is not a set of
// working tokens, and listing enrolments cannot reveal one.
type Enrolment struct {
	// ID is the digest of the token. It names the enrolment in lists and in
	// revoking it.
	ID string `json:"id"`
	// Token is set only on the value returned by CreateEnrolment. It is never
	// stored or listed.
	Token string `json:"token,omitempty"`
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

	// Replaces is read when an enrolment is issued, never stored: the ID of an
	// unused enrolment this one stands in for, which is then ended. Without it
	// every enrolment stands alone, so two machines of the same kind and name
	// can each have one outstanding.
	Replaces string `json:"replaces,omitempty"`
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

// loadEnrolments reads the record file, keyed by token digest. Callers hold
// the lock and have called s.migrateEnrolments.
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

// migrateEnrolments carries tokens an earlier version stored in the clear
// (keyed by the token itself) across to digests and rewrites the file without
// them. A token still good stays good. It runs once, as the store opens, and
// fails if the file cannot be rewritten — the caller does not start.
func (s *Store) migrateEnrolments() error {
	all := s.loadEnrolments()
	changed := false
	now := time.Now().UTC()
	for key, e := range all {
		if e.Token == "" {
			continue
		}
		changed = true
		delete(all, key)
		e.ID = enrolsecret.Digest(e.Token)
		if spent, _ := e.Spent(now); !spent {
			if err := s.enrolSecrets.Adopt(enrolsecret.Entry{Digest: e.ID, Expires: e.ExpiresAt}, now); err != nil {
				return err
			}
		}
		e.Token = ""
		all[e.ID] = e
	}
	if !changed {
		return nil
	}
	return s.saveLocked(s.enrolmentsPath(), all)
}

// CreateEnrolment issues a single-use token. The token is on the returned value
// and nowhere else: it cannot be read back later.
func (s *Store) CreateEnrolment(e Enrolment) (Enrolment, error) {
	if strings.TrimSpace(e.DisplayName) == "" {
		return Enrolment{}, fmt.Errorf("an enrolment token must say what it is for")
	}
	if strings.TrimSpace(e.AssetType) == "" {
		return Enrolment{}, fmt.Errorf("an enrolment token must say what kind of thing it enrols")
	}

	now := time.Now().UTC()
	e.CreatedAt = now
	if e.ExpiresAt.IsZero() {
		e.ExpiresAt = now.Add(DefaultEnrolmentWindow)
	}
	e.UsedAt, e.AssetID, e.Revoked = time.Time{}, "", false
	replaces := e.Replaces
	e.Replaces = ""

	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	// Replacing is explicit and names the enrolment replaced. It must be one
	// that can still be used; nothing else is ended.
	var old Enrolment
	if replaces != "" {
		var ok bool
		old, ok = all[replaces]
		if spent, _ := old.Spent(now); !ok || spent {
			return Enrolment{}, fmt.Errorf("the enrolment to replace is not outstanding")
		}
	}

	// Not exclusive to anything: each enrolment is its own.
	token, entry, err := s.enrolSecrets.Issue("", e.ExpiresAt.Sub(now), now)
	if err != nil {
		return Enrolment{}, err
	}
	e.ID = entry.Digest
	if replaces != "" {
		if err := s.enrolSecrets.Void(replaces, now); err != nil {
			_ = s.enrolSecrets.Void(entry.Digest, now)
			return Enrolment{}, err
		}
		old.Revoked = true
		all[replaces] = old
	}
	all[e.ID] = e
	// Records of tokens that can no longer be used and produced nothing are
	// not kept: the file does not grow with every token ever issued. A used
	// one stays, for it names the asset it made.
	for id, old := range all {
		if old.AssetID == "" && id != e.ID {
			if spent, _ := old.Spent(now); spent {
				delete(all, id)
			}
		}
	}
	if err := s.saveLocked(s.enrolmentsPath(), all); err != nil {
		_ = s.enrolSecrets.Void(entry.Digest, now)
		return Enrolment{}, err
	}
	e.Token = token
	return e, nil
}

// GetEnrolment finds the record a token was issued with.
func (s *Store) GetEnrolment(token string) (Enrolment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.loadEnrolments()[enrolsecret.Digest(token)]
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

// ClaimEnrolment spends a token and returns what it authorised.
//
// The secret is claimed first, in one operation inside the secret store, so
// two machines racing on the same token cannot both pass: exactly one gets it.
// That inverts the failure the alternative has — read it, check it, mint an
// identity, then mark it used — which leaves the whole minting step between
// the check and the record. Two requests arriving together would both get a
// delegated identity anchored in the owner's KEL, the loser refused only after
// its identity already existed and could never be un-anchored. Minting is a
// round trip to the KERI engine, so that window is wide enough to lose by
// accident, not just by attack.
//
// Claiming first means a machine that loses the race is told so before
// anything is created. If the work afterwards fails, ReleaseEnrolment hands the
// token back — a token wrongly spent is a machine that cannot retry, which is
// recoverable by issuing another, whereas an identity wrongly minted is not
// recoverable at all.
func (s *Store) ClaimEnrolment(token string, now time.Time) (Enrolment, error) {
	entry, err := s.enrolSecrets.Claim(token, "", now)
	if err != nil {
		return Enrolment{}, errors.New("this enrolment token cannot be used")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	e, ok := all[entry.Digest]
	if !ok || e.Revoked {
		return Enrolment{}, errors.New("this enrolment token cannot be used")
	}
	e.UsedAt = now
	all[entry.Digest] = e
	if err := s.saveLocked(s.enrolmentsPath(), all); err != nil {
		_ = s.enrolSecrets.Release(entry, now)
		return Enrolment{}, err
	}
	return e, nil
}

// RecordEnrolmentAsset attaches the asset a claimed token produced.
func (s *Store) RecordEnrolmentAsset(token, assetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	id := enrolsecret.Digest(token)
	e, ok := all[id]
	if !ok {
		return fmt.Errorf("no such enrolment token")
	}
	e.AssetID = assetID
	all[id] = e
	return s.saveLocked(s.enrolmentsPath(), all)
}

// ReleaseEnrolment un-claims a token whose enrolment did not complete, so the
// machine it was issued for can try again — unless a newer token has since been
// issued for the same thing, which keeps the older one void.
func (s *Store) ReleaseEnrolment(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	id := enrolsecret.Digest(token)
	e, ok := all[id]
	if !ok {
		return fmt.Errorf("no such enrolment token")
	}
	// Only release a claim that produced nothing. Once an asset is recorded the
	// token did its job, and handing it back would authorise a second identity.
	if e.AssetID != "" {
		return fmt.Errorf("this token already produced an identity and cannot be released")
	}
	now := time.Now().UTC()
	if err := s.enrolSecrets.Release(enrolsecret.Entry{Digest: id, Expires: e.ExpiresAt}, now); err != nil {
		return err
	}
	e.UsedAt = time.Time{}
	all[id] = e
	return s.saveLocked(s.enrolmentsPath(), all)
}

// RevokeEnrolment ends an unused token. id is the enrolment's ID as listed —
// never the token, which would put a secret in a request path.
func (s *Store) RevokeEnrolment(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.loadEnrolments()
	e, ok := all[id]
	if !ok {
		return fmt.Errorf("no such enrolment token")
	}
	if err := s.enrolSecrets.Void(id, time.Now().UTC()); err != nil {
		return err
	}
	e.Revoked = true
	all[id] = e
	return s.saveLocked(s.enrolmentsPath(), all)
}
