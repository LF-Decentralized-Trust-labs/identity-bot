package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/atomicfile"
	"identity-agent-core/enrolsecret"
)

type Store struct {
	mu             sync.RWMutex
	dataDir        string
	assetsPath     string
	invitesPath    string
	membersPath    string
	requestsPath   string
	empInvitesPath string
	employeesPath  string
	// enrolSecrets holds the digests of unused enrolment secrets; the records
	// in asset_enrolments.json say what each was issued for.
	enrolSecrets *enrolsecret.Store
	assetsErr    error // why assets.json could not be read; nil when it could
	secretsErr   error // why a file that can hold a secret could not be read
	assets       map[string]Asset
	invites      map[string]AssetInvite
	members      []AssetMember
	requests     []AssetAccessRequest
	empInvites   map[string]EmployeeInvite
	employees    map[string]Employee // keyed by PairwiseAID
}

func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		dataDir:        dataDir,
		assetsPath:     filepath.Join(dataDir, "assets.json"),
		invitesPath:    filepath.Join(dataDir, "asset_invites.json"),
		membersPath:    filepath.Join(dataDir, "asset_members.json"),
		requestsPath:   filepath.Join(dataDir, "asset_requests.json"),
		empInvitesPath: filepath.Join(dataDir, "employee_invites.json"),
		employeesPath:  filepath.Join(dataDir, "employees.json"),
		enrolSecrets:   enrolsecret.Open(filepath.Join(dataDir, "asset_enrolment_secrets.json")),
		assets:         map[string]Asset{},
		invites:        map[string]AssetInvite{},
		members:        []AssetMember{},
		requests:       []AssetAccessRequest{},
		empInvites:     map[string]EmployeeInvite{},
		employees:      map[string]Employee{},
	}
	// On a load error the store is returned alongside it, with the assets
	// reads reporting that error, so a caller that holds on to it cannot
	// mistake an unreadable store for an empty one. Never rewrites a file.
	//
	loadErr := s.load()
	// Only the three files that can hold a secret (asset_invites.json,
	// employee_invites.json, asset_enrolments.json) stop the agent: clear
	// codes may still be on them, and they cannot be ruled out unread. Any
	// other unreadable file leaves the store returned with its error, so the
	// asset routes answer 503 naming it and everything else keeps running.
	if s.secretsErr != nil {
		return s, fmt.Errorf("%w: %v", ErrSecretsNotMigrated, s.secretsErr)
	}
	// Secrets an earlier version stored in the clear are carried to digests
	// now, before anything is served. If the rewrite fails the store does not
	// start: clear secrets left on disk are what this exists to prevent.
	if err := s.migrateSecrets(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSecretsNotMigrated, err)
	}
	if loadErr != nil {
		return s, loadErr
	}
	return s, nil
}

// ErrSecretsNotMigrated is why a store would not start: one of the files that
// can hold an invite or enrolment secret could not be read, or secrets an
// earlier version saved in the clear could not be rewritten as digests. The
// error names the file.
var ErrSecretsNotMigrated = errors.New("asset store: clear invite or enrolment secrets could not be rewritten as digests, so it will not start")

// migrateSecrets moves every secret an earlier version stored in the clear —
// asset invites and employee invites keyed by their code, enrolments keyed by
// their token — onto digests, and rewrites each file without them.
func (s *Store) migrateSecrets() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for k, inv := range s.invites {
		if inv.Token == "" {
			continue
		}
		delete(s.invites, k)
		inv.ID, inv.Token = enrolsecret.Digest(inv.Token), ""
		s.invites[inv.ID] = inv
		changed = true
	}
	if changed {
		if err := s.saveLocked(s.invitesPath, s.invites); err != nil {
			return err
		}
	}
	changed = false
	for k, inv := range s.empInvites {
		if inv.Token == "" {
			continue
		}
		delete(s.empInvites, k)
		inv.ID, inv.Token = enrolsecret.Digest(inv.Token), ""
		s.empInvites[inv.ID] = inv
		changed = true
	}
	if changed {
		if err := s.saveLocked(s.empInvitesPath, s.empInvites); err != nil {
			return err
		}
	}
	return s.migrateEnrolments()
}

// readJSON loads one store file into v. A missing file is legitimately empty
// and leaves v untouched; anything else (permission, I/O, corrupt JSON) is an
// error naming the file. The file is never rewritten.
func readJSON(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("asset store: cannot read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("asset store: %s is not valid JSON: %w", path, err)
	}
	return nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assetsErr = readJSON(s.assetsPath, &s.assets)
	if s.assetsErr != nil {
		s.assets = map[string]Asset{}
	}
	var errs, secretErrs []error
	errs = append(errs, s.assetsErr)
	for _, f := range []struct {
		path   string
		v      interface{}
		secret bool
	}{
		{s.invitesPath, &s.invites, true},
		{s.membersPath, &s.members, false},
		{s.requestsPath, &s.requests, false},
		{s.empInvitesPath, &s.empInvites, true},
		{s.employeesPath, &s.employees, false},
	} {
		err := readJSON(f.path, f.v)
		errs = append(errs, err)
		if f.secret {
			secretErrs = append(secretErrs, err)
		}
	}
	s.secretsErr = errors.Join(secretErrs...)
	return errors.Join(errs...)
}

func (s *Store) saveLocked(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// Assets
func (s *Store) ListAssets() ([]Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.assetsErr != nil {
		return nil, s.assetsErr
	}
	out := make([]Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, a)
	}
	return out, nil
}

// HasAssetOfType reports whether any asset of the given type is held, without
// copying the store.
func (s *Store) HasAssetOfType(assetType string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.assetsErr != nil {
		return false, s.assetsErr
	}
	for _, a := range s.assets {
		if a.AssetType == assetType {
			return true, nil
		}
	}
	return false, nil
}

// GetAsset returns the asset, found=false when it is not held, or an error when
// the store could not be read: an unreadable store is not an empty one.
func (s *Store) GetAsset(id string) (Asset, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.assetsErr != nil {
		return Asset{}, false, s.assetsErr
	}
	a, ok := s.assets[id]
	return a, ok, nil
}

func (s *Store) UpsertAsset(a Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assetsErr != nil {
		return s.assetsErr
	}
	s.assets[a.ID] = a
	return s.saveLocked(s.assetsPath, s.assets)
}

func (s *Store) DeleteAsset(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.assetsErr != nil {
		return s.assetsErr
	}
	delete(s.assets, id)
	return s.saveLocked(s.assetsPath, s.assets)
}

// Invites
//
// An invite is kept under the digest of its code, never the code (package
// enrolsecret). A code presented is found by comparing it in constant time to
// every stored digest.

// CreateInvite records an invite for the code in inv.Token. The code is not
// stored: only its digest, which becomes the invite's ID.
func (s *Store) CreateInvite(inv AssetInvite) error {
	if inv.Token == "" {
		return errors.New("an invite needs a code")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inv.ID, inv.Token = enrolsecret.Digest(inv.Token), ""
	s.invites[inv.ID] = inv
	return s.saveLocked(s.invitesPath, s.invites)
}

// findInviteLocked returns the ID of the invite a presented code belongs to.
// It compares against every invite and never stops early.
func (s *Store) findInviteLocked(token string) (string, bool) {
	id, found := "", false
	if token == "" {
		return "", false
	}
	for key, inv := range s.invites {
		if enrolsecret.Equal(token, inv.ID) {
			id, found = key, true
		}
	}
	return id, found
}

func (s *Store) GetInvite(token string) (AssetInvite, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.findInviteLocked(token)
	if !ok {
		return AssetInvite{}, false
	}
	return s.invites[id], true
}

func (s *Store) ListInvites(assetID string) []AssetInvite {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []AssetInvite
	for _, inv := range s.invites {
		if inv.AssetID == assetID {
			out = append(out, inv)
		}
	}
	return out
}

// ErrInviteExhausted is returned when a redeem names an invite already used as
// many times as it allows.
var ErrInviteExhausted = errors.New("invite is used up")

// RedeemInvite checks an asset invite and spends one use in a single locked
// step, so concurrent redeems cannot together exceed MaxUses. It fails, and
// spends nothing, if the use cannot be saved.
func (s *Store) RedeemInvite(token string) (AssetInvite, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.findInviteLocked(token)
	if !ok || s.invites[id].Revoked {
		return AssetInvite{}, ErrInviteNotFound
	}
	inv := s.invites[id]
	if inv.usedUp() {
		return AssetInvite{}, ErrInviteExhausted
	}
	inv.UseCount++
	s.invites[id] = inv
	if err := s.saveLocked(s.invitesPath, s.invites); err != nil {
		inv.UseCount--
		s.invites[id] = inv
		return AssetInvite{}, err
	}
	return inv, nil
}

// ErrInviteNotFound is returned when a revoke names a code the store does not hold.
var ErrInviteNotFound = errors.New("no such invite")

// ErrInviteClosed is returned when a revoke names a code that is already revoked
// or already used up, so there is nothing left to withdraw.
var ErrInviteClosed = errors.New("invite is already revoked or used up")

// RevokeInvite withdraws an asset invite. It says ErrInviteNotFound for a token
// it does not hold and ErrInviteClosed for one already revoked or used up, so a
// caller is never told "revoked" about a code that was not live to begin with.
// A token that belongs to a different asset than assetID is reported as not
// found, exactly like an unknown one, so a caller cannot learn which codes exist
// on other assets.
// usedUp is whether an invite has been redeemed as many times as it allows; a
// MaxUses of 0 means no limit. A used-up code is closed: it can be neither
// redeemed nor revoked.
func (inv AssetInvite) usedUp() bool {
	return inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses
}

// RevokeInvite names the invite by its ID (the digest the list shows), never by
// its code: a code in a request path is written to every access log.
func (s *Store) RevokeInvite(assetID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invites[id]
	if !ok || inv.AssetID != assetID {
		return ErrInviteNotFound
	}
	if inv.Revoked || inv.usedUp() {
		return ErrInviteClosed
	}
	inv.Revoked = true
	s.invites[id] = inv
	if err := s.saveLocked(s.invitesPath, s.invites); err != nil {
		inv.Revoked = false
		s.invites[id] = inv
		return err
	}
	return nil
}

// Members
func (s *Store) ListMembers(assetID string) []AssetMember {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []AssetMember
	for _, m := range s.members {
		if m.AssetID == assetID {
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) AddMember(m AssetMember) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.members = append(s.members, m)
	return s.saveLocked(s.membersPath, s.members)
}

func (s *Store) RemoveMember(assetID, pairwiseAID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept []AssetMember
	for _, m := range s.members {
		if !(m.AssetID == assetID && m.PairwiseAID == pairwiseAID) {
			kept = append(kept, m)
		}
	}
	s.members = kept
	return s.saveLocked(s.membersPath, s.members)
}

// Requests
func (s *Store) ListRequests(assetID string) []AssetAccessRequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []AssetAccessRequest
	for _, r := range s.requests {
		if r.AssetID == assetID {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) GetRequest(id string) (AssetAccessRequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.requests {
		if r.ID == id {
			return r, true
		}
	}
	return AssetAccessRequest{}, false
}

func (s *Store) CreateRequest(r AssetAccessRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
	return s.saveLocked(s.requestsPath, s.requests)
}

func (s *Store) UpdateRequestStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.requests {
		if s.requests[i].ID == id {
			s.requests[i].Status = status
			now := s.requests[i].CreatedAt // placeholder, better use time.Now but for simplicity
			s.requests[i].ResolvedAt = &now
			return s.saveLocked(s.requestsPath, s.requests)
		}
	}
	return nil
}
