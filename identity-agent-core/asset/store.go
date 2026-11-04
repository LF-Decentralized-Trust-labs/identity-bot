package asset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"identity-agent-core/internal/atomicfile"
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
	assetsErr      error // why assets.json could not be read; nil when it could
	assets         map[string]Asset
	invites        map[string]AssetInvite
	members        []AssetMember
	requests       []AssetAccessRequest
	empInvites     map[string]EmployeeInvite
	employees      map[string]Employee // keyed by PairwiseAID
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
	return s, s.load()
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
	var errs []error
	errs = append(errs, s.assetsErr)
	for _, f := range []struct {
		path string
		v    interface{}
	}{
		{s.invitesPath, &s.invites},
		{s.membersPath, &s.members},
		{s.requestsPath, &s.requests},
		{s.empInvitesPath, &s.empInvites},
		{s.employeesPath, &s.employees},
	} {
		errs = append(errs, readJSON(f.path, f.v))
	}
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
func (s *Store) CreateInvite(inv AssetInvite) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invites[inv.Token] = inv
	return s.saveLocked(s.invitesPath, s.invites)
}

func (s *Store) GetInvite(token string) (AssetInvite, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	inv, ok := s.invites[token]
	return inv, ok
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

func (s *Store) IncrementInviteUse(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inv, ok := s.invites[token]; ok {
		inv.UseCount++
		s.invites[token] = inv
		return s.saveLocked(s.invitesPath, s.invites)
	}
	return nil
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
func (s *Store) RevokeInvite(assetID, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.invites[token]
	if !ok || inv.AssetID != assetID {
		return ErrInviteNotFound
	}
	if inv.Revoked || (inv.MaxUses > 0 && inv.UseCount >= inv.MaxUses) {
		return ErrInviteClosed
	}
	inv.Revoked = true
	s.invites[token] = inv
	if err := s.saveLocked(s.invitesPath, s.invites); err != nil {
		inv.Revoked = false
		s.invites[token] = inv
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
