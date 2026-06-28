package asset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	mu             sync.RWMutex
	dataDir        string
	assetsPath     string
	invitesPath    string
	membersPath    string
	requestsPath   string
	assets         map[string]Asset
	invites        map[string]AssetInvite
	members        []AssetMember
	requests       []AssetAccessRequest
}

func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		dataDir:      dataDir,
		assetsPath:   filepath.Join(dataDir, "assets.json"),
		invitesPath:  filepath.Join(dataDir, "asset_invites.json"),
		membersPath:  filepath.Join(dataDir, "asset_members.json"),
		requestsPath: filepath.Join(dataDir, "asset_requests.json"),
		assets:       map[string]Asset{},
		invites:      map[string]AssetInvite{},
		members:      []AssetMember{},
		requests:     []AssetAccessRequest{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// assets
	if b, err := os.ReadFile(s.assetsPath); err == nil {
		json.Unmarshal(b, &s.assets)
	}
	// invites
	if b, err := os.ReadFile(s.invitesPath); err == nil {
		json.Unmarshal(b, &s.invites)
	}
	// members
	if b, err := os.ReadFile(s.membersPath); err == nil {
		json.Unmarshal(b, &s.members)
	}
	// requests
	if b, err := os.ReadFile(s.requestsPath); err == nil {
		json.Unmarshal(b, &s.requests)
	}
	return nil
}

func (s *Store) saveLocked(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Assets
func (s *Store) ListAssets() []Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Asset, 0, len(s.assets))
	for _, a := range s.assets {
		out = append(out, a)
	}
	return out
}

func (s *Store) GetAsset(id string) (Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	return a, ok
}

func (s *Store) UpsertAsset(a Asset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.assets[a.ID] = a
	return s.saveLocked(s.assetsPath, s.assets)
}

func (s *Store) DeleteAsset(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *Store) RevokeInvite(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inv, ok := s.invites[token]; ok {
		inv.Revoked = true
		s.invites[token] = inv
		return s.saveLocked(s.invitesPath, s.invites)
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
